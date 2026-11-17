//! Tests for `bin/kata/src/cli/workflows/mod.rs`.

use super::*;
use kata_program::execution_program::VerifierSeverity;

fn repo_root() -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("bin/kata lives two levels below the repo root")
        .to_path_buf()
}

fn bundled_workflow_artifact(filename: &str) -> (WorkflowCompiledArtifact, std::path::PathBuf) {
    let stdlib_root = repo_root().join("workflows").join("std");
    let path = stdlib_root.join(filename);
    let artifact = build_workflow_artifact_from_file(&path, std::slice::from_ref(&stdlib_root))
        .unwrap_or_else(|err| panic!("{filename} must compile through preflight: {err:#}"));
    (artifact, path)
}

fn kata_loop_lite_artifact() -> (WorkflowCompiledArtifact, std::path::PathBuf) {
    bundled_workflow_artifact("kata-loop-lite.star")
}

fn kata_loop_lite_path() -> (std::path::PathBuf, std::path::PathBuf) {
    let stdlib_root = repo_root().join("workflows").join("std");
    let path = stdlib_root.join("kata-loop-lite.star");
    (path, stdlib_root)
}

fn inspect_fixture_projection(value: &serde_json::Value) -> serde_json::Value {
    let stages = value["preflight"]["stages"]
        .as_array()
        .expect("preflight stages are an array")
        .iter()
        .map(|stage| {
            let topology = &stage["topology"];
            serde_json::json!({
                "stage": stage["stage"],
                "agent": stage["agent"],
                "cache_policy": stage["cache_policy"],
                "cost_budget": stage["cost_budget"],
                "output_names": stage["output_names"],
                "progress_visibility": stage["progress_visibility"],
                "sandbox": stage["sandbox"],
                "structured_output_count": stage["structured_output_count"],
                "validate_retries": stage["validate_retries"],
                // The derived containment + cache-eligibility
                // verdict row, READ from the hashed execution class. Pins that a
                // HostUnconfined stage is operator-visible at preflight.
                "execution_class": stage["execution_class"],
                "topology": {
                    "kind": topology["kind"],
                    "root": topology["root"],
                    "workers": topology["workers"],
                    "reviewers": topology["reviewers"],
                    "max_concurrency": topology["max_concurrency"],
                    "fanout_limit": topology["fanout_limit"],
                    "dynamic_fanout": topology["dynamic_fanout"],
                    "mutation_policy": topology["mutation_policy"],
                    "review_quorum": topology["review_quorum"],
                }
            })
        })
        .collect::<Vec<_>>();

    serde_json::json!({
        "name": value["name"],
        "format": value["format"],
        "stage_names": value["stage_names"],
        "execution_program": {
            "schema_version": value["execution_program"]["schema_version"],
            "workflow_name": value["execution_program"]["workflow_name"],
            "program_hash": value["execution_program"]["program_hash"],
            "workflow_class": value["execution_program"]["workflow_class"],
            "summary": value["execution_program"]["summary"],
            "human_request_queue": value["execution_program"]["human_request_queue"],
            "external_input_channels": value["execution_program"]["external_input_channels"],
            "memory_selectors": value["execution_program"]["memory_selectors"],
            "validation_criteria": value["execution_program"]["validation_criteria"],
            "workflow_pattern": value["execution_program"]["workflow_pattern"],
            "verifier": value["execution_program"]["verifier"],
        },
        "preflight": {
            "stage_count": value["preflight"]["stage_count"],
            "edge_count": value["preflight"]["edge_count"],
            "source_format": value["preflight"]["source_format"],
            "worktree_isolated": value["preflight"]["worktree_isolated"],
            "review_loop_count": value["preflight"]["review_loop_count"],
            "sandbox_profile_count": value["preflight"]["sandbox_profile_count"],
            "workflow_budget": value["preflight"]["workflow_budget"],
            "planned_invocation_count": value["preflight"]["planned_invocation_count"],
            "execution_program": value["preflight"]["execution_program"],
            "warnings": value["preflight"]["warnings"],
            "stages": stages,
        }
    })
}

fn normalize_inspect_projection_hashes(mut value: serde_json::Value) -> serde_json::Value {
    if value["execution_program"]["program_hash"].is_string() {
        value["execution_program"]["program_hash"] = serde_json::json!("<program_hash>");
    }
    if value["execution_program"]["workflow_class"]["id"].is_string() {
        value["execution_program"]["workflow_class"]["id"] = serde_json::json!("<workflow_class>");
    }
    if value["preflight"]["execution_program"]["program_hash"].is_string() {
        value["preflight"]["execution_program"]["program_hash"] =
            serde_json::json!("<program_hash>");
    }
    if value["preflight"]["execution_program"]["workflow_class"].is_string() {
        value["preflight"]["execution_program"]["workflow_class"] =
            serde_json::json!("<workflow_class>");
    }
    value
}

fn check_all_fixture_projection(value: &serde_json::Value) -> serde_json::Value {
    let workflows = value["workflows"]
        .as_array()
        .expect("check-all workflows are an array")
        .iter()
        .map(|workflow| {
            serde_json::json!({
                "name": workflow["name"],
                "format": workflow["format"],
                "status": workflow["check"]["status"],
                "passed": workflow["check"]["passed"],
                "diagnostic_count": workflow["check"]["diagnostic_count"],
                "error_count": workflow["check"]["error_count"],
                "warning_count": workflow["check"]["warning_count"],
                "info_count": workflow["check"]["info_count"],
                // The non-issuing typed-operation comparison
                // door. Projected WHOLE — stage ids, operation ids, paths, and
                // the named refusals — so a shipped pack whose checked stage
                // contract moves, or whose construct changes refusal class, shows
                // up here as a reviewable diff rather than silently.
                "typed_operations": workflow["typed_operations"],
            })
        })
        .collect::<Vec<_>>();

    serde_json::json!({
        "check_all": value["check_all"],
        "workflows": workflows,
    })
}

fn stdlib_check_all_reports(
    deny_warnings: bool,
) -> (
    Vec<WorkflowCheckAllReport>,
    WorkflowCheckAllSummary,
    std::path::PathBuf,
) {
    let stdlib_root = repo_root().join("workflows").join("std");
    // The kata-factory builders live in a second bundled root, and the factory
    // packs `load("kata/factory.star", ...)`, so the check-all library must
    // include both roots for those loads to resolve. The gate's smoke rigs are
    // the third: no bundle ships them, but every one is checked here beside the
    // product packs (the roots `KATA_STDLIB_DIR=workflows/std` resolves).
    let factory_root = repo_root().join("workflows").join("kata-factory");
    let smoke_root = repo_root().join("workflows").join("smoke");
    let library = WorkflowLibrary::new(vec![stdlib_root.clone(), factory_root, smoke_root]);
    let reports = library
        .list_effective()
        .into_iter()
        .map(|entry| {
            build_workflow_check_all_report(
                &entry.name,
                &entry.path,
                library.roots(),
                deny_warnings,
            )
        })
        .collect::<Vec<_>>();
    let summary = workflow_check_all_summary(&reports);
    (reports, summary, stdlib_root)
}

#[test]
fn inspect_kata_loop_lite_surfaces_policy() {
    let (path, stdlib_root) = kata_loop_lite_path();

    let rendered =
        render_workflow_inspection_text_from_file(&path, std::slice::from_ref(&stdlib_root))
            .expect("inspect renders");
    assert!(rendered.contains("name:   kata-loop-lite")); // kata-spacing: intentional
    assert!(rendered.contains("format: starlark"));
    assert!(rendered.contains("source_hash: "));
    assert!(rendered.contains("normalized_definition_hash: "));
    assert!(rendered.contains("compiler: kata-workflow:"));
    assert!(rendered.contains("evaluator=starlark-rust:0.13"));
    // kata-loop-lite loads no module, so its provenance carries zero import
    // hashes and renders no per-import lines.
    assert!(rendered.contains("import_hashes: 0"));
    assert!(rendered.contains("worktree_isolated: true"));
    // A std pack authors no cost budget (time bounds only).
    assert!(rendered.contains("cost_budget: unlimited"));
    // implement + review + verdict (the read-only/host-net model-verdict
    // profile added by the HostUnconfined migration).
    assert!(rendered.contains("sandbox_profiles: 3"));
    assert!(rendered.contains(&format!(
        "checked_ir: version={} hash=",
        kata_workflow::execution_program_store::CURRENT_EXECUTION_PROGRAM_SCHEMA_VERSION
    )));
    assert!(rendered.contains(" workflow_class="));
    assert!(rendered.contains("verifier=pass"));
    // The derived containment verdict row is operator-visible at
    // preflight — read from the hashed class, not re-derived. No shipped stage
    // authors `sandbox = "host"`, so the pack's stages are all `contained`.
    assert!(rendered.contains("containment: contained (content_cache_eligible=false"));
    assert!(rendered.contains("human_request_queue: requests=1 max_items=4 displayed=1"));
    assert!(rendered.contains("  - [0] HR-kata-loop-lite-scope priority=medium stage=plan"));
    assert!(rendered.contains(
        "      question: Should the planned implementation wave stay single-writer if ownership is unclear?"
    ));
    assert!(rendered.contains(
        "      default_assumption: Keep the implementation single-writer unless the plan proves disjoint owned paths."
    ));
    assert!(rendered.contains(
        "      context: Advisory steering only; approval gates remain reserved for protected actions."
    ));
    assert!(rendered.contains("external_input_channels: channels=3 max_channels=4 displayed=3"));
    assert!(rendered.contains(
        "  - [0] operator_steering expose_as=steering stage=<global> kind=advisory schema=text max_items=8"
    ));
    assert!(rendered.contains(
        "      description: Run-level external steering rendered into every stage prompt."
    ));
    assert!(rendered.contains("      default_value: No external steering was appended."));
    assert!(rendered.contains(
        "  - [1] plan_feedback expose_as=plan_feedback stage=plan kind=advisory schema=text max_items=4"
    ));
    assert!(rendered.contains(
        "  - [2] review_feedback expose_as=review_feedback stage=review kind=advisory schema=text max_items=4"
    ));
    assert!(
        rendered.contains("workflow_pattern: normal_code_wave risk_tier=normal escape_hatch=false")
    );
    assert!(rendered.contains("review_loops: 1"));
    assert!(rendered.contains("worker=implement reviewer=review max_iterations=2"));
    assert!(rendered.contains("agent: label:reviewer"));
    assert!(rendered.contains("sandbox: named:implement"));
    assert!(rendered.contains("outputs: complete:bool"));
    assert!(rendered.contains("topology: root_with_parallel_workers"));
    assert!(rendered.contains("workers=[package_writer@default:optional"));
    assert!(rendered.contains("invocation_plan: preview_only=true root=root:implementation_root@default:required children=[worker:package_writer@default:optional"));
    assert!(rendered.contains("checked_ir: op=Stage agent=reviewer"));
    assert!(rendered.contains("prompt_hash="));
    assert!(rendered.contains("contract_hash="));
    assert!(rendered.contains("max_concurrency=3 fanout_limit=3"));
    assert!(rendered.contains("topology: review_quorum"));
    assert!(rendered.contains("quorum=required:1 block_on_any_finding:true"));
    assert!(rendered.contains("count_optional_reviewers:false"));
    assert!(rendered.contains("block_on_optional_findings:false"));
    assert!(
        rendered
            .contains("invocation_plan: preview_only=true root=root:review_root@reviewer:required")
    );
    assert!(rendered.contains(
        "quorum=required:1 reviewers:2 required_reviewers:1 advisory_reviewers:1 block_on_any_finding:true"
    ));
}

#[test]
fn check_kata_loop_lite_is_strict_clean() {
    let (artifact, path) = kata_loop_lite_artifact();
    let summary = workflow_check_summary(&artifact, false);

    assert_eq!(summary.status, VerifierStatus::Pass);
    assert!(summary.passed);
    assert_eq!(summary.warning_count, 0);
    assert_eq!(summary.failure_reason, None);

    let rendered = render_workflow_check_text(&path, &artifact, &summary);
    assert!(rendered.contains("workflow check: pass (passed)"));
    assert!(rendered.contains("format: starlark"));
    assert!(rendered.contains(&format!(
        "checked_ir: version={} hash=",
        kata_workflow::execution_program_store::CURRENT_EXECUTION_PROGRAM_SCHEMA_VERSION
    )));
    assert!(rendered.contains("verifier=pass diagnostics=3"));
    assert!(rendered.contains("diagnostics: errors=0 warnings=0 info=3"));
    assert!(rendered.contains("deny_warnings: false"));
    assert!(rendered.contains("verifier_diagnostics:"));
    assert!(!rendered.contains("workflow_pattern_escape_hatch"));
    assert!(rendered.contains("result: passed"));

    let value = workflow_check_json_value(&path, &artifact, &summary);
    assert_eq!(value["name"], serde_json::json!("kata-loop-lite"));
    assert_eq!(value["format"], serde_json::json!("starlark"));
    assert_eq!(value["check"]["status"], serde_json::json!("pass"));
    assert_eq!(value["check"]["passed"], serde_json::json!(true));
    assert_eq!(value["check"]["deny_warnings"], serde_json::json!(false));
    assert_eq!(value["check"]["warning_count"], serde_json::json!(0));
    assert_eq!(
        value["execution_program"]["verifier"]["status"],
        serde_json::json!("pass")
    );
    assert_eq!(
        value["preflight"]["execution_program"]["verifier_status"],
        serde_json::json!("pass")
    );
}

#[test]
fn check_kata_loop_lite_deny_warnings_passes() {
    let (artifact, path) = kata_loop_lite_artifact();
    let summary = workflow_check_summary(&artifact, true);

    assert_eq!(summary.status, VerifierStatus::Pass);
    assert!(summary.passed);
    assert_eq!(summary.failure_reason, None);

    let rendered = render_workflow_check_text(&path, &artifact, &summary);
    assert!(rendered.contains("workflow check: pass (passed)"));
    assert!(rendered.contains("deny_warnings: true"));
    assert!(rendered.contains("result: passed"));

    let value = workflow_check_json_value(&path, &artifact, &summary);
    assert_eq!(value["check"]["status"], serde_json::json!("pass"));
    assert_eq!(value["check"]["passed"], serde_json::json!(true));
    assert_eq!(value["check"]["deny_warnings"], serde_json::json!(true));
    assert_eq!(value["check"]["failure_reason"], serde_json::Value::Null);
}

#[test]
fn build_json_includes_checked_execution_ir() {
    let (artifact, path) = kata_loop_lite_artifact();
    let summary = workflow_check_summary(&artifact, false);

    let value = workflow_build_json_value(&path, &artifact, &summary);

    assert_eq!(value["name"], serde_json::json!("kata-loop-lite"));
    assert_eq!(
        value["source"],
        serde_json::json!(path.display().to_string())
    );
    assert_eq!(value["build"]["status"], serde_json::json!("pass"));
    assert_eq!(value["build"]["passed"], serde_json::json!(true));
    assert_eq!(
        value["build"]["execution_ir"]["schema_version"],
        serde_json::json!(
            kata_workflow::execution_program_store::CURRENT_EXECUTION_PROGRAM_SCHEMA_VERSION
        )
    );
    assert!(value["execution_program"]["stages"].is_object());
    assert_eq!(
        value["execution_program"]["verifier"]["status"],
        serde_json::json!("pass")
    );
}

#[test]
fn check_input_accepts_explicit_file_path() {
    let (path, _) = kata_loop_lite_path();
    let library = WorkflowLibrary::new(Vec::new());

    let resolved = resolve_workflow_check_input(&library, path.to_str().expect("utf8 path"))
        .expect("explicit file path resolves");

    assert_eq!(resolved, path);
}

/// GOLDEN RECORDING of `kata workflows check --all --format json`, per pack.
///
/// Recorded counts move only for a stated reason, because the whole point of the
/// fixture is that an unexplained diagnostic is a diff.
///
/// What moves an id, and what does not:
///
/// * **A declared output is stage-contract material; prompt text is not.**
///   Declaring a new stage output rotates that one stage's `operation` id;
///   rewording a prompt or a shell script moves no id at all.
/// * **The compiler identity rotates exactly the `invoke` ids.** The compiler
///   identity (`kata-workflow:<CARGO_PKG_VERSION>`) is program-hash material, and
///   an `invoke` operation id folds the bound child's `program_hash`, so a
///   workspace version change re-blesses every `invoke` id. No stage
///   `operation`, `policy` or `selector` id moves: a stage contract hash does not
///   carry the compiler identity.
/// * **A program-schema or execution-contract version bump rotates the whole
///   identity family by construction, and moves no count.** The schema version
///   is part of every `kata.execution.*` domain tag. A re-bless after such a bump
///   must touch only 64-hex values under `operation` / `policy` / `selector`
///   and leave the documents structurally identical once those are scrubbed; a
///   count that moved alongside them would mean a lowering change riding an
///   identity bump, which is the pair this fixture exists to separate. A field
///   that only stage policies carry (such as the `timeout_ms` authoring
///   default) rotates `operation` and must NOT rotate `policy` or `selector`: a
///   loop policy hash and an agent-selector hash are not functions of a stage's
///   wall clock.
/// * **`validation_criteria_declared` is ONE diagnostic however many criteria a
///   pack declares, wherever they are bound.** Moving a criterion between stages,
///   or adding a second, moves no count. A graph containing a `promote` with no
///   required criterion is refused at load
///   (`validate_in_graph_promote_declares_a_criterion`), so every pack that
///   promotes carries the info.
/// * An unchanged number after a real structural edit is exactly as much of a
///   claim as a changed one.
///
/// REGENERATING THE FIXTURE: it is written from this projection, never edited by
/// hand. Run
/// `KATA_BLESS_WORKFLOW_CLI_FIXTURES=1 just test-one-crate kata check_all_json_matches_fixture`,
/// then review the diff.
#[test]
fn check_all_json_matches_fixture() {
    let (reports, summary, _) = stdlib_check_all_reports(false);
    let actual = workflow_check_all_json_value(&reports, &summary);
    let fixture_path = repo_root()
        .join("test")
        .join("fixtures")
        .join("workflows")
        .join("cli")
        .join("check-all-effective.json");
    if std::env::var_os("KATA_BLESS_WORKFLOW_CLI_FIXTURES").is_some() {
        let blessed = serde_json::to_string_pretty(&check_all_fixture_projection(&actual))
            .expect("the projection serializes");
        std::fs::write(&fixture_path, format!("{blessed}\n"))
            .unwrap_or_else(|err| panic!("failed to write {}: {err}", fixture_path.display()));
    }
    let expected = std::fs::read_to_string(&fixture_path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", fixture_path.display()));
    let expected: serde_json::Value = serde_json::from_str(&expected).expect("fixture JSON parses");

    assert_eq!(check_all_fixture_projection(&actual), expected);
}

/// The typed-operation comparison door is REACHABLE FROM THE
/// CLI JSON, not just from the library. Read out of the rendered JSON
/// document, the invariants it claims, precisely:
///
/// * `lowered + refused == stage_count` — STILL, and only because a `Select`, an
///   `ExpandBounded` and an input `Wait` are PROGRAM-level operations over
///   `branch_routes` / `review_loops` / the blocking human requests rather than a
///   stage's. A loop's MEMBERS are ordinary stages
///   and are counted in the stage lists, because they are the expansion's
///   template rather than something it consumes;
/// * the document DOES carry `selects` + `refused_selects`, so the route total is
///   checkable here directly; it carries no route count to check it AGAINST, so
///   what is asserted is the coordinate-space property those two lists make
///   available: a select's path is a single coordinate at or past `stage_count`,
///   and an expansion's is at or past `stage_count + selects + refused_selects` —
///   the exact start of the third segment — and the n-th input's is EXACTLY the start
///   of the fourth (`stage_count + routes + loops`) plus n, so the four segments cannot
///   overlap and each operation names a stage the block accounts for;
/// * every lowered stage carries a 64-hex operation id, a single-coordinate path,
///   and a named operation `kind`; every refusal names its stage and its class;
/// * every expansion carries a 64-hex operation id, a 64-hex loop-POLICY hash, a
///   non-empty template of single-coordinate stage paths, and an iteration ceiling
///   of at least one.
#[test]
fn typed_operations_appear_in_workflows_check_json() {
    let (reports, summary, _) = stdlib_check_all_reports(false);
    let document: serde_json::Value = serde_json::from_str(
        &render_json_pretty(&workflow_check_all_json_value(&reports, &summary))
            .expect("the check-all document renders"),
    )
    .expect("the rendered document parses");

    let workflows = document["workflows"]
        .as_array()
        .expect("workflows is an array");
    assert!(
        workflows.len() >= 20,
        "only {} packs checked",
        workflows.len()
    );
    let mut lowered_total = 0usize;
    let mut select_total = 0usize;
    let mut expansion_total = 0usize;
    let mut input_total = 0usize;
    let mut refusal_arms = std::collections::BTreeSet::new();
    let mut kinds = std::collections::BTreeSet::new();

    for workflow in workflows {
        let name = workflow["name"].as_str().expect("a pack name");
        let typed = &workflow["typed_operations"];
        assert_eq!(
            typed["schema_version"],
            kata_program::execution_program::OPERATION_LOWERING_SCHEMA_VERSION,
            "{name}: schema version"
        );
        let lowered = typed["lowered"].as_array().expect("lowered is an array");
        let refused = typed["refused"].as_array().expect("refused is an array");
        let selects = typed["selects"].as_array().expect("selects is an array");
        let expansions = typed["expansions"]
            .as_array()
            .expect("expansions is an array");
        assert!(
            typed["refused_expansions"].is_array(),
            "{name}: the refused-expansion list must be present"
        );
        let route_total = (selects.len()
            + typed["refused_selects"]
                .as_array()
                .expect("refused_selects is an array")
                .len()) as u64;
        assert!(
            typed["refused_selects"]
                .as_array()
                .is_some_and(Vec::is_empty),
            "{name}: no shipped route is refused, and the list must be present"
        );

        let stage_count = workflow["preflight"]["stage_count"]
            .as_u64()
            .expect("the preflight stage count is a number");
        assert_eq!(
            (lowered.len() + refused.len()) as u64,
            stage_count,
            "{name}: every stage must appear once in the typed-operation block"
        );
        // `stages ++ branch_routes ++ review_loops ++ blocking_requests`: the third
        // segment begins after every stage and every route, and the fourth after every
        // loop too, lowered or refused alike.
        let expansion_segment_start = stage_count + route_total;
        let loop_total = (expansions.len()
            + typed["refused_expansions"]
                .as_array()
                .expect("refused_expansions is an array")
                .len()) as u64;
        let input_segment_start = expansion_segment_start + loop_total;
        let inputs = typed["inputs"].as_array().expect("inputs is an array");
        assert!(
            typed["refused_inputs"]
                .as_array()
                .is_some_and(Vec::is_empty),
            "{name}: no shipped blocking request is refused, and the list must be present"
        );

        let mut accounted = std::collections::BTreeSet::new();
        for entry in lowered {
            let operation = entry["operation"].as_str().expect("an operation id");
            assert_eq!(
                operation.len(),
                64,
                "{name}: operation id is a 32-byte hash"
            );
            assert!(
                operation.chars().all(|c| c.is_ascii_hexdigit()),
                "{name}: operation id is hex, got {operation}"
            );
            assert_eq!(
                entry["path"].as_array().expect("a path").len(),
                1,
                "{name}: this increment's path is a single flat coordinate"
            );
            kinds.insert(
                entry["kind"]
                    .as_str()
                    .expect("a lowered operation names its kind")
                    .to_string(),
            );
            accounted.insert(entry["stage"].as_str().expect("a stage id").to_string());
        }
        for entry in refused {
            let arm = entry["refusal"].as_str().expect("a named refusal");
            assert!(
                !arm.is_empty() && entry["stage"].is_string(),
                "{name}: a refusal names its stage and its class"
            );
            refusal_arms.insert(arm.to_string());
            accounted.insert(entry["stage"].as_str().expect("a stage id").to_string());
        }
        for entry in selects {
            let path = entry["path"].as_array().expect("a path");
            assert_eq!(path.len(), 1, "{name}: a route path is one coordinate");
            assert!(
                path[0].as_u64().expect("a coordinate") >= stage_count,
                "{name}: a route path must sit past every stage path"
            );
            assert_eq!(
                entry["selector"].as_str().map(str::len),
                Some(64),
                "{name}: a route carries its selector hash"
            );
            let condition = entry["condition_stage"]
                .as_str()
                .expect("a condition stage id");
            assert!(
                accounted.contains(condition),
                "{name}: a route's condition stage {condition:?} must be a stage of the program"
            );
        }
        for entry in expansions {
            let path = entry["path"].as_array().expect("a path");
            assert_eq!(path.len(), 1, "{name}: an expansion path is one coordinate");
            // The THIRD segment starts after the stages AND after every route,
            // lowered or refused: `stages ++ branch_routes ++ review_loops`.
            assert!(
                path[0].as_u64().expect("a coordinate") >= expansion_segment_start,
                "{name}: an expansion path must sit past every stage and route path \
                 (segment starts at {expansion_segment_start})"
            );
            assert_eq!(
                entry["policy"].as_str().map(str::len),
                Some(64),
                "{name}: an expansion carries its loop-policy hash"
            );
            assert_eq!(
                entry["operation"].as_str().map(str::len),
                Some(64),
                "{name}: an expansion carries its operation id"
            );
            assert!(
                entry["maximum"].as_u64().expect("an iteration ceiling") >= 1,
                "{name}: a bounded expansion iterates at least once"
            );
            let worker = entry["worker_stage"].as_str().expect("a worker stage id");
            assert!(
                accounted.contains(worker),
                "{name}: an expansion's worker stage {worker:?} must be a stage of the program"
            );
            let template = entry["template"].as_array().expect("a template");
            assert!(
                template.len() >= 2,
                "{name}: a loop's template is its body then its gate"
            );
            for member in template {
                let member = member.as_array().expect("a template member path");
                assert_eq!(
                    member.len(),
                    1,
                    "{name}: a template member is a stage path, one coordinate"
                );
                assert!(
                    member[0].as_u64().expect("a coordinate") < stage_count,
                    "{name}: a template member is a STAGE of this program"
                );
            }
        }
        for (index, entry) in inputs.iter().enumerate() {
            let path = entry["path"].as_array().expect("a path");
            assert_eq!(
                path,
                &vec![serde_json::json!(input_segment_start + index as u64)],
                "{name}: the n-th input sits at the start of the FOURTH segment plus n"
            );
            assert_eq!(
                entry["selector"].as_str().map(str::len),
                Some(64),
                "{name}: an input carries its request selector"
            );
            let target = entry["target_stage"].as_str().expect("a target stage id");
            assert!(
                accounted.contains(target),
                "{name}: an input's target stage {target:?} must be a stage of the program"
            );
        }
        lowered_total += lowered.len();
        select_total += selects.len();
        expansion_total += expansions.len();
        input_total += inputs.len();
    }

    // Measured over the bundled corpus and pinned at roughly half the
    // measurement, so this is a collapse detector rather than a tripwire benign
    // pack churn reds.
    assert!(
        lowered_total >= 100,
        "the bundled corpus must lower stages through the CLI door, got {lowered_total}"
    );
    assert!(
        select_total > 0,
        "the bundled corpus must lower branch routes to Selects through the CLI door"
    );
    assert!(
        expansion_total > 0,
        "the bundled corpus must lower review loops to expansions through the CLI door"
    );
    assert!(
        input_total > 0,
        "the bundled corpus must lower blocking human requests to input waits through the \
         CLI door"
    );
    // A static `topology` role list lowers to `expand_bounded`, and
    // `child_invocation` (dynamic-fanout only) is authored by no shipped pack,
    // so every bundled stage lowers. A refusal appearing here is a regression in lowering
    // coverage, not pack churn.
    assert!(
        refusal_arms.is_empty(),
        "every bundled stage lowers through the CLI door; saw refused classes {refusal_arms:?}"
    );
    assert!(
        kinds.contains("execute") && kinds.contains("join"),
        "the lowered shapes must be named in the CLI document, saw {kinds:?}"
    );
}

#[test]
fn check_all_deny_warnings_accepts_the_strict_clean_bundled_corpus() {
    let (reports, summary, _) = stdlib_check_all_reports(true);

    // Every shipped pack must remain warning-free under the installed
    // release's strict preflight. The count is pinned so a pack cannot join or
    // leave the bundled corpus without moving this number in the same diff.
    assert_eq!(summary.total, 42);
    assert_eq!(summary.passed, 42);
    assert_eq!(summary.failed, 0);
    assert_eq!(summary.warnings, 0);
    assert!(reports.iter().all(|report| matches!(
        &report.result,
        WorkflowCheckAllResult::Checked { summary, .. }
            if summary.passed && summary.warning_count == 0
    )));
}

#[test]
fn deny_warnings_rejects_a_reason_backed_escape_hatch() {
    let directory = tempfile::tempdir().expect("temporary workflow directory");
    let path = directory.path().join("reasoned-escape.star");
    std::fs::write(
        &path,
        r#"
work = stage(id = "work", agent = "shell", run = "true")
workflow(
    "reasoned-escape",
    root = [work],
    workflow_pattern = workflow_pattern(
        "normal_code_wave",
        escape_hatch = True,
        escape_reason = "the author accepts the deviation",
    ),
)
"#,
    )
    .expect("write warning fixture");
    let artifact = build_workflow_artifact_from_file(&path, &[])
        .expect("reason-backed escape fixture compiles");

    let summary = workflow_check_summary(&artifact, true);
    assert_eq!(summary.status, VerifierStatus::Warn);
    assert!(!summary.passed);
    assert_eq!(summary.warning_count, 1);
    assert_eq!(
        summary.failure_reason,
        Some("verifier reported warnings and --deny-warnings is set")
    );
    assert!(
        artifact
            .execution_program
            .verifier
            .diagnostics
            .iter()
            .any(
                |diagnostic| diagnostic.severity == VerifierSeverity::Warning
                    && diagnostic.code == "workflow_pattern_escape_hatch"
            )
    );
}

/// REGENERATING THE FIXTURE: it is written from this projection (hashes
/// normalized), never edited by hand. Run
/// `KATA_BLESS_WORKFLOW_CLI_FIXTURES=1 just test-one-crate kata inspect_kata_loop_lite_json_matches_fixture`,
/// then review the diff.
#[test]
fn inspect_kata_loop_lite_json_matches_fixture() {
    let (artifact, _) = kata_loop_lite_artifact();
    let actual = workflow_inspection_json_value(&artifact);
    let fixture_path = repo_root()
        .join("test")
        .join("fixtures")
        .join("workflows")
        .join("cli")
        .join("kata-loop-lite-inspect-preflight.json");
    if std::env::var_os("KATA_BLESS_WORKFLOW_CLI_FIXTURES").is_some() {
        let blessed = serde_json::to_string_pretty(&normalize_inspect_projection_hashes(
            inspect_fixture_projection(&actual),
        ))
        .expect("the projection serializes");
        std::fs::write(&fixture_path, format!("{blessed}\n"))
            .unwrap_or_else(|err| panic!("failed to write {}: {err}", fixture_path.display()));
    }
    let expected = std::fs::read_to_string(&fixture_path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", fixture_path.display()));
    let expected: serde_json::Value = serde_json::from_str(&expected).expect("fixture JSON parses");

    assert_eq!(
        normalize_inspect_projection_hashes(inspect_fixture_projection(&actual)),
        normalize_inspect_projection_hashes(expected)
    );
}

/// The DSL catalog the `kata workflows schema` handler prints
/// is reachable through the public crate API and serializes to the stable,
/// non-empty JSON shape an agent author targets.
#[test]
fn workflows_schema_catalog_is_valid_json_with_stable_keys() {
    let catalog = kata_program::dsl_catalog::dsl_catalog();
    let value = serde_json::to_value(&catalog).expect("catalog serializes to JSON");

    assert!(
        value
            .get("version")
            .and_then(serde_json::Value::as_u64)
            .is_some()
    );
    let builtins = value["builtins"].as_array().expect("builtins is an array");
    assert!(!builtins.is_empty(), "catalog must list builtins");
    assert!(value.get("grammar").is_some(), "catalog carries grammar");

    let names: Vec<&str> = builtins
        .iter()
        .map(|b| b["name"].as_str().unwrap())
        .collect();
    for core in ["stage", "workflow", "contract", "field"] {
        assert!(names.contains(&core), "catalog must contain {core:?}");
    }

    // Round-trips through a string (proves the printed JSON body parses).
    let text = serde_json::to_string_pretty(&catalog).unwrap();
    let reparsed: serde_json::Value = serde_json::from_str(&text).unwrap();
    assert_eq!(reparsed, value);
}

/// Surface hygiene: the empty-state hint from `kata workflows list`
/// must direct operators to `.star` only. A `.toml` file dropped in a root is
/// silently skipped by the loader (`WorkflowLibrary::list` recognizes only the
/// `.star` extension), so advertising `.toml` here would tell operators to do
/// something the loader refuses. Pin the wording so it cannot regress.
#[test]
fn empty_library_hint_names_star_only_never_toml() {
    let hint = super::EMPTY_LIBRARY_HINT.to_ascii_lowercase();
    assert!(
        hint.contains(".star"),
        "empty-library hint must point operators at `.star`: {hint:?}"
    );
    assert!(
        !hint.contains("toml"),
        "empty-library hint still advertises the deleted `.toml` workflow \
         format (the loader silently ignores `.toml` files): {hint:?}"
    );
}

/// The `kata workflows check` / `kata check` compile path —
/// `build_workflow_artifact_from_file`, the same function `check_for_contract`
/// calls — must SURFACE the collected DSL diagnostics, not just the library.
/// A workflow with a `model=` slip and a `stages=` slip reports BOTH, each with
/// its "did you mean" suggestion, in the rendered error.
#[test]
fn check_path_renders_collected_dsl_diagnostics() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("bad.star");
    std::fs::write(
        &path,
        "a = stage(prompt = \"x\", agent = \"worker\", model = \"opus\")\n\
         workflow(\"w\", stages = a)\n",
    )
    .unwrap();

    let err = build_workflow_artifact_from_file(&path, &[])
        .expect_err("a workflow with unknown keywords must fail the check");
    let rendered = format!("{err:#}");
    assert!(
        rendered.contains("did you mean `model_hint`?"),
        "check path must render the model→model_hint suggestion: {rendered}"
    );
    assert!(
        rendered.contains("did you mean `root`?"),
        "check path must render the stages→root suggestion: {rendered}"
    );
    assert!(
        rendered.contains("2 definition errors found"),
        "check path must render the collect-all header: {rendered}"
    );
}

/// `build_workflow_check_all_report` backs
/// `kata workflows check --all`. Its `LoadFailed { error }` must carry the FULL
/// collected DSL diagnostic report, not just the outermost
/// "failed to parse resolved workflow …" context — otherwise the `--all` summary
/// (and the MCP `check` contract face, which flattens the same way) would drop
/// every "did you mean" suggestion the single-workflow path renders.
#[test]
fn check_all_report_surfaces_collected_dsl_diagnostics() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("bad.star");
    std::fs::write(
        &path,
        "a = stage(prompt = \"x\", agent = \"worker\", model = \"opus\")\n\
         workflow(\"w\", stages = a)\n",
    )
    .unwrap();

    let report = build_workflow_check_all_report("bad", &path, &[], false);
    let error = match report.result {
        WorkflowCheckAllResult::LoadFailed { error } => error,
        WorkflowCheckAllResult::Checked { .. } => {
            panic!("a workflow with unknown keywords must fail to load")
        }
    };
    assert!(
        error.contains("did you mean `model_hint`?"),
        "--all report must render the model→model_hint suggestion: {error}"
    );
    assert!(
        error.contains("did you mean `root`?"),
        "--all report must render the stages→root suggestion: {error}"
    );
    assert!(
        error.contains("2 definition errors found"),
        "--all report must render the collect-all header: {error}"
    );
}

/// The `workflows list` JSON row and the `GET /api/v1/workflows` wire row must
/// be ONE spelling, not two. Deserializing a CLI row straight back into
/// [`kata_client::types::WorkflowLibraryEntry`] — the SDK mirror of that REST
/// row — is the mechanical check: a renamed or retyped shared field breaks this
/// test rather than silently forking the contract.
#[test]
fn library_row_matches_rest_wire_shape() {
    let stdlib_root = repo_root().join("workflows").join("std");
    let library = WorkflowLibrary::new(vec![stdlib_root]);
    let entries = library.list_effective();
    assert!(
        !entries.is_empty(),
        "the bundled stdlib root must resolve at least one workflow"
    );

    let listing = json::workflow_listing_json_value(&library, &entries, false);
    let value = serde_json::to_value(&listing).expect("listing serializes");

    let rows = value["workflows"]
        .as_array()
        .expect("workflows is an array");
    assert_eq!(rows.len(), entries.len(), "every entry contributes a row");

    for row in rows {
        // The shared four fields round-trip into the REST/SDK type.
        let entry: kata_client::types::WorkflowLibraryEntry = serde_json::from_value(row.clone())
            .unwrap_or_else(|err| {
                panic!("CLI listing row must deserialize as the REST wire row: {err}\n{row}")
            });
        assert!(!entry.name.is_empty(), "row carries a name: {row}");
        assert!(
            row["path"].as_str().is_some_and(|p| {
                std::path::Path::new(p)
                    .extension()
                    .is_some_and(|ext| ext.eq_ignore_ascii_case("star"))
            }),
            "row path is the resolved source file: {row}"
        );
        // `format` is the same lower-case bare string the REST handler emits.
        assert_eq!(row["format"], "starlark", "shared format spelling: {row}");
        // CLI-only superset field.
        assert_eq!(row["shadowed"], false, "effective listing has no shadows");
    }

    // The roots table is CLI-only and reports existence per priority slot.
    let roots = value["roots"].as_array().expect("roots is an array");
    assert_eq!(roots.len(), 1, "one configured root");
    assert_eq!(roots[0]["priority"], 0);
    assert_eq!(roots[0]["label"], "project");
    assert_eq!(roots[0]["exists"], true);
}

/// T11 for the embedded harness on the CLI's own check faces: under a
/// `--config` whose agents are the two nanocode kinds (`nanocode_openai` under
/// kata's `kata_login`, `nanocode_anthropic` under an `env:` key, no `argv`),
/// plus one node `egress_allow` authority, an agent stage authored
/// `net = "offline"` is `offline` on every face — `kata check`'s text, the
/// `--format json` preflight `kata workflows check` emits, `kata workflows
/// inspect`'s text and the local `check` contract the MCP stdio face and `kata
/// check --format json` serve — for each member of its fallback
/// panel, and so is the shipped `agent-change` pack's `implement` stage (its
/// `edit` profile authors `net = "offline"`). A nanocode turn's model requests
/// leave from the process hosting the worker, never from the capsule, so no
/// face names a vendor endpoint or the node's authority. Every face is read off
/// what it renders.
///
/// **Would red if:** a nanocode capsule authored `offline` opened an endpoint,
/// or were widened to the node's authority.
#[test]
fn check_faces_name_a_nanocode_offline_agent_capsule_offline() {
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("kata.toml");
    std::fs::write(
        &config,
        format!(
            r#"
[node]
id = "t11-nanocode-check"
data_dir = "{data}"
egress_allow = ["intranet.corp.example:443"]

[workers]
transports = [{{ type = "supervised_node" }}]
dispatch_deadline_ms = 5000
heartbeat_interval_ms = 2500
heartbeat_grace_ms = 10000
max_workers = 4

[api]
bind = "127.0.0.1:8400"
auth = {{ type = "signed_token", verifying_key_env = "API_VERIFYING_KEY" }}

[agents.codex]
adapter = "nanocode_openai"
credential = {{ mode = "subscription", source = "kata_login" }}

[agents.claude]
adapter = "nanocode_anthropic"
credential = {{ mode = "api_key", source = "env:ANTHROPIC_API_KEY" }}

[agents.change-agent]
adapter = "nanocode_openai"
credential = {{ mode = "subscription", source = "kata_login" }}
"#,
            data = dir.path().join("data").display(),
        ),
    )
    .unwrap();
    install_node_facts_from_config_flag(Some(&config)).expect("the config installs");
    let path = dir.path().join("offline-review.star");
    std::fs::write(
        &path,
        r#"review = stage(id = "review", agent = ["codex", "claude"], prompt = "review it", sandbox = "ro")
probe = stage(id = "probe", agent = "shell", run = "true", sandbox = "ro", depends_on = ["review"])
workflow("offline-review", root = [review], sandbox_profiles = {"ro": sandbox_profile(workspace = "ro", net = "offline")})
"#,
    )
    .unwrap();
    let artifact = build_workflow_artifact_from_file(&path, &[])
        .expect("the pack checks on the nanocode node");
    let summary = workflow_check_summary(&artifact, false);

    let text = render_workflow_check_text(&path, &artifact, &summary);
    assert!(
        text.contains(
            "capsule_network:\n  - probe: offline\n  - review (agent codex): offline\n  \
             - review (agent claude): offline\n"
        ),
        "kata check text: {text}"
    );
    assert!(
        !text.contains("intranet") && !text.contains("vendor_egress_only"),
        "no node authority or vendor endpoint is named: {text}"
    );

    let value = workflow_check_json_value(&path, &artifact, &summary);
    let stages = value["preflight"]["stages"].as_array().unwrap();
    let review = stages
        .iter()
        .find(|stage| stage["stage"] == "review")
        .unwrap();
    // A network object names no allowlist when it holds none.
    let offline = serde_json::json!({"posture": "offline"});
    assert_eq!(
        review["capsule_networks"],
        serde_json::json!([
            {"agent": "codex", "network": offline},
            {"agent": "claude", "network": offline},
        ]),
        "kata check --format json: {review}"
    );

    let inspected = render_workflow_inspection_text_from_file(&path, &[]).unwrap();
    assert!(
        inspected.contains(
            "      capsule_network (agent codex): offline\n      \
             capsule_network (agent claude): offline\n"
        ),
        "kata workflows inspect: {inspected}"
    );

    let contract = check_for_contract(&kata_op_contract::requests::CheckRequest {
        workflow: Some(path.display().to_string()),
        all: false,
        deny_warnings: false,
    })
    .expect("the local check contract answers");
    let serialized = serde_json::to_value(&contract).unwrap();
    assert_eq!(
        serialized["capsule_networks"],
        serde_json::json!([
            {"stage": "probe", "posture": "offline", "allowlist": []},
            {"stage": "review", "agent": "codex", "posture": "offline", "allowlist": []},
            {"stage": "review", "agent": "claude", "posture": "offline", "allowlist": []},
        ]),
        "the local check contract: {serialized}"
    );

    // The shipped agent-change pack: its `implement` agent stage runs under the
    // `edit` profile, authored `net = "offline"`.
    let shipped = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../workflows/std/agent-change.star");
    let contract = check_for_contract(&kata_op_contract::requests::CheckRequest {
        workflow: Some(shipped.display().to_string()),
        all: false,
        deny_warnings: false,
    })
    .expect("the shipped agent-change pack checks on the nanocode node");
    let serialized = serde_json::to_value(&contract).unwrap();
    let implement: Vec<&serde_json::Value> = serialized["capsule_networks"]
        .as_array()
        .expect("capsule_networks")
        .iter()
        .filter(|network| network["stage"] == "implement")
        .collect();
    assert_eq!(
        implement,
        [&serde_json::json!({
            "stage": "implement",
            "agent": "change-agent",
            "posture": "offline",
            "allowlist": [],
        })],
        "agent-change's implement stage: {serialized}"
    );
}

/// The deferred-node-facts line on BOTH check surfaces. A node-less
/// `kata check` (test door: install the profile, then clear the installed
/// marker — the state the flipped default leaves a real `kata check` in)
/// compiles a pack whose node-dependent arms defer; the rendered text carries
/// the one `not judged without a booted node:` line naming EXACTLY the
/// deferred classes — no class the check judged — and, since `--config` would
/// judge some of them, pointing at it; the JSON `check` object carries the same
/// list.
///
/// **Watched red:** with the render arm deleted, the text assert fails; with
/// the summary field dropped, the JSON assert fails; at the base, the line
/// listed every class whatever was deferred and omitted `ceilings`.
#[test]
fn check_output_carries_the_one_deferred_line() {
    kata_types::node_profile::mark_node_installed();
    kata_types::node_profile::clear_node_installation();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("deferred.star");
    std::fs::write(
        &path,
        r#"researcher = stage(id = "researcher", agent = "researcher", prompt = "plan it")
probe = stage(id = "probe", agent = "shell", run = "true", sandbox = "s", timeout_ms = 30000)
workflow("deferred", root = [researcher, probe], sandbox_profiles = {"s": sandbox_profile(workspace = "ro", net = "host")})
"#,
    )
    .unwrap();
    let artifact = build_workflow_artifact_from_file(&path, &[])
        .expect("a node-less check defers rather than refuses");
    assert_eq!(
        artifact.deferred_node_facts,
        vec![
            "agents".to_owned(),
            "ceilings".to_owned(),
            "egress".to_owned()
        ],
        "the artifact records the deferred classes"
    );

    let summary = workflow_check_summary(&artifact, false);
    let rendered = render_workflow_check_text(&path, &artifact, &summary);
    let notes: Vec<&str> = rendered
        .lines()
        .filter(|line| line.starts_with("note:"))
        .collect();
    assert_eq!(
        notes,
        vec![
            "note: not judged without a booted node: agents, ceilings, egress — a booted node \
             judges them at admission; --config <kata.toml> judges all but environment"
        ],
        "the text surface carries the one deferred line, naming exactly the deferred \
         classes: {rendered}"
    );

    let value = workflow_check_json_value(&path, &artifact, &summary);
    assert_eq!(
        value["check"]["deferred_node_facts"],
        serde_json::json!(["agents", "ceilings", "egress"]),
        "the json surface carries the deferred classes"
    );
}

/// `kata check --config <kata.toml>` installs every node fact a config states
/// — but not the bound environment's `PATH` programs, which a node resolves
/// from its store at boot. The door that reads those programs — a stage
/// authoring `sandbox_profile(requires = [..])` — is therefore NOT judged
/// under `--config`, and the check names `environment` rather than pass it
/// silently; the other classes are judged and not named. The note does not
/// point the `--config` check back at `--config`: it names only what a booted
/// node would judge.
///
/// **Watched red:** at the base the `--config` check deferred nothing and
/// printed no note, so a pack requiring a program the node's environment lacks
/// passed with no word that the requirement went unjudged.
#[test]
fn a_config_check_names_the_environment_it_did_not_judge() {
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("kata.toml");
    std::fs::write(
        &config,
        format!(
            r#"
[node]
id = "p3-config-check"
data_dir = "{data}"

[workers]
transports = [{{ type = "supervised_node" }}]
dispatch_deadline_ms = 5000
heartbeat_interval_ms = 2500
heartbeat_grace_ms = 10000
max_workers = 4

[api]
bind = "127.0.0.1:8400"
auth = {{ type = "signed_token", verifying_key_env = "API_VERIFYING_KEY" }}

[agents.codex]
adapter = "nanocode_openai"
credential = {{ mode = "subscription", source = "kata_login" }}
"#,
            data = dir.path().join("data").display(),
        ),
    )
    .unwrap();
    install_node_facts_from_config_flag(Some(&config)).expect("the config installs");
    const NOTE: &str = "note: not judged without a booted node: environment — a booted node \
                        judges them at admission";
    let path = dir.path().join("requires.star");
    std::fs::write(
        &path,
        r#"probe = stage(id = "probe", agent = "shell", run = "git status", sandbox = "s")
workflow("requires", root = [probe], sandbox_profiles = {"s": sandbox_profile(workspace = "ro", requires = ["git"])})
"#,
    )
    .unwrap();
    let artifact = build_workflow_artifact_from_file(&path, &[])
        .expect("the --config check cannot judge the requirement, so it does not refuse it");
    assert_eq!(
        artifact.deferred_node_facts,
        vec!["environment".to_owned()],
        "exactly the class --config cannot install is named"
    );
    let summary = workflow_check_summary(&artifact, false);
    let rendered = render_workflow_check_text(&path, &artifact, &summary);
    let notes: Vec<&str> = rendered
        .lines()
        .filter(|line| line.starts_with("note:"))
        .collect();
    assert_eq!(
        notes,
        vec![NOTE],
        "the text surface names the unjudged class: {rendered}"
    );

    let value = workflow_check_json_value(&path, &artifact, &summary);
    assert_eq!(
        value["check"]["deferred_node_facts"],
        serde_json::json!(["environment"]),
        "the json surface names the unjudged class"
    );
}
