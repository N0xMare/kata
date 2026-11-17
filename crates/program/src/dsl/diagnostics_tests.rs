//! Unit + golden tests for the load-time DSL diagnostics.

use super::*;
use crate::dsl::catalog::{DslParamKind, dsl_catalog};

/// Render span-LESS diagnostics (the render goldens exercise the format,
/// not the call-site span). A diagnostic with `span == None` renders with no
/// location prefix.
fn render(diags: Vec<DslDiagnostic>) -> String {
    render_report(
        &diags
            .into_iter()
            .map(|diag| SpannedDiagnostic { span: None, diag })
            .collect::<Vec<_>>(),
    )
}

/// The named keywords of a catalog builtin, reflected from its live
/// `#[starlark_module]` signature (excludes the positional `name` and the
/// `**kwargs` catch-all).
fn reflected_named_kwargs(builtin: &str) -> Vec<String> {
    let catalog = dsl_catalog();
    let b = catalog
        .builtins
        .iter()
        .find(|b| b.name == builtin)
        .unwrap_or_else(|| panic!("catalog must contain {builtin:?}"));
    let mut names: Vec<String> = b
        .params
        .iter()
        .filter(|p| p.kind == DslParamKind::NamedOnly)
        .map(|p| p.name.clone())
        .collect();
    names.sort();
    names
}

/// FAIL-CLOSED: the hand-maintained [`STAGE_KWARGS`] menu must exactly match the
/// live `stage()` signature. A newly-added `stage()` keyword that forgets to
/// update the menu fails HERE rather than shipping a suggestion list that omits
/// the real keyword.
#[test]
fn stage_kwargs_match_signature() {
    let reflected = reflected_named_kwargs("stage");
    let declared: Vec<String> = STAGE_KWARGS.iter().map(|s| (*s).to_owned()).collect();
    assert_eq!(
        declared, reflected,
        "STAGE_KWARGS is out of sync with the stage() signature; \
         update the const in diagnostics.rs"
    );
}

/// FAIL-CLOSED counterpart for [`WORKFLOW_KWARGS`].
#[test]
fn workflow_kwargs_match_signature() {
    let reflected = reflected_named_kwargs("workflow");
    let declared: Vec<String> = WORKFLOW_KWARGS.iter().map(|s| (*s).to_owned()).collect();
    assert_eq!(
        declared, reflected,
        "WORKFLOW_KWARGS is out of sync with the workflow() signature; \
         update the const in diagnostics.rs"
    );
    // And `name`, the first positional argument, is intentionally NOT in the
    // named-keyword menu.
    assert!(
        !WORKFLOW_KWARGS.contains(&"name"),
        "workflow name is positional, not a named keyword"
    );
}

/// Three observed authoring stumbles each resolve to their correct keyword.
#[test]
fn suggest_covers_the_three_live_stumbles() {
    assert_eq!(
        suggest("stage", "model", STAGE_KWARGS),
        Some("model_hint"),
        "stumble 1: model → model_hint"
    );
    assert_eq!(
        suggest("workflow", "stages", WORKFLOW_KWARGS),
        Some("root"),
        "stumble 3: stages → root"
    );
    // Stumble 2 (positional name) is handled structurally, not by `suggest`.
}

/// Prefix + edit-distance fallbacks catch ordinary typos, and a truly unrelated
/// keyword yields no false suggestion.
#[test]
fn suggest_prefix_typo_and_no_match() {
    // Prefix of the real keyword.
    assert_eq!(suggest("stage", "prod", STAGE_KWARGS), Some("produces"));
    // One-edit typo.
    assert_eq!(
        suggest("stage", "modl_hint", STAGE_KWARGS),
        Some("model_hint")
    );
    assert_eq!(
        suggest("workflow", "descriptn", WORKFLOW_KWARGS),
        Some("description")
    );
    // Nothing close: no suggestion (the accepted menu still guides the author).
    assert_eq!(suggest("stage", "xyzzy_nonsense", STAGE_KWARGS), None);
}

#[test]
fn levenshtein_basic() {
    assert_eq!(levenshtein("", ""), 0);
    assert_eq!(levenshtein("model_hint", "model_hint"), 0);
    assert_eq!(levenshtein("modl_hint", "model_hint"), 1);
    assert_eq!(levenshtein("kitten", "sitting"), 3);
}

// ---------------------------------------------------------------------------
// Golden reports — the EXACT rendered diagnostics for each live stumble, pinned.
// ---------------------------------------------------------------------------

const STAGE_MENU: &str = "accepted stage() keywords: agent, allowed_tools, approval, approval_reason, body, cache_policy, consumes, cost_budget, depends_on, execution_requirements, exit_policy, id, label, model_hint, op, output_bytes, outputs, produces, produces_files, progress_visibility, prompt, reads, required_capabilities, run, sandbox, timeout_ms, title, topology, validate_feedback_template, validate_retries, work_delta_bytes, work_delta_entries";
const WORKFLOW_MENU: &str = "accepted workflow() keywords: bounds, cost_budget, description, external_input_channels, human_requests, max_concurrency, max_external_input_channels, max_human_requests, max_memory_selectors, max_memory_writebacks, memory_selectors, memory_writebacks, params, root, sandbox_profiles, tags, validation_criteria, version, workflow_pattern, worktree_isolated\n  (plus the workflow name as the first positional argument: workflow(\"name\", root=...))";

#[test]
fn golden_stumble_1_stage_model() {
    let report = render(vec![DslDiagnostic::UnknownKwarg {
        func: "stage",
        key: "model".to_owned(),
        suggestion: Some("model_hint"),
    }]);
    let expected = format!(
        "kata workflow DSL: 1 definition error found — fix it, then re-check:\n  \
         ✗ stage() got an unknown keyword `model`; did you mean `model_hint`?\n{STAGE_MENU}"
    );
    assert_eq!(report, expected);
}

#[test]
fn golden_stumble_2_workflow_name_positional() {
    let report = render(vec![DslDiagnostic::WorkflowName {
        given_as_kwarg: true,
    }]);
    let expected = "kata workflow DSL: 1 definition error found — fix it, then re-check:\n  \
         ✗ workflow()'s name is the first POSITIONAL argument, not a keyword — \
         write workflow(\"my-workflow\", root=...)";
    assert_eq!(report, expected);
}

#[test]
fn golden_stumble_3_workflow_stages_root() {
    let report = render(vec![DslDiagnostic::UnknownKwarg {
        func: "workflow",
        key: "stages".to_owned(),
        suggestion: Some("root"),
    }]);
    let expected = format!(
        "kata workflow DSL: 1 definition error found — fix it, then re-check:\n  \
         ✗ workflow() got an unknown keyword `stages`; did you mean `root`?\n{WORKFLOW_MENU}"
    );
    assert_eq!(report, expected);
}

/// Collect-all: a report gathering multiple unknown keywords across both
/// builtins renders every error plus each builtin's accepted menu, once.
#[test]
fn golden_collect_all_multi_error() {
    let report = render(vec![
        DslDiagnostic::UnknownKwarg {
            func: "stage",
            key: "model".to_owned(),
            suggestion: Some("model_hint"),
        },
        DslDiagnostic::UnknownKwarg {
            func: "stage",
            key: "modl_hint".to_owned(),
            suggestion: Some("model_hint"),
        },
        DslDiagnostic::UnknownKwarg {
            func: "workflow",
            key: "stages".to_owned(),
            suggestion: Some("root"),
        },
    ]);
    let expected = format!(
        "kata workflow DSL: 3 definition errors found — fix all of them, then re-check:\n  \
         ✗ stage() got an unknown keyword `model`; did you mean `model_hint`?\n  \
         ✗ stage() got an unknown keyword `modl_hint`; did you mean `model_hint`?\n  \
         ✗ workflow() got an unknown keyword `stages`; did you mean `root`?\n\
         {STAGE_MENU}\n{WORKFLOW_MENU}"
    );
    assert_eq!(report, expected);
}

/// A name supplied both positionally and as a `name=` keyword renders a targeted
/// "drop the keyword" diagnostic instead of silently dropping the redundant
/// keyword (defect fix: no swallowed double-spec).
#[test]
fn golden_duplicate_workflow_name() {
    let report = render(vec![DslDiagnostic::DuplicateWorkflowName]);
    let expected = "kata workflow DSL: 1 definition error found — fix it, then re-check:\n  \
         ✗ workflow() got its name both positionally and as a `name=` keyword — \
         drop the name= keyword; the first positional argument is the name";
    assert_eq!(report, expected);
}

/// An unknown keyword with no close match still renders, pointing the author at
/// the accepted menu below.
#[test]
fn golden_no_close_match() {
    let report = render(vec![DslDiagnostic::UnknownKwarg {
        func: "stage",
        key: "xyzzy".to_owned(),
        suggestion: None,
    }]);
    let expected = format!(
        "kata workflow DSL: 1 definition error found — fix it, then re-check:\n  \
         ✗ stage() got an unknown keyword `xyzzy` (no close match — see the accepted keywords below)\n{STAGE_MENU}"
    );
    assert_eq!(report, expected);
}
