//! Integration coverage for the workflow-library wire types.
//!
//! Uses the SDK's re-exported public types only.

use kata_client::{WorkflowFormat, WorkflowLibraryEntry, WorkflowSummary};

#[test]
fn workflow_format_serializes_lowercase() {
    assert_eq!(
        serde_json::to_string(&WorkflowFormat::Starlark).unwrap(),
        "\"starlark\""
    );
    assert_eq!(
        serde_json::to_string(&WorkflowFormat::Api).unwrap(),
        "\"api\""
    );
}

#[test]
fn workflow_library_entry_decodes() {
    let raw = serde_json::json!({
        "name": "self-review",
        "format": "starlark",
        "path": "/usr/local/lib/kata/workflows/self-review.star",
        "root_priority": 2u32,
    });
    let entry: WorkflowLibraryEntry = serde_json::from_value(raw).unwrap();
    assert_eq!(entry.name, "self-review");
    assert_eq!(entry.format, WorkflowFormat::Starlark);
}

#[test]
fn workflow_summary_decodes() {
    let raw = serde_json::json!({
        "name": "demo",
        "stages": 2usize,
        "edges": 1usize,
        "format": "starlark",
        "stage_names": ["draft", "review"],
    });
    let s: WorkflowSummary = serde_json::from_value(raw).unwrap();
    assert_eq!(
        s.stage_names,
        vec!["draft".to_string(), "review".to_string()]
    );
    assert_eq!(s.format, WorkflowFormat::Starlark);
    assert!(s.invocation_plan.is_none());
    assert!(s.execution_program.is_none());
    assert!(s.preflight.is_none());
}
