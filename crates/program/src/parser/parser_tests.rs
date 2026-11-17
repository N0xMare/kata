//! Tests for the frontend-agnostic parser surface (file dispatch + shared
//! `validate`). Starlark is the only workflow frontend; the shared
//! normalize/validate logic rides the Starlark path, covered here and in
//! `crate::starlark_eval` / the `workflow_dsl_tests*` integration tests.

use std::path::Path;

use super::from_file_with_library_checked;
use kata_types::KataError;

#[test]
fn starlark_dispatches_to_evaluator() {
    // .star files dispatch to the Starlark evaluator. Passing a non-existent
    // path should yield an I/O error, not "not yet enabled".
    let path = Path::new("nonexistent.star");
    let err = from_file_with_library_checked(path, &[]).unwrap_err();
    assert!(
        matches!(err, KataError::Io(_)),
        "expected Io error for missing .star file, got: {err}"
    );
}

#[test]
fn unsupported_extension_returns_error() {
    for name in ["workflow.yaml", "workflow.json"] {
        let err = from_file_with_library_checked(Path::new(name), &[]).unwrap_err();
        assert!(err.to_string().contains("unsupported"), "{name}: {err}");
    }
}

#[test]
fn toml_extension_is_no_longer_supported() {
    // Starlark is the only frontend, so
    // a `.toml` workflow path is rejected as an unsupported format rather than
    // parsed.
    let err = from_file_with_library_checked(Path::new("workflow.toml"), &[]).unwrap_err();
    match err {
        KataError::Validation(msg) => assert!(
            msg.contains("unsupported") && msg.contains(".star"),
            "expected an unsupported-format validation error naming .star, got: {msg}"
        ),
        other => panic!("expected KataError::Validation, got {other:?}"),
    }
}

#[test]
fn cyclic_workflow_rejected_via_shared_validate() {
    // The shared `validate` builds the stage DAG and rejects cycles regardless of
    // frontend. Exercise it through the (single, Starlark) frontend.
    let err = crate::starlark_eval::evaluate_starlark_checked(
        r#"
a = stage(id = "a", depends_on = ["b"], prompt = "a")
b = stage(id = "b", depends_on = ["a"], prompt = "b")
workflow("cyclic", root = [a])
"#,
        "cyclic.star",
    )
    .unwrap_err();
    assert!(
        err.to_string().to_lowercase().contains("cycle"),
        "expected a cycle rejection, got: {err}"
    );
}
