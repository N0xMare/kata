//! Tests for `crates/test-utils/src/workflow_helpers.rs`. Extracted
//! from the inline `#[cfg(test)]` module.

use kata_test_utils::simple_two_stage_workflow;
use kata_types::StageId;
use smol_str::SmolStr;

#[test]
fn simple_two_stage_is_valid() {
    let p = simple_two_stage_workflow();

    assert_eq!(p.stages.len(), 2);
    assert!(p.stages.contains_key(&StageId(SmolStr::new("draft"))));
    assert!(p.stages.contains_key(&StageId(SmolStr::new("review"))));

    assert_eq!(p.edges.len(), 1);
    assert_eq!(p.edges[0].from, StageId(SmolStr::new("draft")));
    assert_eq!(p.edges[0].to, StageId(SmolStr::new("review")));

    // The review stage has an input that references the draft stage.
    let review = &p.stages[&StageId(SmolStr::new("review"))];
    assert_eq!(review.inputs.len(), 1);
    assert_eq!(review.inputs[0].from, StageId(SmolStr::new("draft")));
}

#[test]
fn simple_two_stage_is_deterministic() {
    let a = simple_two_stage_workflow();
    let b = simple_two_stage_workflow();
    assert_eq!(a, b, "two calls must return identical definitions");
}
