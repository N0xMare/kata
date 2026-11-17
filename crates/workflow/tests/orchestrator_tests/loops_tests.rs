//! Tests for crates/program/src/loops.rs.
//!
//! `loops` exposes its helpers as `pub(crate)` only, so these tests use the
//! `loops::testing` module's `#[doc(hidden)] pub` accessors to probe the
//! iteration-stage-name helpers. (The reviewer verdict vocabulary lives in
//! `kata_types::review_loop::LoopVerdictConfig`/`ControllerDecision`, covered
//! by `kata-types` unit tests.)

use kata_program::loops::testing as loops_testing;
use smol_str::SmolStr;

#[test]
fn iteration_stage_name_zero_preserves_base() {
    let base = SmolStr::new("implement");
    assert_eq!(loops_testing::iteration_stage_name(&base, 0), base);
}

#[test]
fn iteration_stage_name_nonzero_adds_suffix() {
    let base = SmolStr::new("implement");
    assert_eq!(
        loops_testing::iteration_stage_name(&base, 1).as_str(),
        "implement#iter-1"
    );
    assert_eq!(
        loops_testing::iteration_stage_name(&base, 42).as_str(),
        "implement#iter-42"
    );
}

#[test]
fn parse_iteration_round_trips() {
    assert_eq!(
        loops_testing::parse_iteration("implement#iter-2"),
        Some(("implement", 2))
    );
    assert_eq!(
        loops_testing::parse_iteration("foo#iter-0"),
        Some(("foo", 0))
    );
}

#[test]
fn parse_iteration_rejects_malformed() {
    assert_eq!(loops_testing::parse_iteration("implement"), None);
    assert_eq!(loops_testing::parse_iteration("implement#iter-"), None);
    assert_eq!(loops_testing::parse_iteration("implement#iter-abc"), None);
    // We only split on the rightmost `#iter-`, so a stage name
    // that legitimately contains `#iter-` still resolves.
    assert_eq!(
        loops_testing::parse_iteration("run#iter-1#iter-3"),
        Some(("run#iter-1", 3))
    );
}

#[test]
fn base_stage_name_strips_iteration() {
    assert_eq!(
        loops_testing::base_stage_name(&SmolStr::new("worker#iter-5")),
        SmolStr::new("worker")
    );
    assert_eq!(
        loops_testing::base_stage_name(&SmolStr::new("worker")),
        SmolStr::new("worker")
    );
}

#[test]
fn iteration_of_returns_zero_for_unadorned() {
    assert_eq!(loops_testing::iteration_of(&SmolStr::new("foo")), 0);
    assert_eq!(loops_testing::iteration_of(&SmolStr::new("foo#iter-7")), 7);
}
