//! Tests for crates/program/src/orchestrator.rs. Extracted from the inline #[cfg(test)] module.

use kata_program::orchestrator::StageState;
use smol_str::SmolStr;

mod common;
use common::make_definition;

#[test]
fn new_orchestrator_all_pending() {
    let def = make_definition(&[("a", &[]), ("b", &["a"])]);
    let orch = common::orchestrator_from_checked_test_definition(&def).unwrap();
    assert!(matches!(orch.stage_state("a"), Some(StageState::Pending)));
    assert!(matches!(orch.stage_state("b"), Some(StageState::Pending)));
}

#[test]
fn advance_returns_root_stages() {
    let def = make_definition(&[("a", &[]), ("b", &["a"]), ("c", &["a"])]);
    let orch = common::orchestrator_from_checked_test_definition(&def).unwrap();
    let ready = orch.advance();
    assert_eq!(ready, vec![SmolStr::new("a")]);
    assert!(matches!(orch.stage_state("a"), Some(StageState::Ready)));
}

#[test]
fn advance_unlocks_successors_after_completion() {
    let def = make_definition(&[("a", &[]), ("b", &["a"]), ("c", &["a"])]);
    let orch = common::orchestrator_from_checked_test_definition(&def).unwrap();

    // First advance: a becomes ready.
    let ready = orch.advance();
    assert_eq!(ready.len(), 1);

    // Complete a.
    orch.complete_stage("a", serde_json::json!({"ok": true}))
        .unwrap();

    // Second advance: b and c become ready.
    let mut ready = orch.advance();
    ready.sort();
    assert_eq!(ready, vec![SmolStr::new("b"), SmolStr::new("c")]);
}

#[test]
fn is_finished_when_all_complete() {
    let def = make_definition(&[("a", &[])]);
    let orch = common::orchestrator_from_checked_test_definition(&def).unwrap();
    assert!(!orch.is_finished());

    orch.advance();
    orch.complete_stage("a", serde_json::json!(null)).unwrap();
    assert!(orch.is_finished());
}

#[test]
fn is_finished_when_failed() {
    let def = make_definition(&[("a", &[])]);
    let orch = common::orchestrator_from_checked_test_definition(&def).unwrap();
    orch.advance();
    orch.fail_stage("a", "broken".into()).unwrap();
    assert!(orch.is_finished());
}

#[test]
fn complete_unknown_stage_errors() {
    let def = make_definition(&[("a", &[])]);
    let orch = common::orchestrator_from_checked_test_definition(&def).unwrap();
    let err = orch
        .complete_stage("nonexistent", serde_json::json!(null))
        .unwrap_err();
    assert!(err.to_string().contains("unknown stage"));
}

#[test]
fn fail_stage_increments_retries() {
    let def = make_definition(&[("a", &[])]);
    let orch = common::orchestrator_from_checked_test_definition(&def).unwrap();
    orch.advance();
    orch.fail_stage("a", "first".into()).unwrap();

    if let Some(StageState::Failed { retries, .. }) = orch.stage_state("a") {
        assert_eq!(retries, 0);
    } else {
        panic!("expected Failed state");
    }

    orch.fail_stage("a", "second".into()).unwrap();
    if let Some(StageState::Failed { retries, .. }) = orch.stage_state("a") {
        assert_eq!(retries, 1);
    } else {
        panic!("expected Failed state");
    }
}

#[test]
fn cannot_complete_pending_stage() {
    let def = make_definition(&[("a", &[]), ("b", &["a"])]);
    let orch = common::orchestrator_from_checked_test_definition(&def).unwrap();
    // b is still Pending (a hasn't been completed).
    let err = orch
        .complete_stage("b", serde_json::json!(null))
        .unwrap_err();
    assert!(err.to_string().contains("cannot complete"));
}

/// A transition refusal must NAME the state that blocked it.
///
/// Every refusal in `orchestrator.rs` formatted `std::mem::discriminant(other)`,
/// which renders as `Discriminant(5)` — a compiler-assigned index that is not a
/// stable API, is documented nowhere, and shifts the moment a `StageState`
/// variant is added or reordered. No operator can map it to a state, and neither
/// can the engineer holding the failing log.
///
/// `cannot_complete_pending_stage` above is satisfied by that rendering — it
/// asserts the VERB (`"cannot complete"`) and never the state — which is exactly
/// how seven sites kept an unreadable message with test coverage over them.
///
/// The cost was measured, not hypothetical: a worker-death migration flake
/// reported `cannot complete stage "solo" in state Discriminant(5)`, and the
/// index had to be decoded by counting variants in the enum to learn it meant
/// `Failed` — a late completion landing after the stage had already failed, which
/// is the entire diagnosis. The message held the answer and would not say it.
///
/// RED counterfactual: restore `std::mem::discriminant(other)` (with `{:?}`) at
/// any of the seven sites in `crates/program/src/orchestrator.rs`; the matching
/// assertion below fails on the `Discriminant(...)` rendering.
#[test]
fn transition_refusals_name_the_blocking_state_not_a_discriminant_index() {
    let def = make_definition(&[("a", &[]), ("b", &["a"])]);
    let orch = common::orchestrator_from_checked_test_definition(&def).unwrap();

    // `b` is Pending — `a` has not completed.
    let err = orch
        .complete_stage("b", serde_json::json!(null))
        .unwrap_err()
        .to_string();
    assert!(
        err.contains("Pending"),
        "the refusal must NAME the blocking state, got: {err}"
    );
    assert!(
        !err.contains("Discriminant"),
        "the refusal must not leak a compiler discriminant index, got: {err}"
    );

    // `Failed` — a state a discriminant-leaking renderer prints as `Discriminant(5)`.
    // `advance()` first: `fail_stage` refuses a Pending stage, and the refusal it
    // raises ("cannot fail stage \"a\" in state Pending") itself names the state
    // instead of printing `Discriminant(0)`.
    orch.advance();
    orch.fail_stage("a", "broken".into()).unwrap();
    let err = orch
        .complete_stage("a", serde_json::json!(null))
        .unwrap_err()
        .to_string();
    assert!(
        err.contains("Failed"),
        "the refusal must NAME the blocking state, got: {err}"
    );
    assert!(
        !err.contains("Discriminant"),
        "the refusal must not leak a compiler discriminant index, got: {err}"
    );
}

#[test]
fn stage_state_returns_none_for_unknown() {
    let def = make_definition(&[("a", &[])]);
    let orch = common::orchestrator_from_checked_test_definition(&def).unwrap();
    assert!(orch.stage_state("nonexistent").is_none());
}

#[test]
fn pause_stage_for_approval_transitions_ready_to_paused() {
    let def = make_definition(&[("a", &[])]);
    let orch = common::orchestrator_from_checked_test_definition(&def).unwrap();
    orch.advance();
    orch.pause_stage_for_approval("a", "needs review".into())
        .unwrap();
    match orch.stage_state("a") {
        Some(StageState::AwaitingApproval { reason }) => {
            assert_eq!(reason, "needs review");
        }
        other => panic!("expected AwaitingApproval, got {other:?}"),
    }
    // Non-terminal: workflow not finished while paused.
    assert!(!orch.is_finished());
}

#[test]
fn pause_stage_for_approval_rejects_pending() {
    let def = make_definition(&[("a", &[])]);
    let orch = common::orchestrator_from_checked_test_definition(&def).unwrap();
    // Pending (not yet advanced) is not a valid source.
    let err = orch
        .pause_stage_for_approval("a", "reason".into())
        .unwrap_err();
    assert!(err.to_string().contains("cannot pause"));
}

/// Dispatched → awaiting_approval is the loop-escalate-mid-iter
/// case. The runner's loop runtime calls `pause_stage_for_approval`
/// from `OnMaxAction::Escalate` when the worker is still in
/// `Dispatched { worker_id }` from the synthetic last iteration.
///
/// Reach `Dispatched` via the AwaitingApproval → Dispatched arrow
/// since `Orchestrator` has no public `Ready → Dispatched` method
/// (the runner transitions through `apply_event` internally).
#[test]
fn pause_stage_for_approval_transitions_dispatched_to_paused() {
    let def = make_definition(&[("a", &[])]);
    let orch = common::orchestrator_from_checked_test_definition(&def).unwrap();
    orch.advance();
    orch.pause_stage_for_approval("a", "first".into()).unwrap();
    orch.dispatch_stage_after_approval("a", Some(SmolStr::new("w1")))
        .unwrap();
    // Now in `Dispatched { worker_id: Some("w1") }`.
    orch.pause_stage_for_approval("a", "escalated mid-loop".into())
        .unwrap();
    match orch.stage_state("a") {
        Some(StageState::AwaitingApproval { reason }) => {
            assert_eq!(reason, "escalated mid-loop");
        }
        other => panic!("expected AwaitingApproval, got {other:?}"),
    }
}

/// Completed → awaiting_approval is the loop-escalate-after-
/// iter-N case. The last iteration's terminal already landed and the
/// worker is `Completed`; the operator-blocker pause synthesizes a
/// gate on the otherwise-finished stage.
#[test]
fn pause_stage_for_approval_transitions_completed_to_paused() {
    let def = make_definition(&[("a", &[])]);
    let orch = common::orchestrator_from_checked_test_definition(&def).unwrap();
    orch.advance();
    orch.complete_stage("a", serde_json::json!({"iter": "final"}))
        .unwrap();
    orch.pause_stage_for_approval("a", "review final iteration".into())
        .unwrap();
    match orch.stage_state("a") {
        Some(StageState::AwaitingApproval { reason }) => {
            assert_eq!(reason, "review final iteration");
        }
        other => panic!("expected AwaitingApproval, got {other:?}"),
    }
}

/// Idempotent double-pause is an error — callers should learn about
/// it rather than silently accept it.
#[test]
fn pause_stage_for_approval_rejects_already_paused() {
    let def = make_definition(&[("a", &[])]);
    let orch = common::orchestrator_from_checked_test_definition(&def).unwrap();
    orch.advance();
    orch.pause_stage_for_approval("a", "first pause".into())
        .unwrap();
    let err = orch
        .pause_stage_for_approval("a", "second pause".into())
        .unwrap_err();
    assert!(err.to_string().contains("cannot pause"));
}

/// Failed / Skipped / Completed-with-Skipped transitions cannot be
/// escalated for approval — those are terminal-with-error states and
/// asking the operator to "approve" them is meaningless.
#[test]
fn pause_stage_for_approval_rejects_failed() {
    let def = make_definition(&[("a", &[])]);
    let orch = common::orchestrator_from_checked_test_definition(&def).unwrap();
    orch.advance();
    orch.fail_stage("a", "boom".into()).unwrap();
    let err = orch
        .pause_stage_for_approval("a", "reason".into())
        .unwrap_err();
    assert!(err.to_string().contains("cannot pause"));
}

#[test]
fn dispatch_stage_after_approval_transitions_paused_to_dispatched() {
    let def = make_definition(&[("a", &[])]);
    let orch = common::orchestrator_from_checked_test_definition(&def).unwrap();
    orch.advance();
    orch.pause_stage_for_approval("a", "reason".into()).unwrap();
    orch.dispatch_stage_after_approval("a", Some(SmolStr::new("w1")))
        .unwrap();
    match orch.stage_state("a") {
        Some(StageState::Dispatched { worker_id }) => {
            assert_eq!(worker_id.as_deref(), Some("w1"));
        }
        other => panic!("expected Dispatched, got {other:?}"),
    }
}

#[test]
fn dispatch_stage_after_approval_rejects_non_paused() {
    let def = make_definition(&[("a", &[])]);
    let orch = common::orchestrator_from_checked_test_definition(&def).unwrap();
    orch.advance();
    let err = orch
        .dispatch_stage_after_approval("a", Some(SmolStr::new("w1")))
        .unwrap_err();
    assert!(err.to_string().contains("cannot dispatch-after-approval"));
}

#[test]
fn complete_stage_accepts_paused_source() {
    let def = make_definition(&[("a", &[])]);
    let orch = common::orchestrator_from_checked_test_definition(&def).unwrap();
    orch.advance();
    orch.pause_stage_for_approval("a", "reason".into()).unwrap();
    orch.complete_stage("a", serde_json::json!({"ok": true}))
        .unwrap();
    assert!(matches!(
        orch.stage_state("a"),
        Some(StageState::Completed { .. })
    ));
}

#[test]
fn fail_stage_accepts_paused_source() {
    let def = make_definition(&[("a", &[])]);
    let orch = common::orchestrator_from_checked_test_definition(&def).unwrap();
    orch.advance();
    orch.pause_stage_for_approval("a", "reason".into()).unwrap();
    orch.fail_stage("a", "rejected: no".into()).unwrap();
    assert!(matches!(
        orch.stage_state("a"),
        Some(StageState::Failed { .. })
    ));
}

// Small suites folded into this binary so each costs no link of its own. Each
// keeps its module, so its tests are named `<module>::<test>` here.
#[path = "orchestrator_tests/dag_tests.rs"]
mod dag_tests;
#[path = "orchestrator_tests/loops_tests.rs"]
mod loops_tests;
#[path = "orchestrator_tests/structured_io.rs"]
mod structured_io;
#[path = "orchestrator_tests/unsupported_provider_placement.rs"]
mod unsupported_provider_placement;
