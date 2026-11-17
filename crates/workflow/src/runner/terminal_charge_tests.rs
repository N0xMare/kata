//! The RESUME/OLD-ROW safety of the terminal-charge vocabulary:
//!
//! * a completed envelope whose `child_invocation_summary` has no `metering`
//!   key (a pre-change record) is skipped, never failed closed;
//! * a `TerminalCharge` with no `token_usage` (a child-summary-only charge)
//!   states NO direct spend — never an unmeterable one;
//! * a DISPATCHED attempt's failure-class frame that recorded no charge at
//!   all is read as UNKNOWN — through the delivery mapper, the one decoder —
//!   so a hard policy fails closed on it rather than counting it `0`;
//! * and the fail-closed gate fires exactly on `Unavailable` + hard policy,
//!   on the charge's own usage AND on the child summary's unmetered list.

use kata_types::budget::BudgetPolicy;
use kata_types::metering::{
    ChildInvocationSummary, MeteredCost, MeteringSummary, StageUsage, TerminalCharge,
    UnmeteredStage,
};
use smol_str::SmolStr;

use super::{StageHaltTrip, WorkflowRunner};

const HARD: bool = true;

fn unmetered_usage() -> StageUsage {
    StageUsage::unmetered("claude_code", "claude-sonnet-4-6")
}

/// A `MeteringSummary` with one unmetered child stage.
fn metering_with_unmetered(stage: &str) -> MeteringSummary {
    MeteringSummary {
        unmetered_stages: 1,
        unmetered: vec![UnmeteredStage {
            stage: stage.to_string(),
            backend: "claude_code".to_string(),
            model: "claude-sonnet-4-6".to_string(),
        }],
        ..MeteringSummary::default()
    }
}

/// The hard-policy spelling of the charge gate for a workflow carrying a
/// `cost_bound` (which is what `has_cost_bound = true` models): every trip
/// below is evaluated under `Hard`.
#[test]
fn an_unmetered_charge_fails_closed_only_under_a_hard_policy() {
    let charge = TerminalCharge {
        token_usage: Some(unmetered_usage()),
        child_invocation_summary: None,
    };
    let trip = WorkflowRunner::check_charge_metering_enforceable(
        &SmolStr::new("draft"),
        &charge,
        BudgetPolicy::Unlimited,
        BudgetPolicy::Unlimited,
        HARD,
    );
    match trip {
        Some(StageHaltTrip::MeteringUnavailable {
            stage,
            backend,
            model,
        }) => {
            assert_eq!(stage.as_str(), "draft");
            assert_eq!(backend.as_str(), "claude_code");
            assert_eq!(model.as_str(), "claude-sonnet-4-6");
        }
        other => panic!("expected MeteringUnavailable, got {other:?}"),
    }

    // The SAME charge under warn and no policy: recorded, never halted.
    for (wf, st) in [
        (
            BudgetPolicy::Warn { limit_micro_usd: 1 },
            BudgetPolicy::Unlimited,
        ),
        (BudgetPolicy::Unlimited, BudgetPolicy::Unlimited),
    ] {
        assert!(
            WorkflowRunner::check_charge_metering_enforceable(
                &SmolStr::new("draft"),
                &charge,
                wf,
                st,
                false,
            )
            .is_none(),
            "no hard policy: the unmetered charge is recorded, never a halt"
        );
    }
}

/// A charge with NO `token_usage` — the child-summary-only shape a failed
/// `Invoke` parent carries — states no direct spend, and never fails closed
/// on its own.
#[test]
fn a_charge_without_token_usage_states_no_direct_spend() {
    let charge = TerminalCharge {
        token_usage: None,
        child_invocation_summary: None,
    };
    assert!(
        WorkflowRunner::check_charge_metering_enforceable(
            &SmolStr::new("sub"),
            &charge,
            BudgetPolicy::Unlimited,
            BudgetPolicy::Unlimited,
            HARD,
        )
        .is_none()
    );
}

/// A KNOWN charge — authoritative or estimated — never trips the gate under
/// any policy.
#[test]
fn a_known_charge_never_fails_closed() {
    for cost in [
        MeteredCost::Authoritative { micro_usd: 0 },
        MeteredCost::Authoritative { micro_usd: 400 },
        MeteredCost::Estimated {
            micro_usd: 400,
            basis: kata_types::metering::EstimateBasis::UnknownModelFloor {
                model: SmolStr::new("m"),
            },
        },
    ] {
        let usage = StageUsage::metered(&kata_types::cache::TokenUsage::default(), cost, 0);
        let charge = TerminalCharge {
            token_usage: Some(usage),
            child_invocation_summary: None,
        };
        assert!(
            WorkflowRunner::check_charge_metering_enforceable(
                &SmolStr::new("draft"),
                &charge,
                BudgetPolicy::Halt { limit_micro_usd: 1 },
                BudgetPolicy::Unlimited,
                HARD,
            )
            .is_none(),
            "a known charge is enforceable everywhere"
        );
    }
}

/// A child-summary-only charge whose summary reports an unmetered stage DOES
/// fail closed — re-rooted under the parent stage's name (`sub/inner`), the
/// same shape the completed-envelope check produces.
#[test]
fn a_child_summary_unmetered_charge_fails_closed_re_rooted() {
    let charge = TerminalCharge {
        token_usage: None,
        child_invocation_summary: Some(ChildInvocationSummary {
            token_usage: kata_types::metering::ChildInvocationUsage { cost_micro_usd: 5 },
            metering: Some(metering_with_unmetered("inner")),
        }),
    };
    let trip = WorkflowRunner::check_charge_metering_enforceable(
        &SmolStr::new("sub"),
        &charge,
        BudgetPolicy::Unlimited,
        BudgetPolicy::Unlimited,
        HARD,
    );
    match trip {
        Some(StageHaltTrip::MeteringUnavailable { stage, .. }) => {
            assert_eq!(stage.as_str(), "sub/inner");
        }
        other => panic!("expected MeteringUnavailable, got {other:?}"),
    }
}

/// (h) — a child summary with NO `metering` key — the shape every record
/// written before metering was recorded carries — is skipped, never failed closed. This is the
/// resume carve-out: an old parent envelope must not trip a new binary's
/// hard policy.
#[test]
fn a_child_summary_without_metering_is_skipped_never_failed() {
    // The envelope-level gate (completions).
    let envelope = serde_json::json!({
        "child_execution_id": "01ARZ3NDEKTSV4RRFFQ69G5FAV",
        "outputs": {},
        "child_invocation_summary": {
            "token_usage": { "cost_micro_usd": 5 },
        },
    });
    assert!(
        WorkflowRunner::check_metering_enforceable(
            &SmolStr::new("sub"),
            &envelope,
            BudgetPolicy::Halt { limit_micro_usd: 1 },
            BudgetPolicy::Unlimited,
            HARD,
        )
        .is_none(),
        "a pre-change child summary must not fail closed on resume"
    );

    // And the typed-charge twin.
    let charge = TerminalCharge {
        token_usage: None,
        child_invocation_summary: Some(ChildInvocationSummary {
            token_usage: kata_types::metering::ChildInvocationUsage { cost_micro_usd: 5 },
            metering: None,
        }),
    };
    assert!(
        WorkflowRunner::check_charge_metering_enforceable(
            &SmolStr::new("sub"),
            &charge,
            BudgetPolicy::Halt { limit_micro_usd: 1 },
            BudgetPolicy::Unlimited,
            HARD,
        )
        .is_none(),
        "a child summary with no metering key is skipped, never failed"
    );
}

/// The `unbilled` charge a provably-unbilled stage (shell, workspace effect)
/// writes is `Authoritative{0}` — chargeable `0`, no unmetered entry, and
/// `envelope_cost_micro_usd` reads it as the `0` it is.
#[test]
fn an_unbilled_charge_is_an_authoritative_zero_not_a_warning() {
    let charge = TerminalCharge {
        token_usage: Some(StageUsage::unbilled()),
        child_invocation_summary: None,
    };
    assert!(
        WorkflowRunner::check_charge_metering_enforceable(
            &SmolStr::new("shell-stage"),
            &charge,
            BudgetPolicy::Halt { limit_micro_usd: 1 },
            BudgetPolicy::Unlimited,
            HARD,
        )
        .is_none(),
        "a provably-free stage must not metering-halt"
    );
    assert_eq!(
        kata_types::metering::envelope_cost_micro_usd(&charge.envelope()),
        0,
        "the unbilled charge reads as the 0 it is"
    );
}

/// The failed attempt frame the E-prep fake-vendor run recorded for a killed worker
/// (ledger `agent-ambiguous`, transition 7): `delivery` + `reason` and NO
/// `terminal_charge`, verbatim but for the dispatch instant, which `dispatched`
/// decides.
fn charge_less_failed_frame(dispatched: bool) -> kata_core::operational::chain::TransitionFrame {
    let payload = serde_json::json!({
        "delivery": {
            "awaiting_approval_at_ms": null,
            "child_execution_id": null,
            "dispatched_at_ms": if dispatched { serde_json::json!(1_793_637_012_242_i64) } else { serde_json::Value::Null },
            "finished_at_ms": 1_793_637_012_588_i64,
            "last_checkpoint": 0,
            "stage_name": "implement",
            "started_at_ms": 1_793_637_012_249_i64,
            "worker_id": "local-worker-0",
        },
        "reason": "worker local-worker-0 died. PROVEN AMBIGUOUS: the main cannot observe \
                   whether this capsule's container ran, so the stage may have done anything \
                   it was asked. The attempt is settled terminal and NOT re-delivered \
                   (capsule re-delivery is not implemented)",
    });
    kata_core::operational::chain::TransitionFrame {
        seq: 7,
        execution_id: ulid::Ulid::new(),
        scope: kata_core::operational::chain::ChainScope::Attempt,
        stage_id: Some("implement".to_owned()),
        attempt_ordinal: Some(0),
        attempt_id: Some(ulid::Ulid::new()),
        kind: "attempt_advanced".to_owned(),
        resulting_state: "failed".to_owned(),
        folds_projection: true,
        payload_json: serde_json::to_vec(&payload).unwrap(),
        recorded_at_ms: 1_793_637_012_588,
    }
}

/// The charge the RUNNER'S FOLD reads off `frame` — through the delivery mapper and the
/// fold decode, exactly the path `fold_to_head` takes.
fn folded_charge(frame: &kata_core::operational::chain::TransitionFrame) -> Option<TerminalCharge> {
    let crate::attempt_delivery::FrameDelivery::Delivery(delivery) =
        crate::attempt_delivery::envelope_for(frame).expect("the frame maps")
    else {
        panic!("a failed attempt frame is a delivery");
    };
    crate::attempt_delivery::foldable_frame(&delivery)
        .expect("the envelope folds")
        .event
        .terminal_charge
}

/// **A DISPATCHED attempt's failure frame with NO charge is read as UNKNOWN, and a hard
/// policy fails closed on it.** The frame shape is the one the E-prep run recorded for a
/// killed worker: the worker may have issued its turn, and nothing says what it spent.
/// The never-dispatched twin owes no charge and is read as owing none.
///
/// **Would red if:** the mapper copied the absent charge through as `None` (the runner's
/// fold skips it and a hard `cost_bound` under-counts — the defect), or read it as `0`.
#[test]
fn a_dispatched_attempts_charge_less_failure_is_read_as_unknown_and_fails_closed() {
    let charge = folded_charge(&charge_less_failed_frame(true))
        .expect("a dispatched attempt's terminal is charged");
    let trip = WorkflowRunner::check_charge_metering_enforceable(
        &SmolStr::new("implement"),
        &charge,
        BudgetPolicy::Unlimited,
        BudgetPolicy::Unlimited,
        HARD,
    );
    assert!(
        matches!(trip, Some(StageHaltTrip::MeteringUnavailable { ref stage, .. }) if stage == "implement"),
        "{trip:?}"
    );
    assert_eq!(
        kata_types::metering::envelope_cost_micro_usd(&charge.envelope()),
        0,
        "an unknown charge adds no number to the known sum"
    );
    assert_eq!(
        folded_charge(&charge_less_failed_frame(false)),
        None,
        "a never-dispatched attempt owes no charge"
    );
}
