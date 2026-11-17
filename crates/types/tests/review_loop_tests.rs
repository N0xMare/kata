//! Tests for `crates/types/src/review_loop.rs`. Extracted from the inline
//! `#[cfg(test)]` module.

use kata_types::bound::Bound;
use kata_types::review_loop::{OnMaxAction, ReviewLoop};
use smol_str::SmolStr;

#[test]
fn on_max_default_is_fail() {
    assert_eq!(OnMaxAction::default(), OnMaxAction::Fail);
}

#[test]
fn parse_on_max_variants() {
    assert_eq!(
        ReviewLoop::parse_on_max("escalate"),
        Some(OnMaxAction::Escalate)
    );
    assert_eq!(
        ReviewLoop::parse_on_max("accept"),
        Some(OnMaxAction::Accept)
    );
    assert_eq!(ReviewLoop::parse_on_max("fail"), Some(OnMaxAction::Fail));
    assert_eq!(ReviewLoop::parse_on_max("unknown"), None);
}

#[test]
fn on_max_serde_snake_case() {
    assert_eq!(
        serde_json::to_string(&OnMaxAction::Escalate).unwrap(),
        "\"escalate\""
    );
    assert_eq!(
        serde_json::to_string(&OnMaxAction::Accept).unwrap(),
        "\"accept\""
    );
    assert_eq!(
        serde_json::to_string(&OnMaxAction::Fail).unwrap(),
        "\"fail\""
    );
}

#[test]
fn review_loop_serde_roundtrip() {
    let rl = ReviewLoop {
        worker_stage: SmolStr::new("implement"),
        reviewer_stage: SmolStr::new("review"),
        max_iterations: 3,
        on_max: OnMaxAction::Escalate,
        bounds: Vec::new(),
        rollover_after_iterations: None,
        body_stages: Vec::new(),
        gate_verdict: None,
    };
    let json = serde_json::to_string(&rl).unwrap();
    let back: ReviewLoop = serde_json::from_str(&json).unwrap();
    assert_eq!(rl, back);
}

/// A `ReviewLoop` with no loop-scope bounds omits
/// the `bounds` field from its serialization entirely (skip_serializing_if), so
/// every review-loop pack without bounds hashes byte-identically.
#[test]
fn review_loop_empty_bounds_omitted_from_serialization() {
    let rl = ReviewLoop {
        worker_stage: SmolStr::new("implement"),
        reviewer_stage: SmolStr::new("review"),
        max_iterations: 3,
        on_max: OnMaxAction::Fail,
        bounds: Vec::new(),
        rollover_after_iterations: None,
        body_stages: Vec::new(),
        gate_verdict: None,
    };
    let json = serde_json::to_string(&rl).unwrap();
    assert!(
        !json.contains("bounds"),
        "empty bounds must be skipped from serialization; got {json}"
    );
}

/// A `ReviewLoop` carrying loop-scope bounds
/// round-trips through serde, and the bounds are recorded in canonical order
/// (`Time` before `Cost`).
#[test]
fn review_loop_with_bounds_roundtrips_in_canonical_order() {
    let rl = ReviewLoop {
        worker_stage: SmolStr::new("implement"),
        reviewer_stage: SmolStr::new("review"),
        max_iterations: 5,
        on_max: OnMaxAction::Escalate,
        // Canonical order is Time-before-Cost.
        bounds: vec![
            Bound::Time { ms: 60_000 },
            Bound::Cost {
                micro_usd: 5_000_000,
            },
        ],
        rollover_after_iterations: None,
        body_stages: Vec::new(),
        gate_verdict: None,
    };
    let json = serde_json::to_string(&rl).unwrap();
    assert!(
        json.contains("bounds"),
        "bounds must serialize when present"
    );
    let back: ReviewLoop = serde_json::from_str(&json).unwrap();
    assert_eq!(rl, back);
    assert_eq!(
        back.bounds,
        vec![
            Bound::Time { ms: 60_000 },
            Bound::Cost {
                micro_usd: 5_000_000,
            },
        ]
    );
}

// ---- gate verdict config ----

/// A `ReviewLoop` with no `gate_verdict` omits the field from serialization
/// entirely (`skip_serializing_if = "Option::is_none"`), so every existing
/// review-loop pack hashes byte-identically to pre-slice.
#[test]
fn review_loop_gate_verdict_none_omitted_from_serialization() {
    let rl = ReviewLoop {
        worker_stage: SmolStr::new("implement"),
        reviewer_stage: SmolStr::new("review"),
        max_iterations: 3,
        on_max: OnMaxAction::Fail,
        bounds: Vec::new(),
        rollover_after_iterations: None,
        body_stages: Vec::new(),
        gate_verdict: None,
    };
    let json = serde_json::to_string(&rl).unwrap();
    assert!(
        !json.contains("gate_verdict"),
        "None gate_verdict must be skipped from serialization; got {json}"
    );
    // The effective config falls back to the default vocabulary.
    let eff = rl.effective_gate_verdict();
    assert_eq!(eff.verdict_field.as_str(), "verdict");
    assert_eq!(eff.approve, vec![SmolStr::new("approve")]);
    assert_eq!(eff.refine, vec![SmolStr::new("refine")]);
    assert_eq!(eff.block, vec![SmolStr::new("block")]);
}

/// A custom verdict vocabulary round-trips through serde and classifies tags.
#[test]
fn review_loop_custom_gate_verdict_roundtrips_and_classifies() {
    use kata_types::review_loop::{LoopVerdictAction, LoopVerdictConfig};
    let cfg = LoopVerdictConfig::new(
        "decision",
        vec![SmolStr::new("promote")],
        vec![SmolStr::new("retry")],
        vec![SmolStr::new("abort")],
    )
    .unwrap();
    let rl = ReviewLoop {
        worker_stage: SmolStr::new("build"),
        reviewer_stage: SmolStr::new("controller"),
        max_iterations: 2,
        on_max: OnMaxAction::Fail,
        bounds: Vec::new(),
        rollover_after_iterations: None,
        body_stages: Vec::new(),
        gate_verdict: Some(cfg),
    };
    let json = serde_json::to_string(&rl).unwrap();
    assert!(json.contains("gate_verdict"));
    let back: ReviewLoop = serde_json::from_str(&json).unwrap();
    assert_eq!(rl, back);
    let eff = back.effective_gate_verdict();
    assert_eq!(eff.classify("promote"), Some(LoopVerdictAction::Approve));
    assert_eq!(eff.classify("retry"), Some(LoopVerdictAction::Refine));
    assert_eq!(eff.classify("abort"), Some(LoopVerdictAction::Block));
    assert_eq!(eff.classify("nope"), None);
}

/// `validate()` re-checks the invariants on a config that bypassed `new()`
/// (e.g. one deserialized from a pack with `pub` fields), so the load-time
/// checked-IR validator can reject a malformed gate_verdict at the checked
/// boundary rather than let an overlapping tag silently mis-route at runtime.
#[test]
fn gate_verdict_validate_catches_bypass_constructed_malformed_config() {
    use kata_types::review_loop::{LoopVerdictConfig, LoopVerdictConfigError};
    // Direct struct construction bypasses LoopVerdictConfig::new's checks.
    let overlapping = LoopVerdictConfig {
        verdict_field: SmolStr::new("verdict"),
        approve: vec![SmolStr::new("ship")],
        refine: vec![SmolStr::new("ship")], // overlaps `approve`
        block: vec![SmolStr::new("stop")],
    };
    assert!(matches!(
        overlapping.validate(),
        Err(LoopVerdictConfigError::OverlappingTag { .. })
    ));
    let empty_set = LoopVerdictConfig {
        verdict_field: SmolStr::new("verdict"),
        approve: vec![],
        refine: vec![SmolStr::new("again")],
        block: vec![SmolStr::new("stop")],
    };
    assert!(matches!(
        empty_set.validate(),
        Err(LoopVerdictConfigError::EmptyTagSet { .. })
    ));
    // A well-formed config validates.
    assert!(LoopVerdictConfig::default_verdict().validate().is_ok());
}

/// The default vocabulary classifies the approve/refine/block tags
/// exactly and rejects everything else — the behaviorally-identical default.
#[test]
fn default_gate_verdict_classifies_legacy_tags() {
    use kata_types::review_loop::{LoopVerdictAction, LoopVerdictConfig};
    let def = LoopVerdictConfig::default_verdict();
    assert_eq!(def.verdict_field.as_str(), "verdict");
    assert_eq!(def.classify("approve"), Some(LoopVerdictAction::Approve));
    assert_eq!(def.classify("refine"), Some(LoopVerdictAction::Refine));
    assert_eq!(def.classify("block"), Some(LoopVerdictAction::Block));
    assert_eq!(def.classify("accept"), None);
    assert_eq!(def.classify("APPROVE"), None);
    assert_eq!(def.classify(""), None);
}

/// `LoopVerdictConfig::new` rejects an empty field, empty tag-sets, and
/// overlapping tag-sets with clear errors.
#[test]
fn gate_verdict_config_rejects_invalid_vocabularies() {
    use kata_types::review_loop::{LoopVerdictConfig, LoopVerdictConfigError};
    // Empty field.
    assert_eq!(
        LoopVerdictConfig::new(
            "",
            vec![SmolStr::new("a")],
            vec![SmolStr::new("b")],
            vec![SmolStr::new("c")],
        ),
        Err(LoopVerdictConfigError::EmptyField)
    );
    // Empty refine set.
    assert!(matches!(
        LoopVerdictConfig::new(
            "verdict",
            vec![SmolStr::new("a")],
            vec![],
            vec![SmolStr::new("c")],
        ),
        Err(LoopVerdictConfigError::EmptyTagSet { role: "refine" })
    ));
    // Overlapping approve/block tag.
    assert!(matches!(
        LoopVerdictConfig::new(
            "verdict",
            vec![SmolStr::new("dup")],
            vec![SmolStr::new("b")],
            vec![SmolStr::new("dup")],
        ),
        Err(LoopVerdictConfigError::OverlappingTag {
            first: "approve",
            second: "block",
            ..
        })
    ));
}

// ── multi-stage loop body (body_stages) ──────────────────────────────────────

/// A `ReviewLoop` with no multi-stage body omits `body_stages` from its
/// serialization entirely (skip_serializing_if), so every existing
/// single-stage review-loop pack hashes byte-identically to pre-slice.
#[test]
fn review_loop_empty_body_stages_omitted_from_serialization() {
    let rl = ReviewLoop {
        worker_stage: SmolStr::new("implement"),
        reviewer_stage: SmolStr::new("review"),
        max_iterations: 3,
        on_max: OnMaxAction::Fail,
        bounds: Vec::new(),
        rollover_after_iterations: None,
        body_stages: Vec::new(),
        gate_verdict: None,
    };
    let json = serde_json::to_string(&rl).unwrap();
    assert!(
        !json.contains("body_stages"),
        "empty body_stages must be skipped from serialization; got {json}"
    );
}

/// A single-stage body's `effective_body_stages` is the one-element worker list;
/// `validate_body` accepts it; `is_multi_stage_body` is false.
#[test]
fn single_stage_body_effective_and_valid() {
    use kata_types::workflow::StageId;
    let rl = ReviewLoop {
        worker_stage: SmolStr::new("implement"),
        reviewer_stage: SmolStr::new("review"),
        max_iterations: 3,
        on_max: OnMaxAction::Fail,
        bounds: Vec::new(),
        rollover_after_iterations: None,
        body_stages: Vec::new(),
        gate_verdict: None,
    };
    assert!(!rl.is_multi_stage_body());
    assert_eq!(
        rl.effective_body_stages(),
        vec![StageId(SmolStr::new("implement"))]
    );
    assert!(rl.validate_body().is_ok());
}

/// A well-formed multi-stage body (exit == worker_stage, no gate member, no
/// duplicates) validates and reports its ordered members.
#[test]
fn multi_stage_body_valid() {
    use kata_types::workflow::StageId;
    let rl = ReviewLoop {
        worker_stage: SmolStr::new("b"),
        reviewer_stage: SmolStr::new("gate"),
        max_iterations: 3,
        on_max: OnMaxAction::Fail,
        bounds: Vec::new(),
        rollover_after_iterations: None,
        body_stages: vec![StageId(SmolStr::new("a")), StageId(SmolStr::new("b"))],
        gate_verdict: None,
    };
    assert!(rl.is_multi_stage_body());
    assert!(rl.validate_body().is_ok());
    assert_eq!(rl.effective_body_stages(), rl.body_stages);
}

/// `validate_body` rejects a body whose exit stage is not the worker_stage.
#[test]
fn multi_stage_body_exit_mismatch_rejected() {
    use kata_types::review_loop::BodySubgraphError;
    use kata_types::workflow::StageId;
    let rl = ReviewLoop {
        worker_stage: SmolStr::new("a"), // exit should be the LAST member ("b")
        reviewer_stage: SmolStr::new("gate"),
        max_iterations: 3,
        on_max: OnMaxAction::Fail,
        bounds: Vec::new(),
        rollover_after_iterations: None,
        body_stages: vec![StageId(SmolStr::new("a")), StageId(SmolStr::new("b"))],
        gate_verdict: None,
    };
    assert!(matches!(
        rl.validate_body(),
        Err(BodySubgraphError::ExitMismatch { .. })
    ));
}

/// `validate_body` rejects a body that includes the gate as a member.
#[test]
fn multi_stage_body_gate_member_rejected() {
    use kata_types::review_loop::BodySubgraphError;
    use kata_types::workflow::StageId;
    let rl = ReviewLoop {
        worker_stage: SmolStr::new("b"),
        reviewer_stage: SmolStr::new("a"), // gate "a" appears in the body
        max_iterations: 3,
        on_max: OnMaxAction::Fail,
        bounds: Vec::new(),
        rollover_after_iterations: None,
        body_stages: vec![StageId(SmolStr::new("a")), StageId(SmolStr::new("b"))],
        gate_verdict: None,
    };
    assert!(matches!(
        rl.validate_body(),
        Err(BodySubgraphError::GateInBody { .. })
    ));
}

/// `validate_body` rejects a body with a duplicate member.
#[test]
fn multi_stage_body_duplicate_member_rejected() {
    use kata_types::review_loop::BodySubgraphError;
    use kata_types::workflow::StageId;
    let rl = ReviewLoop {
        worker_stage: SmolStr::new("b"),
        reviewer_stage: SmolStr::new("gate"),
        max_iterations: 3,
        on_max: OnMaxAction::Fail,
        bounds: Vec::new(),
        rollover_after_iterations: None,
        body_stages: vec![
            StageId(SmolStr::new("a")),
            StageId(SmolStr::new("a")),
            StageId(SmolStr::new("b")),
        ],
        gate_verdict: None,
    };
    assert!(matches!(
        rl.validate_body(),
        Err(BodySubgraphError::DuplicateBodyStage { .. })
    ));
}

// ── canonical controller decision algebra ────────────────────────────────────

use kata_types::review_loop::{
    ControllerApplicationAction, ControllerDecision, UnknownControllerTag,
};

/// Every decision tag round-trips through `TryFrom<&str>`/`as_str`.
#[test]
fn controller_decision_roundtrips_every_tag() {
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
        let decision = ControllerDecision::try_from(tag).expect("known tag parses");
        assert_eq!(
            decision.as_str(),
            tag,
            "as_str must invert TryFrom for {tag}"
        );
    }
}

/// An out-of-vocabulary tag is a typed error carrying the offending tag.
#[test]
fn controller_decision_rejects_unknown_tag() {
    let err = ControllerDecision::try_from("approve").expect_err("unknown tag rejected");
    assert_eq!(
        err,
        UnknownControllerTag {
            tag: "approve".to_string()
        }
    );
    assert!(ControllerDecision::try_from("").is_err());
    assert!(ControllerDecision::try_from("PROMOTE").is_err());
}

/// `application_action` is the total tag→Option<apply> projection: `stop` and
/// `ask_human` deliberately have NO apply action; the two enums stay distinct.
#[test]
fn controller_decision_application_action_projection() {
    use ControllerApplicationAction as A;
    use ControllerDecision::*;
    assert_eq!(Park.application_action(), Some(A::Park));
    assert_eq!(Promote.application_action(), Some(A::Promote));
    for tag in [Continue, Repair, Split, ReduceScope] {
        assert_eq!(tag.application_action(), Some(A::Advance), "{tag:?}");
    }
    assert_eq!(Stop.application_action(), None);
    assert_eq!(AskHuman.application_action(), None);
    // `PromoteThenAdvance` has no source decision tag but is a valid apply.
    assert!(
        ![
            Park,
            Promote,
            Continue,
            Repair,
            Split,
            ReduceScope,
            Stop,
            AskHuman
        ]
        .into_iter()
        .any(|d| d.application_action() == Some(A::PromoteThenAdvance)),
        "no decision projects to the compound PromoteThenAdvance apply action"
    );
}

/// The apply-action vocabulary round-trips independently of the decision tags.
#[test]
fn controller_application_action_roundtrips() {
    for tag in ["park", "promote", "advance", "promote_then_advance"] {
        let action = ControllerApplicationAction::try_from(tag).expect("known apply tag");
        assert_eq!(action.as_str(), tag);
    }
    assert!(ControllerApplicationAction::try_from("continue").is_err());
    assert!(ControllerApplicationAction::try_from("").is_err());
}
