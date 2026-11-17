//! Tests for `crates/types/src/approval.rs`. Extracted from the inline
//! `#[cfg(test)]` module.

use kata_types::approval::PendingApproval;

#[test]
fn pending_approval_decodes() {
    let raw = serde_json::json!({
        "execution_id": "01HV0VZTBP7TX5DQ1V0G7WB3SK",
        "assignment_id": "01HV0VZTBP7TX5DQ1V0G7WB3SL",
        "stage_name": "review",
        "reason": "stage review requires operator sign-off before dispatch",
        "awaiting_since_ms": 1_700_000_000_000u64,
    });
    let pa: PendingApproval = serde_json::from_value(raw).unwrap();
    assert_eq!(pa.stage_name, "review");
    assert_eq!(pa.awaiting_since_ms, Some(1_700_000_000_000));
}

#[test]
fn pending_approval_roundtrips_json() {
    let pa = PendingApproval {
        execution_id: "01HV0VZTBP7TX5DQ1V0G7WB3SK".to_string(),
        assignment_id: "01HV0VZTBP7TX5DQ1V0G7WB3SL".to_string(),
        stage_name: "review".to_string(),
        reason: "needs sign-off".to_string(),
        awaiting_since_ms: Some(1_700_000_000_000),
        capsule: None,
        workspace_effect: None,
        expansion: None,
        target: None,
        params: Vec::new(),
    };
    let s = serde_json::to_string(&pa).unwrap();
    let back: PendingApproval = serde_json::from_str(&s).unwrap();
    assert_eq!(back.execution_id, pa.execution_id);
    assert_eq!(back.stage_name, pa.stage_name);
}

/// ABSENT is EXPRESSIBLE, and it is `null` rather than `0`.
///
/// `0` would be a FABRICATED INSTANT that also serves as the operator panel's
/// FIFO sort key — an anchorless gate would sort ahead of genuinely older ones
/// and render as 1970. The two must stay
/// distinguishable on the wire in BOTH directions, which is what this asserts.
#[test]
fn an_absent_park_instant_is_null_on_the_wire_and_is_not_zero() {
    let absent = PendingApproval {
        execution_id: "01HV0VZTBP7TX5DQ1V0G7WB3SK".to_string(),
        assignment_id: "01HV0VZTBP7TX5DQ1V0G7WB3SL".to_string(),
        stage_name: "review".to_string(),
        reason: "needs sign-off".to_string(),
        awaiting_since_ms: None,
        capsule: None,
        workspace_effect: None,
        expansion: None,
        target: None,
        params: Vec::new(),
    };
    let encoded: serde_json::Value = serde_json::to_value(&absent).unwrap();
    assert_eq!(
        encoded.get("awaiting_since_ms"),
        Some(&serde_json::Value::Null),
        "an absent anchor must serialize as `null`; `0` is the epoch, which is a \
         value and not an absence"
    );

    let decoded: PendingApproval = serde_json::from_value(encoded).unwrap();
    assert_eq!(decoded.awaiting_since_ms, None);

    // And the counterpart: a real `0` still decodes as a VALUE, so the two are not
    // collapsed on the way back in either.
    let zero: PendingApproval = serde_json::from_value(serde_json::json!({
        "execution_id": "01HV0VZTBP7TX5DQ1V0G7WB3SK",
        "assignment_id": "01HV0VZTBP7TX5DQ1V0G7WB3SL",
        "stage_name": "review",
        "reason": "needs sign-off",
        "awaiting_since_ms": 0,
    }))
    .unwrap();
    assert_eq!(zero.awaiting_since_ms, Some(0));
}

/// A capsule gate carries WHAT approving it authorizes; a non-capsule gate omits the key.
#[test]
fn a_capsule_gate_carries_its_capsule_and_a_legacy_gate_omits_it() {
    let capsule = kata_types::approval::PendingCapsuleGate {
        capsule_id: "ab".repeat(32),
        argv: vec!["sh".into(), "-c".into(), "deploy".into()],
        work_tree_artifact_id: "cd".repeat(32),
        environment_id: "ef".repeat(32),
        produces_files: vec!["out/**".to_string()],
        network: kata_types::execution_contract::CapsuleNetworkPosture::Offline,
    };
    let gate = PendingApproval {
        execution_id: "01HV0VZTBP7TX5DQ1V0G7WB3SK".to_string(),
        assignment_id: "01HV0VZTBP7TX5DQ1V0G7WB3SL".to_string(),
        stage_name: "deploy".to_string(),
        reason: "protected".to_string(),
        awaiting_since_ms: Some(1),
        capsule: Some(capsule.clone()),
        workspace_effect: None,
        expansion: None,
        target: None,
        params: Vec::new(),
    };
    let encoded = serde_json::to_value(&gate).unwrap();
    assert_eq!(encoded["capsule"]["argv"][2], "deploy");
    // The declared output scope rides the gate — an approver reads exactly the
    // closure the /work delta's scope check enforces.
    assert_eq!(encoded["capsule"]["produces_files"][0], "out/**");
    let back: PendingApproval = serde_json::from_value(encoded).unwrap();
    assert_eq!(back.capsule, Some(capsule));
    let without_capsule = PendingApproval {
        capsule: None,
        ..gate
    };
    assert!(
        serde_json::to_value(&without_capsule)
            .unwrap()
            .get("capsule")
            .is_none()
    );
}

/// The recorded principal says what the transport PROVED, tagged by kind.
#[test]
fn the_approval_principal_is_tagged_by_what_the_transport_proved() {
    use kata_types::approval::ApprovalPrincipal;
    assert_eq!(
        serde_json::to_value(ApprovalPrincipal::Token {
            issued_for: "operator-cli".into()
        })
        .unwrap(),
        serde_json::json!({"kind": "token", "issued_for": "operator-cli"})
    );
    assert_eq!(
        serde_json::to_value(ApprovalPrincipal::UnauthenticatedLoopback).unwrap(),
        serde_json::json!({"kind": "unauthenticated_loopback"})
    );
}
