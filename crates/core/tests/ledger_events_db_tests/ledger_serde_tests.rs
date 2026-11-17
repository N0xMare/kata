//! Serde round-trip pins split from `ledger_tests.rs` for
//! `AssignmentStatus` and the wire-facing `LedgerEvent`.

use kata_core::{AssignmentStatus, LedgerEvent};
use smol_str::SmolStr;
use ulid::Ulid;

#[test]
fn awaiting_approval_status_serde_roundtrip() {
    let status = AssignmentStatus::AwaitingApproval {
        worker_id: None,
        reason: "stage review requires approval".to_string(),
    };
    let json = serde_json::to_string(&status).unwrap();
    assert!(
        json.contains("\"kind\":\"awaiting_approval\""),
        "serde tag should be snake_case kind; got {json}"
    );
    assert!(json.contains("\"reason\":\"stage review requires approval\""));
    let parsed: AssignmentStatus = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed, status);
}

#[test]
fn ledger_event_serde_roundtrip() {
    // The SSE endpoint at GET /api/v1/events serializes
    // LedgerEvent to JSON on the wire. Pin the shape so a silent
    // rename or tag change breaks here, not in a dashboard consumer.
    let event = LedgerEvent {
        execution_id: Ulid::new(),
        assignment_id: Ulid::new(),
        stage_name: SmolStr::new("analyze"),
        new_status: AssignmentStatus::Completed {
            worker_id: Some(SmolStr::new("ls-worker-0")),
        },
        output: Some(serde_json::json!({
            "stage": "analyze",
            "content": "ok",
        })),
        terminal_charge: None,
    };

    let json = serde_json::to_value(&event).expect("LedgerEvent serializes");
    assert_eq!(json["stage_name"], "analyze");
    assert_eq!(json["new_status"]["kind"], "completed");
    assert_eq!(json["new_status"]["worker_id"], "ls-worker-0");
    assert_eq!(json["output"]["stage"], "analyze");
    assert_eq!(json["output"]["content"], "ok");
    // execution_id / assignment_id are Ulids serialized as strings.
    assert!(json["execution_id"].is_string());
    assert!(json["assignment_id"].is_string());

    let back: LedgerEvent =
        serde_json::from_value(json).expect("LedgerEvent roundtrips via serde_json");
    assert_eq!(back.execution_id, event.execution_id);
    assert_eq!(back.assignment_id, event.assignment_id);
    assert_eq!(back.stage_name, event.stage_name);
    assert_eq!(back.new_status, event.new_status);
    assert_eq!(back.output, event.output);
}
