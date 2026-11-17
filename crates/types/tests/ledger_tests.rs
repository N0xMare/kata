//! Tests for `crates/types/src/ledger.rs`. Extracted from the inline
//! `#[cfg(test)]` module.

use kata_types::ledger::{AssignmentStatus, LedgerEvent, ProgressEvent};
use smol_str::SmolStr;
use ulid::Ulid;

#[test]
fn assignment_status_is_terminal_matches_variant_set() {
    assert!(!AssignmentStatus::Pending.is_terminal());
    assert!(
        !AssignmentStatus::Dispatched {
            worker_id: SmolStr::new("w1")
        }
        .is_terminal()
    );
    assert!(
        !AssignmentStatus::Running {
            worker_id: SmolStr::new("w1")
        }
        .is_terminal()
    );
    assert!(
        !AssignmentStatus::AwaitingApproval {
            worker_id: None,
            reason: "needs sign-off".into()
        }
        .is_terminal()
    );
    assert!(
        AssignmentStatus::Completed {
            worker_id: Some(SmolStr::new("w1"))
        }
        .is_terminal()
    );
    assert!(
        AssignmentStatus::Failed {
            worker_id: None,
            reason: "boom".into()
        }
        .is_terminal()
    );
    assert!(
        AssignmentStatus::Orphaned {
            prev_worker: None,
            reason: "worker died".into()
        }
        .is_terminal()
    );
}

#[test]
fn assignment_status_tag_round_trip() {
    // Tags stable across releases; pin them.
    assert_eq!(AssignmentStatus::Pending.tag(), "pending");
    assert_eq!(
        AssignmentStatus::Dispatched {
            worker_id: SmolStr::new("w")
        }
        .tag(),
        "dispatched"
    );
    assert_eq!(
        AssignmentStatus::Running {
            worker_id: SmolStr::new("w")
        }
        .tag(),
        "running"
    );
    assert_eq!(
        AssignmentStatus::Completed {
            worker_id: Some(SmolStr::new("w"))
        }
        .tag(),
        "completed"
    );
    assert_eq!(
        AssignmentStatus::AwaitingApproval {
            worker_id: None,
            reason: "x".into()
        }
        .tag(),
        "awaiting_approval"
    );
}

#[test]
fn assignment_status_serde_round_trip() {
    let cases = vec![
        AssignmentStatus::Pending,
        AssignmentStatus::AwaitingApproval {
            worker_id: None,
            reason: "needs review".into(),
        },
        AssignmentStatus::Dispatched {
            worker_id: SmolStr::new("w1"),
        },
        AssignmentStatus::Running {
            worker_id: SmolStr::new("w1"),
        },
        AssignmentStatus::Completed {
            worker_id: Some(SmolStr::new("w1")),
        },
        AssignmentStatus::Failed {
            worker_id: Some(SmolStr::new("w1")),
            reason: "boom".into(),
        },
        AssignmentStatus::Orphaned {
            prev_worker: Some(SmolStr::new("w1")),
            reason: "worker died".into(),
        },
    ];
    for c in cases {
        let s = serde_json::to_string(&c).unwrap();
        let back: AssignmentStatus = serde_json::from_str(&s).unwrap();
        assert_eq!(back, c);
    }
}

#[test]
fn ledger_event_serde_round_trip_and_wire_shape() {
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
    // Wire shape pin: every field that crosses the SSE feed.
    assert_eq!(json["stage_name"], "analyze");
    assert_eq!(json["new_status"]["kind"], "completed");
    assert_eq!(json["new_status"]["worker_id"], "ls-worker-0");
    assert_eq!(json["output"]["stage"], "analyze");
    assert_eq!(json["output"]["content"], "ok");
    // Ulids serialize as strings — the SDK can decode through any
    // type whose serde impl accepts a JSON string (Ulid or String).
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

#[test]
fn progress_event_serde_round_trip_and_wire_shape() {
    let event = ProgressEvent {
        execution_id: Ulid::new(),
        assignment_id: Ulid::new(),
        stage_name: SmolStr::new("implement"),
        byte_offset: 1024,
        preview: "partial chunk text".to_string(),
        dropped: 0,
        at_ms: 1_700_000_000_000,
    };

    let json = serde_json::to_value(&event).expect("ProgressEvent serializes");
    // Wire shape pin: SSE consumers depend on these field names.
    assert!(json["execution_id"].is_string());
    assert!(json["assignment_id"].is_string());
    assert_eq!(json["stage_name"], "implement");
    assert_eq!(json["byte_offset"], 1024);
    assert_eq!(json["preview"], "partial chunk text");
    assert_eq!(json["dropped"], 0);
    assert_eq!(json["at_ms"], 1_700_000_000_000_u64);

    let back: ProgressEvent =
        serde_json::from_value(json).expect("ProgressEvent roundtrips via serde_json");
    assert_eq!(back.execution_id, event.execution_id);
    assert_eq!(back.assignment_id, event.assignment_id);
    assert_eq!(back.stage_name, event.stage_name);
    assert_eq!(back.byte_offset, event.byte_offset);
    assert_eq!(back.preview, event.preview);
    assert_eq!(back.at_ms, event.at_ms);
}

/// A `LedgerEvent` that carries no `terminal_charge` key at all must decode —
/// to `None`, which every reader treats as "no charge recorded", never as
/// "this stage's charge is unknown".
#[test]
fn a_ledger_event_without_terminal_charge_decodes_to_none() {
    let json = serde_json::json!({
        "execution_id": Ulid::new(),
        "assignment_id": Ulid::new(),
        "stage_name": "analyze",
        "new_status": { "kind": "failed", "worker_id": "w-1", "reason": "boom" },
        "output": null,
    });
    let event: LedgerEvent =
        serde_json::from_value(json).expect("a frame without a terminal charge decodes");
    assert!(
        event.terminal_charge.is_none(),
        "absence is a record without a charge, never a failure"
    );
}
