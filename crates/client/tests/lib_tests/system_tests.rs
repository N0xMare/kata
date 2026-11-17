//! Integration coverage for the `SystemStatus` wire shape.
//!
//! Uses the SDK's re-exported public type only.

use kata_client::SystemStatus;

#[test]
fn system_status_decodes() {
    let raw = serde_json::json!({
        "node_id": "unknown",
        "process_mode": "installed",
        "ready": true,
        "uptime_seconds": 0u64,
    });
    let s: SystemStatus = serde_json::from_value(raw).unwrap();
    assert_eq!(s.process_mode, "installed");
    assert!(s.ready);
}

/// `POST /api/v1/executions/{id}/cancel`'s body ALWAYS carries its three counts
/// (`crates/api/src/rest/approvals.rs` emits them on the one success arm), so a body
/// missing any of them is not the server's and is REFUSED at decode, naming the
/// field — never read as "nothing was done".
#[test]
fn a_cancel_outcome_missing_a_count_is_refused() {
    let served = serde_json::json!({
        "status": "stop_requested",
        "assignments_asked_to_stop": 1u64,
        "main_side_settled": 2u64,
        "child_executions_cancelled": 3u64,
    });
    let decoded: kata_client::CancelOutcome =
        serde_json::from_value(served.clone()).expect("the served body decodes");
    assert_eq!(
        (
            decoded.assignments_asked_to_stop,
            decoded.main_side_settled,
            decoded.child_executions_cancelled
        ),
        (1, 2, 3)
    );

    for field in [
        "assignments_asked_to_stop",
        "main_side_settled",
        "child_executions_cancelled",
    ] {
        let mut without = served.clone();
        without.as_object_mut().unwrap().remove(field);
        let error = serde_json::from_value::<kata_client::CancelOutcome>(without)
            .expect_err("a body missing a count must not decode")
            .to_string();
        assert!(error.contains(field), "the refusal names {field}: {error}");
    }
}
