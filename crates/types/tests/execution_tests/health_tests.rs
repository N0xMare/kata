//! Tests for `crates/types/src/health.rs`. Extracted from the inline
//! `#[cfg(test)]` module.

use kata_types::health::{HealthSnapshot, SubsystemHealth, SubsystemId};
use kata_types::test_support::json_roundtrip;

#[test]
fn subsystem_id_all_has_seven_variants() {
    assert_eq!(SubsystemId::ALL.len(), 7);
}

#[test]
fn subsystem_id_serializes_snake_case() {
    assert_eq!(
        serde_json::to_string(&SubsystemId::WorkerPool).unwrap(),
        "\"worker_pool\""
    );
    assert_eq!(serde_json::to_string(&SubsystemId::Vcs).unwrap(), "\"vcs\"");
}

#[test]
fn subsystem_health_state_tag_roundtrip() {
    for h in [
        SubsystemHealth::Healthy,
        SubsystemHealth::Degraded {
            since: 1,
            reason: "rate limited".to_string(),
        },
        SubsystemHealth::Unavailable {
            since: 2,
            reason: "down".to_string(),
        },
    ] {
        json_roundtrip(h);
    }
}

#[test]
fn health_decodes_empty() {
    let raw = serde_json::json!({
        "last_updated_millis": 0u64,
        "subsystems": [],
    });
    let h: HealthSnapshot = serde_json::from_value(raw).unwrap();
    assert!(h.is_healthy());
    assert!(!h.is_unavailable());
}

#[test]
fn health_decodes_with_subsystems() {
    let raw = serde_json::json!({
        "last_updated_millis": 1_700_000_000_000u64,
        "subsystems": [
            ["api", { "state": "healthy" }],
            ["storage", { "state": "unavailable", "since": 1_700_000_000_000u64, "reason": "disk full" }],
        ],
    });
    let h: HealthSnapshot = serde_json::from_value(raw).unwrap();
    assert!(!h.is_healthy());
    assert!(h.is_unavailable());
}
