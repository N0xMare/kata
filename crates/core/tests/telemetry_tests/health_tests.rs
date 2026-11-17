//! Tests for `crates/core/src/health.rs`. Extracted from the inline
//! `#[cfg(test)]` module.

use kata_core::{HealthSnapshot, SubsystemHealth, SubsystemId, SystemHealth};

#[test]
fn subsystem_id_all_has_seven_variants() {
    assert_eq!(SubsystemId::ALL.len(), 7);
}

#[test]
fn empty_system_is_healthy() {
    let h = SystemHealth::new();
    assert_eq!(h.overall(), SubsystemHealth::Healthy);
    assert!(h.snapshot().subsystems.is_empty());
}

#[test]
fn report_then_get_round_trips() {
    let h = SystemHealth::new();
    h.report(SubsystemId::Storage, SubsystemHealth::Healthy);
    assert_eq!(h.get(SubsystemId::Storage), Some(SubsystemHealth::Healthy));
    assert_eq!(h.overall(), SubsystemHealth::Healthy);
}

#[test]
fn degraded_transitions_to_overall_degraded() {
    let h = SystemHealth::new();
    h.report(
        SubsystemId::Agent,
        SubsystemHealth::Degraded {
            since: 100,
            reason: "rate limited".to_string(),
        },
    );
    h.report(SubsystemId::Storage, SubsystemHealth::Healthy);
    match h.overall() {
        SubsystemHealth::Degraded { reason, since } => {
            assert_eq!(since, 100);
            assert!(reason.contains("rate limited"));
        }
        other => panic!("expected degraded, got {other:?}"),
    }
}

#[test]
fn unavailable_beats_degraded_in_overall() {
    let h = SystemHealth::new();
    h.report(
        SubsystemId::Agent,
        SubsystemHealth::Degraded {
            since: 100,
            reason: "slow".into(),
        },
    );
    h.report(
        SubsystemId::Storage,
        SubsystemHealth::Unavailable {
            since: 200,
            reason: "disk full".into(),
        },
    );
    assert!(h.overall().is_unavailable());
}

#[test]
fn snapshot_is_sorted_by_id() {
    let h = SystemHealth::new();
    h.report(SubsystemId::Storage, SubsystemHealth::Healthy);
    h.report(SubsystemId::Agent, SubsystemHealth::Healthy);
    h.report(SubsystemId::Core, SubsystemHealth::Healthy);
    let snap = h.snapshot();
    let ids: Vec<SubsystemId> = snap.subsystems.iter().map(|(id, _)| *id).collect();
    let mut sorted = ids.clone();
    sorted.sort();
    assert_eq!(ids, sorted);
}

#[test]
fn snapshot_json_round_trips() {
    let h = SystemHealth::new();
    h.report(SubsystemId::Api, SubsystemHealth::Healthy);
    h.report(SubsystemId::Core, SubsystemHealth::Healthy);
    let snap = h.snapshot();
    let j = serde_json::to_string(&snap).unwrap();
    let back: HealthSnapshot = serde_json::from_str(&j).unwrap();
    assert_eq!(snap.subsystems, back.subsystems);
}
