//! Local ownership invariants; dispatcher integration tests establish authority.

use super::assignment_registry::AssignmentRegistry;
use super::{AssignmentTiming, Instant, Ulid};

fn timing() -> AssignmentTiming {
    AssignmentTiming {
        submitted_at: Instant::now(),
        dispatched_at: None,
        counted_in_queue: true,
        inflight: None,
    }
}

#[test]
fn stall_cycle_identity_does_not_require_a_monotonic_wall_clock() {
    let registry = AssignmentRegistry::default();
    let id = Ulid::new();
    assert!(registry.claim_stall(id, 100));
    assert!(!registry.claim_stall(id, 100));
    assert!(registry.claim_stall(id, 90));
    assert!(!registry.claim_stall(id, 90));
    assert_eq!(registry.ids(), vec![id]);
}

#[test]
fn failed_stall_capture_cannot_clear_a_different_cycle() {
    let registry = AssignmentRegistry::default();
    let id = Ulid::new();
    assert!(registry.claim_stall(id, 10));
    assert!(registry.claim_stall(id, 11));
    registry.release_stall(id, 10);
    assert!(!registry.claim_stall(id, 11));
    registry.release_stall(id, 11);
    assert!(
        registry.claim_stall(id, 11),
        "failed capture must be retryable"
    );
    assert_eq!(registry.ids(), vec![id]);
}

#[test]
fn timing_is_tracked_until_retire_consumes_it() {
    let registry = AssignmentRegistry::default();
    let id = Ulid::new();
    registry.insert_timing(id, timing());
    assert!(registry.claim_stall(id, 1));

    let retired = registry
        .retire(id)
        .expect("retire consumes the entry's timing for accounting");
    assert!(retired.counted_in_queue);
    assert!(registry.timing_mut(id).is_none());
    assert!(registry.ids().is_empty());
    assert!(registry.retire(id).is_none(), "retirement is consume-once");
}
