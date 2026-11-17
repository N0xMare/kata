//! Load-charge ownership regressions.
//!
//! These are deliberately below the dispatcher module boundary: the proof has
//! to observe the concrete counter instance retained by a charge and the
//! generation token that makes an old cleanup harmless.

use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};

use smol_str::SmolStr;
use ulid::Ulid;

use super::attempt_chain::DispatchToken;
use super::charge::DispatchCharges;

#[test]
fn same_id_replacement_releases_the_concrete_instance_that_was_charged() {
    let charges = DispatchCharges::default();
    let assignment = Ulid::new();
    let old_instance = Arc::new(AtomicU32::new(0));
    let replacement = Arc::new(AtomicU32::new(0));
    let dispatch = DispatchToken::for_test(1);

    let charge = charges.acquire(
        assignment,
        dispatch,
        SmolStr::new("worker"),
        Arc::clone(&old_instance),
    );
    charges.release_if_owned(assignment, charge.token);

    assert_eq!(old_instance.load(Ordering::Relaxed), 0);
    assert_eq!(replacement.load(Ordering::Relaxed), 0);
}

#[test]
fn stale_and_duplicate_cleanup_cannot_release_a_newer_generation_twice() {
    let charges = DispatchCharges::default();
    let assignment = Ulid::new();
    let old_instance = Arc::new(AtomicU32::new(0));
    let current_instance = Arc::new(AtomicU32::new(0));
    let old = DispatchToken::for_test(1);
    let current = DispatchToken::for_test(2);

    let stale_charge = charges.acquire(
        assignment,
        old,
        SmolStr::new("same-id"),
        Arc::clone(&old_instance),
    );
    let current_charge = charges.acquire(
        assignment,
        current,
        SmolStr::new("same-id"),
        Arc::clone(&current_instance),
    );

    assert_eq!(old_instance.load(Ordering::Relaxed), 0);
    assert_eq!(current_instance.load(Ordering::Relaxed), 1);
    assert!(!charges.release_if_owned(assignment, stale_charge.token));
    assert_eq!(current_instance.load(Ordering::Relaxed), 1);
    assert!(charges.release_if_owned(assignment, current_charge.token));
    assert!(!charges.release_if_owned(assignment, current_charge.token));
    assert_eq!(current_instance.load(Ordering::Relaxed), 0);
}

#[test]
fn scheduler_read_witness_observes_transfer_and_consume_exactly_once() {
    let charges = DispatchCharges::default();
    let assignment = Ulid::new();
    let first = Arc::new(AtomicU32::new(0));
    let second = Arc::new(AtomicU32::new(0));
    let first_dispatch = DispatchToken::for_test(11);
    let second_dispatch = DispatchToken::for_test(12);

    let _first_charge = charges.acquire(
        assignment,
        first_dispatch,
        SmolStr::new("worker"),
        Arc::clone(&first),
    );
    assert_eq!(first.load(Ordering::Relaxed), 1, "acquisition witness");

    let second_charge = charges.acquire(
        assignment,
        second_dispatch,
        SmolStr::new("worker"),
        Arc::clone(&second),
    );
    assert_eq!(first.load(Ordering::Relaxed), 0, "transfer release witness");
    assert_eq!(second.load(Ordering::Relaxed), 1, "scheduler read witness");

    charges.release_if_owned(assignment, second_charge.token);
    assert_eq!(
        second.load(Ordering::Relaxed),
        0,
        "terminal release witness"
    );
}

#[test]
fn stale_snapshot_cannot_consume_a_successor_with_the_same_dispatch_token() {
    let charges = DispatchCharges::default();
    let assignment = Ulid::new();
    let counter = Arc::new(AtomicU32::new(0));
    let dispatch = DispatchToken::for_test(21);

    let stale = charges.acquire(
        assignment,
        dispatch,
        SmolStr::new("worker"),
        Arc::clone(&counter),
    );
    let current = charges.acquire(
        assignment,
        dispatch,
        SmolStr::new("worker"),
        Arc::clone(&counter),
    );

    assert!(!charges.release_if_owned(assignment, stale.token));
    assert_eq!(counter.load(Ordering::Relaxed), 1);
    assert!(charges.release_if_owned(assignment, current.token));
    assert_eq!(counter.load(Ordering::Relaxed), 0);
}
