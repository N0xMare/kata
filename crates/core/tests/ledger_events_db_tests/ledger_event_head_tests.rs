//! Delivery publication advances the observation cursor; mirror writes do not.
use super::fixture;

use kata_core::InFlightLedger;
use ulid::Ulid;

#[test]
fn event_head_advances_only_for_new_committed_delivery_frames() {
    let ledger = InFlightLedger::in_memory();
    let execution = Ulid::new();
    assert_eq!(ledger.event_head(), 0, "no publication yet");
    for sequence in 1..=3 {
        let frame = fixture::frame(sequence, execution, Ulid::new());
        ledger
            .commit_delivery_batch(std::slice::from_ref(&frame))
            .unwrap();
        assert_eq!(ledger.event_head(), u64::try_from(sequence).unwrap());
        ledger
            .commit_delivery_batch(&[frame])
            .expect_err("an already projected authority sequence is not a new batch");
        assert_eq!(
            ledger.event_head(),
            u64::try_from(sequence).unwrap(),
            "refused replay must not publish"
        );
    }
    assert_eq!(ledger.delivery_head().unwrap(), 3);
    assert_eq!(ledger.event_head(), 3, "reads must not publish");
}
