//! Persistent connection posture for the two durable files a running engine holds
//! open together: the AUTHORITATIVE attempt chain (`operational.db`) and the
//! delivery/event plane (`ledger_events.db`).
//!
//! These are independent opens, not assertions on a handed-in connection. No
//! physical power-loss or storage-device honesty claim is made — `synchronous=FULL`
//! is what makes a returned commit fsync-durable, which is strictly weaker than a
//! claim about the drive.
//!
//! # Why this file is a CROSS-FILE test
//!
//! The pair asserted here is `ledger_events.db` plus `operational.db`, the two
//! planes that actually coexist: `operational.db` exposes `debug_synchronous_level`
//! and is where the `execution_evidence` / `execution_evidence_claims` rows live.
//!
//! The cross-FILE framing is the point: `synchronous` is per-CONNECTION and is not
//! persisted in the database, so one plane opening FULL says nothing about the
//! other. A mixed pair is the failure this pins — a durable commit on one file and
//! a lost one on its co-located partner, which is the torn window every
//! out-of-process crash cell assumes cannot happen.

use kata_core::{DurableEventLog, OperationalDb};

#[test]
fn persistent_operational_and_event_planes_both_open_full() {
    let dir = tempfile::tempdir().unwrap();
    // Twice, because the posture must be a property of every open — including a
    // reopen onto an existing file, where the DDL path does not run.
    for _ in 0..2 {
        let log = DurableEventLog::open(dir.path().join("ledger_events.db")).unwrap();
        assert_eq!(
            log.debug_synchronous_level().unwrap(),
            2,
            "delivery persistence must open synchronous=FULL"
        );
        let db = OperationalDb::open(dir.path().join("operational.db")).unwrap();
        assert_eq!(
            db.debug_synchronous_level().unwrap(),
            2,
            "the authoritative attempt chain — execution evidence and claims \
             included — requires synchronous=FULL"
        );
    }
}
