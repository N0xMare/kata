//! Regression tests pinning the durable-write-before-broadcast invariant.
//!
//! The operational delivery publisher commits before notifying subscribers.
//! A fault between those steps must leave both lifecycle and informational
//! deliveries available to a reliable subscriber.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use kata_core::{AssignmentStatus, InFlightLedger};
use smol_str::SmolStr;
use tokio::time::timeout;
use tokio_stream::StreamExt as _;
use ulid::Ulid;

use super::fixture as delivery_fixture;

async fn assert_delivery_persists_before_broadcast(status: AssignmentStatus) {
    let fired = Arc::new(AtomicBool::new(false));
    let hook_fired = Arc::clone(&fired);
    let ledger = InFlightLedger::in_memory_with_hook(Arc::new(move || {
        hook_fired.store(true, Ordering::SeqCst);
        panic!("fault-inject: delivery committed before notification");
    }));
    let execution = Ulid::new();
    let assignment = Ulid::new();
    let mut disposition = delivery_fixture::frame(1, execution, assignment);
    let kata_core::operational::delivery::DeliveryDisposition::Publish(ref mut frame) = disposition
    else {
        unreachable!()
    };
    let kata_types::ledger::LedgerLogEvent::V1(mut payload) =
        serde_json::from_value(frame.event.payload.clone()).unwrap()
    else {
        unreachable!()
    };
    payload.new_status = status.clone();
    frame.event.payload =
        serde_json::to_value(kata_types::ledger::LedgerLogEvent::V1(payload)).unwrap();
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        ledger.commit_delivery_batch(&[disposition]).unwrap();
    }));
    assert!(result.is_err());
    assert!(fired.load(Ordering::SeqCst));
    let mut stream = ledger.subscribe_ledger_reliable(None);
    let (sequence, event) = timeout(Duration::from_secs(2), stream.next())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(sequence, 1);
    assert_eq!(event.assignment_id, assignment);
    assert_eq!(event.new_status, status);
}

#[tokio::test]
async fn ledger_delivery_persists_before_broadcast() {
    assert_delivery_persists_before_broadcast(AssignmentStatus::Pending).await;
}

#[tokio::test]
async fn ledger_informational_delivery_persists_before_broadcast() {
    assert_delivery_persists_before_broadcast(AssignmentStatus::Stalled {
        worker_id: SmolStr::new("worker-stall-1"),
        last_heartbeat_at_ms: 1000,
        stalled_for_secs: 30,
    })
    .await;
}
