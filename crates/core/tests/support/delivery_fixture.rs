//! Test-authored delivery envelopes; mapper provenance is tested in workflow.

use kata_core::operational::delivery::{DeliveryDisposition, DeliveryFrame};
use kata_types::event::Event;
use kata_types::ledger::{AssignmentStatus, LedgerEventV1, LedgerLogEvent};
use smol_str::SmolStr;
use ulid::Ulid;

pub fn frame(source_seq: i64, execution: Ulid, assignment: Ulid) -> DeliveryDisposition {
    DeliveryDisposition::Publish(DeliveryFrame {
        source_seq,
        execution_id: execution,
        event: Event {
            timestamp: chrono::Utc::now(),
            sequence: 0,
            payload: serde_json::to_value(LedgerLogEvent::V1(Box::new(LedgerEventV1 {
                execution_id: execution,
                assignment_id: assignment,
                stage_name: SmolStr::new("fixture"),
                new_status: AssignmentStatus::Pending,
                output: None,
                started_at_ms: None,
                last_checkpoint: None,
                terminal_charge: None,
            })))
            .unwrap(),
        },
    })
}
