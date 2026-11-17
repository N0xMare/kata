//! Global, restartable delivery projection. Authority commits never depend on
//! this derived store succeeding; a failed page leaves its durable cursor intact.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use kata_core::operational::chain::{ChainScope, TransitionFrame};
use kata_core::operational::delivery::DeliveryDisposition;
use kata_core::operational::liveness::Wake;
use kata_core::{InFlightLedger, OperationalDb};
use kata_types::error::{KataError, KataResult};

use crate::attempt_delivery::{FrameDelivery, envelope_for};

const PAGE_SIZE: usize = 256;
const RECHECK: Duration = Duration::from_millis(100);

/// One producer for the finalized runtime authority and its delivery store.
/// Construct explicitly after choosing the runtime stores, catch up before
/// admission, then run as an owned background task. No per-execution cursor or
/// in-memory ledger row participates in publication.
pub struct DeliveryService {
    authority: Arc<OperationalDb>,
    ledger: Arc<InFlightLedger>,
    pump: Mutex<()>,
}

impl DeliveryService {
    #[must_use]
    pub fn new(authority: Arc<OperationalDb>, ledger: Arc<InFlightLedger>) -> Self {
        Self {
            authority,
            ledger,
            pump: Mutex::new(()),
        }
    }

    /// Project through the authority head captured at entry. Concurrent commits
    /// are left for the next pass, so a busy source cannot prevent shutdown.
    pub fn catch_up(&self) -> KataResult<usize> {
        let _pump = self
            .pump
            .lock()
            .map_err(|_| KataError::Storage("delivery producer lock poisoned".to_owned()))?;
        let source_cursor = self.ledger.delivery_cursor()?.projected_through_source_seq;
        let mut next = source_cursor
            .checked_add(1)
            .ok_or_else(|| KataError::Storage("delivery source cursor exhausted".to_owned()))?;
        let first = self.authority.read_transition_page(next, PAGE_SIZE)?;
        let target = first.observed_head;
        if source_cursor > target {
            return Err(KataError::Storage(format!(
                "delivery source cursor {source_cursor} is ahead of authority head {target}"
            )));
        }
        let mut page = first;
        let mut consumed = 0;
        loop {
            let dispositions = page
                .frames
                .iter()
                .take_while(|frame| frame.seq <= target)
                .map(|frame| {
                    let frame = self.authority.resolve_transition_output(frame)?;
                    disposition_for(&frame)
                })
                .collect::<KataResult<Vec<_>>>()?;
            if dispositions.is_empty() {
                return Ok(consumed);
            }
            next = dispositions
                .last()
                .expect("nonempty page")
                .source_seq()
                .checked_add(1)
                .ok_or_else(|| KataError::Storage("delivery source cursor exhausted".to_owned()))?;
            self.ledger.commit_delivery_batch(&dispositions)?;
            consumed += dispositions.len();
            if next > target {
                return Ok(consumed);
            }
            page = self.authority.read_transition_page(next, PAGE_SIZE)?;
        }
    }

    /// Notifications are hints. Periodic rereads also cover a commit whose
    /// process died before publishing its wake. A refused page is never skipped.
    pub async fn run(&self) {
        let mut wake = self.authority.liveness();
        loop {
            if let Err(error) = self.catch_up() {
                tracing::error!(%error, "delivery projection stalled; retaining source cursor for retry");
            }
            if wake.wait(RECHECK).await == Wake::Closed {
                return;
            }
        }
    }
}

/// Enumerate the complete source vocabulary, including intentionally opaque
/// record-only payloads (evidence claim keys are bytes, not JSON). The authority
/// reader validates row structure; the envelope mapper validates wire facts.
/// Unknown kinds and wrong scope/fold combinations cannot silently advance the
/// global cursor as no-wire records.
fn disposition_for(frame: &TransitionFrame) -> KataResult<DeliveryDisposition> {
    if frame.scope == ChainScope::Attempt
        && !frame.folds_projection
        && frame.kind == "attempt_stalled"
    {
        return crate::attempt_delivery::map_stalled_delivery_frame(frame)
            .map(DeliveryDisposition::Publish)
            .map_err(|error| KataError::Storage(error.to_string()));
    }
    let known = match (frame.scope, frame.folds_projection) {
        (ChainScope::Execution, true) => matches!(
            frame.kind.as_str(),
            "submitted" | "running" | "terminal_intent" | "terminalized"
        ),
        (ChainScope::Execution, false) => matches!(
            frame.kind.as_str(),
            "dynamic_child_spawned" | "evidence_recorded" | "worker_failure_superseded"
        ),
        // No writer produces a stage-scope projection fold: the undispatched
        // kinds are all record-only.
        (ChainScope::Stage, true) => false,
        (ChainScope::Stage, false) => matches!(
            frame.kind.as_str(),
            "undispatched_stage_admitted"
                | "undispatched_stage_settled"
                | "undispatched_stage_recorded"
        ),
        (ChainScope::Attempt, true) => {
            matches!(
                frame.kind.as_str(),
                "claimed" | "attempt_advanced" | "dispatched" | "event_accepted"
            ) || frame.kind == kata_core::operational::MAIN_ATTEMPT_CLAIMED_KIND
                || frame.kind == kata_core::operational::MAIN_ATTEMPT_PARKED_KIND
                || frame.kind == kata_core::operational::MAIN_ATTEMPT_RESOLVED_KIND
        }
        (ChainScope::Attempt, false) => matches!(
            frame.kind.as_str(),
            "attempt_safe_point"
                | "outcome_amended"
                | kata_core::operational::APPROVAL_DECIDED_KIND
        ),
    };
    if !known {
        return Err(KataError::Storage(format!(
            "delivery refuses unclassified authority transition {}: {:?}/{}/fold={}",
            frame.seq, frame.scope, frame.kind, frame.folds_projection
        )));
    }
    match envelope_for(frame).map_err(|error| KataError::Storage(error.to_string()))? {
        FrameDelivery::Delivery(frame) => Ok(DeliveryDisposition::Publish(*frame)),
        FrameDelivery::Checkpoint { .. } => Ok(DeliveryDisposition::FoldOnly {
            source_seq: frame.seq,
        }),
        FrameDelivery::NotADeliveryEvent { .. } => Ok(DeliveryDisposition::NoWire {
            source_seq: frame.seq,
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ulid::Ulid;

    fn attempt_frame(kind: &str, folds_projection: bool) -> TransitionFrame {
        TransitionFrame {
            seq: 7,
            execution_id: Ulid::new(),
            scope: ChainScope::Attempt,
            stage_id: Some("only".to_owned()),
            attempt_ordinal: Some(0),
            attempt_id: Some(Ulid::new()),
            kind: kind.to_owned(),
            resulting_state: kind.to_owned(),
            folds_projection,
            payload_json: b"{}".to_vec(),
            recorded_at_ms: 0,
        }
    }

    /// A stored attempt-scope row whose kind no writer produces is refused by the
    /// generic arm, naming the row, rather than classified and delivered.
    #[test]
    fn a_kind_no_writer_produces_is_refused_as_unclassified() {
        for (kind, folds_projection) in [
            ("attempt_parked_for_child", true),
            ("attempt_resumed_from_child", true),
            ("attempt_reclaimed", false),
            ("assignment_amended", false),
            ("placement_audit_recorded", false),
            ("generation_advanced", false),
        ] {
            let Err(error) = disposition_for(&attempt_frame(kind, folds_projection)) else {
                panic!("{kind}: a kind no writer produces must be refused");
            };
            let message = error.to_string();
            assert!(
                message.contains("delivery refuses unclassified authority transition 7")
                    && message.contains(kind),
                "{kind}: the generic refusal must name the row and its kind: {message}"
            );
        }
    }
}
