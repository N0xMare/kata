//! A worker failure is one durable input and one atomic policy resolution:
//! the attempt settles `failed` (or `cancelled` under a standing stop) with the
//! worker's verdict, in the transaction that accepts the input. Raw input never
//! changes when the policy decision changes.

use kata_types::effect::DeliveryFailureProvenance;
use kata_types::error::{KataError, KataResult};
use kata_types::idempotency::canonicalize_args;
use kata_types::identity_algebra::converge_accepted_event_content;
use kata_types::primitives::ContentHash;
use rusqlite::{Transaction, params};
use serde::{Deserialize, Serialize};
use std::time::Instant;
use ulid::Ulid;

use super::attempt_payload::finalize_attempt_delivery;
use super::repo::{
    advance_inbox_watermark, dedupe_accepted_event, inbox_watermark, promote_event_slot,
    stored_event_digest,
};
use super::{
    AttemptPlacementExpectation, EventAcceptance, OperationalDb, TransitionEffect, TransitionScope,
    TransitionWrite, now_ms, record_transition,
};

/// Authenticated physical input; the database independently checks its generation.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkerFailureInput {
    pub execution_id: Ulid,
    pub attempt_id: Ulid,
    pub attempt_ordinal: i64,
    pub lease_epoch: i64,
    pub worker_id: String,
    pub reason: String,
    pub verdict: DeliveryFailureProvenance,
    /// What the stage's billable work measured before the failure, in the
    /// same shape a completion's `token_usage` object carries. `None` is a
    /// FACT the worker stated — no billable provider call ran — and is charged
    /// as an authoritative `0`, never read as "usage was not carried".
    pub usage: Option<kata_types::metering::StageUsage>,
    /// The class of the model provider's failure the worker stated beside a
    /// PROVEN NOT PERFORMED verdict, or `None` when it stated none. Recorded on
    /// the accepting transition as `provider_failure`, where the stage's
    /// failure-retry decision reads it.
    pub provider_failure: Option<kata_types::effect::ProviderFailureClass>,
}

/// Checked workflow policy, committed with input acceptance rather than afterward.
#[derive(Clone, Debug)]
pub enum WorkerFailureResolution {
    Failed { reason: String },
    Cancelled { reason: String },
}

/// The exact source at which the checked program made its policy decision.
#[derive(Clone, Debug)]
pub struct WorkerFailurePlan {
    pub expected: AttemptPlacementExpectation,
    pub program_hash: ContentHash,
    pub resolution: WorkerFailureResolution,
    pub expected_standing_stop: bool,
}

/// Offering cannot accidentally ask policy to re-decide an accepted generation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WorkerFailureOffer {
    Ready,
    AlreadyAccepted,
    Superseded,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct BufferedFailure {
    worker_failure: WorkerFailureInput,
}

const MAX_INPUT_BYTES: usize = 64 * 1024 * 1024;

fn storage(error: rusqlite::Error) -> KataError {
    KataError::Storage(format!("worker failure transaction: {error}"))
}

impl WorkerFailureInput {
    fn stream(&self) -> Vec<u8> {
        let mut stream = self.attempt_id.to_bytes().to_vec();
        stream.extend_from_slice(&self.attempt_ordinal.to_be_bytes());
        stream
    }

    fn bytes(&self) -> KataResult<Vec<u8>> {
        if self.worker_id.trim().is_empty()
            || self.worker_id.len() > 1024
            || self.reason.len() > MAX_INPUT_BYTES / 2
        {
            return Err(KataError::Validation(
                "invalid or oversized worker failure input".into(),
            ));
        }
        let bytes = canonicalize_args(&serde_json::json!({"worker_failure":self}));
        if bytes.len() > MAX_INPUT_BYTES {
            return Err(KataError::Validation(
                "worker failure input exceeds record bound".into(),
            ));
        }
        Ok(bytes)
    }
}

fn current_fence(tx: &Transaction<'_>, input: &WorkerFailureInput) -> KataResult<bool> {
    current_worker_fence(
        tx,
        input.execution_id,
        input.attempt_id,
        input.attempt_ordinal,
        input.lease_epoch,
        &input.worker_id,
    )
}

pub(super) fn current_worker_fence(
    tx: &Transaction<'_>,
    execution_id: Ulid,
    attempt_id: Ulid,
    attempt_ordinal: i64,
    lease_epoch: i64,
    worker_id: &str,
) -> KataResult<bool> {
    tx.query_row("SELECT EXISTS(SELECT 1 FROM attempts a JOIN attempt_projection p
        ON p.execution_id=a.execution_id AND p.stage_id=a.stage_id AND p.attempt_ordinal=a.attempt_ordinal
        WHERE a.attempt_id=?1 AND a.execution_id=?2 AND a.attempt_ordinal=?3
          AND a.lease_epoch=?4 AND a.worker_id=?5 AND p.state IN ('dispatched','running','stalled'))",
        params![attempt_id.to_bytes().as_slice(),execution_id.to_bytes().as_slice(),
            attempt_ordinal,lease_epoch,worker_id], |row| row.get(0)).map_err(storage)
}

impl OperationalDb {
    /// Retain one valid-generation raw input before policy evaluation. A stale
    /// input refuses; exact already-accepted redelivery remains a no-op.
    pub fn buffer_worker_failure(
        &self,
        input: &WorkerFailureInput,
    ) -> KataResult<WorkerFailureOffer> {
        let bytes = input.bytes()?;
        let digest = ContentHash::new(*blake3::hash(&bytes).as_bytes());
        let stream = input.stream();
        self.in_writer_txn(|tx| {
            if let Some(stored) = stored_event_digest(tx, &stream, 1)? {
                converge_accepted_event_content(Some(stored), Some(digest))
                    .map_err(|e| KataError::Validation(e.to_string()))?;
                if inbox_watermark(tx, &stream)? >= 1 {
                    return Ok(WorkerFailureOffer::AlreadyAccepted);
                }
                if current_fence(tx, input)? {
                    return Ok(WorkerFailureOffer::Ready);
                }
                promote_event_slot(tx, input.execution_id, &stream, 1, digest, &bytes)?;
                record_transition(
                    tx,
                    &TransitionWrite {
                        execution_id: input.execution_id,
                        kind: "worker_failure_superseded",
                        effect: TransitionEffect::RecordOnly {
                            scope: TransitionScope::Execution,
                            resulting_state: "worker_failure_superseded",
                        },
                        payload_json: &bytes,
                        idempotency_key: None,
                    },
                )?;
                Self::acknowledge_stop_in_tx(tx, input.attempt_id, input.lease_epoch)?;
                advance_inbox_watermark(tx, input.execution_id, &stream, 1)?;
                return Ok(WorkerFailureOffer::Superseded);
            }
            if !current_fence(tx, input)? {
                return Ok(WorkerFailureOffer::Superseded);
            }
            super::inbox::buffer_event(
                tx,
                &super::inbox::IncomingEvent {
                    execution_id: input.execution_id,
                    stream_id: stream.clone(),
                    event_seq: 1,
                    event_digest: digest,
                    payload_json: bytes.clone(),
                },
            )?;
            Ok(WorkerFailureOffer::Ready)
        })
    }

    /// Replay only explicitly tagged failures. The only writer of a buffered
    /// (`accepted = 0`) row is [`Self::buffer_worker_failure`], whose rows are all
    /// tagged; an untagged one is skipped, not refused, and nothing else reads or
    /// settles it. Bounded before allocating bytes.
    pub fn buffered_worker_failures(
        &self,
        execution_id: Ulid,
        deadline: Instant,
    ) -> KataResult<Vec<WorkerFailureInput>> {
        self.with_read(|conn| {
            let _deadline=super::RecoveryReadDeadline::new(conn,deadline)?;
            let mut stmt=conn.prepare("SELECT CASE WHEN length(payload_json)<=?1 THEN payload_json END,
                    stream_id,event_seq,event_digest
                FROM event_inbox WHERE accepted=0 AND execution_id=?2 ORDER BY received_at_ms,stream_id").map_err(storage)?;
            let mut rows=stmt.query(params![i64::try_from(MAX_INPUT_BYTES).expect("64 MiB fits i64"),execution_id.to_bytes().as_slice()]).map_err(storage)?;
            let mut inputs=Vec::new();
            let mut retained_bytes=0usize;
            while let Some(row)=rows.next().map_err(storage)? {
                if Instant::now()>=deadline { return Err(KataError::Validation("worker failure replay deadline elapsed".into())); }
                let bytes:Option<Vec<u8>>=row.get(0).map_err(storage)?;
                let bytes=bytes.ok_or_else(||KataError::Validation("oversized buffered input".into()))?;
                let value:serde_json::Value=serde_json::from_slice(&bytes)
                    .map_err(|e|KataError::Validation(format!("malformed buffered input: {e}")))?;
                if value.get("worker_failure").is_some() {
                    retained_bytes=retained_bytes.checked_add(bytes.len())
                        .ok_or_else(||KataError::Validation("worker failure replay size overflow".into()))?;
                    if retained_bytes>MAX_INPUT_BYTES || inputs.len()>=100_000 {
                        return Err(KataError::Validation("worker failure replay batch exceeds bounded capacity".into()));
                    }
                    let decoded:BufferedFailure=serde_json::from_value(value)
                        .map_err(|e|KataError::Validation(format!("malformed buffered worker failure: {e}")))?;
                    let stream:Vec<u8>=row.get(1).map_err(storage)?;
                    let seq:i64=row.get(2).map_err(storage)?;
                    let digest:Vec<u8>=row.get(3).map_err(storage)?;
                    if decoded.worker_failure.bytes()? != bytes || decoded.worker_failure.execution_id!=execution_id
                        || decoded.worker_failure.stream()!=stream || seq!=1
                        || digest.as_slice()!=blake3::hash(&bytes).as_bytes() {
                        return Err(KataError::Validation("buffered worker failure identity or content mismatch".into()));
                    }
                    inputs.push(decoded.worker_failure);
                }
            }
            Ok(inputs)
        })
    }

    /// None means the checked source was superseded, with no acceptance. Dedupe
    /// occurs first, so an old accepted input cannot touch its successor.
    pub fn adjudicate_worker_failure(
        &self,
        input: &WorkerFailureInput,
        plan: &WorkerFailurePlan,
    ) -> KataResult<Option<EventAcceptance>> {
        let bytes = input.bytes()?;
        let digest = ContentHash::new(*blake3::hash(&bytes).as_bytes());
        let stream = input.stream();
        let acceptance = self.in_writer_txn(|tx| {
            if inbox_watermark(tx,&stream)? >= 1 {
                return dedupe_accepted_event(tx,&stream,1,digest).map(Some);
            }
            if !current_fence(tx,input)? { return Ok(None); }
            let expected=&plan.expected;
            let matches:bool=tx.query_row("SELECT EXISTS(SELECT 1 FROM attempts a
                JOIN attempt_projection p ON p.execution_id=a.execution_id AND p.stage_id=a.stage_id
                    AND p.attempt_ordinal=a.attempt_ordinal JOIN programs g ON g.execution_id=a.execution_id
                WHERE a.attempt_id=?1 AND a.attempt_ordinal=?2 AND a.lease_epoch=?3
                    AND p.source_seq=?4 AND p.state=?5
                    AND a.run_ordinal=?6 AND g.program_hash=?7)",
                params![expected.attempt_id.to_bytes().as_slice(),expected.attempt_ordinal,
                    expected.lease_epoch,expected.state_source_seq,expected.state.as_str(),
                    expected.run_ordinal,plan.program_hash.as_bytes()],
                |row|row.get(0)).map_err(storage)?;
            if expected.attempt_id!=input.attempt_id || !matches { return Ok(None); }
            let stopped:bool=tx.query_row("SELECT EXISTS(SELECT 1 FROM attempt_stop_requests
                WHERE execution_id=?1 AND attempt_id=?2)",
                params![input.execution_id.to_bytes().as_slice(),input.attempt_id.to_bytes().as_slice()],
                |row|row.get(0)).map_err(storage)?;
            if stopped!=plan.expected_standing_stop { return Ok(None); }
            super::inbox::crash_before_buffered_accept(tx, &stream, digest)?;
            let (state,reason)=match &plan.resolution {
                WorkerFailureResolution::Failed{reason}=>("failed",reason),
                WorkerFailureResolution::Cancelled{reason}=>("cancelled",reason),
            };
            // The charge this failed or cancelled attempt made, in the
            // typed `TerminalCharge` shape every terminal transition carries.
            // The worker's `usage` is preserved verbatim; `None` states "no
            // billable call ran", which is an authoritative `0`, not an
            // absence — so the durable record always carries the field.
            let terminal_charge = kata_types::metering::TerminalCharge {
                token_usage: Some(
                    input
                        .usage
                        .clone()
                        .unwrap_or_else(kata_types::metering::StageUsage::unbilled),
                ),
                child_invocation_summary: None,
            };
            let payload=canonicalize_args(&serde_json::json!({"reason":reason,"worker_reason":input.reason,
                "verdict":input.verdict,"provider_failure":input.provider_failure,
                "terminal_charge":terminal_charge}));
            promote_event_slot(tx,input.execution_id,&stream,1,digest,&bytes)?;
            let seq=record_transition(tx,&TransitionWrite{execution_id:input.execution_id,
                kind:"event_accepted",effect:TransitionEffect::Attempt{attempt_id:input.attempt_id,state},
                payload_json:&payload,idempotency_key:None})?;
            tx.execute("UPDATE attempts SET finished_at_ms=?1,source_seq=?3 WHERE attempt_id=?2",
                params![now_ms(),input.attempt_id.to_bytes().as_slice(),seq]).map_err(storage)?;
            finalize_attempt_delivery(tx,seq,input.attempt_id)?;
            Self::acknowledge_stop_in_tx(tx,input.attempt_id,input.lease_epoch)?;
            advance_inbox_watermark(tx,input.execution_id,&stream,1)?;
            Ok(Some(EventAcceptance::Accepted{seq}))
        })?;
        if matches!(acceptance, Some(EventAcceptance::Accepted { .. })) {
            crate::fault_inject::operational_crash_point("after_accept_event");
        }
        Ok(acceptance)
    }
}

#[cfg(test)]
#[path = "worker_failure_tests.rs"]
pub(super) mod tests;
