//! Separate metadata appends for undispatched assignments. Growing expansion
//! collections are never copied onto each lifecycle transition.

use kata_types::error::{KataError, KataResult};
use rusqlite::{OptionalExtension, Transaction, params};
use serde::{Deserialize, Serialize};
use ulid::Ulid;

use super::{OperationalDb, TransitionEffect, TransitionScope, TransitionWrite, record_transition};

/// A record-only stage append, distinct from a lifecycle settlement.
pub const UNDISPATCHED_STAGE_RECORD_KIND: &str = "undispatched_stage_recorded";

/// One metadata mutation; each variant retains only the fact being changed.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub enum UndispatchedStageRecord {
    OutcomeAmended(serde_json::Value),
}

/// The self-contained payload decoded by both metadata readers and delivery
/// classification, which must refuse malformed no-wire records too.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UndispatchedStageRecordPayload {
    pub assignment_id: Ulid,
    pub record: UndispatchedStageRecord,
}

/// An attributed metadata fact in authority order.
#[derive(Clone, Debug)]
pub struct UndispatchedStageAppend {
    pub assignment_id: Ulid,
    pub seq: i64,
    pub record: UndispatchedStageRecord,
}

impl OperationalDb {
    /// Append metadata for an admitted, undispatched assignment. This does not
    /// create an attempt or change the assignment's lifecycle state.
    pub fn record_undispatched_stage_metadata(
        &self,
        assignment_id: Ulid,
        record: UndispatchedStageRecord,
    ) -> KataResult<i64> {
        let admission = self
            .undispatched_stage_admission(assignment_id)?
            .ok_or_else(|| {
                KataError::Validation(format!("no undispatched stage {assignment_id}"))
            })?;
        let UndispatchedStageRecord::OutcomeAmended(output) = &record;
        let prepared = self.prepare_output(admission.execution_id, output)?;
        let record = UndispatchedStageRecord::OutcomeAmended(prepared.envelope());
        let payload = serde_json::to_vec(&UndispatchedStageRecordPayload {
            assignment_id,
            record,
        })
        .map_err(|error| KataError::Storage(format!("encode stage metadata: {error}")))?;
        self.in_writer_txn(|tx| {
            if stage_state(tx, admission.execution_id, assignment_id)? != "completed" {
                return Err(KataError::Validation(format!(
                    "cannot amend output of incomplete stage {assignment_id}"
                )));
            }
            prepared.record_root(tx)?;
            record_transition(
                tx,
                &TransitionWrite {
                    execution_id: admission.execution_id,
                    kind: UNDISPATCHED_STAGE_RECORD_KIND,
                    effect: TransitionEffect::RecordOnly {
                        scope: TransitionScope::Stage {
                            stage_id: &admission.stage_id,
                        },
                        resulting_state: UNDISPATCHED_STAGE_RECORD_KIND,
                    },
                    payload_json: &payload,
                    idempotency_key: None,
                },
            )
        })
    }

    /// Read the metadata population independently of ledger rows.
    /// Undecodable or incorrectly attributed records refuse the entire read.
    #[cfg(any(test, feature = "test-support"))]
    pub fn undispatched_stage_metadata(
        &self,
        execution_id: Ulid,
    ) -> KataResult<Vec<UndispatchedStageAppend>> {
        let rows = self.with_read(|conn| {
            let mut stmt = conn
                .prepare(
                    "SELECT seq, stage_id, payload_json FROM transitions
                WHERE execution_id = ?1 AND scope = 'stage' AND kind = ?2 ORDER BY seq",
                )
                .map_err(|error| KataError::Storage(format!("prepare stage metadata: {error}")))?;
            stmt.query_map(
                params![
                    execution_id.to_bytes().as_ref(),
                    UNDISPATCHED_STAGE_RECORD_KIND
                ],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, Vec<u8>>(2)?,
                    ))
                },
            )
            .map_err(|error| KataError::Storage(format!("read stage metadata: {error}")))?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| KataError::Storage(format!("collect stage metadata: {error}")))
        })?;
        let mut records = Vec::with_capacity(rows.len());
        for (seq, stage_id, bytes) in rows {
            let bytes =
                self.resolve_output_payload(execution_id, UNDISPATCHED_STAGE_RECORD_KIND, &bytes)?;
            let payload: UndispatchedStageRecordPayload =
                serde_json::from_slice(&bytes).map_err(|error| {
                    KataError::Storage(format!("stage metadata at {seq} is undecodable: {error}"))
                })?;
            let admission = self
                .undispatched_stage_admission(payload.assignment_id)?
                .ok_or_else(|| {
                    KataError::Storage(format!("stage metadata at {seq} has no admission"))
                })?;
            if admission.execution_id != execution_id
                || admission.stage_id != stage_id
                || admission.seq >= seq
            {
                return Err(KataError::Storage(format!(
                    "stage metadata at {seq} disagrees with its admission"
                )));
            }
            records.push(UndispatchedStageAppend {
                assignment_id: payload.assignment_id,
                seq,
                record: payload.record,
            });
        }
        Ok(records)
    }
}

pub(super) fn stage_state(
    tx: &Transaction<'_>,
    execution_id: Ulid,
    assignment_id: Ulid,
) -> KataResult<String> {
    tx.query_row(
        "SELECT resulting_state FROM transitions WHERE execution_id = ?1
         AND scope = 'stage' AND kind IN (?2, ?3)
         AND json_extract(CAST(payload_json AS TEXT), '$.assignment_id') = ?4
         ORDER BY seq DESC LIMIT 1",
        params![
            execution_id.to_bytes().as_ref(),
            super::UNDISPATCHED_STAGE_ADMITTED_KIND,
            super::UNDISPATCHED_STAGE_SETTLED_KIND,
            assignment_id.to_string()
        ],
        |row| row.get(0),
    )
    .optional()
    .map_err(|error| KataError::Storage(format!("read stage terminal latch: {error}")))?
    .ok_or_else(|| KataError::Storage(format!("stage {assignment_id} has no lifecycle frame")))
}
