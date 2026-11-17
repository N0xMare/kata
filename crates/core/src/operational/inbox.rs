//! The worker inbox's ARRIVAL GATE: the buffered row a worker input is parked as,
//! and the kill point between parking and acceptance.
//!
//! # Invariant
//!
//! A worker input stream is keyed `attempt_id ++ attempt_ordinal` and carries one
//! slot, `event_seq = 1`, bound to one content digest. The gate is a BUFFER, not an
//! acceptor: [`buffer_event`] parks the input as an `accepted = 0` row and writes no
//! acceptance flag and no `event_inbox_watermark`. Acceptance is written only by
//! `promote_event_slot` and the watermark only by `advance_inbox_watermark`, and both
//! run inside a checked decision that records the slot's transition in the same
//! transaction: the worker-failure adjudication (`adjudicate_worker_failure`) and the
//! worker-completion acceptance (`accept_worker_completion_with`, through
//! `OperationalDb::accept_incoming_event_in_tx`) fold the input, and the supersession
//! branch of `buffer_worker_failure` records it as superseded. `promote_event_slot`
//! CONVERGES the stored digest before it promotes, so no path marks a slot accepted
//! with content other than what was parked, and the gate itself never marks one
//! accepted. The worker reactor parks only a FAILURE at the gate
//! (`buffer_worker_failure`, which retains the raw input before the checked decision);
//! a completion is accepted in the one transaction that adopts its result, so no
//! completion is ever parked.
//!
//! # Retention scope
//!
//! Every row this module writes carries the `execution_id` its arrival belongs
//! to, with an `ON DELETE CASCADE` reference to `programs`, so a
//! `programs`-rooted prune reaches buffered and accepted inbox rows alike
//! (`deleting_an_execution_now_reaches_the_event_inbox`). The scope is a COLUMN and
//! not a join because the consumer is a foreign-key cascade, and a cascade has no
//! query to join in.

use kata_types::error::{KataError, KataResult};
use kata_types::primitives::ContentHash;
use rusqlite::{Transaction, params};
use ulid::Ulid;

use super::now_ms;

/// The `before_accept_event` kill point is a retained-input boundary, not an
/// arbitrary adjudication call. The caller has already checked current physical
/// authority; no acceptance writes have run in this transaction, so an abort leaves
/// this exact slot replayable.
pub(super) fn crash_before_buffered_accept(
    tx: &Transaction<'_>,
    stream: &[u8],
    digest: ContentHash,
) -> KataResult<()> {
    if crate::fault_inject::selected_operational_target("before_accept_event").is_none() {
        return Ok(());
    }
    let retained: bool = tx.query_row(
        "SELECT EXISTS(SELECT 1 FROM event_inbox WHERE stream_id=?1 AND event_seq=1 AND event_digest=?2 AND accepted=0)",
        params![stream, digest.as_bytes()], |row| row.get(0),
    ).map_err(|error| KataError::Storage(format!("inspect buffered acceptance boundary: {error}")))?;
    if retained {
        crate::fault_inject::operational_crash_point("before_accept_event");
    }
    Ok(())
}

/// One worker input parked in the inbox.
#[derive(Clone, Debug)]
pub(super) struct IncomingEvent {
    /// The execution this arrival belongs to — its RETENTION SCOPE.
    ///
    /// It is a separate field rather than something derived from `stream_id`
    /// on the way to the row, and that is the whole point of the column. The key
    /// is opaque bytes here (the worker inputs build it as
    /// `attempt_id ++ attempt_ordinal`), and a durable table that recovered the
    /// scope by re-parsing the key would be re-deriving, per row and forever, a
    /// fact the caller already holds.
    ///
    /// The execution must already be submitted: the column carries an
    /// `ON DELETE CASCADE` foreign key to `programs`, so an unknown execution is
    /// a foreign-key refusal at the buffering INSERT rather than an orphan.
    pub(super) execution_id: Ulid,
    /// The stream key (typically an attempt identity).
    pub(super) stream_id: Vec<u8>,
    /// The event's ordered sequence within its stream (>= 1).
    pub(super) event_seq: i64,
    /// The event's content digest — the single-value invariant of its slot.
    pub(super) event_digest: ContentHash,
    /// The opaque event payload.
    pub(super) payload_json: Vec<u8>,
}

/// Park an arrival as a BUFFERED (`accepted = 0`) row. The gate writes nothing
/// else: no acceptance flag, no watermark.
pub(super) fn buffer_event(tx: &Transaction<'_>, event: &IncomingEvent) -> KataResult<()> {
    tx.execute(
        "INSERT INTO event_inbox
             (stream_id, event_seq, execution_id, event_digest, accepted, payload_json,
              received_at_ms)
         VALUES (?1, ?2, ?3, ?4, 0, ?5, ?6)",
        params![
            event.stream_id,
            event.event_seq,
            event.execution_id.to_bytes().as_ref(),
            event.event_digest.as_bytes(),
            event.payload_json,
            now_ms(),
        ],
    )
    .map_err(|error| KataError::Storage(format!("buffer inbox event: {error}")))?;
    Ok(())
}
