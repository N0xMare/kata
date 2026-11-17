//! The DURABLE STOP-ACK.
//!
//! # What this plane answers
//!
//! One question, asked by `require_terminal_lifecycle_for_parking`: *may this
//! execution's workspace be reclaimed, or could a worker still be writing to it?*
//!
//! `WorkflowExecutor::cancel` reaches a worker and the worker acts on the stop, but
//! without a durable record the fact that it did dies with the main process, and
//! the parking arm could only say "refused until durable worker-stop
//! acknowledgement proves no worker can still mutate the workspace". This plane is
//! that proof.
//!
//! # THE ACK IS THE WORKER'S TERMINAL FRAME, NOT A NEW FRAME TYPE
//!
//! The obvious design is a `WorkerMessage::StopAck` the worker sends when it
//! honours a stop. It is refused, and the reason is the property rather than the
//! plumbing.
//!
//! What parking needs to know is "no worker is still running this attempt". An
//! explicit ack sent AT THE MOMENT THE STOP IS RECEIVED would not say that — the
//! worker acknowledges, then still has to drop the stage future and reap the
//! child. An ack sent after the reaping says exactly what the attempt-terminal
//! frame already says, on a second frame that can be lost independently of the
//! first, giving two sources for one fact that can disagree.
//!
//! The ack is the authenticated terminal input. The typed completion/failure
//! transactions call [`OperationalDb::acknowledge_stop_in_tx`] atomically with
//! new inbox acceptance, including an already-buffered superseded generation.
//! Restart therefore cannot accept a terminal while losing its stop acknowledgement.
//! Idempotent input redelivery does not acknowledge a stop authored after that
//! input was accepted. A consequence worth stating
//! plainly, because it looks like a bug and is not — **a stage that finished on
//! its own a millisecond after the stop was sent also acknowledges it.** That is
//! correct. The stop asked the worker to stop running the attempt; the worker is
//! not running the attempt. Whether it stopped BECAUSE of the ask is a question
//! about causation that the safety property does not ask, and answering it would
//! require classifying the worker's free-text reason, which no consumer may do.
//!
//! # Why the fence is not re-checked here
//!
//! A stop is addressed to `(attempt_id, lease_epoch)` and acknowledged by the same
//! pair. `worker_id` is stored for the operator's record but is NOT part of the
//! match: a worker failure is checked against the exact durable placement before its
//! bytes are retained, and its adjudication verifies the same generation or consumes
//! that already-authenticated buffered input as superseded; a completion is accepted
//! only under that same fence, read in its accepting transaction.
//! This helper uses that retained physical identity, never a successor's worker.
//!
//! Production dispatches an attempt once, at one epoch; a retry is a new attempt
//! row with stops of its own. A terminal carrying any other epoch — a stale or
//! forged frame — matches no row and acknowledges nothing, which is the intended
//! behaviour and not an oversight.

use kata_types::error::{KataError, KataResult};
use kata_types::execution::StopDischarge;
use rusqlite::{OptionalExtension, params};
use ulid::Ulid;

use super::{OperationalDb, now_ms, ulid_from_bytes};

/// One durable stop request, as an operator or the parking predicate reads it.
///
/// The three timestamps are three DIFFERENT observers and no one of them implies
/// another, which is why this is not one `state` column.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StopRequestRow {
    /// The attempt asked to stop.
    pub attempt_id: Ulid,
    /// The execution that attempt belongs to.
    ///
    /// A stored COLUMN, not a value re-derived through `attempts`. It is
    /// on the row rather than left implicit in the query parameter because it is
    /// the only thing that can locate this latch once its attempt is pruned — a
    /// row type that hid its own scoping column would invite the next reader to
    /// re-derive it through a join.
    pub execution_id: Ulid,
    /// The GENERATION asked to stop: the epoch the attempt's dispatch fenced its
    /// command at. A stop is addressed to `(attempt_id, lease_epoch)`, the pair
    /// the worker's terminal frame carries, so only a terminal from that
    /// dispatch acknowledges it.
    pub lease_epoch: i64,
    /// The worker the stop was addressed to, for the record an operator reads.
    /// Deliberately not part of the acknowledgement match; see the module doc.
    pub worker_id: String,
    /// The operator's stated reason.
    pub reason: String,
    /// The MAIN decided to stop this generation. Written before the frame is
    /// handed to any transport.
    pub requested_at_ms: i64,
    /// A TRANSPORT accepted the frame. Proves the frame left; proves nothing
    /// about the worker.
    pub delivered_at_ms: Option<i64>,
    /// The stop was DISCHARGED. Normally this is the FENCED WORKER's own
    /// attempt-terminal frame arriving, which alone proves no worker is still
    /// running the attempt; when [`Self::discharge`] is present it is instead the
    /// instant an operator asserted it.
    pub acknowledged_at_ms: Option<i64>,
    /// The attributed operator assertion that discharged this stop, when
    /// one did.
    ///
    /// `None` for every stop the worker answered itself, which is the ordinary
    /// case. Present means a human, not the engine, decided that no worker can
    /// still be running the attempt — and the record says so in its own words
    /// rather than letting the cleared timestamp imply a proof nobody made.
    pub discharge: Option<StopDischarge>,
}

impl StopRequestRow {
    /// Whether this stop still awaits a discharge.
    ///
    /// The parking predicate's whole question. Note it reads `acknowledged_at_ms`
    /// and NOT `delivered_at_ms`: a delivered-but-unacknowledged stop is the
    /// single most dangerous state in this plane — the frame is gone, so the
    /// caller got `Ok`, and the worker may be doing anything at all.
    #[must_use]
    pub const fn is_outstanding(&self) -> bool {
        self.acknowledged_at_ms.is_none()
    }

    /// Whether the discharge rests on a machine PROOF — the worker's own terminal
    /// frame — rather than on a human assertion.
    ///
    /// `false` for an outstanding stop (nothing has discharged it) and for an
    /// operator-asserted one. Spelled to match
    /// [`StopDischarge::rests_on_a_proof`] so the question has one wording across
    /// both planes, and answered from the ROW so no caller has to know that an
    /// absent `discharge` means the worker answered.
    #[must_use]
    #[cfg(any(test, feature = "test-support"))]
    pub const fn discharge_rests_on_a_proof(&self) -> bool {
        self.acknowledged_at_ms.is_some() && self.discharge.is_none()
    }
}

/// What [`OperationalDb::record_stop_request`] found.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StopRequestOutcome {
    /// First stop for this generation; the row is new.
    Recorded,
    /// A stop for this generation was already durable. Idempotent — the ORIGINAL
    /// `requested_at_ms` and reason are kept, because the first ask is the one an
    /// operator would be reconstructing a timeline from, and a re-cancel is a
    /// repetition of it rather than a new decision.
    AlreadyRecorded,
}

/// What [`OperationalDb::discharge_stop`] found.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StopDischargeOutcome {
    /// The stop was outstanding and is now discharged on the operator's
    /// attributed assertion.
    Discharged,
    /// This stop already carried a BYTE-IDENTICAL operator discharge. Idempotent
    /// — a re-submitted operator action, which on an operator surface is an
    /// ordinary double-click. A discharge by the WORKER is NOT this variant; it
    /// is a refusal, because there is nothing left to discharge.
    AlreadyDischarged,
}

/// What acknowledging a stop found (`OperationalDb::acknowledge_stop_in_tx`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StopAckOutcome {
    /// An outstanding stop for this generation is now acknowledged.
    Acknowledged,
    /// This generation was already acknowledged. First ack wins.
    AlreadyAcknowledged,
    /// No stop was ever asked for this generation — the overwhelmingly common
    /// case, since every ordinary terminal calls this. NOT an error.
    NoStopRequested,
}

impl OperationalDb {
    /// Record that the main has decided to stop `(attempt_id, lease_epoch)`.
    ///
    /// # Ordering
    ///
    /// MUST be called BEFORE the control frame is handed to a transport. A crash
    /// between this write and the send leaves a stop that is visible and
    /// unacknowledged, which is the safe reading — the caller does not know
    /// whether the frame left, so neither does the record. The reverse order
    /// leaves a stop that was SENT and is recorded nowhere: the worker acts on it,
    /// the main forgets it was ever asked, and parking would be allowed on the
    /// strength of a lifecycle that no longer describes anything.
    ///
    /// # The execution is DERIVED here, not supplied by the caller
    ///
    /// This table has its own `execution_id`, and the value is read off the
    /// attempt inside this transaction rather than added to the signature. A
    /// caller that could pass one could pass a DIFFERENT one — and since that
    /// column is the only route from an execution to its stops, a stop filed
    /// under the wrong execution would be an outstanding latch on an execution
    /// nobody cancelled and, worse, an absent one on the execution being
    /// cancelled. Deriving it makes the disagreement unrepresentable.
    ///
    /// It is deliberately NOT an `INSERT ... SELECT` from `attempts`, which would
    /// be the terser spelling. That form inserts zero rows for an unknown
    /// attempt, which is indistinguishable from the `ON CONFLICT DO NOTHING` zero
    /// — so a stop addressed to nothing would be reported as
    /// [`StopRequestOutcome::AlreadyRecorded`]. The explicit probe below is what
    /// keeps those two zeros apart.
    ///
    /// # Failure
    ///
    /// Refuses an `attempt_id` with no durable attempt row, and an empty
    /// `worker_id`. Both are the same defect seen from two sides: a stop
    /// addressed to nothing. The first is a typed refusal that names the attempt,
    /// and the foreign key remains as the backstop. Refuses, by name, an
    /// `executor = 'main'` attempt: no worker holds one, so there is no generation
    /// to stop.
    pub fn record_stop_request(
        &self,
        attempt_id: Ulid,
        lease_epoch: i64,
        worker_id: &str,
        reason: &str,
    ) -> KataResult<StopRequestOutcome> {
        let now = now_ms();
        self.in_writer_txn(|tx| {
            let attempt: Option<(Vec<u8>, String)> = tx
                .query_row(
                    "SELECT execution_id, executor FROM attempts WHERE attempt_id = ?1",
                    params![attempt_id.to_bytes().as_ref()],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .optional()
                .map_err(|error| {
                    KataError::Storage(format!(
                        "read the execution of attempt {attempt_id} before recording its stop: \
                         {error}"
                    ))
                })?;
            let Some((execution_id, executor)) = attempt else {
                return Err(KataError::Validation(format!(
                    "operational.db record_stop_request has no durable attempt {attempt_id}; a \
                     stop addressed to an attempt that does not exist could never be \
                     acknowledged — no terminal will ever name it — so it would be a permanent \
                     parking refusal for an attempt nobody is running"
                )));
            };
            // REFUSED BY NAME: a MAIN-RESOLVED attempt has no worker to stop,
            // and this writer records no transition, so the executor latch in
            // `record_transition` never sees it. Its stop is a `Cancel` resolution.
            if super::AttemptExecutor::from_column(&executor)? == super::AttemptExecutor::Main {
                return Err(KataError::Validation(format!(
                    "operational.db record_stop_request refuses attempt {attempt_id}: it is a \
                     MAIN-RESOLVED attempt (`executor = 'main'`), which no worker holds, so there \
                     is nothing to stop; resolve it `cancelled` through `resolve_main_attempt`"
                )));
            }
            // `ON CONFLICT DO NOTHING` rather than an upsert: see
            // `StopRequestOutcome::AlreadyRecorded` for why the first ask wins.
            let inserted = tx
                .execute(
                    "INSERT INTO attempt_stop_requests
                         (attempt_id, lease_epoch, execution_id, worker_id, reason,
                          requested_at_ms, delivered_at_ms, acknowledged_at_ms, discharge_json)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, NULL, NULL, NULL)
                     ON CONFLICT (attempt_id, lease_epoch) DO NOTHING",
                    params![
                        attempt_id.to_bytes().as_ref(),
                        lease_epoch,
                        execution_id,
                        worker_id,
                        reason,
                        now,
                    ],
                )
                .map_err(|error| {
                    KataError::Storage(format!(
                        "record stop request for attempt {attempt_id} epoch {lease_epoch}: {error}"
                    ))
                })?;
            Ok(if inserted == 0 {
                StopRequestOutcome::AlreadyRecorded
            } else {
                StopRequestOutcome::Recorded
            })
        })
    }

    /// Mark that a transport accepted the stop frame for this generation.
    ///
    /// This is BOOKKEEPING, not safety: no SAFETY decision reads it. It is not
    /// true that "nothing branches on it":
    /// `require_terminal_lifecycle_for_parking`'s refusal message branches on it to say
    /// "delivered, unanswered" versus "never delivered",
    /// which is the difference between a wedged worker and a transport that never
    /// carried the frame.
    ///
    /// That matters because of a crash window this write cannot close. A crash
    /// between `send_control_to` returning and this mark landing leaves a stop
    /// that WAS delivered recorded as though it never was — so the refusal tells
    /// an operator "transport fault, re-issue" when the truth is "the frame
    /// landed, the worker is wedged". It is the one place this plane misreports,
    /// it misreports in the direction of extra work rather than unsafety, and
    /// closing it would need the send and the mark in one transaction across a
    /// process boundary, which is the thing that cannot be done.
    ///
    /// Idempotent, and deliberately tolerant of an absent row: a stop whose
    /// request write is somehow missing must not turn a successful send into an
    /// error. First delivery timestamp wins.
    pub fn mark_stop_delivered(&self, attempt_id: Ulid, lease_epoch: i64) -> KataResult<()> {
        let now = now_ms();
        self.in_writer_txn(|tx| {
            tx.execute(
                "UPDATE attempt_stop_requests
                    SET delivered_at_ms = ?1
                  WHERE attempt_id = ?2 AND lease_epoch = ?3 AND delivered_at_ms IS NULL",
                params![now, attempt_id.to_bytes().as_ref(), lease_epoch],
            )
            .map_err(|error| {
                KataError::Storage(format!(
                    "mark stop delivered for attempt {attempt_id} epoch {lease_epoch}: {error}"
                ))
            })?;
            Ok(())
        })
    }

    /// TEST-ONLY: [`Self::acknowledge_stop_in_tx`] in its own writer transaction.
    /// Production acknowledges inside the transaction that accepts the worker's
    /// terminal (`accept_worker_completion_with`, `adjudicate_worker_failure`).
    #[cfg(any(test, feature = "test-support"))]
    pub fn acknowledge_stop(
        &self,
        attempt_id: Ulid,
        lease_epoch: i64,
    ) -> KataResult<StopAckOutcome> {
        self.in_writer_txn(|tx| Self::acknowledge_stop_in_tx(tx, attempt_id, lease_epoch))
    }

    /// Acknowledge that the fenced worker has reported this generation's terminal.
    ///
    /// Only an authenticated physical terminal newly accepted by this transaction
    /// may discharge its exact generation. Idempotent inbox ACKs must not call
    /// this: a stop authored after the original acceptance is a new obligation.
    ///
    /// Every newly accepted terminal reaches it, so
    /// [`StopAckOutcome::NoStopRequested`] is the ordinary answer and costs one
    /// primary-key probe. It is a distinct variant rather than a silent no-op
    /// because a caller that cannot tell "acknowledged a stop" from "there was no
    /// stop" cannot log the first, and the first is the event an operator waiting
    /// on a cancel is watching for.
    pub(super) fn acknowledge_stop_in_tx(
        tx: &rusqlite::Transaction<'_>,
        attempt_id: Ulid,
        lease_epoch: i64,
    ) -> KataResult<StopAckOutcome> {
        let now = now_ms();
        let existing: Option<Option<i64>> = tx
            .query_row(
                "SELECT acknowledged_at_ms FROM attempt_stop_requests
                  WHERE attempt_id = ?1 AND lease_epoch = ?2",
                params![attempt_id.to_bytes().as_ref(), lease_epoch],
                |row| row.get(0),
            )
            .optional()
            .map_err(|error| {
                KataError::Storage(format!(
                    "read stop request for attempt {attempt_id} epoch {lease_epoch}: {error}"
                ))
            })?;
        let Some(acknowledged_at_ms) = existing else {
            return Ok(StopAckOutcome::NoStopRequested);
        };
        if acknowledged_at_ms.is_some() {
            return Ok(StopAckOutcome::AlreadyAcknowledged);
        }
        tx.execute(
            "UPDATE attempt_stop_requests
                SET acknowledged_at_ms = ?1
              WHERE attempt_id = ?2 AND lease_epoch = ?3 AND acknowledged_at_ms IS NULL",
            params![now, attempt_id.to_bytes().as_ref(), lease_epoch],
        )
        .map_err(|error| {
            KataError::Storage(format!(
                "acknowledge stop for attempt {attempt_id} epoch {lease_epoch}: {error}"
            ))
        })?;
        Ok(StopAckOutcome::Acknowledged)
    }

    /// Every stop of this execution that the worker has not answered.
    ///
    /// Empty means the execution holds no worker that was asked to stop and has
    /// not reported a terminal — which is what authorizes reclaiming its
    /// workspace. Rows are returned in `(attempt_id, lease_epoch)` order so an
    /// operator-facing refusal names them deterministically; a message that
    /// reorders itself between two runs reads as two different faults.
    ///
    /// # Why the whole row and not a count
    ///
    /// The refusal has to NAME the attempt still holding the workspace. A count
    /// tells an operator that something is outstanding and gives them no way to
    /// find it — which is the shape of refusal this whole item exists to delete.
    pub fn unacknowledged_stops(&self, execution_id: Ulid) -> KataResult<Vec<StopRequestRow>> {
        self.stop_request_scan(execution_id, true)
    }

    /// EVERY stop of this execution, acknowledged or not.
    ///
    /// # Why this is separate from [`Self::unacknowledged_stops`] rather than a
    /// filter over it
    ///
    /// They serve two different consumers with two different failure polarities,
    /// and one method with a `bool` would let a caller pick the wrong one by
    /// getting an argument backwards.
    ///
    /// [`Self::unacknowledged_stops`] is a SAFETY PREDICATE on the parking hot
    /// path: it asks one question, its answer gates a destructive operation, and
    /// it rides the partial index that holds only the outstanding rows. This is a
    /// VISIBILITY read for the execution record — an operator wants the settled
    /// stops too, because "your cancel was acknowledged 40ms later" is the answer
    /// they came for, and a projection that showed only outstanding stops would go
    /// EMPTY at the moment the cancel succeeded and look exactly like a cancel
    /// that never happened.
    pub fn execution_stop_requests(&self, execution_id: Ulid) -> KataResult<Vec<StopRequestRow>> {
        self.stop_request_scan(execution_id, false)
    }

    /// # THERE IS NO JOIN, AND THAT IS THE SAFETY PROPERTY
    ///
    /// A join through `attempts` is sound ONLY under `ON DELETE CASCADE`, where an
    /// orphaned stop row cannot exist. Under `NO ACTION` an orphan is
    /// representable, an inner join cannot see one, and
    /// [`Self::unacknowledged_stops`] would EMPTY — satisfying the parking
    /// predicate's first conjunct VACUOUSLY and authorising the workspace reclaim
    /// the latch exists to refuse.
    ///
    /// **A LEFT JOIN would NOT fix that, and this is worth stating because it is
    /// the obvious fix and it is a no-op.** Scoping through `attempts` makes the
    /// predicate `WHERE a.execution_id = ?1` — and a `WHERE` on the right-hand
    /// table of a LEFT JOIN discards exactly the NULL-extended rows the LEFT JOIN
    /// produced, collapsing it back into an inner join. The orphan stays
    /// invisible. A LEFT JOIN works only when its predicate is on the CHILD's own
    /// execution column — which is the column this table carries.
    ///
    /// So the safety comes from the column, and with the column there is nothing
    /// left to join: every field returned here comes from `attempt_stop_requests`. A join
    /// retained for symmetry would be a join a future edit could make inner
    /// again.
    fn stop_request_scan(
        &self,
        execution_id: Ulid,
        outstanding_only: bool,
    ) -> KataResult<Vec<StopRequestRow>> {
        self.with_read(|conn| {
            let predicate = if outstanding_only {
                "AND acknowledged_at_ms IS NULL"
            } else {
                ""
            };
            let mut statement = conn
                .prepare(&format!(
                    "SELECT attempt_id, lease_epoch, worker_id, reason,
                            requested_at_ms, delivered_at_ms, acknowledged_at_ms, discharge_json
                       FROM attempt_stop_requests
                      WHERE execution_id = ?1 {predicate}
                      ORDER BY attempt_id, lease_epoch"
                ))
                .map_err(|error| {
                    KataError::Storage(format!("prepare unacknowledged stop scan: {error}"))
                })?;
            let rows = statement
                .query_map(params![execution_id.to_bytes().as_ref()], |row| {
                    Ok((
                        row.get::<_, Vec<u8>>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, i64>(4)?,
                        row.get::<_, Option<i64>>(5)?,
                        row.get::<_, Option<i64>>(6)?,
                        row.get::<_, Option<Vec<u8>>>(7)?,
                    ))
                })
                .map_err(|error| {
                    KataError::Storage(format!("scan unacknowledged stops: {error}"))
                })?;
            let mut out = Vec::new();
            for row in rows {
                let (
                    attempt_id,
                    lease_epoch,
                    worker_id,
                    reason,
                    requested,
                    delivered,
                    acked,
                    discharge,
                ) = row.map_err(|error| {
                    KataError::Storage(format!("read unacknowledged stop row: {error}"))
                })?;
                out.push(StopRequestRow {
                    attempt_id: ulid_from_bytes(&attempt_id)?,
                    execution_id,
                    lease_epoch,
                    worker_id,
                    reason,
                    requested_at_ms: requested,
                    delivered_at_ms: delivered,
                    acknowledged_at_ms: acked,
                    discharge: decode_discharge(discharge.as_deref())?,
                });
            }
            Ok(out)
        })
    }

    /// One generation's durable stop record, or `None` when none was asked.
    #[cfg(any(test, feature = "test-support"))]
    pub fn stop_request(
        &self,
        attempt_id: Ulid,
        lease_epoch: i64,
    ) -> KataResult<Option<StopRequestRow>> {
        let row: Option<PointStopColumns> = self.with_read(|conn| {
            conn.query_row(
                "SELECT execution_id, worker_id, reason, requested_at_ms, delivered_at_ms,
                            acknowledged_at_ms, discharge_json
                       FROM attempt_stop_requests
                      WHERE attempt_id = ?1 AND lease_epoch = ?2",
                params![attempt_id.to_bytes().as_ref(), lease_epoch],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                        row.get(5)?,
                        row.get(6)?,
                    ))
                },
            )
            .optional()
            .map_err(|error| {
                KataError::Storage(format!(
                    "read stop request for attempt {attempt_id} epoch {lease_epoch}: {error}"
                ))
            })
        })?;
        let Some((execution_id, worker_id, reason, requested, delivered, acked, discharge)) = row
        else {
            return Ok(None);
        };
        Ok(Some(StopRequestRow {
            attempt_id,
            execution_id: ulid_from_bytes(&execution_id)?,
            lease_epoch,
            worker_id,
            reason,
            requested_at_ms: requested,
            delivered_at_ms: delivered,
            acknowledged_at_ms: acked,
            discharge: decode_discharge(discharge.as_deref())?,
        }))
    }

    /// Every stop ever asked of this attempt, ACKNOWLEDGED OR NOT, in generation
    /// order.
    ///
    /// # Why this is not [`Self::unacknowledged_stops`] filtered to one attempt
    ///
    /// It is the opposite filter, and that is the whole point. A cancel is
    /// honoured, the worker's terminal acknowledges it at epoch E,
    /// `unacknowledged_stops` empties — and a failure settlement asking whether a
    /// stop is OUTSTANDING would then record the stage `failed` rather than
    /// `cancelled`, which the runner's retry fold re-runs as a new attempt, while
    /// the operator's surface says the cancel landed.
    ///
    /// Under the latch reading a stop is a STANDING INSTRUCTION about the
    /// attempt, not an observation about one generation. The acknowledgement
    /// discharges the SAFETY question (no worker is running generation E); it
    /// does not withdraw the instruction. So the failure settlement consumes this
    /// reader, which ignores `acknowledged_at_ms` entirely.
    ///
    /// # Why it is keyed on the attempt and not on a generation
    ///
    /// A second key for this question alongside the composite `(attempt_id, lease_epoch)`
    /// the rest of the plane uses would risk re-introducing the cross-generation confusion
    /// that composite key exists to prevent. There is no second key here: this reads the
    /// PRIMARY KEY's leftmost column, so it is a point lookup on the same index every other
    /// stop read rides, and it returns EVERY generation because the instruction was never
    /// about one.
    ///
    /// `execution_id` is a defence-in-depth predicate: the caller has already
    /// resolved the attempt's execution, and a disagreement means the two are talking about
    /// different work.
    pub fn stops_standing_against_attempt(
        &self,
        execution_id: Ulid,
        attempt_id: Ulid,
    ) -> KataResult<Vec<StopRequestRow>> {
        self.with_read(|conn| {
            let mut statement = conn
                .prepare(
                    "SELECT lease_epoch, worker_id, reason, requested_at_ms, delivered_at_ms,
                            acknowledged_at_ms, discharge_json
                       FROM attempt_stop_requests
                      WHERE attempt_id = ?1 AND execution_id = ?2
                      ORDER BY lease_epoch",
                )
                .map_err(|error| {
                    KataError::Storage(format!("prepare standing stop lookup: {error}"))
                })?;
            let rows = statement
                .query_map(
                    params![
                        attempt_id.to_bytes().as_ref(),
                        execution_id.to_bytes().as_ref()
                    ],
                    |row| {
                        Ok((
                            row.get::<_, i64>(0)?,
                            row.get::<_, String>(1)?,
                            row.get::<_, String>(2)?,
                            row.get::<_, i64>(3)?,
                            row.get::<_, Option<i64>>(4)?,
                            row.get::<_, Option<i64>>(5)?,
                            row.get::<_, Option<Vec<u8>>>(6)?,
                        ))
                    },
                )
                .map_err(|error| {
                    KataError::Storage(format!("scan standing stops for attempt: {error}"))
                })?;
            let mut out = Vec::new();
            for row in rows {
                let (lease_epoch, worker_id, reason, requested, delivered, acked, discharge) = row
                    .map_err(|error| {
                        KataError::Storage(format!("read standing stop row: {error}"))
                    })?;
                out.push(StopRequestRow {
                    attempt_id,
                    execution_id,
                    lease_epoch,
                    worker_id,
                    reason,
                    requested_at_ms: requested,
                    delivered_at_ms: delivered,
                    acknowledged_at_ms: acked,
                    discharge: decode_discharge(discharge.as_deref())?,
                });
            }
            Ok(out)
        })
    }

    /// DISCHARGE an outstanding stop on an ATTRIBUTED OPERATOR ASSERTION.
    ///
    /// # Why this has to exist at all
    ///
    /// An `attempt_stop_requests` row is a latch that outlives its attempt:
    /// while it is outstanding `require_terminal_lifecycle_for_parking` refuses
    /// the workspace. The
    /// fenced worker's own terminal frame is the ordinary discharge, and there
    /// are reachable states in which that frame can never arrive — the worker's
    /// host is gone, or the worker died before answering, and an attempt is
    /// dispatched only once, so no later worker carries the stop's epoch.
    /// Without another discharge the workspace stays stranded forever, an
    /// unbounded disk leak with no exit. A
    /// latch whose only discharge is unreachable is a recourse nobody can invoke,
    /// so this discharge is MANDATORY rather than optional.
    ///
    /// # It wears the provenance vocabulary
    ///
    /// [`StopDischarge`] carries [`ObservationProvenance`](kata_types::effect::ObservationProvenance)
    /// and answers `rests_on_a_proof`, because it is a human asserting something
    /// kata cannot verify, admissible only because it is LABELLED as a human's
    /// judgement rather than dressed as a machine's observation. A `Probed`
    /// provenance is unconstructible (see [`StopDischarge::from_provenance`]), so
    /// an auto-discharge-on-worker-death — which is forbidden — cannot be built on
    /// top of this.
    ///
    /// # What it does NOT do
    ///
    /// It does not withdraw the stop. The row survives, so
    /// [`Self::stops_standing_against_attempt`] still reports it and the attempt's
    /// failure-retry stays suppressed. Discharging the SAFETY latch and
    /// re-authorizing the work are different decisions, and an operator who wants
    /// the stage to run again re-submits it rather than un-cancelling it.
    ///
    /// # Failure
    ///
    /// * ABSENT row — refused. The caller is an operator acting on a stop they
    ///   read off an execution record; telling them it is gone beats a silent
    ///   success that leaves them believing they cleared something.
    /// * Already discharged BY THE WORKER — refused. There is nothing to
    ///   discharge, and recording an assertion over a proof would replace the
    ///   strongest evidence in this plane with the weakest.
    /// * Already discharged BY AN OPERATOR — IDEMPOTENT when the record is
    ///   byte-identical (an operator surface's ordinary double-click), refused
    ///   for a different one: a conflicting re-record is not a double-click.
    pub fn discharge_stop(
        &self,
        execution_id: Ulid,
        attempt_id: Ulid,
        lease_epoch: i64,
        discharge: &StopDischarge,
    ) -> KataResult<StopDischargeOutcome> {
        let record_json = serde_json::to_vec(discharge)
            .map_err(|error| KataError::Internal(format!("serialize stop discharge: {error}")))?;
        let now = now_ms();
        self.in_writer_txn(|tx| {
            let existing: Option<(Option<i64>, Option<Vec<u8>>)> = tx
                .query_row(
                    "SELECT acknowledged_at_ms, discharge_json FROM attempt_stop_requests
                      WHERE attempt_id = ?1 AND lease_epoch = ?2 AND execution_id = ?3",
                    params![
                        attempt_id.to_bytes().as_ref(),
                        lease_epoch,
                        execution_id.to_bytes().as_ref()
                    ],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .optional()
                .map_err(|error| {
                    KataError::Storage(format!(
                        "read stop request for attempt {attempt_id} epoch {lease_epoch} before \
                         discharging it: {error}"
                    ))
                })?;
            let Some((acknowledged_at_ms, stored_discharge)) = existing else {
                return Err(KataError::Validation(format!(
                    "operational.db discharge_stop has no stop request for attempt {attempt_id} \
                     generation {lease_epoch} in execution {execution_id}; an operator discharge \
                     addresses a stop read off an execution record, so an absent one is reported \
                     rather than treated as already discharged"
                )));
            };
            if acknowledged_at_ms.is_some() {
                let Some(stored_discharge) = stored_discharge else {
                    return Err(KataError::Validation(format!(
                        "operational.db discharge_stop refuses to record an operator assertion \
                         over stop request for attempt {attempt_id} generation {lease_epoch}: it \
                         was already acknowledged by the fenced worker's own terminal frame, which \
                         PROVES no worker is running that generation. There is nothing left to \
                         discharge, and overwriting the proof with an assertion would replace this \
                         plane's strongest evidence with its weakest"
                    )));
                };
                if stored_discharge == record_json {
                    return Ok(StopDischargeOutcome::AlreadyDischarged);
                }
                return Err(KataError::Validation(format!(
                    "operational.db discharge_stop refuses to overwrite the recorded operator \
                     discharge of stop request for attempt {attempt_id} generation {lease_epoch} \
                     with a different one: the first assertion is already durable and attributed, \
                     and two disagreeing assertions about one stop is a genuine conflict rather \
                     than a last-writer-wins update"
                )));
            }
            let updated = tx
                .execute(
                    "UPDATE attempt_stop_requests
                        SET acknowledged_at_ms = ?1, discharge_json = ?2
                      WHERE attempt_id = ?3 AND lease_epoch = ?4 AND execution_id = ?5
                        AND acknowledged_at_ms IS NULL",
                    params![
                        now,
                        record_json.as_slice(),
                        attempt_id.to_bytes().as_ref(),
                        lease_epoch,
                        execution_id.to_bytes().as_ref()
                    ],
                )
                .map_err(|error| {
                    KataError::Storage(format!(
                        "discharge stop for attempt {attempt_id} epoch {lease_epoch}: {error}"
                    ))
                })?;
            if updated != 1 {
                return Err(KataError::Storage(format!(
                    "operational.db discharge_stop matched one stop request for attempt \
                     {attempt_id} generation {lease_epoch} and then updated {updated} rows for it; \
                     the (attempt_id, lease_epoch) PRIMARY KEY is not in force"
                )));
            }
            Ok(StopDischargeOutcome::Discharged)
        })
    }
}

/// The raw columns [`OperationalDb::stop_request`] selects for one generation:
/// `(execution_id, worker_id, reason, requested_at_ms, delivered_at_ms,
/// acknowledged_at_ms, discharge_json)`.
///
/// Named rather than written inline because the read is a point lookup whose key
/// is already known, so the row it builds needs both the key and every stored
/// column — which is one field past what clippy will accept as an anonymous
/// tuple. The alias is deliberately NOT shared with the scans: they select a
/// different column list (the scans already know the execution, this one does
/// not), and one alias covering both would have to be the union of two shapes.
#[cfg(any(test, feature = "test-support"))]
type PointStopColumns = (
    Vec<u8>,
    String,
    String,
    i64,
    Option<i64>,
    Option<i64>,
    Option<Vec<u8>>,
);

/// Decode a stored [`StopDischarge`], refusing bytes this binary cannot read.
///
/// A row whose discharge record will not decode is reported as an error rather
/// than read as `None`. `None` MEANS "the worker answered this stop", so a silent
/// fallback would relabel an operator's assertion as a machine proof — turning
/// unreadable evidence into the strongest claim this plane can make.
fn decode_discharge(bytes: Option<&[u8]>) -> KataResult<Option<StopDischarge>> {
    let Some(bytes) = bytes else {
        return Ok(None);
    };
    serde_json::from_slice(bytes)
        .map(Some)
        .map_err(|error| KataError::Storage(format!("decode stop discharge record: {error}")))
}
