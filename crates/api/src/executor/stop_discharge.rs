//! The ATTRIBUTED OPERATOR DISCHARGE of a worker stop.
//!
//! # Why this exists, and why it is MANDATORY rather than a convenience
//!
//! An `attempt_stop_requests` row is a LATCH gating a destructive operation, not
//! evidence that dies with its attempt: while a stop is outstanding,
//! `require_terminal_lifecycle_for_parking` refuses to reclaim the execution's candidate
//! workspace. (The row's `attempts` foreign key is `NO ACTION`; kata deletes no attempt
//! rows, so that key refuses nothing today.)
//!
//! The only other discharge is the fenced worker's own terminal frame, and
//! `acknowledge_stop_in_tx` has exactly one caller: a terminal carrying the
//! stop's `lease_epoch`. Once the worker's host is gone, or the worker died
//! before answering, no frame will ever carry it: an attempt is dispatched once,
//! and nothing re-dispatches it to a worker that could. That strands the workspace forever — an unbounded disk leak
//! with no exit.
//!
//! A latch whose only discharge is unreachable is a recourse nobody can invoke;
//! this is its reachable discharge.
//!
//! # It records a human assertion in the shared provenance vocabulary
//!
//! It is a human asserting something kata cannot verify, so it wears the tree's
//! one spelling of that: `ObservationProvenance::OperatorAsserted`, a required
//! attribution, `rests_on_a_proof: false`, and a durable record on the authority
//! chain. A parallel vocabulary for "how do we know, and is it a proof?" would be
//! a second answer to one question, and two answers to one question is how they
//! come to disagree.
//!
//! # What it is NOT: an auto-discharge
//!
//! What must not happen is auto-discharge on a worker-death declaration —
//! heartbeat loss is not proof of process exit, which is the premise of the
//! parking predicate's second conjunct. There
//! is no probe mode here and there cannot be one:
//! [`StopDischarge::from_provenance`] returns `None` for a probe, so an
//! automatic discharge is unconstructible rather than merely discouraged.

use kata_core::operational::stop_ack::StopDischargeOutcome;
use kata_types::effect::ObservationProvenance;
use kata_types::execution::StopDischarge;
use kata_types::time::now_ms;
use ulid::Ulid;

use super::{ExecutorError, WorkflowExecutor};

/// One operator's attributed assertion that a stopped worker is no longer
/// running.
///
/// The attribution is a required field rather than an option: there is no other
/// provenance, so there is no case in which an unattributed call would be
/// meaningful.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StopDischargeAssertion {
    /// Who is asserting.
    pub operator: String,
    /// What they established, in their own words.
    pub assertion: String,
}

/// The result of one discharge attempt.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StopDischargeOutcomeReport {
    /// The attempt whose stop was addressed.
    pub attempt_id: Ulid,
    /// The lease epoch whose stop was addressed.
    pub lease_epoch: i64,
    /// Whether THIS call performed the discharge. `false` means an identical
    /// assertion had already been recorded.
    pub discharged: bool,
    /// The durable record that stands, which on a re-submission is the FIRST
    /// one recorded rather than the one just presented.
    pub record: StopDischarge,
    /// How many of the execution's stops remain outstanding afterwards.
    pub outstanding_remaining: usize,
}

impl WorkflowExecutor {
    /// Discharge one outstanding worker stop on an attributed operator
    /// assertion.
    ///
    /// An operator reads the attempt and lease epoch off
    /// `ExecutionRecord.evidence.worker_stops[]` — the row whose
    /// `awaiting_worker_acknowledgement` is `true` — and passes them here,
    /// through `kata run discharge-stop`, the `discharge_stop` operation on any
    /// face, or `POST /ops/discharge_stop`.
    ///
    /// # The lease epoch is REQUIRED and is not defaulted
    ///
    /// A stop is keyed by `(attempt_id, lease_epoch)`, and the discharge names the
    /// exact row it clears, copied from the evidence row, rather than one a default
    /// would pick.
    ///
    /// # Errors
    ///
    /// [`ExecutorError::PolicyDenied`] when the assertion is unattributed or
    /// empty (an assertion nobody can be held to is not an attribution), and when
    /// the addressed stop is absent, was already answered BY THE WORKER, or
    /// already carries a DIFFERENT operator's assertion.
    /// [`ExecutorError::DurabilityFailed`] when the stop plane cannot be read or
    /// written.
    pub fn discharge_worker_stop(
        &self,
        execution_id: Ulid,
        attempt_id: Ulid,
        lease_epoch: i64,
        assertion: &StopDischargeAssertion,
    ) -> Result<StopDischargeOutcomeReport, ExecutorError> {
        // Built BEFORE anything is read, so an inadmissible assertion is refused
        // without the caller learning whether the stop they named exists.
        let record = StopDischarge::from_provenance(
            ObservationProvenance::OperatorAsserted {
                operator: assertion.operator.clone(),
            },
            assertion.assertion.clone(),
            now_ms(),
        )
        .ok_or_else(|| {
            ExecutorError::PolicyDenied(
                "a stop discharge requires BOTH a named operator and a non-empty assertion: the \
                 durable record is admissible only because it says which human decided and what \
                 they checked, and an unattributed or empty one is indistinguishable from a \
                 machine observation to everyone who reads it later"
                    .to_string(),
            )
        })?;

        // Report an ABSENT stop as not-found HERE, so it is distinguishable from
        // the refusals that mean "the stop exists and may not be discharged". The
        // durable mutator refuses an absent row independently — this is not a
        // substitute for that guard, it is a typed answer for the operator, and
        // both must hold.
        let before = self
            .dispatcher
            .execution_attempt_stops(execution_id)
            .map_err(|error| {
                ExecutorError::DurabilityFailed(format!(
                    "read worker stops for {execution_id}: {error}"
                ))
            })?;
        if !before
            .iter()
            .any(|row| row.attempt_id == attempt_id && row.lease_epoch == lease_epoch)
        {
            return Err(ExecutorError::ExecutionNotFound(format!(
                "execution {execution_id} holds no stop for attempt {attempt_id} lease epoch \
                 {lease_epoch}; the attempt and lease epoch are copied from a `worker_stops` \
                 evidence row, and an absent one means you are addressing something that no \
                 longer exists rather than something already discharged"
            )));
        }

        let outcome = self
            .dispatcher
            .discharge_attempt_stop(execution_id, attempt_id, lease_epoch, &record)
            .map_err(|error| classify_discharge_error(&error))?;

        // Re-read rather than assume: on `AlreadyDischarged` the record that
        // STANDS is the first one, not the one just presented, and reporting the
        // presented one back would tell a second operator their attribution
        // landed when it did not.
        let stored = self
            .dispatcher
            .execution_attempt_stops(execution_id)
            .map_err(|error| {
                ExecutorError::DurabilityFailed(format!(
                    "re-read worker stops for {execution_id} after discharging attempt \
                     {attempt_id} lease epoch {lease_epoch}: {error}"
                ))
            })?;
        let record = stored
            .iter()
            .find(|row| row.attempt_id == attempt_id && row.lease_epoch == lease_epoch)
            .and_then(|row| row.discharge.clone())
            .unwrap_or(record);
        let outstanding_remaining = stored.iter().filter(|row| row.is_outstanding()).count();

        Ok(StopDischargeOutcomeReport {
            attempt_id,
            lease_epoch,
            discharged: outcome == StopDischargeOutcome::Discharged,
            record,
            outstanding_remaining,
        })
    }
}

/// Map the durable plane's refusal onto the operator-facing error class.
///
/// `Validation` is the plane's word for every refusal this operation can
/// legitimately meet — absent stop, already answered by the worker, conflicting
/// assertion — and each is a POLICY answer to a well-formed request rather than a
/// durability fault. Collapsing them all into `DurabilityFailed` would report an
/// operator's mistake as a node fault and page somebody.
fn classify_discharge_error(error: &kata_types::error::KataError) -> ExecutorError {
    match error {
        kata_types::error::KataError::Validation(message) => {
            ExecutorError::PolicyDenied(message.clone())
        }
        other => ExecutorError::DurabilityFailed(other.to_string()),
    }
}
