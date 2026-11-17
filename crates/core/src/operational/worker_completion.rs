//! A completed worker input commits its acceptance and lifecycle together.
use kata_types::error::{KataError, KataResult};
use kata_types::idempotency::canonicalize_args;
use kata_types::primitives::ContentHash;
use rusqlite::{Transaction, params};
use serde::{Deserialize, Serialize};
use ulid::Ulid;

use super::repo::{dedupe_accepted_event, inbox_watermark};
use super::worker_failure::current_worker_fence;
use super::{EventAcceptance, OperationalDb};

/// A worker's completion of one attempt under the placement it was sent with. It is
/// never retained before acceptance: the capsule door accepts it in the writer
/// transaction that adopts its result
/// ([`OperationalDb::adopt_and_accept_capsule_completion`]), so a main that dies first
/// holds nothing of it, and the attempt is settled by the restart.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkerCompletionInput {
    pub execution_id: Ulid,
    pub attempt_id: Ulid,
    pub attempt_ordinal: i64,
    pub lease_epoch: i64,
    pub worker_id: String,
    pub output: serde_json::Value,
}

/// What one [`OperationalDb::adopt_and_accept_capsule_completion`] decided.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CompletionVerdict {
    /// Newly accepted; the accepting transition committed at `seq`.
    Accepted { seq: i64 },
    /// This completion was already accepted (an idempotent redelivery).
    AlreadyAccepted,
    /// The attempt was no longer this generation's live attempt when the writer
    /// transaction read it — settled, or superseded — so NOTHING was written.
    Superseded,
}

const MAX_INPUT_BYTES: usize = 64 * 1024 * 1024;

fn storage(e: rusqlite::Error) -> KataError {
    KataError::Storage(format!("worker completion: {e}"))
}

impl WorkerCompletionInput {
    fn stream(&self) -> Vec<u8> {
        let mut stream = self.attempt_id.to_bytes().to_vec();
        stream.extend_from_slice(&self.attempt_ordinal.to_be_bytes());
        stream
    }
    fn bytes(&self) -> KataResult<Vec<u8>> {
        if self.worker_id.trim().is_empty() || self.worker_id.len() > 1024 {
            return Err(KataError::Validation(
                "invalid worker completion placement".into(),
            ));
        }
        let mut value =
            serde_json::to_value(self).map_err(|e| KataError::Serialization(e.to_string()))?;
        value
            .as_object_mut()
            .expect("typed completion is an object")
            .insert("kind".into(), "worker_completion".into());
        let bytes = canonicalize_args(&value);
        if bytes.len() > MAX_INPUT_BYTES {
            return Err(KataError::Validation(
                "worker completion exceeds input record bound".into(),
            ));
        }
        Ok(bytes)
    }
    fn current(&self, tx: &Transaction<'_>) -> KataResult<bool> {
        current_worker_fence(
            tx,
            self.execution_id,
            self.attempt_id,
            self.attempt_ordinal,
            self.lease_epoch,
            &self.worker_id,
        )
    }
}

impl OperationalDb {
    fn prepare_completion(
        &self,
        input: &WorkerCompletionInput,
    ) -> KataResult<(Vec<u8>, Option<super::output::PreparedOutput>)> {
        let raw = input.bytes()?;
        let Some(prepared) =
            self.prepare_offloaded_output(input.execution_id, &input.output, raw.len())?
        else {
            return Ok((raw, None));
        };
        let mut value: serde_json::Value = serde_json::from_slice(&raw)
            .map_err(|error| KataError::Serialization(error.to_string()))?;
        prepared.write_fields(
            value
                .as_object_mut()
                .expect("typed completion is an object"),
        );
        Ok((canonicalize_args(&value), Some(prepared)))
    }

    /// The ACCEPTING half of a worker completion, on the caller's writer transaction:
    /// the inbox fold that records the attempt's `completed` transition, the stop
    /// acknowledgement and `source_seq`.
    ///
    /// The caller has already decided the input is CURRENT under the same transaction;
    /// this never re-reads the fence.
    fn accept_completion_in_tx(
        tx: &Transaction<'_>,
        input: &WorkerCompletionInput,
        stream: &[u8],
        digest: ContentHash,
        bytes: &[u8],
    ) -> KataResult<EventAcceptance> {
        let accepted = Self::accept_incoming_event_in_tx(
            tx,
            input.execution_id,
            input.attempt_id,
            stream,
            1,
            digest,
            "completed",
            bytes,
        )?;
        if let EventAcceptance::Accepted { seq } = accepted {
            Self::acknowledge_stop_in_tx(tx, input.attempt_id, input.lease_epoch)?;
            tx.execute(
                "UPDATE attempts SET source_seq=?1 WHERE attempt_id=?2",
                params![seq, input.attempt_id.to_bytes().as_slice()],
            )
            .map_err(storage)?;
        }
        Ok(accepted)
    }

    /// [`Self::accept_worker_completion_with`] declaring nothing: the capsule door's
    /// accepting transaction for a rig that declares a result on its own
    /// ([`Self::adopt_capsule_result`]) or carries none. Production accepts a worker
    /// completion only through [`Self::adopt_and_accept_capsule_completion`].
    ///
    /// # Errors
    ///
    /// [`Self::accept_worker_completion_with`]'s.
    #[cfg(any(test, feature = "test-support"))]
    pub fn accept_worker_completion(
        &self,
        input: &WorkerCompletionInput,
    ) -> KataResult<CompletionVerdict> {
        self.accept_worker_completion_with(input, |_| Ok(()))
    }

    /// ONE writer transaction that re-reads the fence, runs `before_accept` (the capsule
    /// result's declaration), and accepts.
    ///
    /// # Invariant — exactly one of accept or settle wins
    ///
    /// The fence (`current_worker_fence`: this generation, this worker, a LIVE
    /// projected state) is read UNDER THE WRITE LOCK, and a main-side settlement
    /// ([`OperationalDb::record_main_side_transition_if_live`]) reads liveness under the
    /// same lock. Whichever commits first leaves the other a no-op: a settled attempt
    /// answers [`CompletionVerdict::Superseded`] here with `before_accept` NEVER RUN —
    /// so a capsule result is declared only in the transaction that accepts it — and an
    /// accepted attempt answers `None` to the settlement.
    ///
    /// # Errors
    ///
    /// An invalid input, `before_accept`'s refusal (which rolls the whole transaction
    /// back), a digest that diverges from an already-accepted completion, and storage.
    pub(super) fn accept_worker_completion_with(
        &self,
        input: &WorkerCompletionInput,
        before_accept: impl FnOnce(&Transaction<'_>) -> KataResult<()>,
    ) -> KataResult<CompletionVerdict> {
        let (bytes, prepared) = self.prepare_completion(input)?;
        let digest = ContentHash::new(*blake3::hash(&bytes).as_bytes());
        let stream = input.stream();
        let verdict = self.in_writer_txn(|tx| {
            if inbox_watermark(tx, &stream)? >= 1 {
                dedupe_accepted_event(tx, &stream, 1, digest)?;
                return Ok(CompletionVerdict::AlreadyAccepted);
            }
            if !input.current(tx)? {
                return Ok(CompletionVerdict::Superseded);
            }
            if let Some(prepared) = &prepared {
                prepared.record_root(tx)?;
            }
            before_accept(tx)?;
            match Self::accept_completion_in_tx(tx, input, &stream, digest, &bytes)? {
                EventAcceptance::Accepted { seq } => Ok(CompletionVerdict::Accepted { seq }),
                EventAcceptance::IdempotentAck => Ok(CompletionVerdict::AlreadyAccepted),
            }
        })?;
        if matches!(verdict, CompletionVerdict::Accepted { .. }) {
            crate::fault_inject::operational_crash_point("after_accept_event");
        }
        Ok(verdict)
    }
}

#[cfg(test)]
#[path = "worker_completion_tests.rs"]
mod tests;
