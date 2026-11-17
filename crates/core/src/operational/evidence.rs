//! Execution-level evidence.
//!
//! # What these tables are, and what they deliberately are not
//!
//! `execution_evidence` and `execution_evidence_claims` rows have no source sequence on
//! the transition chain. `append_execution_evidence`
//! appends "without creating a worker assignment or emitting a lifecycle ledger event",
//! so there is no transition to attribute one to, and minting a synthetic one would
//! make an OBSERVATION look like a DECISION in the audit chain.
//!
//! They carry a foreign key — `execution_id` REFERENCES `programs` ON DELETE CASCADE —
//! and the operational plane's `synchronous=FULL` writer, so they never outlive their
//! execution with their full payload.
//!
//! # The refusal this creates, stated rather than discovered
//!
//! The foreign key means evidence for an execution this node never SUBMITTED is
//! unwritable. That is the point — an evidence row nothing can adjudicate is a
//! reference with no subject — but it is also a real ordering obligation on callers:
//! the `programs` row must commit before its evidence. Every production caller already
//! satisfies it (admission submits the execution before publishing admission evidence),
//! and a caller that does not gets a typed foreign-key refusal naming the execution
//! rather than a row nobody can find later.

use kata_types::error::{KataError, KataResult};
use kata_types::execution::ExecutionEvidence;
use rusqlite::{Transaction, params};
use serde::{Deserialize, Serialize};
use ulid::Ulid;

use super::OperationalDb;

/// Durable execution-level evidence that is not itself a worker assignment.
///
/// Execution evidence is stored through this typed metadata record so replay,
/// recovery, and projection do not depend on synthetic worker assignments.
///
/// The whole record is serialized into `execution_evidence.evidence_json`, and the
/// three scalar columns beside it are the LOOKUP coordinates rather than a second copy
/// of the payload's meaning — the same posture `capsules` takes toward its object.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct ExecutionEvidenceRecord {
    pub id: Ulid,
    pub execution_id: Ulid,
    pub created_at_ms: u64,
    pub evidence: ExecutionEvidence,
}

/// Result of an atomic execution-evidence claim append.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ExecutionEvidenceClaimOutcome {
    /// This caller won the claim and the supplied evidence row was persisted.
    Claimed,
    /// Another caller already owns this execution-local claim key.
    AlreadyClaimed,
}

impl OperationalDb {
    /// Append one execution-level evidence row. Idempotent by `record.id`.
    ///
    /// # Failure
    ///
    /// An `execution_id` with no `programs` row is a typed refusal from the foreign
    /// key — see this module's header for why that refusal is the point.
    pub fn append_execution_evidence(&self, record: &ExecutionEvidenceRecord) -> KataResult<()> {
        let bytes = encode(record)?;
        self.in_writer_txn(|tx| insert_evidence(tx, record, &bytes))
    }

    /// Atomically claim one execution-local key and append `record` only if this
    /// caller won the claim.
    ///
    /// # Invariant
    ///
    /// THE CLAIM AND THE ROW COMMIT TOGETHER. `(execution_id, claim_key)` is the
    /// deduplication boundary and the reason callers place this BEFORE a
    /// non-idempotent side effect: a claim that committed without its evidence would
    /// report "already claimed" forever for a row that does not exist, so the
    /// observation the claim was taken out to record would be permanently unwritable.
    /// One `in_writer_txn` is what makes that unrepresentable.
    ///
    /// # Failure
    ///
    /// An empty `claim_key` is refused by the stored `CHECK (length(claim_key) > 0)`;
    /// an unsubmitted `execution_id` by the foreign key.
    pub fn append_execution_evidence_claimed(
        &self,
        claim_key: &str,
        record: &ExecutionEvidenceRecord,
    ) -> KataResult<ExecutionEvidenceClaimOutcome> {
        let bytes = encode(record)?;
        self.in_writer_txn(|tx| {
            let inserted = tx
                .execute(
                    "INSERT OR IGNORE INTO execution_evidence_claims
                         (execution_id, claim_key, evidence_id, created_at_ms)
                     VALUES (?1, ?2, ?3, ?4)",
                    params![
                        record.execution_id.to_bytes().as_ref(),
                        claim_key,
                        record.id.to_bytes().as_ref(),
                        created_at_ms(record),
                    ],
                )
                .map_err(|error| {
                    KataError::Storage(format!(
                        "operational.db insert execution evidence claim: {error}"
                    ))
                })?;
            if inserted == 0 {
                return Ok(ExecutionEvidenceClaimOutcome::AlreadyClaimed);
            }
            insert_evidence(tx, record, &bytes)?;
            Ok(ExecutionEvidenceClaimOutcome::Claimed)
        })
    }

    /// Every execution-level evidence row on this plane, in the deterministic
    /// `(created_at_ms, evidence_id)` order replay and projection depend on — served by
    /// `idx_execution_evidence_execution`.
    pub fn load_all_execution_evidence(&self) -> KataResult<Vec<ExecutionEvidenceRecord>> {
        self.with_read(|conn| {
            let mut statement = conn
                .prepare(
                    "SELECT evidence_json FROM execution_evidence
                      ORDER BY created_at_ms ASC, evidence_id ASC",
                )
                .map_err(|error| {
                    KataError::Storage(format!(
                        "operational.db prepare execution evidence scan: {error}"
                    ))
                })?;
            let rows = statement
                .query_map([], |row| row.get::<_, Vec<u8>>(0))
                .map_err(|error| {
                    KataError::Storage(format!("operational.db execution evidence scan: {error}"))
                })?;
            let mut out = Vec::new();
            for row in rows {
                let bytes = row.map_err(|error| {
                    KataError::Storage(format!(
                        "operational.db execution evidence row read: {error}"
                    ))
                })?;
                out.push(decode(&bytes)?);
            }
            Ok(out)
        })
    }

    /// Every execution-level evidence row for ONE execution, in the same order.
    #[cfg(any(test, feature = "test-support"))]
    pub fn execution_evidence_for(
        &self,
        execution_id: Ulid,
    ) -> KataResult<Vec<ExecutionEvidenceRecord>> {
        self.with_read(|conn| {
            let mut statement = conn
                .prepare(
                    "SELECT evidence_json FROM execution_evidence
                      WHERE execution_id = ?1
                      ORDER BY created_at_ms ASC, evidence_id ASC",
                )
                .map_err(|error| {
                    KataError::Storage(format!(
                        "operational.db prepare per-execution evidence scan: {error}"
                    ))
                })?;
            let rows = statement
                .query_map(params![execution_id.to_bytes().as_ref()], |row| {
                    row.get::<_, Vec<u8>>(0)
                })
                .map_err(|error| {
                    KataError::Storage(format!(
                        "operational.db per-execution evidence scan: {error}"
                    ))
                })?;
            let mut out = Vec::new();
            for row in rows {
                let bytes = row.map_err(|error| {
                    KataError::Storage(format!("operational.db evidence row read: {error}"))
                })?;
                out.push(decode(&bytes)?);
            }
            Ok(out)
        })
    }
}

/// `INSERT OR REPLACE` keyed on `evidence_id`, carried over from `ledger.db`
/// unchanged: the id is minted per append, so a replace can only ever be a retry of
/// the identical row, and the claimed door's dedupe boundary is the CLAIM rather than
/// this key.
/// `pub(super)` — `capsule_result` writes its egress-refusal row through this
/// same INSERT inside the accepting transaction; nothing outside `operational`
/// writes evidence rows.
pub(super) fn insert_evidence(
    tx: &Transaction<'_>,
    record: &ExecutionEvidenceRecord,
    bytes: &[u8],
) -> KataResult<()> {
    tx.execute(
        "INSERT OR REPLACE INTO execution_evidence
             (evidence_id, execution_id, created_at_ms, evidence_json)
         VALUES (?1, ?2, ?3, ?4)",
        params![
            record.id.to_bytes().as_ref(),
            record.execution_id.to_bytes().as_ref(),
            created_at_ms(record),
            bytes,
        ],
    )
    .map_err(|error| {
        KataError::Storage(format!("operational.db append execution evidence: {error}"))
    })?;
    Ok(())
}

/// The record's instant as the column's `i64`. SATURATING, exactly as `ledger.db`
/// did: the field is a `u64` whose only producer is `now_ms()`, so a value above
/// `i64::MAX` is unreachable, and clamping keeps a corrupt one from becoming a
/// negative instant that would sort before every real row.
fn created_at_ms(record: &ExecutionEvidenceRecord) -> i64 {
    i64::try_from(record.created_at_ms).unwrap_or(i64::MAX)
}

/// `pub(super)` — the same row serializes one way whether it is appended from
/// `append_execution_evidence`, claimed, or written inside an accepting
/// transaction (`capsule_result`); the error a mis-shaped record returns is
/// identical on every door.
pub(super) fn encode(record: &ExecutionEvidenceRecord) -> KataResult<Vec<u8>> {
    serde_json::to_vec(record).map_err(|error| {
        KataError::Serialization(format!(
            "operational.db serialize ExecutionEvidenceRecord: {error}"
        ))
    })
}

fn decode(bytes: &[u8]) -> KataResult<ExecutionEvidenceRecord> {
    serde_json::from_slice(bytes).map_err(|error| {
        KataError::Serialization(format!(
            "operational.db deserialize ExecutionEvidenceRecord: {error}"
        ))
    })
}
