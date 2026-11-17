//! [`ExecutionLifecycleView`] — the ONE narrow read facade over the execution
//! nucleus (`programs`, `invocations`, `execution_lifecycle`).
//!
//! # Invariant
//!
//! Every production reader of execution lifecycle / checked program / immutable
//! invocation state goes through this view, so a new reader extends the view rather
//! than re-threading the call sites in `crates/api/src/executor/mod.rs`.
//!
//! # Failure mode
//!
//! [`ExecutionLifecycleView::invocation`] RE-VERIFIES the durable invocation on
//! every read: the stored bytes must be canonical JSON and `blake3(bytes)` must
//! equal the stored `admission_digest`. Dropping that re-verification is what
//! would turn the invocation from a self-verifying resume authority into a blob
//! the runtime trusts. The typed decode stays with the caller (the typed
//! `ExecutionInvocation` lives in `kata-workflow`, which this crate does not
//! depend on); the BYTE-level anti-forgery check lives here so no face can skip
//! it.
//!
//! # Enforcement
//!
//! The view holds only an `Arc<OperationalDb>` and issues no writes — every
//! mutation of the nucleus stays inside [`OperationalDb`]'s typed transactions.
//! Its reads run on the owned writer connection: each one is a single-row
//! primary-key lookup or a bounded id scan. Long or streaming projection scans belong
//! on [`OperationalDb::open_reader`], which carries the busy timeout.

use std::sync::Arc;

use kata_types::error::{KataError, KataResult};
use kata_types::idempotency::canonicalize_args;
use kata_types::identity_algebra::AdmissionDigest;
use kata_types::primitives::ContentHash;
use rusqlite::{Connection, OptionalExtension, params};
use ulid::Ulid;

use super::{InvocationKind, LifecycleRow, OperationalDb, ulid_from_bytes};

/// The durable checked program for one execution, as stored.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProgramView {
    /// The program's content-hash identity.
    pub program_hash: ContentHash,
    /// The program-format schema version.
    pub schema_version: i64,
    /// The opaque serialized checked program.
    pub program_json: Vec<u8>,
    /// Admission instant.
    pub created_at_ms: i64,
}

/// The durable immutable invocation for one execution, re-verified on read.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InvocationView {
    /// The invocation-envelope schema version.
    pub schema_version: i64,
    /// Workflow or direct-agent admission.
    pub kind: InvocationKind,
    /// The digest binding this invocation to one resolved typed-input set. Proven
    /// on read to equal `blake3(invocation_json)`.
    pub admission_digest: AdmissionDigest,
    /// The canonical serialized invocation envelope.
    pub invocation_json: Vec<u8>,
    /// Admission instant.
    pub created_at_ms: i64,
}

/// The narrow read facade over the execution nucleus. Clone-cheap.
#[derive(Clone, Debug)]
pub struct ExecutionLifecycleView {
    db: Arc<OperationalDb>,
}

impl ExecutionLifecycleView {
    /// Wrap an operational database in the read facade.
    #[must_use]
    pub fn new(db: Arc<OperationalDb>) -> Self {
        Self { db }
    }

    /// The operational writer this view reads from. Writers reach the nucleus only
    /// through [`OperationalDb`]'s typed transaction methods.
    #[must_use]
    pub fn db(&self) -> &Arc<OperationalDb> {
        &self.db
    }

    /// The durable lifecycle row, or `None` when the execution was never
    /// submitted.
    pub fn lifecycle(&self, execution_id: Ulid) -> KataResult<Option<LifecycleRow>> {
        self.db.execution_lifecycle(execution_id)
    }

    /// The opaque checked-program JSON for an execution.
    pub fn program_json(&self, execution_id: Ulid) -> KataResult<Option<Vec<u8>>> {
        self.with_read(|conn| {
            conn.query_row(
                "SELECT program_json FROM programs WHERE execution_id = ?1",
                params![execution_id.to_bytes().as_ref()],
                |row| row.get::<_, Vec<u8>>(0),
            )
            .optional()
            .map_err(|error| KataError::Storage(format!("read program json: {error}")))
        })
    }

    /// The full durable program row.
    pub fn program(&self, execution_id: Ulid) -> KataResult<Option<ProgramView>> {
        self.with_read(|conn| {
            conn.query_row(
                "SELECT program_hash, schema_version, program_json, created_at_ms
                   FROM programs WHERE execution_id = ?1",
                params![execution_id.to_bytes().as_ref()],
                |row| {
                    Ok((
                        row.get::<_, Vec<u8>>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, Vec<u8>>(2)?,
                        row.get::<_, i64>(3)?,
                    ))
                },
            )
            .optional()
            .map_err(|error| KataError::Storage(format!("read program: {error}")))?
            .map(|(hash, schema_version, program_json, created_at_ms)| {
                Ok(ProgramView {
                    program_hash: content_hash(&hash, "program hash")?,
                    schema_version,
                    program_json,
                    created_at_ms,
                })
            })
            .transpose()
        })
    }

    /// The immutable invocation envelope, RE-VERIFIED: canonical JSON, and
    /// `blake3(invocation_json) == admission_digest`.
    ///
    /// # Failure
    ///
    /// A stored envelope that is not canonical JSON, or whose stored digest does
    /// not bind its bytes, is a typed [`KataError::Storage`] refusal, never a
    /// silently-accepted read.
    pub fn invocation(&self, execution_id: Ulid) -> KataResult<Option<InvocationView>> {
        let row = self.with_read(|conn| {
            conn.query_row(
                "SELECT schema_version, kind, admission_digest, invocation_json, created_at_ms
                   FROM invocations WHERE execution_id = ?1",
                params![execution_id.to_bytes().as_ref()],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, Vec<u8>>(2)?,
                        row.get::<_, Vec<u8>>(3)?,
                        row.get::<_, i64>(4)?,
                    ))
                },
            )
            .optional()
            .map_err(|error| KataError::Storage(format!("read invocation: {error}")))
        })?;
        let Some((schema_version, kind, digest, invocation_json, created_at_ms)) = row else {
            return Ok(None);
        };
        let value: serde_json::Value =
            serde_json::from_slice(&invocation_json).map_err(|error| {
                KataError::Storage(format!(
                    "decode invocation for execution {execution_id}: {error}"
                ))
            })?;
        if canonicalize_args(&value) != invocation_json {
            return Err(KataError::Storage(format!(
                "execution {execution_id} invocation is not canonical JSON"
            )));
        }
        let stored = content_hash(&digest, "admission digest")?;
        if *blake3::hash(&invocation_json).as_bytes() != stored.into_array() {
            return Err(KataError::Storage(format!(
                "execution {execution_id} admission digest does not bind its invocation"
            )));
        }
        Ok(Some(InvocationView {
            schema_version,
            kind: parse_invocation_kind(&kind)?,
            admission_digest: AdmissionDigest(stored),
            invocation_json,
            created_at_ms,
        }))
    }

    /// Every non-terminal execution recovery must reconcile before readiness.
    pub fn recoverable_ids(&self) -> KataResult<Vec<Ulid>> {
        self.scan_ids(
            "SELECT execution_id FROM execution_lifecycle
              WHERE state IN ('admitting', 'running', 'terminalizing')
              ORDER BY execution_id",
        )
    }

    /// Every execution the nucleus knows about, in id order.
    pub fn known_ids(&self) -> KataResult<Vec<Ulid>> {
        self.scan_ids("SELECT execution_id FROM execution_lifecycle ORDER BY execution_id")
    }

    /// Every active execution the boot-time THREE-WAY integrity check must examine.
    ///
    /// # Failure mode
    ///
    /// [`Self::recoverable_ids`] selects on `execution_lifecycle.state` — one of
    /// the three representations the check compares. Drawing the check's
    /// candidate set from it means a lifecycle row corrupted in the in-flight ->
    /// terminal direction removes ITSELF from the set and is never examined,
    /// which is precisely the corruption that silently abandons live work: boot
    /// finds "nothing to recover" and reports ready.
    ///
    /// So this set is the UNION of three questions asked of two independent
    /// columns:
    ///
    /// - the lifecycle says in-flight (the recoverable set — still needed, it is
    ///   what recovery acts on);
    /// - the PROJECTION says in-flight (catches the lifecycle forged terminal);
    ///
    /// Active state on either side is sufficient to catch disagreement in either
    /// direction and a missing counterpart without scanning terminal history.
    ///
    /// # Enforcement
    ///
    /// BOUNDED, and deliberately not a full-history scan. Partial active indexes
    /// enumerate only recoverable rows and primary-key probes check the other
    /// side, so this is O(number of active executions) with NO `transitions`
    /// access at all. Only the ids it returns pay
    /// the O(chain length) `rebuild_from_chain`, and on a coherent nucleus it
    /// returns only the genuinely in-flight ones. The remaining per-boot cost is
    /// one `MAX(seq)` index lookup for the global watermark.
    ///
    /// It is not a total detector, and cannot be: a corruption that moved the
    /// lifecycle row AND the projection to the same wrong state agrees on both
    /// columns, and only the chain — the O(#transitions) representation — would
    /// disagree. Catching that per boot means replaying every chain on every
    /// boot, which is the cost this bound exists to refuse. The chain remains the
    /// authority for every execution this set DOES return.
    pub fn integrity_candidate_ids(&self) -> KataResult<Vec<Ulid>> {
        self.scan_ids(
            "SELECT execution_id FROM (
                 SELECT l.execution_id AS execution_id
                   FROM execution_lifecycle l
                   LEFT JOIN execution_projection p ON p.execution_id = l.execution_id
                  WHERE l.state IN ('admitting', 'running', 'terminalizing')
                 UNION
                 SELECT p.execution_id AS execution_id
                   FROM execution_projection p
                   LEFT JOIN execution_lifecycle l ON l.execution_id = p.execution_id
                  WHERE p.state IN ('admitting', 'running', 'terminalizing')
             )
             ORDER BY execution_id",
        )
    }

    /// [`active_program_rows`] on the nucleus's own connection: the programs boot's
    /// compatibility membrane classifies.
    pub fn active_program_json(&self) -> KataResult<Vec<(Ulid, Vec<u8>)>> {
        self.with_read(active_program_rows)
    }

    /// Canonical checked-program and invocation byte lengths for active executions.
    pub fn active_admission_byte_lengths(&self) -> KataResult<Vec<(Ulid, u64)>> {
        self.with_read(|conn| {
            let mut stmt = conn
                .prepare(
                    "SELECT l.execution_id, length(p.program_json), length(i.invocation_json)
                   FROM execution_lifecycle l
                   JOIN programs p ON p.execution_id = l.execution_id
                   JOIN invocations i ON i.execution_id = l.execution_id
                  WHERE l.state IN ('admitting', 'running', 'terminalizing')
                  ORDER BY l.execution_id",
                )
                .map_err(|error| {
                    KataError::Storage(format!("prepare active residency scan: {error}"))
                })?;
            let rows = stmt
                .query_map([], |row| {
                    Ok((
                        row.get::<_, Vec<u8>>(0)?,
                        row.get::<_, u64>(1)?,
                        row.get::<_, u64>(2)?,
                    ))
                })
                .map_err(|error| KataError::Storage(format!("scan active residency: {error}")))?;
            let mut out = Vec::new();
            for row in rows {
                let (id, program, invocation) = row.map_err(|error| {
                    KataError::Storage(format!("active residency row: {error}"))
                })?;
                let bytes = program.checked_add(invocation).ok_or_else(|| {
                    KataError::Storage(
                        "active execution canonical byte length overflow".to_string(),
                    )
                })?;
                out.push((ulid_from_bytes(&id)?, bytes));
            }
            Ok(out)
        })
    }

    fn scan_ids(&self, sql: &str) -> KataResult<Vec<Ulid>> {
        self.with_read(|conn| {
            let mut stmt = conn
                .prepare(sql)
                .map_err(|error| KataError::Storage(format!("prepare id scan: {error}")))?;
            let rows = stmt
                .query_map([], |row| row.get::<_, Vec<u8>>(0))
                .map_err(|error| KataError::Storage(format!("id scan: {error}")))?;
            let mut ids = Vec::new();
            for row in rows {
                let bytes = row.map_err(|error| KataError::Storage(format!("id row: {error}")))?;
                ids.push(ulid_from_bytes(&bytes)?);
            }
            Ok(ids)
        })
    }

    /// Run a nucleus read on the owned writer connection.
    ///
    /// Deliberately NOT a fresh [`OperationalDb::open_reader`] per call: every read
    /// here is a single-row primary-key lookup or a bounded id scan, and minting a
    /// SQLite connection per read costs more than the microseconds it holds the
    /// writer mutex: one `Mutex<Connection>` serving reads and writes. Long or streaming
    /// projection scans belong on [`OperationalDb::open_reader`], which carries the
    /// busy timeout.
    fn with_read<T>(&self, body: impl FnOnce(&Connection) -> KataResult<T>) -> KataResult<T> {
        self.db.with_read(body)
    }
}

/// The `(execution_id, program_json)` of every execution whose top-level lifecycle is
/// NOT terminal (`admitting`, `running`, `terminalizing`), in id order — the retained
/// checked programs a binary must be able to dispatch before it may run on this
/// directory.
///
/// # Invariant
///
/// ONE definition, two connections: boot reads it through
/// [`ExecutionLifecycleView::active_program_json`] on the opened nucleus, and
/// `kata upgrade` reads it on the immutable inspection handle, which has no
/// [`OperationalDb`] to borrow. Both classify the rows the same way
/// (`kata_workflow::execution_program_store::blocking_incompatible_programs`), so the
/// preview cannot refuse a directory boot starts on, nor pass one boot refuses — for
/// instance by blocking on terminal and lifecycle-less rows boot never checks.
///
/// A terminal execution's program is retained evidence, never dispatched again, and
/// a program row with no lifecycle row was never admitted to run; neither is
/// returned. The lifecycle row is the top-level terminal authority — assignment
/// rows are not, because a completed predecessor may have an undispatched successor.
pub fn active_program_rows(conn: &Connection) -> KataResult<Vec<(Ulid, Vec<u8>)>> {
    let mut stmt = conn
        .prepare(
            "SELECT p.execution_id, p.program_json
               FROM execution_lifecycle l
               JOIN programs p ON p.execution_id = l.execution_id
              WHERE l.state IN ('admitting', 'running', 'terminalizing')
              ORDER BY l.execution_id",
        )
        .map_err(|error| KataError::Storage(format!("prepare program scan: {error}")))?;
    let rows = stmt
        .query_map([], |row| {
            Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?))
        })
        .map_err(|error| KataError::Storage(format!("scan programs: {error}")))?;
    let mut out = Vec::new();
    for row in rows {
        let (id, json) =
            row.map_err(|error| KataError::Storage(format!("program row: {error}")))?;
        out.push((ulid_from_bytes(&id)?, json));
    }
    Ok(out)
}

fn content_hash(bytes: &[u8], what: &str) -> KataResult<ContentHash> {
    let array: [u8; 32] = bytes.try_into().map_err(|_| {
        KataError::Storage(format!(
            "operational.db {what} must be 32 bytes, got {}",
            bytes.len()
        ))
    })?;
    Ok(ContentHash::new(array))
}

fn parse_invocation_kind(raw: &str) -> KataResult<InvocationKind> {
    match raw {
        "workflow" => Ok(InvocationKind::Workflow),
        "direct_agent" => Ok(InvocationKind::DirectAgent),
        other => Err(KataError::Storage(format!(
            "operational.db invalid invocation kind {other:?}"
        ))),
    }
}
