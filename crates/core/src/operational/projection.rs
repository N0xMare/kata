//! Projection reads + the rebuild-from-transition-chain integrity check.
//!
//! # Invariant
//!
//! The latest-state projections (`execution_projection`, `attempt_projection`)
//! are a PURE FOLD of the immutable transition chain: for every scope key, the
//! projected `(state, source_seq)` equals the last FOLDING transition that touched
//! that key. A stage-scope transition never folds (the `transitions` CHECK), so there is
//! no stage projection to agree with. [`OperationalDb::verify_projection_integrity`]
//! rebuilds from the chain and compares exactly; a mismatch refuses advancement
//! and is repaired only through [`OperationalDb::rebuild_projection`].
//!
//! # Enforcement
//!
//! Projection reads run on a SEPARATE read-only connection
//! ([`OperationalReader`]) so a long read never blocks the single writer.

use std::collections::BTreeMap;
use std::path::Path;

use kata_types::error::{KataError, KataResult};
use rusqlite::{Connection, OpenFlags, OptionalExtension, params};
use ulid::Ulid;

use super::OperationalDb;

/// The latest execution-level projected state.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExecutionProjectionRow {
    /// The projected state string.
    pub state: String,
    /// The transition sequence this projection was folded from.
    pub source_seq: i64,
}

/// The latest projected state for one attempt.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AttemptProjectionRow {
    /// The stage identity.
    pub stage_id: String,
    /// The attempt ordinal.
    pub attempt_ordinal: i64,
    /// The projected state string.
    pub state: String,
    /// The source transition sequence.
    pub source_seq: i64,
}

/// WHICH of the three representations disagrees — and therefore whether the
/// sanctioned projection rebuild can actually repair it.
///
/// # Failure mode
///
/// A boot refusal that named "an explicit projection rebuild" as the ONE sanctioned
/// repair for every mismatch would be provably false for the lifecycle-vs-chain
/// class: [`OperationalDb::rebuild_projection`] rebuilds the PROJECTION
/// from the chain and never touches `execution_lifecycle`, so the mismatch
/// survives the repair verbatim (the repo's own
/// `a_lifecycle_row_that_drifts_from_its_chain_is_a_three_way_mismatch` asserts
/// exactly that). Every such mismatch would be a permanent, unrecoverable boot
/// refusal pointing at an action that could not work. Classifying is what lets the
/// diagnostic name only what is true for the class in hand.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NucleusMismatch {
    /// The stored latest-state projection disagrees with a rebuild from the
    /// transition chain. The chain is the authority and the projection is a pure
    /// fold of it, so this class IS repairable — by rebuilding the projection.
    Projection,
    /// `execution_lifecycle.state` disagrees with the state its own chain folds
    /// to. NOT repairable by a projection rebuild: the repair never writes the
    /// lifecycle row (nor the chain), by design — rebuilding either FROM the
    /// projection would let a derived view overwrite its own authority.
    Lifecycle,
    /// The global fold cursor disagrees with the transition chain's head
    /// (the global watermark invariant). NOT repairable by a per-execution projection rebuild: the
    /// watermark is global and the rebuild does not write it.
    Watermark,
}

impl NucleusMismatch {
    /// Whether [`OperationalDb::rebuild_projection`] can actually repair this
    /// class.
    #[must_use]
    pub fn is_repairable_by_projection_rebuild(self) -> bool {
        matches!(self, NucleusMismatch::Projection)
    }

    /// A stable label for logs and operator output.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            NucleusMismatch::Projection => "projection-vs-chain",
            NucleusMismatch::Lifecycle => "lifecycle-vs-chain",
            NucleusMismatch::Watermark => "watermark-vs-chain",
        }
    }

    /// The action the operator can ACTUALLY take for this class. Never names an
    /// action that cannot work on it.
    #[must_use]
    pub fn recourse(self) -> &'static str {
        match self {
            NucleusMismatch::Projection => {
                "REPAIRABLE: the transition chain is the authority and the projection is a pure \
                 fold of it, so an explicit projection rebuild reconciles this. Run `kata \
                 repair-nucleus --apply --data-dir <dir>` with the main stopped."
            }
            NucleusMismatch::Lifecycle => {
                "UNREPAIRABLE IN PLACE: a projection rebuild cannot fix this. It rebuilds the \
                 projection FROM the chain and never writes execution_lifecycle or the chain — \
                 rebuilding either from a derived view would let the view overwrite its own \
                 authority. Preserve this directory offline for authority investigation, or \
                 restore a verified current-format backup into a separate offline target."
            }
            NucleusMismatch::Watermark => {
                "UNREPAIRABLE IN PLACE: the fold cursor is global and no per-execution projection \
                 rebuild writes it. Preserve this directory offline for authority investigation, \
                 or restore a verified current-format backup into a separate offline target."
            }
        }
    }
}

/// One classified three-way mismatch: which execution, which class, and the
/// exact message the refusal carries.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClassifiedNucleusMismatch {
    /// The execution whose representations disagree.
    pub execution_id: Ulid,
    /// Which representation disagrees, and therefore what can repair it.
    pub class: NucleusMismatch,
    /// The typed refusal text.
    pub detail: String,
}

/// A separate read-only connection for projection reads.
///
/// File-backed only. In-memory databases read through the writer via the
/// [`OperationalDb`] read methods.
pub struct OperationalReader {
    conn: Connection,
}

impl std::fmt::Debug for OperationalReader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OperationalReader").finish_non_exhaustive()
    }
}

impl OperationalReader {
    pub(crate) fn open(path: &Path) -> KataResult<Self> {
        let conn = Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )
        .map_err(|error| {
            KataError::Storage(format!(
                "operational.db open_reader({}) failed: {error}",
                path.display()
            ))
        })?;
        conn.pragma_update(None, "foreign_keys", "ON")
            .map_err(|error| {
                KataError::Storage(format!(
                    "operational.db reader pragma foreign_keys=ON: {error}"
                ))
            })?;
        // A projection read that collides with a WAL checkpoint must wait-and-retry
        // instead of hard-erroring with SQLITE_BUSY (the SQLite default of 0).
        conn.pragma_update(
            None,
            "busy_timeout",
            super::schema::OPERATIONAL_BUSY_TIMEOUT_MS,
        )
        .map_err(|error| {
            KataError::Storage(format!(
                "operational.db reader pragma busy_timeout: {error}"
            ))
        })?;
        Ok(Self { conn })
    }

    /// The latest execution-level projection.
    pub fn execution_projection(
        &self,
        execution_id: Ulid,
    ) -> KataResult<Option<ExecutionProjectionRow>> {
        read_execution_projection(&self.conn, execution_id)
    }

    /// Every attempt projection for an execution, ordered by (stage, ordinal).
    #[cfg(any(test, feature = "test-support"))]
    pub fn attempt_projections(&self, execution_id: Ulid) -> KataResult<Vec<AttemptProjectionRow>> {
        read_attempt_projections(&self.conn, execution_id)
    }

    /// One attempt's projection, addressed by ATTEMPT ID.
    ///
    /// See [`OperationalDb::attempt_projection_for`] for why the join exists.
    #[cfg(any(test, feature = "test-support"))]
    pub fn attempt_projection_for(
        &self,
        attempt_id: Ulid,
    ) -> KataResult<Option<AttemptProjectionRow>> {
        read_attempt_projection_for(&self.conn, attempt_id)
    }

    /// The reader connection's live `PRAGMA busy_timeout` in milliseconds. Test
    /// accessor backing the wait-and-retry posture proof.
    #[cfg(any(test, feature = "test-support"))]
    pub fn debug_busy_timeout(&self) -> KataResult<i64> {
        self.conn
            .pragma_query_value(None, "busy_timeout", |row| row.get(0))
            .map_err(|error| {
                KataError::Storage(format!("operational.db reader read busy_timeout: {error}"))
            })
    }
}

impl OperationalDb {
    /// The latest execution-level projection (in-memory read path).
    pub fn execution_projection(
        &self,
        execution_id: Ulid,
    ) -> KataResult<Option<ExecutionProjectionRow>> {
        self.with_read(|conn| read_execution_projection(conn, execution_id))
    }

    /// Every attempt projection for an execution (in-memory read path).
    #[cfg(any(test, feature = "test-support"))]
    pub fn attempt_projections(&self, execution_id: Ulid) -> KataResult<Vec<AttemptProjectionRow>> {
        self.with_read(|conn| read_attempt_projections(conn, execution_id))
    }

    /// One attempt's latest-state projection, addressed by ATTEMPT ID.
    ///
    /// # Invariant
    ///
    /// The projection is keyed `(execution_id, stage_id, attempt_ordinal)` and
    /// [`AttemptProjectionRow`] deliberately carries no attempt id — the row is a
    /// per-GENERATION fact and the id names an assignment across generations. The
    /// authoritative link is `attempts(attempt_id) -> (execution_id, stage_id,
    /// attempt_ordinal)`, so this resolves the CURRENT generation's coordinates
    /// from the attempt row and reads its projection in one statement.
    ///
    /// `None` means either "no such attempt" or "that attempt's current generation
    /// has folded no projection yet" — the two are indistinguishable here on
    /// purpose, because both mean the same thing to a reader deciding whether a
    /// state exists: nothing justifies one.
    ///
    /// # Failure mode
    ///
    /// Without it, every caller holding an attempt id would have to go
    /// [`OperationalDb::attempt`] -> coordinates -> scan
    /// [`Self::attempt_projections`], four lines at each site.
    #[cfg(any(test, feature = "test-support"))]
    pub fn attempt_projection_for(
        &self,
        attempt_id: Ulid,
    ) -> KataResult<Option<AttemptProjectionRow>> {
        self.with_read(|conn| read_attempt_projection_for(conn, attempt_id))
    }

    /// THREE-WAY agreement: `execution_lifecycle.state` ==
    /// `execution_projection.state` == the rebuild from the transition chain, plus
    /// the global watermark.
    ///
    /// # Failure mode
    ///
    /// A two-way form (projection vs chain) would leave `execution_lifecycle.state`
    /// as a representation outside the check — a co-authority: no transition may
    /// consult a second watermark or treat two disagreeing representations as
    /// co-authority. A lifecycle row that drifted from its own chain would pass
    /// such a check silently, and every dispatch/promotion/parking gate reads the
    /// LIFECYCLE, not the projection.
    ///
    /// # Enforcement
    ///
    /// A mismatch is a typed [`KataError::Validation`] refusal.
    /// [`OperationalDb::rebuild_projection`] is the only sanctioned IN-PLACE
    /// repair, and it repairs the PROJECTION from the chain (never the chain from
    /// the projection, and never the lifecycle from either) — which is exactly
    /// why it cannot repair every class. Use
    /// [`OperationalDb::classify_nucleus_mismatch`] when the caller must tell the
    /// operator what is actually available.
    pub fn verify_projection_integrity(&self, execution_id: Ulid) -> KataResult<()> {
        match self.classify_nucleus_mismatch(execution_id)? {
            None => Ok(()),
            Some(mismatch) => Err(KataError::Validation(mismatch.detail)),
        }
    }

    /// The three-way check, reporting WHICH representation disagrees rather than
    /// only that one does.
    ///
    /// `Ok(None)` is agreement. `Ok(Some(_))` carries the class — which decides
    /// whether a projection rebuild can repair it — and the same message
    /// [`Self::verify_projection_integrity`] raises.
    pub fn classify_nucleus_mismatch(
        &self,
        execution_id: Ulid,
    ) -> KataResult<Option<ClassifiedNucleusMismatch>> {
        self.with_read(|conn| classify_nucleus_mismatch_at(conn, execution_id))
    }

    /// Assert `projection_watermark.applied_through_seq == max(transitions.seq)` AND
    /// `transition_sequence.value == max(transitions.seq)` (the global watermark invariant
    /// — the second clause is what distinguishes the operational plane from the ledger,
    /// which reserves BEFORE commit and therefore has holes by design).
    pub fn verify_global_watermark(&self) -> KataResult<bool> {
        self.with_read(|conn| {
            if watermark_disagreement(conn)?.is_some() {
                return Ok(false);
            }
            let reserved: i64 = conn
                .query_row(
                    "SELECT value FROM transition_sequence WHERE id = 0",
                    [],
                    |row| row.get(0),
                )
                .map_err(|error| {
                    KataError::Storage(format!("read transition_sequence: {error}"))
                })?;
            let max_seq: i64 = conn
                .query_row("SELECT COALESCE(MAX(seq), 0) FROM transitions", [], |row| {
                    row.get(0)
                })
                .map_err(|error| KataError::Storage(format!("read max transition seq: {error}")))?;
            Ok(reserved == max_seq)
        })
    }

    /// Repair an execution's projections by replacing them with a fresh rebuild
    /// from the transition chain. The only sanctioned path to reconcile a
    /// detected mismatch.
    pub fn rebuild_projection(&self, execution_id: Ulid) -> KataResult<()> {
        self.in_writer_txn(|tx| {
            let rebuilt = rebuild_from_chain(tx, execution_id)?;
            let id = execution_id.to_bytes();
            tx.execute(
                "DELETE FROM execution_projection WHERE execution_id = ?1",
                params![id.as_ref()],
            )
            .map_err(|error| KataError::Storage(format!("clear execution projection: {error}")))?;
            tx.execute(
                "DELETE FROM attempt_projection WHERE execution_id = ?1",
                params![id.as_ref()],
            )
            .map_err(|error| KataError::Storage(format!("clear attempt projection: {error}")))?;
            let now = super::now_ms();
            if let Some((state, source_seq)) = &rebuilt.execution {
                tx.execute(
                    "INSERT INTO execution_projection (execution_id, state, source_seq, updated_at_ms)
                     VALUES (?1, ?2, ?3, ?4)",
                    params![id.as_ref(), state, source_seq, now],
                )
                .map_err(|error| KataError::Storage(format!("rebuild execution projection: {error}")))?;
            }
            for ((stage_id, ordinal), (state, source_seq)) in &rebuilt.attempts {
                tx.execute(
                    "INSERT INTO attempt_projection
                         (execution_id, stage_id, attempt_ordinal, state, source_seq, updated_at_ms)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                    params![id.as_ref(), stage_id, ordinal, state, source_seq, now],
                )
                .map_err(|error| KataError::Storage(format!("rebuild attempt projection: {error}")))?;
            }
            Ok(())
        })
    }

    /// Corrupt a stored execution projection state. Test seam for the
    /// integrity-mismatch refusal proof; never a production path.
    #[cfg(any(test, feature = "test-support"))]
    pub fn debug_corrupt_execution_projection(
        &self,
        execution_id: Ulid,
        state: &str,
    ) -> KataResult<()> {
        self.with_read(|conn| {
            conn.execute(
                "UPDATE execution_projection SET state = ?1 WHERE execution_id = ?2",
                params![state, execution_id.to_bytes().as_ref()],
            )
            .map_err(|error| KataError::Storage(format!("corrupt projection: {error}")))?;
            Ok(())
        })
    }

    /// Forge an execution's LIFECYCLE row to a terminal state, leaving the chain
    /// and the projection untouched.
    ///
    /// The corruption class the boot check exists to catch, and the one a
    /// candidate set drawn from `execution_lifecycle.state` structurally cannot
    /// see: the forged row deletes itself from the recoverable scan, so the
    /// execution is never examined and boot reports ready while live work is
    /// silently abandoned. Test seam only.
    #[cfg(any(test, feature = "test-support"))]
    pub fn debug_forge_lifecycle_terminal(
        &self,
        execution_id: Ulid,
        state: &str,
    ) -> KataResult<()> {
        self.with_read(|conn| {
            conn.execute(
                "UPDATE execution_lifecycle
                    SET state = ?1, terminal_outcome = ?1,
                        terminal_reason_json = ?3, terminal_started_at_ms = ?4,
                        finished_at_ms = ?4
                  WHERE execution_id = ?2",
                params![
                    state,
                    execution_id.to_bytes().as_ref(),
                    br#"{"code":"completed","message":"forged"}"#.as_slice(),
                    super::now_ms(),
                ],
            )
            .map_err(|error| KataError::Storage(format!("forge lifecycle terminal: {error}")))?;
            Ok(())
        })
    }

    /// Corrupt one stored ATTEMPT projection's state, leaving the chain and every
    /// other representation untouched.
    ///
    /// It forges the exact pre-image of a projection that disagrees with its own chain, which
    /// is the only way to reach [`NucleusMismatch::Projection`] on the attempt
    /// plane. [`Self::debug_corrupt_execution_projection`] touches
    /// `execution_projection` ONLY, so without this seam the whole
    /// projection-vs-chain adjudication group would be unwritable at attempt scope.
    ///
    /// Returns the number of rows changed, so a test cannot silently corrupt
    /// nothing and then assert a mismatch that never had a pre-image.
    ///
    /// # Failure
    ///
    /// The `attempt_projection.state` CHECK still applies: a state outside the
    /// stamped vocabulary is REFUSED, not stored. That is deliberate — this seam
    /// forges a disagreement, never an unrepresentable value, and the refusal is
    /// itself what proves the CHECK is total (see the effect-vocabulary
    /// disjointness regression).
    #[cfg(any(test, feature = "test-support"))]
    pub fn debug_corrupt_attempt_projection(
        &self,
        execution_id: Ulid,
        stage_id: &str,
        attempt_ordinal: i64,
        state: &str,
    ) -> KataResult<usize> {
        self.with_read(|conn| {
            conn.execute(
                "UPDATE attempt_projection SET state = ?1
                  WHERE execution_id = ?2 AND stage_id = ?3 AND attempt_ordinal = ?4",
                params![
                    state,
                    execution_id.to_bytes().as_ref(),
                    stage_id,
                    attempt_ordinal
                ],
            )
            .map_err(|error| KataError::Storage(format!("corrupt attempt projection: {error}")))
        })
    }

    /// Rewind one stored ATTEMPT projection's `source_seq`, forging the
    /// projection-LAGS-chain pre-image.
    ///
    /// # Invariant
    ///
    /// `source_seq REFERENCES transitions(seq)` constrains this to a REAL,
    /// EXISTING sequence, and that asymmetry is itself the property: "the
    /// projection lags the chain" is forgeable, "the projection LEADS the chain" is
    /// structurally unforgeable. A test asserting the second must assert the
    /// unreachability rather than simulate it.
    ///
    /// Returns the number of rows changed.
    #[cfg(any(test, feature = "test-support"))]
    pub fn debug_set_attempt_projection_source_seq(
        &self,
        execution_id: Ulid,
        stage_id: &str,
        attempt_ordinal: i64,
        source_seq: i64,
    ) -> KataResult<usize> {
        self.with_read(|conn| {
            conn.execute(
                "UPDATE attempt_projection SET source_seq = ?1
                  WHERE execution_id = ?2 AND stage_id = ?3 AND attempt_ordinal = ?4",
                params![
                    source_seq,
                    execution_id.to_bytes().as_ref(),
                    stage_id,
                    attempt_ordinal
                ],
            )
            .map_err(|error| {
                KataError::Storage(format!("rewind attempt projection source seq: {error}"))
            })
        })
    }

    /// Rewind the GLOBAL projection watermark behind the chain head, leaving
    /// every per-execution representation in agreement. Only
    /// [`OperationalDb::verify_global_watermark`] can see this, which is what
    /// makes it the steady-state proof. Test seam only.
    #[cfg(any(test, feature = "test-support"))]
    pub fn debug_rewind_projection_watermark(&self, to_seq: i64) -> KataResult<()> {
        self.with_read(|conn| {
            conn.execute(
                "UPDATE projection_watermark SET applied_through_seq = ?1 WHERE id = 0",
                params![to_seq],
            )
            .map_err(|error| KataError::Storage(format!("rewind projection watermark: {error}")))?;
            Ok(())
        })
    }
}

/// The reconstructed projection for one execution, keyed for exact comparison.
#[derive(Debug, PartialEq, Eq)]
struct RebuiltProjection {
    execution: Option<(String, i64)>,
    attempts: BTreeMap<(String, i64), (String, i64)>,
}

/// Replay an execution's transitions in sequence order and fold the projection.
pub(super) fn classify_nucleus_mismatch_at(
    conn: &Connection,
    execution_id: Ulid,
) -> KataResult<Option<ClassifiedNucleusMismatch>> {
    let rebuilt = rebuild_from_chain(conn, execution_id)?;
    let stored = load_stored_projection(conn, execution_id)?;
    if rebuilt != stored {
        return Ok(Some(ClassifiedNucleusMismatch {
            execution_id,
            class: NucleusMismatch::Projection,
            detail: format!(
                "operational.db projection integrity check failed for execution {execution_id}: the stored projection disagrees with a rebuild from the transition chain (refusing advancement)"
            ),
        }));
    }
    if let Some(detail) = lifecycle_disagreement(conn, execution_id, rebuilt.execution.as_ref())? {
        return Ok(Some(ClassifiedNucleusMismatch {
            execution_id,
            class: NucleusMismatch::Lifecycle,
            detail,
        }));
    }
    if let Some(detail) = watermark_disagreement(conn)? {
        return Ok(Some(ClassifiedNucleusMismatch {
            execution_id,
            class: NucleusMismatch::Watermark,
            detail,
        }));
    }
    Ok(None)
}

fn rebuild_from_chain(conn: &Connection, execution_id: Ulid) -> KataResult<RebuiltProjection> {
    let mut stmt = conn
        .prepare(
            // `folds_projection = 0` transitions (effect-plane bookkeeping) were
            // never folded, so a rebuild that replayed them would produce a
            // projection the writer never wrote — and the mismatch would blame the
            // projection for the rebuild's error.
            "SELECT seq, scope, stage_id, attempt_ordinal, resulting_state
               FROM transitions
              WHERE execution_id = ?1 AND folds_projection = 1
              ORDER BY seq",
        )
        .map_err(|error| KataError::Storage(format!("prepare transition replay: {error}")))?;
    let rows = stmt
        .query_map(params![execution_id.to_bytes().as_ref()], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, Option<String>>(2)?,
                row.get::<_, Option<i64>>(3)?,
                row.get::<_, String>(4)?,
            ))
        })
        .map_err(|error| KataError::Storage(format!("replay transitions: {error}")))?;

    let mut rebuilt = RebuiltProjection {
        execution: None,
        attempts: BTreeMap::new(),
    };
    for row in rows {
        let (seq, scope, stage_id, attempt_ordinal, state) =
            row.map_err(|error| KataError::Storage(format!("replay transition row: {error}")))?;
        match scope.as_str() {
            "execution" => rebuilt.execution = Some((state, seq)),
            // Unreachable on a current file: `transitions` CHECKs that a stage-scope row
            // never folds. Refused rather than skipped, because a folding stage row
            // would be a projection this plane has no table for.
            "stage" => {
                return Err(KataError::Storage(format!(
                    "transition {seq} is a FOLDING stage-scope transition; a stage \
                     transition is record-only and no stage projection exists"
                )));
            }
            "attempt" => {
                let stage_key = stage_id.ok_or_else(|| {
                    KataError::Storage("attempt transition missing stage_id".to_string())
                })?;
                let ordinal = attempt_ordinal.ok_or_else(|| {
                    KataError::Storage("attempt transition missing ordinal".to_string())
                })?;
                rebuilt.attempts.insert((stage_key, ordinal), (state, seq));
            }
            other => {
                return Err(KataError::Storage(format!(
                    "unknown transition scope {other}"
                )));
            }
        }
    }
    Ok(rebuilt)
}

/// Load an execution's STORED projection into the same comparable shape.
fn load_stored_projection(conn: &Connection, execution_id: Ulid) -> KataResult<RebuiltProjection> {
    let execution =
        read_execution_projection(conn, execution_id)?.map(|row| (row.state, row.source_seq));
    let mut attempts = BTreeMap::new();
    for row in read_attempt_projections(conn, execution_id)? {
        attempts.insert(
            (row.stage_id, row.attempt_ordinal),
            (row.state, row.source_seq),
        );
    }
    Ok(RebuiltProjection {
        execution,
        attempts,
    })
}

/// The THIRD way: the durable `execution_lifecycle.state` must equal the state the
/// chain folds to. `None` on both sides agrees (an execution with no chain and no
/// lifecycle is simply unknown); either side alone is a mismatch.
/// `Ok(Some(detail))` when the durable lifecycle state disagrees with the state
/// the chain folds to. A failure to read the lifecycle row is `Err(Storage)`,
/// never a disagreement (see [`watermark_disagreement`]).
fn lifecycle_disagreement(
    conn: &Connection,
    execution_id: Ulid,
    folded: Option<&(String, i64)>,
) -> KataResult<Option<String>> {
    let lifecycle: Option<String> = conn
        .query_row(
            "SELECT state FROM execution_lifecycle WHERE execution_id = ?1",
            params![execution_id.to_bytes().as_ref()],
            |row| row.get(0),
        )
        .optional()
        .map_err(|error| KataError::Storage(format!("read lifecycle state: {error}")))?;
    let folded = folded.map(|(state, _)| state.as_str());
    if lifecycle.as_deref() == folded {
        return Ok(None);
    }
    Ok(Some(format!(
        "operational.db three-way integrity check failed for execution {execution_id}: the \
         durable lifecycle state {lifecycle:?} disagrees with the state its transition chain \
         folds to {folded:?} (refusing advancement)"
    )))
}

/// Assert the projection watermark equals the highest transition sequence.
pub(super) fn verify_watermark(conn: &Connection) -> KataResult<()> {
    match watermark_disagreement(conn)? {
        None => Ok(()),
        Some(detail) => Err(KataError::Validation(detail)),
    }
}

/// `Ok(Some(detail))` when the projection watermark disagrees with the highest
/// transition sequence. A failure to READ either side is `Err(Storage)`, never a
/// disagreement: a read fault is not a verdict on the fold cursor, and the
/// Watermark class's recourse declares the directory unrepairable in place.
fn watermark_disagreement(conn: &Connection) -> KataResult<Option<String>> {
    let watermark: i64 = conn
        .query_row(
            "SELECT applied_through_seq FROM projection_watermark WHERE id = 0",
            [],
            |row| row.get(0),
        )
        .map_err(|error| KataError::Storage(format!("read watermark: {error}")))?;
    let max_seq: i64 = conn
        .query_row("SELECT COALESCE(MAX(seq), 0) FROM transitions", [], |row| {
            row.get(0)
        })
        .map_err(|error| KataError::Storage(format!("read max transition seq: {error}")))?;
    Ok((watermark != max_seq).then(|| {
        format!(
            "operational.db projection watermark {watermark} disagrees with the highest \
             transition sequence {max_seq}"
        )
    }))
}

fn read_execution_projection(
    conn: &Connection,
    execution_id: Ulid,
) -> KataResult<Option<ExecutionProjectionRow>> {
    conn.query_row(
        "SELECT state, source_seq FROM execution_projection WHERE execution_id = ?1",
        params![execution_id.to_bytes().as_ref()],
        |row| {
            Ok(ExecutionProjectionRow {
                state: row.get(0)?,
                source_seq: row.get(1)?,
            })
        },
    )
    .optional()
    .map_err(|error| KataError::Storage(format!("read execution projection: {error}")))
}

/// Resolve an attempt's CURRENT coordinates from its `attempts` row and read the
/// projection at them, in one statement.
#[cfg(any(test, feature = "test-support"))]
fn read_attempt_projection_for(
    conn: &Connection,
    attempt_id: Ulid,
) -> KataResult<Option<AttemptProjectionRow>> {
    conn.query_row(
        "SELECT p.stage_id, p.attempt_ordinal, p.state, p.source_seq
           FROM attempt_projection p
           JOIN attempts a
             ON a.execution_id = p.execution_id
            AND a.stage_id = p.stage_id
            AND a.attempt_ordinal = p.attempt_ordinal
          WHERE a.attempt_id = ?1",
        params![attempt_id.to_bytes().as_ref()],
        |row| {
            Ok(AttemptProjectionRow {
                stage_id: row.get(0)?,
                attempt_ordinal: row.get(1)?,
                state: row.get(2)?,
                source_seq: row.get(3)?,
            })
        },
    )
    .optional()
    .map_err(|error| KataError::Storage(format!("read attempt projection by id: {error}")))
}

fn read_attempt_projections(
    conn: &Connection,
    execution_id: Ulid,
) -> KataResult<Vec<AttemptProjectionRow>> {
    let mut stmt = conn
        .prepare(
            "SELECT stage_id, attempt_ordinal, state, source_seq FROM attempt_projection
              WHERE execution_id = ?1 ORDER BY stage_id, attempt_ordinal",
        )
        .map_err(|error| KataError::Storage(format!("prepare attempt projection read: {error}")))?;
    let rows = stmt
        .query_map(params![execution_id.to_bytes().as_ref()], |row| {
            Ok(AttemptProjectionRow {
                stage_id: row.get(0)?,
                attempt_ordinal: row.get(1)?,
                state: row.get(2)?,
                source_seq: row.get(3)?,
            })
        })
        .map_err(|error| KataError::Storage(format!("read attempt projections: {error}")))?;
    rows.collect::<Result<Vec<_>, _>>()
        .map_err(|error| KataError::Storage(format!("collect attempt projections: {error}")))
}
