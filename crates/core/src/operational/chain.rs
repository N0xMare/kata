//! The OPERATIONAL CHAIN READER: paged, per-execution, resumable reads of
//! `transitions`, the attempt authority's plane.
//!
//! # Invariant
//!
//! THE TWO PLANES HAVE OPPOSITE HOLE REGIMES AND THIS READER IMPLEMENTS THE
//! OPERATIONAL ONE. A caller that ports the delivery relay's assumptions here is
//! wrong even though the code compiles, because both planes page `i64`/`u64`
//! sequences with an ascending `WHERE seq >= ?`:
//!
//! | | delivery plane (`ledger_events.db`) | this plane (`operational.db`) |
//! |---|---|---|
//! | Sequence reserved | BEFORE the commit | INSIDE the caller's transaction |
//! | A rolled-back write | burns a PERMANENT hole, by design | reverts the counter: NO hole |
//! | `max(seq)` vs the counter | may lag it forever | equal on a coherent database |
//! | An undecodable row | is SKIPPED by the SSE relay | is a typed REFUSAL (see below) |
//! | Tail test | raw rows `< limit` (skips make the decoded count unreliable) | per-execution: `frames.len() < limit`; global: next sequence exceeds the counter-checked head |
//!
//! The SSE relay therefore advances its cursor over the RAW rows it scanned, not
//! the frames it decoded: it must step over both holes and skipped frames, so the
//! row it stopped at is not derivable from the frames it forwarded. Neither exists
//! here. This reader's cursor is derivable
//! from its own frames, which is only sound because it never skips.
//!
//! # Failure mode
//!
//! Importing the ledger's SKIP rule onto the authority plane is the specific
//! defect this module's shape exists to prevent. On a derived delivery plane a
//! skipped frame costs one SSE message; on the authority plane it is a lifecycle
//! transition silently, permanently, and undetectably dropped from the fold that
//! decides whether a stage re-runs. So every row this reader
//! cannot interpret becomes an [`UnreconstructableExecution`], never an omission,
//! and the diagnostic names the execution, the sequence, and the class.
//!
//! # Enforcement
//!
//! Two entry points preserve two different cursor scopes. The per-execution reader
//! uses `WHERE execution_id = ?`, served by `idx_transitions_execution`
//! (`(execution_id, seq)`). [`OperationalDb::read_transition_page`] scans the
//! GLOBAL chain for a singleton projection cursor; it cross-checks
//! `transition_sequence.value` against stored `MAX(seq)` and requires every source
//! in its page to be adjacent.
//!
//! Both forms are RESUMABLE AND TOTAL. Their `next_from_seq` is derived from the
//! last frame actually returned, so a caller that stops anywhere and resumes from
//! it observes every frame in that cursor scope exactly once, in `seq` order, with
//! nothing skipped or repeated across the page boundary.

use kata_types::error::{KataError, KataResult};
use rusqlite::Connection;
use ulid::Ulid;

use super::{AttemptRecordKind, OperationalDb, ulid_from_bytes};

/// The projection scope a chain frame names, decoded from the `scope` column.
///
/// A closed enum rather than the raw string, so a fold cannot branch on a scope
/// the schema does not define: the decode is the only place an unknown value can
/// enter, and there it is a refusal.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChainScope {
    /// An execution-level transition (the lifecycle chain).
    Execution,
    /// A stage-level transition.
    Stage,
    /// An attempt-level transition.
    Attempt,
}

impl ChainScope {
    /// The `scope` column value this variant decodes from.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            ChainScope::Execution => "execution",
            ChainScope::Stage => "stage",
            ChainScope::Attempt => "attempt",
        }
    }
}

/// One immutable authority transition, as the runner fold and the delivery
/// mapping consume it.
///
/// # Invariant
///
/// `seq` is AUTHORITY ordering. It is the value `attempts.source_seq`,
/// `attempt_projection.source_seq`, and every other projection cursor foreign-key
/// into. It is NOT a delivery sequence: it must never be handed to a client as a
/// resume cursor, nor compared with one. The two spaces are both integers, which
/// is exactly why the distinction has to be carried by the type's documentation
/// rather than by the compiler.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TransitionFrame {
    /// The global authority sequence of this transition.
    pub seq: i64,
    /// The execution this transition belongs to, decoded from the stored row. For
    /// a per-execution read it equals the requested execution; for a global read it
    /// identifies whichever execution owns this position in the shared chain.
    pub execution_id: Ulid,
    /// The projection scope this transition names.
    pub scope: ChainScope,
    /// The canonical stage id, present for stage and attempt scope.
    pub stage_id: Option<String>,
    /// The attempt generation's chain-allocated ordinal, present for attempt scope.
    pub attempt_ordinal: Option<i64>,
    /// The attempt IDENTITY this transition is attributed to.
    ///
    /// `None` on an attempt-scope frame is NOT corruption: pruning an attempt sets
    /// the reference NULL and keeps the row, and the schema's CHECK is deliberately
    /// the implication (`attempt_id IS NULL OR scope = 'attempt'`) rather than an
    /// iff for that reason. A consumer that needs the identity must fail closed on `None`; it
    /// must not invent one.
    pub attempt_id: Option<Ulid>,
    /// The transition kind (`dispatched`, `event_accepted`, `outcome_amended`, …).
    pub kind: String,
    /// The state this transition established for its scope.
    pub resulting_state: String,
    /// Whether this transition ADVANCED its scope's latest-state projection. Read
    /// from the persisted column, not re-derived from `kind`, so a fold reproduces
    /// exactly the choice the writer made.
    pub folds_projection: bool,
    /// The opaque payload the writer recorded. This layer never decodes it — see
    /// the module doc on why the envelope mapping lives one layer up.
    pub payload_json: Vec<u8>,
    /// Wall-clock ms at which the transition was recorded.
    pub recorded_at_ms: i64,
}

/// One page of the authority chain for a single execution.
///
/// # Invariant
///
/// RESUMABLE AND TOTAL. Feed [`Self::next_from_seq`] back as the next read's
/// `from_seq` and the concatenation of the pages is exactly the execution's chain
/// from the original `from_seq`, in ascending `seq`, each frame once.
///
/// There is deliberately no raw-scan watermark beside the frames. The SSE relay
/// keeps one because it SKIPS delivery rows it cannot decode, so it cannot derive
/// where the scan stopped from the frames it forwarded. This reader refuses instead of skipping,
/// so the cursor IS derivable from the frames — and keeping a second, independently
/// advanced watermark would be a place for the two to disagree.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TransitionPage {
    /// The frames, ascending by `seq`, with no gaps relative to the chain.
    pub frames: Vec<TransitionFrame>,
    /// The `from_seq` to pass to the next read to continue exactly where this
    /// page stopped. Unchanged from the request when the page is empty, so
    /// re-reading an exhausted chain is idempotent rather than rewinding.
    pub next_from_seq: i64,
    /// Whether this page reached the execution's durable tail.
    ///
    /// Sound as `frames.len() < limit` ONLY because this reader never skips a row;
    /// the ledger's equivalent must test its RAW row count for that reason.
    pub reached_tail: bool,
}

/// One contiguous page of the GLOBAL authority chain.
///
/// Unlike [`TransitionPage`], this page is suitable for advancing a global
/// projection cursor: every authority sequence in its covered interval is present,
/// regardless of which execution owns it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GlobalTransitionPage {
    /// Frames in adjacent global authority order.
    pub frames: Vec<TransitionFrame>,
    /// The next global sequence to request.
    pub next_from_seq: i64,
    /// The authority head observed in the same read critical section as this page.
    pub observed_head: i64,
    /// Whether this page consumed through [`Self::observed_head`].
    pub reached_tail: bool,
}

/// Why an execution's durable chain cannot be reconstructed.
///
/// # Invariant
///
/// EVERY VARIANT NAMES A CLASS THE READER REFUSES TO GUESS AT. This is the
/// execution-granularity fail-closed posture recovery relies on: an execution whose
/// chain cannot be folded makes the binary REFUSE TO RESUME that execution with an
/// exact diagnostic, rather than inventing the state the fold could not derive.
/// Inventing it is the forgery the admission chokepoint exists to prevent, one
/// plane down.
///
/// The variants are distinguishable by `match`, not only by message text, so a
/// caller can route (refuse this execution, continue the others) instead of
/// string-matching a `Display`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ChainDefect {
    /// A ULID identity column was not 16 bytes.
    MalformedIdentity {
        /// The column that failed to decode.
        column: &'static str,
        /// The underlying decode message.
        detail: String,
    },
    /// The `scope` column held a value outside the schema's vocabulary. Reachable
    /// on a database whose CHECK was bypassed (a hand-edited file, an older
    /// writer, a restored artifact) — a CHECK constrains writes, never reads.
    UnknownScope {
        /// The value found on the row.
        found: String,
    },
    /// The scope and its coordinate columns disagree: a stage-scope row with no
    /// stage id, an attempt-scope row with no ordinal, an execution-scope row
    /// carrying either.
    ScopeCoordinateDisagreement {
        /// The decoded scope.
        scope: ChainScope,
        /// What was wrong with the coordinates.
        detail: String,
    },
    /// A row returned by a per-execution read carried a DIFFERENT execution id.
    /// Reachable only through index corruption or a caller reaching past the API,
    /// and fatal either way: the fold would attribute one execution's transition
    /// to another.
    ForeignExecutionRow {
        /// The execution the row actually names.
        found: Ulid,
    },
}

impl ChainDefect {
    /// A stable, greppable class tag for logs and for tests that assert WHICH
    /// refusal fired rather than merely that one did.
    #[must_use]
    pub fn class(&self) -> &'static str {
        match self {
            ChainDefect::MalformedIdentity { .. } => "malformed-identity",
            ChainDefect::UnknownScope { .. } => "unknown-scope",
            ChainDefect::ScopeCoordinateDisagreement { .. } => "scope-coordinate-disagreement",
            ChainDefect::ForeignExecutionRow { .. } => "foreign-execution-row",
        }
    }
}

impl std::fmt::Display for ChainDefect {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ChainDefect::MalformedIdentity { column, detail } => {
                write!(f, "identity column `{column}` is malformed ({detail})")
            }
            ChainDefect::UnknownScope { found } => write!(
                f,
                "scope `{found}` is outside the schema vocabulary \
                 (execution | stage | attempt)"
            ),
            ChainDefect::ScopeCoordinateDisagreement { scope, detail } => write!(
                f,
                "scope `{}` disagrees with its coordinate columns ({detail})",
                scope.as_str()
            ),
            ChainDefect::ForeignExecutionRow { found } => write!(
                f,
                "the row belongs to execution {found}, which a per-execution read \
                 must never return"
            ),
        }
    }
}

/// The recourse sentence EVERY execution-granularity refusal carries, in one
/// place so the layers cannot drift apart.
///
/// # Invariant
///
/// IT NAMES ONLY ACTIONS THAT EXIST, AND IT DENIES THE ONE THAT DOES NOT APPLY.
/// Clean-format boot creates no prototype recovery generation. The directory must
/// therefore remain offline for authority investigation, or be superseded by a
/// separately extracted, verified current-format backup. It also states outright
/// that a projection rebuild cannot repair the class — a rebuild re-reads the chain
/// that was just refused.
pub const CURRENT_FORMAT_REFUSAL_RECOURSE: &str = "Recourse: preserve this directory offline for authority investigation, or restore a \
     verified current-format backup into a separate offline target. A projection \
     rebuild CANNOT repair this class — it re-reads the same chain.";

/// The prefix every execution-granularity refusal opens with, so an operator can
/// grep one string across both planes' diagnostics.
pub const REFUSE_TO_RESUME_PREFIX: &str = "REFUSING TO RESUME execution";

/// A named, typed refusal to reconstruct ONE execution from its durable chain.
///
/// # Invariant
///
/// FAIL CLOSED AT EXECUTION GRANULARITY, WITH A REACHABLE RECOURSE. Preserve the
/// refused directory offline for investigation; a verified current-format backup
/// may be extracted into a separate offline target. No prototype recovery
/// generation is promised. A projection rebuild reads the same chain this reader
/// refused, so it cannot repair the missing authority.
///
/// # Failure
///
/// Converts to [`KataError::Storage`], whose severity is FATAL. That is
/// deliberate: an unreconstructable authority chain is not a caller mistake to be
/// reported as `Expected`, and it is not transient — retrying reads the identical
/// bytes. The node must not resume the execution.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UnreconstructableExecution {
    /// The execution that cannot be reconstructed.
    pub execution_id: Ulid,
    /// The authority sequence of the offending row, when one is known.
    pub seq: Option<i64>,
    /// What is wrong.
    pub defect: ChainDefect,
}

impl std::fmt::Display for UnreconstructableExecution {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{REFUSE_TO_RESUME_PREFIX} {}", self.execution_id)?;
        if let Some(seq) = self.seq {
            write!(f, " at transition seq {seq}")?;
        }
        write!(
            f,
            ": its operational chain is unreconstructable [{}] — {}. \
             This execution's durable state cannot be folded, and inventing the \
             missing state would forge authority the chain does not carry. \
             {CURRENT_FORMAT_REFUSAL_RECOURSE}",
            self.defect.class(),
            self.defect
        )
    }
}

impl std::error::Error for UnreconstructableExecution {}

impl From<UnreconstructableExecution> for KataError {
    fn from(refusal: UnreconstructableExecution) -> Self {
        KataError::Storage(refusal.to_string())
    }
}

/// Columns every chain read selects, in the order [`decode_frame`] expects.
const CHAIN_COLUMNS_SQL: &str = "seq, execution_id, scope, stage_id, attempt_ordinal, \
                                 attempt_id, kind, resulting_state, folds_projection, \
                                 payload_json, recorded_at_ms";

impl OperationalDb {
    /// Read one contiguous page of the GLOBAL authority transition chain.
    ///
    /// This is the source reader for a global projection cursor. It therefore
    /// refuses a missing sequence instead of stepping over it: a later cursor
    /// cannot distinguish a deleted row from a consumed one.
    pub fn read_transition_page(
        &self,
        from_seq: i64,
        limit: usize,
    ) -> KataResult<GlobalTransitionPage> {
        if limit == 0 {
            return Err(KataError::Validation(
                "global operational chain reader refuses a zero-limit page".to_string(),
            ));
        }
        if from_seq < 1 {
            return Err(KataError::Validation(format!(
                "global operational chain reader refuses from_seq {from_seq}; transition \
                 sequences start at 1"
            )));
        }
        self.with_read(|conn| read_global_page(conn, from_seq, limit))
    }

    /// Read one page of ONE execution's authority chain, starting at `from_seq`
    /// (inclusive).
    ///
    /// It differs from the delivery plane's reads in every way the module doc's
    /// table lists. Read it before moving a caller.
    ///
    /// # Invariant
    ///
    /// NO HOLES, NO SKIPS, SO THE CURSOR IS DERIVABLE. The operational plane
    /// reserves its sequence inside the writing transaction, so a rolled-back
    /// transition reverts the counter and leaves no gap — unlike the ledger, which
    /// reserves before commit and leaves permanent holes BY DESIGN. Nothing here
    /// tolerates, reclaims, or reasons about a hole, because on this plane a gap
    /// between consecutive `transitions.seq` values for one execution is just
    /// another execution's row, never a lost one.
    ///
    /// # Failure
    ///
    /// - `limit == 0` is a typed refusal. A zero-limit page would be empty and
    ///   would therefore report `reached_tail`, telling a caller the chain is
    ///   exhausted when it has read nothing — a silent, total loss of the tail.
    /// - `from_seq < 1` is a typed refusal: sequences start at 1 and 0 aliases
    ///   "no transition", so accepting it would let a caller's uninitialized
    ///   cursor read as a legitimate start.
    /// - A row this reader cannot interpret is an [`UnreconstructableExecution`],
    ///   never a skipped frame.
    pub fn read_transitions_for_execution(
        &self,
        execution_id: Ulid,
        from_seq: i64,
        limit: usize,
    ) -> KataResult<TransitionPage> {
        if limit == 0 {
            return Err(KataError::Validation(format!(
                "operational chain reader refuses a zero-limit page for execution \
                 {execution_id}: an empty page reports the durable tail, so a \
                 zero limit would tell the caller the chain is exhausted before \
                 reading any of it"
            )));
        }
        if from_seq < 1 {
            return Err(KataError::Validation(format!(
                "operational chain reader refuses from_seq {from_seq} for execution \
                 {execution_id}: transition sequences start at 1 and 0 aliases 'no \
                 transition'"
            )));
        }
        self.with_read(|conn| read_page(conn, execution_id, from_seq, limit))
    }

    /// Read one attempt's complete retained prefix across generations, bounded by
    /// a previously captured execution head. Uses the attempt identity index.
    #[cfg(any(test, feature = "test-support"))]
    pub fn read_attempt_transition_prefix(
        &self,
        execution_id: Ulid,
        attempt_id: Ulid,
        through_seq: i64,
    ) -> KataResult<Vec<TransitionFrame>> {
        self.with_read(|conn| {
            read_scoped_prefix(
                conn,
                execution_id,
                "idx_transitions_attempt",
                "attempt_id = ?2 AND scope = 'attempt'",
                rusqlite::types::Value::Blob(attempt_id.to_bytes().to_vec()),
                through_seq,
            )
        })
    }

    /// The HIGHEST authority sequence this execution's chain holds, or `0` when
    /// it holds none.
    ///
    /// # Why this exists, and why it reads the same plane as the fold
    ///
    /// `WorkflowRunner::run_replay`'s blocked-check compares its fold watermark
    /// `A` against a per-execution durable head `H` and may only declare a run
    /// stuck at `A == H`. `A` is whatever the fold advanced over, so the head it
    /// is compared against MUST come from the same plane the fold read.
    /// A `ledger_events` delivery sequence is a different space; a
    /// chain watermark below a larger delivery-plane head keeps `A < H` true
    /// forever and the run folds an empty tail on every pass — a live-lock. So the
    /// head moves with the fold, or neither moves.
    ///
    /// # Invariant
    ///
    /// THE SAME SEQUENCE SPACE AS [`TransitionFrame::seq`], and therefore as
    /// [`TransitionPage::next_from_seq`]. A fold that consumed this execution's
    /// durable tail has advanced its watermark to exactly this value, so `A == H`
    /// is REACHABLE rather than merely approached. It is NOT a delivery sequence
    /// and must never be compared with one.
    ///
    /// # Enforcement
    ///
    /// Per-execution, served by `idx_transitions_execution` (`(execution_id,
    /// seq)`), so this is an index-tail probe rather than a scan — the same cost
    /// discipline the paged reader states, for a call the drive loop makes on
    /// every pass.
    ///
    /// `0` means the execution has no transitions at all, which is the honest
    /// answer for a fresh run and is exactly what a watermark seeded at `0`
    /// already equals. It is never "unknown": the caller's fail-closed nucleus
    /// gate has already established that this plane can speak for the execution.
    pub fn execution_transition_head(&self, execution_id: Ulid) -> KataResult<i64> {
        self.with_read(|conn| {
            conn.query_row(
                "SELECT COALESCE(MAX(seq), 0) FROM transitions WHERE execution_id = ?1",
                rusqlite::params![execution_id.to_bytes().as_ref()],
                |row| row.get::<_, i64>(0),
            )
            .map_err(|error| {
                KataError::Storage(format!(
                    "read the authority chain head for execution {execution_id}: {error}"
                ))
            })
        })
    }

    /// Every `outcome_amended` frame this execution's chain holds, ascending by
    /// authority sequence.
    ///
    /// # Why this is a SEPARATE read and not a frame the paged reader hands over
    ///
    /// An amendment is deliberately invisible to both consumers of
    /// [`Self::read_transitions_for_execution`]. It is `RecordOnly`, so the
    /// delivery mapping refuses to build a wire envelope for it (a second
    /// broadcast would make subscribers redo work), and the runner's FOLD must not
    /// see it — the fold consumes the pre-amendment output.
    ///
    /// The amendment belongs to the ROW projection: it overwrites the attempt's
    /// recorded output in place. So it belongs to the
    /// row-shaped reader and to nothing else, and giving it its own door — rather
    /// than a new `MappedFrame` variant — is what keeps a future fold consumer from
    /// picking it up by accident: two readers of one ambiguous name.
    ///
    /// # Invariant
    ///
    /// SELECTED BY `kind`, ascending by `seq`, with no per-attempt collapse. The
    /// caller decides which amendment wins, because the rule it needs —
    /// "the latest amendment recorded AFTER the settlement being amended" —
    /// depends on the settlement's own sequence, which is a fold result this layer
    /// does not have.
    #[cfg(any(test, feature = "test-support"))]
    pub fn attempt_outcome_amendments(
        &self,
        execution_id: Ulid,
    ) -> KataResult<Vec<AttemptOutcomeAmendment>> {
        Ok(self
            .attempt_record_appends(
                AttemptRecordScope::Execution(execution_id),
                AttemptRecordKind::OutcomeAmended,
            )?
            .into_iter()
            .map(|append| AttemptOutcomeAmendment {
                attempt_id: append.attempt_id,
                seq: append.seq,
                outcome_json: append.payload_json,
            })
            .collect())
    }

    /// Every RECORD-ONLY append of one `kind` at one `scope`, ascending by authority
    /// sequence.
    ///
    /// # Why ONE reader, parameterised, and not one door per kind
    ///
    /// This body WAS `attempt_outcome_amendments`, spelled for a single kind. The
    /// invocation family needs the identical read for two more ([`AttemptRecordKind`]), and
    /// a second copy of it would be two implementations of one rule — a data-loss class,
    /// where the divergence IS the defect. There is one query, one fail-closed decode, and
    /// one ordering; the kind is an argument.
    ///
    /// # Invariant
    ///
    /// SELECTED BY `kind`, ASCENDING BY `seq`, WITH NO COLLAPSE. The caller decides
    /// which append wins, because the three kinds collapse under three DIFFERENT
    /// rules and every one of them is the ledger plane's own: an amendment applies
    /// only when its sequence exceeds the settlement it amends; an invocation record
    /// is LAST-WINS on `(kind, role, parent_id)`; a dynamic-expansion event is
    /// WHOLE-VALUE dedupe. Folding any of them here would either impose one rule on
    /// three facts or grow three collapses inside a reader that has no business
    /// knowing them.
    ///
    /// # Enforcement
    ///
    /// THE SCOPE IS THE INDEX CHOICE, and it is a parameter because the two callers
    /// genuinely differ. The POPULATION read serves a per-execution fold and rides
    /// `idx_transitions_execution`; the POINT read serves the per-transition
    /// pre-image and rides `idx_transitions_attempt`, so composing a pre-image does
    /// not re-scan the whole execution on every write.
    ///
    /// # Failure
    ///
    /// FAILS CLOSED on an UNATTRIBUTED append, matching [`decode_frame`]. An append
    /// naming no attempt cannot be applied to a row, and silently dropping it would
    /// report a stale value as current — for the amendment kind that is the
    /// PRE-amendment output, and for the invocation kind it is a dynamic-fanout
    /// parent whose root record has vanished. Unreachable through
    /// [`OperationalDb::record_attempt_append`](super::OperationalDb), which resolves
    /// the attempt before it writes; reachable on a hand-edited database, which is
    /// exactly the population a read-side check exists for.
    pub fn attempt_record_appends(
        &self,
        scope: AttemptRecordScope,
        kind: AttemptRecordKind,
    ) -> KataResult<Vec<AttemptRecordAppend>> {
        // The execution a refusal NAMES is read off the row, never echoed from the
        // request: the attempt-scoped read has no execution in hand, and the
        // execution-scoped one would be comparing the row against itself.
        let (predicate, key) = match scope {
            AttemptRecordScope::Execution(execution_id) => ("execution_id = ?1", execution_id),
            AttemptRecordScope::Attempt(attempt_id) => {
                ("attempt_id = ?1 AND scope = 'attempt'", attempt_id)
            }
        };
        self.with_read(|conn| {
            let sql = format!(
                "SELECT seq, execution_id, attempt_id, payload_json FROM transitions \
                  WHERE {predicate} AND kind = ?2 ORDER BY seq ASC"
            );
            let mut stmt = conn.prepare(&sql).map_err(|error| {
                KataError::Storage(format!("prepare record-append scan: {error}"))
            })?;
            let raw = stmt
                .query_map(
                    rusqlite::params![key.to_bytes().as_ref(), kind.as_str()],
                    |row| {
                        Ok((
                            row.get::<_, i64>(0)?,
                            row.get::<_, Vec<u8>>(1)?,
                            row.get::<_, Option<Vec<u8>>>(2)?,
                            row.get::<_, Vec<u8>>(3)?,
                        ))
                    },
                )
                .map_err(|error| KataError::Storage(format!("scan record appends: {error}")))?
                .collect::<Result<Vec<_>, _>>()
                .map_err(|error| KataError::Storage(format!("collect record appends: {error}")))?;
            let mut appends = Vec::with_capacity(raw.len());
            for (seq, execution_id, attempt_id, payload_json) in raw {
                let execution_id =
                    ulid_from_bytes(&execution_id).map_err(|error| UnreconstructableExecution {
                        execution_id: Ulid::nil(),
                        seq: Some(seq),
                        defect: ChainDefect::MalformedIdentity {
                            column: "execution_id",
                            detail: error.to_string(),
                        },
                    })?;
                let Some(Ok(attempt_id)) = attempt_id.as_deref().map(ulid_from_bytes) else {
                    return Err(UnreconstructableExecution {
                        execution_id,
                        seq: Some(seq),
                        defect: ChainDefect::MalformedIdentity {
                            column: "attempt_id",
                            detail: format!(
                                "a `{}` frame must name the attempt it records a fact about",
                                kind.as_str()
                            ),
                        },
                    }
                    .into());
                };
                let payload_json = if kind == AttemptRecordKind::OutcomeAmended {
                    super::resolve_authoritative_output_payload(
                        conn,
                        execution_id,
                        kind.as_str(),
                        &payload_json,
                        |address, size, maximum| self.read_output(address, size, maximum),
                    )?
                } else {
                    payload_json
                };
                appends.push(AttemptRecordAppend {
                    execution_id,
                    attempt_id,
                    seq,
                    payload_json,
                });
            }
            Ok(appends)
        })
    }

    /// The LAST stage-scope transition ONE undispatched stage recorded.
    ///
    /// # Why this exists, and why it is not an attempt-scope read
    ///
    /// The undispatched class has no `attempt_id` BY CONSTRUCTION — that is what
    /// makes it the class — so it cannot be read through `idx_transitions_attempt`.
    /// The stage-scope chain carries the assignment identity in its PAYLOAD instead,
    /// so the class needs its own probe.
    ///
    /// # Invariant
    ///
    /// LAST TRANSITION WINS, BY AUTHORITY SEQUENCE — the identical rule
    /// [`OperationalDb::undispatched_stage_states`](super::OperationalDb) folds
    /// under, run here as a `DESC LIMIT`-shaped scan rather than a second fold so
    /// the two cannot come to disagree about which frame states a stage's current
    /// state. There is no `folds_projection` filter, and that is not an omission:
    /// both undispatched-stage kinds are `RecordOnly` by design, so filtering on it
    /// would return nothing at all.
    ///
    /// # Enforcement
    ///
    /// Scoped to ONE execution and to the two undispatched-stage kinds, so it is
    /// served by `idx_transitions_execution` and bounded by that execution's
    /// stage-scope frames rather than by the whole table. The identity match is on
    /// the payload, which SQLite cannot index, so the rows are decoded newest-first
    /// and the scan stops at the first match — the shortest walk this shape admits.
    ///
    /// # Failure
    ///
    /// `None` means the chain holds no stage-scope frame for this assignment, which
    /// is an ANSWER: it is not a member of the class. A row this reader cannot
    /// interpret is an [`UnreconstructableExecution`], never a skipped frame — the
    /// same polarity every other chain reader takes, and for the same reason: a
    /// skipped frame makes a decoding hole indistinguishable from an absent stage.
    pub fn last_undispatched_stage_transition(
        &self,
        execution_id: Ulid,
        assignment_id: Ulid,
    ) -> KataResult<Option<TransitionFrame>> {
        let wanted = assignment_id.to_string();
        self.with_read(|conn| {
            let sql = format!(
                "SELECT {CHAIN_COLUMNS_SQL} FROM transitions \
                  WHERE execution_id = ?1 AND scope = 'stage' AND kind IN (?2, ?3) \
                  ORDER BY seq DESC"
            );
            let mut stmt = conn.prepare(&sql).map_err(|error| {
                KataError::Storage(format!(
                    "prepare the stage-scope pre-image probe for execution {execution_id}: \
                     {error}"
                ))
            })?;
            let rows = stmt
                .query_map(
                    rusqlite::params![
                        execution_id.to_bytes().as_ref(),
                        super::UNDISPATCHED_STAGE_ADMITTED_KIND,
                        super::UNDISPATCHED_STAGE_SETTLED_KIND,
                    ],
                    |row| {
                        Ok(RawChainRow {
                            seq: row.get(0)?,
                            execution_id: row.get(1)?,
                            scope: row.get(2)?,
                            stage_id: row.get(3)?,
                            attempt_ordinal: row.get(4)?,
                            attempt_id: row.get(5)?,
                            kind: row.get(6)?,
                            resulting_state: row.get(7)?,
                            folds_projection: row.get(8)?,
                            payload_json: row.get(9)?,
                            recorded_at_ms: row.get(10)?,
                        })
                    },
                )
                .map_err(|error| {
                    KataError::Storage(format!(
                        "scan the stage-scope chain of execution {execution_id}: {error}"
                    ))
                })?;
            for row in rows {
                let raw = row.map_err(|error| {
                    KataError::Storage(format!(
                        "read a stage-scope frame of execution {execution_id}: {error}"
                    ))
                })?;
                let frame = decode_frame(execution_id, raw)?;
                let payload: serde_json::Value = serde_json::from_slice(&frame.payload_json)
                    .map_err(|error| {
                        KataError::Storage(format!(
                            "operational.db stage-scope transition at seq {} of execution \
                             {execution_id} carries an undecodable payload: {error}",
                            frame.seq
                        ))
                    })?;
                if payload
                    .get("assignment_id")
                    .and_then(serde_json::Value::as_str)
                    == Some(wanted.as_str())
                {
                    return Ok(Some(frame));
                }
            }
            Ok(None)
        })
    }

    /// The FIRST transition that parked ONE assignment on the approval gate.
    ///
    /// # What this is for, and why FIRST rather than LAST
    ///
    /// It is the chain's home for the approval-park anchor
    /// (`AttemptDeliverySnapshot::awaiting_approval_at_ms`), and that anchor is
    /// **STICKY**: `finalize_attempt_delivery` reads the EARLIEST
    /// `awaiting_approval` frame, so it holds the FIRST park's instant and no later
    /// park moves it. Reading the LAST park frame instead would be the LATEST
    /// instant, and the consumer is not indifferent between them: the operator's
    /// gate list uses it as an age column AND as the FIFO sort key, so latest-park
    /// semantics would reset a re-parked gate's age and send it to the back of the
    /// queue.
    ///
    /// Sticky is therefore the answer, and it is spelled as the FIRST frame rather than derived
    /// from a re-park being currently unreachable — no production path parks one
    /// assignment id twice today, but the mutator carries no precondition that
    /// forbids it, and a latent hole in an anchor a self-heal deadline is computed
    /// from is not a hole worth leaving.
    ///
    /// # BOTH scopes, in one scan
    ///
    /// An approval gate lives on either chain class: a gated stage is an `attempts`
    /// row, and a review-loop escalation gate is admitted through
    /// `admit_undispatched_stage` and is recorded at STAGE
    /// scope with no attempt row at all. The attempt half matches on `attempt_id`;
    /// the stage half matches the assignment identity on the PAYLOAD, exactly as
    /// [`Self::last_undispatched_stage_transition`] does and for the same reason —
    /// SQLite cannot index it.
    ///
    /// # Enforcement
    ///
    /// Scoped to ONE execution and to the park state, so it is served by
    /// `idx_transitions_execution` and bounded by that execution's approval-park
    /// frames rather than by the whole table. Ascending, and the scan stops at the
    /// first match: the FIRST park is the first row that matches.
    ///
    /// # Failure
    ///
    /// `None` means the chain holds no approval-park frame for this assignment,
    /// which is an ANSWER — it has never been parked. A row this reader cannot
    /// interpret is an [`UnreconstructableExecution`], never a skipped frame, which
    /// is this module's rule everywhere: a skipped frame would make a decoding hole
    /// indistinguishable from an unparked assignment, and the consumer turns that
    /// absence into "this gate has no recorded park instant".
    pub fn first_approval_park_transition(
        &self,
        execution_id: Ulid,
        assignment_id: Ulid,
    ) -> KataResult<Option<TransitionFrame>> {
        let wanted = assignment_id.to_string();
        self.with_read(|conn| {
            let sql = format!(
                "SELECT {CHAIN_COLUMNS_SQL} FROM transitions \
                  WHERE execution_id = ?1 AND resulting_state = ?2 \
                  ORDER BY seq ASC"
            );
            let mut stmt = conn.prepare(&sql).map_err(|error| {
                KataError::Storage(format!(
                    "prepare the approval-park anchor probe for execution {execution_id}: {error}"
                ))
            })?;
            let rows = stmt
                .query_map(
                    rusqlite::params![
                        execution_id.to_bytes().as_ref(),
                        super::AWAITING_APPROVAL_STATE,
                    ],
                    |row| {
                        Ok(RawChainRow {
                            seq: row.get(0)?,
                            execution_id: row.get(1)?,
                            scope: row.get(2)?,
                            stage_id: row.get(3)?,
                            attempt_ordinal: row.get(4)?,
                            attempt_id: row.get(5)?,
                            kind: row.get(6)?,
                            resulting_state: row.get(7)?,
                            folds_projection: row.get(8)?,
                            payload_json: row.get(9)?,
                            recorded_at_ms: row.get(10)?,
                        })
                    },
                )
                .map_err(|error| {
                    KataError::Storage(format!(
                        "scan the approval-park frames of execution {execution_id}: {error}"
                    ))
                })?;
            for row in rows {
                let raw = row.map_err(|error| {
                    KataError::Storage(format!(
                        "read an approval-park frame of execution {execution_id}: {error}"
                    ))
                })?;
                let frame = decode_frame(execution_id, raw)?;
                let attributed = match frame.scope {
                    ChainScope::Attempt => frame.attempt_id == Some(assignment_id),
                    // The identity is on the payload for this class, because it has
                    // no `attempts` row to carry a column — that absence is what
                    // DEFINES the class.
                    ChainScope::Stage => {
                        let payload: serde_json::Value =
                            serde_json::from_slice(&frame.payload_json).map_err(|error| {
                                KataError::Storage(format!(
                                    "operational.db stage-scope transition at seq {} of \
                                     execution {execution_id} carries an undecodable payload: \
                                     {error}",
                                    frame.seq
                                ))
                            })?;
                        payload
                            .get("assignment_id")
                            .and_then(serde_json::Value::as_str)
                            == Some(wanted.as_str())
                    }
                    // An execution-scope frame names no assignment; `awaiting_approval`
                    // is not in its vocabulary, so this arm is unreachable on a
                    // well-formed chain and is stated rather than defaulted.
                    ChainScope::Execution => false,
                };
                if attributed {
                    return Ok(Some(frame));
                }
            }
            Ok(None)
        })
    }
}

/// ONE recorded amendment of a terminal attempt's outcome.
///
/// The chain's record of an in-place output amendment, read back for the
/// row-shaped reader. See `OperationalDb::attempt_outcome_amendments` (a
/// test-support reader) for why it does not arrive as a [`TransitionFrame`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AttemptOutcomeAmendment {
    /// The attempt whose recorded outcome this amends.
    pub attempt_id: Ulid,
    /// The authority sequence at which the amendment was recorded.
    ///
    /// The whole ordering rule: an amendment amends the settlement that PRECEDED
    /// it, so a consumer applies it only when this exceeds the sequence of the
    /// transition that established the state it is amending. That is what keeps a
    /// previous generation's amendment off a re-run generation's completion.
    pub seq: i64,
    /// The amended outcome bytes, exactly as the writer bounded them.
    pub outcome_json: Vec<u8>,
}

/// WHICH record-only appends one read of the chain selects.
///
/// A closed enum rather than two doors: the query, the decode and the fail-closed
/// attribution check are identical, and only the indexed predicate differs. Two
/// doors would be two implementations of one rule.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AttemptRecordScope {
    /// Every append of one EXECUTION, across all of its attempts — the POPULATION
    /// read, for a fold that is already per-execution.
    Execution(Ulid),
    /// Every append of ONE attempt — the POINT read, for the per-transition
    /// pre-image, which must not re-scan an execution on every write.
    Attempt(Ulid),
}

/// ONE record-only append the chain holds for an attempt.
///
/// The general shape [`AttemptOutcomeAmendment`] is one projection of. It carries
/// the payload OPAQUELY: this layer selects and attributes appends, and decoding
/// one is the consumer's job, for the same reason [`TransitionFrame::payload_json`]
/// is opaque — the envelope mapping lives one layer up, where the type the bytes
/// decode to is known.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AttemptRecordAppend {
    /// The execution this append belongs to, RE-DECODED from the row rather than
    /// echoed from the request — the attempt-scoped read has none to echo, and a
    /// consumer whose refusal must name an execution would otherwise have to invent
    /// one.
    pub execution_id: Ulid,
    /// The attempt this append records a fact about.
    pub attempt_id: Ulid,
    /// The authority sequence at which the append was recorded. TOTAL and monotone
    /// over an execution's appends, so a consumer whose collapse rule is
    /// "last wins" needs no tiebreak and no wall clock.
    pub seq: i64,
    /// The recorded bytes, exactly as the writer stored them.
    pub payload_json: Vec<u8>,
}

/// One page of the GLOBAL chain: `?1` the first sequence, `?2` the limit. Served by the
/// `seq` primary key.
fn global_page_sql() -> String {
    format!(
        "SELECT {CHAIN_COLUMNS_SQL} FROM transitions \
          WHERE seq >= ?1 ORDER BY seq ASC LIMIT ?2"
    )
}

/// One page of ONE execution's chain: `?1` the execution id, `?2` the first sequence,
/// `?3` the limit. Served by `idx_transitions_execution`.
fn execution_page_sql() -> String {
    format!(
        "SELECT {CHAIN_COLUMNS_SQL} FROM transitions \
          WHERE execution_id = ?1 AND seq >= ?2 \
          ORDER BY seq ASC LIMIT ?3"
    )
}

impl OperationalDb {
    /// SQLite's `EXPLAIN QUERY PLAN` details for the two chain page reads, as
    /// `(global, per-execution)`, each row's detail joined by `"; "`. It plans the very
    /// SQL [`Self::read_transition_page`] and [`Self::read_transitions_for_execution`]
    /// run, so a measurement asserts the shape of the query that runs rather than of a
    /// copy that can keep its index while the reader loses it.
    #[cfg(any(test, feature = "test-support"))]
    pub fn chain_page_query_plans(&self) -> KataResult<(String, String)> {
        self.with_read(|conn| {
            Ok((
                query_plan(conn, &global_page_sql())?,
                query_plan(conn, &execution_page_sql())?,
            ))
        })
    }
}

#[cfg(any(test, feature = "test-support"))]
fn query_plan(conn: &Connection, sql: &str) -> KataResult<String> {
    let storage = |error: rusqlite::Error| KataError::Storage(format!("plan `{sql}`: {error}"));
    let mut stmt = conn
        .prepare(&format!("EXPLAIN QUERY PLAN {sql}"))
        .map_err(storage)?;
    // Planned with its parameters unbound: the plan is the statement's, not a value's.
    let mut rows = stmt.raw_query();
    let mut details = Vec::new();
    while let Some(row) = rows.next().map_err(storage)? {
        details.push(row.get::<_, String>(3).map_err(storage)?);
    }
    Ok(details.join("; "))
}

/// The paged read itself, factored out so both the writer connection and a
/// read-only connection can serve it without duplicating the decode contract.
fn read_global_page(
    conn: &Connection,
    from_seq: i64,
    limit: usize,
) -> KataResult<GlobalTransitionPage> {
    let (observed_head, stored_head): (i64, i64) = conn
        .query_row(
            "SELECT
                 (SELECT value FROM transition_sequence WHERE id = 0),
                 COALESCE(MAX(seq), 0)
               FROM transitions",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .map_err(|error| KataError::Storage(format!("read global chain head: {error}")))?;
    if observed_head != stored_head {
        return Err(KataError::Storage(format!(
            "global operational chain head disagrees with its durable sequence counter: counter \
             is {observed_head}, stored MAX(seq) is {stored_head}"
        )));
    }
    let mut stmt = conn
        .prepare(&global_page_sql())
        .map_err(|error| KataError::Storage(format!("prepare global chain page: {error}")))?;
    let raw = stmt
        .query_map(
            rusqlite::params![from_seq, i64::try_from(limit).unwrap_or(i64::MAX)],
            |row| {
                Ok(RawChainRow {
                    seq: row.get(0)?,
                    execution_id: row.get(1)?,
                    scope: row.get(2)?,
                    stage_id: row.get(3)?,
                    attempt_ordinal: row.get(4)?,
                    attempt_id: row.get(5)?,
                    kind: row.get(6)?,
                    resulting_state: row.get(7)?,
                    folds_projection: row.get(8)?,
                    payload_json: row.get(9)?,
                    recorded_at_ms: row.get(10)?,
                })
            },
        )
        .map_err(|error| KataError::Storage(format!("scan global chain page: {error}")))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| KataError::Storage(format!("collect global chain page: {error}")))?;

    let mut expected = from_seq;
    let mut frames = Vec::with_capacity(raw.len());
    for row in raw {
        if row.seq != expected {
            return Err(KataError::Storage(format!(
                "global operational chain is not contiguous: expected source sequence \
                 {expected}, found {} while the observed head is {observed_head}",
                row.seq
            )));
        }
        expected = row.seq.checked_add(1).ok_or_else(|| {
            KataError::Storage(
                "global operational chain reached i64::MAX and cannot form a resumable cursor"
                    .to_string(),
            )
        })?;
        let execution_id = ulid_from_bytes(&row.execution_id).map_err(|error| {
            KataError::Storage(format!(
                "decode global chain execution identity at source sequence {}: {error}",
                row.seq
            ))
        })?;
        frames.push(decode_frame(execution_id, row)?);
    }
    if frames.is_empty() && from_seq <= observed_head {
        return Err(KataError::Storage(format!(
            "global operational chain is missing source sequence {from_seq} below observed head \
             {observed_head}"
        )));
    }
    let next_from_seq = frames.last().map_or(from_seq, |_| expected);
    let reached_tail = next_from_seq > observed_head;
    Ok(GlobalTransitionPage {
        frames,
        next_from_seq,
        observed_head,
        reached_tail,
    })
}

#[cfg(any(test, feature = "test-support"))]
fn read_scoped_prefix(
    conn: &Connection,
    execution_id: Ulid,
    index: &str,
    predicate: &str,
    key: rusqlite::types::Value,
    through_seq: i64,
) -> KataResult<Vec<TransitionFrame>> {
    if through_seq < 0 {
        return Err(KataError::Validation(
            "negative captured authority head".into(),
        ));
    }
    let sql = format!(
        "SELECT {CHAIN_COLUMNS_SQL} FROM transitions INDEXED BY {index} WHERE execution_id = ?1 AND {predicate} AND seq <= ?3 ORDER BY seq"
    );
    let mut stmt = conn
        .prepare(&sql)
        .map_err(|error| KataError::Storage(format!("prepare scoped prefix: {error}")))?;
    let raw = stmt
        .query_map(
            rusqlite::params![execution_id.to_bytes().as_ref(), key, through_seq],
            |row| {
                Ok(RawChainRow {
                    seq: row.get(0)?,
                    execution_id: row.get(1)?,
                    scope: row.get(2)?,
                    stage_id: row.get(3)?,
                    attempt_ordinal: row.get(4)?,
                    attempt_id: row.get(5)?,
                    kind: row.get(6)?,
                    resulting_state: row.get(7)?,
                    folds_projection: row.get(8)?,
                    payload_json: row.get(9)?,
                    recorded_at_ms: row.get(10)?,
                })
            },
        )
        .map_err(|error| KataError::Storage(format!("read scoped prefix: {error}")))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| KataError::Storage(format!("collect scoped prefix: {error}")))?;
    raw.into_iter()
        .map(|row| decode_frame(execution_id, row).map_err(Into::into))
        .collect()
}

fn read_page(
    conn: &Connection,
    execution_id: Ulid,
    from_seq: i64,
    limit: usize,
) -> KataResult<TransitionPage> {
    let mut stmt = conn
        .prepare(&execution_page_sql())
        .map_err(|error| KataError::Storage(format!("prepare chain page: {error}")))?;
    let raw = stmt
        .query_map(
            rusqlite::params![
                execution_id.to_bytes().as_ref(),
                from_seq,
                i64::try_from(limit).unwrap_or(i64::MAX),
            ],
            |row| {
                Ok(RawChainRow {
                    seq: row.get(0)?,
                    execution_id: row.get(1)?,
                    scope: row.get(2)?,
                    stage_id: row.get(3)?,
                    attempt_ordinal: row.get(4)?,
                    attempt_id: row.get(5)?,
                    kind: row.get(6)?,
                    resulting_state: row.get(7)?,
                    folds_projection: row.get(8)?,
                    payload_json: row.get(9)?,
                    recorded_at_ms: row.get(10)?,
                })
            },
        )
        .map_err(|error| KataError::Storage(format!("scan chain page: {error}")))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| KataError::Storage(format!("collect chain page: {error}")))?;

    let reached_tail = raw.len() < limit;
    let mut frames = Vec::with_capacity(raw.len());
    for row in raw {
        frames.push(decode_frame(execution_id, row)?);
    }
    // The cursor is derived from the LAST FRAME RETURNED, never from
    // `from_seq + limit`: the chain is global, so this execution's sequences are
    // sparse within it, and advancing by the page size would step over another
    // execution's rows AND this one's next frame alike.
    let next_from_seq = frames
        .last()
        .map_or(from_seq, |frame| frame.seq.saturating_add(1));
    Ok(TransitionPage {
        frames,
        next_from_seq,
        reached_tail,
    })
}

/// The raw column tuple, decoded from SQLite types only. Semantic decoding —
/// which is where refusals live — happens in [`decode_frame`], so a SQLite type
/// error and a chain defect never masquerade as each other.
struct RawChainRow {
    seq: i64,
    execution_id: Vec<u8>,
    scope: String,
    stage_id: Option<String>,
    attempt_ordinal: Option<i64>,
    attempt_id: Option<Vec<u8>>,
    kind: String,
    resulting_state: String,
    folds_projection: i64,
    payload_json: Vec<u8>,
    recorded_at_ms: i64,
}

/// Decode one raw row into a [`TransitionFrame`], refusing every shape the fold
/// could not reconstruct.
fn decode_frame(
    requested: Ulid,
    row: RawChainRow,
) -> Result<TransitionFrame, UnreconstructableExecution> {
    let refuse = |defect: ChainDefect| UnreconstructableExecution {
        execution_id: requested,
        seq: Some(row.seq),
        defect,
    };
    let row_execution = ulid_from_bytes(&row.execution_id).map_err(|error| {
        refuse(ChainDefect::MalformedIdentity {
            column: "execution_id",
            detail: error.to_string(),
        })
    })?;
    if row_execution != requested {
        return Err(refuse(ChainDefect::ForeignExecutionRow {
            found: row_execution,
        }));
    }
    let scope = match row.scope.as_str() {
        "execution" => ChainScope::Execution,
        "stage" => ChainScope::Stage,
        "attempt" => ChainScope::Attempt,
        other => {
            return Err(refuse(ChainDefect::UnknownScope {
                found: other.to_string(),
            }));
        }
    };
    // The schema CHECK already forbids each of these on WRITE. It is re-asserted
    // on READ because a CHECK constrains writers, not files: a restored artifact,
    // a hand-edited database, or a file written with constraints disabled all
    // reach this decode with the constraint unenforced. The write-side
    // constraint and this read-side refusal are the same rule applied at both
    // ends, not a duplicated one.
    let coordinates_ok = match scope {
        ChainScope::Execution => row.stage_id.is_none() && row.attempt_ordinal.is_none(),
        ChainScope::Stage => row.stage_id.is_some() && row.attempt_ordinal.is_none(),
        ChainScope::Attempt => row.stage_id.is_some() && row.attempt_ordinal.is_some(),
    };
    if !coordinates_ok {
        return Err(refuse(ChainDefect::ScopeCoordinateDisagreement {
            scope,
            detail: format!(
                "stage_id={:?}, attempt_ordinal={:?}",
                row.stage_id, row.attempt_ordinal
            ),
        }));
    }
    if row.attempt_id.is_some() && scope != ChainScope::Attempt {
        return Err(refuse(ChainDefect::ScopeCoordinateDisagreement {
            scope,
            detail: "an attempt identity appears outside attempt scope".to_string(),
        }));
    }
    let attempt_id = row
        .attempt_id
        .as_deref()
        .map(|bytes| {
            ulid_from_bytes(bytes).map_err(|error| {
                refuse(ChainDefect::MalformedIdentity {
                    column: "attempt_id",
                    detail: error.to_string(),
                })
            })
        })
        .transpose()?;
    Ok(TransitionFrame {
        seq: row.seq,
        execution_id: row_execution,
        scope,
        stage_id: row.stage_id,
        attempt_ordinal: row.attempt_ordinal,
        attempt_id,
        kind: row.kind,
        resulting_state: row.resulting_state,
        folds_projection: row.folds_projection != 0,
        payload_json: row.payload_json,
        recorded_at_ms: row.recorded_at_ms,
    })
}
