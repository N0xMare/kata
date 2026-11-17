//! Durable occurrence identity — ADR-0001 trust boundary 2.
//!
//! # What an occurrence is, and what this plane adds
//!
//! `kata_types::execution_contract::OccurrenceRef` already names one logical
//! invocation of one checked operation, with "retry, lease, worker, and attempt facts
//! deliberately absent so they cannot rotate logical identity". That type is a value
//! in RAM. This module is where the distinction becomes DURABLE, and the reason it
//! has to be is one question: **has this logical work already been accepted?**
//!
//! "Did this ATTEMPT finish?" is a different question, and it stops being
//! equivalent the moment a re-dispatch happens. An attempt orphaned by a worker
//! death and re-dispatched under a fresh ordinal is a SECOND attempt at the SAME
//! occurrence, and nothing in the attempt tables relates the two. Without this
//! plane two generations could each produce a result and each be adjudicated as
//! the outcome, and the transition chain would record both without contradiction —
//! one `completed` per attempt key, which is exactly what the attempt-scope
//! terminal latch permits.
//!
//! # The invariant, and the three mechanisms that enforce it
//!
//! ONE ACCEPTED OUTCOME PER OCCURRENCE. Three mechanisms, at three different layers,
//! and they refuse three DIFFERENT things — see the `occurrences` DDL for the
//! per-mechanism argument and `crates/core/tests/operational_occurrences.rs`, which
//! falsifies 1, 2 and mechanism 3's Rust latch separately. Mechanism 3's UPDATE
//! predicate (`AND accepted_attempt_id IS NULL`) has NO cell of its own and cannot have
//! one through this API: `accept_occurrence_outcome` reads the stored acceptance and
//! refuses a second one in the same transaction BEFORE the UPDATE runs, so removing
//! the predicate changes no observable outcome (a mutation survives it). It
//! is kept as the in-SQL statement of write-once for a writer that skipped the read:
//!
//! 1. the stored `CHECK ((accepted_at_ms IS NULL) = (accepted_attempt_id IS NULL))`
//!    refuses a HALF-WRITTEN acceptance — an instant with no attempt or an attempt
//!    with no instant, which would make "is this accepted?" answer differently
//!    depending on which column a reader consults;
//! 2. `idx_occurrences_accepted_attempt` (partial UNIQUE) refuses ONE ATTEMPT from
//!    being the accepted outcome of TWO occurrences;
//! 3. [`OperationalDb::accept_occurrence_outcome`]'s write-once
//!    `UPDATE ... WHERE occurrence_id = ? AND accepted_attempt_id IS NULL` with an
//!    asserted `rowcount == 1`, plus the Rust latch
//!    [`super::refuse_second_occurrence_acceptance`] in `record_transition`, refuse
//!    ONE OCCURRENCE from accepting TWO attempts.
//!
//! Mechanism 3 is the invariant; 1 and 2 are the two ways a writer that bypassed it
//! could still leave the plane incoherent.
//!
//! # Why the acceptance is issued INSIDE the accepting transition
//!
//! `accept_occurrence_outcome` takes a `&Transaction` and has no `in_writer_txn` of
//! its own, deliberately. The acceptance and the attempt's accepting lifecycle
//! transition are ONE fact: an acceptance that committed without the transition would
//! burn the occurrence for an attempt whose completion is not in the chain, and a
//! transition that committed without the acceptance would leave the occurrence open
//! for a second generation to accept. Two transactions here is the two-facts-one-crash
//! exposure the crash proof is stated over, and a separate verb is how a caller would
//! acquire it.

use kata_types::error::{KataError, KataResult};
use rusqlite::{OptionalExtension, Transaction, params};
use ulid::Ulid;

use super::{OperationalDb, now_ms, ulid_from_bytes};

/// One `occurrences` row, decoded.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OccurrenceRow {
    pub occurrence_id: [u8; 32],
    pub execution_id: Ulid,
    pub program_hash: [u8; 32],
    pub operation_contract_id: [u8; 32],
    /// `OperationPath::canonical_bytes()` — the u64 LE coordinate count followed by
    /// each coordinate as u32 LE. Stored, not decoded back into an `OperationPath`,
    /// because it is the LOOKUP KEY: a reader that re-derived coordinates and
    /// re-encoded them to query would have a second encoding, which is the one thing
    /// `canonical_bytes` exists to prevent.
    pub operation_path: Vec<u8>,
    pub prepared_action_id: Option<[u8; 32]>,
    pub capsule_id: Option<[u8; 32]>,
    pub created_at_ms: i64,
    /// The accepted PAIR, carried as one `Option` rather than two, so a reader cannot
    /// spell the half-written state the stored CHECK forbids.
    pub accepted: Option<AcceptedOutcome>,
    /// The walked `/work` tree bound to this occurrence BY ROLE, when it has one.
    pub work_tree_artifact_id: Option<[u8; 32]>,
}

/// The accepted outcome of one occurrence: which attempt produced it, and when.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AcceptedOutcome {
    pub attempt_id: Ulid,
    pub at_ms: i64,
}

/// Which commandless attempt at an occurrence a reader asks for.
#[derive(Clone, Copy)]
enum OccurrenceClaimShape {
    /// A live claim the occurrence recovery may ADOPT and dispatch: not terminal and not
    /// parked awaiting approval.
    Adoptable,
    /// A claim parked awaiting an operator's approval — re-presented, never dispatched.
    ParkedForApproval,
}

impl OccurrenceClaimShape {
    const fn describe(self) -> &'static str {
        match self {
            Self::Adoptable => "undispatched",
            Self::ParkedForApproval => "approval-parked",
        }
    }
}

/// The one column list every occurrence read uses, so a column added to the table
/// cannot reach one reader and miss another.
const OCCURRENCE_COLUMNS: &str = "SELECT occurrence_id, execution_id, program_hash, \
                                  operation_contract_id, operation_path, prepared_action_id, \
                                  capsule_id, created_at_ms, accepted_at_ms, \
                                  accepted_attempt_id, work_tree_artifact_id FROM occurrences";

impl OperationalDb {
    /// One occurrence by its content id.
    pub fn occurrence(&self, occurrence_id: [u8; 32]) -> KataResult<Option<OccurrenceRow>> {
        self.with_read(|conn| occurrence_by_id(conn, occurrence_id))
    }

    /// One occurrence by the coordinates a caller holds BEFORE it knows the id —
    /// served by `UNIQUE(execution_id, operation_contract_id, operation_path)`.
    pub fn occurrence_at(
        &self,
        execution_id: Ulid,
        operation_contract_id: [u8; 32],
        operation_path: &[u8],
    ) -> KataResult<Option<OccurrenceRow>> {
        self.with_read(|conn| {
            occurrence_by_coordinates(conn, execution_id, operation_contract_id, operation_path)
                .map_err(|error| KataError::Storage(format!("read occurrence at path: {error}")))?
                .transpose()
        })
    }

    /// The attempt bound to `occurrence_id` that carries NO DISPATCH.
    ///
    /// # What this is for
    ///
    /// It is the reader `after_occurrence_authorized_before_dispatch`'s recovery
    /// obligation is discharged through (and `after_claim_commit`'s, the same durable
    /// state one statement earlier). That window leaves exactly this residue: an
    /// occurrence whose attempt row, binding and claiming transition are durable and
    /// for which nothing was ever enqueued. The obligation is "a durable occurrence
    /// acquires exactly ONE dispatch", so recovery must DISPATCH THAT ATTEMPT rather
    /// than claim a second generation — a second attempt would satisfy "the occurrence
    /// got a dispatch" while leaving the first one pending forever, unreachable by any
    /// sweep that keys on the occurrence, which is the accumulating-orphan shape the
    /// boundary exists to prevent.
    ///
    /// # The predicate, and why it is a conjunction
    ///
    /// NOT TERMINAL, NOT PARKED AWAITING APPROVAL, `dispatched_at_ms IS NULL` AND no
    /// `attempt_commands` row.
    ///
    /// Not parked, because a parked approval gate is exactly an undispatched claim that
    /// must NOT be dispatched by re-presentation: adopting it here is how a runner resume
    /// would bypass the operator. [`Self::parked_capsule_attempt_at_occurrence`] is the
    /// gated path's read.
    ///
    /// Not terminal, because an undispatched attempt can be SETTLED: a claim whose dispatch
    /// failed, or whose execution latched a terminal outcome before any dispatch, is
    /// recorded PROVEN NOT PERFORMED (`Dispatcher::settle_unsent_capsule_claim`). Adopting
    /// that row would dispatch an attempt the chain has already finished — a refusal every
    /// later submit of the occurrence would repeat — and counting it would make the fresh
    /// claim the next submit mints look like a second residue beside it.
    /// [`OperationalDb::dispatch_claimed_attempt`] writes both in ONE transaction, so
    /// either alone would answer the question; taking both makes a row where they
    /// DISAGREE invisible to this reader instead of arbitrarily included by whichever
    /// half it happened to consult. A disagreement is a plane no writer of this API can
    /// produce, and this reader is not the place to adjudicate one — it is the place
    /// not to act on it.
    ///
    /// # A MAIN-RESOLVED attempt is excluded BY NAME
    ///
    /// `executor = 'worker'` is part of the predicate. A waiting main attempt satisfies
    /// every other clause (never dispatched, no command, not terminal), and the reader's
    /// two production callers — `authorize_attempt`'s adoption, and the resumed runner's
    /// boot dispatch of a claim the previous main left
    /// (`Dispatcher::dispatch_claims_left_undispatched`) — both DISPATCH what it finds,
    /// so without the clause a re-presented occurrence would put a main attempt on a
    /// worker. The dispatch would then be refused by the executor latch, but the adoption
    /// would have answered "this occurrence has an undispatched attempt" for work no worker
    /// may ever run, and every later submit would repeat the refusal.
    ///
    /// # Failure
    ///
    /// A typed [`KataError::Validation`] when TWO OR MORE undispatched attempts are
    /// bound to one occurrence. That is unreachable through this API — a claim that
    /// finds one converges on it instead of adding another — so it is a refusal rather
    /// than a "pick the oldest": choosing would dispatch one and strand the rest under
    /// the same invariant this reader exists to serve.
    pub fn undispatched_attempt_at_occurrence(
        &self,
        occurrence_id: [u8; 32],
    ) -> KataResult<Option<Ulid>> {
        self.sole_commandless_attempt_at_occurrence(occurrence_id, OccurrenceClaimShape::Adoptable)
    }

    /// The CAPSULE attempt PARKED awaiting an operator's approval at `occurrence_id`.
    ///
    /// # What this is for, and why it is not [`Self::undispatched_attempt_at_occurrence`]
    ///
    /// A gated occurrence's claim lands in `awaiting_approval` in its own transaction
    /// (`AttemptClaimSpec::park_reason`). It carries no dispatch, so the adoption read
    /// above would match it — and `authorize_attempt`'s occurrence recovery would then
    /// DISPATCH it on the next re-presentation of the stage: an approval bypass reached by
    /// nothing more than a runner resume. So that read excludes the parked state, and the
    /// gated path reads this one instead, which answers the park it RE-PRESENTS and never
    /// dispatches. The one door that turns a parked claim into a dispatch is
    /// `OperationalDb::decide_capsule_approval`.
    ///
    /// # The predicate
    ///
    /// Projected state `awaiting_approval`, `dispatched_at_ms IS NULL` and no
    /// `attempt_commands` row — the same conjunction as the adoption read, restricted to
    /// the parked state. An approved gate is dispatched in the decision's own
    /// transaction, so it is `dispatched` and no longer matches.
    ///
    /// # Failure
    ///
    /// [`Self::undispatched_attempt_at_occurrence`]'s: two or more such attempts at one
    /// occurrence is a typed refusal rather than a choice.
    pub fn parked_capsule_attempt_at_occurrence(
        &self,
        occurrence_id: [u8; 32],
    ) -> KataResult<Option<Ulid>> {
        self.sole_commandless_attempt_at_occurrence(
            occurrence_id,
            OccurrenceClaimShape::ParkedForApproval,
        )
    }

    fn sole_commandless_attempt_at_occurrence(
        &self,
        occurrence_id: [u8; 32],
        shape: OccurrenceClaimShape,
    ) -> KataResult<Option<Ulid>> {
        let state_clause = match shape {
            OccurrenceClaimShape::Adoptable => {
                let excluded = super::ATTEMPT_TERMINAL_STATES
                    .iter()
                    .chain(std::iter::once(&super::AWAITING_APPROVAL_STATE))
                    .map(|state| format!("'{state}'"))
                    .collect::<Vec<_>>()
                    .join(", ");
                format!("(p.state IS NULL OR p.state NOT IN ({excluded}))")
            }
            OccurrenceClaimShape::ParkedForApproval => {
                format!("p.state = '{}'", super::AWAITING_APPROVAL_STATE)
            }
        };
        let described = shape.describe();
        self.with_read(|conn| {
            let mut statement = conn
                .prepare(&format!(
                    "SELECT a.attempt_id FROM attempts a
                       LEFT JOIN attempt_projection p
                         ON p.execution_id = a.execution_id AND p.stage_id = a.stage_id
                        AND p.attempt_ordinal = a.attempt_ordinal
                      WHERE a.occurrence_id = ?1
                        AND a.executor = 'worker'
                        AND a.dispatched_at_ms IS NULL
                        AND {state_clause}
                        AND NOT EXISTS (
                              SELECT 1 FROM attempt_commands c WHERE c.attempt_id = a.attempt_id)
                      ORDER BY a.attempt_id",
                ))
                .map_err(|error| {
                    KataError::Storage(format!("prepare {described} attempt read: {error}"))
                })?;
            let rows = statement
                .query_map(params![occurrence_id.as_slice()], |row| {
                    row.get::<_, Vec<u8>>(0)
                })
                .map_err(|error| {
                    KataError::Storage(format!("read {described} attempt: {error}"))
                })?;
            let mut found = Vec::new();
            for row in rows {
                let bytes = row.map_err(|error| {
                    KataError::Storage(format!("decode {described} attempt: {error}"))
                })?;
                found.push(ulid_from_bytes(&bytes)?);
            }
            match found.len() {
                0 => Ok(None),
                1 => Ok(Some(found[0])),
                _ => Err(KataError::Validation(format!(
                    "operational.db holds {} {described} attempts bound to occurrence {}: {}. \
                     One occurrence acquires ONE dispatch, so there is no correct choice among \
                     them and this reader refuses rather than dispatching one and stranding the \
                     rest",
                    found.len(),
                    hex::encode(occurrence_id),
                    found
                        .iter()
                        .map(ToString::to_string)
                        .collect::<Vec<_>>()
                        .join(", ")
                ))),
            }
        })
    }

    /// LATCH the accepted outcome of `occurrence_id` to `attempt_id`, ON THE CALLER'S
    /// TRANSACTION.
    ///
    /// # Invariant
    ///
    /// WRITE-ONCE, and the predicate is what makes it so: the UPDATE carries
    /// `AND accepted_attempt_id IS NULL`, so a second acceptance of one occurrence
    /// matches ZERO rows. `rowcount == 1` is then asserted rather than assumed, which
    /// is what turns "the row was already accepted" and "there is no such occurrence"
    /// into two named refusals instead of one silent no-op. A bare
    /// `UPDATE ... WHERE occurrence_id = ?` would overwrite the first acceptance and
    /// the plane would end up recording the LAST generation to finish, which is the
    /// opposite of the invariant.
    ///
    /// # THE INSTANT IS THE ACCEPTING TRANSITION'S, read off its row
    ///
    /// `accepted_at_ms` is `(SELECT recorded_at_ms FROM transitions WHERE seq = ?)` for the
    /// transition this acceptance rides, not a second `now_ms()`. Two disagreeing
    /// representations of one fact are never allowed, and "when was this occurrence's
    /// outcome accepted?" and "when was the accepting transition recorded?" are ONE fact:
    /// they commit together, in this transaction, and nothing can order them apart. Two
    /// clock reads would differ by a millisecond under load — measured as two `now_ms()`
    /// calls 1 ms apart for one fact (see `record_main_side_transition`'s start-anchor
    /// paragraph) — and a reader comparing the two would see an acceptance that preceded or
    /// followed its own transition. It is the same idiom `accept_incoming_event_in_tx`
    /// already uses for `attempts.finished_at_ms`.
    ///
    /// The subquery cannot silently yield NULL: the caller inserts that transition row
    /// earlier in this transaction, and a NULL would violate the stored
    /// `(accepted_at_ms IS NULL) = (accepted_attempt_id IS NULL)` CHECK rather than write a
    /// half-accepted row.
    ///
    /// THERE IS DELIBERATELY NO `CHECK (accepted_at_ms >= created_at_ms)`. It read like an
    /// obvious integrity rule and it compared two columns whose instants come from
    /// DIFFERENT readers — the same class of CHECK `attempt_stop_requests` refuses for its
    /// three timestamps. The ordering it asserted is structural anyway (the accepting
    /// transition is appended after the claim that minted the row), so the CHECK could only
    /// ever fire on a clock that moved backwards, refusing the one write that records what
    /// actually happened.
    ///
    /// Takes `&Transaction` and NOT `&self` on a fresh transaction — see this module's
    /// header for why a standalone verb would be the defect.
    ///
    /// # Failure
    ///
    /// Three typed [`KataError::Validation`]s, all of them BEFORE any write:
    /// an unknown occurrence, an occurrence already accepted by a DIFFERENT attempt,
    /// and an occurrence already accepted by THIS attempt (which is a re-presentation
    /// the caller must recognize rather than absorb: the chain's own idempotency
    /// answers whether the frame was already folded, and swallowing it here would let
    /// a genuine double-accept look like a benign retry).
    pub(crate) fn accept_occurrence_outcome(
        tx: &Transaction<'_>,
        occurrence_id: [u8; 32],
        attempt_id: Ulid,
        accepting_seq: i64,
    ) -> KataResult<()> {
        let stored = read_occurrence(tx, occurrence_id)?.ok_or_else(|| {
            KataError::Validation(format!(
                "operational.db has no occurrence {} to accept an outcome for; an attempt's \
                 occurrence binding names a row the claim wrote in the same transaction, so an \
                 absent row means the binding was minted outside this API",
                hex::encode(occurrence_id)
            ))
        })?;
        if let Some(accepted) = stored.accepted {
            return Err(KataError::Validation(format!(
                "operational.db refuses a second accepted outcome for occurrence {}: attempt {} \
                 accepted it at {}, and this acceptance names attempt {attempt_id}. One \
                 occurrence has ONE accepted outcome — a later generation of the same logical \
                 work may run, but it may not be adjudicated as the result a second time",
                hex::encode(occurrence_id),
                accepted.attempt_id,
                accepted.at_ms
            )));
        }
        let updated = tx
            .execute(
                "UPDATE occurrences
                    SET accepted_at_ms = (SELECT recorded_at_ms FROM transitions WHERE seq = ?1),
                        accepted_attempt_id = ?2
                  WHERE occurrence_id = ?3 AND accepted_attempt_id IS NULL",
                params![
                    accepting_seq,
                    attempt_id.to_bytes().as_ref(),
                    occurrence_id.as_slice()
                ],
            )
            .map_err(|error| KataError::Storage(format!("accept occurrence outcome: {error}")))?;
        if updated != 1 {
            return Err(KataError::Validation(format!(
                "operational.db accepted-outcome write for occurrence {} matched {updated} rows, \
                 not 1; the conditional predicate is what makes the column write-once, so any \
                 other count means a concurrent writer accepted it between this transaction's \
                 read and its update",
                hex::encode(occurrence_id)
            )));
        }
        Ok(())
    }
}

/// MINT the occurrence `binding` names, on the caller's transaction, and answer the
/// row that is durable afterwards.
///
/// # Invariant
///
/// `INSERT ... ON CONFLICT DO NOTHING` FOLLOWED BY A READ-BACK, never an upsert. The
/// conflict target is the LOOKUP key, not the primary key, and that is the whole
/// point: a re-presentation of the same logical work must converge on the row that is
/// already there, and a row whose coordinates match but whose CONTENT disagrees must
/// REFUSE rather than be converged on. `DO UPDATE` would silently adopt the newer
/// claim — which, since `occurrence_id` folds the program hash, is exactly how a
/// repointed execution would overwrite the identity of work already in flight.
///
/// The read-back is unconditional (not `RETURNING` on the insert) because the row this
/// transaction must agree with is the STORED one whether or not this statement wrote
/// it, and a `RETURNING` clause on a `DO NOTHING` conflict yields nothing at all.
pub(super) fn mint_occurrence(
    tx: &Transaction<'_>,
    binding: &super::records::OccurrenceBinding,
) -> KataResult<OccurrenceRow> {
    let occurrence_id = binding.occurrence_id();
    let operation_path = binding.operation_path();
    tx.execute(
        "INSERT INTO occurrences
             (occurrence_id, execution_id, program_hash, operation_contract_id, operation_path,
              prepared_action_id, capsule_id, created_at_ms, work_tree_artifact_id)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
         ON CONFLICT(execution_id, operation_contract_id, operation_path) DO NOTHING",
        params![
            occurrence_id.as_slice(),
            binding.execution_id().to_bytes().as_ref(),
            binding.program_hash().as_slice(),
            binding.operation_contract_id().as_slice(),
            operation_path.as_slice(),
            binding.prepared_action_id().map(|id| id.to_vec()),
            binding.capsule_id().map(|id| id.to_vec()),
            now_ms(),
            binding.work_tree_artifact_id.map(|id| id.to_vec()),
        ],
    )
    .map_err(|error| KataError::Storage(format!("mint occurrence: {error}")))?;
    let stored = occurrence_by_coordinates(
        tx,
        binding.execution_id(),
        binding.operation_contract_id(),
        &operation_path,
    )
    .map_err(|error| KataError::Storage(format!("read minted occurrence: {error}")))?
    .transpose()?
    .ok_or_else(|| {
        KataError::Storage(format!(
            "operational.db minted occurrence {} is not readable back in its own \
                 transaction; the lookup key and the insert disagree",
            hex::encode(occurrence_id)
        ))
    })?;
    refuse_divergent_occurrence(&stored, binding)?;
    Ok(stored)
}

/// Refuse a stored occurrence whose CONTENT disagrees with the binding presented for
/// the same coordinates.
///
/// # The refused set, exactly
///
/// Four fields, and no others: `occurrence_id`, `program_hash`, `capsule_id`,
/// `work_tree_artifact_id`.
///
/// * `occurrence_id` and `program_hash` travel together — the id FOLDS the hash — so a
///   disagreement in either is a REPOINTED EXECUTION: the same operation at the same
///   path under a different program. Converging would mean a capsule assembled for one
///   program's operation is accepted as the outcome of another's.
/// * `capsule_id` is refused because the capsule is what the worker will actually run.
///   Two claims at one occurrence naming two capsules is two different bodies of work
///   presented as one logical occurrence, which is the aliasing the occurrence id
///   exists to prevent.
///
/// * `work_tree_artifact_id` is refused because the walked `/work` tree is the INPUT the
///   capsule maps by role: the same occurrence re-presented over a different walk is a
///   different body of work under one occurrence — the divergent re-declaration the
///   `/work` producer names.
///
/// `prepared_action_id` is deliberately NOT in the set, and is not adopted either: a
/// binding that carries one where the stored row has none is the ordinary order
/// (minting precedes preparation), so refusing it would refuse that order. It is
/// stated here rather than left as an absence, because "we refuse divergence" would
/// otherwise be a claim wider than its mechanism. There is no verb that binds a
/// prepared action onto a minted occurrence.
fn refuse_divergent_occurrence(
    stored: &OccurrenceRow,
    binding: &super::records::OccurrenceBinding,
) -> KataResult<()> {
    let divergent: Vec<&str> = [
        (
            "occurrence_id",
            stored.occurrence_id == binding.occurrence_id(),
        ),
        (
            "program_hash",
            stored.program_hash == binding.program_hash(),
        ),
        (
            "capsule_id",
            binding
                .capsule_id()
                .is_none_or(|capsule| stored.capsule_id.is_some_and(|stored| stored == capsule)),
        ),
        (
            "work_tree_artifact_id",
            binding.work_tree_artifact_id.is_none_or(|tree| {
                stored
                    .work_tree_artifact_id
                    .is_some_and(|stored| stored == tree)
            }),
        ),
    ]
    .into_iter()
    .filter_map(|(field, equal)| (!equal).then_some(field))
    .collect();
    if divergent.is_empty() {
        return Ok(());
    }
    Err(KataError::Validation(format!(
        "operational.db refuses to claim an attempt at occurrence {} (execution {}, operation {}): \
         the stored row disagrees on {}. These coordinates already name work this node authorized, \
         and adopting a different {} under them would alias two logical occurrences onto one row",
        hex::encode(binding.occurrence_id()),
        binding.execution_id(),
        hex::encode(binding.operation_contract_id()),
        divergent.join(", "),
        divergent.join("/")
    )))
}

/// The refusal a join answers when an input it fans in is not ACCEPTED.
pub const JOIN_INPUT_UNACCEPTED: &str = "join_input_unaccepted";

/// REQUIRE every occurrence in `inputs` to be an ACCEPTED occurrence of `execution_id`,
/// read on the caller's writer transaction — the join's precondition, so "every input is
/// accepted" is decided on the same snapshot the join's own acceptance commits on.
///
/// # The refused set, exactly
///
/// [`JOIN_INPUT_UNACCEPTED`], naming the first offending input, for an input occurrence
/// with NO ROW (never minted, so never accepted), a row of ANOTHER execution (not an
/// input this execution can fan in), or a row with no accepted outcome. Nothing else: an
/// empty `inputs` holds vacuously, and the order of `inputs` is not checked here — it is
/// the caller's, and the join records it.
pub(super) fn require_occurrences_accepted(
    tx: &Transaction<'_>,
    execution_id: Ulid,
    inputs: &[[u8; 32]],
) -> KataResult<()> {
    for input in inputs {
        let unaccepted = |why: &str| {
            KataError::Validation(format!(
                "operational.db refuses the join ({JOIN_INPUT_UNACCEPTED}): its input occurrence \
                 {} {why}. A join resolves once EVERY input it fans in has an accepted outcome, \
                 and nothing of the join was written",
                hex::encode(input)
            ))
        };
        let row = read_occurrence(tx, *input)?.ok_or_else(|| unaccepted("has no row"))?;
        if row.execution_id != execution_id {
            return Err(unaccepted(&format!(
                "belongs to execution {}, not the join's execution {execution_id}",
                row.execution_id
            )));
        }
        if row.accepted.is_none() {
            return Err(unaccepted("has no accepted outcome"));
        }
    }
    Ok(())
}

/// Read one occurrence inside a writer transaction.
pub(super) fn read_occurrence(
    tx: &Transaction<'_>,
    occurrence_id: [u8; 32],
) -> KataResult<Option<OccurrenceRow>> {
    tx.query_row(
        &format!("{OCCURRENCE_COLUMNS} WHERE occurrence_id = ?1"),
        params![occurrence_id.as_slice()],
        decode_occurrence,
    )
    .optional()
    .map_err(|error| KataError::Storage(format!("read occurrence in txn: {error}")))?
    .transpose()
}

/// The occurrence one attempt is bound to, if it carries a binding at all — served by
/// `idx_attempts_occurrence`.
pub(super) fn attempt_occurrence(
    tx: &Transaction<'_>,
    attempt_id: Ulid,
) -> KataResult<Option<[u8; 32]>> {
    let stored: Option<Option<Vec<u8>>> = tx
        .query_row(
            "SELECT occurrence_id FROM attempts WHERE attempt_id = ?1",
            params![attempt_id.to_bytes().as_ref()],
            |row| row.get(0),
        )
        .optional()
        .map_err(|error| KataError::Storage(format!("read attempt occurrence: {error}")))?;
    match stored.flatten() {
        None => Ok(None),
        Some(bytes) => digest32(&bytes, "occurrence_id").map(Some),
    }
}

/// The stored occurrence at `binding`'s coordinates, if one exists — a READ inside the
/// caller's writer transaction, for a verb that must decide before it mints.
pub(super) fn stored_occurrence_at(
    tx: &Transaction<'_>,
    binding: &super::records::OccurrenceBinding,
) -> KataResult<Option<OccurrenceRow>> {
    occurrence_by_coordinates(
        tx,
        binding.execution_id(),
        binding.operation_contract_id(),
        &binding.operation_path(),
    )
    .map_err(|error| KataError::Storage(format!("read occurrence at coordinates: {error}")))?
    .transpose()
}

/// The one lookup by `UNIQUE(execution_id, operation_contract_id, operation_path)`,
/// shared by [`OperationalDb::occurrence_at`] and [`mint_occurrence`]'s read-back so the
/// key the insert conflicts on and the key the reads use cannot drift apart.
fn occurrence_by_coordinates(
    conn: &rusqlite::Connection,
    execution_id: Ulid,
    operation_contract_id: [u8; 32],
    operation_path: &[u8],
) -> rusqlite::Result<Option<KataResult<OccurrenceRow>>> {
    conn.query_row(
        &format!(
            "{OCCURRENCE_COLUMNS} WHERE execution_id = ?1 \
               AND operation_contract_id = ?2 AND operation_path = ?3"
        ),
        params![
            execution_id.to_bytes().as_ref(),
            operation_contract_id.as_slice(),
            operation_path
        ],
        decode_occurrence,
    )
    .optional()
}

/// One occurrence by its content id, on `conn` — the read
/// [`OperationalDb::occurrence`] and the one-snapshot settlement read share.
pub(super) fn occurrence_by_id(
    conn: &rusqlite::Connection,
    occurrence_id: [u8; 32],
) -> KataResult<Option<OccurrenceRow>> {
    conn.query_row(
        &format!("{OCCURRENCE_COLUMNS} WHERE occurrence_id = ?1"),
        params![occurrence_id.as_slice()],
        decode_occurrence,
    )
    .optional()
    .map_err(|error| KataError::Storage(format!("read occurrence: {error}")))?
    .transpose()
}

/// Decode one row, deferring the fixed-width refusals to [`KataResult`] so a corrupt
/// stored blob is a typed storage refusal rather than a panic inside rusqlite's
/// closure.
#[allow(clippy::type_complexity)]
fn decode_occurrence(row: &rusqlite::Row<'_>) -> rusqlite::Result<KataResult<OccurrenceRow>> {
    let occurrence_id: Vec<u8> = row.get(0)?;
    let execution_id: Vec<u8> = row.get(1)?;
    let program_hash: Vec<u8> = row.get(2)?;
    let operation_contract_id: Vec<u8> = row.get(3)?;
    let operation_path: Vec<u8> = row.get(4)?;
    let prepared_action_id: Option<Vec<u8>> = row.get(5)?;
    let capsule_id: Option<Vec<u8>> = row.get(6)?;
    let created_at_ms: i64 = row.get(7)?;
    let accepted_at_ms: Option<i64> = row.get(8)?;
    let accepted_attempt_id: Option<Vec<u8>> = row.get(9)?;
    let work_tree_artifact_id: Option<Vec<u8>> = row.get(10)?;
    Ok((|| {
        // THE PAIR IS DECODED AS A PAIR. The stored CHECK forbids a half-written
        // acceptance, so a half-written one reaching this decoder means the CHECK is
        // not in force — which is a typed storage refusal, never a row read as
        // 'unaccepted' on a plane that can no longer say.
        let accepted = match (accepted_at_ms, accepted_attempt_id) {
            (None, None) => None,
            (Some(at_ms), Some(attempt)) => Some(AcceptedOutcome {
                attempt_id: ulid_from_bytes(&attempt)?,
                at_ms,
            }),
            (at_ms, attempt) => {
                return Err(KataError::Storage(format!(
                    "operational.db occurrence {} carries a half-written acceptance \
                     (accepted_at_ms={at_ms:?}, accepted_attempt_id present={}); the \
                     (accepted_at_ms IS NULL) = (accepted_attempt_id IS NULL) CHECK is not in \
                     force",
                    hex::encode(&occurrence_id),
                    attempt.is_some()
                )));
            }
        };
        Ok(OccurrenceRow {
            occurrence_id: digest32(&occurrence_id, "occurrence_id")?,
            execution_id: ulid_from_bytes(&execution_id)?,
            program_hash: digest32(&program_hash, "program_hash")?,
            operation_contract_id: digest32(&operation_contract_id, "operation_contract_id")?,
            operation_path,
            prepared_action_id: prepared_action_id
                .as_deref()
                .map(|bytes| digest32(bytes, "prepared_action_id"))
                .transpose()?,
            capsule_id: capsule_id
                .as_deref()
                .map(|bytes| digest32(bytes, "capsule_id"))
                .transpose()?,
            created_at_ms,
            accepted,
            work_tree_artifact_id: work_tree_artifact_id
                .as_deref()
                .map(|bytes| digest32(bytes, "work_tree_artifact_id"))
                .transpose()?,
        })
    })())
}

fn digest32(bytes: &[u8], column: &str) -> KataResult<[u8; 32]> {
    bytes.try_into().map_err(|_| {
        KataError::Storage(format!(
            "operational.db occurrences.{column} must be 32 bytes, got {}",
            bytes.len()
        ))
    })
}
