//! Cold rebuild, fold SHAPE, per-execution isolation, and
//! the replay-equals-live-state invariant, all on the single operational plane.
//!
//! # Regime, stated once for the whole file
//!
//! `operational.db` reserves `transitions.seq` IN-TRANSACTION
//! (`UPDATE transition_sequence SET value = value + 1 … RETURNING value`), so an
//! aborted or REFUSED transition reverts its reservation and the chain has **no
//! holes**. That is the opposite of the ledger plane, which reserves BEFORE the
//! commit and therefore leaves permanent holes by design — correct there, because
//! an SSE `?since=N` cursor a client already passed must never be re-served with a
//! different event.
//!
//! The distinction is not cosmetic here. `attempt_projection.source_seq` and
//! `attempts.source_seq` are FOREIGN KEYS into `transitions(seq)`, so a hole on
//! this plane is a dangling reference and an unsatisfiable watermark, not a
//! tolerated gap. Every assertion below is a DELTA or a STRUCTURAL EQUALITY; none
//! pins an absolute sequence value, because such a value pins a fold artifact
//! rather than a durability property.
//!
//! # The fold-cardinality trap these tests deliberately avoid
//!
//! [`OperationalDb::dispatch_attempt`] writes **two** transitions — the
//! attempt-scope `claimed` and `dispatched` of its one commit. A transition COUNT
//! would pin that fold cardinality instead of a durability property. The dispatch path is
//! therefore asserted by ORDERING (the claim precedes the dispatch) and by which
//! projections moved, never by a count.

use kata_core::operational::AttemptClaimSpec;
use kata_core::operational::OccurrenceBinding;
use kata_core::operational::projection::AttemptProjectionRow;
use kata_core::{
    CommandSpec, InvocationKind, InvocationRecord, OperationalDb, ProgramRecord, SubmitOutcome,
};
use kata_types::error::KataError;
use kata_types::idempotency::canonicalize_args;
use kata_types::identity_algebra::AdmissionDigest;
use kata_types::primitives::ContentHash;
use ulid::Ulid;

const STAGE_A: &str = "draft";
const STAGE_B: &str = "review";

/// The attempt-scope ABSORBING states. Kept as a local literal on purpose: a test
/// that imported the production constant would compare it to itself, which is the
/// tautology class.
const TERMINALS: &[&str] = &["completed", "failed", "cancelled", "timed_out"];

fn program() -> ProgramRecord {
    ProgramRecord {
        program_hash: ContentHash::new([11u8; 32]),
        schema_version: 4,
        program_json: b"{\"program\":1}".to_vec(),
    }
}

fn invocation() -> InvocationRecord {
    let bytes = canonicalize_args(&serde_json::json!({"schema_version": 1}));
    let digest = *blake3::hash(&bytes).as_bytes();
    InvocationRecord {
        schema_version: 1,
        kind: InvocationKind::Workflow,
        admission_digest: AdmissionDigest(ContentHash::new(digest)),
        invocation_json: bytes,
    }
}

/// Submit an execution and move it to `running` — the lifecycle precondition every
/// attempt-scope fixture below needs, since a transition is scoped to a submitted
/// execution by foreign key.
fn submit(db: &OperationalDb) -> Ulid {
    let execution_id = Ulid::new();
    assert!(matches!(
        db.submit_execution(execution_id, &program(), &invocation())
            .unwrap(),
        SubmitOutcome::Submitted { .. }
    ));
    db.mark_running(execution_id).unwrap();
    execution_id
}

/// Claim one attempt at a CHAIN-allocated ordinal, returning its identity and the
/// sequence of the `claimed` transition that authorized it.
fn claim(db: &OperationalDb, execution_id: Ulid, stage_id: &str, state: &str) -> (Ulid, i64) {
    let attempt_id = Ulid::new();
    let claimed = db
        .claim_attempt(
            execution_id,
            attempt_id,
            &AttemptClaimSpec {
                stage_id: stage_id.to_string(),
                assignment_json: b"{\"capsule\":{\"stage_name\":\"fixture\"}}".to_vec(),
                initial_state: state.to_string(),
                run_ordinal: 0,
                // A placement is recorded so a later advance into a
                // worker-attributed state has one to adjudicate against. Since
                // the CLAIM itself may not name such a state, so
                // `state` here is always one that asserts no dispatch.
                worker_id: Some("w-1".to_string()),
                occurrence: OccurrenceBinding::for_test(execution_id, stage_id),
            },
        )
        .unwrap();
    (attempt_id, claimed.seq)
}

/// Every mutator leaves the nucleus coherent: three-way agreement plus watermark
/// contiguity. Asserted after each scenario so no test can pass while breaking the
/// invariant every other assertion rests on.
fn assert_coherent(db: &OperationalDb, execution_id: Ulid) {
    db.verify_projection_integrity(execution_id).unwrap();
    assert!(
        db.verify_global_watermark().unwrap(),
        "applied_through_seq == transition_sequence.value == MAX(transitions.seq)"
    );
}

/// One expected projection row, spelled out so a wrong stage/ordinal/state/source
/// combination cannot pass by matching on one field.
fn row(stage_id: &str, attempt_ordinal: i64, state: &str, source_seq: i64) -> AttemptProjectionRow {
    AttemptProjectionRow {
        stage_id: stage_id.to_string(),
        attempt_ordinal,
        state: state.to_string(),
        source_seq,
    }
}

// -- cold rebuild, last-wins per (stage_id, attempt_ordinal) ---------

/// Operational regime (reserve-in-transaction, no holes): a COLD rebuild from the
/// retained transition chain reconstructs each attempt's latest state, last-wins
/// per `(stage_id, attempt_ordinal)`, with every row carrying the sequence of its
/// OWN latest advancing transition.
///
/// Cold rebuild with last-wins folded in — `rebuild_from_chain` is a last-wins insert per
/// key over an `ORDER BY seq` scan, so "collapses to one row at the later state
/// with the later source seq" is the same fact as "reconstructs latest status" and
/// splitting them would assert the same fold twice.
///
/// Nothing here chooses a sequence: each
/// mutator RETURNS the value it reserved, and the assertions are structural
/// equalities against those returns plus the relative ordering between them.
#[test]
fn operational_fold_shape_cold_rebuild_reconstructs_latest_status_last_wins() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("operational.db");

    let (execution_id, drafted_seq, reviewed_seq, running_seq, completed_seq, live_rows) = {
        let db = OperationalDb::open(&path).unwrap();
        let execution_id = submit(&db);
        // a: claimed → dispatched → running → completed (FOUR advancing
        // attempt-scope transitions for ONE key). b: claimed only.
        let (attempt_a, drafted_seq) = claim(&db, execution_id, STAGE_A, "pending");
        let (_attempt_b, reviewed_seq) = claim(&db, execution_id, STAGE_B, "pending");
        db.advance_attempt(attempt_a, "dispatched").unwrap();
        let running_seq = db.advance_attempt(attempt_a, "running").unwrap();
        let completed_seq = db
            .complete_attempt(attempt_a, &serde_json::json!({"ok": true}))
            .unwrap();
        let live_rows = db.attempt_projections(execution_id).unwrap();
        assert_coherent(&db, execution_id);
        (
            execution_id,
            drafted_seq,
            reviewed_seq,
            running_seq,
            completed_seq,
            live_rows,
        )
    };

    // COLD: a brand-new handle over the file, with the live fold's in-RAM state
    // gone, rebuilding purely from the retained chain.
    let db = OperationalDb::open(&path).unwrap();
    db.rebuild_projection(execution_id).unwrap();
    let rebuilt = db.attempt_projections(execution_id).unwrap();

    assert_eq!(
        rebuilt,
        vec![
            row(STAGE_A, 0, "completed", completed_seq),
            row(STAGE_B, 0, "pending", reviewed_seq),
        ],
        "one row per (stage_id, attempt_ordinal), each at its LATEST advancing state \
         and carrying that transition's own sequence"
    );
    assert_eq!(
        rebuilt, live_rows,
        "the cold rebuild must reproduce what the live fold wrote, exactly — same states AND \
         same source sequences"
    );
    // LAST-WINS, stated so it cannot pass on a stale pick: a's four advancing
    // transitions collapsed to ONE row, and that row does NOT carry the
    // second-to-last sequence.
    assert_ne!(
        rebuilt[0].source_seq, running_seq,
        "the row must carry the LATEST advancing transition, not an earlier one"
    );
    // Relative ordering only — never a literal.
    assert!(drafted_seq < reviewed_seq);
    assert!(reviewed_seq < running_seq);
    assert!(running_seq < completed_seq);

    assert_coherent(&db, execution_id);
}

// -- the EMPTY-database case, for every reader touched above -----------------

/// Operational regime: on an EMPTY authority every projection reader is empty, the
/// integrity check AGREES (two empties agree) rather than refusing, the rebuild of
/// nothing is a no-op, and all of it survives a reopen.
///
/// Readers on this plane have opposite fail-safe polarities — dispatch/promotion/
/// parking gates fail CLOSED on an absent row while both workspace reapers fail
/// SAFE — so the empty database is a distinct case from the populated one and a
/// reader that conflates them either wedges live work or deletes a live execution's workspace.
/// Every group-D reader is exercised against it here.
#[test]
fn operational_fold_shape_empty_database_reads_are_empty_and_coherent() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("operational.db");
    let ghost = Ulid::new();

    {
        let db = OperationalDb::open(&path).unwrap();
        assert_eq!(db.debug_count("transitions").unwrap(), 0);
        // Zero here is the EMPTINESS itself — "nothing was ever reserved" — not a
        // pinned sequence value.
        assert_eq!(db.debug_reserved_seq().unwrap(), 0);

        assert!(db.attempt_projections(ghost).unwrap().is_empty());
        assert!(db.execution_projection(ghost).unwrap().is_none());
        assert!(db.attempt_projection_for(Ulid::new()).unwrap().is_none());
        assert_coherent(&db, ghost);

        // A rebuild over no chain writes no row and consumes no sequence.
        db.rebuild_projection(ghost).unwrap();
        assert!(db.attempt_projections(ghost).unwrap().is_empty());
        assert_eq!(db.debug_reserved_seq().unwrap(), 0);
        assert_eq!(db.debug_count("transitions").unwrap(), 0);
        assert_coherent(&db, ghost);
    }

    // Reopening an empty authority is still empty and still coherent — the case a
    // first boot on a fresh data dir actually takes.
    let db = OperationalDb::open(&path).unwrap();
    assert_eq!(db.debug_count("transitions").unwrap(), 0);
    assert_eq!(db.debug_reserved_seq().unwrap(), 0);
    assert!(db.attempt_projections(ghost).unwrap().is_empty());
    assert_coherent(&db, ghost);
}

// -- the mechanism dies, the property survives ---------------------------

/// Operational regime: because every transition folds its projection and advances
/// the watermark IN THE SAME COMMIT, a reopen performs no projection work and
/// requires no rebuild.
///
/// A metric that had not incremented — `applied.is_none() || applied == Some(0)` —
/// passes VACUOUSLY if the counter is never registered at all. There is no
/// catch-up fold to count, so this asserts the POSITIVE fact instead: the
/// chain, the reservation, and every projected row are byte-identical across the
/// reopen, and the integrity check passes with no `rebuild_projection` call
/// anywhere in the test.
#[test]
fn operational_fold_shape_reopen_performs_no_projection_work_and_needs_no_rebuild() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("operational.db");

    let (execution_id, reserved_before, chain_before, rows_before) = {
        let db = OperationalDb::open(&path).unwrap();
        let execution_id = submit(&db);
        let (attempt_id, _) = claim(&db, execution_id, STAGE_A, "pending");
        db.advance_attempt(attempt_id, "running").unwrap();
        db.complete_attempt(attempt_id, &serde_json::json!({"ok": true}))
            .unwrap();
        assert_coherent(&db, execution_id);
        (
            execution_id,
            db.debug_reserved_seq().unwrap(),
            db.debug_count("transitions").unwrap(),
            db.attempt_projections(execution_id).unwrap(),
        )
    };
    assert!(
        chain_before > 0 && !rows_before.is_empty(),
        "non-vacuity: an unchanged NOTHING would satisfy every assertion below"
    );

    let db = OperationalDb::open(&path).unwrap();
    assert_eq!(
        db.debug_reserved_seq().unwrap(),
        reserved_before,
        "a reopen reserves no sequence: there is no tail to fold"
    );
    assert_eq!(db.debug_count("transitions").unwrap(), chain_before);
    assert_eq!(db.attempt_projections(execution_id).unwrap(), rows_before);
    // No rebuild call — the projection is already current because it was written in
    // the same transaction as its authority.
    assert_coherent(&db, execution_id);
}

// -- rows and watermark persist across a reopen --------------------------

/// Operational regime: the projected rows and the global fold cursor are durable,
/// and the chain they cover is CONTIGUOUS — no hole, because the reservation lives
/// inside the transaction that uses it.
///
/// **Regime trap, avoided deliberately.** Forging one event at sequence 7 into an
/// empty log and asserting the watermark jumped 0 → 7 treats a six-wide hole as
/// legitimate. That is correct for reserve-before-commit and meaningless here: transplanting a
/// forged high sequence would import the wrong
/// regime and, on this plane, would also be unwritable — `record_transition`
/// allocates the number itself, so no caller can choose one.
#[test]
fn operational_fold_shape_rows_and_watermark_persist_across_reopen() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("operational.db");

    let (execution_id, attempt_id, completed_seq) = {
        let db = OperationalDb::open(&path).unwrap();
        let execution_id = submit(&db);
        let (attempt_id, _) = claim(&db, execution_id, STAGE_A, "pending");
        db.advance_attempt(attempt_id, "running").unwrap();
        let completed_seq = db
            .complete_attempt(attempt_id, &serde_json::json!({"ok": true}))
            .unwrap();
        assert_coherent(&db, execution_id);
        (execution_id, attempt_id, completed_seq)
    };

    let db = OperationalDb::open(&path).unwrap();
    assert_eq!(
        db.attempt_projection_for(attempt_id).unwrap().unwrap(),
        row(STAGE_A, 0, "completed", completed_seq),
        "the same row, at the same state, pointing at the same authorizing transition"
    );
    // `verify_global_watermark` IS the persistence claim, stated structurally:
    // applied_through_seq == transition_sequence.value == MAX(transitions.seq).
    assert_coherent(&db, execution_id);

    let chain = db.debug_transition_kinds(execution_id).unwrap();
    assert!(!chain.is_empty(), "non-vacuity: the chain must exist");
    for pair in chain.windows(2) {
        assert_eq!(
            pair[1].0,
            pair[0].0 + 1,
            "consecutive sequences differ by exactly one: an abort on this plane reverts its \
             reservation, so there is no hole to tolerate"
        );
    }
    assert_eq!(
        chain.last().unwrap().0,
        db.debug_reserved_seq().unwrap(),
        "the reservation counter re-seeds to the chain head, not past it"
    );
    assert_eq!(
        completed_seq,
        chain.last().unwrap().0,
        "the terminal fold is the chain head"
    );
}

// -- the operational plane is the ONLY authority file --------------------

/// Operational regime: a full attempt lifecycle creates exactly one authority file
/// — `operational.db` — and its projection reads the terminal state LIVE, before
/// any reopen and before any rebuild.
///
/// This is the strongest anti-regression on the surface, and the `!path.exists()`
/// idiom is why: it catches a sibling plane created behind everyone's back. It
/// asserts "no file in the data directory that is not `operational.db` or one of
/// its own WAL sidecars", so a NEW sibling authority also trips it.
#[test]
fn operational_fold_shape_operational_db_is_the_only_authority_file() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("operational.db");
    let legacy_mirror = dir.path().join("ledger.db");
    let legacy_events = dir.path().join("ledger_events.db");

    let db = OperationalDb::open(&path).unwrap();
    let execution_id = submit(&db);
    let (attempt_id, _) = claim(&db, execution_id, STAGE_A, "pending");
    db.advance_attempt(attempt_id, "running").unwrap();
    let completed_seq = db
        .complete_attempt(attempt_id, &serde_json::json!({"ok": true}))
        .unwrap();

    // (b) LIVE, on the still-open handle: no reopen, no rebuild.
    assert_eq!(
        db.attempt_projections(execution_id).unwrap(),
        vec![row(STAGE_A, 0, "completed", completed_seq)],
        "the projection is current the moment the run finishes — it was written in the same \
         transaction as its authority"
    );
    // (c)
    assert_coherent(&db, execution_id);

    // (a)
    assert!(path.exists(), "non-vacuity: the authority file must exist");
    assert!(
        !legacy_mirror.exists(),
        "the single-plane collapse must NOT create a ledger.db authority"
    );
    assert!(
        !legacy_events.exists(),
        "the single-plane collapse must NOT create a ledger_events.db authority"
    );
    for entry in std::fs::read_dir(dir.path()).unwrap() {
        let name = entry.unwrap().file_name();
        let name = name.to_string_lossy().into_owned();
        assert!(
            name.starts_with("operational.db"),
            "an operational lifecycle must create no file other than the authority and its own \
             WAL sidecars, found {name}"
        );
    }
}

// -- per-execution isolation ---------------------------------------------

/// Operational regime: two executions interleave in ONE `transitions` table, and
/// every projection read is scoped by `execution_id` with last-wins applied within
/// the scope.
///
/// **Declared narrowing.** There is no GLOBAL attempt count here: a global
/// attempt read is not a capability this plane should acquire, and the leak
/// direction it guarded is structurally closed — every reader takes an
/// `execution_id` and there is no global attempt read to leak through.
///
/// **Non-vacuity is preserved in the other direction**, which is the part that
/// matters: without it, isolation would pass because the rows simply are not there.
/// The global `debug_count("transitions")` is asserted to cover BOTH executions.
#[test]
fn operational_fold_shape_attempt_projections_isolate_one_execution() {
    let db = OperationalDb::open_in_memory().unwrap();
    let exec_a = submit(&db);
    let exec_b = submit(&db);

    // Interleaved, with a last-wins advance for a's first attempt.
    let (a1, _) = claim(&db, exec_a, STAGE_A, "pending");
    let (_b1, b1_claim_seq) = claim(&db, exec_b, STAGE_A, "pending");
    let a1_completed_seq = db
        .complete_attempt(a1, &serde_json::json!({"ok": true}))
        .unwrap();
    let (_a2, a2_claim_seq) = claim(&db, exec_a, STAGE_B, "pending");

    assert_eq!(
        db.attempt_projections(exec_a).unwrap(),
        vec![
            row(STAGE_A, 0, "completed", a1_completed_seq),
            row(STAGE_B, 0, "pending", a2_claim_seq),
        ],
        "exec_a sees exactly its own two attempts, a1 at its LAST state"
    );
    assert_eq!(
        db.attempt_projections(exec_b).unwrap(),
        vec![row(STAGE_A, 0, "pending", b1_claim_seq)],
        "exec_b sees only its own attempt, even though it shares a stage id with exec_a"
    );
    assert!(
        db.attempt_projections(Ulid::new()).unwrap().is_empty(),
        "an execution with no rows reads empty rather than borrowing another's"
    );

    // NON-VACUITY: the shared table really does hold both executions' chains, so
    // the isolation above is a filter doing work rather than an empty table.
    let a_chain = db.debug_count_for_execution("transitions", exec_a).unwrap();
    let b_chain = db.debug_count_for_execution("transitions", exec_b).unwrap();
    assert!(a_chain > 0 && b_chain > 0);
    assert_eq!(
        db.debug_count("transitions").unwrap(),
        a_chain + b_chain,
        "one chain table covers both executions — nothing is partitioned by file"
    );

    assert_coherent(&db, exec_a);
    assert_coherent(&db, exec_b);
}

// -- the attempt-scope terminal latch, the part not already covered ------

/// Operational regime: a refusal costs ZERO sequence, so the rebuild that follows
/// it is byte-identical to the projection that preceded it — the refused
/// transition left nothing in the chain for a pure fold to adopt.
///
/// # What this does NOT re-assert
///
/// `operational_attempt_latch.rs` already covers the latch's typed refusal, its
/// zero-sequence cost through `accept_incoming_event`, every terminal state, the
/// ambiguous carve-out, the record-only admission, the new-generation carve-out,
/// and that the rebuild stays a pure fold of a CORRUPTED projection. The delta
/// asserted here is the composition of the two halves the plan named together:
/// the MAIN-side writer (`advance_attempt`, not the inbox seam), the zero-cost
/// clause measured on the GLOBAL `debug_count("transitions")` rather than the
/// per-execution one, and the REBUILD taken directly across a refusal.
#[test]
fn operational_fold_shape_terminal_latch_refusal_leaves_the_rebuild_identical() {
    let db = OperationalDb::open_in_memory().unwrap();
    let execution_id = submit(&db);
    let (attempt_id, _) = claim(&db, execution_id, STAGE_A, "pending");
    db.advance_attempt(attempt_id, "running").unwrap();
    db.complete_attempt(attempt_id, &serde_json::json!({"ok": true}))
        .unwrap();

    let projected_before = db.attempt_projection_for(attempt_id).unwrap().unwrap();
    assert!(
        TERMINALS.contains(&projected_before.state.as_str()),
        "non-vacuity: the latch means nothing unless the attempt really is terminal"
    );
    let reserved_before = db.debug_reserved_seq().unwrap();
    let chain_before = db.debug_count("transitions").unwrap();

    let error = db
        .advance_attempt(attempt_id, "running")
        .expect_err("an advancing transition against a terminal attempt must refuse");
    assert!(matches!(error, KataError::Validation(_)), "{error:?}");

    assert_eq!(
        db.debug_reserved_seq().unwrap(),
        reserved_before,
        "the refusal is raised BEFORE the reservation, so it burns no sequence — on the ledger's \
         regime the same refusal would have left a permanent hole"
    );
    assert_eq!(
        db.debug_count("transitions").unwrap(),
        chain_before,
        "and appends no row, globally"
    );

    // The rebuild half, taken across the refusal: a PURE fold of the chain still
    // produces the terminal state, because the refused advance never reached it.
    db.rebuild_projection(execution_id).unwrap();
    assert_eq!(
        db.attempt_projection_for(attempt_id).unwrap().unwrap(),
        projected_before,
        "state AND source seq — a rebuild that had adopted the refused advance would silently \
         un-terminalize a finished attempt, and would then AGREE with the stored projection, \
         leaving the integrity check blind"
    );
    let advances = db
        .debug_transition_kinds(execution_id)
        .unwrap()
        .into_iter()
        .filter(|(_, kind)| kind == "attempt_advanced")
        .count();
    assert_eq!(
        advances, 2,
        "exactly the two advances that were ACCEPTED are on the chain; the refused third is not"
    );
    assert_coherent(&db, execution_id);
}

// -- replay == live state, both terminal paths --------------------

/// Operational regime: on a FILE-BACKED `operational.db`, a rebuild from the
/// retained chain reproduces the live projection exactly — "replay(record) == live
/// state" on one plane, completed path.
///
/// **Inertia hazard, avoided deliberately.** A test against
/// `InFlightLedger::in_memory()`, a RAM primitive, would keep passing while proving
/// nothing about the live durability plane — a green test that reads as proof. This
/// one is written against the durable authority for exactly that reason.
///
/// The dispatch path is driven through [`OperationalDb::dispatch_attempt`], which
/// writes TWO transitions (the claim, then the dispatch); that is asserted by
/// ORDERING and by which projections moved, never by a transition count.
#[test]
fn operational_fold_shape_replay_equals_live_state_on_the_completed_path() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("operational.db");
    let db = OperationalDb::open(&path).unwrap();
    let execution_id = submit(&db);
    let attempt_id = Ulid::new();

    let dispatch_seq = db
        .dispatch_attempt(
            execution_id,
            attempt_id,
            Ulid::new(),
            &AttemptClaimSpec {
                stage_id: STAGE_A.to_string(),
                initial_state: "pending".to_string(),
                assignment_json: b"{\"capsule\":{\"stage_name\":\"draft\"}}".to_vec(),
                run_ordinal: 0,
                worker_id: Some("w-1".to_string()),
                occurrence: OccurrenceBinding::for_test(execution_id, STAGE_A),
            },
            &CommandSpec {
                command_json: b"{\"cmd\":1}".to_vec(),
            },
        )
        .unwrap();
    db.advance_attempt(attempt_id, "running").unwrap();
    let completed_seq = db
        .complete_attempt(attempt_id, &serde_json::json!({"ok": true}))
        .unwrap();

    assert!(
        dispatch_seq < completed_seq,
        "the completion folds after the dispatch it completes"
    );

    let live_attempts = db.attempt_projections(execution_id).unwrap();
    let live_execution = db.execution_projection(execution_id).unwrap();

    assert_eq!(
        live_attempts,
        vec![row(STAGE_A, 0, "completed", completed_seq)]
    );
    // Explicit terminal-state assertion: without it this passes on a chain that
    // never reached a terminal at all.
    assert!(
        TERMINALS.contains(&live_attempts[0].state.as_str()),
        "the run must have reached an absorbing attempt state, got {}",
        live_attempts[0].state
    );
    // REPLAY == LIVE: rebuild every scope from the chain and compare.
    db.rebuild_projection(execution_id).unwrap();
    assert_eq!(db.attempt_projections(execution_id).unwrap(), live_attempts);
    assert_eq!(
        db.execution_projection(execution_id).unwrap(),
        live_execution
    );
    assert_coherent(&db, execution_id);
}

/// Operational regime: the MAIN-SIDE failed path folds a terminal `failed` and
/// replays to it, and — decisively — never enters the inbox.
///
/// The design splits failure in two. A worker-REPORTED terminal
/// frame arrives through the inbox fold (`adjudicate_worker_failure`), which
/// dedupes it against the inbox before folding, and that path is covered by
/// `operational_inbox_composition.rs`; it is not duplicated here. A MAIN-side decision —
/// a stall sweep declaring an attempt orphaned, a deadline sweep failing one — has
/// no incoming frame to dedupe and must not synthesize one. Collapsing the two back
/// together would either give the inbox a second acceptance writer or make every
/// sweep decision look like a worker observation in the audit chain, so "the inbox
/// is untouched" is asserted rather than assumed.
#[test]
fn operational_fold_shape_replay_equals_live_state_on_the_main_side_failed_path() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("operational.db");
    let db = OperationalDb::open(&path).unwrap();
    let execution_id = submit(&db);
    let (attempt_id, _) = claim(&db, execution_id, STAGE_A, "pending");

    let inbox_before = db.debug_count("event_inbox").unwrap();
    let watermark_before = db.debug_count("event_inbox_watermark").unwrap();

    db.advance_attempt(attempt_id, "running").unwrap();
    let failed_seq = db.advance_attempt(attempt_id, "failed").unwrap();

    let live_attempts = db.attempt_projections(execution_id).unwrap();
    assert_eq!(live_attempts, vec![row(STAGE_A, 0, "failed", failed_seq)]);
    assert!(
        TERMINALS.contains(&live_attempts[0].state.as_str()),
        "the failed path must reach an absorbing attempt state"
    );

    assert_eq!(
        db.debug_count("event_inbox").unwrap(),
        inbox_before,
        "a main-side sweep failure must NOT enter the inbox"
    );
    assert_eq!(
        db.debug_count("event_inbox_watermark").unwrap(),
        watermark_before,
        "…and must not advance an acceptance watermark for a frame that never arrived"
    );
    assert_eq!(
        inbox_before, 0,
        "non-vacuity: unchanged-from-nonzero would also pass the two assertions above"
    );

    db.rebuild_projection(execution_id).unwrap();
    assert_eq!(db.attempt_projections(execution_id).unwrap(), live_attempts);
    assert_coherent(&db, execution_id);
}

// -- the durable persist-and-reload replay invariant --------------------

/// Operational regime: the replay invariant survives a durable persist and a cold
/// reload, and the chain it replays is NOT empty.
///
/// Clause (a) — a non-zero chain for THIS execution after the reopen — is the whole value
/// of the test: a fold over nothing agrees with a projection of nothing, so every other
/// assertion here passes vacuously without it. Any re-expression that omits it is strictly
/// weaker than what exists today.
#[test]
fn operational_fold_shape_replay_invariant_survives_durable_persist_and_reload() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("operational.db");

    let (execution_id, attempt_id, completed_seq) = {
        let db = OperationalDb::open(&path).unwrap();
        let execution_id = submit(&db);
        let (attempt_id, _) = claim(&db, execution_id, STAGE_A, "pending");
        db.advance_attempt(attempt_id, "running").unwrap();
        let completed_seq = db
            .complete_attempt(attempt_id, &serde_json::json!({"ok": true}))
            .unwrap();
        (execution_id, attempt_id, completed_seq)
    };

    // Cold reopen — what a fresh process sees on restart.
    let db = OperationalDb::open(&path).unwrap();

    // (a) THE NON-VACUITY GUARD.
    assert!(
        db.debug_count_for_execution("transitions", execution_id)
            .unwrap()
            > 0,
        "the retained chain must survive the reload, else the replay below is vacuous"
    );
    assert!(
        db.debug_count_for_execution("attempts", execution_id)
            .unwrap()
            > 0,
        "…and so must the attempt row the chain attributes its transitions to"
    );

    // (b) the projection agrees with a fresh rebuild from that chain.
    assert_coherent(&db, execution_id);

    // (c) the projected state is the terminal one the run reached.
    assert_eq!(
        db.attempt_projection_for(attempt_id).unwrap().unwrap(),
        row(STAGE_A, 0, "completed", completed_seq)
    );
}
