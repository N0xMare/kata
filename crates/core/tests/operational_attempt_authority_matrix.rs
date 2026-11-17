//! The generated attempt-lifecycle CHECK, proven against an independent
//! authority: the wire type that produces every advancing attempt state.

use kata_core::operational::AttemptLifecycle;
use kata_core::{InvocationKind, InvocationRecord, OperationalDb, ProgramRecord, SubmitOutcome};
use kata_types::idempotency::canonicalize_args;
use kata_types::identity_algebra::AdmissionDigest;
use kata_types::primitives::ContentHash;
use ulid::Ulid;

const STAGE: &str = "only";

fn program() -> ProgramRecord {
    ProgramRecord {
        program_hash: ContentHash::new([1u8; 32]),
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

// -- The vocabulary is GENERATED, proven behaviorally -------------------------

/// The `attempt_projection.state` CHECK admits every spelling PRODUCTION WRITES and
/// refuses everything else, proven by writing against a real database.
///
/// # Why the positive half is driven from the WIRE type and not from `ALL`
///
/// Asserting that the CHECK admits `AttemptLifecycle::ALL` is a TAUTOLOGY: the
/// CHECK is generated from `ALL`, so the two agree by construction and the
/// assertion is satisfiable by observing nothing: renaming `Stalled`'s spelling
/// (to `stalled_TYPO`, say) would leave it GREEN, because the typo reaches the
/// CHECK too. `attempt_lifecycle_writers_match_the_wire_status_tags`, which
/// compares against `AssignmentStatus::tag()`, is what catches that drift.
///
/// The type-to-CHECK relation is therefore STRUCTURAL and needs no test. What needs
/// one is the relation to an INDEPENDENT authority, so the positive half here
/// inserts the wire tags: a database whose CHECK refused a spelling production
/// writes is the failure that matters, and only a second source can see it.
///
/// The negative half stays: a near-miss must be REFUSED, or the slot failed open
/// and the CHECK is enforcing nothing at all.
#[test]
fn the_generated_check_admits_every_production_spelling_and_refuses_the_rest() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("operational.db");
    let db = OperationalDb::open(&path).unwrap();
    let execution_id = Ulid::new();
    let seq = match db
        .submit_execution(execution_id, &program(), &invocation())
        .unwrap()
    {
        SubmitOutcome::Submitted { seq } => seq,
        other @ SubmitOutcome::AlreadySubmitted => {
            panic!("expected a fresh submit, got {other:?}")
        }
    };
    // A RAW connection, deliberately: this is the SCHEMA's guard, not the typed
    // API's, and routing through a mutator would prove the mutator refuses rather
    // than that the CHECK is in force.
    let conn = rusqlite::Connection::open(&path).unwrap();
    conn.pragma_update(None, "foreign_keys", "ON").unwrap();
    let insert = |ordinal: i64, state: &str| {
        conn.execute(
            "INSERT INTO attempt_projection
                 (execution_id, stage_id, attempt_ordinal, state, source_seq, updated_at_ms)
             VALUES (?1, ?2, ?3, ?4, ?5, 0)",
            rusqlite::params![execution_id.to_bytes().as_ref(), STAGE, ordinal, state, seq],
        )
    };

    // The INDEPENDENT authority: every spelling an advancing attempt-scope
    // transition can carry is an `AssignmentStatus::tag()`.
    for (ordinal, tag) in wire_status_tags().into_iter().enumerate() {
        insert(i64::try_from(ordinal).unwrap(), tag).unwrap_or_else(|error| {
            panic!("the generated CHECK must admit the wire tag {tag}: {error}")
        });
    }

    // COUNTERFACTUAL, seen to trip: spellings the type does NOT declare — four
    // retired effect-claim transition kinds, two near-miss spellings, and four
    // retired states no writer produced.
    for outside in [
        "effect_issued",
        "effect_ambiguous",
        "effect_failed",
        "outcome_recorded",
        "prepared",
        "claimed",
        "resumed",
        "timed_out",
        "ambiguous",
        "awaiting_retry",
    ] {
        let refusal = insert(99, outside).expect_err(
            "a spelling outside the typed vocabulary must be refused by the CHECK, or \
             the generated slot failed open",
        );
        assert!(
            refusal.to_string().to_lowercase().contains("constraint"),
            "the refusal must come from the CHECK: {refusal}"
        );
    }
}

/// The ten states a worker path writes are EXACTLY the
/// `AssignmentStatus::tag()` arms, and the two others are exactly the
/// main-resolved waits `OperationalDb::claim_main_attempt` writes.
///
/// Derived from the wire type rather than restated: `tag()` is the only producer
/// of a worker attempt's advancing `resulting_state`, so a vocabulary member it
/// cannot emit and that is not a main-resolved wait would be a state nothing
/// writes, and a tag missing from the vocabulary would be refused by the CHECK.
#[test]
fn attempt_lifecycle_writers_match_the_wire_status_tags() {
    let tags = wire_status_tags();
    for tag in &tags {
        let state = AttemptLifecycle::from_state(tag)
            .unwrap_or_else(|| panic!("the wire tag {tag} must be in the typed vocabulary"));
        assert!(
            !state.is_main_resolved_wait(),
            "{tag} has a wire status, so it must not be a main-resolved wait"
        );
    }
    let with_writers: Vec<&str> = AttemptLifecycle::ALL
        .iter()
        .filter(|state| !state.is_main_resolved_wait())
        .map(|state| state.as_str())
        .collect();
    assert_eq!(
        with_writers.len(),
        tags.len(),
        "the writer-bearing set and the wire-tag set must be the same size; \
         writers {with_writers:?} vs tags {tags:?}"
    );
    for tag in &tags {
        assert!(with_writers.contains(tag), "{tag} missing from the writers");
    }
}

/// EVERY spelling an advancing attempt-scope transition can carry, derived from
/// the wire type that produces them.
///
/// This is the INDEPENDENT authority the two tests above check the vocabulary
/// against. `AssignmentStatus::tag()` is the only producer of an advancing
/// attempt-scope `resulting_state`, so a state it can emit that the type calls
/// writer-less would be a lie in one direction, and a state it cannot emit that
/// the type calls live would be a named recourse nobody can invoke in the other.
///
/// The list is kept honest by the EXHAUSTIVE match at the bottom rather than by
/// inspection: a variant added to `AssignmentStatus` makes that match fail to
/// COMPILE, so this file cannot silently fall behind the type it derives from.
fn wire_status_tags() -> Vec<&'static str> {
    use kata_types::ledger::AssignmentStatus as S;
    use smol_str::SmolStr;

    let worker = || SmolStr::new("w");
    let reason = || "r".to_string();
    let statuses = vec![
        S::Pending,
        S::AwaitingApproval {
            worker_id: None,
            reason: reason(),
        },
        S::AwaitingChildCompletion {
            child_execution_id: Ulid::new(),
            reason: reason(),
        },
        S::Dispatched {
            worker_id: worker(),
        },
        S::Running {
            worker_id: worker(),
        },
        S::Completed {
            worker_id: Some(worker()),
        },
        S::Failed {
            worker_id: None,
            reason: reason(),
        },
        S::Cancelled {
            worker_id: None,
            reason: reason(),
        },
        S::Orphaned {
            prev_worker: None,
            reason: reason(),
        },
        S::Stalled {
            worker_id: worker(),
            last_heartbeat_at_ms: 0,
            stalled_for_secs: 0,
        },
    ];

    // THE COMPLETENESS PROOF, enforced by the compiler. Each variant is named
    // once; adding one to the wire type breaks this match, which is what forces
    // the list above to grow with it.
    let mut named = 0usize;
    for status in &statuses {
        named += 1;
        match status {
            S::Pending
            | S::AwaitingApproval { .. }
            | S::AwaitingChildCompletion { .. }
            | S::Dispatched { .. }
            | S::Running { .. }
            | S::Completed { .. }
            | S::Failed { .. }
            | S::Cancelled { .. }
            | S::Orphaned { .. }
            | S::Stalled { .. } => {}
        }
    }
    assert_eq!(named, statuses.len());

    statuses.iter().map(S::tag).collect()
}
