//! The operational substrate: schema forward-refuse (rollback-journal, WAL, and
//! HOT-WAL fixtures), the stamped CHECK/FK/index guards, the typed transaction
//! surface (happy path + converge-or-refuse + atomicity crash matrix +
//! no-hole-on-failure), and the projection rebuild/integrity check.

use std::path::{Path, PathBuf};

use kata_core::operational::AttemptClaimSpec;
use kata_core::operational::OccurrenceBinding;
use kata_core::operational::projection::{AttemptProjectionRow, ExecutionProjectionRow};
use kata_core::{
    CasRootOwner, CasRootSpec, ClaimOutcome, CommandSpec, EventAcceptance, FireOutcome,
    InstallOutcome, InvocationKind, InvocationRecord, LifecycleState, MissedFirePolicy,
    OPERATIONAL_INDEXES, OPERATIONAL_SCHEMA_VERSION, OPERATIONAL_TABLE_COLUMNS, OPERATIONAL_TABLES,
    OperationalDb, ProgramRecord, RebindOutcome, ScheduleInstall, SubmitOutcome,
};
use kata_types::error::KataError;
use kata_types::identity_algebra::AdmissionDigest;
use kata_types::primitives::ContentHash;
use rusqlite::params;
use ulid::Ulid;

#[test]
fn stale_park_release_cannot_place_a_new_park_or_generation() {
    for advance_generation in [false, true] {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("operational.db");
        let db = OperationalDb::open(&path).unwrap();
        let domain = db
            .enroll_worker_domain(
                "release-main",
                kata_types::identity::WorkerMembraneId(Ulid::new()),
            )
            .unwrap();
        let execution = Ulid::new();
        submit(&db, execution, 25);
        let attempt = claim(&db, execution);
        // A REQUEUE to `pending`: an approval park of a capsule attempt has exactly
        // one way out, `decide_capsule_approval`, which refuses a release with no
        // recorded decision before any placement expectation is read — so the
        // expectation fence under test is reached through a requeue, which a release
        // really does leave.
        let park = kata_core::operational::MainSideTransition::bare("pending");
        db.record_main_side_transition(attempt, &park).unwrap();
        let expected = db
            .recovered_attempt(attempt)
            .unwrap()
            .unwrap()
            .placement_expectation()
            .unwrap();
        if advance_generation {
            db.advance_attempt_generation(attempt, 1).unwrap();
        }
        // The same state and reason are deliberately insufficient to distinguish
        // this new decision from the release's source lifecycle edge.
        db.record_main_side_transition(attempt, &park).unwrap();
        let before = db.recovered_attempt(attempt).unwrap().unwrap();
        let rejected_command = Ulid::new();
        assert_eq!(
            db.dispatch_claimed_attempt_in_domain(
                attempt,
                "w-1",
                rejected_command,
                &CommandSpec {
                    command_json: b"{}".to_vec()
                },
                &domain,
                &expected
            )
            .unwrap(),
            None
        );
        assert_eq!(db.recovered_attempt(attempt).unwrap().unwrap(), before);
        let raw = raw_conn(&path);
        let commands: i64 = raw
            .query_row(
                "SELECT count(*) FROM attempt_commands WHERE command_id = ?1",
                [rejected_command.to_bytes().as_slice()],
                |row| row.get(0),
            )
            .unwrap();
        let bindings: i64 = raw
            .query_row(
                "SELECT count(*) FROM worker_dispatch_domains WHERE attempt_id = ?1",
                [attempt.to_bytes().as_slice()],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!((commands, bindings), (0, 0));
    }
}

#[test]
fn stale_release_cannot_converge_on_a_newer_placement() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("operational.db");
    let db = OperationalDb::open(&path).unwrap();
    let domain = db
        .enroll_worker_domain(
            "release-main",
            kata_types::identity::WorkerMembraneId(Ulid::new()),
        )
        .unwrap();
    let execution = Ulid::new();
    submit(&db, execution, 27);
    let attempt = claim(&db, execution);
    let expected = db
        .recovered_attempt(attempt)
        .unwrap()
        .unwrap()
        .placement_expectation()
        .unwrap();
    let command = CommandSpec {
        command_json: b"{}".to_vec(),
    };
    assert!(matches!(
        db.dispatch_claimed_attempt_in_domain(
            attempt,
            "w-1",
            Ulid::new(),
            &command,
            &domain,
            &expected
        )
        .unwrap(),
        Some(ClaimOutcome::Recorded { .. })
    ));
    let before = db.recovered_attempt(attempt).unwrap().unwrap();
    assert_eq!(
        db.dispatch_claimed_attempt_in_domain(
            attempt,
            "w-1",
            Ulid::new(),
            &command,
            &domain,
            &expected
        )
        .unwrap(),
        None
    );
    let current = before.placement_expectation().unwrap();
    assert_eq!(
        db.dispatch_claimed_attempt_in_domain(
            attempt,
            "w-1",
            Ulid::new(),
            &command,
            &domain,
            &current
        )
        .unwrap(),
        Some(ClaimOutcome::AlreadyRecorded)
    );
    assert_eq!(db.recovered_attempt(attempt).unwrap().unwrap(), before);
    let count: i64 = raw_conn(&path)
        .query_row(
            "SELECT count(*) FROM attempt_commands WHERE attempt_id = ?1",
            [attempt.to_bytes().as_slice()],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(count, 1);
}

#[test]
fn recovery_worker_census_retains_empty_domains() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("operational.db");
    let db = OperationalDb::open(&path).unwrap();
    let active = db
        .enroll_worker_domain(
            "source",
            kata_types::identity::WorkerMembraneId(Ulid::new()),
        )
        .unwrap();
    let empty = db
        .enroll_worker_domain(
            "source",
            kata_types::identity::WorkerMembraneId(Ulid::new()),
        )
        .unwrap();
    let execution = Ulid::new();
    submit(&db, execution, 23);
    let attempt = claim(&db, execution);
    db.dispatch_claimed_attempt_in_domain(
        attempt,
        "worker",
        Ulid::new(),
        &CommandSpec {
            command_json: b"{}".to_vec(),
        },
        &active,
        &db.recovered_attempt(attempt)
            .unwrap()
            .unwrap()
            .placement_expectation()
            .unwrap(),
    )
    .unwrap();
    let raw = raw_conn(&path);
    let census = db.worker_recovery_domains().unwrap();
    assert_eq!(
        census.len(),
        2,
        "an enrollment without main claims still needs a worker inventory"
    );
    assert!(census.contains(&active));
    assert!(census.contains(&empty));
    let plan: String = raw.query_row("EXPLAIN QUERY PLAN SELECT attempt_id FROM worker_dispatch_domains WHERE enrollment_id=?1", [active.enrollment.to_bytes().as_slice()], |row| row.get(3)).unwrap();
    assert!(
        plan.contains("idx_worker_dispatch_domain_attempt"),
        "{plan}"
    );
    drop(raw);
    drop(db);
    assert_eq!(
        OperationalDb::open(path)
            .unwrap()
            .worker_recovery_domains()
            .unwrap(),
        census
    );
}

#[test]
fn worker_domain_binding_commits_with_placement_and_survives_replacement_and_reopen() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("operational.db");
    let db = OperationalDb::open(&path).unwrap();
    let membrane = kata_types::identity::WorkerMembraneId(Ulid::new());
    let first = db.enroll_worker_domain("source-main", membrane).unwrap();
    assert_eq!(
        db.enroll_worker_domain("source-main", membrane).unwrap(),
        first
    );
    let replacement = db
        .enroll_worker_domain(
            "source-main",
            kata_types::identity::WorkerMembraneId(Ulid::new()),
        )
        .unwrap();
    assert_ne!(replacement.enrollment, first.enrollment);
    let execution = Ulid::new();
    submit(&db, execution, 23);
    let attempt = claim(&db, execution);
    let command = CommandSpec {
        command_json: b"{}".to_vec(),
    };
    db.dispatch_claimed_attempt_in_domain(
        attempt,
        "w-1",
        Ulid::new(),
        &command,
        &first,
        &db.recovered_attempt(attempt)
            .unwrap()
            .unwrap()
            .placement_expectation()
            .unwrap(),
    )
    .unwrap();
    let epoch = db.attempt(attempt).unwrap().unwrap().lease_epoch;
    let raw = raw_conn(&path);
    let binding: (Vec<u8>, i64) = raw.query_row(
        "SELECT d.enrollment_id, a.lease_epoch FROM worker_dispatch_domains d JOIN attempts a ON a.attempt_id = d.attempt_id AND a.lease_epoch = d.lease_epoch WHERE a.attempt_id = ?1",
        [attempt.to_bytes().as_slice()], |row| Ok((row.get(0)?, row.get(1)?))).unwrap();
    assert_eq!(binding, (first.enrollment.to_bytes().to_vec(), epoch));
    assert!(
        db.dispatch_claimed_attempt_in_domain(
            attempt,
            "w-1",
            Ulid::new(),
            &command,
            &replacement,
            &db.recovered_attempt(attempt)
                .unwrap()
                .unwrap()
                .placement_expectation()
                .unwrap()
        )
        .is_err()
    );
    assert_eq!(
        db.worker_dispatch_domain(attempt, epoch).unwrap(),
        Some(first.clone())
    );
    drop(raw);
    drop(db);
    let reopened = OperationalDb::open(&path).unwrap();
    assert_eq!(reopened.worker_effect_domains().unwrap().len(), 2);
    assert_eq!(
        reopened.worker_dispatch_domain(attempt, epoch).unwrap(),
        Some(first)
    );
}

#[test]
fn unregistered_worker_domain_rolls_back_placement_and_command() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("operational.db");
    let db = OperationalDb::open(&path).unwrap();
    let execution = Ulid::new();
    submit(&db, execution, 24);
    let attempt = claim(&db, execution);
    let before = db.attempt(attempt).unwrap().unwrap();
    let rejected_command = Ulid::new();
    let domain = kata_types::identity::WorkerEffectDomain {
        source_main: "unregistered".into(),
        membrane: kata_types::identity::WorkerMembraneId(Ulid::new()),
        enrollment: Ulid::new(),
    };
    assert!(
        db.dispatch_claimed_attempt_in_domain(
            attempt,
            "w-1",
            rejected_command,
            &CommandSpec {
                command_json: b"{}".to_vec()
            },
            &domain,
            &db.recovered_attempt(attempt)
                .unwrap()
                .unwrap()
                .placement_expectation()
                .unwrap(),
        )
        .is_err()
    );
    let after = db.attempt(attempt).unwrap().unwrap();
    assert_eq!(after.lease_epoch, before.lease_epoch);
    assert_eq!(after.source_seq, before.source_seq);
    let raw = raw_conn(&path);
    let command_count: i64 = raw
        .query_row(
            "SELECT count(*) FROM attempt_commands WHERE attempt_id = ?1 OR command_id = ?2",
            params![
                attempt.to_bytes().as_slice(),
                rejected_command.to_bytes().as_slice()
            ],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(command_count, 0, "refused placement must leave no command");
    assert_eq!(
        db.worker_dispatch_domain(attempt, before.lease_epoch + 1)
            .unwrap(),
        None
    );
}

#[test]
fn worker_domain_schema_refuses_lost_foreign_keys_or_enrollment_uniqueness() {
    for remove_foreign_keys in [false, true] {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("operational.db");
        drop(OperationalDb::open(&path).unwrap());
        let raw = raw_conn(&path);
        if remove_foreign_keys {
            raw.execute_batch(
                "DROP TABLE worker_dispatch_domains;
                CREATE TABLE worker_dispatch_domains (
                    attempt_id BLOB NOT NULL,
                    lease_epoch INTEGER NOT NULL,
                    enrollment_id BLOB NOT NULL,
                    worker_label TEXT NOT NULL,
                    PRIMARY KEY(attempt_id, lease_epoch)
                );",
            )
            .unwrap();
        } else {
            raw.execute_batch("DROP INDEX idx_worker_effect_domain_enrollment;
                CREATE INDEX idx_worker_effect_domain_enrollment ON worker_effect_domains(enrollment_id);").unwrap();
        }
        drop(raw);
        assert!(
            OperationalDb::open(&path).is_err(),
            "changed worker domain authority constraints must refuse"
        );
    }
}

#[test]
fn worker_domain_census_refuses_over_limit_instead_of_truncating() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("operational.db");
    let db = OperationalDb::open(&path).unwrap();
    let raw = raw_conn(&path);
    raw.execute_batch("WITH RECURSIVE instances(n) AS (SELECT 1 UNION ALL SELECT n + 1 FROM instances WHERE n < 4097)
        INSERT INTO worker_effect_domains(source_main, membrane_id, enrollment_id)
        SELECT 'test-main', CAST(printf('%016d', n) AS BLOB), CAST(printf('%016d', n) AS BLOB) FROM instances;").unwrap();
    assert!(
        db.worker_effect_domains()
            .unwrap_err()
            .to_string()
            .contains("4096")
    );
    let count: i64 = raw
        .query_row("SELECT count(*) FROM worker_effect_domains", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(
        count, 4097,
        "a refused capture does not retire any enrollment"
    );
}

/// A COHERENT program fixture: the opaque `program_json` carries the same
/// `program_hash` and `schema_version` header the record declares.
///
/// A fixture whose payload disagreed with its own header — say a pinned
/// `bound_program_hash = [7; 32]` beside a `{"program":1}` payload — would be an
/// internally incoherent row. The schedule pin is load-bearing, so the fixture has
/// to be able to survive being read.
fn program(seed: u8) -> ProgramRecord {
    let program_hash = ContentHash::new([seed; 32]);
    ProgramRecord {
        program_hash,
        schema_version: 4,
        program_json: kata_types::idempotency::canonicalize_args(&serde_json::json!({
            "schema_version": 4,
            "program_hash": program_hash.to_string(),
            "program": seed,
        })),
    }
}

/// A COHERENT invocation fixture: the admission digest is `blake3` over the
/// canonical bytes it binds, exactly as
/// `kata_workflow::admission::validated_invocation_bytes` derives it, and the
/// bytes carry the `schema_version` / `kind` header an envelope really has.
fn invocation(seed: u8) -> InvocationRecord {
    let invocation_json = kata_types::idempotency::canonicalize_args(&serde_json::json!({
        "schema_version": 1,
        "kind": "workflow",
        "inputs": [seed],
    }));
    InvocationRecord {
        schema_version: 1,
        kind: InvocationKind::Workflow,
        admission_digest: AdmissionDigest(ContentHash::new(
            *blake3::hash(&invocation_json).as_bytes(),
        )),
        invocation_json,
    }
}

/// A `DurableObject` receipt for a synthetic digest — `CasRootSpec::for_object`
/// demands proof the bytes are durable, and these fixtures stand up no `CasStore`.
fn receipt(seed: u8) -> kata_core::store::cas::DurableObject {
    kata_core::store::cas::DurableObject::__test_unwritten(kata_types::primitives::ObjectId::from(
        [seed; 32],
    ))
}

fn digest(seed: u8) -> ContentHash {
    ContentHash::new([seed; 32])
}

fn schedule(id: &str) -> ScheduleInstall {
    ScheduleInstall {
        schedule_id: id.to_string(),
        submit_pack: "nightly".to_string(),
        trigger: "{\"interval\":{\"every_ms\":1000}}".to_string(),
        on_missed: MissedFirePolicy::FireOnceOnBoot,
        cursor_ms: 1_000,
    }
}

/// Submit a fresh execution and return its transition sequence.
/// CLAIM one attempt on `exec` and return its identity.
///
/// An attempt-scope transition is attributed to an attempt, and its stage and
/// ordinal are RESOLVED from the row — so every fixture that folds one needs a real
/// claimed attempt rather than a caller-supplied coordinate pair.
fn claim(db: &OperationalDb, exec: Ulid) -> Ulid {
    let attempt_id = Ulid::new();
    db.claim_attempt(
        exec,
        attempt_id,
        &AttemptClaimSpec {
            stage_id: "stage-a".to_string(),
            assignment_json: br#"{"capsule":{"stage_name":"fixture"}}"#.to_vec(),
            initial_state: "pending".to_string(),
            run_ordinal: 0,
            worker_id: Some("w-1".to_string()),
            occurrence: OccurrenceBinding::for_test(exec, "stage-a"),
        },
    )
    .unwrap();
    attempt_id
}

fn submit(db: &OperationalDb, exec: Ulid, seed: u8) -> i64 {
    match db
        .submit_execution(exec, &program(seed), &invocation(seed))
        .unwrap()
    {
        SubmitOutcome::Submitted { seq } => seq,
        other @ SubmitOutcome::AlreadySubmitted => {
            panic!("expected a fresh submission, got {other:?}")
        }
    }
}

fn sidecar(path: &Path, suffix: &str) -> PathBuf {
    let mut raw = path.to_path_buf().into_os_string();
    raw.push(suffix);
    PathBuf::from(raw)
}

/// The 4-byte big-endian `user_version` in a database file's header, read by
/// plain file I/O exactly as the refusal gate does.
fn header_user_version(path: &Path) -> i64 {
    let bytes = std::fs::read(path).unwrap();
    i64::from(u32::from_be_bytes([
        bytes[60], bytes[61], bytes[62], bytes[63],
    ]))
}

/// A raw connection on an operational file: the CHECK / FOREIGN KEY guards are the
/// SCHEMA's, provable only by reaching around the typed API.
fn raw_conn(path: &Path) -> rusqlite::Connection {
    let conn = rusqlite::Connection::open(path).unwrap();
    conn.pragma_update(None, "foreign_keys", "ON").unwrap();
    conn
}

// -- schema: forward-refuse + creation --------------------------------------

#[test]
fn operational_open_creates_schema_and_stamps_current_version() {
    let db = OperationalDb::open_in_memory().unwrap();
    assert_eq!(db.debug_user_version().unwrap(), OPERATIONAL_SCHEMA_VERSION);
    // Opening validates every declared table AND index exists, so a successful
    // open is that proof; these spot-check emptiness.
    assert_eq!(db.debug_count("programs").unwrap(), 0);
    assert_eq!(db.debug_count("transitions").unwrap(), 0);
    assert_eq!(db.debug_reserved_seq().unwrap(), 0);
}

#[test]
fn operational_open_refuses_an_orphan_wal_without_creating_new_authority() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("operational.db");
    let wal = sidecar(&path, "-wal");
    let evidence = b"orphan operational WAL evidence";
    std::fs::write(&wal, evidence).unwrap();

    let error = OperationalDb::open(&path)
        .expect_err("an orphan WAL must not be interpreted as a fresh operational store");
    assert!(
        matches!(error, KataError::SchemaMigrationRequired(_)),
        "orphan crash evidence must produce an operator-actionable refusal: {error:?}"
    );
    assert!(
        !path.exists(),
        "refusal must not create a new main database"
    );
    assert_eq!(
        std::fs::read(&wal).unwrap(),
        evidence,
        "refusal must preserve the orphan WAL byte-for-byte"
    );
}

#[test]
fn operational_reopen_existing_database_is_idempotent() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("operational.db");
    {
        let db = OperationalDb::open(&path).unwrap();
        submit(&db, Ulid::new(), 1);
    }
    // Reopen: schema creation is IF NOT EXISTS, the version re-stamps, and the
    // prior row survives.
    let db = OperationalDb::open(&path).unwrap();
    assert_eq!(db.debug_user_version().unwrap(), OPERATIONAL_SCHEMA_VERSION);
    assert_eq!(db.debug_count("programs").unwrap(), 1);
}

/// A CURRENT stamp over a shape that is not the current one is a REFUSAL, not a
/// clean open followed by a write failure.
///
/// # Why this is load-bearing
///
/// The operational plane has no upgrade ladder, so this assertion is the ONLY thing
/// standing between a hand-edited or partially-restored file and adoption, because the
/// version gate can only compare a number and this compares the shape the number claims.
#[test]
fn a_current_version_database_missing_a_declared_column_is_refused_at_open() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("operational.db");
    build_transitions_missing_folds_projection(&path);
    let error = OperationalDb::open(&path)
        .expect_err("a current-stamped database with the wrong shape must be refused");
    let message = error.to_string();
    assert!(
        message.contains("transitions") && message.contains("folds_projection"),
        "the refusal must name the table AND the missing column: {message}"
    );
}

/// A current stamp plus a familiar index NAME is not sufficient authority. The
/// idempotency index's uniqueness and partial predicate are semantic: weakening
/// either admits duplicate external inputs while every table/column check stays
/// green.
#[test]
fn a_current_version_database_with_a_nonunique_idempotency_index_is_refused_at_open() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("operational.db");
    drop(OperationalDb::open(&path).unwrap());

    let conn = raw_conn(&path);
    conn.execute_batch(
        "DROP INDEX idx_transitions_idempotency;
         CREATE INDEX idx_transitions_idempotency
             ON transitions (idempotency_key) WHERE idempotency_key IS NOT NULL;
         INSERT INTO programs
             (execution_id, program_hash, schema_version, program_json, created_at_ms)
         VALUES (zeroblob(16), zeroblob(32), 4, X'7B7D', 0);
         INSERT INTO transitions
             (seq, execution_id, scope, kind, resulting_state, folds_projection,
              payload_json, idempotency_key, recorded_at_ms)
         VALUES (1, zeroblob(16), 'execution', 'fixture', 'accepted', 0,
                 X'7B7D', X'01', 0),
                (2, zeroblob(16), 'execution', 'fixture', 'accepted', 0,
                 X'7B7D', X'01', 0);",
    )
    .unwrap();
    let unique: i64 = conn
        .query_row(
            "SELECT \"unique\" FROM pragma_index_list('transitions')
              WHERE name = 'idx_transitions_idempotency'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    let duplicate_count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM transitions WHERE idempotency_key = X'01'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!((unique, duplicate_count), (0, 2));
    drop(conn);

    let error = OperationalDb::open(&path)
        .expect_err("a named but non-unique idempotency index must be refused");
    let message = error.to_string();
    assert!(
        message.contains("idx_transitions_idempotency") && message.contains("unique=0"),
        "the refusal must name the weakened index contract: {message}"
    );
}

#[test]
fn a_current_version_database_with_the_wrong_idempotency_predicate_is_refused_at_open() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("operational.db");
    drop(OperationalDb::open(&path).unwrap());

    let conn = raw_conn(&path);
    conn.execute_batch(
        "DROP INDEX idx_transitions_idempotency;
         CREATE UNIQUE INDEX idx_transitions_idempotency
             ON transitions (idempotency_key) WHERE idempotency_key IS NULL;",
    )
    .unwrap();
    let partial: i64 = conn
        .query_row(
            "SELECT partial FROM pragma_index_list('transitions')
              WHERE name = 'idx_transitions_idempotency'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(
        partial, 1,
        "the forged index must still look partial by metadata"
    );
    drop(conn);

    let error = OperationalDb::open(&path)
        .expect_err("a partial index with the wrong authority predicate must be refused");
    let message = error.to_string();
    assert!(
        message.contains("idx_transitions_idempotency")
            && message.contains("idempotency_key IS NULL"),
        "the refusal must expose the forged predicate: {message}"
    );
}

#[test]
fn a_current_version_database_without_the_transition_sequence_primary_key_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("operational.db");
    drop(OperationalDb::open(&path).unwrap());

    let conn = raw_conn(&path);
    let sql: String = conn
        .query_row(
            "SELECT sql FROM sqlite_schema WHERE type = 'table' AND name = 'transitions'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    let weakened = sql.replacen(
        "seq             INTEGER NOT NULL PRIMARY KEY",
        "seq             INTEGER NOT NULL",
        1,
    );
    assert_ne!(
        weakened, sql,
        "fixture must remove the real primary-key clause"
    );
    conn.pragma_update(None, "writable_schema", "ON").unwrap();
    conn.execute(
        "UPDATE sqlite_schema SET sql = ?1 WHERE type = 'table' AND name = 'transitions'",
        [weakened],
    )
    .unwrap();
    conn.pragma_update(None, "writable_schema", "OFF").unwrap();
    drop(conn);

    let oracle = raw_conn(&path);
    let seq_contract: (String, i64, i64) = oracle
        .query_row(
            "SELECT type, \"notnull\", pk FROM pragma_table_info('transitions') WHERE name = 'seq'",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap();
    assert_eq!(seq_contract, ("INTEGER".to_string(), 1, 0));
    drop(oracle);

    OperationalDb::open(&path)
        .expect_err("the global transition sequence without its primary key must be refused");
}

#[test]
fn a_current_version_database_without_the_allocator_singleton_primary_key_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("operational.db");
    drop(OperationalDb::open(&path).unwrap());

    let conn = raw_conn(&path);
    let sql: String = conn
        .query_row(
            "SELECT sql FROM sqlite_schema WHERE type = 'table' AND name = 'transition_sequence'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    let weakened = sql.replacen(
        "id      INTEGER NOT NULL PRIMARY KEY",
        "id      INTEGER NOT NULL",
        1,
    );
    assert_ne!(
        weakened, sql,
        "fixture must remove the allocator primary key"
    );
    conn.pragma_update(None, "writable_schema", "ON").unwrap();
    conn.execute(
        "UPDATE sqlite_schema SET sql = ?1 WHERE type = 'table' AND name = 'transition_sequence'",
        [weakened],
    )
    .unwrap();
    conn.pragma_update(None, "writable_schema", "OFF").unwrap();
    drop(conn);

    let oracle = raw_conn(&path);
    let id_contract: (String, i64, i64) = oracle
        .query_row(
            "SELECT type, \"notnull\", pk FROM pragma_table_info('transition_sequence') WHERE name = 'id'",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap();
    assert_eq!(id_contract, ("INTEGER".to_string(), 1, 0));
    drop(oracle);

    OperationalDb::open(&path)
        .expect_err("the global sequence allocator without its singleton key must be refused");
}

/// The two declarations must not drift apart: `OPERATIONAL_TABLES` is what the
/// name check and `debug_count` iterate, `OPERATIONAL_TABLE_COLUMNS` is what the
/// SHAPE check iterates. A table added to one and not the other is a table whose
/// column set nobody validates.
#[test]
fn every_declared_table_declares_its_column_set() {
    let tables: Vec<&str> = OPERATIONAL_TABLE_COLUMNS
        .iter()
        .map(|(table, _)| *table)
        .collect();
    assert_eq!(
        tables, OPERATIONAL_TABLES,
        "OPERATIONAL_TABLES and OPERATIONAL_TABLE_COLUMNS must name the same tables, in order"
    );
    for (table, columns) in OPERATIONAL_TABLE_COLUMNS {
        assert!(!columns.is_empty(), "{table} declares no columns");
        let mut sorted = columns.to_vec();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(
            sorted.len(),
            columns.len(),
            "{table} declares a duplicate column"
        );
    }
}

#[test]
fn operational_forward_version_refusal_is_byte_identical() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("operational.db");

    // Build a single-file SQLite database stamped with a FUTURE version, in the
    // default rollback-journal mode (no persistent WAL sidecar).
    {
        let conn = rusqlite::Connection::open(&path).unwrap();
        conn.execute_batch("CREATE TABLE marker(x);").unwrap();
        conn.pragma_update(None, "user_version", OPERATIONAL_SCHEMA_VERSION + 1)
            .unwrap();
    }

    let before = std::fs::read(&path).unwrap();
    let sidecars: Vec<PathBuf> = ["-wal", "-shm", "-journal"]
        .iter()
        .map(|suffix| sidecar(&path, suffix))
        .collect();
    for file in &sidecars {
        assert!(!file.exists(), "precondition: no sidecar {file:?}");
    }

    let error = OperationalDb::open(&path).unwrap_err();
    assert!(
        matches!(error, KataError::SchemaMigrationRequired(_)),
        "a newer schema must be refused as SchemaMigrationRequired, got {error:?}"
    );

    // Byte-identical: not one page rewritten, not one sidecar created.
    assert_eq!(
        std::fs::read(&path).unwrap(),
        before,
        "refusal rewrote the file"
    );
    for file in &sidecars {
        assert!(
            !file.exists(),
            "refusal created sidecar {file:?} (mutation before refusal)"
        );
    }
}

/// A WAL-mode database (cleanly closed, so no sidecar is present but the
/// header declares WAL) must refuse a forward version WITHOUT the driver ever
/// opening it. Opening a WAL database materializes `-shm`, so the sidecar
/// assertions below are the empirical detector for a driver-mediated version read.
#[test]
fn operational_forward_version_refusal_on_wal_database_touches_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("operational.db");
    {
        let conn = rusqlite::Connection::open(&path).unwrap();
        conn.pragma_update(None, "journal_mode", "WAL").unwrap();
        conn.execute_batch("CREATE TABLE marker(x);").unwrap();
        conn.pragma_update(None, "user_version", OPERATIONAL_SCHEMA_VERSION + 7)
            .unwrap();
        // Clean close checkpoints the WAL into the main file and removes the
        // sidecars, leaving a WAL-MODE database with the stamp in its header.
    }
    assert_eq!(
        header_user_version(&path),
        OPERATIONAL_SCHEMA_VERSION + 7,
        "fixture must carry the forward stamp in the main header"
    );
    let before = std::fs::read(&path).unwrap();

    let error = OperationalDb::open(&path).unwrap_err();
    assert!(
        matches!(error, KataError::SchemaMigrationRequired(_)),
        "a newer WAL-mode schema must be refused, got {error:?}"
    );
    assert_eq!(
        std::fs::read(&path).unwrap(),
        before,
        "refusal rewrote the WAL-mode file"
    );
    for suffix in ["-wal", "-shm", "-journal"] {
        let file = sidecar(&path, suffix);
        assert!(
            !file.exists(),
            "refusal created {file:?}: the version was read by OPENING SQLite, not by file I/O"
        );
    }
}

/// A HOT WAL — a pending, unchecked `-wal` sidecar whose frames carry an
/// UNCHECKPOINTED forward stamp the main header does not show. The gate must fold
/// the WAL's page-1 stamp into its decision and refuse, still without opening
/// SQLite (no `-shm` may appear, and neither existing file may change).
#[test]
fn operational_forward_version_refusal_on_hot_wal_sidecar_touches_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("operational.db");
    build_hot_wal_fixture(&path, OPERATIONAL_SCHEMA_VERSION + 3);

    // The main header still shows the COMPATIBLE version: only the pending WAL
    // frame carries the forward stamp, so a header-only read would wrongly admit.
    assert_eq!(
        header_user_version(&path),
        OPERATIONAL_SCHEMA_VERSION,
        "fixture precondition: the forward stamp is uncheckpointed"
    );
    let wal = sidecar(&path, "-wal");
    assert!(wal.exists(), "fixture precondition: a hot -wal is present");
    let before_db = std::fs::read(&path).unwrap();
    let before_wal = std::fs::read(&wal).unwrap();

    let error = OperationalDb::open(&path).unwrap_err();
    assert!(
        matches!(error, KataError::SchemaMigrationRequired(_)),
        "an uncheckpointed forward stamp in a hot WAL must be refused, got {error:?}"
    );
    assert_eq!(
        std::fs::read(&path).unwrap(),
        before_db,
        "refusal wrote the db"
    );
    assert_eq!(
        std::fs::read(&wal).unwrap(),
        before_wal,
        "refusal wrote the hot WAL (it was recovered instead of refused)"
    );
    assert!(
        !sidecar(&path, "-shm").exists(),
        "refusal created -shm: SQLite was opened before the version gate"
    );
}

/// The gate must not OVER-refuse: a hot WAL carrying a COMPATIBLE stamp opens
/// normally (and its uncommitted-to-main frames recover as usual).
#[test]
fn operational_hot_wal_with_compatible_version_opens() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("operational.db");
    build_hot_wal_fixture(&path, OPERATIONAL_SCHEMA_VERSION);
    assert!(sidecar(&path, "-wal").exists());

    let db = OperationalDb::open(&path).unwrap();
    assert_eq!(db.debug_user_version().unwrap(), OPERATIONAL_SCHEMA_VERSION);
    submit(&db, Ulid::new(), 1);
    assert_eq!(db.debug_count("programs").unwrap(), 1);
}

/// Build `path` + a HOT `-wal` sidecar: the main file is checkpointed at the
/// current schema version, then `user_version` is set to `wal_version` and left
/// UNCHECKPOINTED in the WAL. Copies both files out from under a still-open
/// connection so the pending frames survive into the fixture.
fn build_hot_wal_fixture(path: &Path, wal_version: i64) {
    let dir = path.parent().unwrap();
    let live = dir.join("live-source.db");
    // A REAL operational database, not a stand-in `marker` table. A stamp AT the
    // current version claims the current SHAPE, and the open path asserts that shape
    // before any DDL, so a current-stamped fixture must actually carry it — the
    // compatible-stamp half of this pair would otherwise be refused for having no
    // `programs` table rather than admitted for having a compatible stamp.
    drop(OperationalDb::open(&live).unwrap());
    let conn = rusqlite::Connection::open(&live).unwrap();
    conn.pragma_update(None, "journal_mode", "WAL").unwrap();
    // Fold everything so far into the main file, then start a fresh WAL.
    conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")
        .unwrap();
    // This page-1 write lands in the WAL and is NOT checkpointed.
    conn.pragma_update(None, "user_version", wal_version)
        .unwrap();

    std::fs::copy(&live, path).unwrap();
    std::fs::copy(sidecar(&live, "-wal"), sidecar(path, "-wal")).unwrap();
    drop(conn);
    std::fs::remove_file(&live).unwrap();
}

// -- schema: the stamped CHECK / FK / index guards ---------------------------

/// Plant one `occurrences` row for `execution_id` through a RAW handle and return
/// its id, so a raw `attempts` fixture can carry the binding the schema requires.
/// Every column is the smallest value the table's CHECKs admit; the operation path
/// is empty (a root occurrence).
fn insert_raw_occurrence(conn: &rusqlite::Connection, execution_id: Ulid) -> [u8; 32] {
    let occurrence = [0x5A; 32];
    conn.execute(
        "INSERT INTO occurrences
             (occurrence_id, execution_id, program_hash, operation_contract_id,
              operation_path, created_at_ms)
         VALUES (?1, ?2, ?3, ?4, x'', 0)",
        params![
            occurrence.as_slice(),
            execution_id.to_bytes().as_ref(),
            [0x01_u8; 32].as_slice(),
            [0x02_u8; 32].as_slice()
        ],
    )
    .expect("plant a raw occurrence");
    occurrence
}

/// `attempts.occurrence_id` is `NOT NULL`. A RAW insert
/// of an attempt row that is valid in every other column — real execution, real
/// source transition, a real occurrence a sibling row binds — is refused by
/// SQLite itself when it omits the binding, and the same row with the binding is
/// admitted. Proven through a second, raw connection: this is the schema's
/// guard, not the typed API's, which never writes such a row.
#[test]
fn an_attempt_row_without_an_occurrence_binding_is_refused_by_the_schema() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("operational.db");
    let db = OperationalDb::open(&path).unwrap();
    let exec = Ulid::new();
    let seq = submit(&db, exec, 1);
    let conn = raw_conn(&path);
    let occurrence = insert_raw_occurrence(&conn, exec);

    let unbound = conn
        .execute(
            "INSERT INTO attempts
                 (attempt_id, execution_id, stage_id, attempt_ordinal, lease_epoch,
                  assignment_json, source_seq, created_at_ms, run_ordinal)
             VALUES (?1, ?2, 'stage-a', 0, 0, x'', ?3, 0, 0)",
            params![
                Ulid::new().to_bytes().as_ref(),
                exec.to_bytes().as_ref(),
                seq
            ],
        )
        .expect_err("an attempt with no occurrence binding must be unwritable");
    assert!(
        unbound
            .to_string()
            .contains("NOT NULL constraint failed: attempts.occurrence_id"),
        "the refusal must be the column's NOT NULL, not some other constraint: {unbound}"
    );
    conn.execute(
        "INSERT INTO attempts
             (attempt_id, execution_id, stage_id, attempt_ordinal, lease_epoch,
              assignment_json, source_seq, created_at_ms, run_ordinal, occurrence_id)
         VALUES (?1, ?2, 'stage-a', 0, 0, x'', ?3, 0, 0, ?4)",
        params![
            Ulid::new().to_bytes().as_ref(),
            exec.to_bytes().as_ref(),
            seq,
            occurrence.as_slice()
        ],
    )
    .expect("the same row WITH its binding is admitted, so the refusal above is the binding's");
}

/// A stage-scope transition is RECORD-ONLY by the schema, not by a census of its writers.
/// Every stage-scope writer passes `TransitionEffect::RecordOnly`, and there is no stage
/// projection table; this CHECK is what keeps "no stage transition folds" true for a writer
/// added later, and what the rebuild's stage-leg refusal leans on. Proven through a raw
/// second handle: the same row is refused folding and admitted record-only, so the refusal
/// is the fold bit's.
#[test]
fn a_folding_stage_scope_transition_is_refused_by_the_schema() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("operational.db");
    let db = OperationalDb::open(&path).unwrap();
    let exec = Ulid::new();
    let head = submit(&db, exec, 1);
    let conn = raw_conn(&path);
    let insert = |folds: i64| {
        conn.execute(
            "INSERT INTO transitions
                 (seq, execution_id, scope, stage_id, kind, resulting_state, folds_projection,
                  payload_json, recorded_at_ms)
             VALUES (?1, ?2, 'stage', 'stage-a', 'undispatched_stage_settled', 'failed', ?3,
                     x'', 0)",
            params![head + 1, exec.to_bytes().as_ref(), folds],
        )
    };
    let refused = insert(1).expect_err("a folding stage-scope transition must be unwritable");
    assert!(
        refused
            .to_string()
            .contains("CHECK constraint failed: scope <> 'stage' OR folds_projection = 0"),
        "the refusal must be the stage fold CHECK, not some other constraint: {refused}"
    );
    insert(0).expect("the same row record-only is admitted, so the refusal is the fold bit's");
}

/// The rebuild REFUSES a folding stage-scope transition rather than skipping it: a
/// stage row that folds would be a projection this plane has no table for, so a
/// rebuild that skipped it would "repair" an execution by discarding the evidence.
/// The schema's CHECK keeps the row out of a real file, so it is planted through a
/// raw handle with `ignore_check_constraints` (a hand-edited or foreign file). Both
/// readers of `rebuild_from_chain` refuse it by name, and the stored projection
/// survives the refused repair (read raw).
#[test]
fn a_folding_stage_scope_transition_is_refused_by_the_rebuild() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("operational.db");
    let db = OperationalDb::open(&path).unwrap();
    let exec = Ulid::new();
    let head = submit(&db, exec, 1);
    let conn = raw_conn(&path);
    conn.pragma_update(None, "ignore_check_constraints", "ON")
        .unwrap();
    conn.execute(
        "INSERT INTO transitions
             (seq, execution_id, scope, stage_id, kind, resulting_state, folds_projection,
              payload_json, recorded_at_ms)
         VALUES (?1, ?2, 'stage', 'stage-a', 'undispatched_stage_settled', 'failed', 1, x'', 0)",
        params![head + 1, exec.to_bytes().as_ref()],
    )
    .expect("premise: with the CHECK ignored, the folding stage row is planted");

    let named = "is a FOLDING stage-scope transition";
    let repair = db
        .rebuild_projection(exec)
        .expect_err("the rebuild must refuse a folding stage row, not skip it");
    assert!(repair.to_string().contains(named), "{repair}");
    let verify = db
        .verify_projection_integrity(exec)
        .expect_err("the integrity check must refuse it too");
    assert!(verify.to_string().contains(named), "{verify}");
    let stored: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM execution_projection WHERE execution_id = ?1",
            params![exec.to_bytes().as_ref()],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(stored, 1, "the refused repair cleared no stored projection");
}

/// The stamped vocabularies and shape CHECKs refuse an out-of-band write. Proven
/// through a RAW connection: these are the schema's guards, not the typed API's.
#[test]
fn operational_schema_checks_refuse_out_of_vocabulary_writes() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("operational.db");
    let db = OperationalDb::open(&path).unwrap();
    let exec = Ulid::new();
    let seq = submit(&db, exec, 1);
    let conn = raw_conn(&path);

    // The stamped ATTEMPT vocabulary lives on `attempt_projection.state` —
    // the one value an attempt-scope fold actually writes. `attempts` carries no
    // state column at all, so there is no second representation to disagree with
    // the projection and no unadjudicated mirror inside `operational.db`.
    let occurrence = insert_raw_occurrence(&conn, exec);
    let insert_attempt = |attempt_id: Ulid, ordinal: i64| {
        conn.execute(
            "INSERT INTO attempts
                 (attempt_id, execution_id, stage_id, attempt_ordinal, lease_epoch,
                  assignment_json, source_seq, created_at_ms, run_ordinal, occurrence_id)
             VALUES (?1, ?2, 'stage-a', ?3, 0, x'', ?4, 0, 0, ?5)",
            params![
                attempt_id.to_bytes().as_ref(),
                exec.to_bytes().as_ref(),
                ordinal,
                seq,
                occurrence.as_slice()
            ],
        )
    };
    let insert_projection = |ordinal: i64, state: &str| {
        conn.execute(
            "INSERT INTO attempt_projection
                 (execution_id, stage_id, attempt_ordinal, state, source_seq, updated_at_ms)
             VALUES (?1, 'stage-a', ?2, ?3, ?4, 0)",
            params![exec.to_bytes().as_ref(), ordinal, state, seq],
        )
    };
    insert_attempt(Ulid::new(), 0).expect("an attempt row carries no state of its own");
    insert_attempt(Ulid::new(), 1).unwrap();
    insert_projection(0, "stalled").expect("'stalled' is in the stamped attempt vocabulary");
    insert_projection(1, "running").expect("'running' is in the stamped attempt vocabulary");
    assert!(
        insert_projection(2, "definitely-not-a-state").is_err(),
        "attempt_projection.state must refuse an undeclared state"
    );
    assert!(
        conn.execute(
            "INSERT INTO attempts
                 (attempt_id, execution_id, stage_id, attempt_ordinal, lease_epoch, state,
                  assignment_json, source_seq, created_at_ms, run_ordinal, occurrence_id)
             VALUES (?1, ?2, 'stage-a', 9, 0, 'running', x'', ?3, 0, 0, ?4)",
            params![
                Ulid::new().to_bytes().as_ref(),
                exec.to_bytes().as_ref(),
                seq,
                occurrence.as_slice()
            ],
        )
        .is_err(),
        "attempts has no state column; a writer that supplies one must fail loudly rather \
         than create an unadjudicated mirror of the projection"
    );

    // transitions.seq >= 1 (0 would alias 'no transition').
    assert!(
        conn.execute(
            "INSERT INTO transitions
                 (seq, execution_id, scope, kind, resulting_state, payload_json, recorded_at_ms)
             VALUES (0, ?1, 'execution', 'k', 's', x'', 0)",
            params![exec.to_bytes().as_ref()],
        )
        .is_err(),
        "transitions.seq must refuse 0"
    );

    // event_inbox.event_seq >= 1 (0 is the empty-watermark value).
    //
    // `execution_id` is supplied deliberately, and it is not padding: the column is
    // NOT NULL, so an INSERT that omits it is refused for the WRONG reason
    // and this assertion would pass while proving nothing about the seq CHECK.
    assert!(
        conn.execute(
            "INSERT INTO event_inbox
                 (stream_id, event_seq, execution_id, event_digest, accepted, payload_json,
                  received_at_ms)
             VALUES (x'01', 0, ?2, ?1, 0, x'', 0)",
            params![digest(1).as_bytes(), exec.to_bytes().as_ref()],
        )
        .is_err(),
        "event_inbox.event_seq must refuse 0"
    );

    // length-32 hash CHECKs.
    assert!(
        conn.execute(
            "INSERT INTO programs (execution_id, program_hash, schema_version, program_json,
                                   created_at_ms)
             VALUES (?1, x'0011', 1, x'', 0)",
            params![Ulid::new().to_bytes().as_ref()],
        )
        .is_err(),
        "programs.program_hash must be 32 bytes"
    );

    // schedules.on_missed vocabulary.
    assert!(
        conn.execute(
            "INSERT INTO schedules
                 (schedule_id, submit_pack, \"trigger\", on_missed, bound_program_hash,
                  bound_admission_digest, program_json, invocation_json, cursor_ms, created_at_ms)
             VALUES ('s', 'pack', '{}', 'whenever-really', ?1, ?2, x'', x'', 0, 0)",
            params![digest(1).as_bytes(), digest(2).as_bytes()],
        )
        .is_err(),
        "schedules.on_missed must refuse an undeclared policy"
    );
}

/// `terminal_started_at_ms` — the instant terminal INTENT was latched — round-trips
/// through the typed lifecycle faces.
#[test]
fn operational_lifecycle_terminal_started_at_ms_round_trips() {
    let db = OperationalDb::open_in_memory().unwrap();
    let exec = Ulid::new();
    submit(&db, exec, 1);

    // Pre-terminal: the intent instant is absent.
    let admitted = db.execution_lifecycle(exec).unwrap().unwrap();
    assert_eq!(admitted.state, LifecycleState::Admitting);
    assert_eq!(admitted.terminal_started_at_ms, None);
    assert_eq!(admitted.terminal_outcome, None);
    assert_eq!(admitted.finished_at_ms, None);

    // Latching terminal INTENT stamps it (and only it — the outcome is not yet
    // published).
    let reason = b"{\"code\":\"cancelled_by_operator\"}";
    assert!(matches!(
        db.begin_terminalization(exec, LifecycleState::Cancelled, reason)
            .unwrap(),
        ClaimOutcome::Recorded { .. }
    ));
    let latched = db.execution_lifecycle(exec).unwrap().unwrap();
    assert_eq!(latched.state, LifecycleState::Terminalizing);
    assert_eq!(latched.terminal_outcome, Some(LifecycleState::Cancelled));
    assert_eq!(latched.terminal_reason_json.as_deref(), Some(&reason[..]));
    let intent_at = latched
        .terminal_started_at_ms
        .expect("terminal intent must stamp terminal_started_at_ms");
    assert!(intent_at > 0);
    assert_eq!(latched.finished_at_ms, None);

    // Re-latching the same intent is idempotent and does NOT restamp.
    assert_eq!(
        db.begin_terminalization(exec, LifecycleState::Cancelled, reason)
            .unwrap(),
        ClaimOutcome::AlreadyRecorded
    );
    assert_eq!(
        db.execution_lifecycle(exec)
            .unwrap()
            .unwrap()
            .terminal_started_at_ms,
        Some(intent_at)
    );
    // A CONFLICTING intent refuses.
    assert!(
        db.begin_terminalization(exec, LifecycleState::Failed, reason)
            .is_err()
    );

    // Publishing keeps the intent instant and adds the finish instant.
    assert!(matches!(
        db.finish_terminalization(exec).unwrap(),
        ClaimOutcome::Recorded { .. }
    ));
    let published = db.execution_lifecycle(exec).unwrap().unwrap();
    assert_eq!(published.state, LifecycleState::Cancelled);
    assert_eq!(published.terminal_started_at_ms, Some(intent_at));
    assert!(published.finished_at_ms.is_some());
    // Publishing twice is idempotent.
    assert_eq!(
        db.finish_terminalization(exec).unwrap(),
        ClaimOutcome::AlreadyRecorded
    );

    // A non-terminal outcome, an empty reason, and finishing without beginning are
    // all refused.
    let other = Ulid::new();
    submit(&db, other, 2);
    assert!(
        db.begin_terminalization(other, LifecycleState::Running, reason)
            .is_err()
    );
    assert!(
        db.begin_terminalization(other, LifecycleState::Failed, b"")
            .is_err()
    );
    assert!(db.finish_terminalization(other).is_err());
}

/// The lifecycle CHECK matrix rejects an incoherent `terminal_started_at_ms`.
#[test]
fn operational_lifecycle_check_matrix_refuses_incoherent_terminal_started_at_ms() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("operational.db");
    let db = OperationalDb::open(&path).unwrap();
    let exec = Ulid::new();
    submit(&db, exec, 1);
    let conn = raw_conn(&path);

    // `terminalizing` REQUIRES the intent instant.
    assert!(
        conn.execute(
            "UPDATE execution_lifecycle
                SET state = 'terminalizing', terminal_outcome = 'failed',
                    terminal_reason_json = x'7b7d', terminal_started_at_ms = NULL
              WHERE execution_id = ?1",
            params![exec.to_bytes().as_ref()],
        )
        .is_err(),
        "terminalizing with a NULL terminal_started_at_ms must violate the CHECK matrix"
    );
    // An in-flight row must NOT carry one.
    assert!(
        conn.execute(
            "UPDATE execution_lifecycle SET state = 'running', terminal_started_at_ms = 123
              WHERE execution_id = ?1",
            params![exec.to_bytes().as_ref()],
        )
        .is_err(),
        "a running lifecycle with a terminal_started_at_ms must violate the CHECK matrix"
    );
    // A published terminal row REQUIRES both instants.
    assert!(
        conn.execute(
            "UPDATE execution_lifecycle
                SET state = 'failed', terminal_outcome = 'failed',
                    terminal_reason_json = x'7b7d', terminal_started_at_ms = NULL,
                    finished_at_ms = 456
              WHERE execution_id = ?1",
            params![exec.to_bytes().as_ref()],
        )
        .is_err(),
        "a terminal lifecycle without a terminal_started_at_ms must violate the CHECK matrix"
    );
    // The coherent shape is accepted, so the refusals above are the matrix and not
    // an unrelated constraint.
    conn.execute(
        "UPDATE execution_lifecycle
            SET state = 'failed', terminal_outcome = 'failed',
                terminal_reason_json = x'7b7d', terminal_started_at_ms = 123,
                finished_at_ms = 456
          WHERE execution_id = ?1",
        params![exec.to_bytes().as_ref()],
    )
    .expect("a coherent terminal lifecycle row is accepted");
}

/// The stamped `transitions` foreign key refuses an orphan transition — a
/// transition for an execution that was never submitted is unreachable state.
#[test]
fn operational_transitions_foreign_key_refuses_an_orphan_transition() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("operational.db");
    let db = OperationalDb::open(&path).unwrap();
    let exec = Ulid::new();
    submit(&db, exec, 1);
    let conn = raw_conn(&path);

    let orphan = conn.execute(
        "INSERT INTO transitions
             (seq, execution_id, scope, kind, resulting_state, payload_json, recorded_at_ms)
         VALUES (9999, ?1, 'execution', 'k', 's', x'', 0)",
        params![Ulid::new().to_bytes().as_ref()],
    );
    assert!(
        orphan.is_err(),
        "a transition for an unsubmitted execution must violate the programs FK"
    );
    // The same row for a SUBMITTED execution is accepted, so the refusal above is
    // the FK and not some unrelated constraint.
    conn.execute(
        "INSERT INTO transitions
             (seq, execution_id, scope, kind, resulting_state, payload_json, recorded_at_ms)
         VALUES (9999, ?1, 'execution', 'k', 's', x'', 0)",
        params![exec.to_bytes().as_ref()],
    )
    .expect("a transition for a submitted execution satisfies the FK");
}

/// Every `EXPLAIN QUERY PLAN` row for `sql`, joined.
///
/// All rows, not the first: a statement with a subquery or a NOT EXISTS emits one
/// plan row per scan, and the one naming the index is not reliably first. Reading
/// only `query_row`'s first row would let an index proof pass or fail on plan
/// ordering rather than on index use.
/// A CURRENT-stamped database whose `transitions` table is MISSING
/// `folds_projection` — an out-of-band shape edit under a correct stamp.
///
/// Built from the current schema so every other table matches production
/// byte-for-byte and the only difference is the one column, then re-stamped CURRENT:
/// the file's header says "this is the current shape" and its content disagrees,
/// which is exactly the state `validate_schema` exists to refuse. `ALTER TABLE ...
/// DROP COLUMN` cannot produce it — the column is named by a table CHECK — so the
/// table is rebuilt.
fn build_transitions_missing_folds_projection(path: &Path) {
    OperationalDb::open(path).unwrap();
    let conn = rusqlite::Connection::open(path).unwrap();
    conn.execute_batch(
        "PRAGMA foreign_keys = OFF;
         BEGIN;
         DROP TABLE transitions;
         CREATE TABLE transitions (
             seq             INTEGER NOT NULL PRIMARY KEY,
             execution_id    BLOB    NOT NULL,
             scope           TEXT    NOT NULL,
             stage_id        TEXT,
             attempt_ordinal INTEGER,
             kind            TEXT    NOT NULL,
             resulting_state TEXT    NOT NULL,
             payload_json    BLOB    NOT NULL,
             idempotency_key BLOB,
             recorded_at_ms  INTEGER NOT NULL,
             attempt_id      BLOB,
             FOREIGN KEY(execution_id) REFERENCES programs(execution_id) ON DELETE CASCADE,
             CHECK (seq >= 1),
             CHECK (scope IN ('execution', 'stage', 'attempt')),
             CHECK (idempotency_key IS NULL OR length(idempotency_key) > 0)
         );
         CREATE INDEX idx_transitions_execution ON transitions (execution_id, seq);
         CREATE UNIQUE INDEX idx_transitions_idempotency
             ON transitions (idempotency_key) WHERE idempotency_key IS NOT NULL;
         COMMIT;",
    )
    .unwrap();
    conn.pragma_update(None, "user_version", OPERATIONAL_SCHEMA_VERSION)
        .unwrap();
    drop(conn);
}

/// `NIX_ENVIRONMENT_COLUMN_CONTRACT` really refuses: rebuild
/// `root_promoted_at_ms` as `NOT NULL DEFAULT 0` under a CURRENT stamp, and the reopen
/// must be a refusal naming the contract.
///
/// # Why the column SET check cannot catch this, which is why the contract exists
///
/// The column NAMES and their count are unchanged, so `OPERATIONAL_TABLE_COLUMNS` passes.
/// What moved is NULLABILITY — and for this table nullability IS the reconciliation
/// protocol: `unpromoted_environments` selects `WHERE root_promoted_at_ms IS NULL` and
/// `active_environments` selects `WHERE released_at_ms IS NULL`, both riding partial
/// indexes with those exact predicates. A `NOT NULL DEFAULT 0` column keeps the indexes
/// valid SQL and silently EMPTIES the boot reconciler's work list, so every environment
/// whose promotion a crash interrupted would read as promoted and be bound with a gc root
/// still in a staging generation. A validator that is never watched refusing is a
/// validator nobody has seen work, so this is the falsification rather than the happy
/// path.
#[test]
fn a_nix_environments_column_whose_nullability_moved_is_refused_at_open() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("operational.db");
    drop(OperationalDb::open(&path).unwrap());
    {
        let conn = rusqlite::Connection::open(&path).unwrap();
        conn.execute_batch(
            "PRAGMA foreign_keys = OFF;
             BEGIN;
             DROP TABLE nix_environments;
             CREATE TABLE nix_environments (
                 environment_id       BLOB    NOT NULL PRIMARY KEY,
                 manifest_object_id   BLOB    NOT NULL,
                 closure_digest       BLOB    NOT NULL,
                 label                TEXT    NOT NULL,
                 platform_id          BLOB    NOT NULL,
                 root_stage_id        TEXT    NOT NULL,
                 root_promoted_at_ms  INTEGER NOT NULL DEFAULT 0,
                 released_at_ms       INTEGER,
                 created_at_ms        INTEGER NOT NULL,
                 verification_evidence BLOB
             );
             CREATE INDEX idx_nix_environments_active
                 ON nix_environments (environment_id) WHERE released_at_ms IS NULL;
             CREATE INDEX idx_nix_environments_unpromoted
                 ON nix_environments (environment_id) WHERE root_promoted_at_ms IS NULL;
             CREATE UNIQUE INDEX idx_nix_environments_manifest_live
                 ON nix_environments (manifest_object_id) WHERE released_at_ms IS NULL;
             COMMIT;",
        )
        .unwrap();
        // The stamp stays CURRENT, so the version gate cannot be what refuses.
        assert_eq!(
            conn.query_row::<i64, _, _>("PRAGMA user_version", [], |row| row.get(0))
                .unwrap(),
            OPERATIONAL_SCHEMA_VERSION
        );
    }

    let error = OperationalDb::open(&path)
        .expect_err("a nix_environments column whose nullability moved must be refused");
    let message = error.to_string();
    assert!(
        message.contains("nix_environments"),
        "the refusal must name the table whose contract failed: {message}"
    );
    assert!(
        message.contains("root_promoted_at_ms"),
        "and the observed contract must show the column that moved: {message}"
    );
    // The column SET is intact, so this could ONLY have come from the ordered
    // column/type/null/key contract — asserted rather than assumed, because a refusal
    // produced by the set check would mean the contract is still unexercised.
    let columns: Vec<String> = rusqlite::Connection::open(&path)
        .unwrap()
        .prepare("SELECT name FROM pragma_table_info('nix_environments')")
        .unwrap()
        .query_map([], |row| row.get(0))
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    let declared = OPERATIONAL_TABLE_COLUMNS
        .iter()
        .find(|(table, _)| *table == "nix_environments")
        .map(|(_, columns)| *columns)
        .expect("nix_environments is declared");
    assert_eq!(
        columns.len(),
        declared.len(),
        "non-vacuity: the forged table must keep the DECLARED column set, or the set check \
         refuses first and the ordered contract is still untested"
    );
}

/// An `artifacts` column whose NULLABILITY moved is refused at open.
///
/// # Why the column SET check cannot catch this, which is why the contract exists
///
/// The column NAMES and their count are unchanged, so `OPERATIONAL_TABLE_COLUMNS` passes.
/// What moved is NULLABILITY: a nullable `kind` would admit a row that says nothing about
/// how its object is read, which every reader of the row would then have to guess. A
/// validator that is never watched refusing is a validator nobody has seen work, so this
/// is the falsification rather than the happy path.
#[test]
fn an_artifacts_column_whose_nullability_moved_is_refused_at_open() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("operational.db");
    drop(OperationalDb::open(&path).unwrap());
    {
        let conn = rusqlite::Connection::open(&path).unwrap();
        conn.execute_batch(
            "PRAGMA foreign_keys = OFF;
             BEGIN;
             DROP TABLE artifacts;
             CREATE TABLE artifacts (
                 artifact_id        BLOB    NOT NULL PRIMARY KEY,
                 object_id          BLOB    NOT NULL,
                 size_bytes         INTEGER NOT NULL,
                 privacy            TEXT    NOT NULL,
                 kind               TEXT,
                 created_at_ms      INTEGER NOT NULL
             );
             CREATE UNIQUE INDEX idx_artifacts_object ON artifacts (object_id);
             COMMIT;",
        )
        .unwrap();
        // The stamp stays CURRENT, so the version gate cannot be what refuses.
        assert_eq!(
            conn.query_row::<i64, _, _>("PRAGMA user_version", [], |row| row.get(0))
                .unwrap(),
            OPERATIONAL_SCHEMA_VERSION
        );
    }

    let error = OperationalDb::open(&path)
        .expect_err("an artifacts column whose nullability moved must be refused");
    let message = error.to_string();
    assert!(
        message.contains("artifacts"),
        "the refusal must name the table whose contract failed: {message}"
    );
    assert!(
        message.contains("kind"),
        "and the observed contract must show the column that moved: {message}"
    );
    // The column SET is intact, so this could ONLY have come from the ordered
    // column/type/null/key contract.
    let columns: Vec<String> = rusqlite::Connection::open(&path)
        .unwrap()
        .prepare("SELECT name FROM pragma_table_info('artifacts')")
        .unwrap()
        .query_map([], |row| row.get(0))
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    let declared = OPERATIONAL_TABLE_COLUMNS
        .iter()
        .find(|(table, _)| *table == "artifacts")
        .map(|(_, columns)| *columns)
        .expect("artifacts is declared");
    assert_eq!(
        columns.len(),
        declared.len(),
        "non-vacuity: the forged table must keep the DECLARED column set, or the set check \
         refuses first and the ordered contract is still untested"
    );
}

/// A `capsules` column that became NULLABLE is refused at open.
///
/// # Why the column SET check cannot catch this, which is why the contract exists
///
/// Every `capsules` column is NOT NULL because a capsule is total: it names its
/// occurrence, its prepared action, its environment, its platform and its bytes, or it is
/// not the immutable binding ADR-0001 trust boundary 3 describes. A nullable
/// `environment_id` keeps the column set identical, keeps the foreign key valid SQL (a
/// NULL child satisfies any FK), and lets a row claim a capsule whose environment binding
/// is absent — which `declare_capsule`'s environment refusal would then be reachable
/// AROUND rather than through.
#[test]
fn a_capsules_column_that_became_nullable_is_refused_at_open() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("operational.db");
    drop(OperationalDb::open(&path).unwrap());
    {
        let conn = rusqlite::Connection::open(&path).unwrap();
        conn.execute_batch(
            "PRAGMA foreign_keys = OFF;
             BEGIN;
             DROP TABLE capsules;
             CREATE TABLE capsules (
                 capsule_id         BLOB    NOT NULL PRIMARY KEY,
                 occurrence_id      BLOB    NOT NULL,
                 prepared_action_id BLOB    NOT NULL,
                 environment_id     BLOB,
                 platform_id        BLOB    NOT NULL,
                 capsule_object_id  BLOB    NOT NULL,
                 created_at_ms      INTEGER NOT NULL,
                 FOREIGN KEY(environment_id) REFERENCES nix_environments(environment_id)
             );
             CREATE INDEX idx_capsules_environment ON capsules (environment_id);
             COMMIT;",
        )
        .unwrap();
        assert_eq!(
            conn.query_row::<i64, _, _>("PRAGMA user_version", [], |row| row.get(0))
                .unwrap(),
            OPERATIONAL_SCHEMA_VERSION
        );
    }

    let error = OperationalDb::open(&path)
        .expect_err("a capsules column that became nullable must be refused");
    let message = error.to_string();
    assert!(
        message.contains("capsules"),
        "the refusal must name the table whose contract failed: {message}"
    );
    assert!(
        message.contains("environment_id"),
        "and the observed contract must show the column that moved: {message}"
    );
    let columns: Vec<String> = rusqlite::Connection::open(&path)
        .unwrap()
        .prepare("SELECT name FROM pragma_table_info('capsules')")
        .unwrap()
        .query_map([], |row| row.get(0))
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    let declared = OPERATIONAL_TABLE_COLUMNS
        .iter()
        .find(|(table, _)| *table == "capsules")
        .map(|(_, columns)| *columns)
        .expect("capsules is declared");
    assert_eq!(
        columns.len(),
        declared.len(),
        "non-vacuity: the forged table must keep the DECLARED column set, or the set check \
         refuses first and the ordered contract is still untested"
    );
}

/// A stamp one version BEHIND the current one is refused before SQLite is opened, and
/// the refusal names the operator's recourse.
///
/// # Why this test is the disposition, not a spot check
///
/// The operational plane has no upgrade ladder. A durable schema change still owes
/// an explicit disposition, and for this plane the disposition IS this refusal: a data directory
/// at any other stamp is not imported, not repaired and not
/// reinterpreted —
/// it is refused, and the operator keeps it offline and starts a fresh one. So the
/// recourse STRING is asserted, not merely the error variant: an operator who is told
/// only "schema migration required" will look for a migration that does not exist.
///
/// The version is NOT spelled in this test's name or body: it is
/// `OPERATIONAL_SCHEMA_VERSION - 1`, so the cell follows every bump instead of pinning
/// the one version it was written under and quietly testing an ancient stamp.
///
/// # This cell has to hold for a change that moves NO DDL
///
/// A change to what `attempts.assignment_json` or an undispatched-stage admission's
/// payload HOLDS changes no table, column, index or CHECK. Every table-shape assertion
/// in this file is satisfied by a directory written before such a change, and THIS
/// cell is the only thing standing between a retained one and a reader that would
/// refuse its blobs a sweep later with no operator recourse.
/// [`a_blob_shaped_for_the_previous_version_never_reaches_a_reader`] is its companion:
/// it proves the refusal really does land at boot, ahead of the blob reader.
#[test]
fn a_stamp_one_version_behind_is_refused_with_the_new_data_directory_recourse() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("operational.db");
    {
        let db = OperationalDb::open(&path).unwrap();
        submit(&db, Ulid::new(), 1);
        db.debug_stamp_user_version(OPERATIONAL_SCHEMA_VERSION - 1)
            .unwrap();
    }
    let bytes_before = std::fs::read(&path).unwrap();

    let error = OperationalDb::open(&path)
        .expect_err("a behind-stamped database must be refused, never upgraded in place");
    assert!(
        matches!(error, KataError::SchemaMigrationRequired(_)),
        "a non-current stamp must be an operator-actionable refusal, got {error:?}"
    );
    let message = error.to_string();
    assert!(
        message.contains(&format!(
            "schema version {} is not the clean runtime version {OPERATIONAL_SCHEMA_VERSION}",
            OPERATIONAL_SCHEMA_VERSION - 1
        )),
        "the refusal must name both the observed and the required version: {message}"
    );
    assert!(
        message.contains("use a new empty data directory and preserve this directory offline"),
        "the refusal must name the operator's recourse, because there is no migration \
         to point at: {message}"
    );
    // The refusal is also the DISPOSITION: the retained directory is left exactly as
    // it was, so "preserve this directory offline" is advice the code has not already
    // violated. Observed on the file itself rather than through the driver that just
    // refused it.
    assert_eq!(
        std::fs::read(&path).unwrap(),
        bytes_before,
        "a refused open must not have rewritten a single page of the retained directory"
    );
    // And the standalone probe agrees with the open path, so a data-dir preflight
    // cannot report green on a directory boot then refuses.
    assert!(
        OperationalDb::refuse_noncurrent_file_schema(&path).is_err(),
        "the immutable probe must refuse exactly what the open path refuses"
    );
}

/// A data directory written at schema 37 — the shape that still carried the
/// `effect_claims` table and the `awaiting_retry` park's columns — is refused at
/// open by its stamp, with the new-empty-directory recourse, and left untouched.
/// Nothing reads its retired rows: the refusal precedes every reader.
#[test]
fn a_schema_37_data_directory_is_refused_at_open() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("operational.db");
    {
        let db = OperationalDb::open(&path).unwrap();
        submit(&db, Ulid::new(), 1);
        db.debug_stamp_user_version(37).unwrap();
    }
    let bytes_before = std::fs::read(&path).unwrap();
    let error = OperationalDb::open(&path).expect_err("a schema-37 directory is refused");
    assert!(
        matches!(error, KataError::SchemaMigrationRequired(_)),
        "{error:?}"
    );
    let message = error.to_string();
    assert!(
        message.contains(&format!(
            "schema version 37 is not the clean runtime version {OPERATIONAL_SCHEMA_VERSION}"
        )) && message.contains("use a new empty data directory"),
        "{message}"
    );
    assert_eq!(std::fs::read(&path).unwrap(), bytes_before);
}

/// A data directory written at schema 42 is refused at open, with the
/// new-empty-directory recourse, and left untouched. Its rows hold durable shapes
/// this build REREADS: a dispatched attempt's `failed`/`cancelled`/`orphaned`
/// terminal with no `terminal_charge` (which 42-era settlements wrote, and this
/// build reads as an UNKNOWN charge that fails a hard cost policy closed), and
/// `child_invocation_summary.metering` objects with no `tokens` (which would read
/// as a known zero token count under a `token_bound`). Retained data is never
/// silently reinterpreted, so the refusal precedes every reader.
#[test]
fn a_schema_42_data_directory_is_refused_at_open() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("operational.db");
    {
        let db = OperationalDb::open(&path).unwrap();
        submit(&db, Ulid::new(), 1);
        db.debug_stamp_user_version(42).unwrap();
    }
    let bytes_before = std::fs::read(&path).unwrap();
    let error = OperationalDb::open(&path).expect_err("a schema-42 directory is refused");
    assert!(
        matches!(error, KataError::SchemaMigrationRequired(_)),
        "{error:?}"
    );
    let message = error.to_string();
    assert!(
        message.contains(&format!(
            "schema version 42 is not the clean runtime version {OPERATIONAL_SCHEMA_VERSION}"
        )) && message.contains("use a new empty data directory"),
        "{message}"
    );
    assert_eq!(std::fs::read(&path).unwrap(), bytes_before);
}

/// A data directory written at schema 43 is refused at open, with the
/// new-empty-directory recourse, and left untouched. Its rows hold durable shapes
/// this build REREADS: a buffered `worker_failure` input with no
/// `provider_failure`, which this build's replay would re-encode with the field and
/// refuse as a content mismatch, and worker-failure settlements with no
/// `provider_failure`, which this build's failure-retry decision would read as "the
/// worker stated no provider failure". Retained data is never silently
/// reinterpreted, so the refusal precedes every reader.
#[test]
fn a_schema_43_data_directory_is_refused_at_open() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("operational.db");
    {
        let db = OperationalDb::open(&path).unwrap();
        submit(&db, Ulid::new(), 1);
        db.debug_stamp_user_version(43).unwrap();
    }
    let bytes_before = std::fs::read(&path).unwrap();
    let error = OperationalDb::open(&path).expect_err("a schema-43 directory is refused");
    assert!(
        matches!(error, KataError::SchemaMigrationRequired(_)),
        "{error:?}"
    );
    let message = error.to_string();
    assert!(
        message.contains(&format!(
            "schema version 43 is not the clean runtime version {OPERATIONAL_SCHEMA_VERSION}"
        )) && message.contains("use a new empty data directory"),
        "{message}"
    );
    assert_eq!(std::fs::read(&path).unwrap(), bytes_before);
}

/// A data directory written at schema 44 is refused at open, with the
/// new-empty-directory recourse, and left untouched. Its `operational.db` has no
/// `forge_intents` table: a `forge_export` it left pending may have pushed its
/// branch or opened its pull request with no intent row, which this build reads
/// as never issued (PROVEN NOT PERFORMED) and issues again. Retained data is never
/// silently reinterpreted, so the refusal precedes every reader.
#[test]
fn a_schema_44_data_directory_is_refused_at_open() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("operational.db");
    {
        let db = OperationalDb::open(&path).unwrap();
        submit(&db, Ulid::new(), 1);
        db.debug_stamp_user_version(44).unwrap();
    }
    let bytes_before = std::fs::read(&path).unwrap();
    let error = OperationalDb::open(&path).expect_err("a schema-44 directory is refused");
    assert!(
        matches!(error, KataError::SchemaMigrationRequired(_)),
        "{error:?}"
    );
    let message = error.to_string();
    assert!(
        message.contains(&format!(
            "schema version 44 is not the clean runtime version {OPERATIONAL_SCHEMA_VERSION}"
        )) && message.contains("use a new empty data directory"),
        "{message}"
    );
    assert_eq!(std::fs::read(&path).unwrap(), bytes_before);
}

/// A data directory written at schema 45 is refused at open, with the
/// new-empty-directory recourse, and left untouched. Its CAS can hold execution
/// contracts at schema 12 — capsules whose turn names a removed vendor adapter
/// (`codex_app_server`, `generic_acp`, `grok_acp`, `pi_rpc`) or a host-login
/// credential source — which this build cannot decode, so every read of such a
/// capsule (an execution's record, an approval park, a settlement) would fail
/// with no recourse. Retained data is never silently reinterpreted, so the
/// refusal precedes every reader.
#[test]
fn a_schema_45_data_directory_is_refused_at_open() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("operational.db");
    {
        let db = OperationalDb::open(&path).unwrap();
        submit(&db, Ulid::new(), 1);
        db.debug_stamp_user_version(45).unwrap();
    }
    let bytes_before = std::fs::read(&path).unwrap();
    let error = OperationalDb::open(&path).expect_err("a schema-45 directory is refused");
    assert!(
        matches!(error, KataError::SchemaMigrationRequired(_)),
        "{error:?}"
    );
    let message = error.to_string();
    assert!(
        message.contains(&format!(
            "schema version 45 is not the clean runtime version {OPERATIONAL_SCHEMA_VERSION}"
        )) && message.contains("use a new empty data directory"),
        "{message}"
    );
    assert_eq!(std::fs::read(&path).unwrap(), bytes_before);
}

/// A data directory written at schema 46 is refused at open, with the
/// new-empty-directory recourse, and left untouched. Its main-side settlements name
/// their verdict only in their reason, with no typed `verdict` on the terminal
/// transition, and the failure retry reads the typed field alone — so this build
/// would read every one of them as unclassified and never re-run an attempt an
/// earlier build would have. Retained data is never silently reinterpreted, so the
/// refusal precedes every reader.
#[test]
fn a_schema_46_data_directory_is_refused_at_open() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("operational.db");
    {
        let db = OperationalDb::open(&path).unwrap();
        submit(&db, Ulid::new(), 1);
        db.debug_stamp_user_version(46).unwrap();
    }
    let bytes_before = std::fs::read(&path).unwrap();
    let error = OperationalDb::open(&path).expect_err("a schema-46 directory is refused");
    assert!(
        matches!(error, KataError::SchemaMigrationRequired(_)),
        "{error:?}"
    );
    let message = error.to_string();
    assert!(
        message.contains(&format!(
            "schema version 46 is not the clean runtime version {OPERATIONAL_SCHEMA_VERSION}"
        )) && message.contains("use a new empty data directory"),
        "{message}"
    );
    assert_eq!(std::fs::read(&path).unwrap(), bytes_before);
}

/// A data directory written at schema 47 is refused at open, with the
/// new-empty-directory recourse, and left untouched. Its `forge_intents` rows
/// carry no count of their observer's unanswered reads and no command error: a
/// pending export there could be asked past the bound, or issued again after a
/// NOT PERFORMED read that followed a failed command. Retained data is never
/// silently reinterpreted, so the refusal precedes every reader.
#[test]
fn a_schema_47_data_directory_is_refused_at_open() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("operational.db");
    {
        let db = OperationalDb::open(&path).unwrap();
        submit(&db, Ulid::new(), 1);
        db.debug_stamp_user_version(47).unwrap();
    }
    let bytes_before = std::fs::read(&path).unwrap();
    let error = OperationalDb::open(&path).expect_err("a schema-47 directory is refused");
    assert!(
        matches!(error, KataError::SchemaMigrationRequired(_)),
        "{error:?}"
    );
    let message = error.to_string();
    assert!(
        message.contains(&format!(
            "schema version 47 is not the clean runtime version {OPERATIONAL_SCHEMA_VERSION}"
        )) && message.contains("use a new empty data directory"),
        "{message}"
    );
    assert_eq!(std::fs::read(&path).unwrap(), bytes_before);
}

/// A data directory written at schema 48 is refused at open, with the
/// new-empty-directory recourse, and left untouched. Its CAS can hold execution
/// contracts at schema 13, whose agent turns could declare `http_proxy`,
/// `https_proxy`, `ALL_PROXY`, `all_proxy` or `XDG_RUNTIME_DIR` in their env —
/// names this build reserves, so every read of such a capsule (an execution's
/// record, an approval park, a settlement) would fail at decode with no recourse.
/// Retained data is never silently reinterpreted, so the refusal precedes every
/// reader.
#[test]
fn a_schema_48_data_directory_is_refused_at_open() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("operational.db");
    {
        let db = OperationalDb::open(&path).unwrap();
        submit(&db, Ulid::new(), 1);
        db.debug_stamp_user_version(48).unwrap();
    }
    let bytes_before = std::fs::read(&path).unwrap();
    let error = OperationalDb::open(&path).expect_err("a schema-48 directory is refused");
    assert!(
        matches!(error, KataError::SchemaMigrationRequired(_)),
        "{error:?}"
    );
    let message = error.to_string();
    assert!(
        message.contains(&format!(
            "schema version 48 is not the clean runtime version {OPERATIONAL_SCHEMA_VERSION}"
        )) && message.contains("use a new empty data directory"),
        "{message}"
    );
    assert_eq!(std::fs::read(&path).unwrap(), bytes_before);
}

/// **The operator guide states the operational schema this build opens, and quotes
/// the refusal a data directory at any other schema meets as this build prints it.**
/// An operator reads the version and the recourse there, so a bump that leaves
/// either behind sends them to the wrong data directory. The refusal is the one a
/// directory one schema behind gets at open, its observed version written as the
/// guide's `<n>`; the guide is compared with its whitespace collapsed, since its
/// prose and its quote wrap.
///
/// **Would red if:** the guide stated another schema, or quoted the refusal with
/// another clean runtime version (watched: the quote left at 44 while the schema
/// line moved to 45).
#[test]
fn the_operator_guide_quotes_the_operational_schema_refusal_this_build_prints() {
    let guide = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../docs/product/operator-guide.md"
    ))
    .expect("the operator guide is readable");
    let guide = guide.split_whitespace().collect::<Vec<_>>().join(" ");
    let stated = format!("**The operational database is at schema {OPERATIONAL_SCHEMA_VERSION}**");
    assert!(
        guide.contains(&stated),
        "docs/product/operator-guide.md does not state {stated:?}"
    );

    let behind = OPERATIONAL_SCHEMA_VERSION - 1;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("operational.db");
    {
        let db = OperationalDb::open(&path).unwrap();
        db.debug_stamp_user_version(behind).unwrap();
    }
    let error = OperationalDb::open(&path).expect_err("a directory one schema behind is refused");
    let KataError::SchemaMigrationRequired(refusal) = error else {
        panic!("a schema refusal, not {error:?}");
    };
    let quoted = format!(
        "`{}`",
        refusal.replace(&format!("schema version {behind} "), "schema version <n> ")
    );
    assert!(
        guide.contains(&quoted),
        "docs/product/operator-guide.md does not quote the refusal this build prints, {quoted}"
    );
}

/// THE PRE-OPEN FILE PROBE, pinned on its own. The open path carries TWO
/// version gates — `refuse_noncurrent_operational_schema` by plain file I/O before
/// SQLite is opened, then `refuse_noncurrent_schema_on_conn` on the driver's view —
/// and every cell that only asserts "refused" passes with either one deleted,
/// because the other still refuses. What the FILE probe alone buys is
/// refuse-BEFORE-touch, so that is what this asserts: a behind stamp carried only by
/// an uncheckpointed WAL frame (the main header still reads current) is refused with
/// the main file and the WAL byte-identical and no `-shm` created. Without the probe
/// the conn gate still refuses, but only after SQLite has opened the file, built a
/// `-shm`, recovered the WAL and checkpointed it into the main file on close.
#[test]
fn a_behind_stamp_in_a_hot_wal_is_refused_before_sqlite_touches_the_directory() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("operational.db");
    build_hot_wal_fixture(&path, OPERATIONAL_SCHEMA_VERSION - 1);
    assert_eq!(
        header_user_version(&path),
        OPERATIONAL_SCHEMA_VERSION,
        "fixture precondition: the behind stamp is only in the uncheckpointed WAL"
    );
    let wal = sidecar(&path, "-wal");
    let before_db = std::fs::read(&path).unwrap();
    let before_wal = std::fs::read(&wal).unwrap();

    let error = OperationalDb::open(&path).expect_err("a behind stamp in a hot WAL is refused");
    assert!(
        error.to_string().contains(&format!(
            "schema version {} is not the clean runtime version {OPERATIONAL_SCHEMA_VERSION}",
            OPERATIONAL_SCHEMA_VERSION - 1
        )),
        "{error}"
    );
    assert_eq!(
        std::fs::read(&path).unwrap(),
        before_db,
        "the refusal wrote the db"
    );
    assert_eq!(
        std::fs::read(&wal).unwrap(),
        before_wal,
        "the refusal recovered the hot WAL instead of refusing it"
    );
    assert!(
        !sidecar(&path, "-shm").exists(),
        "the refusal created -shm: SQLite was opened before the version gate"
    );
}

/// THE CONN-LEVEL GATE, pinned on its own: the shape the file probe cannot
/// interpret. A HOT ROLLBACK JOURNAL holds page 1's pre-transaction image, so a main
/// file whose header reads CURRENT rolls back to a BEHIND stamp the moment SQLite
/// reads it — and the file probe reads only the main header and the WAL, never
/// `-journal`. The premise is asserted (the probe admits this file), so the refusal
/// below can only be `refuse_noncurrent_schema_on_conn`'s; without it the open
/// succeeds, because the column shape is current.
///
/// Refused, but NOT refuse-before-touch: SQLite's journal playback has rewritten the
/// main file by the time the driver reports the version. The operational plane runs in
/// WAL mode and never writes a rollback journal, so this shape reaches a main only
/// as a copied or restored file; the gate exists for it all the same.
#[test]
fn a_behind_stamp_restored_by_a_hot_rollback_journal_is_refused_by_the_driver_gate() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("operational.db");
    build_hot_rollback_journal_fixture(&path, OPERATIONAL_SCHEMA_VERSION - 1);
    assert_eq!(
        header_user_version(&path),
        OPERATIONAL_SCHEMA_VERSION,
        "fixture precondition: the main header reads current"
    );
    assert!(
        sidecar(&path, "-journal").exists(),
        "fixture precondition: a hot journal"
    );
    OperationalDb::refuse_noncurrent_file_schema(&path)
        .expect("premise: the file probe cannot see a rollback journal's page 1");

    let error = OperationalDb::open(&path)
        .expect_err("the driver gate must refuse the stamp the journal restores");
    assert!(
        matches!(error, KataError::SchemaMigrationRequired(_)),
        "{error:?}"
    );
    assert!(
        error.to_string().contains(&format!(
            "schema version {} is not the clean runtime version {OPERATIONAL_SCHEMA_VERSION}",
            OPERATIONAL_SCHEMA_VERSION - 1
        )),
        "{error}"
    );
    assert_eq!(
        header_user_version(&path),
        OPERATIONAL_SCHEMA_VERSION - 1,
        "the journal was played back, so the driver saw the behind stamp it refused"
    );
}

/// Build `path` + a HOT `-journal`: a real current-shape database in ROLLBACK mode
/// whose main file is stamped current while its journal holds page 1's previous image
/// stamped `journal_version`. The journal is copied out mid-transaction (after page 1
/// was journaled, before the commit deleted it) and the main file after the commit,
/// which is exactly the pair a crash between the main write and the journal delete
/// leaves. `synchronous = OFF` makes SQLite write the journal header's magic and a
/// "count records by size" record count up front instead of at the sync it skips, so
/// the copied journal is a valid one.
fn build_hot_rollback_journal_fixture(path: &Path, journal_version: i64) {
    let dir = path.parent().unwrap();
    let live = dir.join("journal-source.db");
    drop(OperationalDb::open(&live).unwrap());
    let conn = rusqlite::Connection::open(&live).unwrap();
    let mode: String = conn
        .query_row("PRAGMA journal_mode = DELETE", [], |row| row.get(0))
        .unwrap();
    assert_eq!(mode, "delete", "fixture: the source must leave WAL mode");
    conn.pragma_update(None, "user_version", journal_version)
        .unwrap();
    conn.pragma_update(None, "synchronous", "OFF").unwrap();
    conn.execute_batch("BEGIN IMMEDIATE").unwrap();
    conn.pragma_update(None, "user_version", OPERATIONAL_SCHEMA_VERSION)
        .unwrap();
    std::fs::copy(sidecar(&live, "-journal"), sidecar(path, "-journal")).unwrap();
    conn.execute_batch("COMMIT").unwrap();
    drop(conn);
    std::fs::copy(&live, path).unwrap();
    std::fs::remove_file(&live).unwrap();
}

fn index_plan(conn: &rusqlite::Connection, sql: &str) -> String {
    let mut stmt = conn.prepare(sql).unwrap();
    let rows = stmt
        .query_map([], |row| row.get::<_, String>(3))
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    rows.join(" | ")
}

// -- foreign-key actions retention depends on ---------------------------------

/// The foreign-key ACTIONS retention depends on, asserted on a FRESH database.
///
/// # Why this is not covered by anything else
///
/// [`validate_schema`] compares COLUMN SETS, exactly, and an `ON DELETE` action
/// is not a column. So these actions are invisible to the validator that runs on
/// every open: flipping any of them produces a database that validates cleanly,
/// stamps current, and means something different. This test proves the CREATE
/// batch produces them, which is the shape every install has.
///
/// [`validate_schema`]: kata_core::operational
#[test]
fn the_declared_foreign_key_actions_are_the_ones_retention_depends_on() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("operational.db");
    let _db = OperationalDb::open(&path).unwrap();
    let conn = raw_conn(&path);

    let action = |table: &str, column: &str| -> String {
        let mut stmt = conn
            .prepare(&format!(
                "SELECT \"table\", \"from\", on_delete FROM pragma_foreign_key_list('{table}')"
            ))
            .unwrap();
        stmt.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
            ))
        })
        .unwrap()
        .map(Result::unwrap)
        .find(|(parent, from, _)| parent == "programs" && from == column)
        .map_or_else(
            || panic!("{table}.{column} has no foreign key to programs at all"),
            |(_, _, on_delete)| on_delete,
        )
    };

    assert_eq!(
        action("event_inbox", "execution_id"),
        "CASCADE",
        "If this is NO ACTION the polarity is inverted: an accepted frame is DERIVED buffer \
         state whose authority already folded into `transitions`, so pinning an execution on it \
         refuses retention for a row nothing reads"
    );
    assert_eq!(action("event_inbox_watermark", "execution_id"), "CASCADE");
    assert_eq!(
        action("attempt_stop_requests", "execution_id"),
        "CASCADE",
        "CASCADE here is deliberate — a stop latch gates ONE execution's workspace \
         reclaim, so once the execution is gone the latch has no subject"
    );
    assert_eq!(
        action("forge_intents", "execution_id"),
        "CASCADE",
        "a forge intent is a fact about one execution's wire effects and goes with it"
    );
}

/// Every declared hot-path index exists, and the retained-input probe actually
/// uses the partial buffered-inbox index.
#[test]
fn operational_schema_declares_the_hot_path_indexes() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("operational.db");
    let _db = OperationalDb::open(&path).unwrap();
    let conn = raw_conn(&path);

    for index in OPERATIONAL_INDEXES {
        let exists: bool = conn
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE type = 'index' AND name = ?1)",
                params![index],
                |row| row.get(0),
            )
            .unwrap();
        assert!(exists, "declared index {index} is missing");
    }
    // Why each non-obvious index exists. A change to the declared set must
    // re-derive it from the query surfaces rather than bump the number.
    //
    // `idx_attempt_stop_requests_unacknowledged` is a PARTIAL index over
    // `attempt_stop_requests` `WHERE acknowledged_at_ms IS NULL`. It serves
    // exactly one query surface — `unacknowledged_stops`, the safety predicate
    // `require_terminal_lifecycle_for_parking` gates a destructive workspace
    // reclaim on — and it is partial for the same reason `idx_attempts_worker`
    // is: an acknowledged stop is settled and does not belong in an index whose
    // only reader asks which stops are outstanding. It keys on the table's own
    // `execution_id`, not on `attempt_id`: reaching the execution through an
    // inner join on `attempts` would make an orphaned stop invisible, so the
    // safety predicate would empty and parking would open.
    //
    // `idx_event_inbox_execution` and `idx_event_inbox_watermark_execution` serve
    // a FOREIGN-KEY CHILD SCAN and nothing else. Both inbox tables carry an
    // `execution_id` with `ON DELETE CASCADE`, and SQLite runs the child scan once
    // per deleted parent row — so without them an execution delete re-scans every
    // inbox row in the node PER DELETED EXECUTION, which is the same O(deletes x
    // inbox) shape `idx_cas_roots_owner` exists to avoid on its table. kata deletes
    // no execution in production today (the one `DELETE FROM programs` is the
    // test-support `debug_delete_execution`); the indexes keep any future retention
    // sweep off that shape. Neither is partial: unlike
    // `idx_attempt_stop_requests_unacknowledged`, a cascade has no settled subset
    // to exclude — every row is a candidate exactly once.
    //
    // The unique enrollment identity and the dispatch-domain attempt index key the
    // worker effect domain. The two partial active-row indexes serve only the boot
    // compatibility, residency, and integrity scans, and the partial due-cleanup
    // index serves the retry reader, so terminal and completed rows do not grow any
    // of those hot-path indexes.
    //
    // `idx_nix_environments_active` (`released_at_ms IS NULL`) serves
    // `active_environments`, the "which environments may still be bound?" question, and
    // `idx_nix_environments_unpromoted` (`root_promoted_at_ms IS NULL`) serves
    // `unpromoted_environments`, the boot reconciler's work list after a crash.
    // Both are partial for `idx_execution_lifecycle_active`'s reason: a released or
    // promoted environment is settled and does not belong in an index whose only reader
    // asks what is unfinished, so the scans stay proportional to live/unfinished rows
    // rather than to the node's environment history. Their use is pinned by
    // `EXPLAIN QUERY PLAN` in `operational_environments.rs`, not by existence alone.
    //
    // `idx_nix_environments_manifest_live` is AUTHORITY rather than a query hint: UNIQUE
    // over `manifest_object_id` where `released_at_ms IS NULL`. A manifest root's id
    // derives from `(node, NULL, nix_environment_manifest, object)`, so two
    // LIVE environments over one manifest would share a single `cas_roots` row and
    // releasing either would release the other's root. Partial on the live rows, so
    // re-declaring a manifest after release or delete still works.
    //
    // `idx_cas_roots_artifact_object` (partial, `(object_digest)` where the purpose
    // is `artifact_object`) serves `declare_capsule`'s mapping check, "does ANY root
    // name this object", and `idx_cas_roots_owner_artifact` (partial,
    // `(owner_execution_id, object_digest)`) serves `active_artifacts_for`, which joins
    // an execution's roots onto the rows their objects name. Two indexes and not one because the
    // two reads lead with different terms; the second's use is pinned by
    // `EXPLAIN QUERY PLAN` in `operational_artifacts.rs`, not by existence alone.
    //
    // `idx_artifacts_object` is AUTHORITY rather than a query hint: UNIQUE over
    // `object_id`. `ArtifactId` folds `(object, size, privacy)`, and object and size are
    // fixed by the bytes — so two distinct ids over one object differ in PRIVACY and
    // nothing else, and this index's refused set is exactly "the same bytes declared both
    // as a public artifact and as a private one", which discharges the private
    // classification through the public twin. An artifact row names no execution: two
    // executions holding one artifact are one row and two roots.
    //
    // `idx_capsules_environment` serves the nix_environments -> capsules foreign-key child
    // scan. The FK is NO ACTION, and a NO ACTION parent delete must still PROVE no child
    // references the row — without the index SQLite proves it by scanning every capsule
    // the node has declared. Not partial: like a cascade, every row is a candidate exactly
    // once.
    //
    // `idx_attempts_occurrence` serves the `occurrences -> attempts` NO ACTION parent
    // check — the same argument as `idx_capsules_environment`, one plane over.
    //
    // `idx_occurrences_execution` serves the `programs -> occurrences` CASCADE child scan.
    // It is deliberately kept EXPLICIT even though the three-column UNIQUE key leads with
    // the same column: the cascade is the one consumer that must not depend on the planner
    // preferring a wider index.
    //
    // `idx_occurrences_accepted_attempt` is AUTHORITY rather than a query hint, and its
    // refused set is NARROWER than the invariant it belongs to: UNIQUE over
    // `accepted_attempt_id` refuses one ATTEMPT accepting two OCCURRENCES, while "one
    // occurrence has one accepted outcome" is carried by the primary key plus
    // `accept_occurrence_outcome`'s write-once predicate. The three mechanisms are
    // falsified separately in `operational_occurrences.rs`, because a guarantee proved only
    // by a test that trips all three at once is wider than any of them.
    //
    // `idx_execution_evidence_execution` is `(execution_id, created_at_ms, evidence_id)`:
    // both the `programs -> execution_evidence` cascade child scan and the exact ORDER BY
    // `execution_evidence_records` issues, so an index stopping at `execution_id` would
    // leave the sort to a temp b-tree. `execution_evidence_claims` deliberately has NO
    // index: its composite PRIMARY KEY's implicit index already leads with `execution_id`,
    // so an explicit one would be a second copy of an index SQLite maintains anyway.
    //
    // `idx_attempts_worker_started` is proven USED by the start-deadline guard's own two
    // statements in `repo.rs`'s `start_overdue_plan_tests`.
    //
    // `idx_attempts_wait_due` is PARTIAL over `wait_deadline_ms IS NOT NULL`: the main
    // claim writes the deadline and the resolution clears it, so the index holds exactly
    // the outstanding main-resolved waits a due read needs.
    //
    // `idx_execution_work_tree_heads_artifact` serves the
    // `artifacts -> execution_work_tree_heads` NO ACTION child scan: refusing an
    // artifact's delete has to prove no head names it without a full-head scan
    // (the PRIMARY KEY leads with execution_id and cannot serve the predicate).
    //
    // `idx_execution_git_views_artifact` is the same NO ACTION child scan one table
    // over: `artifacts -> execution_git_views` refuses an artifact delete while a view
    // row names it, and the PRIMARY KEY again leads with execution_id.
    //
    // `idx_forge_intents_execution` is `(execution_id, seq)`: the
    // `programs -> forge_intents` cascade child scan and `last_performed_forge_push`'s
    // newest-first read of one execution's intents. An attempt's own intents and the
    // `attempts` foreign-key child scan ride the table's UNIQUE (attempt_id,
    // effect_index) index, so they need none.
    assert_eq!(
        OPERATIONAL_INDEXES.len(),
        36,
        "the declared index set changed; re-derive it from the repo query surfaces"
    );

    // The captured-prefix stage reader and retained worker obligation join now
    // have independent indexes; their query-plan regressions pin actual use.
    assert!(OPERATIONAL_INDEXES.contains(&"idx_transitions_stage_history"));
    assert!(OPERATIONAL_INDEXES.contains(&"idx_worker_dispatch_domain_attempt"));

    // The enrollment unique index is identity authority, not merely
    // a performance hint: dispatch-domain rows reference this exact key.
    let unique: i64 = conn.query_row(
        "SELECT \"unique\" FROM pragma_index_list('worker_effect_domains') WHERE name = 'idx_worker_effect_domain_enrollment'",
        [], |row| row.get(0),
    ).unwrap();
    assert_eq!(
        unique, 1,
        "enrollment identity must be unique for its FK consumers"
    );
    let columns: Vec<String> = conn.prepare("SELECT name FROM pragma_index_info('idx_worker_effect_domain_enrollment') ORDER BY seqno").unwrap()
        .query_map([], |row| row.get(0)).unwrap().collect::<Result<_, _>>().unwrap();
    assert_eq!(
        columns,
        ["enrollment_id"],
        "the identity index targets the referenced enrollment, not the connection label"
    );

    // `idx_cas_roots_owner` serves the `programs -> cas_roots` cascade's child scan,
    // proven on the scan's own predicate rather than merely declared.
    let plan = index_plan(
        &conn,
        "EXPLAIN QUERY PLAN SELECT 1 FROM cas_roots WHERE owner_execution_id = x'00'",
    );
    assert!(
        plan.contains("idx_cas_roots_owner"),
        "the per-execution root child scan must use its index: {plan}"
    );

    let plan: String = conn
        .query_row(
            "EXPLAIN QUERY PLAN
                 SELECT 1 FROM event_inbox WHERE accepted = 0",
            [],
            |row| row.get(3),
        )
        .unwrap();
    assert!(
        plan.contains("idx_event_inbox_buffered"),
        "the recovery population's retained-input probe must use the partial buffered \
         index, got: {plan}"
    );
}

// -- repo: happy path + converge-or-refuse ----------------------------------

#[test]
fn operational_submit_execution_admits_and_projects() {
    let db = OperationalDb::open_in_memory().unwrap();
    let exec = Ulid::new();
    let seq = submit(&db, exec, 1);
    assert_eq!(seq, 1, "first transition is seq 1");
    let projection = db.execution_projection(exec).unwrap().unwrap();
    assert_eq!(
        projection,
        ExecutionProjectionRow {
            state: "admitting".to_string(),
            source_seq: 1
        }
    );
    assert_eq!(db.debug_count("programs").unwrap(), 1);
    assert_eq!(db.debug_count("invocations").unwrap(), 1);
    assert_eq!(db.debug_count("execution_lifecycle").unwrap(), 1);
}

/// A re-submitted execution is a TYPED `AlreadySubmitted`, not a raw primary-key
/// error; a re-submission with a different program or admission digest refuses.
#[test]
fn operational_resubmit_is_typed_already_submitted_and_divergence_refuses() {
    let db = OperationalDb::open_in_memory().unwrap();
    let exec = Ulid::new();
    assert_eq!(
        db.submit_execution(exec, &program(1), &invocation(1))
            .unwrap(),
        SubmitOutcome::Submitted { seq: 1 }
    );
    let before_seq = db.debug_reserved_seq().unwrap();

    let again = db
        .submit_execution(exec, &program(1), &invocation(1))
        .unwrap();
    assert_eq!(again, SubmitOutcome::AlreadySubmitted);
    assert_eq!(again.submitted_seq(), None);
    assert_eq!(
        db.debug_reserved_seq().unwrap(),
        before_seq,
        "an idempotent re-submission reserves no sequence"
    );
    assert_eq!(db.debug_count("programs").unwrap(), 1);

    // A different checked program under the same execution id refuses.
    let program_divergence = db
        .submit_execution(exec, &program(2), &invocation(1))
        .unwrap_err();
    assert!(
        program_divergence.to_string().contains("program hash"),
        "{program_divergence:?}"
    );
    // A different resolved typed-input set under the same execution id refuses.
    let digest_divergence = db
        .submit_execution(exec, &program(1), &invocation(2))
        .unwrap_err();
    assert!(
        digest_divergence.to_string().contains("admission digest"),
        "{digest_divergence:?}"
    );
}

#[test]
fn operational_fire_schedule_is_idempotent_on_double_fire() {
    let db = OperationalDb::open_in_memory().unwrap();
    let mut spec = schedule("sched-1");
    spec.cursor_ms = 100;
    db.install_schedule(&spec, &program(1), &invocation(1))
        .unwrap();

    let first = db
        .fire_schedule("sched-1", 100, Ulid::new(), 2000, None)
        .unwrap();
    assert!(matches!(first, FireOutcome::Fired { .. }), "{first:?}");

    // Same fire instant redelivered: the firing PK makes it a no-op — no second
    // execution. This is the eliminated half-commit double-fire window.
    let again = db
        .fire_schedule("sched-1", 100, Ulid::new(), 3000, None)
        .unwrap();
    assert_eq!(again, FireOutcome::AlreadyFired);
    assert_eq!(db.debug_count("schedule_firings").unwrap(), 1);
    assert_eq!(db.debug_count("programs").unwrap(), 1);
    assert_eq!(
        db.debug_schedule_cursor_ms("sched-1").unwrap(),
        Some(3000),
        "an AlreadyFired claim must STILL advance the cursor: returning early without \
         advancing is what wedges a schedule into a permanent spin"
    );

    // A new instant fires a fresh execution.
    let next = db
        .fire_schedule("sched-1", 3000, Ulid::new(), 4000, None)
        .unwrap();
    assert!(matches!(next, FireOutcome::Fired { .. }), "{next:?}");
    assert_eq!(db.debug_count("schedule_firings").unwrap(), 2);
}

#[test]
fn import_quarantine_refuses_fresh_admission_attempt_and_schedule_without_sql_mutation() {
    let home = tempfile::tempdir().unwrap();
    let path = home.path().join("operational.db");
    let db = OperationalDb::open(&path).unwrap();
    let execution = Ulid::new();
    submit(&db, execution, 1);
    claim(&db, execution);
    let mut spec = schedule("quarantined");
    spec.cursor_ms = 100;
    db.install_schedule(&spec, &program(2), &invocation(2))
        .unwrap();
    let raw = raw_conn(&path);
    raw.execute(
        "INSERT INTO recovery_imports VALUES(?1,'source','target',?2,NULL)",
        params![Ulid::new().to_bytes().as_slice(), "a".repeat(64)],
    )
    .unwrap();
    let counts = || {
        ["programs", "attempts", "transitions"].map(|table| {
            raw.query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
                row.get::<_, i64>(0)
            })
            .unwrap()
        })
    };
    let before = counts();
    let outcomes = [
        db.submit_execution(Ulid::new(), &program(3), &invocation(3))
            .map(|_| ()),
        db.claim_attempt(
            execution,
            Ulid::new(),
            &AttemptClaimSpec {
                stage_id: "fresh-stage".into(),
                assignment_json: br#"{"capsule":{"stage_name":"fixture"}}"#.to_vec(),
                initial_state: "pending".into(),
                run_ordinal: 0,
                worker_id: Some("w-1".into()),
                occurrence: OccurrenceBinding::for_test(execution, "fresh-stage"),
            },
        )
        .map(|_| ()),
        db.fire_schedule("quarantined", 100, Ulid::new(), 2000, None)
            .map(|_| ()),
    ];
    for result in outcomes {
        let error = result.expect_err("pending import must fence every authority writer");
        assert!(error.to_string().contains("quarantine"), "{error}");
    }
    assert_eq!(
        counts(),
        before,
        "independent SQL observes no admission, attempt or transition writes"
    );
    drop(db);
    assert!(
        OperationalDb::open(&path)
            .unwrap()
            .require_imports_reconciled()
            .is_err()
    );
}

#[test]
fn import_operator_authorization_is_subject_bound_atomic_and_does_not_release_the_import() {
    use kata_core::operational::{ImportDecision, ImportDecisionPacket, ImportSubjectDecision};
    let home = tempfile::tempdir().unwrap();
    let path = home.path().join("operational.db");
    let db = OperationalDb::open(&path).unwrap();
    let execution = Ulid::new();
    submit(&db, execution, 1);
    claim(&db, execution);
    let raw = raw_conn(&path);
    let artifact_id = Ulid::new();
    raw.execute(
        "INSERT INTO recovery_imports VALUES(?1,'source','target',?2,NULL)",
        params![artifact_id.to_bytes().as_slice(), "a".repeat(64)],
    )
    .unwrap();
    raw.execute(
        "INSERT INTO recovery_import_subjects VALUES(?1,'retained-execution',NULL)",
        [artifact_id.to_bytes().as_slice()],
    )
    .unwrap();
    let decision = ImportSubjectDecision {
        subject_key: "retained-execution".into(),
        decision: ImportDecision::ExecutionResumeApproved,
        operator: "fixture-operator".into(),
        reason: "Explicit target root authorization".into(),
    };
    let mut unrelated = decision.clone();
    unrelated.subject_key = "unrelated".into();
    assert!(
        db.apply_import_decisions(&ImportDecisionPacket {
            artifact_id,
            decisions: vec![decision.clone(), unrelated]
        })
        .is_err()
    );
    let pending: i64 = raw
        .query_row(
            "SELECT COUNT(*) FROM recovery_import_subjects WHERE decision_json IS NULL",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(
        pending, 1,
        "a later invalid subject rolls back the earlier valid decision"
    );
    db.apply_import_decisions(&ImportDecisionPacket {
        artifact_id,
        decisions: vec![decision],
    })
    .unwrap();
    let authorization: String = raw
        .query_row(
            "SELECT decision_json FROM recovery_import_subjects",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&authorization).unwrap()["operator"],
        "fixture-operator"
    );
    assert!(
        db.require_imports_reconciled().is_err(),
        "operator authorization alone does not release the import"
    );
}

/// The stamped schedule columns (`trigger` / `on_missed` / `submit_pack`) persist,
/// an identical re-install is idempotent and PRESERVES the cursor, and a divergent
/// re-install refuses (schedule immutability).
#[test]
fn operational_install_schedule_converges_or_refuses() {
    let db = OperationalDb::open_in_memory().unwrap();
    let spec = schedule("nightly");
    assert_eq!(
        db.install_schedule(&spec, &program(1), &invocation(1))
            .unwrap(),
        InstallOutcome::Installed
    );
    // Advance the cursor as a fire would.
    db.fire_schedule("nightly", 1_000, Ulid::new(), 5_000, None)
        .unwrap();

    // Re-installing the IDENTICAL schedule is an idempotent no-op that preserves
    // the durable cursor.
    assert_eq!(
        db.install_schedule(&spec, &program(1), &invocation(1))
            .unwrap(),
        InstallOutcome::AlreadyInstalled
    );
    assert_eq!(db.debug_count("schedules").unwrap(), 1);
    assert_eq!(
        db.debug_schedule_cursor_ms("nightly").unwrap(),
        Some(5_000),
        "an idempotent re-install must not rewind the durable cursor"
    );
    assert_eq!(
        db.debug_schedule_columns("nightly").unwrap(),
        Some((
            spec.submit_pack.clone(),
            spec.trigger.clone(),
            spec.on_missed.as_str().to_string()
        )),
        "the stamped trigger / on_missed / submit_pack columns must round-trip"
    );

    // A different trigger (or policy, or submit target) is a refusal.
    let mut divergent = spec.clone();
    divergent.trigger = "{\"cron\":{\"expr\":\"0 2 * * *\"}}".to_string();
    let error = db
        .install_schedule(&divergent, &program(1), &invocation(1))
        .unwrap_err();
    assert!(error.to_string().contains("different binding"), "{error:?}");

    // A different PINNED PROGRAM is likewise a refusal — and the divergence can
    // only be expressed by presenting a different program, because
    // `ScheduleInstall` carries no caller-supplied hash to disagree with it.
    let rebound = db.install_schedule(&spec, &program(9), &invocation(1));
    assert!(
        rebound.is_err(),
        "rebinding a schedule's pinned program must refuse an install: {rebound:?}"
    );
}

/// The structural half: the schedule pin is DERIVED from the program record,
/// so an incoherent row (`bound_program_hash = [7; 32]` beside a
/// `{"program":1}` payload) has no
/// argument left to enter through.
#[test]
fn operational_install_schedule_derives_the_pin_from_the_program_record() {
    let db = OperationalDb::open_in_memory().unwrap();
    db.install_schedule(&schedule("nightly"), &program(4), &invocation(4))
        .unwrap();

    let row = db.installed_schedule("nightly").unwrap().unwrap();
    assert_eq!(
        row.bound_program_hash,
        program(4).program_hash,
        "the pin must be the PROGRAM RECORD's hash, never a caller-supplied field"
    );
    assert_eq!(
        row.bound_admission_digest,
        invocation(4).admission_digest.0,
        "the pinned digest must be the INVOCATION RECORD's digest"
    );

    // And the pinned bytes are exactly what a fire will submit.
    let (pinned_program, pinned_invocation) =
        db.pinned_schedule_admission("nightly").unwrap().unwrap();
    assert_eq!(pinned_program.program_json, program(4).program_json);
    assert_eq!(pinned_program.program_hash, program(4).program_hash);
    assert_eq!(pinned_program.schema_version, program(4).schema_version);
    assert_eq!(
        pinned_invocation.invocation_json,
        invocation(4).invocation_json
    );
    assert_eq!(pinned_invocation.kind, invocation(4).kind);
    assert_eq!(
        pinned_invocation.schema_version,
        invocation(4).schema_version
    );
}

/// The stored pin must BIND its own bytes. A digest that does not is refused
/// at install; a FORGED payload written around the typed API is refused at fire,
/// before anything is admitted.
#[test]
fn operational_schedule_refuses_a_pin_that_does_not_bind_its_bytes() {
    let db = OperationalDb::open_in_memory().unwrap();

    let mut forged = invocation(1);
    forged.admission_digest = AdmissionDigest(digest(9));
    let error = db
        .install_schedule(&schedule("nightly"), &program(1), &forged)
        .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("does not bind the presented invocation bytes"),
        "{error:?}"
    );

    db.install_schedule(&schedule("nightly"), &program(1), &invocation(1))
        .unwrap();
    db.debug_forge_schedule_pin(
        "nightly",
        &program(2).program_json,
        &invocation(2).invocation_json,
    )
    .unwrap();

    let error = db
        .fire_schedule("nightly", 1_000, Ulid::new(), 2_000, None)
        .unwrap_err();
    assert!(
        error.to_string().contains("do not bind"),
        "a forged pin must refuse the fire, not silently submit it: {error:?}"
    );
    assert_eq!(
        db.debug_count("programs").unwrap(),
        0,
        "a refused fire admits nothing"
    );
    assert_eq!(
        db.debug_count("schedule_firings").unwrap(),
        0,
        "a refused fire claims no instant"
    );
    assert_eq!(
        db.debug_schedule_cursor_ms("nightly").unwrap(),
        Some(1_000),
        "a refused fire does not advance the cursor"
    );
}

/// The fire path submits THE PINNED PROGRAM. After the signature change that is a
/// compile-time guarantee (`fire_schedule` takes no program), so what this asserts
/// is the observable consequence: the pinned bytes are what land in `programs`.
#[test]
fn operational_fire_schedule_submits_the_pinned_program() {
    let db = OperationalDb::open_in_memory().unwrap();
    db.install_schedule(&schedule("nightly"), &program(5), &invocation(5))
        .unwrap();

    let execution_id = Ulid::new();
    db.fire_schedule("nightly", 1_000, execution_id, 2_000, None)
        .unwrap();

    let view = kata_core::operational::ExecutionLifecycleView::new(std::sync::Arc::new(db));
    let stored = view.program_json(execution_id).unwrap().unwrap();
    assert_eq!(
        stored,
        program(5).program_json,
        "the execution must hold its own immutable copy of the PINNED program"
    );
    let invocation_view = view.invocation(execution_id).unwrap().unwrap();
    assert_eq!(
        invocation_view.invocation_json,
        invocation(5).invocation_json
    );
    assert_eq!(
        invocation_view.admission_digest,
        invocation(5).admission_digest
    );
}

/// `fire_instant` is the DUE cursor, never `now`. A fresh claim at any other
/// instant refuses — with `now_ms` the claim key changes on every retry and the
/// firing primary key provides zero idempotency.
#[test]
fn operational_fire_schedule_refuses_a_claim_that_is_not_the_due_instant() {
    let db = OperationalDb::open_in_memory().unwrap();
    db.install_schedule(&schedule("nightly"), &program(1), &invocation(1))
        .unwrap();

    // 1_000 is the due cursor; 1_234 is a plausible wall-clock `now`.
    let error = db
        .fire_schedule("nightly", 1_234, Ulid::new(), 2_000, None)
        .unwrap_err();
    assert!(
        error.to_string().contains("must claim the DUE instant"),
        "{error:?}"
    );
    assert_eq!(db.debug_count("schedule_firings").unwrap(), 0);
    assert_eq!(db.debug_count("programs").unwrap(), 0);

    // And a fire that would not move the cursor past the instant it claims is
    // refused before anything is written: that is the permanent-spin wedge.
    let error = db
        .fire_schedule("nightly", 1_000, Ulid::new(), 1_000, None)
        .unwrap_err();
    assert!(
        error.to_string().contains("advance STRICTLY past"),
        "{error:?}"
    );
    assert_eq!(db.debug_count("schedule_firings").unwrap(), 0);
}

/// A backward wall-clock step cannot move the cursor backwards. The cursor
/// assignment is `MAX`, so an NTP step that makes the next occurrence earlier than
/// the durable cursor leaves the cursor where it was rather than rewinding it onto
/// an already-claimed instant.
#[test]
fn operational_a_backward_clock_step_cannot_move_the_schedule_cursor_backwards() {
    let db = OperationalDb::open_in_memory().unwrap();
    db.install_schedule(&schedule("nightly"), &program(1), &invocation(1))
        .unwrap();
    db.fire_schedule("nightly", 1_000, Ulid::new(), 9_000, None)
        .unwrap();
    assert_eq!(db.debug_schedule_cursor_ms("nightly").unwrap(), Some(9_000));

    // The clock steps back: the sweep's `next_after(now)` now lands before the
    // durable cursor. A skip must not rewind it.
    db.skip_schedule_to("nightly", 2_000).unwrap();
    assert_eq!(
        db.debug_schedule_cursor_ms("nightly").unwrap(),
        Some(9_000),
        "a skip is monotone"
    );

    // Nor may a redelivered claim for an already-spent instant.
    assert_eq!(
        db.fire_schedule("nightly", 1_000, Ulid::new(), 2_000, None)
            .unwrap(),
        FireOutcome::AlreadyFired
    );
    assert_eq!(db.debug_schedule_cursor_ms("nightly").unwrap(), Some(9_000));
}

/// The fire's `submitted` transition carries the schedule provenance, so the
/// link from a retained execution back to the schedule that fired it survives
/// `remove_schedule`'s CASCADE of the `schedule_firings` row.
#[test]
fn operational_remove_schedule_cascades_firings_and_leaves_provenance_intact() {
    let db = OperationalDb::open_in_memory().unwrap();
    db.install_schedule(&schedule("nightly"), &program(1), &invocation(1))
        .unwrap();
    let execution_id = Ulid::new();
    db.fire_schedule("nightly", 1_000, execution_id, 2_000, None)
        .unwrap();

    let firings = db.schedule_firings("nightly").unwrap();
    assert_eq!(firings.len(), 1);
    assert_eq!(firings[0].fire_instant, 1_000);
    assert_eq!(firings[0].execution_id(), Some(execution_id));

    let payload = db
        .debug_transition_payload(execution_id, "submitted")
        .unwrap();
    let payload: serde_json::Value = serde_json::from_slice(&payload).unwrap();
    assert_eq!(payload["source"], "schedule");
    assert_eq!(payload["schedule_id"], "nightly");
    assert_eq!(payload["fire_instant"], 1_000);

    assert!(db.remove_schedule("nightly").unwrap());
    assert!(!db.remove_schedule("nightly").unwrap());
    assert_eq!(
        db.debug_count("schedule_firings").unwrap(),
        0,
        "the firing history CASCADEs with its schedule"
    );
    assert_eq!(
        db.debug_count("programs").unwrap(),
        1,
        "the executions the schedule fired are untouched"
    );
    // The provenance is still readable from the RETAINED transition chain.
    let payload = db
        .debug_transition_payload(execution_id, "submitted")
        .unwrap();
    let payload: serde_json::Value = serde_json::from_slice(&payload).unwrap();
    assert_eq!(payload["schedule_id"], "nightly");
}

/// `rebind_schedule` is the ONE function that may change a pin. It preserves
/// the durable cursor when the trigger is unchanged, re-anchors when it changed,
/// and leaves an execution already fired from the PREVIOUS binding untouched.
#[test]
fn operational_rebind_schedule_replaces_the_pin_and_respects_the_cursor_rule() {
    let db = OperationalDb::open_in_memory().unwrap();
    let spec = schedule("nightly");
    db.install_schedule(&spec, &program(1), &invocation(1))
        .unwrap();
    let fired_from_old_binding = Ulid::new();
    db.fire_schedule("nightly", 1_000, fired_from_old_binding, 5_000, None)
        .unwrap();

    // Rebinding an unchanged binding is a no-op.
    assert_eq!(
        db.rebind_schedule(&spec, &program(1), &invocation(1))
            .unwrap(),
        RebindOutcome::Unchanged
    );

    // A new pin under an UNCHANGED trigger preserves the cursor.
    assert_eq!(
        db.rebind_schedule(&spec, &program(2), &invocation(2))
            .unwrap(),
        RebindOutcome::Rebound {
            cursor_ms: 5_000,
            trigger_changed: false
        }
    );
    let row = db.installed_schedule("nightly").unwrap().unwrap();
    assert_eq!(row.bound_program_hash, program(2).program_hash);
    assert_eq!(row.cursor_ms, 5_000);

    // A CHANGED trigger re-anchors to the presented cursor.
    let mut retriggered = spec.clone();
    retriggered.trigger = "{\"cron\":{\"expr\":\"0 2 * * *\"}}".to_string();
    retriggered.cursor_ms = 42_000;
    assert_eq!(
        db.rebind_schedule(&retriggered, &program(2), &invocation(2))
            .unwrap(),
        RebindOutcome::Rebound {
            cursor_ms: 42_000,
            trigger_changed: true
        }
    );
    assert_eq!(
        db.debug_schedule_cursor_ms("nightly").unwrap(),
        Some(42_000)
    );

    // The execution fired from the PREVIOUS binding still holds its own copy.
    let view = kata_core::operational::ExecutionLifecycleView::new(std::sync::Arc::new(db));
    assert_eq!(
        view.program_json(fired_from_old_binding).unwrap().unwrap(),
        program(1).program_json,
        "a rebind must not alter an execution already fired from the prior binding"
    );
}

/// A rebind of a schedule that is not installed refuses — a rebind is not an
/// install, and the two are kept distinct so exactly ONE function in the workspace
/// can change a pin.
#[test]
fn operational_rebind_schedule_refuses_an_uninstalled_schedule() {
    let db = OperationalDb::open_in_memory().unwrap();
    let error = db
        .rebind_schedule(&schedule("ghost"), &program(1), &invocation(1))
        .unwrap_err();
    assert!(
        error.to_string().contains("it is not installed"),
        "{error:?}"
    );
}

/// Fail-safe polarity: the dangerous case is the EMPTY database. An absent
/// schedule row must refuse the fire, never fall through to "unclaimed".
#[test]
fn operational_fire_schedule_fails_closed_on_an_absent_schedule() {
    let db = OperationalDb::open_in_memory().unwrap();
    let error = db
        .fire_schedule("never-installed", 1_000, Ulid::new(), 2_000, None)
        .unwrap_err();
    assert!(
        error.to_string().contains("it is not installed"),
        "{error:?}"
    );
    assert_eq!(db.debug_count("schedule_firings").unwrap(), 0);
    assert_eq!(db.debug_count("programs").unwrap(), 0);
}

#[test]
fn operational_dispatch_attempt_writes_attempt_and_command() {
    let db = OperationalDb::open_in_memory().unwrap();
    let exec = Ulid::new();
    submit(&db, exec, 1);
    let attempt = AttemptClaimSpec {
        stage_id: "stage-a".to_string(),
        initial_state: "pending".to_string(),
        assignment_json: b"{\"capsule\":{\"stage_name\":\"fixture\",\"assignment\":true}}".to_vec(),
        run_ordinal: 0,
        worker_id: Some("w-1".to_string()),
        occurrence: OccurrenceBinding::for_test(exec, "stage-a"),
    };
    let command = CommandSpec {
        command_json: b"{\"cmd\":true}".to_vec(),
    };
    let seq = db
        .dispatch_attempt(exec, Ulid::new(), Ulid::new(), &attempt, &command)
        .unwrap();
    assert_eq!(db.debug_count("attempts").unwrap(), 1);
    assert_eq!(db.debug_count("attempt_commands").unwrap(), 1);

    // The fused door is claim + dispatch: it folds the ATTEMPT scope only (a stage
    // transition never folds — the schema's CHECK — and there is no stage projection).
    let attempts = db.attempt_projections(exec).unwrap();
    assert_eq!(
        attempts,
        vec![AttemptProjectionRow {
            stage_id: "stage-a".to_string(),
            attempt_ordinal: 0,
            state: "dispatched".to_string(),
            source_seq: seq
        }]
    );
}

#[test]
fn operational_accept_incoming_event_dedupes_and_refuses_divergence() {
    let db = OperationalDb::open_in_memory().unwrap();
    let exec = Ulid::new();
    submit(&db, exec, 1);
    let attempt_id = claim(&db, exec);
    let stream = b"stream-1";

    let accepted = db
        .accept_incoming_event(exec, attempt_id, stream, 1, digest(0xAA), "running", b"{}")
        .unwrap();
    assert!(
        matches!(accepted, EventAcceptance::Accepted { .. }),
        "{accepted:?}"
    );

    // Same slot, same digest -> idempotent ACK, no new fact.
    let before_seq = db.debug_reserved_seq().unwrap();
    let ack = db
        .accept_incoming_event(exec, attempt_id, stream, 1, digest(0xAA), "running", b"{}")
        .unwrap();
    assert_eq!(ack, EventAcceptance::IdempotentAck);
    assert_eq!(
        db.debug_reserved_seq().unwrap(),
        before_seq,
        "ACK reserves no seq"
    );

    // Same slot, DIFFERENT digest -> typed divergence refusal.
    let divergence = db
        .accept_incoming_event(exec, attempt_id, stream, 1, digest(0xBB), "running", b"{}")
        .unwrap_err();
    let message = divergence.to_string();
    assert!(
        message.contains("accepted_event_content") && message.contains("convergence violated"),
        "divergence must name the relation: {message}"
    );

    // A gap above the watermark is refused (buffering is the inbox layer's job).
    let gap = db
        .accept_incoming_event(exec, attempt_id, stream, 3, digest(0xCC), "running", b"{}")
        .unwrap_err();
    assert!(matches!(gap, KataError::Validation(_)), "gap: {gap:?}");

    // The next contiguous event accepts and advances.
    let next = db
        .accept_incoming_event(exec, attempt_id, stream, 2, digest(0xDD), "running", b"{}")
        .unwrap();
    assert!(matches!(next, EventAcceptance::Accepted { .. }), "{next:?}");
    assert_eq!(db.debug_count("event_inbox").unwrap(), 2);
}

/// A root id BINDS to exactly one object.
///
/// `root_id` is DERIVED from `(owner, purpose, object)`, so ONE
/// caller-supplied `root_id` with TWO object digests is unconstructible: two
/// digests are two roots. The property is therefore asserted where it is
/// falsifiable — the ids differ, so the second root cannot overwrite the first's
/// binding — and the converge-or-refuse arm is proven separately against a FORGED
/// stored row in `cas_root_ownership.rs`, which is the only way a disagreeing
/// row can exist.
#[test]
fn operational_cas_root_ids_bind_to_exactly_one_object() {
    let exec = Ulid::new();
    let root = |object_digest: u8| {
        CasRootSpec::for_object(
            &receipt(object_digest),
            CasRootOwner::Execution(exec),
            "output",
        )
    };
    assert_ne!(
        root(0x22).root_id(),
        root(0x33).root_id(),
        "a derived root id must separate two objects under one purpose"
    );
}

#[test]
fn operational_dynamic_child_consumes_bound_idempotently() {
    let db = OperationalDb::open_in_memory().unwrap();
    let parent = Ulid::new();
    submit(&db, parent, 1);
    let child = Ulid::new();

    let spawned = db
        .dynamic_child(parent, child, &program(2), &invocation(2), b"bound-1")
        .unwrap();
    assert!(
        matches!(spawned, ClaimOutcome::Recorded { .. }),
        "{spawned:?}"
    );
    assert!(db.execution_projection(child).unwrap().is_some());

    // The same bound cannot be consumed twice.
    let again = db
        .dynamic_child(parent, Ulid::new(), &program(3), &invocation(3), b"bound-1")
        .unwrap();
    assert_eq!(again, ClaimOutcome::AlreadyRecorded);
    // Only one child execution exists (parent + one child = 2 programs).
    assert_eq!(db.debug_count("programs").unwrap(), 2);

    // The bound is READABLE, which is what makes `AlreadyRecorded`
    // actionable: it names the child that won rather than only saying one did.
    assert_eq!(
        db.dynamic_child_bound(b"bound-1").unwrap(),
        Some(child),
        "the spent bound resolves to the child its own transaction submitted"
    );
    assert_eq!(
        db.dynamic_child_bound(b"bound-never-consumed").unwrap(),
        None,
        "an unconsumed bound resolves to nothing"
    );
    assert!(
        db.dynamic_child_bound(b"").is_err(),
        "an empty bound key is refused on the read side too, matching the writer"
    );
}

/// The bound is not global: two parents, or one parent's two stages, get
/// independent bounds. A reader that ignored the key would hand one stage's child
/// to another.
#[test]
fn operational_dynamic_child_bounds_are_independent() {
    let db = OperationalDb::open_in_memory().unwrap();
    let first_parent = Ulid::new();
    let second_parent = Ulid::new();
    submit(&db, first_parent, 1);
    submit(&db, second_parent, 2);
    let first_child = Ulid::new();
    let second_child = Ulid::new();

    db.dynamic_child(
        first_parent,
        first_child,
        &program(3),
        &invocation(3),
        b"bound-a",
    )
    .unwrap();
    db.dynamic_child(
        second_parent,
        second_child,
        &program(4),
        &invocation(4),
        b"bound-b",
    )
    .unwrap();

    assert_eq!(
        db.dynamic_child_bound(b"bound-a").unwrap(),
        Some(first_child)
    );
    assert_eq!(
        db.dynamic_child_bound(b"bound-b").unwrap(),
        Some(second_child)
    );
    assert_ne!(first_child, second_child);
}

/// A TERMINAL parent cannot consume a spawn bound. This is the chain terminal
/// latch reached through `dynamic_child`, and it is the property that stops a
/// finished execution from launching work nothing will collect.
#[test]
fn operational_dynamic_child_is_refused_after_the_parent_terminalizes() {
    let db = OperationalDb::open_in_memory().unwrap();
    let parent = Ulid::new();
    submit(&db, parent, 1);
    db.mark_running(parent).unwrap();
    // Below: while the parent is live the same call SUCCEEDS, so the refusal
    // afterwards is about terminality and nothing else.
    let live_child = Ulid::new();
    db.dynamic_child(
        parent,
        live_child,
        &program(2),
        &invocation(2),
        b"bound-live",
    )
    .unwrap();

    db.begin_terminalization(parent, LifecycleState::Completed, b"{}")
        .unwrap();
    db.finish_terminalization(parent).unwrap();

    let error = db
        .dynamic_child(
            parent,
            Ulid::new(),
            &program(3),
            &invocation(3),
            b"bound-after-terminal",
        )
        .expect_err("a terminal parent must not consume a new spawn bound");
    assert!(
        error.to_string().contains("terminal"),
        "the refusal must name the parent's terminality: {error}"
    );
    assert_eq!(
        db.dynamic_child_bound(b"bound-after-terminal").unwrap(),
        None,
        "the refused bound stays unconsumed"
    );
    // The bound spent while the parent was live is still readable afterwards.
    assert_eq!(
        db.dynamic_child_bound(b"bound-live").unwrap(),
        Some(live_child)
    );
}

// -- repo: atomicity crash matrix (no partial fact, no sequence hole) --------

/// Assert a method armed with a pre-commit fault leaves NO fact and NO hole,
/// then succeeds cleanly on retry with the very next sequence.
fn assert_rolls_back_cleanly(
    db: &OperationalDb,
    tables: &[&str],
    before_counts: &[i64],
    before_seq: i64,
) {
    for (table, before) in tables.iter().zip(before_counts) {
        assert_eq!(
            db.debug_count(table).unwrap(),
            *before,
            "table {table} gained a partial fact across a rolled-back transaction"
        );
    }
    assert_eq!(
        db.debug_reserved_seq().unwrap(),
        before_seq,
        "a rolled-back transaction burned a transition sequence (hole)"
    );
}

#[test]
fn operational_atomicity_submit_execution_rolls_back_with_no_partial_fact_or_hole() {
    let db = OperationalDb::open_in_memory().unwrap();
    let exec = Ulid::new();
    let tables = [
        "programs",
        "invocations",
        "execution_lifecycle",
        "transitions",
    ];
    let before: Vec<i64> = tables.iter().map(|t| db.debug_count(t).unwrap()).collect();

    db.arm_commit_fault();
    let error = db
        .submit_execution(exec, &program(1), &invocation(1))
        .unwrap_err();
    assert!(matches!(error, KataError::Storage(_)), "{error:?}");
    assert_rolls_back_cleanly(&db, &tables, &before, 0);

    // Retry without the fault succeeds and takes seq 1 (no hole).
    assert_eq!(submit(&db, exec, 1), 1);
}

#[test]
fn operational_atomicity_fire_schedule_rolls_back_with_no_partial_fact_or_hole() {
    let db = OperationalDb::open_in_memory().unwrap();
    let mut spec = schedule("s");
    spec.cursor_ms = 100;
    db.install_schedule(&spec, &program(1), &invocation(1))
        .unwrap();
    let tables = ["schedule_firings", "programs", "transitions"];
    let before: Vec<i64> = tables.iter().map(|t| db.debug_count(t).unwrap()).collect();

    db.arm_commit_fault();
    let error = db
        .fire_schedule("s", 100, Ulid::new(), 200, None)
        .unwrap_err();
    assert!(matches!(error, KataError::Storage(_)), "{error:?}");
    assert_rolls_back_cleanly(&db, &tables, &before, 0);
    assert_eq!(
        db.debug_schedule_cursor_ms("s").unwrap(),
        Some(100),
        "an aborted fire must not leave the cursor advanced past an unclaimed instant"
    );

    // The firing never persisted, so the same instant fires cleanly now.
    let fired = db.fire_schedule("s", 100, Ulid::new(), 200, None).unwrap();
    assert!(matches!(fired, FireOutcome::Fired { .. }), "{fired:?}");
}

#[test]
fn operational_atomicity_dispatch_attempt_rolls_back_with_no_partial_fact_or_hole() {
    let db = OperationalDb::open_in_memory().unwrap();
    let exec = Ulid::new();
    let base_seq = submit(&db, exec, 1);
    let tables = ["attempts", "attempt_commands"];
    let before: Vec<i64> = tables.iter().map(|t| db.debug_count(t).unwrap()).collect();

    let attempt = AttemptClaimSpec {
        stage_id: "stage-a".to_string(),
        initial_state: "pending".to_string(),
        assignment_json: br#"{"capsule":{"stage_name":"fixture"}}"#.to_vec(),
        run_ordinal: 0,
        worker_id: Some("w-1".to_string()),
        occurrence: OccurrenceBinding::for_test(exec, "stage-a"),
    };
    let command = CommandSpec {
        command_json: b"{}".to_vec(),
    };
    db.arm_commit_fault();
    let error = db
        .dispatch_attempt(exec, Ulid::new(), Ulid::new(), &attempt, &command)
        .unwrap_err();
    assert!(matches!(error, KataError::Storage(_)), "{error:?}");
    assert_rolls_back_cleanly(&db, &tables, &before, base_seq);

    // Retry succeeds; the stage+attempt transitions take the very next seqs.
    let seq = db
        .dispatch_attempt(exec, Ulid::new(), Ulid::new(), &attempt, &command)
        .unwrap();
    assert_eq!(seq, base_seq + 2, "no hole: stage seq then attempt seq");
}

/// The OPERATIONAL half of the two-regime hole invariant.
///
/// `record_transition` reserves its sequence IN-TRANSACTION — `UPDATE
/// transition_sequence SET value = value + 1 ... RETURNING value` — so a rollback
/// reverts the bump and a failed transition leaves NO hole. That is the OPPOSITE
/// of the delivery event log's regime, and both are correct; see
/// `crates/core/tests/ledger_events_db_tests/ledger_seq_hole_tests.rs` for the paired half.
#[test]
fn operational_atomicity_claim_attempt_rolls_back_with_no_partial_fact_or_hole() {
    let db = OperationalDb::open_in_memory().unwrap();
    let exec = Ulid::new();
    let base_seq = submit(&db, exec, 1);
    let tables = ["attempts", "attempt_projection", "transitions"];
    let before: Vec<i64> = tables.iter().map(|t| db.debug_count(t).unwrap()).collect();

    let spec = AttemptClaimSpec {
        stage_id: "stage-a".to_string(),
        assignment_json: br#"{"capsule":{"stage_name":"fixture"}}"#.to_vec(),
        initial_state: "pending".to_string(),
        run_ordinal: 0,
        worker_id: Some("w-1".to_string()),
        occurrence: OccurrenceBinding::for_test(exec, "stage-a"),
    };
    db.arm_commit_fault();
    let error = db.claim_attempt(exec, Ulid::new(), &spec).unwrap_err();
    assert!(matches!(error, KataError::Storage(_)), "{error:?}");
    assert_rolls_back_cleanly(&db, &tables, &before, base_seq);

    // Retry takes the VERY NEXT seq. A reserved-then-abandoned sequence would show
    // up here as a gap, and `attempts.source_seq` / `attempt_projection.source_seq`
    // are foreign keys INTO this space — so a hole here is not a tolerable gap the
    // way a ledger hole is, it is a dangling reference waiting to happen.
    let claimed = db.claim_attempt(exec, Ulid::new(), &spec).unwrap();
    assert_eq!(claimed.seq, base_seq + 1, "no hole after an aborted claim");
    assert_eq!(claimed.attempt_ordinal, 0);
    assert_eq!(claimed.lease_epoch, 0, "a claim seeds epoch 0");
}

#[test]
fn operational_atomicity_accept_incoming_event_rolls_back_with_no_partial_fact_or_hole() {
    let db = OperationalDb::open_in_memory().unwrap();
    let exec = Ulid::new();
    submit(&db, exec, 1);
    let attempt_id = claim(&db, exec);
    let base_seq = db.debug_reserved_seq().unwrap();
    let tables = ["event_inbox", "event_inbox_watermark", "transitions"];
    let before: Vec<i64> = tables.iter().map(|t| db.debug_count(t).unwrap()).collect();

    db.arm_commit_fault();
    let error = db
        .accept_incoming_event(exec, attempt_id, b"s", 1, digest(1), "running", b"{}")
        .unwrap_err();
    assert!(matches!(error, KataError::Storage(_)), "{error:?}");
    assert_rolls_back_cleanly(&db, &tables, &before, base_seq);

    let accepted = db
        .accept_incoming_event(exec, attempt_id, b"s", 1, digest(1), "running", b"{}")
        .unwrap();
    assert!(
        matches!(accepted, EventAcceptance::Accepted { .. }),
        "{accepted:?}"
    );
}

/// The BOOT clause the rest of this family cannot state.
///
/// Every sibling above runs in memory, so each proves the rollback left no partial
/// fact and no hole *in the handle that took the fault*. This one takes the same
/// fault on a FILE-backed database, then drops the handle and opens the file cold —
/// which is what a restart after a crashed commit actually does. The unique
/// contribution is the last two assertions: on a fresh boot with no repair call in
/// between, the stored projection still equals a rebuild from the chain, and the
/// global fence still holds.
///
/// # Regime trap
///
/// "The run completes cleanly past the consumed-but-unwritten seq" is the EVENT
/// LOG's regime, where an aborted append burns a number permanently. The
/// operational assertion is its opposite: the reservation reverted, so the retry
/// takes the VERY NEXT sequence and the chain the reopen folds is contiguous.
#[test]
fn operational_atomicity_rollback_survives_a_boot_with_no_hole_and_a_coherent_projection() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("operational.db");
    let exec = Ulid::new();
    let attempt_id;
    {
        let db = OperationalDb::open(&path).unwrap();
        submit(&db, exec, 1);
        attempt_id = claim(&db, exec);
        let projection_before = db.attempt_projection_for(attempt_id).unwrap().unwrap();
        let tables = ["transitions", "attempts", "attempt_projection"];
        let before: Vec<i64> = tables.iter().map(|t| db.debug_count(t).unwrap()).collect();
        let base_seq = db.debug_reserved_seq().unwrap();

        db.arm_commit_fault();
        let error = db.advance_attempt(attempt_id, "running").unwrap_err();
        assert!(matches!(error, KataError::Storage(_)), "{error:?}");

        assert_rolls_back_cleanly(&db, &tables, &before, base_seq);
        assert_eq!(
            db.attempt_projection_for(attempt_id).unwrap().unwrap(),
            projection_before,
            "the aborted advance must leave the projection's (state, source_seq) untouched"
        );
        assert!(
            db.verify_global_watermark().unwrap(),
            "applied_through_seq == transition_sequence.value == MAX(transitions.seq) is \
             unchanged across the abort"
        );

        // The retry takes the VERY NEXT sequence — no hole to fold across below.
        assert_eq!(
            db.advance_attempt(attempt_id, "running").unwrap(),
            base_seq + 1
        );
    }

    // BOOT: a cold handle on the file, with no rebuild call in between.
    let reopened = OperationalDb::open(&path).unwrap();
    reopened.verify_projection_integrity(exec).unwrap();
    assert!(reopened.verify_global_watermark().unwrap());
    assert_eq!(
        reopened
            .attempt_projection_for(attempt_id)
            .unwrap()
            .unwrap()
            .state,
        "running",
        "the retry's fact — not the aborted one — is what the boot recovers"
    );
}

#[test]
fn operational_atomicity_dynamic_child_rolls_back_with_no_partial_fact_or_hole() {
    let db = OperationalDb::open_in_memory().unwrap();
    let parent = Ulid::new();
    let base_seq = submit(&db, parent, 1);
    let before = db.debug_count("programs").unwrap();

    db.arm_commit_fault();
    let error = db
        .dynamic_child(parent, Ulid::new(), &program(2), &invocation(2), b"bound")
        .unwrap_err();
    assert!(matches!(error, KataError::Storage(_)), "{error:?}");
    assert_rolls_back_cleanly(&db, &["programs"], &[before], base_seq);

    // The bound never persisted, so the child spawns cleanly now.
    assert!(matches!(
        db.dynamic_child(parent, Ulid::new(), &program(2), &invocation(2), b"bound")
            .unwrap(),
        ClaimOutcome::Recorded { .. }
    ));
}

// -- projection: rebuild == chain, mismatch refusal, reader ------------------

#[test]
fn operational_projection_rebuild_equals_chain_and_refuses_mismatch() {
    let db = OperationalDb::open_in_memory().unwrap();
    let exec = Ulid::new();
    submit(&db, exec, 1);
    let attempt = AttemptClaimSpec {
        stage_id: "stage-a".to_string(),
        initial_state: "pending".to_string(),
        assignment_json: br#"{"capsule":{"stage_name":"fixture"}}"#.to_vec(),
        run_ordinal: 0,
        worker_id: Some("w-1".to_string()),
        occurrence: OccurrenceBinding::for_test(exec, "stage-a"),
    };
    let command = CommandSpec {
        command_json: b"{}".to_vec(),
    };
    db.dispatch_attempt(exec, Ulid::new(), Ulid::new(), &attempt, &command)
        .unwrap();

    // The stored projection matches a rebuild from the transition chain.
    db.verify_projection_integrity(exec).unwrap();

    // Corrupt the stored projection -> integrity refuses advancement.
    db.debug_corrupt_execution_projection(exec, "bogus")
        .unwrap();
    let error = db.verify_projection_integrity(exec).unwrap_err();
    assert!(matches!(error, KataError::Validation(_)), "{error:?}");

    // The sanctioned repair path reconciles it.
    db.rebuild_projection(exec).unwrap();
    db.verify_projection_integrity(exec).unwrap();
}

#[test]
fn operational_separate_reader_sees_committed_projections() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("operational.db");
    let db = OperationalDb::open(&path).unwrap();
    let exec = Ulid::new();
    submit(&db, exec, 1);
    let attempt = AttemptClaimSpec {
        stage_id: "stage-a".to_string(),
        initial_state: "pending".to_string(),
        assignment_json: br#"{"capsule":{"stage_name":"fixture"}}"#.to_vec(),
        run_ordinal: 0,
        worker_id: Some("w-1".to_string()),
        occurrence: OccurrenceBinding::for_test(exec, "stage-a"),
    };
    let command = CommandSpec {
        command_json: b"{}".to_vec(),
    };
    db.dispatch_attempt(exec, Ulid::new(), Ulid::new(), &attempt, &command)
        .unwrap();

    // A SEPARATE read-only connection reads the same committed projections.
    let reader = db.open_reader().unwrap();
    assert_eq!(
        reader.execution_projection(exec).unwrap().unwrap().state,
        "admitting"
    );
    assert_eq!(reader.attempt_projections(exec).unwrap().len(), 1);
    // A reader that collides with a checkpoint waits instead of hard-erroring
    // SQLITE_BUSY (the SQLite default of 0).
    assert!(
        reader.debug_busy_timeout().unwrap() > 0,
        "projection readers must arm a busy timeout"
    );
}

/// A BLOB shaped for a previous version never reaches a reader.
///
/// # Why a stamp bump is owed for a change that moves no DDL
///
/// `attempts.assignment_json` stores an externally tagged `DispatchFrame`; a bare, untagged
/// body is a shape the reader refuses. No column distinguishes the two, so every structural
/// assertion in this file passes on a directory holding the untagged shape, and the
/// incompatibility surfaces only when something READS the blob — at which point the refusal
/// has no operator recourse attached to it, because the plane is already open and the
/// execution is already admitted. The bump moves that refusal to boot, where the recourse
/// (a new empty data directory, the old one kept offline) exists.
///
/// # The two halves, and why both are needed
///
/// 1. stamped BEHIND, the open is refused and the untagged blob is never read. That is
///    the property.
/// 2. stamped CURRENT — the counterfactual of a change that skipped the bump — the
///    open SUCCEEDS and the untagged blob is refused by the blob reader instead, with a
///    message about arms rather than about data directories. Without this half, half 1
///    would pass for a blob shape that was never incompatible at all.
#[test]
fn a_blob_shaped_for_the_previous_version_never_reaches_a_reader() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("operational.db");
    let execution = Ulid::new();
    let attempt = {
        let db = OperationalDb::open(&path).unwrap();
        submit(&db, execution, 1);
        claim(&db, execution)
    };

    // REWRITE the blob to an untagged body.
    {
        let conn = rusqlite::Connection::open(&path).unwrap();
        conn.execute(
            "UPDATE attempts SET assignment_json = ?1 WHERE attempt_id = ?2",
            rusqlite::params![
                br#"{"stage_name":"fixture"}"#.as_slice(),
                attempt.to_bytes().as_slice()
            ],
        )
        .unwrap();
    }

    // HALF 1 — behind the stamp: refused at boot, blob unread.
    {
        let db = OperationalDb::open(&path).unwrap();
        db.debug_stamp_user_version(OPERATIONAL_SCHEMA_VERSION - 1)
            .unwrap();
    }
    let error = OperationalDb::open(&path)
        .expect_err("a directory carrying the previous version's blob shape must be refused");
    assert!(
        matches!(error, KataError::SchemaMigrationRequired(_)),
        "the refusal must be the boot-time, operator-actionable one, got {error:?}"
    );
    assert!(
        error
            .to_string()
            .contains("use a new empty data directory and preserve this directory offline"),
        "and it must carry the recourse, which is the whole reason the stamp moved: {error}"
    );

    // HALF 2 — the counterfactual. Stamped CURRENT, the same directory opens, and the
    // untagged blob is refused by the BLOB reader, at a door with no data-directory
    // recourse to offer. This is what skipping the bump would ship.
    {
        let conn = rusqlite::Connection::open(&path).unwrap();
        conn.pragma_update(None, "user_version", OPERATIONAL_SCHEMA_VERSION)
            .unwrap();
    }
    let db = OperationalDb::open(&path).expect("a current stamp opens, DDL being identical");
    // The blob reader is the arm classification every frame consumer goes through.
    let reader_error = db
        .recovered_attempt(attempt)
        .unwrap()
        .expect("the attempt row is still there")
        .arm()
        .expect_err("the untagged blob must be refused by the blob reader");
    let message = reader_error.to_string();
    assert!(
        message.contains("names NEITHER of the arms `capsule` / `main`"),
        "the reader's refusal names ARMS, not data directories — which is exactly why it \
         is the wrong place for this failure to land: {message}"
    );
    assert!(
        !message.contains("new empty data directory"),
        "and it offers no recourse, because by this point the plane is open and the \
         execution is admitted: {message}"
    );
    drop(dir);
}

/// An operational.db whose FIRST creation was interrupted — SQLite created the
/// file (0 bytes), or created it and switched it to WAL, and the process died
/// before `create_fresh_current_schema` committed the DDL and the stamp — carries
/// stamp 0. That is not evidence of an older format, so the refusal names both
/// causes it cannot tell apart, an interrupted first creation and an older or
/// foreign file, with the new-empty-directory recourse. Both shapes are built by
/// the filesystem and a raw SQLite handle, not by the store, and both doors —
/// the pre-open file probe boot and `kata upgrade` read, and the store open —
/// are asked, with the file left byte-identical.
#[test]
fn an_interrupted_first_creation_is_refused_naming_both_causes_not_as_an_older_format() {
    let dir = tempfile::tempdir().unwrap();
    let empty = dir.path().join("empty").join("operational.db");
    std::fs::create_dir(empty.parent().unwrap()).unwrap();
    std::fs::File::create(&empty).unwrap();
    let wal_only = dir.path().join("wal-only").join("operational.db");
    std::fs::create_dir(wal_only.parent().unwrap()).unwrap();
    {
        let raw = rusqlite::Connection::open(&wal_only).unwrap();
        let mode: String = raw
            .query_row("PRAGMA journal_mode=WAL", [], |row| row.get(0))
            .unwrap();
        assert_eq!(mode, "wal");
    }
    assert_eq!(
        header_user_version(&wal_only),
        0,
        "fixture: no stamp committed"
    );

    for path in [&empty, &wal_only] {
        let before = std::fs::read(path).unwrap();
        let probe = OperationalDb::refuse_noncurrent_file_schema(path)
            .expect_err("an unstamped operational.db is refused by the file probe");
        let open =
            OperationalDb::open(path).expect_err("an unstamped operational.db is refused at open");
        for error in [probe, open] {
            assert!(
                matches!(error, KataError::SchemaMigrationRequired(_)),
                "{error:?}"
            );
            let message = error.to_string();
            assert!(
                message.contains("first creation was interrupted")
                    && message.contains("older or foreign")
                    && message.contains(
                        "use a new empty data directory and preserve this directory offline"
                    ),
                "{}: the refusal must name both causes and the recourse: {message}",
                path.display()
            );
            assert!(
                !message.contains("is not the clean runtime version"),
                "{}: stamp 0 must not be diagnosed as an older version alone: {message}",
                path.display()
            );
        }
        assert_eq!(std::fs::read(path).unwrap(), before, "{}", path.display());
    }

    // A MISSING file also reads as stamp 0 to the probe, and is neither cause.
    let missing = dir.path().join("missing").join("operational.db");
    let error = OperationalDb::refuse_noncurrent_file_schema(&missing)
        .expect_err("the probe does not accept a missing file");
    let message = error.to_string();
    assert!(
        matches!(error, KataError::SchemaMigrationRequired(_))
            && message.contains("does not exist")
            && !message.contains("first creation was interrupted"),
        "{message}"
    );
    assert!(!missing.exists() && !dir.path().join("missing").exists());
}
