use super::*;
use crate::{InvocationKind, InvocationRecord, LifecycleState, ProgramRecord};
use kata_types::identity_algebra::AdmissionDigest;
use kata_types::primitives::ContentHash;

#[test]
fn recovery_resume_authorization_requires_exact_artifact_and_execution_set() {
    let artifact = Ulid::new();
    let execution = Ulid::new();
    let packet = ImportDecisionPacket {
        artifact_id: artifact,
        decisions: vec![ImportSubjectDecision {
            subject_key: format!("{:032x}", u128::from(execution)),
            decision: ImportDecision::ExecutionResumeApproved,
            operator: "fixture-owner".into(),
            reason: "resume the verified checkpoint".into(),
        }],
    };
    packet
        .validate_execution_resume_set(artifact, &[execution])
        .unwrap();
    assert!(
        packet
            .validate_execution_resume_set(Ulid::new(), &[execution])
            .is_err()
    );
    assert!(
        packet
            .validate_execution_resume_set(artifact, &[Ulid::new()])
            .is_err()
    );
    assert!(packet.validate_execution_resume_set(artifact, &[]).is_err());
    let mut invalid = packet.clone();
    invalid.decisions.clear();
    assert!(
        invalid
            .validate_execution_resume_set(artifact, &[execution])
            .is_err()
    );
    let mut invalid = packet.clone();
    invalid.decisions.push(invalid.decisions[0].clone());
    assert!(
        invalid
            .validate_execution_resume_set(artifact, &[execution])
            .is_err()
    );
    let mut retired = serde_json::to_value(&packet.decisions[0]).unwrap();
    retired["decision"] = "schedule_rebind_approved".into();
    let error = serde_json::from_value::<ImportSubjectDecision>(retired).unwrap_err();
    assert!(error.to_string().contains("unknown variant"), "{error}");
    let mut invalid = packet.clone();
    invalid.decisions[0].operator = " ".into();
    assert!(
        invalid
            .validate_execution_resume_set(artifact, &[execution])
            .is_err()
    );
    let mut invalid = packet.clone();
    invalid.decisions[0].reason = "x".repeat(4097);
    assert!(
        invalid
            .validate_execution_resume_set(artifact, &[execution])
            .is_err()
    );
}

fn authority() -> ImportAuthority {
    ImportAuthority {
        artifact_id: Ulid::new(),
        source_directory_id: "source".into(),
        target_directory_id: "target".into(),
        catalog_digest: "a".repeat(64),
    }
}

fn timer_spec(execution: Ulid, path: u32) -> crate::operational::MainAttemptSpec {
    use kata_types::execution_contract::{OccurrenceRef, OperationContractId, OperationPath};
    crate::operational::MainAttemptSpec {
        stage_id: "nap".into(),
        occurrence: crate::operational::OccurrenceBinding::new(
            OccurrenceRef::new(
                kata_types::workflow::ExecutionId(execution),
                ContentHash::new([3; 32]),
                OperationContractId(ContentHash::new([0x2E; 32])),
                OperationPath(vec![path]),
            ),
            None,
            None,
        ),
    }
}

/// The durable-sleep cohort is an execution parked ONLY in main-side `awaiting_timer`
/// waits: such a wait is captured with the attempt row's own deadline and fences, and
/// everything else a restored main could not resume from its rows alone is refused — a
/// running execution with nothing parked, a live INPUT wait (by name), and a timer row
/// whose deadline was lost.
#[test]
fn recovery_sleep_population_captures_exactly_the_parked_timer_waits() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("operational.db");
    let db = OperationalDb::open(&path).unwrap();
    let execution = submit(&db);
    db.mark_running(execution).unwrap();
    let raw = Connection::open(&path).unwrap();
    assert!(
        inspect_recovery_sleep_population(&raw, deadline()).is_err(),
        "a running execution parked in nothing is not the cohort"
    );
    let attempt = Ulid::new();
    let claimed = db
        .claim_main_attempt(
            attempt,
            &timer_spec(execution, 1),
            crate::operational::MainWait::Timer(kata_types::wait::WaitDeadline::At {
                epoch_ms: 123_456_789,
            }),
        )
        .unwrap();
    let crate::operational::MainClaimOutcome::Claimed { park_seq, .. } = claimed else {
        panic!("a fresh timer wait claims: {claimed:?}");
    };
    let population = inspect_recovery_sleep_population(&raw, deadline()).unwrap();
    assert_eq!(
        population.executions[&execution],
        vec![crate::store::backup::RecoverySleepCheckpoint {
            attempt_id: attempt,
            stage_id: "nap".into(),
            attempt_ordinal: 0,
            lease_epoch: 0,
            wait_deadline_ms: 123_456_789,
            transition_seq: u64::try_from(park_seq).unwrap(),
        }]
    );
    let stored: (String, String, i64) = raw
        .query_row(
            "SELECT a.executor,p.state,a.wait_deadline_ms FROM attempts a JOIN attempt_projection p \
             USING(execution_id,stage_id,attempt_ordinal) WHERE a.attempt_id=?1",
            [attempt.to_bytes().as_slice()],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .unwrap();
    assert_eq!(
        stored,
        ("main".into(), "awaiting_timer".into(), 123_456_789)
    );

    // An INPUT wait beside it is refused by name.
    let input = Ulid::new();
    db.claim_main_attempt(
        input,
        &crate::operational::MainAttemptSpec {
            stage_id: "ask".into(),
            ..timer_spec(execution, 2)
        },
        crate::operational::MainWait::Input(None),
    )
    .unwrap();
    let refused = inspect_recovery_sleep_population(&raw, deadline())
        .unwrap_err()
        .to_string();
    assert!(refused.contains("live main INPUT wait"), "{refused}");
    raw.execute("DELETE FROM attempt_projection WHERE stage_id='ask'", [])
        .unwrap();
    raw.execute(
        "DELETE FROM attempts WHERE attempt_id=?1",
        [input.to_bytes().as_slice()],
    )
    .ok();

    // A timer whose deadline is gone is not a timer a restored main can resume.
    raw.execute(
        "UPDATE attempts SET wait_deadline_ms=NULL WHERE attempt_id=?1",
        [attempt.to_bytes().as_slice()],
    )
    .unwrap();
    assert!(inspect_recovery_sleep_population(&raw, deadline()).is_err());
}

fn deadline() -> Instant {
    Instant::now() + Duration::from_secs(10)
}

fn records() -> (ProgramRecord, InvocationRecord) {
    let invocation = kata_types::idempotency::canonicalize_args(
        &serde_json::json!({"schema_version": 1, "kind": "workflow"}),
    );
    let hash = ContentHash::new([3; 32]);
    (
        ProgramRecord {
            program_hash: hash,
            schema_version: 4,
            program_json: kata_types::idempotency::canonicalize_args(
                &serde_json::json!({"schema_version": 4, "program_hash": hash.to_string()}),
            ),
        },
        InvocationRecord {
            schema_version: 1,
            kind: InvocationKind::Workflow,
            admission_digest: AdmissionDigest(ContentHash::new(
                *blake3::hash(&invocation).as_bytes(),
            )),
            invocation_json: invocation,
        },
    )
}

fn submit(db: &OperationalDb) -> Ulid {
    let id = Ulid::new();
    let (program, invocation) = records();
    db.submit_execution(id, &program, &invocation).unwrap();
    id
}

/// A clone population that carries an INSTALLED SCHEDULE is refused at quarantine,
/// before any import authority is written.
///
/// A schedule fires on its own, so a cloned one would fire on the target as well as on
/// the source. The recovery capture already refuses a source with installed schedules,
/// and this is the same refusal at the door that writes the quarantine — so a schedule
/// can never become an import subject no decision could ever release.
#[test]
fn import_quarantine_refuses_a_population_with_installed_schedules() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("operational.db");
    let db = OperationalDb::open(&path).unwrap();
    let (program, invocation) = records();
    db.install_schedule(
        &crate::operational::ScheduleInstall {
            schedule_id: "nightly".into(),
            submit_pack: "nightly".into(),
            trigger: "{\"interval_ms\":1000}".into(),
            on_missed: crate::operational::MissedFirePolicy::Skip,
            cursor_ms: 1000,
        },
        &program,
        &invocation,
    )
    .unwrap();
    let error = db
        .quarantine_verified_import(&authority(), deadline())
        .expect_err("a population with an installed schedule must be refused");
    assert!(
        error.to_string().contains("installed schedule"),
        "the refusal must name the schedule: {error}"
    );
    let counts: (i64, i64) = Connection::open(&path)
        .unwrap()
        .query_row(
            "SELECT (SELECT count(*) FROM recovery_imports),
                    (SELECT count(*) FROM recovery_import_subjects)",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!(counts, (0, 0), "a refused quarantine writes nothing");
}

#[test]
fn import_quarantine_terminal_history_and_empty_domain_need_no_manual_blessing() {
    let directory = tempfile::tempdir().unwrap();
    let db = OperationalDb::open(directory.path().join("operational.db")).unwrap();
    let execution = submit(&db);
    db.mark_running(execution).unwrap();
    db.begin_terminalization(execution, LifecycleState::Completed, b"{}")
        .unwrap();
    db.finish_terminalization(execution).unwrap();
    db.enroll_worker_domain(
        "source",
        kata_types::identity::WorkerMembraneId(Ulid::new()),
    )
    .unwrap();
    db.quarantine_verified_import(&authority(), deadline())
        .unwrap();
    assert!(
        db.pending_import_subjects().unwrap().is_empty(),
        "terminal history and immutable empty-domain evidence are not operator decisions"
    );
}

#[test]
fn import_quarantine_operator_words_alone_cannot_release_without_target_verification() {
    let directory = tempfile::tempdir().unwrap();
    let db = OperationalDb::open(directory.path().join("operational.db")).unwrap();
    submit(&db);
    let authority = authority();
    db.quarantine_verified_import(&authority, deadline())
        .unwrap();
    let decisions = db
        .pending_import_subjects()
        .unwrap()
        .into_iter()
        .map(|subject| ImportSubjectDecision {
            subject_key: subject.key,
            decision: ImportDecision::ExecutionResumeApproved,
            operator: "operator".into(),
            reason: "a statement is not target verification".into(),
        })
        .collect();
    db.apply_import_decisions(&ImportDecisionPacket {
        artifact_id: authority.artifact_id,
        decisions,
    })
    .unwrap();
    struct RefusingTarget;
    impl ImportTargetVerifier for RefusingTarget {
        fn verify_current_target(
            &self,
            _: &Path,
            _: &str,
            _: &ImportAuthority,
            _: &[ImportSubject],
        ) -> KataResult<()> {
            Err(KataError::Validation("no actual target verified".into()))
        }
    }
    assert!(
        db.verify_import_readiness(
            directory.path(),
            "target",
            authority.artifact_id,
            deadline(),
            &RefusingTarget
        )
        .is_err(),
        "no target configuration, repository, identity or catalog verifier ran"
    );
    assert!(db.require_imports_reconciled().is_err());
}

/// The guard refuses a deadline that has already passed when it is built, so a
/// fixed margin between `Instant::now()` and `RecoveryReadDeadline::new` fails
/// whenever the test thread is descheduled for longer than that margin. Each
/// attempt therefore takes a FRESH deadline with twice the margin, and only that
/// one refusal is retried: once a guard is built its deadline is still ahead, and
/// the query below outlasts any margin this loop reaches, so the interrupt the
/// test asserts is the deadline's whatever the load.
fn deadline_guard_ahead_of_the_scheduler(connection: &Connection) -> RecoveryReadDeadline<'_> {
    let mut margin = Duration::from_millis(10);
    loop {
        match RecoveryReadDeadline::new(connection, Instant::now() + margin) {
            Ok(guard) => return guard,
            Err(KataError::Validation(message))
                if message == "recovery SQL deadline elapsed"
                    && margin < Duration::from_secs(10) =>
            {
                margin *= 2;
            }
            Err(error) => panic!("the deadline guard must build: {error:?}"),
        }
    }
}

#[test]
fn import_quarantine_sql_deadline_interrupts_work_and_does_not_poison_next_query() {
    let connection = Connection::open_in_memory().unwrap();
    {
        let _guard = deadline_guard_ahead_of_the_scheduler(&connection);
        // Far longer than any margin above: only the deadline's interrupt ends it.
        let query = connection.query_row(
            "WITH RECURSIVE work(n) AS (SELECT 1 UNION ALL SELECT n+1 FROM work WHERE n<1000000000000) SELECT count(*) FROM work",
            [],
            |row| row.get::<_, i64>(0),
        );
        assert!(
            matches!(
                &query,
                Err(rusqlite::Error::SqliteFailure(failure, _))
                    if failure.code == rusqlite::ErrorCode::OperationInterrupted
            ),
            "the SQL VM must be interrupted, not only checked after returning: {query:?}"
        );
    }
    assert_eq!(
        connection
            .query_row("SELECT 42", [], |row| row.get::<_, i64>(0))
            .unwrap(),
        42
    );
}

#[test]
fn expired_import_readiness_cannot_probe_target_or_release_quarantine() {
    struct MustNotProbe;
    impl ImportTargetVerifier for MustNotProbe {
        fn verify_current_target(
            &self,
            _: &Path,
            _: &str,
            _: &ImportAuthority,
            _: &[ImportSubject],
        ) -> KataResult<()> {
            panic!("expired readiness must not invoke target verification");
        }
    }
    let directory = tempfile::tempdir().unwrap();
    let db = OperationalDb::open(directory.path().join("operational.db")).unwrap();
    let authority = authority();
    db.quarantine_verified_import(&authority, deadline())
        .unwrap();
    assert!(
        db.verify_import_readiness(
            directory.path(),
            "target",
            authority.artifact_id,
            Instant::now().checked_sub(Duration::from_secs(1)).unwrap(),
            &MustNotProbe
        )
        .is_err()
    );
    let raw = Connection::open(directory.path().join("operational.db")).unwrap();
    let released: Option<i64> = raw
        .query_row(
            "SELECT released_at_ms FROM recovery_imports WHERE artifact_id=?1",
            [authority.artifact_id.to_bytes().as_slice()],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(released, None);
}

#[test]
fn import_quarantine_precommit_fault_rolls_back_gate_and_subjects() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("operational.db");
    let db = OperationalDb::open(&path).unwrap();
    submit(&db);
    let authority = authority();
    db.arm_commit_fault();
    assert!(
        db.quarantine_verified_import(&authority, deadline())
            .is_err()
    );
    drop(db);
    let db = OperationalDb::open(&path).unwrap();
    let raw = rusqlite::Connection::open(&path).unwrap();
    let counts: (i64, i64) = raw
        .query_row(
            "SELECT (SELECT count(*) FROM recovery_imports),
        (SELECT count(*) FROM recovery_import_subjects)",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    assert_eq!(counts, (0, 0));
    db.quarantine_verified_import(&authority, deadline())
        .unwrap();
    let counts: (i64, i64) = raw
        .query_row(
            "SELECT (SELECT count(*) FROM recovery_imports),
        (SELECT count(*) FROM recovery_import_subjects)",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    assert_eq!(counts, (1, 1));
}
