//! Persistent current-writer measurements, not a frontend/worker throughput SLO.
//! Each sample includes the public method's lock wait, staging and FULL commit.
//! Database/sidecar lengths are a logical footprint, not physical bytes written.

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::{Arc, Barrier};
use std::time::{Duration, Instant};

use kata_core::operational::OccurrenceBinding;
use kata_core::operational::{
    AttemptClaimSpec, CompletionVerdict, MainSideTransition, WorkerCompletionInput,
};
use kata_core::{
    ClaimOutcome, CommandSpec, InvocationKind, InvocationRecord, LifecycleState,
    OPERATIONAL_SCHEMA_VERSION, OperationalDb, ProgramRecord, SubmitOutcome,
};
use kata_types::identity::{WorkerEffectDomain, WorkerMembraneId};
use kata_types::identity_algebra::AdmissionDigest;
use kata_types::primitives::ContentHash;
use ulid::Ulid;

const LIFECYCLES_PER_PRODUCER: usize = 128;
const OUTPUT_BYTES: usize = 4096;
// One transaction per named public method below; enrollment and database setup
// precede timing.
const TRANSACTIONS_PER_LIFECYCLE: usize = 8;

type Samples = BTreeMap<&'static str, Vec<Duration>>;

fn timed<T>(samples: &mut Samples, label: &'static str, action: impl FnOnce() -> T) -> T {
    let start = Instant::now();
    let result = action();
    samples.entry(label).or_default().push(start.elapsed());
    result
}

fn lifecycle(db: &OperationalDb, domain: &WorkerEffectDomain, samples: &mut Samples) {
    let execution = Ulid::new();
    let attempt = Ulid::new();
    // Program bytes are opaque to this core boundary. This does not claim to
    // compile Starlark or time admission checking in the workflow crate.
    let hash = ContentHash::new([1; 32]);
    let program = ProgramRecord {
        program_hash: hash,
        schema_version: 4,
        program_json: serde_json::to_vec(&serde_json::json!({
            "schema_version":4,"program_hash":hash.to_string(),"fixture":"writer measurement"
        }))
        .unwrap(),
    };
    let invocation_json = kata_types::idempotency::canonicalize_args(&serde_json::json!({
        "schema_version":1,"kind":"workflow","inputs":[]
    }));
    let invocation = InvocationRecord {
        schema_version: 1,
        kind: InvocationKind::Workflow,
        admission_digest: AdmissionDigest(ContentHash::new(
            *blake3::hash(&invocation_json).as_bytes(),
        )),
        invocation_json,
    };
    assert!(matches!(
        timed(samples, "submit", || db.submit_execution(
            execution,
            &program,
            &invocation
        ))
        .unwrap(),
        SubmitOutcome::Submitted { .. }
    ));
    assert!(matches!(
        timed(samples, "running", || db.mark_running(execution)).unwrap(),
        ClaimOutcome::Recorded { .. }
    ));
    let claimed = timed(samples, "claim", || {
        db.claim_attempt(
            execution,
            attempt,
            &AttemptClaimSpec {
                stage_id: "measured".into(),
                assignment_json: br#"{"capsule":{"stage_name":"measured"}}"#.to_vec(),
                initial_state: "pending".into(),
                run_ordinal: 0,
                worker_id: None,
                occurrence: OccurrenceBinding::for_test(execution, "measured"),
            },
        )
    })
    .unwrap();
    let expected = db
        .recovered_attempt(attempt)
        .unwrap()
        .unwrap()
        .placement_expectation()
        .unwrap();
    assert!(matches!(
        timed(samples, "dispatch", || db
            .dispatch_claimed_attempt_in_domain(
                attempt,
                "measured-worker",
                Ulid::new(),
                &CommandSpec {
                    command_json: b"{}".to_vec()
                },
                domain,
                &expected,
            ))
        .unwrap(),
        Some(ClaimOutcome::Recorded { .. })
    ));
    timed(samples, "start", || {
        db.record_main_side_transition(attempt, &MainSideTransition::bare("running"))
    })
    .unwrap();
    let completion = WorkerCompletionInput {
        execution_id: execution,
        attempt_id: attempt,
        attempt_ordinal: claimed.attempt_ordinal,
        lease_epoch: claimed.lease_epoch + 1,
        worker_id: "measured-worker".into(),
        output: serde_json::json!({"content":"x".repeat(OUTPUT_BYTES)}),
    };
    assert!(matches!(
        timed(samples, "completion_accept", || db
            .accept_worker_completion(&completion))
        .unwrap(),
        CompletionVerdict::Accepted { .. }
    ));
    assert!(matches!(
        timed(samples, "terminal_intent", || db.begin_terminalization(
            execution,
            LifecycleState::Completed,
            br#"{"reason":"measured completion"}"#
        ))
        .unwrap(),
        ClaimOutcome::Recorded { .. }
    ));
    assert!(matches!(
        timed(samples, "terminal_publish", || db
            .finish_terminalization(execution))
        .unwrap(),
        ClaimOutcome::Recorded { .. }
    ));
}

fn raw_verify(path: &Path, count: usize) -> i64 {
    let raw =
        rusqlite::Connection::open_with_flags(path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
            .unwrap();
    let expected = i64::try_from(count).unwrap();
    for query in [
        "SELECT count(*) FROM programs",
        "SELECT count(*) FROM execution_lifecycle WHERE state='completed'",
        "SELECT count(*) FROM attempts WHERE started_at_ms IS NOT NULL AND finished_at_ms IS NOT NULL",
        "SELECT count(*) FROM attempt_projection WHERE state='completed'",
        "SELECT count(*) FROM attempt_commands",
        "SELECT count(*) FROM worker_dispatch_domains",
        "SELECT count(*) FROM event_inbox WHERE accepted=1",
        "SELECT count(*) FROM transitions WHERE kind='event_accepted'",
    ] {
        let actual: i64 = raw.query_row(query, [], |row| row.get(0)).unwrap();
        assert_eq!(actual, expected, "{query}");
    }
    let mut statement = raw
        .prepare("SELECT payload_json FROM event_inbox WHERE accepted=1")
        .unwrap();
    for bytes in statement
        .query_map([], |row| row.get::<_, Vec<u8>>(0))
        .unwrap()
    {
        let input: serde_json::Value = serde_json::from_slice(&bytes.unwrap()).unwrap();
        assert_eq!(input["output"]["content"], "x".repeat(OUTPUT_BYTES));
    }
    let (count, first, last): (i64, i64, i64) = raw
        .query_row(
            "SELECT count(*),min(seq),max(seq) FROM transitions",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap();
    assert_eq!(first, 1);
    assert_eq!(
        last, count,
        "no sequence holes or lost committed transitions"
    );
    // Independently enumerate the expected records: submit, running, claim,
    // dispatch, start, acceptance, terminal intent + publish.
    assert_eq!(count, expected * 8);
    assert_eq!(
        raw.query_row("PRAGMA integrity_check", [], |row| row.get::<_, String>(0))
            .unwrap(),
        "ok"
    );
    count
}

fn footprint(path: &Path) -> u64 {
    ["", "-wal", "-shm"]
        .into_iter()
        .map(|suffix| {
            let mut file = path.as_os_str().to_os_string();
            file.push(suffix);
            std::fs::metadata(file).map_or(0, |metadata| metadata.len())
        })
        .sum()
}

#[test]
fn current_writer_measurement_has_a_separate_bounded_serial_profile() {
    let config: toml::Value =
        toml::from_str(include_str!("../../../.config/nextest.toml")).unwrap();
    let measurement = &config["profile"]["measurement"];
    assert_eq!(measurement["test-threads"].as_integer(), Some(1));
    assert_eq!(measurement["slow-timeout"]["period"].as_str(), Some("30s"));
    assert_eq!(
        measurement["slow-timeout"]["terminate-after"].as_integer(),
        Some(4)
    );
    assert_eq!(
        measurement["default-filter"].as_str(),
        Some(
            "(binary(=operational_write_measurement) & test(=persistent_current_writer_reports_serialized_transaction_latency_and_throughput))"
        )
    );
    assert!(
        measurement.get("overrides").is_none(),
        "the measurement lane carries one cell and no per-cell override"
    );
}

#[test]
fn persistent_current_writer_lifecycle_is_verified_by_raw_sql_after_reopen() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("writer.db");
    let db = OperationalDb::open(&path).unwrap();
    assert_eq!(db.debug_synchronous_level().unwrap(), 2);
    let domain = db
        .enroll_worker_domain("correctness-main", WorkerMembraneId(Ulid::new()))
        .unwrap();
    let mut samples = Samples::new();
    lifecycle(&db, &domain, &mut samples);
    assert_eq!(samples.len(), TRANSACTIONS_PER_LIFECYCLE);
    assert!(samples.values().all(|durations| durations.len() == 1));
    raw_verify(&path, 1);
    drop(db);
    let reopened = OperationalDb::open(&path).unwrap();
    raw_verify(&path, 1);
    drop(reopened);
    raw_verify(&path, 1);
}

#[kata_test_utils::kata_timeout(secs = 100)]
#[tokio::test]
async fn persistent_current_writer_reports_serialized_transaction_latency_and_throughput() {
    tokio::task::spawn_blocking(measure_current_writer)
        .await
        .unwrap();
}

fn measure_current_writer() {
    // Locate on the build tree's filesystem, not a possibly RAM-backed /tmp —
    // and outside the source tree: a directory appearing under `crates/core`
    // mid-run is a source-tree change, which re-ran `kata`'s build script and
    // recompiled `kata` in every later cargo step.
    let root = tempfile::Builder::new()
        .prefix("operational-write-measurement-")
        .tempdir_in(env!("CARGO_TARGET_TMPDIR"))
        .unwrap();
    let filesystem = std::process::Command::new("stat")
        .args(["-f", "-c", "%T"])
        .arg(root.path())
        .output()
        .unwrap();
    assert!(filesystem.status.success());
    println!(
        "measurement_only=true profile=debug fs={} dir={} host_load={}",
        String::from_utf8_lossy(&filesystem.stdout).trim(),
        root.path().display(),
        std::fs::read_to_string("/proc/loadavg").unwrap().trim()
    );
    for producers in [1, 4] {
        let path = root.path().join(format!("writers-{producers}.db"));
        let db = Arc::new(OperationalDb::open(&path).unwrap());
        assert_eq!(db.debug_user_version().unwrap(), OPERATIONAL_SCHEMA_VERSION);
        assert_eq!(db.debug_synchronous_level().unwrap(), 2);
        let domain = db
            .enroll_worker_domain("measurement-main", WorkerMembraneId(Ulid::new()))
            .unwrap();
        let before_bytes = footprint(&path);
        let barrier = Arc::new(Barrier::new(producers + 1));
        let (samples, elapsed) = std::thread::scope(|scope| {
            let handles: Vec<_> = (0..producers)
                .map(|_| {
                    let db = Arc::clone(&db);
                    let barrier = Arc::clone(&barrier);
                    let domain = domain.clone();
                    scope.spawn(move || {
                        let mut samples = Samples::new();
                        barrier.wait();
                        for _ in 0..LIFECYCLES_PER_PRODUCER {
                            lifecycle(&db, &domain, &mut samples);
                        }
                        samples
                    })
                })
                .collect();
            let start = Instant::now();
            barrier.wait();
            let mut samples = Samples::new();
            for handle in handles {
                for (label, durations) in handle.join().unwrap() {
                    samples.entry(label).or_default().extend(durations);
                }
            }
            (samples, start.elapsed())
        });
        let lifecycles = producers * LIFECYCLES_PER_PRODUCER;
        assert_eq!(samples.len(), TRANSACTIONS_PER_LIFECYCLE);
        let transactions: usize = samples.values().map(Vec::len).sum();
        assert_eq!(transactions, lifecycles * TRANSACTIONS_PER_LIFECYCLE);
        let bytes = footprint(&path);
        let transitions = raw_verify(&path, lifecycles);
        println!(
            "producers={producers} writer_connections=1 synchronous=FULL lifecycles={lifecycles} successful_transactions={transactions} transitions={transitions} output_bytes_each={OUTPUT_BYTES} elapsed_ms={:.3} transactions_per_sec={:.3} lifecycles_per_sec={:.3} initial_logical_bytes={before_bytes} final_logical_bytes={bytes}",
            elapsed.as_secs_f64() * 1000.0,
            f64::from(u32::try_from(transactions).unwrap()) / elapsed.as_secs_f64(),
            f64::from(u32::try_from(lifecycles).unwrap()) / elapsed.as_secs_f64()
        );
        for (label, mut durations) in samples {
            assert_eq!(durations.len(), lifecycles);
            durations.sort_unstable();
            let percentile = |percent: usize| {
                durations[(durations.len() * percent).div_ceil(100) - 1].as_secs_f64() * 1000.0
            };
            println!(
                "producers={producers} operation={label} samples={} p50_ms={:.3} p99_ms={:.3} max_ms={:.3}",
                durations.len(),
                percentile(50),
                percentile(99),
                durations.last().unwrap().as_secs_f64() * 1000.0
            );
        }
        drop(db);
        raw_verify(&path, lifecycles);
    }
}
