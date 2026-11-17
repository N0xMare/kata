//! Measured current-format authority reads over 20,000 admitted attempts (the
//! `recovery_100k` bench keeps the 100,000-attempt corpus, ungated).
//! Global, per-execution and captured-tail reads are measured on the same corpus.
//! This measures clean reopen and indexed reads, not physical power loss or a
//! persisted assignment snapshot (the current runner reconstructs its prefix).
//!
//! The corpus is built through `OperationalDb::debug_claim_attempts_in_one_txn`, many
//! claims per commit, because one FULL-sync `claim_attempt` commit per claim would add
//! about 40 s of fsync at 20,000 attempts (scaled from 200 s at 100,000) for fixture
//! state the measurement never times. That is sound only while the durable
//! state the read path sees is the state the real door writes, which
//! `authority_corpus_bulk_matches_the_claim_door` holds: it builds one corpus both
//! ways, with the SAME execution and attempt ids, and compares the two database files
//! through raw SQLite — every schema object, every table, every row.

#[path = "support/authority_corpus.rs"]
mod corpus;

use kata_core::OperationalDb;
use rusqlite::types::Value;
use std::collections::BTreeMap;
use std::path::Path;
use std::time::Instant;
use ulid::Ulid;

/// **Resume reads stay bounded against the whole-chain scan, on the queries that run.**
///
/// Two kinds of assertion, each catching a different full-scan regression:
///
/// * SHAPE — SQLite's plan for the readers' own SQL
///   (`OperationalDb::chain_page_query_plans`): the per-execution page is served by
///   `idx_transitions_execution` and the global page by the `seq` primary key. Size-free,
///   and the only check that sees a per-execution read turned into a scan: MEASURED with
///   the reader's predicate made unindexable (`+execution_id`), the indexed read still
///   beat the whole-chain scan by 12x at 20,000 attempts and 13x at 100,000 (it skips
///   rows without decoding them, the scan decodes every one), so no ratio caught it.
/// * COST — the per-execution, reopen and grown-tail reads against the whole-chain scan,
///   as ratios. MEASURED at 20,000 attempts under a load average of 30-60: indexed 51x,
///   reopen+empty tail 13x, grown tail 20x below the scan (asserted: 3x, 5x, 5x); a
///   reopen that walks the chain (every page read at `open`) measured 1.08x the scan
///   and fails. The reopen ratio is the binding one, since opening costs a fixed ~3.7 ms:
///   6.8x at 10,000 attempts and 3.4-3.9x (red) at 5,000, so 20,000 is the smallest
///   corpus measured with margin.
///
/// The corpus build is the cost: 10 s at 20,000 attempts, where the 100,000-attempt
/// cell took 122-172 s (it grows faster than linearly), every read under 0.5 s.
#[kata_test_utils::kata_timeout(secs = 540)]
#[tokio::test(flavor = "multi_thread")]
async fn recovery_100k_resume_is_bounded() {
    const ATTEMPTS: usize = 20_000;
    const EXECUTIONS: usize = 100;
    let build_start = Instant::now();
    let (directory, db, ids) = corpus::build(ATTEMPTS, EXECUTIONS);
    let build_elapsed = build_start.elapsed();
    let target = ids[EXECUTIONS / 2];
    let raw = rusqlite::Connection::open(directory.path().join("operational.db")).unwrap();
    let (total, head): (usize, i64) = raw
        .query_row("SELECT count(*), max(seq) FROM transitions", [], |row| {
            Ok((row.get(0)?, row.get(1)?))
        })
        .unwrap();
    let expected: usize = raw
        .query_row(
            "SELECT count(*) FROM transitions WHERE execution_id=?1",
            [target.to_bytes().as_slice()],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(total, ATTEMPTS + 2 * EXECUTIONS);
    let (global_plan, execution_plan) = db.chain_page_query_plans().unwrap();
    assert!(
        execution_plan.contains("USING INDEX idx_transitions_execution"),
        "the per-execution page read is not served by its index: {execution_plan}"
    );
    assert!(
        global_plan.contains("USING INTEGER PRIMARY KEY"),
        "the global page read is not served by the `seq` primary key: {global_plan}"
    );

    let indexed_start = Instant::now();
    let indexed = corpus::execution_rows(&db, target);
    let indexed_elapsed = indexed_start.elapsed();
    let cold_start = Instant::now();
    let (scanned, matched) = corpus::global_rows(&db, 1, target);
    let cold_elapsed = cold_start.elapsed();
    assert_eq!(indexed, expected);
    assert_eq!(matched, expected);
    assert_eq!(scanned, total);
    assert_eq!(indexed * EXECUTIONS, scanned);

    drop(raw);
    drop(db);
    let warm_start = Instant::now();
    let db = OperationalDb::open(directory.path().join("operational.db")).unwrap();
    assert_eq!(corpus::global_rows(&db, head + 1, target), (0, 0));
    let warm_elapsed = warm_start.elapsed();

    const DELTA: usize = 1_000;
    corpus::append(&db, &[target], DELTA);
    let tail_start = Instant::now();
    assert_eq!(corpus::global_rows(&db, head + 1, target), (DELTA, DELTA));
    let tail_elapsed = tail_start.elapsed();
    println!(
        "authority recovery: build={build_elapsed:?}; global={cold_elapsed:?} ({scanned} rows); indexed={indexed_elapsed:?} ({indexed} rows); clean reopen+empty tail={warm_elapsed:?}; grown tail={tail_elapsed:?} ({DELTA} rows); plans: global `{global_plan}`, per-execution `{execution_plan}`"
    );
    assert!(
        indexed_elapsed * 3 <= cold_elapsed,
        "indexed={indexed_elapsed:?}, whole-chain={cold_elapsed:?}"
    );
    assert!(
        warm_elapsed * 5 <= cold_elapsed,
        "reopen+empty-tail={warm_elapsed:?}, whole-chain={cold_elapsed:?}"
    );
    assert!(
        tail_elapsed * 5 <= cold_elapsed,
        "grown-tail={tail_elapsed:?}, whole-chain={cold_elapsed:?}"
    );
}

/// Columns that hold the wall clock at write time (`now_ms()`), and nothing else. They
/// are the only values the two builds may legitimately disagree on, so they are compared
/// as present-or-NULL rather than by value. Every other column of every table is
/// compared by value.
const WALL_CLOCK: &[(&str, &str)] = &[
    ("attempt_projection", "updated_at_ms"),
    ("attempts", "created_at_ms"),
    ("execution_lifecycle", "created_at_ms"),
    ("execution_projection", "updated_at_ms"),
    ("invocations", "created_at_ms"),
    ("occurrences", "created_at_ms"),
    ("programs", "created_at_ms"),
    ("transitions", "recorded_at_ms"),
];

/// `PRAGMA user_version`, every schema object `(type, name, tbl_name, sql)`, and every
/// table's rows sorted.
struct Dump {
    user_version: i64,
    schema: Vec<(String, String, String, Option<String>)>,
    tables: BTreeMap<String, Vec<Vec<String>>>,
}

fn dump(path: &Path) -> Dump {
    let raw =
        rusqlite::Connection::open_with_flags(path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
            .unwrap();
    let schema: Vec<(String, String, String, Option<String>)> = raw
        .prepare("SELECT type, name, tbl_name, sql FROM sqlite_schema ORDER BY type, name")
        .unwrap()
        .query_map([], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
        })
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    let mut tables = BTreeMap::new();
    for (kind, name, _, _) in &schema {
        if kind != "table" {
            continue;
        }
        let mut statement = raw.prepare(&format!("SELECT * FROM \"{name}\"")).unwrap();
        let columns: Vec<String> = statement.column_names().map(str::to_owned).collect();
        let mut rows: Vec<Vec<String>> = statement
            .query_map([], |row| {
                Ok(columns
                    .iter()
                    .enumerate()
                    .map(|(index, column)| {
                        let value: Value = row.get(index).unwrap();
                        if WALL_CLOCK.contains(&(name.as_str(), column.as_str())) {
                            return format!("{column}=<clock:{}>", value != Value::Null);
                        }
                        format!("{column}={value:?}")
                    })
                    .collect())
            })
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        rows.sort();
        tables.insert(name.clone(), rows);
    }
    let user_version = raw
        .query_row("PRAGMA user_version", [], |row| row.get(0))
        .unwrap();
    Dump {
        user_version,
        schema,
        tables,
    }
}

#[test]
fn authority_corpus_bulk_matches_the_claim_door() {
    const ATTEMPTS: usize = 120;
    const EXECUTIONS: usize = 10;
    // Not a divisor of ATTEMPTS, so the last writer transaction is a partial one and
    // the sequence has to run on across several commits.
    const BATCH: usize = 50;
    let ids: Vec<_> = (0..EXECUTIONS).map(|_| Ulid::new()).collect();
    let claims = corpus::claims(&ids, ATTEMPTS);

    let (door_directory, door) = corpus::open_running(&ids);
    corpus::claim_through_the_door(&door, &claims);
    let (bulk_directory, bulk) = corpus::open_running(&ids);
    corpus::claim_in_batches(&bulk, &claims, BATCH);
    drop(door);
    drop(bulk);
    let door = dump(&door_directory.path().join("operational.db"));
    let bulk = dump(&bulk_directory.path().join("operational.db"));

    assert_eq!(door.user_version, bulk.user_version);
    assert_eq!(door.schema, bulk.schema);
    assert_eq!(
        door.tables.keys().collect::<Vec<_>>(),
        bulk.tables.keys().collect::<Vec<_>>()
    );
    // The door's corpus is the one the soak measures: one claimed transition per
    // attempt over the submit + running pair per execution, and one attempt row each.
    assert_eq!(door.tables["transitions"].len(), ATTEMPTS + 2 * EXECUTIONS);
    assert_eq!(door.tables["attempts"].len(), ATTEMPTS);
    let mut differences = Vec::new();
    for (table, door_rows) in &door.tables {
        let bulk_rows = &bulk.tables[table];
        println!("{table}: {} rows", door_rows.len());
        if door_rows.len() != bulk_rows.len() {
            differences.push(format!(
                "`{table}` holds {} rows through the door and {} in bulk",
                door_rows.len(),
                bulk_rows.len()
            ));
            continue;
        }
        if let Some((door_row, bulk_row)) = door_rows
            .iter()
            .zip(bulk_rows)
            .find(|(door_row, bulk_row)| door_row != bulk_row)
        {
            differences.push(format!(
                "`{table}` differs:\n door: {door_row:?}\n bulk: {bulk_row:?}"
            ));
        }
    }
    assert!(differences.is_empty(), "{}", differences.join("\n"));
}
