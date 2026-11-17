//! Direct SDK opens must enforce the durable JSON boundary without a main lock.
//!
//! The disposition of a durable shape change is stated once, in
//! `crates/core/src/operational/schema.rs` under `OPERATIONAL_SCHEMA_VERSION`'s
//! "Disposition rule for a shape change": a database at any other stamp is REFUSED
//! before SQLite is opened, and the refusal changes no bytes. The table below is the
//! per-store proof of that rule.

use std::collections::BTreeMap;
use std::path::Path;

use kata_core::{DurableEventLog, OperationalDb};

fn files(dir: &Path) -> BTreeMap<std::ffi::OsString, Vec<u8>> {
    std::fs::read_dir(dir)
        .unwrap()
        .map(|entry| {
            let entry = entry.unwrap();
            (entry.file_name(), std::fs::read(entry.path()).unwrap())
        })
        .collect()
}

fn prior_stamp_refuses_without_mutation(
    name: &str,
    prior: i64,
    open: impl Fn(&Path) -> kata_types::error::KataResult<()>,
) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join(name);
    open(&path).unwrap();
    let conn = rusqlite::Connection::open(&path).unwrap();
    conn.pragma_update(None, "user_version", prior).unwrap();
    drop(conn);
    let before = files(dir.path());

    let result = open(&path);
    assert!(result.is_err(), "{name}: prior payload format was admitted");
    let message = result.unwrap_err().to_string();
    assert!(message.contains("schema version"), "{message}");
    assert_eq!(files(dir.path()), before, "{name}: refusal changed bytes");
}

#[test]
fn direct_event_open_refuses_prior_completion_payload_format() {
    prior_stamp_refuses_without_mutation("ledger_events.db", 1, |path| {
        DurableEventLog::open(path).map(drop)
    });
}

#[test]
fn direct_operational_open_refuses_prior_attempt_payload_format() {
    for prior in [11, 13] {
        prior_stamp_refuses_without_mutation("operational.db", prior, |path| {
            OperationalDb::open(path).map(drop)
        });
    }
}
