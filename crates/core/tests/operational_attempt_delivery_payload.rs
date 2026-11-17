//! Immutable attempt delivery facts are asserted through an independent SQLite reader.
use kata_core::operational::OccurrenceBinding;
use kata_core::operational::{AttemptClaimSpec, MainSideTransition};
use kata_core::{InvocationKind, InvocationRecord, OperationalDb, ProgramRecord};
use kata_types::identity_algebra::AdmissionDigest;
use kata_types::primitives::ContentHash;
use ulid::Ulid;

fn submit(db: &OperationalDb) -> Ulid {
    let id = Ulid::new();
    db.submit_execution(
        id,
        &ProgramRecord {
            program_hash: ContentHash::new([9; 32]),
            schema_version: 4,
            program_json: b"{\"program\":1}".to_vec(),
        },
        &InvocationRecord {
            schema_version: 1,
            kind: InvocationKind::Workflow,
            admission_digest: AdmissionDigest(ContentHash::new(
                *blake3::hash(b"{\"schema_version\":1}").as_bytes(),
            )),
            invocation_json: b"{\"schema_version\":1}".to_vec(),
        },
    )
    .unwrap();
    db.mark_running(id).unwrap();
    id
}

fn claim(
    db: &OperationalDb,
    execution: Ulid,
    bytes: &[u8],
) -> kata_core::operational::ClaimedAttempt {
    db.claim_attempt(
        execution,
        Ulid::new(),
        &AttemptClaimSpec {
            stage_id: "build".into(),
            assignment_json: bytes.to_vec(),
            initial_state: "pending".into(),
            run_ordinal: 0,
            worker_id: None,
            occurrence: OccurrenceBinding::for_test(execution, "build"),
        },
    )
    .unwrap()
}

fn payload(sql: &rusqlite::Connection, seq: i64) -> serde_json::Value {
    let bytes: Vec<u8> = sql
        .query_row(
            "SELECT payload_json FROM transitions WHERE seq=?1",
            [seq],
            |row| row.get(0),
        )
        .unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

#[test]
fn stalled_observation_captures_history_without_folding_lifecycle() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("operational.db");
    let db = OperationalDb::open(&path).unwrap();
    let execution = submit(&db);
    claim(&db, execution, br#"{"capsule":{"stage_name":"original"}}"#);
    let sql = rusqlite::Connection::open(&path).unwrap();
    let id: Vec<u8> = sql
        .query_row("SELECT attempt_id FROM attempts", [], |r| r.get(0))
        .unwrap();
    let attempt = Ulid::from_bytes(id.try_into().unwrap());
    sql.execute("UPDATE attempts SET worker_id='worker'", [])
        .unwrap();
    let seq = db
        .record_attempt_stalled(attempt, "worker", 123, 7)
        .unwrap()
        .unwrap();
    let captured = payload(&sql, seq);
    assert_eq!(captured["delivery"]["stage_name"], "build");
    assert_eq!(captured["last_heartbeat_at_ms"], 123);
    assert_eq!(captured["stalled_for_secs"], 7);
    let lifecycle: String = sql
        .query_row("SELECT state FROM attempt_projection", [], |r| r.get(0))
        .unwrap();
    assert_eq!(lifecycle, "pending");
    let folds: i64 = sql
        .query_row(
            "SELECT folds_projection FROM transitions WHERE seq=?1",
            [seq],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(folds, 0);
    sql.execute(
        "UPDATE attempts SET worker_id='replacement', assignment_json=?1",
        [br#"{"capsule":{"stage_name":"later"}}"#.as_slice()],
    )
    .unwrap();
    assert_eq!(payload(&sql, seq), captured);
    assert_eq!(
        db.record_attempt_stalled(attempt, "worker", 123, 7)
            .unwrap(),
        None
    );
    assert!(
        db.record_attempt_stalled(attempt, "replacement", -1, 7)
            .is_err()
    );
    let count = || {
        sql.query_row("SELECT COUNT(*) FROM transitions", [], |row| {
            row.get::<_, i64>(0)
        })
        .unwrap()
    };
    let before = count();
    // The capture reads the ROW, never the blob (neither surviving arm carries a
    // display name), so the malformed input is a row column the capture decodes: a
    // child link that is not a ULID.
    sql.execute("UPDATE attempts SET child_execution_id=x'00'", [])
        .unwrap();
    assert!(
        db.record_attempt_stalled(attempt, "replacement", 124, 8)
            .is_err()
    );
    assert_eq!(
        count(),
        before,
        "malformed capture rolls back the new authority record"
    );
    sql.execute("UPDATE attempts SET child_execution_id=NULL", [])
        .unwrap();
    sql.execute("DELETE FROM attempt_projection", []).unwrap();
    assert!(
        db.record_attempt_stalled(attempt, "replacement", 124, 8)
            .is_err(),
        "missing projection is corruption, not an absent attempt"
    );
}

#[test]
fn delivery_payload_captures_claim_and_adjudicated_postimage() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("operational.db");
    let db = OperationalDb::open(&path).unwrap();
    let execution = submit(&db);
    let claimed = claim(&db, execution, br#"{"capsule":{"stage_name":"original"}}"#);
    let sql = rusqlite::Connection::open(&path).unwrap();
    let attempt_bytes: Vec<u8> = sql
        .query_row("SELECT attempt_id FROM attempts", [], |row| row.get(0))
        .unwrap();
    let attempt = Ulid::from_bytes(attempt_bytes.try_into().unwrap());
    let before = payload(&sql, claimed.seq);
    assert_eq!(before["delivery"]["stage_name"], "build");
    assert!(
        before["delivery"]
            .as_object()
            .unwrap()
            .contains_key("last_checkpoint")
    );
    db.record_attempt_safe_point(attempt, 7).unwrap();
    let first = db
        .record_main_side_transition(attempt, &MainSideTransition::bare("pending"))
        .unwrap();
    let second = db
        .record_main_side_transition(attempt, &MainSideTransition::bare("pending"))
        .unwrap();
    assert_eq!(payload(&sql, first)["delivery"]["last_checkpoint"], 7);
    assert_eq!(payload(&sql, claimed.seq), before);
    let delivery = payload(&sql, second)["delivery"].clone();
    for retired in ["retry_after_ms", "failure_retry_attempt"] {
        assert!(
            delivery.get(retired).is_none(),
            "the delivery snapshot carries no `{retired}`: {delivery}"
        );
    }
    assert!(payload(&sql, second).get("worker_id").is_none());
}

#[test]
fn delivery_payload_fused_dispatch_and_approval_anchor_are_captured() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("operational.db");
    let db = OperationalDb::open(&path).unwrap();
    let execution = submit(&db);
    let attempt = Ulid::new();
    let seq = db
        .dispatch_attempt(
            execution,
            attempt,
            Ulid::new(),
            &kata_core::operational::AttemptClaimSpec {
                stage_id: "build".into(),
                initial_state: "pending".to_string(),
                assignment_json: br#"{"capsule":{"stage_name":"build"}}"#.to_vec(),
                worker_id: Some("worker-b".into()),
                run_ordinal: 0,
                occurrence: OccurrenceBinding::for_test(execution, "build"),
            },
            &kata_core::operational::CommandSpec {
                command_json: b"{}".to_vec(),
            },
        )
        .unwrap();
    let sql = rusqlite::Connection::open(&path).unwrap();
    assert_eq!(payload(&sql, seq)["delivery"]["worker_id"], "worker-b");
    // The fused door is claim + dispatch in one commit: the assignment rides the
    // CLAIMING transition, the placement the dispatching one.
    let claimed: i64 = sql
        .query_row(
            "SELECT seq FROM transitions WHERE attempt_id=?1 AND kind='claimed'",
            [attempt.to_bytes().as_slice()],
            |r| r.get(0),
        )
        .unwrap();
    assert!(
        claimed < seq,
        "the claim precedes the dispatch in the chain"
    );
    assert_eq!(
        payload(&sql, claimed)["assignment"]["capsule"]["stage_name"],
        "build"
    );
    let approval = db
        .record_main_side_transition(
            attempt,
            &MainSideTransition {
                reason: Some("operator must approve candidate"),
                ..MainSideTransition::bare("awaiting_approval")
            },
        )
        .unwrap();
    let recorded: i64 = sql
        .query_row(
            "SELECT recorded_at_ms FROM transitions WHERE seq=?1",
            [approval],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(
        payload(&sql, approval)["delivery"]["awaiting_approval_at_ms"],
        recorded
    );
    let next = db.advance_attempt(attempt, "pending").unwrap();
    assert_eq!(
        payload(&sql, next)["delivery"]["awaiting_approval_at_ms"],
        recorded
    );
}

#[test]
fn delivery_payload_malformed_inbox_aborts_the_whole_transition() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("operational.db");
    let db = OperationalDb::open(&path).unwrap();
    let execution = submit(&db);
    let claimed = claim(&db, execution, br#"{"capsule":{"stage_name":"build"}}"#);
    let sql = rusqlite::Connection::open(&path).unwrap();
    let bytes: Vec<u8> = sql
        .query_row("SELECT attempt_id FROM attempts", [], |r| r.get(0))
        .unwrap();
    let attempt = Ulid::from_bytes(bytes.try_into().unwrap());
    assert!(
        db.accept_incoming_event(
            execution,
            attempt,
            b"stream",
            1,
            ContentHash::new([1; 32]),
            "failed",
            b"[]"
        )
        .is_err()
    );
    assert_eq!(
        sql.query_row("SELECT count(*) FROM event_inbox", [], |r| r
            .get::<_, i64>(0))
            .unwrap(),
        0
    );
    assert_eq!(
        sql.query_row("SELECT MAX(seq) FROM transitions", [], |r| r
            .get::<_, i64>(0))
            .unwrap(),
        claimed.seq
    );
}

#[test]
fn delivery_payload_refuses_bad_assignment_and_rolls_back_adjudication() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("operational.db");
    let db = OperationalDb::open(&path).unwrap();
    let execution = submit(&db);
    let sql = rusqlite::Connection::open(&path).unwrap();
    let head = || {
        sql.query_row("SELECT MAX(seq) FROM transitions", [], |r| {
            r.get::<_, i64>(0)
        })
        .unwrap()
    };
    let before = head();
    for bytes in [
        b"{}".as_slice(),
        br#"{"main":{"stage_id":"build"}}"#,
        b"not-json",
    ] {
        assert!(
            db.claim_attempt(
                execution,
                Ulid::new(),
                &AttemptClaimSpec {
                    stage_id: "build".into(),
                    assignment_json: bytes.to_vec(),
                    initial_state: "pending".into(),
                    run_ordinal: 0,
                    worker_id: None,
                    occurrence: OccurrenceBinding::for_test(execution, "build"),
                }
            )
            .is_err()
        );
        assert_eq!(head(), before);
    }
    let claimed = claim(&db, execution, br#"{"capsule":{"stage_name":"build"}}"#);
    let attempt_bytes: Vec<u8> = sql
        .query_row("SELECT attempt_id FROM attempts", [], |r| r.get(0))
        .unwrap();
    let attempt = Ulid::from_bytes(attempt_bytes.try_into().unwrap());
    db.arm_commit_fault();
    assert!(
        db.record_main_side_transition(attempt, &MainSideTransition::bare("pending"))
            .is_err()
    );
    assert_eq!(head(), claimed.seq);
    let accepted = db.advance_attempt(attempt, "pending").unwrap();
    assert_eq!(payload(&sql, accepted)["delivery"]["stage_name"], "build");
}

#[test]
fn delivery_snapshot_requires_nullable_keys_and_rejects_unknown_fields() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("operational.db");
    let db = OperationalDb::open(&path).unwrap();
    let execution = submit(&db);
    let claimed = claim(&db, execution, br#"{"capsule":{"stage_name":"build"}}"#);
    let sql = rusqlite::Connection::open(&path).unwrap();
    let snapshot = payload(&sql, claimed.seq)["delivery"].clone();
    serde_json::from_value::<kata_core::operational::AttemptDeliverySnapshot>(snapshot.clone())
        .unwrap();
    for key in snapshot.as_object().unwrap().keys() {
        let mut incomplete = snapshot.clone();
        incomplete.as_object_mut().unwrap().remove(key);
        assert!(
            serde_json::from_value::<kata_core::operational::AttemptDeliverySnapshot>(incomplete)
                .is_err(),
            "missing {key}"
        );
    }
    let mut unknown = snapshot;
    unknown["invented"] = true.into();
    assert!(
        serde_json::from_value::<kata_core::operational::AttemptDeliverySnapshot>(unknown).is_err()
    );
}

#[test]
fn safe_point_records_postclamp_value_and_rollback_preserves_chain() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("operational.db");
    let db = OperationalDb::open(&path).unwrap();
    let execution = submit(&db);
    claim(&db, execution, br#"{"capsule":{"stage_name":"build"}}"#);
    let sql = rusqlite::Connection::open(&path).unwrap();
    let bytes: Vec<u8> = sql
        .query_row("SELECT attempt_id FROM attempts", [], |r| r.get(0))
        .unwrap();
    let attempt = Ulid::from_bytes(bytes.try_into().unwrap());
    assert_eq!(db.record_attempt_safe_point(attempt, 9).unwrap(), 9);
    assert_eq!(db.record_attempt_safe_point(attempt, 3).unwrap(), 9);
    let mut stmt = sql
        .prepare(
            "SELECT payload_json FROM transitions WHERE kind='attempt_safe_point' ORDER BY seq",
        )
        .unwrap();
    let values = stmt
        .query_map([], |r| r.get::<_, Vec<u8>>(0))
        .unwrap()
        .map(|r| serde_json::from_slice::<serde_json::Value>(&r.unwrap()).unwrap())
        .collect::<Vec<_>>();
    assert_eq!(values, vec![serde_json::json!({"last_checkpoint":9}); 2]);
    db.arm_commit_fault();
    assert!(db.record_attempt_safe_point(attempt, 10).is_err());
    assert_eq!(
        sql.query_row("SELECT last_checkpoint FROM attempts", [], |r| r
            .get::<_, i64>(0))
            .unwrap(),
        9
    );
    assert_eq!(
        sql.query_row(
            "SELECT count(*) FROM transitions WHERE kind='attempt_safe_point'",
            [],
            |r| r.get::<_, i64>(0)
        )
        .unwrap(),
        2
    );
}

#[test]
fn delivery_payload_tracks_child_assignment_without_rewriting_history() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("operational.db");
    let db = OperationalDb::open(&path).unwrap();
    let execution = submit(&db);
    let claimed = claim(&db, execution, br#"{"capsule":{"stage_name":"first"}}"#);
    let sql = rusqlite::Connection::open(&path).unwrap();
    let bytes: Vec<u8> = sql
        .query_row("SELECT attempt_id FROM attempts", [], |r| r.get(0))
        .unwrap();
    let attempt = Ulid::from_bytes(bytes.try_into().unwrap());
    let child = Ulid::new();
    let park = db
        .record_main_side_transition(
            attempt,
            &MainSideTransition {
                reason: Some("await requested child result"),
                child_execution_id: Some(child),
                ..MainSideTransition::bare("awaiting_child_completion")
            },
        )
        .unwrap();
    assert_eq!(
        payload(&sql, park)["delivery"]["child_execution_id"],
        child.to_string()
    );
    assert_eq!(
        payload(&sql, park)["reason"],
        "await requested child result"
    );
    let advance = db.advance_attempt(attempt, "pending").unwrap();
    assert_eq!(payload(&sql, advance)["delivery"]["stage_name"], "build");
    assert_eq!(
        payload(&sql, claimed.seq)["assignment"]["capsule"]["stage_name"],
        "first"
    );
    assert_eq!(payload(&sql, park)["delivery"]["stage_name"], "build");
}

#[test]
fn delivery_payload_inbox_keeps_canonical_bytes_and_snapshots_accepted_terminal() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("operational.db");
    let db = OperationalDb::open(&path).unwrap();
    let execution = submit(&db);
    claim(&db, execution, br#"{"capsule":{"stage_name":"build"}}"#);
    let sql = rusqlite::Connection::open(&path).unwrap();
    let bytes: Vec<u8> = sql
        .query_row("SELECT attempt_id FROM attempts", [], |r| r.get(0))
        .unwrap();
    let attempt = Ulid::from_bytes(bytes.try_into().unwrap());
    let command = kata_core::operational::CommandSpec {
        command_json: br#"{"kind":"dispatch"}"#.to_vec(),
    };
    let dispatched = db
        .dispatch_claimed_attempt(attempt, "worker-a", Ulid::new(), &command)
        .unwrap();
    let kata_core::operational::ClaimOutcome::Recorded { seq: dispatch_seq } = dispatched else {
        panic!("new dispatch");
    };
    assert_eq!(
        payload(&sql, dispatch_seq)["delivery"]["worker_id"],
        "worker-a"
    );
    assert!(payload(&sql, dispatch_seq)["delivery"]["dispatched_at_ms"].is_i64());
    let canonical = br#"{ "kind":"completed", "output":{"result":7} }"#;
    let digest = ContentHash::new(*blake3::hash(canonical).as_bytes());
    let accepted = db
        .accept_incoming_event(
            execution,
            attempt,
            b"stream",
            1,
            digest,
            "completed",
            canonical,
        )
        .unwrap();
    let kata_core::operational::EventAcceptance::Accepted { seq } = accepted else {
        panic!("new acceptance");
    };
    let stored: (Vec<u8>, Vec<u8>) = sql
        .query_row(
            "SELECT payload_json,event_digest FROM event_inbox",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    assert_eq!(stored.0, canonical);
    assert_eq!(stored.1, digest.as_bytes());
    assert_eq!(payload(&sql, seq)["delivery"]["worker_id"], "worker-a");
    assert!(payload(&sql, seq)["delivery"]["finished_at_ms"].is_i64());
    assert_eq!(
        payload(&sql, seq)["output"],
        serde_json::json!({"result":7})
    );
    assert!(matches!(
        db.accept_incoming_event(
            execution,
            attempt,
            b"stream",
            1,
            digest,
            "completed",
            canonical
        )
        .unwrap(),
        kata_core::operational::EventAcceptance::IdempotentAck
    ));
}

/// THE CAPSULE ARM AT THE CORE LEVEL.
///
/// # What this covers that the workflow-crate tests cannot
///
/// `kata-core` is the crate that WRITES the transition payload and the delivery
/// snapshot, and it does so without depending on `kata-transport`: it walks the blob
/// structurally for the arm tag. Every other test
/// of the capsule arm lives a crate away, where `DispatchFrame` is in scope — so none of
/// them exercises this plane's own reader against a capsule blob. This one does, with a
/// hand-written capsule arm rather than the transport type, which is the point: the
/// structural reader must agree with a shape it cannot name.
///
/// Three facts, each of which a defect would break separately:
///
/// 1. the claim is ACCEPTED — a capsule arm carries no `stage_name`, and refusing it
///    would make an authorized occurrence undispatchable;
/// 2. the transition payload carries the frame VERBATIM under `assignment`, arm tag
///    included, so a reader can tell which shape the attempt was claimed with;
/// 3. the delivery snapshot's `stage_name` falls back to `attempts.stage_id` — the
///    CANONICAL id — instead of being empty, which is what a naive "the blob has no
///    stage name" path would leave behind.
#[test]
fn delivery_payload_accepts_a_capsule_arm_and_names_the_stage_from_the_attempt_row() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("operational.db");
    let db = OperationalDb::open(&path).unwrap();
    let execution = submit(&db);

    // A capsule arm, spelled by hand. `kata-core` does not depend on
    // `kata-transport`, so a fixture built from `DispatchFrame` would be testing this
    // reader against the very type it deliberately cannot see.
    let capsule = br#"{"capsule":{"attempt_id":"01JZZZZZZZZZZZZZZZZZZZZZH1",
        "occurrence_id":"0101010101010101010101010101010101010101010101010101010101010101",
        "capsule":{"id":"0202020202020202020202020202020202020202020202020202020202020202",
        "object":"0303030303030303030303030303030303030303030303030303030303030303",
        "size_bytes":512},"lease_epoch":0}}"#;
    let claimed = claim(&db, execution, capsule);

    let sql = rusqlite::Connection::open(&path).unwrap();
    let recorded = payload(&sql, claimed.seq);
    assert!(
        recorded["assignment"]["capsule"].is_object(),
        "the payload must carry the frame VERBATIM, arm tag included: {recorded}"
    );
    assert!(
        recorded["assignment"]["main"].is_null(),
        "and it must not have invented the other arm: {recorded}"
    );
    assert_eq!(
        recorded["delivery"]["stage_name"], "build",
        "a capsule frame carries no display name, so the snapshot takes the CANONICAL \
         `attempts.stage_id` — never an empty string, which is what a reader would show \
         an operator"
    );

    // NON-VACUITY OF THE FALLBACK: the blob genuinely has no `stage_name` anywhere, so
    // "build" cannot have come from it.
    let stored: Vec<u8> = sql
        .query_row("SELECT assignment_json FROM attempts", [], |row| row.get(0))
        .unwrap();
    assert!(
        !String::from_utf8(stored).unwrap().contains("stage_name"),
        "the capsule blob must carry no stage_name, or the fallback is untested"
    );

    // AND AN ADVANCING TRANSITION over the same attempt keeps the fallback, so the
    // snapshot is not merely right at the claim.
    let attempt: Vec<u8> = sql
        .query_row("SELECT attempt_id FROM attempts", [], |row| row.get(0))
        .unwrap();
    let attempt = Ulid::from_bytes(attempt.try_into().expect("a stored ULID is 16 bytes"));
    let advanced = db
        .record_main_side_transition(attempt, &MainSideTransition::bare("awaiting_approval"))
        .unwrap();
    assert_eq!(payload(&sql, advanced)["delivery"]["stage_name"], "build");
    drop(dir);
}
