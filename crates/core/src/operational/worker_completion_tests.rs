use super::*;
use std::time::{Duration, Instant};

/// The attempt's last frame that advanced its projection, read through the
/// attempt-index prefix every production pre-image read uses.
fn last_advancing_frame(
    db: &OperationalDb,
    execution_id: Ulid,
    attempt_id: Ulid,
) -> super::super::TransitionFrame {
    db.read_attempt_transition_prefix(execution_id, attempt_id, i64::MAX)
        .unwrap()
        .into_iter()
        .rev()
        .find(|frame| frame.folds_projection)
        .expect("the attempt has an advancing frame")
}

fn accept(db: &OperationalDb, input: &WorkerCompletionInput) -> KataResult<CompletionVerdict> {
    db.accept_worker_completion(input)
}

fn input(failure: super::super::WorkerFailureInput) -> WorkerCompletionInput {
    WorkerCompletionInput {
        execution_id: failure.execution_id,
        attempt_id: failure.attempt_id,
        attempt_ordinal: failure.attempt_ordinal,
        lease_epoch: failure.lease_epoch,
        worker_id: failure.worker_id,
        output: serde_json::json!({"content":"observed completed output"}),
    }
}

#[test]
fn authoritative_output_threshold_inline_preserves_raw_completion_identity_without_cas() {
    for output_size in [
        crate::store::INLINE_THRESHOLD - 1,
        crate::store::INLINE_THRESHOLD,
    ] {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("operational.db");
        let (db, failure, _) = super::super::worker_failure::tests::fixture_with_db(
            OperationalDb::open(&path).unwrap(),
        );
        let mut input = input(failure);
        // A JSON string contributes exactly two quote bytes beyond its ASCII body.
        input.output = serde_json::Value::String("x".repeat(output_size - 2));
        assert_eq!(canonicalize_args(&input.output).len(), output_size);
        let mut expected = serde_json::to_value(&input).unwrap();
        expected
            .as_object_mut()
            .unwrap()
            .insert("kind".into(), "worker_completion".into());
        let expected = canonicalize_args(&expected);
        assert!(expected.len() > crate::store::INLINE_THRESHOLD);
        let expected_digest = blake3::hash(&expected);
        assert!(matches!(
            accept(&db, &input).unwrap(),
            CompletionVerdict::Accepted { .. }
        ));
        let raw = rusqlite::Connection::open(&path).unwrap();
        let read = || {
            raw.query_row(
                "SELECT payload_json,event_digest FROM event_inbox",
                [],
                |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?)),
            )
            .unwrap()
        };
        let (accepted_bytes, accepted_digest) = read();
        assert!(
            accepted_bytes == expected,
            "acceptance rewrote canonical inbox bytes"
        );
        assert_eq!(accepted_digest, expected_digest.as_bytes());
        let chain: Vec<u8> = raw
            .query_row(
                "SELECT payload_json FROM transitions WHERE kind='event_accepted'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        // Acceptance appends adjudicated delivery facts to the transition, not
        // to the inbox identity. Compare like-shaped records after checking that
        // augmentation explicitly; the complete original envelope must survive.
        let mut chain_value: serde_json::Value = serde_json::from_slice(&chain).unwrap();
        assert!(chain_value.get("output_ref").is_none());
        assert!(
            chain_value.get("output") == Some(&input.output),
            "accepted inline output changed"
        );
        let delivery = chain_value
            .as_object_mut()
            .unwrap()
            .remove("delivery")
            .expect("accepted attempt frame carries adjudicated delivery facts");
        // Neither surviving arm names a stage: the delivery carries the canonical stage id.
        assert_eq!(delivery["stage_name"], "only");
        assert_eq!(delivery["worker_id"], input.worker_id);
        assert!(
            canonicalize_args(&chain_value) == expected,
            "accepted transition changed fields beyond its delivery augmentation"
        );
        let roots: i64 = raw
            .query_row("SELECT count(*) FROM cas_roots", [], |row| row.get(0))
            .unwrap();
        assert_eq!(
            roots, 0,
            "envelope overhead must not offload an inline output"
        );
    }
}

#[test]
fn authoritative_output_one_byte_above_threshold_requires_bound_cas() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("operational.db");
    let (db, failure, _) =
        super::super::worker_failure::tests::fixture_with_db(OperationalDb::open(&path).unwrap());
    let mut input = input(failure);
    input.output = serde_json::Value::String("x".repeat(crate::store::INLINE_THRESHOLD - 1));
    assert_eq!(
        canonicalize_args(&input.output).len(),
        crate::store::INLINE_THRESHOLD + 1
    );
    let raw = rusqlite::Connection::open(&path).unwrap();
    let count = || {
        raw.query_row("SELECT count(*) FROM transitions", [], |row| {
            row.get::<_, i64>(0)
        })
        .unwrap()
    };
    let before = count();
    let error = accept(&db, &input).unwrap_err();
    assert!(
        error.to_string().contains("explicitly bound CAS store"),
        "{error}"
    );
    assert_eq!(count(), before);
    let rows: i64 = raw
        .query_row(
            "SELECT (SELECT count(*) FROM event_inbox)+(SELECT count(*) FROM cas_roots)",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(rows, 0, "refusal must publish neither input nor root");
}

#[test]
fn authoritative_large_completion_keeps_inbox_and_chain_payloads_small() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("operational.db");
    let cas = std::sync::Arc::new(
        crate::store::CasStore::open(
            directory.path().join("cas.db"),
            directory.path().join("cas"),
        )
        .unwrap(),
    );
    let (db, failure, _) = super::super::worker_failure::tests::fixture_with_db(
        OperationalDb::open_with_cas(&path, cas.clone()).unwrap(),
    );
    let mut input = input(failure);
    input.output = serde_json::json!({"content": "actual-output-byte".repeat(16_384)});
    assert!(matches!(
        accept(&db, &input).unwrap(),
        CompletionVerdict::Accepted { .. }
    ));
    let raw = rusqlite::Connection::open(&path).unwrap();
    let (inbox_bytes, chain_bytes): (i64, i64) = raw
        .query_row(
            "SELECT (SELECT max(length(payload_json)) FROM event_inbox),
                (SELECT max(length(payload_json)) FROM transitions WHERE kind='event_accepted')",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    println!("authoritative output raw SQL lengths: inbox={inbox_bytes}, chain={chain_bytes}");
    assert!(
        inbox_bytes < 4096 && chain_bytes < 4096,
        "authoritative large output remained inline: inbox={inbox_bytes}, chain={chain_bytes}"
    );
    let roots: i64 = raw
        .query_row(
            "SELECT count(*) FROM cas_roots WHERE purpose='operational_output'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(roots, 1);
    let frame = last_advancing_frame(&db, input.execution_id, input.attempt_id);
    let resolved = db.resolve_transition_output(&frame).unwrap();
    let value: serde_json::Value = serde_json::from_slice(&resolved.payload_json).unwrap();
    assert_eq!(value["output"], input.output);
    drop(db);
    let reopened = OperationalDb::open_with_cas(&path, cas).unwrap();
    assert_eq!(
        reopened
            .resolve_transition_output(&frame)
            .unwrap()
            .payload_json,
        resolved.payload_json
    );
}

#[test]
fn authoritative_large_output_main_and_stage_completion_and_amendments() {
    use super::super::{UndispatchedStageOutcome, UndispatchedStageRecord};
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("operational.db");
    let cas = std::sync::Arc::new(
        crate::store::CasStore::open(
            directory.path().join("cas.db"),
            directory.path().join("cas"),
        )
        .unwrap(),
    );
    let (db, failure, _) = super::super::worker_failure::tests::fixture_with_db(
        OperationalDb::open_with_cas(&path, cas).unwrap(),
    );
    let output = serde_json::json!({"output_ref":"user text, not a descriptor", "body":"main-stage-output".repeat(16384)});
    db.complete_attempt(failure.attempt_id, &output).unwrap();
    let main_frame = last_advancing_frame(&db, failure.execution_id, failure.attempt_id);
    let main_resolved = db.resolve_transition_output(&main_frame).unwrap();
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&main_resolved.payload_json).unwrap()["output"],
        output
    );
    let amended = serde_json::json!({"body":"amended-output".repeat(16384)});
    db.amend_attempt_outcome(failure.attempt_id, &canonicalize_args(&amended))
        .unwrap();
    let amendments = db.attempt_outcome_amendments(failure.execution_id).unwrap();
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&amendments[0].outcome_json).unwrap(),
        amended
    );
    let stage = Ulid::new();
    db.admit_undispatched_stage(failure.execution_id, stage, "synthetic", "synthetic")
        .unwrap();
    db.record_undispatched_stage_transition(
        stage,
        &UndispatchedStageOutcome {
            state: "completed",
            reason: None,
            child_execution_id: None,
            output: Some(&output),
            finished_at_ms: Some(123),
            awaiting_approval_at_ms: None,
            terminal_charge: None,
        },
    )
    .unwrap();
    db.record_undispatched_stage_metadata(
        stage,
        UndispatchedStageRecord::OutcomeAmended(amended.clone()),
    )
    .unwrap();
    let metadata = db
        .undispatched_stage_metadata(failure.execution_id)
        .unwrap();
    let UndispatchedStageRecord::OutcomeAmended(value) = &metadata[0].record;
    assert_eq!(value, &amended);
    let raw = rusqlite::Connection::open(&path).unwrap();
    let (count, largest): (i64, i64) = raw.query_row(
        "SELECT count(*),max(length(payload_json)) FROM transitions WHERE kind IN ('attempt_advanced','outcome_amended','undispatched_stage_settled','undispatched_stage_recorded')",
        [], |r| Ok((r.get(0)?,r.get(1)?)),
    ).unwrap();
    assert_eq!(count, 4);
    assert!(
        largest < 4096,
        "main/stage output remained inline: {largest}"
    );
    let roots: i64 = raw
        .query_row(
            "SELECT count(*) FROM cas_roots WHERE purpose='operational_output'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(
        roots, 2,
        "same output under same execution shares a protected root"
    );
}

#[test]
fn authoritative_large_output_acceptance_commits_its_root_atomically_and_converges_on_redelivery() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("operational.db");
    let cas = std::sync::Arc::new(
        crate::store::CasStore::open(
            directory.path().join("cas.db"),
            directory.path().join("cas"),
        )
        .unwrap(),
    );
    let (db, failure, _) = super::super::worker_failure::tests::fixture_with_db(
        OperationalDb::open_with_cas(&path, cas.clone()).unwrap(),
    );
    let mut input = input(failure);
    input.output = serde_json::json!({"body":"accepted-output".repeat(16384)});
    db.arm_commit_fault();
    assert!(accept(&db, &input).is_err());
    let raw = rusqlite::Connection::open(&path).unwrap();
    let counts: (i64, i64) = raw
        .query_row(
            "SELECT (SELECT count(*) FROM event_inbox),(SELECT count(*) FROM cas_roots)",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    assert_eq!(
        counts,
        (0, 0),
        "root and accepted reference must commit together"
    );
    assert!(matches!(
        accept(&db, &input).unwrap(),
        CompletionVerdict::Accepted { .. }
    ));
    let before: Vec<u8> = raw
        .query_row(
            "SELECT event_digest FROM event_inbox WHERE accepted=1",
            [],
            |r| r.get(0),
        )
        .unwrap();
    drop(db);
    let db = OperationalDb::open_with_cas(&path, cas).unwrap();
    assert_eq!(
        accept(&db, &input).unwrap(),
        CompletionVerdict::AlreadyAccepted
    );
    let after: Vec<u8> = raw
        .query_row(
            "SELECT event_digest FROM event_inbox WHERE accepted=1",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(before, after);
    let mut different = input.clone();
    different.output["changed"] = true.into();
    assert!(accept(&db, &different).is_err());
}

#[test]
fn authoritative_large_output_missing_binding_or_bytes_refuses() {
    let (unbound, failure, _) = super::super::worker_failure::tests::fixture();
    let mut completion = input(failure);
    completion.output = serde_json::json!({"body":"unbound-output".repeat(16384)});
    assert!(
        accept(&unbound, &completion)
            .unwrap_err()
            .to_string()
            .contains("explicitly bound")
    );
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("operational.db");
    let cas = std::sync::Arc::new(
        crate::store::CasStore::open(
            directory.path().join("cas.db"),
            directory.path().join("cas"),
        )
        .unwrap(),
    );
    let (db, failure, _) = super::super::worker_failure::tests::fixture_with_db(
        OperationalDb::open_with_cas(&path, cas).unwrap(),
    );
    completion = input(failure);
    completion.output = serde_json::json!({"body":"missing-output".repeat(16384)});
    accept(&db, &completion).unwrap();
    let frame = last_advancing_frame(&db, completion.execution_id, completion.attempt_id);
    let cas_raw = rusqlite::Connection::open(directory.path().join("cas.db")).unwrap();
    cas_raw.execute("DELETE FROM cas_objects", []).unwrap();
    assert!(db.resolve_transition_output(&frame).is_err());
    let raw = rusqlite::Connection::open(path).unwrap();
    let retained: i64 = raw
        .query_row("SELECT count(*) FROM cas_roots", [], |r| r.get(0))
        .unwrap();
    assert_eq!(retained, 1);
}

#[test]
fn authoritative_output_root_verifier_checks_content() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("operational.db");
    let cas = std::sync::Arc::new(
        crate::store::CasStore::open(
            directory.path().join("cas.db"),
            directory.path().join("cas"),
        )
        .unwrap(),
    );
    let (db, failure, _) = super::super::worker_failure::tests::fixture_with_db(
        OperationalDb::open_with_cas(&path, cas.clone()).unwrap(),
    );
    db.complete_attempt(
        failure.attempt_id,
        &serde_json::json!({"body":"root-verifier-bytes".repeat(16384)}),
    )
    .unwrap();
    let raw = rusqlite::Connection::open(directory.path().join("cas.db")).unwrap();
    raw.execute("UPDATE cas_objects SET size=size+1", [])
        .unwrap();
    assert!(
        super::super::cas_liveness::verify_authoritative_roots_resolve(&db, &cas).is_err(),
        "output-root verification accepted a wrong byte length"
    );
}

#[test]
fn authoritative_output_root_verifier_refuses_retransmitted_missing_bytes() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("operational.db");
    let cas = std::sync::Arc::new(
        crate::store::CasStore::open(
            directory.path().join("cas.db"),
            directory.path().join("cas"),
        )
        .unwrap(),
    );
    let (db, failure, _) = super::super::worker_failure::tests::fixture_with_db(
        OperationalDb::open_with_cas(&path, cas).unwrap(),
    );
    let mut completion = input(failure);
    completion.output = serde_json::json!({"body":"retained-root-output".repeat(16384)});
    assert!(matches!(
        accept(&db, &completion).unwrap(),
        CompletionVerdict::Accepted { .. }
    ));
    let raw = rusqlite::Connection::open(&path).unwrap();
    let before: Vec<u8> = raw
        .query_row(
            "SELECT event_digest FROM event_inbox WHERE accepted=1",
            [],
            |r| r.get(0),
        )
        .unwrap();
    let address =
        kata_types::cache::cas_address_for_canonical_bytes(&canonicalize_args(&completion.output));
    let rendered = address.to_string();
    let blob = directory
        .path()
        .join("cas")
        .join(&rendered[..2])
        .join(rendered);
    assert!(blob.is_file());
    std::fs::remove_file(&blob).unwrap();
    assert!(
        accept(&db, &completion).is_err(),
        "retransmission silently recreated rooted authority bytes"
    );
    assert!(
        !blob.exists(),
        "refusal must preserve the missing-byte diagnosis"
    );
    let after: Vec<u8> = raw
        .query_row(
            "SELECT event_digest FROM event_inbox WHERE accepted=1",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(before, after);
}

#[test]
fn authoritative_output_reference_scan_checks_the_accepted_inbox_and_chain() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("operational.db");
    let cas = std::sync::Arc::new(
        crate::store::CasStore::open(
            directory.path().join("cas.db"),
            directory.path().join("cas"),
        )
        .unwrap(),
    );
    let (db, failure, _) = super::super::worker_failure::tests::fixture_with_db(
        OperationalDb::open_with_cas(&path, cas.clone()).unwrap(),
    );
    let mut completion = input(failure);
    completion.output = serde_json::json!({"body":"retained-input".repeat(16384)});
    accept(&db, &completion).unwrap();
    let raw = rusqlite::Connection::open(&path).unwrap();
    let verify = |limit| {
        super::super::verify_authoritative_output_references(
            &raw,
            Instant::now() + Duration::from_secs(5),
            limit,
            |address, size, maximum| cas.get_verified(&address.hash(), size, maximum),
        )
    };
    assert_eq!(
        verify(10).unwrap(),
        2,
        "the accepted inbox row and the accepting transition both carry output"
    );
    assert!(
        verify(0).is_err(),
        "bound cannot silently omit the first record"
    );
    raw.execute(
        "UPDATE cas_roots SET purpose='wrong-purpose' WHERE purpose='operational_output'",
        [],
    )
    .unwrap();
    assert!(
        verify(10).is_err(),
        "a coherent artifact still must bind the output to its actual root"
    );
}

#[test]
fn worker_completion_precommit_fault_leaves_no_acceptance_and_a_redelivery_accepts_once() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("operational.db");
    let (db, failure, _) =
        super::super::worker_failure::tests::fixture_with_db(OperationalDb::open(&path).unwrap());
    let input = input(failure);
    db.arm_commit_fault();
    assert!(accept(&db, &input).is_err());
    drop(db);
    let raw = rusqlite::Connection::open(&path).unwrap();
    let facts: (i64, i64) = raw
        .query_row(
            "SELECT
        (SELECT count(*) FROM event_inbox),
        (SELECT count(*) FROM transitions WHERE kind='event_accepted')",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    assert_eq!(facts, (0, 0));
    let db = OperationalDb::open(&path).unwrap();
    assert!(matches!(
        accept(&db, &input).unwrap(),
        CompletionVerdict::Accepted { .. }
    ));
    let facts: (i64, String) = raw
        .query_row(
            "SELECT
        (SELECT count(*) FROM event_inbox WHERE accepted=1),
        (SELECT state FROM attempt_projection)",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    assert_eq!(facts, (1, "completed".into()));
    assert_eq!(
        accept(&db, &input).unwrap(),
        CompletionVerdict::AlreadyAccepted
    );
}

#[test]
fn worker_completion_redelivery_cannot_acknowledge_a_later_stop() {
    let (db, failure, _) = super::super::worker_failure::tests::fixture();
    let input = input(failure);
    assert!(matches!(
        accept(&db, &input).unwrap(),
        CompletionVerdict::Accepted { .. }
    ));
    db.record_stop_request(
        input.attempt_id,
        input.lease_epoch,
        &input.worker_id,
        "later stop",
    )
    .unwrap();
    assert_eq!(
        accept(&db, &input).unwrap(),
        CompletionVerdict::AlreadyAccepted
    );
    db.with_read(|c| {
        let ack: Option<i64> = c
            .query_row(
                "SELECT acknowledged_at_ms FROM attempt_stop_requests",
                [],
                |r| r.get(0),
            )
            .map_err(storage)?;
        assert_eq!(
            ack, None,
            "old accepted terminal cannot discharge a later stop"
        );
        Ok(())
    })
    .unwrap();
}

#[test]
fn worker_completion_stop_ack_is_atomic_with_acceptance() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("operational.db");
    let (db, failure, _) =
        super::super::worker_failure::tests::fixture_with_db(OperationalDb::open(&path).unwrap());
    let input = input(failure);
    db.record_stop_request(
        input.attempt_id,
        input.lease_epoch,
        &input.worker_id,
        "stop old worker",
    )
    .unwrap();
    db.arm_commit_fault();
    assert!(accept(&db, &input).is_err());
    drop(db);
    let raw = rusqlite::Connection::open(&path).unwrap();
    let counts = || {
        raw.query_row(
            "SELECT (SELECT count(*) FROM event_inbox WHERE accepted=1),
        (SELECT count(*) FROM attempt_stop_requests WHERE acknowledged_at_ms IS NOT NULL)",
            [],
            |r| Ok((r.get::<_, i64>(0)?, r.get::<_, i64>(1)?)),
        )
        .unwrap()
    };
    assert_eq!(
        counts(),
        (0, 0),
        "fault cannot acknowledge without accepting"
    );
    let db = OperationalDb::open(&path).unwrap();
    assert!(matches!(
        accept(&db, &input).unwrap(),
        CompletionVerdict::Accepted { .. }
    ));
    assert_eq!(
        counts(),
        (1, 1),
        "the accepted terminal must acknowledge its stop atomically"
    );
}

#[test]
fn worker_completion_of_an_old_generation_cannot_complete_its_successor() {
    let (db, failure, _) = super::super::worker_failure::tests::fixture();
    let input = input(failure);
    db.advance_attempt_generation(input.attempt_id, 1).unwrap();
    assert_eq!(accept(&db, &input).unwrap(), CompletionVerdict::Superseded);
    db.with_read(|c| {
        let rows: i64 = c
            .query_row("SELECT count(*) FROM event_inbox", [], |r| r.get(0))
            .map_err(storage)?;
        assert_eq!(rows, 0, "a superseded completion writes nothing");
        Ok(())
    })
    .unwrap();
}
