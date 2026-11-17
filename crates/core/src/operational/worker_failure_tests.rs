use super::super::{
    AttemptClaimSpec, CommandSpec, InvocationKind, InvocationRecord, ProgramRecord,
};
use super::*;
use crate::operational::OccurrenceBinding;
use kata_types::identity_algebra::AdmissionDigest;
use std::time::Duration;

pub(in crate::operational) fn fixture() -> (OperationalDb, WorkerFailureInput, WorkerFailurePlan) {
    let db = OperationalDb::open_in_memory().unwrap();
    fixture_with_db(db)
}

pub(in crate::operational) fn fixture_with_db(
    db: OperationalDb,
) -> (OperationalDb, WorkerFailureInput, WorkerFailurePlan) {
    let execution_id = Ulid::new();
    let attempt_id = Ulid::new();
    let hash = ContentHash::new([1; 32]);
    let invocation = canonicalize_args(&serde_json::json!({"schema_version":1}));
    db.submit_execution(
        execution_id,
        &ProgramRecord {
            program_hash: hash,
            schema_version: 4,
            program_json: b"{}".to_vec(),
        },
        &InvocationRecord {
            schema_version: 1,
            kind: InvocationKind::Workflow,
            admission_digest: AdmissionDigest(ContentHash::new(
                *blake3::hash(&invocation).as_bytes(),
            )),
            invocation_json: invocation,
        },
    )
    .unwrap();
    db.mark_running(execution_id).unwrap();
    db.dispatch_attempt(
        execution_id,
        attempt_id,
        Ulid::new(),
        &AttemptClaimSpec {
            stage_id: "only".into(),
            initial_state: "pending".to_string(),
            assignment_json: br#"{"capsule":{"stage_name":"fixture"}}"#.to_vec(),
            run_ordinal: 0,
            worker_id: Some("worker".into()),
            occurrence: OccurrenceBinding::for_test(execution_id, "only"),
        },
        &CommandSpec {
            command_json: b"{}".to_vec(),
        },
    )
    .unwrap();
    let current = db.recovered_attempt(attempt_id).unwrap().unwrap();
    let input = WorkerFailureInput {
        execution_id,
        attempt_id,
        attempt_ordinal: current.row.attempt_ordinal,
        lease_epoch: current.row.lease_epoch,
        worker_id: "worker".into(),
        reason: "raw failure".into(),
        verdict: DeliveryFailureProvenance::ProvenNotPerformed,
        usage: None,
        provider_failure: None,
    };
    let plan = WorkerFailurePlan {
        expected: current.placement_expectation().unwrap(),
        program_hash: hash,
        expected_standing_stop: false,
        resolution: WorkerFailureResolution::Failed {
            reason: "policy failure".into(),
        },
    };
    (db, input, plan)
}

fn sql_state(db: &OperationalDb, input: &WorkerFailureInput) -> (i64, i64, String) {
    db.with_read(|c| {
        c.query_row(
            "SELECT a.attempt_ordinal,a.lease_epoch,p.state
        FROM attempts a JOIN attempt_projection p ON p.execution_id=a.execution_id
        AND p.stage_id=a.stage_id AND p.attempt_ordinal=a.attempt_ordinal WHERE a.attempt_id=?1",
            [input.attempt_id.to_bytes().as_slice()],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .map_err(storage)
    })
    .unwrap()
}

#[test]
fn worker_failure_is_atomic_and_a_duplicate_is_an_idempotent_ack() {
    let (db, input, plan) = fixture();
    assert_eq!(
        db.buffer_worker_failure(&input).unwrap(),
        WorkerFailureOffer::Ready
    );
    assert_eq!(
        db.buffered_worker_failures(input.execution_id, Instant::now() + Duration::from_secs(2))
            .unwrap()
            .len(),
        1
    );
    db.adjudicate_worker_failure(&input, &plan)
        .unwrap()
        .unwrap();
    assert_eq!(
        sql_state(&db, &input),
        (input.attempt_ordinal, input.lease_epoch, "failed".into())
    );
    db.with_read(|c| {
        let (accepted, old_state, payload): (i64, String, Vec<u8>) = c
            .query_row(
                "SELECT i.accepted,p.state,t.payload_json FROM event_inbox i
             JOIN transitions t ON t.execution_id=i.execution_id AND t.kind='event_accepted'
             JOIN attempt_projection p ON p.execution_id=t.execution_id AND p.stage_id=t.stage_id
                AND p.attempt_ordinal=t.attempt_ordinal WHERE i.stream_id=?1",
                [input.stream()],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .map_err(storage)?;
        assert_eq!((accepted, old_state), (1, "failed".into()));
        let payload: serde_json::Value = serde_json::from_slice(&payload).unwrap();
        assert!(
            payload.get("failure_resolution").is_none(),
            "an accepted worker failure always settles the attempt; it names no resolution: \
             {payload}"
        );
        assert_eq!(payload["worker_reason"], "raw failure");
        assert_eq!(
            payload["verdict"],
            serde_json::to_value(input.verdict).unwrap()
        );
        Ok(())
    })
    .unwrap();
    assert!(matches!(
        db.adjudicate_worker_failure(&input, &plan).unwrap(),
        Some(EventAcceptance::IdempotentAck)
    ));
}

#[test]
fn worker_failure_redelivery_cannot_acknowledge_a_later_stop() {
    for superseded in [false, true] {
        let (db, input, plan) = fixture();
        db.buffer_worker_failure(&input).unwrap();
        if superseded {
            db.advance_attempt_generation(input.attempt_id, 1).unwrap();
            assert_eq!(
                db.buffer_worker_failure(&input).unwrap(),
                WorkerFailureOffer::Superseded
            );
        } else {
            db.adjudicate_worker_failure(&input, &plan)
                .unwrap()
                .unwrap();
        }
        db.record_stop_request(
            input.attempt_id,
            input.lease_epoch,
            &input.worker_id,
            "later stop",
        )
        .unwrap();
        assert_eq!(
            db.buffer_worker_failure(&input).unwrap(),
            WorkerFailureOffer::AlreadyAccepted
        );
        assert!(matches!(
            db.adjudicate_worker_failure(&input, &plan).unwrap(),
            Some(EventAcceptance::IdempotentAck)
        ));
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
}

#[test]
fn worker_failure_stop_ack_is_atomic_with_replayed_and_superseded_acceptance() {
    for superseded in [true, false] {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("operational.db");
        let (db, input, mut plan) = fixture_with_db(OperationalDb::open(&path).unwrap());
        db.record_stop_request(
            input.attempt_id,
            input.lease_epoch,
            &input.worker_id,
            "stop old worker",
        )
        .unwrap();
        db.buffer_worker_failure(&input).unwrap();
        plan.expected_standing_stop = true;
        plan.resolution = WorkerFailureResolution::Cancelled {
            reason: "stopped".into(),
        };
        if superseded {
            db.advance_attempt_generation(input.attempt_id, 1).unwrap();
            db.record_stop_request(
                input.attempt_id,
                input.lease_epoch + 1,
                "successor",
                "stop successor",
            )
            .unwrap();
        }
        db.arm_commit_fault();
        if superseded {
            assert!(db.buffer_worker_failure(&input).is_err());
        } else {
            assert!(db.adjudicate_worker_failure(&input, &plan).is_err());
        }
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
        if superseded {
            assert_eq!(
                db.buffer_worker_failure(&input).unwrap(),
                WorkerFailureOffer::Superseded
            );
        } else {
            assert!(
                db.adjudicate_worker_failure(&input, &plan)
                    .unwrap()
                    .is_some()
            );
        }
        assert_eq!(
            counts(),
            (1, 1),
            "retained physical terminal must acknowledge its stop atomically"
        );
        if superseded {
            let successor: Option<i64> = raw
                .query_row(
                    "SELECT acknowledged_at_ms FROM attempt_stop_requests WHERE lease_epoch=?1",
                    [input.lease_epoch + 1],
                    |r| r.get(0),
                )
                .unwrap();
            assert_eq!(
                successor, None,
                "old physical input cannot acknowledge the successor"
            );
        }
    }
}

#[test]
fn worker_failure_superseded_buffer_is_consumed_without_touching_current_generation() {
    let (db, input, _) = fixture();
    db.buffer_worker_failure(&input).unwrap();
    db.advance_attempt_generation(input.attempt_id, 1).unwrap();
    assert_eq!(
        db.buffer_worker_failure(&input).unwrap(),
        WorkerFailureOffer::Superseded
    );
    assert!(
        db.buffered_worker_failures(input.execution_id, Instant::now() + Duration::from_secs(2))
            .unwrap()
            .is_empty()
    );
    db.with_read(|c| {
        let accepted: i64 = c
            .query_row(
                "SELECT count(*) FROM transitions WHERE kind='event_accepted'",
                [],
                |r| r.get(0),
            )
            .map_err(storage)?;
        assert_eq!(
            accepted, 0,
            "the superseded input settles nothing on the current generation"
        );
        Ok(())
    })
    .unwrap();
}

#[test]
fn worker_failure_precommit_fault_reopens_with_raw_input_and_no_partial_resolution() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("operational.db");
    let (db, input, plan) = fixture_with_db(OperationalDb::open(&path).unwrap());
    db.arm_commit_fault();
    assert!(db.buffer_worker_failure(&input).is_err());
    assert!(
        db.buffered_worker_failures(input.execution_id, Instant::now() + Duration::from_secs(2))
            .unwrap()
            .is_empty()
    );
    db.buffer_worker_failure(&input).unwrap();
    db.arm_commit_fault();
    assert!(db.adjudicate_worker_failure(&input, &plan).is_err());
    drop(db);
    let db = OperationalDb::open(&path).unwrap();
    assert_eq!(
        sql_state(&db, &input),
        (
            input.attempt_ordinal,
            input.lease_epoch,
            "dispatched".into()
        )
    );
    let raw = rusqlite::Connection::open(&path).unwrap();
    let facts: (i64, i64) = raw
        .query_row(
            "SELECT
        (SELECT count(*) FROM event_inbox WHERE accepted=0),
        (SELECT count(*) FROM transitions WHERE kind='event_accepted')",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    assert_eq!(facts, (1, 0));
    db.adjudicate_worker_failure(&input, &plan)
        .unwrap()
        .unwrap();
    drop(db);
    let db = OperationalDb::open(&path).unwrap();
    assert_eq!(
        sql_state(&db, &input),
        (input.attempt_ordinal, input.lease_epoch, "failed".into())
    );
}

#[test]
fn worker_failure_terminal_verdicts_are_recorded_on_the_failed_attempt() {
    for verdict in DeliveryFailureProvenance::every() {
        let (db, mut input, mut plan) = fixture();
        input.verdict = verdict;
        plan.resolution = WorkerFailureResolution::Failed {
            reason: "terminal policy".into(),
        };
        db.adjudicate_worker_failure(&input, &plan)
            .unwrap()
            .unwrap();
        assert_eq!(
            db.attempt_terminal_verdict(input.attempt_id).unwrap(),
            Some(verdict),
            "the failure-retry decision reads the verdict off the terminal transition"
        );
        assert_eq!(
            sql_state(&db, &input),
            (input.attempt_ordinal, input.lease_epoch, "failed".into())
        );
    }
}

#[test]
fn worker_failure_source_program_and_standing_stop_cas_refuse_without_acceptance() {
    let (db, input, mut plan) = fixture();
    db.buffer_worker_failure(&input).unwrap();
    plan.program_hash = ContentHash::new([9; 32]);
    assert!(
        db.adjudicate_worker_failure(&input, &plan)
            .unwrap()
            .is_none()
    );
    plan.program_hash = ContentHash::new([1; 32]);
    db.with_read(|c|{
        c.execute("INSERT INTO attempt_stop_requests(attempt_id,lease_epoch,execution_id,worker_id,reason,
            requested_at_ms,acknowledged_at_ms) VALUES(?1,?2,?3,?4,'cancel',1,2)",
            params![input.attempt_id.to_bytes().as_slice(),input.lease_epoch,input.execution_id.to_bytes().as_slice(),input.worker_id]).map_err(storage)?;
        Ok(())
    }).unwrap();
    assert!(
        db.adjudicate_worker_failure(&input, &plan)
            .unwrap()
            .is_none()
    );
    assert_eq!(
        sql_state(&db, &input),
        (
            input.attempt_ordinal,
            input.lease_epoch,
            "dispatched".into()
        )
    );
    plan.expected_standing_stop = true;
    plan.resolution = WorkerFailureResolution::Cancelled {
        reason: "standing cancel".into(),
    };
    db.adjudicate_worker_failure(&input, &plan)
        .unwrap()
        .unwrap();
    assert_eq!(
        sql_state(&db, &input),
        (input.attempt_ordinal, input.lease_epoch, "cancelled".into())
    );
}
