//! Large authority outputs must survive the workflow's cold delivery/population readers.
use std::sync::Arc;

use kata_core::operational::OccurrenceBinding;
use kata_core::operational::{
    AttemptClaimSpec, CommandSpec, MainSideTransition, WorkerCompletionInput,
};
use kata_core::{InvocationKind, InvocationRecord, OperationalDb, ProgramRecord};
use kata_test_utils::sample_capsule_assignment;
use kata_types::idempotency::canonicalize_args;
use kata_types::identity::WorkerMembraneId;
use kata_types::identity_algebra::AdmissionDigest;
use kata_types::ledger::LedgerLogEvent;
use kata_types::primitives::ContentHash;
use kata_workflow::attempt_delivery::{AttemptDeliveryMapper, MappedFrame};
use ulid::Ulid;

#[test]
fn cold_workflow_readers_preserve_large_completion_and_latest_amendment() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("operational.db");
    let cas_path = directory.path().join("cas.db");
    let blobs = directory.path().join("cas");
    let cas = Arc::new(kata_core::store::CasStore::open(&cas_path, &blobs).unwrap());
    let db = OperationalDb::open_with_cas(&path, cas).unwrap();
    let execution = Ulid::new();
    let mut capsule = sample_capsule_assignment();
    capsule.execution_id = execution;
    capsule.capsule.id = kata_types::execution_contract::CapsuleId(
        kata_types::primitives::ContentHash::new([7; 32]),
    );
    let attempt = capsule.attempt_id;
    let assignment_json = serde_json::to_vec(&kata_transport::types::DispatchFrame::Capsule(
        Box::new(capsule),
    ))
    .unwrap();
    let hash = ContentHash::new([41; 32]);
    db.submit_execution(
        execution,
        &ProgramRecord {
            program_hash: hash,
            schema_version: 4,
            program_json: b"{}".to_vec(),
        },
        &InvocationRecord {
            schema_version: 1,
            kind: InvocationKind::Workflow,
            admission_digest: AdmissionDigest(hash),
            invocation_json: b"{}".to_vec(),
        },
    )
    .unwrap();
    db.mark_running(execution).unwrap();
    let domain = db
        .enroll_worker_domain("test-main", WorkerMembraneId(Ulid::new()))
        .unwrap();
    let claim = db
        .claim_attempt(
            execution,
            attempt,
            &AttemptClaimSpec {
                stage_id: "draft".into(),
                assignment_json: assignment_json.clone(),
                initial_state: "pending".into(),
                run_ordinal: 0,
                worker_id: None,
                occurrence: OccurrenceBinding::for_test(execution, "draft"),
            },
        )
        .unwrap();
    let expected = db
        .recovered_attempt(attempt)
        .unwrap()
        .unwrap()
        .placement_expectation()
        .unwrap();
    db.dispatch_claimed_attempt_in_domain(
        attempt,
        "worker",
        Ulid::new(),
        &CommandSpec {
            command_json: b"{}".to_vec(),
        },
        &domain,
        &expected,
    )
    .unwrap()
    .unwrap();
    db.record_main_side_transition(attempt, &MainSideTransition::bare("running"))
        .unwrap();
    let original = serde_json::json!({"content": serde_json::to_string(&serde_json::json!({"blob":"a".repeat(110_000)})).unwrap()});
    let amended =
        serde_json::json!({"content":original["content"], "parsed":{"blob":"b".repeat(110_000)}});
    let completion = WorkerCompletionInput {
        execution_id: execution,
        attempt_id: attempt,
        attempt_ordinal: claim.attempt_ordinal,
        lease_epoch: claim.lease_epoch + 1,
        worker_id: "worker".into(),
        output: original.clone(),
    };
    assert!(matches!(
        db.accept_worker_completion(&completion).unwrap(),
        kata_core::operational::CompletionVerdict::Accepted { .. }
    ));
    db.amend_attempt_outcome(attempt, &canonicalize_args(&amended))
        .unwrap();
    let raw = rusqlite::Connection::open(&path).unwrap();
    let roots: i64 = raw
        .query_row(
            "SELECT count(*) FROM cas_roots WHERE purpose='operational_output'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(
        roots, 2,
        "completion and amendment are distinct rooted objects"
    );
    let largest: i64 = raw
        .query_row(
            "SELECT max(length(payload_json)) FROM transitions",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert!(
        largest < 16_384,
        "fixture must use descriptors, not inline outputs"
    );
    drop(raw);
    drop(db);

    let cas = Arc::new(kata_core::store::CasStore::open(&cas_path, &blobs).unwrap());
    let db = Arc::new(OperationalDb::open_with_cas(&path, cas).unwrap());
    let mapper = AttemptDeliveryMapper::new(db.clone());
    let page = mapper.map_page(execution, 1, 10_000).unwrap();
    let outputs: Vec<_> = page
        .mapped
        .into_iter()
        .filter_map(|mapped| match mapped {
            MappedFrame::Delivery(frame) => Some(frame),
            MappedFrame::Checkpoint { .. } => None,
        })
        .filter_map(|frame| {
            let event: LedgerLogEvent = serde_json::from_value(frame.event.payload).unwrap();
            event.as_ledger_event().unwrap().output.clone()
        })
        .collect();
    assert!(
        outputs.contains(&original),
        "cold delivery loses the full raw completion Value"
    );
    let states = mapper.execution_assignment_states(execution).unwrap();
    assert_eq!(states.len(), 1);
    assert_eq!(
        states[0].output(),
        Some(&amended),
        "cold population must retain latest parsed amendment"
    );

    // Installed recovery reconciles this runner before activation; run() then
    // boots it again with a fresh context. Both folds must reconstruct outputs.
    let program = kata_program::execution_program::compile_execution_program_from_parts_for_tests(
        kata_test_utils::simple_two_stage_workflow(),
        kata_program::policy::WorkflowExtensions::empty(),
        kata_program::execution_program::ExecutionProgramCompileOptions::empty(),
    )
    .unwrap();
    let dispatcher = Arc::new(
        kata_workflow::dispatcher::Dispatcher::new(
            Arc::new(kata_transport::WorkerPoolSupervisor::new()),
            Arc::new(kata_transport::heartbeat::HeartbeatMonitor::new(
                std::time::Duration::from_millis(50),
                std::time::Duration::from_millis(50),
            )),
            kata_core::InFlightLedger::in_memory(),
        )
        .with_execution_lifecycle(
            kata_workflow::execution_lifecycle::ExecutionLifecycleFace::new(db),
        ),
    );
    let runner =
        kata_workflow::runner::WorkflowRunner::new_from_program(program, dispatcher, execution)
            .unwrap();
    let mut reconciliation_outputs = std::collections::BTreeMap::new();
    runner
        .resume_via_replay(&mut reconciliation_outputs)
        .unwrap();
    // This checked fixture is free-form: replay preserves the original content
    // rather than injecting parsed fields. The population assertion above tests
    // latest record-only amendments separately; the installed structured fixture
    // tests parsed output re-derived from the original content.
    assert_eq!(reconciliation_outputs.get("draft"), Some(&original));
    let mut activation_outputs = std::collections::BTreeMap::new();
    let raw = rusqlite::Connection::open(&path).unwrap();
    let count = || {
        raw.query_row("SELECT count(*) FROM transitions", [], |r| {
            r.get::<_, i64>(0)
        })
        .unwrap()
    };
    let before_replay = count();
    runner.resume_via_replay(&mut activation_outputs).unwrap();
    assert!(
        activation_outputs == reconciliation_outputs,
        "activation replay lost the already reconciled predecessor context"
    );
    assert_eq!(activation_outputs.get("draft"), Some(&original));
    assert_eq!(
        count(),
        before_replay,
        "repeated replay must not append completion work"
    );
    let newer = serde_json::json!({"parsed":{"blob":"newer-known-context"}});
    activation_outputs.insert("draft".into(), newer.clone());
    runner.resume_via_replay(&mut activation_outputs).unwrap();
    assert_eq!(
        activation_outputs.get("draft"),
        Some(&newer),
        "old completion frames must not replace newer context"
    );
    assert_eq!(count(), before_replay);
}
