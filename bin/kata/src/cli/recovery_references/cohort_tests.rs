use super::{Instant, Ulid, recovery_cohort_source};

/// A source data directory holding one `worktree_isolated` execution parked on a
/// durable sleep exactly as the runner parks it: returns the held data-dir lock,
/// the data directory, the execution and the parked main attempt.
struct ParkedSleepSource {
    _owner: crate::data_dir_lock::DataDirLock,
    data: std::path::PathBuf,
    execution: Ulid,
    attempt: Ulid,
}

fn parked_sleep_source(directory: &std::path::Path) -> ParkedSleepSource {
    let data = directory.join("source");
    let owner = crate::data_dir_lock::DataDirLock::initialize_installed_for_test(&data).unwrap();
    let db = kata_core::OperationalDb::open(data.join("operational.db")).unwrap();
    let program = kata_program::preflight::build_starlark_workflow_compiled_artifact(
        "nap = sleep(id = \"nap\", for_ms = 10000)\nother = stage(id = \"other\", run = \"true\", agent = \"shell\", depends_on = [nap])\nworkflow(\"sleep-authority\", root = [other], worktree_isolated = True)\n",
        "sleep-authority.star", &[],
    ).unwrap().execution_program;
    let execution = Ulid::new();
    // An isolated admission carries its frozen target; this source has no
    // repository behind it, so the fixture target stands in.
    kata_workflow::admission::checked_admission(
        &program,
        &kata_workflow::execution_program_store::ExecutionInvocation::workflow(Vec::new())
            .with_target(Some(kata_types::test_support::fixture_trunk_target())),
    )
    .unwrap()
    .persist(&db, execution)
    .unwrap();
    db.mark_running(execution).unwrap();
    // Park `nap` exactly as the runner does: one main attempt at the stage's lowered
    // occurrence, in `awaiting_timer` with its durable deadline.
    let attempt = ulid::Ulid::new();
    let lowered = kata_program::execution_program::lower_stage_operation(
        &program,
        &kata_types::workflow::StageId("nap".into()),
    )
    .unwrap();
    db.claim_main_attempt(
        attempt,
        &kata_core::operational::MainAttemptSpec {
            stage_id: "nap".into(),
            occurrence: kata_core::operational::OccurrenceBinding::new(
                kata_program::execution_program::occurrence_for(
                    &program,
                    kata_types::workflow::ExecutionId(execution),
                    &lowered,
                ),
                None,
                None,
            ),
        },
        kata_core::operational::MainWait::Timer(kata_types::wait::WaitDeadline::At {
            epoch_ms: 123_456_789,
        }),
    )
    .unwrap();
    ParkedSleepSource {
        _owner: owner,
        data,
        execution,
        attempt,
    }
}

#[test]
fn sleep_checkpoint_rejects_a_different_valid_stage_authority_on_the_same_sql_attempt() {
    let directory = tempfile::tempdir().unwrap();
    let source = parked_sleep_source(directory.path());
    let (data, execution, attempt) = (&source.data, source.execution, source.attempt);
    let deadline = Instant::now() + std::time::Duration::from_secs(30);
    recovery_cohort_source(data, deadline).unwrap();
    let raw = rusqlite::Connection::open(data.join("operational.db")).unwrap();
    let stored: String = raw
        .query_row(
            "SELECT stage_id FROM attempts WHERE attempt_id=?1",
            [attempt.to_bytes().as_slice()],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(stored, "nap");
    assert!(
        recovery_cohort_source(data, deadline).is_ok(),
        "the intact census admits the durable sleep"
    );

    // The census binds the ROW's columns — every mutation below is one the
    // refused sets in `inspect_recovery_sleep_population` own.
    let mutations = [
        "UPDATE attempts SET stage_id='other' WHERE attempt_id=?1",
        "UPDATE attempt_projection SET state='pending' WHERE execution_id=?1",
        "UPDATE attempts SET wait_deadline_ms=NULL WHERE attempt_id=?1",
    ];
    for (variant, statement) in mutations.iter().enumerate() {
        raw.execute(statement, rusqlite::params![attempt.to_bytes().as_slice()])
            .unwrap();
        assert!(
            recovery_cohort_source(data, deadline).is_err(),
            "identity mutation {variant} ({statement}) must refuse"
        );
    }
    // Restore the row to its durable-sleep shape.
    raw.execute_batch("UPDATE attempts SET stage_id='nap',wait_deadline_ms=123456789")
        .unwrap();
    raw.execute(
        "UPDATE attempt_projection SET state='awaiting_timer' WHERE execution_id=?1",
        rusqlite::params![execution.to_bytes().as_slice()],
    )
    .unwrap();
    recovery_cohort_source(data, deadline).unwrap();
}

/// A parked execution whose retained checked program another build wrote is
/// refused BY ITS SCHEMA, the way the reference census refuses it
/// (`refuse_noncurrent_program_schema`). The pre-rename builds stored
/// checked-program schema 7 with `{"kind":"bwrap"}`; decoding that into the
/// current `ExecutionProgram` fails first, and the operator learned only
/// "invalid checkpoint program".
#[test]
fn a_parked_execution_with_a_retired_program_schema_is_refused_by_name() {
    let directory = tempfile::tempdir().unwrap();
    let source = parked_sleep_source(directory.path());
    let (data, execution) = (&source.data, source.execution);
    let deadline = Instant::now() + std::time::Duration::from_secs(30);
    recovery_cohort_source(data, deadline).expect("premise: the intact source admits");
    let retired = serde_json::json!({
        "schema_version": 7,
        "workflow_name": "pre-rename",
        "sandbox_profiles": {"confined": {"exec": {"kind": "bwrap"}}},
    });
    let changed = rusqlite::Connection::open(data.join("operational.db"))
        .unwrap()
        .execute(
            "UPDATE programs SET program_json=?2 WHERE execution_id=?1",
            rusqlite::params![
                execution.to_bytes().as_slice(),
                serde_json::to_vec(&retired).unwrap()
            ],
        )
        .unwrap();
    assert_eq!(
        changed, 1,
        "premise: the parked execution's program row was rewritten"
    );
    let error = recovery_cohort_source(data, deadline)
        .expect_err("a retired program schema is refused")
        .to_string();
    let current = kata_program::execution_program::EXECUTION_PROGRAM_SCHEMA_VERSION;
    assert!(
        error.contains(&format!(
            "checked program schema 7 is not the supported schema {current}"
        )),
        "the refusal names the schema: {error}"
    );
    assert!(!error.contains("bwrap"), "and the schema alone: {error}");
}

#[test]
fn checkpoint_agent_inventory_includes_declared_child_roles() {
    let program = kata_program::preflight::build_starlark_workflow_compiled_artifact(
        r#"
implement = stage(id = "implement", agent = "shell", prompt = "implement",
    topology = topology("root_with_parallel_workers", max_concurrency = 3,
        fanout_limit = 3, dynamic_fanout = True, mutation_policy = "owned_paths",
        workers = [role("writer", agent = "declared-child")]))
workflow("children", root = [implement], worktree_isolated = True)
"#,
        "children.star",
        &[],
    )
    .unwrap()
    .execution_program;
    let (labels, _) = super::declared_agent_labels(&program);
    assert!(
        labels.contains("declared-child"),
        "checked child label must participate in target configuration verification"
    );
}
