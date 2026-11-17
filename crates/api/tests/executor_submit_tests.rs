//! Submit / dispatch / run-agent / compile-ref / human-request / input-await /
//! external-input tests for `kata_api::executor`.
//!
//! Shared boot / mock / build / seed helpers live in `common`.

#![allow(clippy::large_futures)]

mod common;
use common::*;

use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use kata_api::executor::{
    AGENT_RUN_STAGE_NAME, Acceptance, ExecutionStatus, ExecutorError, WorktreeFailure,
    persist_execution_admission_evidence,
};
use kata_core::InFlightLedger;
use kata_effects_contract::{ExecutionWorkspaceKey, ExecutionWorkspaceProvider};
use kata_program::execution_program::{ExecutionProgram, ExecutionPromptRendering};
use kata_program::library::WorkflowLibrary;
use kata_transport::transport::WorkerTransport;
use kata_transport::{InProcessTransport, WorkerPoolSupervisor};
use kata_types::agent_run::{AgentRunRequest, AgentRunStatus};
use kata_types::execution::{
    EXTERNAL_INPUT_EVIDENCE_SCHEMA_VERSION, EXTERNAL_INPUT_TEXT_MAX_CHARS,
    ExecutionControllerApplyFinalizeRequest, ExecutionControllerApplyRequest, ExecutionEvidence,
    ExecutionExternalInputAppendRequest, ExecutionExternalInputEvidence,
    ExecutionHumanRequestAnswerRequest,
};
use kata_types::workflow::{AgentSelector, StageId};
use kata_workflow::execution_lifecycle::ExecutionLifecycleFace;
use kata_workflow::execution_program_store::{ExecutionInvocation, ExecutionLifecycleState};
use smol_str::SmolStr;
use ulid::Ulid;

#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn submit_completes_and_stores_outputs() {
    let stack = boot_executor();
    let executor = Arc::clone(&stack.executor);

    let id = executor
        .submit_execution_program(compile_definition(tiny_definition("hi")))
        .expect("submit should succeed with a live worker");

    let rec = wait_terminal(&executor, &id).await;
    assert_eq!(rec.status, ExecutionStatus::Completed);
    assert_eq!(rec.workflow_name, "hi");
    let execution_program = rec
        .execution_program
        .as_ref()
        .expect("execution program identity is stamped on submitted runs");
    assert_eq!(
        execution_program.schema_version,
        kata_workflow::execution_program_store::CURRENT_EXECUTION_PROGRAM_SCHEMA_VERSION
    );
    assert_eq!(
        rec.evidence.execution_program.as_ref(),
        Some(execution_program)
    );
    assert_eq!(rec.worker_id, "test-worker");
    let outputs = rec.outputs.expect("outputs populated on success");
    assert!(outputs.contains_key("only"));
    // The scripted capsule worker emits its sequence-0 `capsule_started`
    // checkpoint immediately before answering, which the reactor folds into the
    // attempt's `started_at_ms`. Pin the behaviour so a regression in
    // attempt-specific start reporting shows up here instead of as a silently
    // null field in the HTTP response.
    assert!(
        rec.started_at_ms.is_some(),
        "started_at_ms must be populated once the worker emits \
         its start checkpoint — regression in the capsule start fold?"
    );
    assert!(rec.finished_at_ms.is_some());
    assert!(rec.error.is_none());
}

#[tokio::test]
async fn lifecycle_keeps_api_running_when_all_current_assignments_are_terminal() {
    let store = ExecutionLifecycleFace::in_memory().unwrap();
    let executor = build_executor_with_execution_lifecycle(
        Arc::new(WorkerPoolSupervisor::new()),
        Arc::new(WorkflowLibrary::new(vec![])),
        Some(store.clone()),
    );
    let execution_id = Ulid::new();
    let program = compile_definition(tiny_definition("between-stage"));
    store.put_current_program(execution_id, &program).unwrap();

    seed_completed_capsule_attempt_on_authority(
        &executor,
        execution_id,
        "only",
        serde_json::json!({"ok": true}),
    )
    .expect("seed the completed predecessor on the chain");

    let between = executor
        .get_execution(&execution_id.to_string())
        .expect("lifecycle-only execution is queryable");
    assert_eq!(between.status, ExecutionStatus::Running);
    assert!(between.finished_at_ms.is_none());

    store
        .mark_terminal(execution_id, ExecutionLifecycleState::Completed)
        .unwrap();
    let terminal = executor.get_execution(&execution_id.to_string()).unwrap();
    assert_eq!(terminal.status, ExecutionStatus::Completed);
    assert!(terminal.finished_at_ms.is_some());
}

/// THE FAILED-RUN CRASH WINDOW of the resumed closeout: a failed isolated run
/// parked its candidate at `parked/<exec>` and the process died before the
/// parked-candidate evidence was appended, leaving the workspace gone and the
/// ref present. The resumed closeout must reconcile that evidence from the ref
/// BEFORE it publishes `Failed`: a first boot whose parked-candidate append
/// fails latches the node fatal with the raw lifecycle still `terminalizing` and
/// the append failure on the raw cleanup obligation, and only the next boot (a
/// fresh node over the same files) publishes. The outcome is read
/// out of git and the operational database through a second, read-only handle.
#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn resumed_failure_reconciles_parked_ref_before_terminal_lifecycle() {
    let (tmp, backend) = jj_fixture();
    let provider: Arc<dyn ExecutionWorkspaceProvider> = backend.clone();
    let execution_id = Ulid::new();
    let mut definition = tiny_definition("resume-park-evidence");
    definition.worktree_isolated = true;
    let program = compile_definition(definition);
    let op_dir = tempfile::tempdir().unwrap();
    let op_path = op_dir.path().join("operational.db");
    let program_store = ExecutionLifecycleFace::open(&op_path).unwrap();
    program_store
        .put_current_program_with_target(
            execution_id,
            &program,
            kata_vcs::test_support::resolve_trunk_target(
                &*provider,
                &ExecutionWorkspaceKey::execution(execution_id),
            )
            .unwrap(),
        )
        .unwrap();

    let faults = Arc::new(FailingUnclaimedEvidenceStore::new(false));
    let stack = boot_executor_with_custom_ledger(
        faults.open_ledger(),
        Some(Arc::clone(&provider)),
        Some(program_store.clone()),
    );
    assert_eq!(stack.op_path.as_deref(), Some(op_path.as_path()));
    let executor = Arc::clone(&stack.executor);
    // Through the PRODUCTION PAIRED WRITERS, which is why the
    // executor is built FIRST — it owns the dispatcher bound to this lifecycle
    // face. Seeding `InFlightLedger` alone would name the ledger projection as this
    // test's contract, and the deciding reader (`WorkflowRunner::fold_to_head`)
    // folds the AUTHORITY CHAIN, on which a ledger-only failure is no history at all.
    let attempt_id = seed_dispatched_capsule_attempt_on_authority(&executor, execution_id, "only")
        .expect("seed the claimed attempt");
    executor
        .dispatcher_for_test()
        .mark_failed_and_fold_attempt(attempt_id, "injected pre-crash failure")
        .expect("persist failed stage");

    let key = ExecutionWorkspaceKey::execution(execution_id);
    let path = kata_vcs::test_support::create_trunk_workspace(&*provider, &key)
        .expect("create execution workspace")
        .path;
    std::fs::write(path.join("candidate.txt"), "candidate\n").unwrap();
    let parked = provider
        .park_workspace(&key, None)
        .expect("simulate park committed before evidence append");
    assert!(!path.exists(), "parking removed the live workspace");
    let parked_ref = format!("parked/{execution_id}");
    assert_eq!(parked.ref_name, parked_ref);
    // Read out of git, never out of the provider: the commit the ref names.
    let ref_commit = || {
        let output = kata_test_utils::git::hermetic_git_in(tmp.path())
            .args(["rev-parse", "--verify", &format!("{parked_ref}^{{commit}}")])
            .output()
            .expect("git runs");
        output
            .status
            .success()
            .then(|| String::from_utf8(output.stdout).unwrap().trim().to_owned())
    };
    let commit = ref_commit().unwrap_or_else(|| panic!("git holds {parked_ref}"));
    let candidate = kata_test_utils::git::hermetic_git_in(tmp.path())
        .args(["show", &format!("{commit}:candidate.txt")])
        .output()
        .expect("git runs");
    assert_eq!(
        String::from_utf8_lossy(&candidate.stdout),
        "candidate\n",
        "the parked ref holds the failed run's candidate"
    );
    assert!(
        raw_parked_evidence(&op_path, execution_id).is_empty(),
        "the crash left no parked-candidate evidence"
    );

    // The ORDER, not only the end state: while the parked-candidate append
    // fails, the resumed closeout records the failure on its cleanup obligation,
    // `Failed` stays unpublished, and the node dies (its fatal latch).
    faults.set_fail_parked_candidate_evidence(true);
    assert_eq!(executor.resume_in_flight_runs().unwrap(), [execution_id]);
    let deferred = wait_raw_closeout(&op_path, execution_id).await;
    assert_eq!(
        raw_lifecycle(&op_path, execution_id),
        ("terminalizing".to_owned(), Some("failed".to_owned())),
        "no outcome is published before the parked candidate's evidence"
    );
    let deferred = deferred.expect("the closeout deferred");
    assert!(
        deferred.contains("reconciled parked candidate evidence")
            && deferred.contains("injected parked candidate evidence append failure"),
        "the closeout deferred on the reconcile's append: {deferred}"
    );
    assert!(raw_parked_evidence(&op_path, execution_id).is_empty());
    assert_eq!(
        ref_commit().as_deref(),
        Some(commit.as_str()),
        "the deferred closeout left the parked ref where the crash put it"
    );
    // The obligation's `last_error` lands before the closeout returns its error,
    // and the caller latches the node fatal only after that: wait for the latch.
    let fatal = tokio::time::timeout(Duration::from_secs(10), executor.wait_for_fatal())
        .await
        .expect("a closeout that cannot persist latches the node fatal");
    assert!(
        fatal.contains("lifecycle remains Terminalizing"),
        "the node died with the outcome unpublished: {fatal}"
    );

    // The next boot: a fresh node over the same operational file, stage-cache
    // store and repository, its ledger bound to that file and no fault armed.
    // The dead node's stack stays alive only so its node dir, which holds the
    // shared CAS, is not deleted under the new one.
    let dead = stack;
    let stack = boot_executor_with_custom_ledger_and_cache_store(
        InFlightLedger::in_memory(),
        Some(Arc::clone(&provider)),
        Some(ExecutionLifecycleFace::open(&op_path).unwrap()),
        Arc::clone(&dead.store),
    );
    let executor = Arc::clone(&stack.executor);
    assert_eq!(executor.resume_in_flight_runs().unwrap(), [execution_id]);
    assert_eq!(
        raw_lifecycle(&op_path, execution_id),
        ("failed".to_owned(), Some("failed".to_owned())),
        "the next boot published the latched outcome"
    );
    assert_eq!(
        raw_parked_evidence(&op_path, execution_id),
        [(parked_ref.clone(), commit.clone(), true)],
        "the parked candidate was appended, read off the ref, as auto-parked"
    );
    assert_eq!(
        ref_commit().as_deref(),
        Some(commit.as_str()),
        "the published failure kept the parked ref the evidence names"
    );
    assert!(executor.fatal_reason().is_none());
}

/// A failed isolated run closed out over a `parked/<exec>` it did not write:
/// its `promote` landing parked the delivered commit's rebase for revalidation
/// at `parked/<exec>` (another execution landed first) and left the workspace
/// standing at the recorded candidate. The cells build that end state directly
/// with the real landing ladder (`land_committed_candidate`) rather than by
/// driving a promote attempt and recovery's `Diverged` answer to it: the refs,
/// the standing workspace and the head row are the ones that answer leaves.
/// The run's failed attempt is seeded; `resume_in_flight_runs` drives the
/// resumed failed-run closeout (`park_candidate_at_closeout`).
struct ClosedOutOverALandingPark {
    _repo: tempfile::TempDir,
    _op_dir: tempfile::TempDir,
    faults: Arc<FailingUnclaimedEvidenceStore>,
    stack: ExecutorStack,
    provider: Arc<dyn ExecutionWorkspaceProvider>,
    repo: std::path::PathBuf,
    op_path: std::path::PathBuf,
    executor: Arc<kata_api::executor::WorkflowExecutor>,
    execution_id: Ulid,
    /// The execution workspace's directory.
    path: std::path::PathBuf,
    parked_ref: String,
    /// The landing's rebase `parked/<exec>` names (empty when no landing ran:
    /// [`a_failed_isolated_run`]).
    rebased: String,
    /// The candidate the execution delivered.
    delivered: String,
}

/// `git <args>` in `repo`, hermetic: stdout trimmed, or `None` on a failure.
fn git_at(repo: &std::path::Path, args: &[&str]) -> Option<String> {
    let output = kata_test_utils::git::hermetic_git_in(repo)
        .args(args)
        .output()
        .expect("git runs");
    output
        .status
        .success()
        .then(|| String::from_utf8(output.stdout).unwrap().trim().to_owned())
}

fn a_failed_run_over_a_landing_park() -> ClosedOutOverALandingPark {
    a_failed_isolated_run(true)
}

/// [`a_failed_run_over_a_landing_park`], or with `landing_park` false the same
/// run whose own landing never ran: no `parked/<exec>` stands, and `rebased`
/// is empty.
fn a_failed_isolated_run(landing_park: bool) -> ClosedOutOverALandingPark {
    use kata_vcs::VcsBackend as _;

    // A repository with a trunk: the landing ladder bases on `main`.
    let tmp = tempfile::tempdir().unwrap();
    kata_test_utils::git::init_git_repo_at(tmp.path());
    let backend = Arc::new(
        <kata_vcs::JjBackend as kata_vcs::VcsBackend>::open(tmp.path()).expect("open jj backend"),
    );
    let provider: Arc<dyn ExecutionWorkspaceProvider> = backend.clone();
    let execution_id = Ulid::new();
    let key = ExecutionWorkspaceKey::execution(execution_id);
    let mut definition = tiny_definition("closeout-over-a-landing-park");
    definition.worktree_isolated = true;
    let program = compile_definition(definition);
    let op_dir = tempfile::tempdir().unwrap();
    let op_path = op_dir.path().join("operational.db");
    let program_store = ExecutionLifecycleFace::open(&op_path).unwrap();
    program_store
        .put_current_program_with_target(
            execution_id,
            &program,
            kata_vcs::test_support::resolve_trunk_target(&*provider, &key).unwrap(),
        )
        .unwrap();
    let faults = Arc::new(FailingUnclaimedEvidenceStore::new(false));
    let stack = boot_executor_with_custom_ledger(
        faults.open_ledger(),
        Some(Arc::clone(&provider)),
        Some(program_store.clone()),
    );
    let executor = Arc::clone(&stack.executor);
    let attempt_id = seed_dispatched_capsule_attempt_on_authority(&executor, execution_id, "only")
        .expect("seed the claimed attempt");
    executor
        .dispatcher_for_test()
        .mark_failed_and_fold_attempt(attempt_id, "injected pre-crash failure")
        .expect("persist failed stage");

    // Another execution lands first, so this execution's landing finds its
    // base advanced and parks the rebase of its delivered commit.
    let other = ExecutionWorkspaceKey::execution(Ulid::new());
    let other_path = kata_vcs::test_support::create_trunk_workspace(&*provider, &other)
        .unwrap()
        .path;
    let path = kata_vcs::test_support::create_trunk_workspace(&*provider, &key)
        .expect("create execution workspace")
        .path;
    std::fs::write(other_path.join("other.txt"), "other\n").unwrap();
    let first = backend
        .commit(&kata_types::AgentId(other.execution_id), "first")
        .unwrap();
    std::fs::write(path.join("candidate.txt"), "candidate\n").unwrap();
    let delivered = backend
        .commit(&kata_types::AgentId(execution_id), "candidate")
        .unwrap();
    assert!(
        backend
            .land_committed_candidate(&other, &first, None)
            .unwrap()
            .is_landed()
    );
    provider.remove_workspace(&other).unwrap();
    let parked_ref = format!("parked/{execution_id}");
    let rebased = if landing_park {
        assert!(
            !backend
                .land_committed_candidate(&key, &delivered, None)
                .unwrap()
                .is_landed(),
            "the landing parks its rebase for revalidation"
        );
        let rebased = git_at(
            tmp.path(),
            &["rev-parse", "--verify", &format!("{parked_ref}^{{commit}}")],
        )
        .expect("git holds the park");
        assert_ne!(
            rebased, delivered,
            "the park names the rebase, not the candidate"
        );
        assert_eq!(
            git_at(tmp.path(), &["show", &format!("{rebased}:other.txt")]).as_deref(),
            Some("other"),
            "the rebase carries trunk's side"
        );
        rebased
    } else {
        String::new()
    };
    // The head row records the standing workspace's `@` as the candidate, as
    // admission and every apply do, so the preservation fence passes.
    let candidate = provider
        .workspace_effect_candidate_commit(&key)
        .unwrap()
        .expect("the live workspace's @ reads");
    let seed = kata_core::work_tree::declare_empty_tree(&stack.db, stack.store.cas(), execution_id)
        .expect("the head's tree declares");
    stack
        .db
        .record_work_tree_head(execution_id, &first, seed.id().0.0, &candidate)
        .expect("the head row records");

    ClosedOutOverALandingPark {
        repo: tmp.path().to_path_buf(),
        _repo: tmp,
        _op_dir: op_dir,
        faults,
        stack,
        provider,
        op_path,
        executor,
        execution_id,
        path,
        parked_ref,
        rebased,
        delivered,
    }
}

/// [`a_failed_run_over_a_landing_park`], its resumed closeout driven to
/// settlement.
async fn a_failed_run_closed_out_over_a_landing_park() -> ClosedOutOverALandingPark {
    let run = a_failed_run_over_a_landing_park();
    assert_eq!(
        run.executor.resume_in_flight_runs().unwrap(),
        [run.execution_id]
    );
    assert_eq!(
        wait_raw_closeout(&run.op_path, run.execution_id).await,
        None,
        "the closeout settled without deferring"
    );
    run
}

/// THE CLOSEOUT NEVER PARKS OVER A `parked/<exec>` IT DID NOT WRITE, AND
/// RECORDS THAT IT DID NOT ([`a_failed_run_closed_out_over_a_landing_park`]).
/// The ref names the landing's rebase, not the candidate the closeout would
/// park, so the closeout refuses `parked_ref_occupied`: the ref keeps the
/// rebase, the workspace stands for inspection, no parked candidate is
/// recorded, the refusal is recorded on the execution, and the run publishes
/// `failed` (the refusal is the closeout's answer, as the preservation fence's
/// is). `GET /api/v1/executions/<id>` — what `kata run show` prints — serves
/// the refusal and no parked candidate, and reading it does not adopt the
/// standing ref as the run's own park. Read out of git, the filesystem, and
/// the operational database through a second, read-only handle.
#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn the_failed_run_closeout_keeps_a_parked_ref_it_did_not_write() {
    let run = a_failed_run_closed_out_over_a_landing_park().await;
    let parked_rev = format!("{}^{{commit}}", run.parked_ref);
    assert_eq!(
        raw_lifecycle(&run.op_path, run.execution_id),
        ("failed".to_owned(), Some("failed".to_owned())),
        "the refusal is the closeout's answer, not a repair failure"
    );
    assert_the_closeout_park_refusal_is_recorded(&run);
    let router = kata_api::server::ApiServer::build(
        &kata_types::config::ApiConfig {
            bind: "127.0.0.1:0".into(),
            auth: kata_types::config::ApiAuthConfig::Disabled {},
        },
        kata_api::state::AppState::with_executor(
            Arc::new(kata_core::SystemHealth::new()),
            Arc::clone(&run.executor),
        ),
    )
    .unwrap()
    .into_router();
    let (status, record) =
        get_json(&router, &format!("/api/v1/executions/{}", run.execution_id)).await;
    assert_eq!(status, axum::http::StatusCode::OK, "{record}");
    let refusal = &record["evidence"]["closeout_park_refusal"];
    assert_eq!(refusal["refusal"], "parked_ref_occupied", "{record}");
    assert_eq!(refusal["parked_ref"], run.parked_ref.as_str(), "{record}");
    assert!(
        record["evidence"]["parked_candidate"].is_null(),
        "the face claims no park the closeout refused: {record}"
    );
    assert!(
        raw_parked_evidence(&run.op_path, run.execution_id).is_empty(),
        "reading the record adopted no parked candidate"
    );
    assert_eq!(
        git_at(&run.repo, &["rev-parse", "--verify", &parked_rev]).as_deref(),
        Some(run.rebased.as_str()),
        "the closeout kept the landing's rebase at {}",
        run.parked_ref
    );
    assert!(
        raw_parked_evidence(&run.op_path, run.execution_id).is_empty(),
        "no parked candidate is recorded for a park that did not happen"
    );
    assert_eq!(
        std::fs::read_to_string(run.path.join("candidate.txt"))
            .as_deref()
            .ok(),
        Some("candidate\n"),
        "the workspace stands for inspection"
    );
    assert!(run.executor.fatal_reason().is_none());
}

/// The closeout's refusal, read raw off the operational file: ONE row naming
/// `parked_ref_occupied`, the default parked ref, and both commits — the
/// landing's rebase the ref names and the candidate the park would have written.
fn assert_the_closeout_park_refusal_is_recorded(run: &ClosedOutOverALandingPark) {
    let refusals = raw_closeout_park_refusals(&run.op_path, run.execution_id);
    let [(refusal, parked_ref, message)] = refusals.as_slice() else {
        panic!("one recorded closeout park refusal: {refusals:?}");
    };
    assert_eq!(refusal, "parked_ref_occupied");
    assert_eq!(parked_ref, &run.parked_ref);
    assert!(
        message.contains(&run.rebased) && message.contains(&run.delivered),
        "the record names both commits: {message}"
    );
}

/// A CRASH BETWEEN THE CLOSEOUT'S PARK REFUSAL AND ITS RECORD PUBLISHES
/// NOTHING, AND THE NEXT BOOT RECORDS THE REFUSAL ONCE
/// ([`a_terminalizing_run_over_a_landing_park`]). The refusal changes nothing,
/// so the window is the record's append: while it fails, the resumed closeout
/// records the failure on its cleanup obligation, `failed` stays unpublished
/// and the node dies (its fatal latch). The next boot's repair asks the park again over
/// the same repository, gets the same refusal, records it and publishes
/// `failed`. Read out of git, the filesystem, and the operational database
/// through a second, read-only handle.
#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn a_crash_before_the_closeout_park_refusal_is_recorded_records_it_on_the_next_boot() {
    let (run, stack) = a_terminalizing_run_over_a_landing_park().await;
    let parked_rev = format!("{}^{{commit}}", run.parked_ref);
    assert_eq!(
        stack.executor.resume_in_flight_runs().unwrap(),
        [run.execution_id]
    );
    assert_eq!(
        raw_lifecycle(&run.op_path, run.execution_id),
        ("failed".to_owned(), Some("failed".to_owned())),
        "the repair recorded the refusal and published the latched outcome"
    );
    assert_the_closeout_park_refusal_is_recorded(&run);
    assert_eq!(
        git_at(&run.repo, &["rev-parse", "--verify", &parked_rev]).as_deref(),
        Some(run.rebased.as_str()),
        "neither closeout moved {}",
        run.parked_ref
    );
    assert!(raw_parked_evidence(&run.op_path, run.execution_id).is_empty());
    assert_eq!(
        std::fs::read_to_string(run.path.join("candidate.txt"))
            .as_deref()
            .ok(),
        Some("candidate\n"),
        "the workspace stands for inspection"
    );
    assert!(stack.executor.fatal_reason().is_none());
}

/// [`a_failed_run_over_a_landing_park`] whose resumed closeout could not
/// record its refusal: while the refusal's evidence append fails, the closeout
/// records the failure on its cleanup obligation, `failed` stays unpublished
/// and the node dies (its fatal latch) — all read raw. Returned with a fresh
/// node booted over the same operational file, stage-cache store and
/// repository, its ledger bound to that file and no fault armed, not yet
/// resumed.
async fn a_terminalizing_run_over_a_landing_park() -> (ClosedOutOverALandingPark, ExecutorStack) {
    a_terminalizing_run(a_failed_run_over_a_landing_park()).await
}

/// `run`, its resumed closeout deferred as
/// [`a_terminalizing_run_over_a_landing_park`] describes, and the fresh node.
async fn a_terminalizing_run(
    run: ClosedOutOverALandingPark,
) -> (ClosedOutOverALandingPark, ExecutorStack) {
    run.faults.set_fail_closeout_park_refusal_evidence(true);
    assert_eq!(
        run.executor.resume_in_flight_runs().unwrap(),
        [run.execution_id]
    );
    let deferred = wait_raw_closeout(&run.op_path, run.execution_id)
        .await
        .expect("the closeout deferred");
    assert_eq!(
        raw_lifecycle(&run.op_path, run.execution_id),
        ("terminalizing".to_owned(), Some("failed".to_owned())),
        "no outcome is published before the refusal's record"
    );
    assert!(
        deferred.contains("injected closeout park refusal evidence append failure"),
        "the closeout deferred on the refusal's append: {deferred}"
    );
    assert!(raw_closeout_park_refusals(&run.op_path, run.execution_id).is_empty());
    let fatal = tokio::time::timeout(Duration::from_secs(10), run.executor.wait_for_fatal())
        .await
        .expect("a closeout that cannot persist latches the node fatal");
    assert!(
        fatal.contains("lifecycle remains Terminalizing"),
        "the node died with the outcome unpublished: {fatal}"
    );

    let stack = boot_executor_with_custom_ledger_and_cache_store(
        InFlightLedger::in_memory(),
        Some(Arc::clone(&run.provider)),
        Some(ExecutionLifecycleFace::open(&run.op_path).unwrap()),
        Arc::clone(&run.stack.store),
    );
    (run, stack)
}

/// What a closeout that recorded its refusal and then crashed before
/// publishing leaves: the refusal's claimed row (claim key
/// `terminal_closeout_park_refusal:v1`, a durable-format fact spelled here)
/// beside a `Terminalizing` lifecycle. Written through `stack`'s ledger, as
/// the crashed closeout wrote it.
fn record_the_closeout_park_refusal_before_the_crash(
    run: &ClosedOutOverALandingPark,
    stack: &ExecutorStack,
    refusal: &str,
) {
    let refusal = kata_types::execution::CloseoutParkRefusal {
        refusal: refusal.to_owned(),
        parked_ref: run.parked_ref.clone(),
        message: format!("{refusal}: the closeout park of {} refused", run.parked_ref),
    };
    stack
        .executor
        .dispatcher_for_test()
        .ledger()
        .append_execution_evidence_claimed(
            run.execution_id,
            "terminal_closeout_park_refusal:v1",
            ExecutionEvidence {
                closeout_park_refusal: Some(refusal),
                ..ExecutionEvidence::default()
            },
        )
        .unwrap()
        .expect("the refusal's claim is new");
    assert_eq!(
        raw_lifecycle(&run.op_path, run.execution_id),
        ("terminalizing".to_owned(), Some("failed".to_owned()))
    );
    assert_eq!(
        raw_closeout_park_refusals(&run.op_path, run.execution_id).len(),
        1
    );
}

/// A RECORDED CLOSEOUT PARK REFUSAL IS THE CLOSEOUT'S ANSWER FOR GOOD. A
/// failed run with no landing park ([`a_failed_isolated_run`]) whose standing
/// workspace carries a foreign file: its closeout refuses
/// `oci_candidate_disk_diverged` and, its record's append failing, defers
/// ([`a_terminalizing_run`]); the record then stands as a closeout that
/// recorded it and crashed before the publish left it
/// ([`record_the_closeout_park_refusal_before_the_crash`]). The foreign file is
/// removed meanwhile, so asking the park again would now park the candidate
/// beside the recorded refusal. The repair does not ask: it publishes `failed`
/// with the one recorded refusal, no parked-candidate row, no `parked/<exec>`
/// in git and the workspace standing. Read out of git, the filesystem, and the
/// operational database through a second, read-only handle.
#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn a_repaired_closeout_keeps_its_recorded_park_refusal_as_its_answer() {
    let run = a_failed_isolated_run(false);
    std::fs::write(run.path.join("foreign.txt"), "foreign\n").unwrap();
    let (run, stack) = a_terminalizing_run(run).await;
    record_the_closeout_park_refusal_before_the_crash(&run, &stack, "oci_candidate_disk_diverged");
    std::fs::remove_file(run.path.join("foreign.txt")).unwrap();

    assert_eq!(
        stack.executor.resume_in_flight_runs().unwrap(),
        [run.execution_id]
    );
    assert_eq!(
        raw_lifecycle(&run.op_path, run.execution_id),
        ("failed".to_owned(), Some("failed".to_owned())),
        "the repair published the latched outcome"
    );
    assert_eq!(
        raw_closeout_park_refusals(&run.op_path, run.execution_id).len(),
        1,
        "the recorded refusal, once"
    );
    assert!(
        raw_parked_evidence(&run.op_path, run.execution_id).is_empty(),
        "no park recorded beside the refusal"
    );
    assert_eq!(
        git_at(
            &run.repo,
            &[
                "rev-parse",
                "--verify",
                &format!("{}^{{commit}}", run.parked_ref)
            ]
        ),
        None,
        "the repair parked nothing"
    );
    assert_eq!(
        std::fs::read_to_string(run.path.join("candidate.txt"))
            .as_deref()
            .ok(),
        Some("candidate\n"),
        "the workspace stands for inspection"
    );
    assert!(stack.executor.fatal_reason().is_none());
}

/// A REPAIRED CLOSEOUT NEVER ADOPTS THE REF ITS RECORDED REFUSAL NAMES
/// ([`a_terminalizing_run_over_a_landing_park`],
/// [`record_the_closeout_park_refusal_before_the_crash`]), with the workspace
/// removed before the repair. The repair's workspace-gone arm reads a standing
/// `parked/<exec>` as its own interrupted park's write — here it is the
/// landing's rebase the closeout refused to overwrite, so the repair publishes
/// `failed` with no parked-candidate row and the ref unchanged. Read out of
/// git and the operational database through a second, read-only handle.
#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn a_repaired_closeout_never_adopts_the_ref_its_recorded_refusal_names() {
    let (run, stack) = a_terminalizing_run_over_a_landing_park().await;
    record_the_closeout_park_refusal_before_the_crash(&run, &stack, "parked_ref_occupied");
    run.provider
        .remove_workspace(&ExecutionWorkspaceKey::execution(run.execution_id))
        .unwrap();
    assert!(!run.path.exists(), "the workspace is gone");

    assert_eq!(
        stack.executor.resume_in_flight_runs().unwrap(),
        [run.execution_id]
    );
    assert_eq!(
        raw_lifecycle(&run.op_path, run.execution_id),
        ("failed".to_owned(), Some("failed".to_owned())),
        "the repair published the latched outcome"
    );
    assert!(
        raw_parked_evidence(&run.op_path, run.execution_id).is_empty(),
        "the repair adopted no parked candidate"
    );
    assert_eq!(
        git_at(
            &run.repo,
            &[
                "rev-parse",
                "--verify",
                &format!("{}^{{commit}}", run.parked_ref)
            ]
        )
        .as_deref(),
        Some(run.rebased.as_str()),
        "{} still names the landing's rebase",
        run.parked_ref
    );
    assert!(stack.executor.fatal_reason().is_none());
}

/// THE OPERATOR'S DEFAULT PARK NEVER ADOPTS THE REF ITS CLOSEOUT REFUSED, ONCE
/// THE WORKSPACE IS GONE ([`a_failed_run_closed_out_over_a_landing_park`]).
/// The terminal reaper removes the refused run's standing workspace; the
/// default park, which adopts a standing `parked/<exec>` as an interrupted
/// park's write when the workspace is gone, refuses `parked_ref_occupied`
/// beside the recorded refusal: git's `parked/<exec>` still names the rebase
/// and no raw parked-candidate row exists.
#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn the_operator_park_never_adopts_the_ref_its_closeout_refused_once_the_workspace_is_gone() {
    let run = a_failed_run_closed_out_over_a_landing_park().await;
    assert_the_closeout_park_refusal_is_recorded(&run);
    run.provider
        .remove_workspace(&ExecutionWorkspaceKey::execution(run.execution_id))
        .unwrap();
    assert!(!run.path.exists(), "the workspace is gone");

    let refused = run
        .executor
        .park_candidate(run.execution_id, None)
        .expect_err("the default park refuses the ref its closeout refused");
    assert!(
        refused.to_string().contains("parked_ref_occupied")
            && refused.to_string().contains(&run.rebased),
        "{refused}"
    );
    assert!(
        raw_parked_evidence(&run.op_path, run.execution_id).is_empty(),
        "no parked candidate recorded"
    );
    assert_eq!(
        git_at(
            &run.repo,
            &[
                "rev-parse",
                "--verify",
                &format!("{}^{{commit}}", run.parked_ref)
            ]
        )
        .as_deref(),
        Some(run.rebased.as_str()),
        "{} still names the landing's rebase",
        run.parked_ref
    );
}

/// EVERY NAMED CLOSEOUT PARK REFUSAL IS RECORDED, the preservation fence's two
/// as well as `parked_ref_occupied`: [`a_failed_run_over_a_landing_park`] with
/// its standing workspace perturbed by `perturb` before the resumed closeout,
/// which refuses `refusal` (the fence runs before the occupied-ref check) and
/// publishes `failed`. Read raw: ONE refusal row naming `refusal` and
/// `parked/<exec>`, whose message names it too; no parked-candidate
/// row; the ref still the landing's rebase.
async fn assert_the_fence_refusal_is_recorded(
    refusal: &str,
    perturb: impl FnOnce(&ClosedOutOverALandingPark),
) {
    let run = a_failed_run_over_a_landing_park();
    perturb(&run);
    assert_eq!(
        run.executor.resume_in_flight_runs().unwrap(),
        [run.execution_id]
    );
    assert_eq!(
        wait_raw_closeout(&run.op_path, run.execution_id).await,
        None,
        "the closeout settled without deferring"
    );
    assert_eq!(
        raw_lifecycle(&run.op_path, run.execution_id),
        ("failed".to_owned(), Some("failed".to_owned()))
    );
    let refusals = raw_closeout_park_refusals(&run.op_path, run.execution_id);
    let [(recorded, parked_ref, message)] = refusals.as_slice() else {
        panic!("one recorded closeout park refusal: {refusals:?}");
    };
    assert_eq!(recorded, refusal);
    assert_eq!(parked_ref, &run.parked_ref);
    assert!(message.contains(refusal), "{message}");
    assert!(raw_parked_evidence(&run.op_path, run.execution_id).is_empty());
    assert_eq!(
        git_at(
            &run.repo,
            &[
                "rev-parse",
                "--verify",
                &format!("{}^{{commit}}", run.parked_ref)
            ]
        )
        .as_deref(),
        Some(run.rebased.as_str())
    );
    assert!(run.executor.fatal_reason().is_none());
}

/// [`assert_the_fence_refusal_is_recorded`] over a foreign file written into
/// the standing workspace: `oci_candidate_disk_diverged`.
#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn a_closeout_refused_over_foreign_disk_edits_records_the_refusal() {
    assert_the_fence_refusal_is_recorded("oci_candidate_disk_diverged", |run| {
        std::fs::write(run.path.join("foreign.txt"), "foreign\n").unwrap();
    })
    .await;
}

/// [`assert_the_fence_refusal_is_recorded`] over a commit made in the standing
/// workspace, which moves its `@` off the recorded candidate:
/// `oci_candidate_diverged`.
#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn a_closeout_refused_over_a_moved_candidate_records_the_refusal() {
    use kata_vcs::VcsBackend as _;
    assert_the_fence_refusal_is_recorded("oci_candidate_diverged", |run| {
        std::fs::write(run.path.join("foreign.txt"), "foreign\n").unwrap();
        <kata_vcs::JjBackend as kata_vcs::VcsBackend>::open(&run.repo)
            .expect("open jj backend")
            .commit(&kata_types::AgentId(run.execution_id), "foreign")
            .expect("the foreign commit moves @");
    })
    .await;
}

/// The last operational stamp whose closeouts recorded no park refusal — a fact
/// about directories already on disk, so it is spelled, never derived.
const LAST_STAMP_WITHOUT_CLOSEOUT_PARK_REFUSALS: i64 = 42;

/// **A data directory whose closeouts recorded no park refusal is refused at
/// OPEN, never read as "nothing refused".** The closeout's refusal over a
/// landing park ([`a_failed_run_closed_out_over_a_landing_park`]) is rewritten
/// (raw SQL) to what stamp 42 left — the refusal's evidence row and its claim
/// deleted, the file stamped back to 42. Read by this build, that run would
/// report no refusal and its execution read would adopt the landing's rebase as
/// the run's auto-parked candidate; reopening refuses it
/// `SchemaMigrationRequired` with the new-data-directory recourse.
#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn a_directory_whose_closeouts_recorded_no_park_refusal_is_refused_at_open() {
    let run = a_failed_run_closed_out_over_a_landing_park().await;
    assert_the_closeout_park_refusal_is_recorded(&run);
    let writer = rusqlite::Connection::open(&run.op_path).unwrap();
    let execution = run.execution_id.to_bytes();
    let refusal_rows = writer
        .execute(
            "DELETE FROM execution_evidence WHERE execution_id = ?1 \
             AND json_extract(CAST(evidence_json AS TEXT), '$.evidence.closeout_park_refusal') \
             IS NOT NULL",
            [execution.as_slice()],
        )
        .unwrap();
    assert_eq!(refusal_rows, 1, "the one refusal row");
    assert_eq!(
        writer
            .execute(
                "DELETE FROM execution_evidence_claims WHERE execution_id = ?1 \
                 AND claim_key LIKE '%park_refusal%'",
                [execution.as_slice()],
            )
            .unwrap(),
        1,
        "the refusal's claim"
    );
    writer
        .pragma_update(
            None,
            "user_version",
            LAST_STAMP_WITHOUT_CLOSEOUT_PARK_REFUSALS,
        )
        .unwrap();
    drop(writer);
    assert!(raw_closeout_park_refusals(&run.op_path, run.execution_id).is_empty());

    let Err(error) = ExecutionLifecycleFace::open(&run.op_path) else {
        panic!("a directory whose closeouts recorded no park refusal is refused");
    };
    assert!(
        matches!(error, kata_types::KataError::SchemaMigrationRequired(_)),
        "refused at open, never read: {error:?}"
    );
    let rendered = error.to_string();
    assert!(
        rendered.contains(&format!(
            "schema version {LAST_STAMP_WITHOUT_CLOSEOUT_PARK_REFUSALS} is not the clean \
             runtime version"
        )) && rendered
            .contains("use a new empty data directory and preserve this directory offline"),
        "{rendered}"
    );
}

/// THE OPERATOR'S DEFAULT PARK ADOPTS `parked/<exec>` ONLY AS ITS OWN WRITE. On
/// the end state the closeout's `parked_ref_occupied` leaves
/// ([`a_failed_run_closed_out_over_a_landing_park`]) — the workspace standing,
/// `parked/<exec>` naming the landing's rebase — `park_candidate` with no label
/// refuses the same name rather than record the rebase as this execution's
/// parked candidate: the ref, the workspace and the evidence are as they stood.
/// The recourse it names, a labelled park, parks the standing workspace's
/// candidate under `parked/<label>` and tears the workspace down. Read out of
/// git, the filesystem, and the operational database through a second,
/// read-only handle.
#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn the_operator_park_keeps_a_parked_ref_it_did_not_write() {
    let run = a_failed_run_closed_out_over_a_landing_park().await;
    let parked_rev = format!("{}^{{commit}}", run.parked_ref);

    let refused = run
        .executor
        .park_candidate(run.execution_id, None)
        .expect_err("the default park refuses a parked ref it did not write");
    assert!(
        refused.to_string().contains("parked_ref_occupied")
            && refused.to_string().contains(&run.rebased),
        "{refused}"
    );
    assert_eq!(
        git_at(&run.repo, &["rev-parse", "--verify", &parked_rev]).as_deref(),
        Some(run.rebased.as_str()),
        "the refused park kept the landing's rebase at {}",
        run.parked_ref
    );
    assert!(
        raw_parked_evidence(&run.op_path, run.execution_id).is_empty(),
        "the refused park recorded no parked candidate"
    );
    assert_eq!(
        std::fs::read_to_string(run.path.join("candidate.txt"))
            .as_deref()
            .ok(),
        Some("candidate\n"),
        "the refused park left the workspace standing"
    );

    let parked = run
        .executor
        .park_candidate(run.execution_id, Some("review"))
        .expect("a labelled park parks the standing candidate");
    assert_eq!(parked.ref_name, "parked/review");
    assert_eq!(
        git_at(
            &run.repo,
            &["rev-parse", "--verify", "parked/review^{commit}"]
        )
        .as_deref(),
        Some(run.delivered.as_str()),
        "the labelled park names the delivered candidate"
    );
    assert_eq!(
        raw_parked_evidence(&run.op_path, run.execution_id),
        [("parked/review".to_owned(), run.delivered.clone(), false)],
        "the labelled park recorded its own ref as the operator's parked candidate"
    );
    assert_eq!(
        git_at(&run.repo, &["rev-parse", "--verify", &parked_rev]).as_deref(),
        Some(run.rebased.as_str()),
        "the labelled park left the landing's rebase at {}",
        run.parked_ref
    );
    assert!(
        !run.path.exists(),
        "the labelled park tore the workspace down"
    );
    assert!(run.executor.fatal_reason().is_none());
}

/// The repair path's twin of an unjudged loop: a loop under `accept` whose bound
/// tripped before its gate classified, and every stage after it hanging off a
/// route on that gate — the `change` pack's shape.
const UNJUDGED_LOOP_PACK: &str = r#"
implement = stage(id = "implement", agent = "shell", sandbox = "edit", run = "true")
test = stage(
    id = "test",
    agent = "shell",
    sandbox = "verify",
    depends_on = ["implement"],
    run = "true",
    produces = contract("TestReport", {"status": field(enum("passed", "failed"))}),
)
loop(
    body = implement,
    gate = test,
    max_iterations = 2,
    on_exhaustion = "accept",
    bounds = [time_bound(1)],
    gate_verdict = {"field": "status", "approve": ["passed"], "refine": ["failed"], "block": ["error"]},
)
approve = stage(id = "approve", agent = "shell", sandbox = "verify", depends_on = ["test"], run = "true")
park_unfinished = stage(id = "park_unfinished", agent = "workspace_effect", op = "park", depends_on = ["test"])
route(on = test, field = "status", arms = {"passed": approve, "failed": park_unfinished})
workflow(
    "unjudged-park-repair",
    root = [implement],
    worktree_isolated = True,
    sandbox_profiles = {
        "edit": sandbox_profile(workspace = "rw", net = "offline"),
        "verify": sandbox_profile(workspace = "ro", net = "offline"),
    },
)
"#;

/// THE COMPLETED-RUN CRASH WINDOW of the unjudged-candidate closeout
/// (`park_unjudged_candidate_at_closeout`): a completed isolated run whose loop
/// exhausted under `accept` with no verdict latched `Completed` intent, parked
/// its candidate at `parked/<exec>` and crashed before the parked-candidate
/// evidence was appended. The repair (`repair_terminalizing_execution`) re-asks
/// the durable loop record, finds the workspace gone, reconciles the evidence
/// from the deterministic ref and only then publishes `Completed`: a first
/// boot whose parked-candidate append fails refuses with the lifecycle still
/// `terminalizing`, and only the next one publishes. The twin of
/// [`resumed_failure_reconciles_parked_ref_before_terminal_lifecycle`] for the
/// failed-run closeout. The outcome is read out of git and the operational
/// database through a second, read-only handle.
#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn resumed_completion_reconciles_an_unjudged_loop_park_before_terminal_lifecycle() {
    use kata_core::operational::{
        ExpansionClaimOutcome, ExpansionSpec, MainAttemptSpec, MainResolution, OccurrenceBinding,
    };
    use kata_program::execution_program::expansion::{
        ExpansionMember, ExpansionOnMax, ExpansionRecord, ExpansionResolution,
    };
    use kata_types::execution_contract::{OccurrenceRef, RuntimeOperation};

    let (tmp, backend) = jj_fixture();
    let provider: Arc<dyn ExecutionWorkspaceProvider> = backend.clone();
    let program = parse_inline_starlark_checked(UNJUDGED_LOOP_PACK, "unjudged-park.star", &[])
        .expect("the pack checks");
    let faults = Arc::new(FailingUnclaimedEvidenceStore::new(false));
    let stack =
        boot_executor_with_custom_ledger(faults.open_ledger(), Some(Arc::clone(&provider)), None);
    let executor = Arc::clone(&stack.executor);
    let op_path = stack.op_path.clone().expect("the rig's database is a file");
    let face = executor.execution_lifecycle().clone();
    let execution_id = Ulid::new();
    face.put_current_program_with_target(
        execution_id,
        &program,
        kata_vcs::test_support::resolve_trunk_target(
            &*provider,
            &ExecutionWorkspaceKey::execution(execution_id),
        )
        .unwrap(),
    )
    .unwrap();

    // Iteration 0's member ran; the bound tripped before `test` classified.
    seed_completed_capsule_attempt_on_authority(
        &executor,
        execution_id,
        "implement",
        serde_json::json!({}),
    )
    .expect("seed the loop member");
    // The loop's accepted record, claimed and resolved at the coordinates the
    // ONE lowering names, as the runner's `expansion_claim_parts` builds them.
    let lowered =
        kata_program::execution_program::lower_review_loop(&program, 0).expect("the loop lowers");
    let RuntimeOperation::ExpandBounded {
        template,
        maximum,
        policy_hash,
    } = &lowered.contract.operation
    else {
        panic!("a loop lowers to an ExpandBounded");
    };
    let spec = MainAttemptSpec {
        stage_id: lowered.path.program_operation_stage_id(),
        occurrence: OccurrenceBinding::new(
            OccurrenceRef::new(
                kata_types::workflow::ExecutionId(execution_id),
                program.program_hash,
                lowered.contract.id(),
                lowered.path.clone(),
            ),
            None,
            None,
        ),
    };
    let expansion = ExpansionSpec {
        operation: lowered.contract.id().0.to_string(),
        path: lowered.path.clone(),
        stage: lowered.contract.source_stage.0.to_string(),
        template: template.clone(),
        maximum: *maximum,
        policy: policy_hash.to_string(),
    };
    let loop_attempt = Ulid::new();
    assert!(matches!(
        face.db()
            .claim_expansion_attempt(loop_attempt, &spec, &expansion)
            .expect("the loop's expansion claims"),
        ExpansionClaimOutcome::Claimed { .. }
    ));
    let record = ExpansionRecord {
        operation: expansion.operation.clone(),
        path: spec.stage_id.clone(),
        stage: "implement".to_owned(),
        resolution: ExpansionResolution::Exhausted {
            iterations: 1,
            on_max: ExpansionOnMax::Accept,
        },
        members: vec![ExpansionMember {
            iteration: 0,
            member: 0,
            stage: "implement".to_owned(),
            occurrence: "ab".repeat(32),
        }],
        verdicts: Vec::new(),
        quorum_unmet: None,
    };
    assert!(record.is_unjudged_accept_exhaustion());
    face.db()
        .resolve_expansion_attempt(
            loop_attempt,
            &MainResolution::Complete {
                output: &record.to_output(),
            },
        )
        .expect("the loop's record resolves")
        .expect("the pending expansion accepts its record");

    // The run latched Completed, the closeout parked the candidate, and the
    // process died before the parked-candidate evidence was appended.
    face.begin_terminalization(
        execution_id,
        ExecutionLifecycleState::Completed,
        &kata_workflow::execution_program_store::ExecutionTerminalReason::new(
            "completed",
            "workflow completed",
        ),
    )
    .unwrap();
    let key = ExecutionWorkspaceKey::execution(execution_id);
    let path = kata_vcs::test_support::create_trunk_workspace(&*provider, &key)
        .expect("create execution workspace")
        .path;
    std::fs::write(path.join("candidate.txt"), "unjudged\n").unwrap();
    let parked = provider
        .park_workspace(&key, None)
        .expect("simulate the park committed before its evidence");
    assert!(!path.exists(), "parking removed the live workspace");
    let parked_ref = format!("parked/{execution_id}");
    assert_eq!(parked.ref_name, parked_ref);
    assert_eq!(
        raw_lifecycle(&op_path, execution_id),
        ("terminalizing".to_owned(), Some("completed".to_owned()))
    );
    assert!(
        raw_parked_evidence(&op_path, execution_id).is_empty(),
        "the crash left no parked-candidate evidence"
    );

    // The ORDER, not only the end state: while the parked-candidate append
    // fails, the repair refuses and `Completed` stays unpublished.
    faults.set_fail_parked_candidate_evidence(true);
    executor
        .resume_in_flight_runs()
        .expect_err("the repair cannot append the parked candidate");
    assert_eq!(
        raw_lifecycle(&op_path, execution_id),
        ("terminalizing".to_owned(), Some("completed".to_owned())),
        "no outcome is published before the parked candidate's evidence"
    );
    assert!(raw_parked_evidence(&op_path, execution_id).is_empty());
    faults.set_fail_parked_candidate_evidence(false);

    assert_eq!(executor.resume_in_flight_runs().unwrap(), [execution_id]);

    assert_eq!(
        raw_lifecycle(&op_path, execution_id),
        ("completed".to_owned(), Some("completed".to_owned())),
        "the repair published the latched outcome"
    );
    let commit = kata_test_utils::git::hermetic_git_in(tmp.path())
        .args(["rev-parse", "--verify", &format!("{parked_ref}^{{commit}}")])
        .output()
        .expect("git runs");
    assert!(commit.status.success(), "git holds {parked_ref}");
    let commit = String::from_utf8(commit.stdout).unwrap().trim().to_owned();
    let candidate = kata_test_utils::git::hermetic_git_in(tmp.path())
        .args(["show", &format!("{commit}:candidate.txt")])
        .output()
        .expect("git runs");
    assert_eq!(
        String::from_utf8_lossy(&candidate.stdout),
        "unjudged\n",
        "the parked ref holds the candidate the loop ended on"
    );
    assert_eq!(
        raw_parked_evidence(&op_path, execution_id),
        [(parked_ref, commit, true)],
        "the repair appended the parked candidate, read off the ref, as auto-parked"
    );
    assert!(executor.fatal_reason().is_none());
}

/// Every closeout park refusal row of `execution`, read raw off `path`:
/// `(refusal, parked_ref, message)`.
fn raw_closeout_park_refusals(
    path: &std::path::Path,
    execution: Ulid,
) -> Vec<(String, String, String)> {
    let conn = rusqlite::Connection::open_with_flags(
        path,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .unwrap();
    let mut statement = conn
        .prepare(
            "SELECT CAST(evidence_json AS TEXT) FROM execution_evidence WHERE execution_id = ?1",
        )
        .unwrap();
    statement
        .query_map([execution.to_bytes().as_slice()], |row| {
            row.get::<_, String>(0)
        })
        .unwrap()
        .map(|row| serde_json::from_str::<serde_json::Value>(&row.unwrap()).unwrap())
        .filter_map(|row| {
            let refusal = &row["evidence"]["closeout_park_refusal"];
            Some((
                refusal["refusal"].as_str()?.to_owned(),
                refusal["parked_ref"].as_str()?.to_owned(),
                refusal["message"].as_str()?.to_owned(),
            ))
        })
        .collect()
}

/// Every parked-candidate evidence row of `execution`, read raw off `path`:
/// `(parked_ref, commit_sha, auto_parked)`.
fn raw_parked_evidence(path: &std::path::Path, execution: Ulid) -> Vec<(String, String, bool)> {
    let conn = rusqlite::Connection::open_with_flags(
        path,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .unwrap();
    let mut statement = conn
        .prepare(
            "SELECT CAST(evidence_json AS TEXT) FROM execution_evidence WHERE execution_id = ?1",
        )
        .unwrap();
    statement
        .query_map([execution.to_bytes().as_slice()], |row| {
            row.get::<_, String>(0)
        })
        .unwrap()
        .map(|row| serde_json::from_str::<serde_json::Value>(&row.unwrap()).unwrap())
        .filter_map(|row| {
            let candidate = &row["evidence"]["parked_candidate"];
            Some((
                candidate["parked_ref"].as_str()?.to_owned(),
                candidate["commit_sha"].as_str()?.to_owned(),
                // `auto_parked` is skipped when false (`#[serde(default)]`).
                row["evidence"]["auto_parked"].as_bool().unwrap_or(false),
            ))
        })
        .collect()
}

#[tokio::test]
async fn lifecycle_scan_failure_refuses_recovery_without_orphaning_assignments() {
    let store = ExecutionLifecycleFace::in_memory().unwrap();
    let executor = build_executor_with_execution_lifecycle(
        Arc::new(WorkerPoolSupervisor::new()),
        Arc::new(WorkflowLibrary::new(vec![])),
        Some(store.clone()),
    );
    let execution_id = Ulid::new();
    store
        .put_current_program(
            execution_id,
            &compile_definition(tiny_definition("scan-fault")),
        )
        .unwrap();
    let _pending_attempt_id =
        seed_pending_capsule_attempt_on_authority(&executor, execution_id, "only")
            .expect("seed the pending attempt");

    store.drop_lifecycle_table_for_test().unwrap();
    let error = executor.resume_in_flight_runs().unwrap_err();
    // The FIRST reader of `execution_lifecycle` is the boot integrity candidate
    // scan, which runs ahead of the recoverable scan, so the refusal is raised
    // there. Assert the property (an unreadable lifecycle
    // table fails CLOSED, naming the unreadable table) rather than which of the
    // two scans happened to reach it first.
    assert!(
        error
            .to_string()
            .contains("no such table: execution_lifecycle"),
        "{error}"
    );
    assert!(
        error
            .to_string()
            .contains("scan operational nucleus integrity candidates")
            || error
                .to_string()
                .contains("scan durable recoverable execution lifecycles"),
        "{error}"
    );
    let face = executor.execution_lifecycle();
    assert!(
        face.db()
            .attempts_for_execution(execution_id)
            .expect("read attempts")
            .iter()
            .any(|row| row.row.stage_id == "only" && row.state.as_deref() == Some("pending")),
        "the pending attempt remains parked on the chain"
    );
}

#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn recovery_validates_every_running_candidate_before_spawning_any_runner() {
    let store = ExecutionLifecycleFace::in_memory().unwrap();
    let executor = build_executor_with_execution_lifecycle(
        Arc::new(WorkerPoolSupervisor::new()),
        Arc::new(WorkflowLibrary::new(vec![])),
        Some(store.clone()),
    );

    let first_execution_id = Ulid::from_bytes([0; 16]);
    let mut second_id_bytes = [0; 16];
    second_id_bytes[15] = 1;
    let second_execution_id = Ulid::from_bytes(second_id_bytes);

    let first_program = compile_definition(tiny_definition("valid-first-candidate"));
    store
        .put_current_program(first_execution_id, &first_program)
        .unwrap();

    let mut invalid_second_definition = tiny_definition("invalid-second-candidate");
    invalid_second_definition.worktree_isolated = true;
    let invalid_second_program = compile_definition(invalid_second_definition);
    store
        .put_current_program_with_target(
            second_execution_id,
            &invalid_second_program,
            kata_types::test_support::fixture_trunk_target(),
        )
        .unwrap();

    let error = executor.resume_in_flight_runs().unwrap_err();
    assert!(
        error.to_string().contains("no workspace provider"),
        "{error}"
    );

    // Give a mistakenly spawned first runner enough time to create an
    // assignment and fail on the empty worker pool. Recovery must instead
    // refuse the complete batch before polling any runner future.
    //
    // Stated on the AUTHORITY CHAIN. On the ledger projection this claim would be
    // silently vacuous without row creation — it would still pass, having stopped
    // observing the dispatch it denies. The chain half
    // of the admission door survives and runs FIRST, and the chain read REFUSES an
    // execution the nucleus does not hold rather than answering "no stages", so
    // the `expect` cannot quietly stand in for the assertion.
    tokio::time::sleep(Duration::from_millis(250)).await;
    assert!(
        executor
            .dispatcher_for_test()
            .execution_stage_states(first_execution_id)
            .expect("the nucleus holds this candidate, so the chain read SUCCEEDS")
            .is_empty(),
        "a valid earlier candidate dispatched during a failed startup batch"
    );
    assert_eq!(
        store.lifecycle(first_execution_id).unwrap().unwrap().state,
        ExecutionLifecycleState::Running
    );
    assert!(executor.fatal_reason().is_none());
}

#[tokio::test]
async fn lifecycle_read_failure_is_explicit_and_latches_executor_fatal() {
    let store = ExecutionLifecycleFace::in_memory().unwrap();
    let executor = build_executor_with_execution_lifecycle(
        Arc::new(WorkerPoolSupervisor::new()),
        Arc::new(WorkflowLibrary::new(vec![])),
        Some(store.clone()),
    );
    let execution_id = Ulid::new();
    store
        .put_current_program(
            execution_id,
            &compile_definition(tiny_definition("observation-fault")),
        )
        .unwrap();
    store.drop_lifecycle_table_for_test().unwrap();

    let get_error = executor
        .try_get_execution(&execution_id.to_string())
        .expect_err("authoritative lifecycle failure must not become 404");
    assert!(matches!(get_error, ExecutorError::DurabilityFailed(_)));
    let list_error = executor
        .try_list_executions()
        .expect_err("authoritative lifecycle scan failure must not return a partial list");
    assert!(matches!(list_error, ExecutorError::DurabilityFailed(_)));
    let fatal = executor
        .fatal_reason()
        .expect("authoritative observation failure must force node restart");
    assert!(fatal.contains("observation authority failed"), "{fatal}");
}

#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn resume_refuses_missing_running_workspace_even_without_stage_history() {
    let (tmp, backend) = jj_fixture();
    let provider: Arc<dyn ExecutionWorkspaceProvider> = backend.clone();
    let agents = tmp.path().join(kata_vcs::jj::AGENTS_DIR_NAME);
    let store = ExecutionLifecycleFace::in_memory().unwrap();
    let execution_id = Ulid::new();
    let mut definition = tiny_definition("resume-pre-dispatch-workspace");
    definition.worktree_isolated = true;
    let program = compile_definition(definition);
    let target = kata_vcs::test_support::resolve_trunk_target(
        &*provider,
        &ExecutionWorkspaceKey::execution(execution_id),
    )
    .unwrap();
    store
        .put_current_program_with_target(execution_id, &program, target)
        .unwrap();

    let stack = boot_executor_with_custom_ledger(
        InFlightLedger::in_memory(),
        Some(Arc::clone(&provider)),
        Some(store.clone()),
    );

    let executor = Arc::clone(&stack.executor);
    let key = ExecutionWorkspaceKey::execution(execution_id);
    assert!(provider.lookup_workspace(&key).unwrap().is_none());

    let error = executor
        .resume_in_flight_runs()
        .expect_err("Running authority cannot authorize a fresh replacement workspace");
    assert!(error.to_string().contains("no live workspace"), "{error}");
    assert!(
        provider.lookup_workspace(&key).unwrap().is_none(),
        "missing Running isolation must not be recreated from absence of stage history"
    );
    assert_eq!(
        store.lifecycle(execution_id).unwrap().unwrap().state,
        ExecutionLifecycleState::Running
    );
    assert!(
        !agents.join(execution_id.to_string()).exists(),
        "refused recovery must leave no execution workspace on disk"
    );
    assert!(executor.fatal_reason().is_none());
}

#[tokio::test]
async fn resume_refuses_missing_isolated_workspace_after_durable_evidence() {
    let (_tmp, backend) = jj_fixture();
    let provider: Arc<dyn ExecutionWorkspaceProvider> = backend.clone();
    let store = ExecutionLifecycleFace::in_memory().unwrap();
    let execution_id = Ulid::new();
    let mut definition = tiny_definition("resume-lost-workspace-evidence");
    definition.worktree_isolated = true;
    let program = compile_definition(definition);
    let target = kata_vcs::test_support::resolve_trunk_target(
        &*provider,
        &ExecutionWorkspaceKey::execution(execution_id),
    )
    .unwrap();
    store
        .put_current_program_with_target(execution_id, &program, target)
        .unwrap();
    let ledger = InFlightLedger::in_memory();
    persist_execution_admission_evidence(
        &ledger,
        execution_id,
        &program,
        &ExecutionInvocation::workflow(Vec::new()),
        &[],
    )
    .unwrap();
    // The admission evidence writer lands on its own typed table; the attempt/stage plane stays empty — on the chain,
    // which is the read every deciding consumer makes.
    assert!(
        store
            .db()
            .attempts_for_execution(execution_id)
            .expect("the chain answers")
            .is_empty()
            && store
                .db()
                .undispatched_stage_states(execution_id)
                .expect("the stage plane answers")
                .is_empty(),
        "the evidence writer must not create assignment authority"
    );
    assert!(!ledger.execution_evidence_records(execution_id).is_empty());

    let stack = boot_executor_with_custom_ledger(
        Arc::clone(&ledger),
        Some(Arc::clone(&provider)),
        Some(store.clone()),
    );

    let executor = Arc::clone(&stack.executor);
    let error = executor.resume_in_flight_runs().unwrap_err();
    assert!(error.to_string().contains("no live workspace"), "{error}");
    assert!(
        provider
            .lookup_workspace(&ExecutionWorkspaceKey::execution(execution_id))
            .unwrap()
            .is_none()
    );
}

// A cancel between stages asks a worker to stop, so it cannot also leave the world
// untouched; the durability-fatal path on an unreadable lifecycle is asserted
// below.

#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn cancellation_lifecycle_read_failure_is_durability_fatal() {
    let store = ExecutionLifecycleFace::in_memory().expect("program store");
    let executor = build_executor_with_execution_lifecycle(
        Arc::new(WorkerPoolSupervisor::new()),
        Arc::new(WorkflowLibrary::new(vec![])),
        Some(store.clone()),
    );
    let execution_id = Ulid::new();
    store
        .put_current_program(
            execution_id,
            &compile_definition(tiny_definition("cancel-lifecycle-read-failure")),
        )
        .expect("seed durable Running lifecycle");
    store
        .drop_lifecycle_table_for_test()
        .expect("inject lifecycle read failure");

    let error = executor
        .cancel(execution_id, "must fail closed".to_string())
        .await
        .expect_err("unreadable cancellation authority must not become a no-op");
    assert!(
        matches!(&error, ExecutorError::DurabilityFailed(message)
            if message.contains("before cancelling")),
        "{error:?}"
    );
    assert!(
        executor
            .fatal_reason()
            .is_some_and(|reason| reason.contains("cancellation lifecycle authority read failed")),
        "cancellation authority failure must force main restart"
    );
}

#[tokio::test]
async fn shutdown_admission_fence_rejects_new_checked_work() {
    let stack = boot_executor();
    let executor = Arc::clone(&stack.executor);
    executor.close_admission();
    let error = executor
        .submit_execution_program(compile_definition(tiny_definition("after-shutdown")))
        .expect_err("closed main admission must reject every submission source");
    assert!(matches!(error, ExecutorError::AdmissionClosed));
}

#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn authoritative_task_failure_latches_fatal_and_preserves_running_lifecycle() {
    let stack = boot_executor();
    let executor = Arc::clone(&stack.executor);
    let execution_id = Ulid::new();
    executor
        .execution_lifecycle()
        .put_current_program(
            execution_id,
            &compile_definition(tiny_definition("fatal-terminalization")),
        )
        .unwrap();

    executor.spawn_authoritative_failure_for_test(execution_id, false);
    let reason = tokio::time::timeout(Duration::from_secs(2), executor.wait_for_fatal())
        .await
        .expect("fatal supervision must resolve without a main restart");
    assert!(
        reason.contains(&execution_id.to_string()),
        "reason={reason}"
    );
    assert!(reason.contains("terminalization failed"), "reason={reason}");
    assert_eq!(
        executor
            .execution_lifecycle()
            .lifecycle(execution_id)
            .unwrap()
            .unwrap()
            .state,
        ExecutionLifecycleState::Running,
        "fatal escalation preserves durable Running authority for restart recovery"
    );
}

#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn authoritative_task_panic_is_caught_and_latches_fatal() {
    let stack = boot_executor();
    let executor = Arc::clone(&stack.executor);
    let execution_id = Ulid::new();
    executor.spawn_authoritative_failure_for_test(execution_id, true);

    let reason = tokio::time::timeout(Duration::from_secs(2), executor.wait_for_fatal())
        .await
        .expect("panic must reach fatal supervision without waiting for shutdown drain");
    assert!(
        reason.contains(&execution_id.to_string()),
        "reason={reason}"
    );
    assert!(reason.contains("panicked"), "reason={reason}");
    assert!(reason.contains("injected authoritative workflow panic"));
}

#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn resumed_terminal_intent_failure_forces_fatal_with_lifecycle_running() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("operational.db");
    let face = ExecutionLifecycleFace::open(&path).unwrap();
    let execution_id = Ulid::new();
    let program = compile_definition(tiny_definition("readonly-terminal-latch"));
    face.put_current_program(execution_id, &program).unwrap();
    // `operational.db` has no read-only production open, so isolate the same window precisely:
    // reads keep working (recovery must be able to LOAD the candidate) and only the lifecycle WRITE
    // fails, which is what must escalate to a whole-node fatal.
    face.reject_lifecycle_writes_for_test().unwrap();

    let ledger = InFlightLedger::in_memory();
    let stack = boot_executor_with_custom_ledger(Arc::clone(&ledger), None, Some(face.clone()));
    let executor = Arc::clone(&stack.executor);
    // Seed through the production paired doors. A ledger-only completion
    // leaves the deciding transition chain empty, so the resumed runner can
    // enter the cross-process wake/recheck path before it reaches the lifecycle
    // write under test. Whether another wake short-circuits that path is unrelated
    // to this assertion. Supplying terminal authority here keeps the test about
    // the terminal-intent failure and its fatal publication.
    //
    // The seed is a CAPSULE attempt — the capsule arm is what the live claim door
    // mints now, and the only arm `oci` resume accepts.
    let cas = stack.store.cas();
    let attempt_id = kata_workflow::test_harness::seed_dispatched_capsule_attempt(
        &stack.db,
        cas,
        execution_id,
        program.program_hash,
        "only",
        "worker",
        None,
    );
    stack
        .db
        .complete_attempt(attempt_id, &serde_json::json!({"ok": true}))
        .expect("the capsule completion, on the chain plane a capsule owns");
    let raw = rusqlite::Connection::open_with_flags(
        &path,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .expect("open raw authority oracle");
    let raw_terminal_count: i64 = raw
        .query_row(
            "SELECT COUNT(*) FROM transitions \
             WHERE execution_id = ?1 AND attempt_id = ?2 AND resulting_state = 'completed'",
            rusqlite::params![
                execution_id.to_bytes().as_ref(),
                attempt_id.to_bytes().as_ref()
            ],
            |row| row.get(0),
        )
        .expect("query raw terminal authority");
    assert_eq!(
        raw_terminal_count, 1,
        "POSITIVE CONTROL: resume starts with one raw terminal transition for the exact attempt"
    );

    assert_eq!(executor.resume_in_flight_runs().unwrap(), [execution_id]);
    let reason = tokio::time::timeout(Duration::from_secs(2), executor.wait_for_fatal())
        .await
        .expect("terminal latch failure must force engine-level fatal recovery");
    assert!(
        reason.contains(&execution_id.to_string()),
        "reason={reason}"
    );
    assert!(
        reason.contains("failed to durably decide resumed workflow outcome"),
        "reason={reason}"
    );
    assert_eq!(
        face.lifecycle(execution_id).unwrap().unwrap().state,
        ExecutionLifecycleState::Running
    );
}

#[tokio::test]
async fn shutdown_admission_fence_rejects_direct_agent_run_authority() {
    let stack = boot_executor_for_agent_run(
        "default",
        kata_test_utils::MockAgentBackend::with_responses(vec![]),
    );
    let executor = Arc::clone(&stack.executor);
    executor.close_admission();

    let error = executor
        .run_agent(AgentRunRequest {
            prompt: "must not start".to_string(),
            agent: "default".into(),
            model_hint: None,
            timeout_ms: None,
            output_schema: None,
            allowed_tools: vec![],
            sandbox: None,
        })
        .await
        .expect_err("direct agent runs are workflow authority and must share shutdown admission");
    assert!(matches!(error, ExecutorError::AdmissionClosed));
}

#[tokio::test]
async fn shutdown_admission_fence_covers_every_operator_mutation() {
    let stack = boot_executor();
    let executor = Arc::clone(&stack.executor);
    executor.close_admission();
    let execution = Ulid::new();
    let assignment = Ulid::new();

    assert!(matches!(
        executor.approve(execution, assignment, None).await,
        Err(ExecutorError::AdmissionClosed)
    ));
    assert!(matches!(
        executor.reject(execution, assignment, "no".to_string(), None),
        Err(ExecutorError::AdmissionClosed)
    ));
    assert!(matches!(
        executor.cancel(execution, "stop".to_string()).await,
        Err(ExecutorError::AdmissionClosed)
    ));
    assert!(matches!(
        executor.promote(execution),
        Err(ExecutorError::AdmissionClosed)
    ));
    assert!(matches!(
        executor.park_candidate(execution, None),
        Err(ExecutorError::AdmissionClosed)
    ));
    assert!(matches!(
        executor.answer_human_request(
            execution,
            ExecutionHumanRequestAnswerRequest {
                request_id: "request".to_string(),
                answer_summary: "answer".to_string(),
                answered_by_steering_id: None,
            },
            None
        ),
        Err(ExecutorError::AdmissionClosed)
    ));
    let signal = ExecutionExternalInputAppendRequest {
        channel: "signal".to_string(),
        text: "payload".to_string(),
        input_id: None,
        source: None,
        target_stage: None,
        payload: None,
    };
    assert!(matches!(
        executor.append_external_input(execution, signal),
        Err(ExecutorError::AdmissionClosed)
    ));
    assert!(matches!(
        executor
            .apply_controller_decision_once(execution, ExecutionControllerApplyRequest::default(),),
        Err(ExecutorError::AdmissionClosed)
    ));
    assert!(matches!(
        executor.finalize_controller_application_claim(
            execution,
            ExecutionControllerApplyFinalizeRequest::default(),
        ),
        Err(ExecutorError::AdmissionClosed)
    ));
}

#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn checked_workflow_stage_named_agent_run_remains_visible() {
    let stack = boot_executor();
    let executor = Arc::clone(&stack.executor);
    let mut definition = tiny_definition("normal-agent-run-stage");
    let old_id = StageId(SmolStr::new("only"));
    let new_id = StageId(SmolStr::new(AGENT_RUN_STAGE_NAME));
    let mut stage = definition.stages.remove(&old_id).expect("tiny stage");
    stage.id = new_id.clone();
    stage.prompt_template = "normal workflow stage named agent_run".to_string();
    definition.stages.insert(new_id, stage);

    let id = executor
        .submit_execution_program(compile_definition(definition))
        .expect("normal checked workflow should submit");

    let pending = executor
        .get_execution(&id)
        .expect("normal checked workflow must be visible before terminal state");
    assert_eq!(pending.workflow_name, "normal-agent-run-stage");

    let rec = wait_terminal(&executor, &id).await;
    assert_eq!(rec.status, ExecutionStatus::Completed);
    assert_eq!(rec.workflow_name, "normal-agent-run-stage");
    assert!(
        rec.outputs
            .expect("completed workflow outputs")
            .contains_key(AGENT_RUN_STAGE_NAME),
        "stage name agent_run is valid for normal checked workflows"
    );
}

#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn submit_fails_closed_when_execution_lifecycle_cannot_write_checked_program() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("operational.db");
    let face = ExecutionLifecycleFace::open(&path).expect("create schema");
    // Same substitution as above: the nucleus cannot be opened read-only, so reject
    // program INSERTs and let every read succeed.
    face.reject_program_writes_for_test()
        .expect("arm the program-write fault");
    let stack = boot_executor_with_execution_lifecycle(Some(face));
    let executor = Arc::clone(&stack.executor);

    let err = executor
        .submit_execution_program(compile_definition(tiny_definition("readonly-store")))
        .expect_err("submit must fail before runner spawn when checked program cannot persist");
    assert!(
        matches!(&err, ExecutorError::DurabilityFailed(msg) if msg.contains("admit checked execution program and invocation")),
        "unexpected error: {err:?}"
    );
    assert!(
        executor.list_executions().is_empty(),
        "failed submit must not leave an observable execution"
    );
}

#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn submit_worktree_isolated_without_provider_fails_before_execution_visible() {
    let stack = boot_executor();
    let executor = Arc::clone(&stack.executor);
    let mut definition = tiny_definition("missing-workspace-provider");
    definition.worktree_isolated = true;

    let err = executor
        .submit_execution_program(compile_definition(definition))
        .expect_err("isolated submissions must fail without a workspace provider");
    assert!(
        matches!(
            &err,
            ExecutorError::WorktreeIsolation {
                kind: WorktreeFailure::Unavailable,
                ..
            }
        ),
        "unexpected error: {err:?}"
    );
    assert!(
        executor.list_executions().is_empty(),
        "failed isolated submit must not leave an observable execution"
    );
}

#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn submit_worktree_isolated_creates_no_workspace_when_admission_evidence_fails() {
    let (_tmp, backend) = jj_fixture();
    let provider: Arc<dyn ExecutionWorkspaceProvider> = backend.clone();
    let store = Arc::new(FailingUnclaimedEvidenceStore::new(true));
    store.set_fail_claimed_evidence(true);
    let ledger = store.open_ledger();
    let program_store = ExecutionLifecycleFace::in_memory().unwrap();
    let stack = boot_executor_with_custom_ledger(
        ledger,
        Some(Arc::clone(&provider)),
        Some(program_store.clone()),
    );
    let executor = Arc::clone(&stack.executor);
    let mut definition = tiny_definition("isolated-cleanup-evidence-failure");
    definition.worktree_isolated = true;

    let execution_id = executor
        .submit_execution_program(compile_definition(definition))
        .expect("durable admission is the acceptance boundary");
    let execution_ulid = Ulid::from_string(&execution_id).unwrap();
    assert!(
        provider
            .lookup_workspace(&ExecutionWorkspaceKey::execution(execution_ulid))
            .unwrap()
            .is_none(),
        "admission evidence must become durable before isolated workspace creation"
    );
    let records = executor.list_executions();
    assert_eq!(records.len(), 1, "accepted failure remains observable");
    assert_eq!(records[0].id, execution_id);
    assert_eq!(
        records[0].status,
        ExecutionStatus::Failed,
        "failure sentinel and terminal closeout remain durable even when admission projection fails"
    );
    assert!(
        records[0]
            .error
            .as_deref()
            .is_some_and(|error| { error.contains("persist checked admission evidence") })
    );
    assert_eq!(
        program_store
            .lifecycle(execution_ulid)
            .unwrap()
            .unwrap()
            .state,
        ExecutionLifecycleState::Failed
    );
    assert!(executor.fatal_reason().is_none());
}

#[tokio::test]
async fn admitting_restart_refuses_conflicting_input_without_workspace_or_dispatch() {
    let (_tmp, backend) = jj_fixture();
    let provider: Arc<dyn ExecutionWorkspaceProvider> = backend.clone();
    let ledger = InFlightLedger::in_memory();
    let program_store = ExecutionLifecycleFace::in_memory().unwrap();
    let execution_id = Ulid::new();
    let definition = parse_inline_starlark_checked(
        r#"
only = stage(id = "only", prompt = "{{ external_inputs.controller.items }}", agent = "default")
workflow(
    "admitting-conflict-refusal",
    root = only,
    worktree_isolated = True,
    max_external_input_channels = 1,
    external_input_channels = [
        channel("controller_decision", stage = "only", expose_as = "controller", max_items = 1),
    ],
)
"#,
        "admitting_conflict_refusal.star",
        &[],
    )
    .expect("workflow parses");
    let program = compile_checked_definition(definition);
    let accepted = ExecutionExternalInputEvidence {
        schema_version: EXTERNAL_INPUT_EVIDENCE_SCHEMA_VERSION,
        id: "stable-id".to_string(),
        channel: "controller_decision".to_string(),
        source: Some("controller".to_string()),
        target_stage: Some("only".to_string()),
        text: "accepted".to_string(),
        payload: None,
        projection: "accepted".to_string(),
        appended_at_ms: 99,
    };
    let invocation = ExecutionInvocation::workflow(vec![accepted.clone()]).with_target(Some(
        kata_vcs::test_support::resolve_trunk_target(
            &*provider,
            &ExecutionWorkspaceKey::execution(execution_id),
        )
        .unwrap(),
    ));
    program_store
        .admit_current_execution(execution_id, &program, &invocation)
        .unwrap();
    let mut conflicting = accepted;
    conflicting.text = "forged".to_string();
    conflicting.projection = "forged".to_string();
    ledger
        .append_execution_evidence(
            execution_id,
            ExecutionEvidence {
                external_inputs: vec![conflicting],
                ..ExecutionEvidence::default()
            },
        )
        .unwrap();

    let stack = boot_executor_with_custom_ledger(
        Arc::clone(&ledger),
        Some(Arc::clone(&provider)),
        Some(program_store.clone()),
    );

    let executor = Arc::clone(&stack.executor);
    let error = executor.resume_in_flight_runs().unwrap_err();
    assert!(
        error.to_string().contains("initial external-input row"),
        "{error}"
    );
    assert!(
        provider
            .lookup_workspace(&ExecutionWorkspaceKey::execution(execution_id))
            .unwrap()
            .is_none()
    );
    // The AUTHORITY plane, for the reason the sibling refusal
    // above states — on the ledger projection this would be a tautology.
    assert!(
        executor
            .dispatcher_for_test()
            .execution_stage_states(execution_id)
            .expect("the nucleus holds this admitted execution, so the chain read SUCCEEDS")
            .is_empty(),
        "an admission-conflict refusal must precede every admission"
    );
    assert_eq!(
        program_store
            .lifecycle(execution_id)
            .unwrap()
            .unwrap()
            .state,
        ExecutionLifecycleState::Admitting
    );
}

#[tokio::test]
async fn legacy_completed_predecessor_refuses_without_inventing_invocation_or_lifecycle() {
    let execution_id = Ulid::new();
    let definition = parse_inline_starlark_checked(
        r#"
first = stage(id = "first", prompt = "first", agent = "default")
second = stage(id = "second", prompt = "second", agent = "default")
sequence(first, second)
workflow("predecessor-only", root = [first])
"#,
        "legacy_predecessor_only.star",
        &[],
    )
    .expect("workflow parses");
    let program = compile_checked_definition(definition);
    let program_store = ExecutionLifecycleFace::in_memory().unwrap();
    program_store
        .put_raw_legacy_evidence_json(execution_id, &serde_json::to_vec(&program).unwrap())
        .unwrap();
    let ledger = InFlightLedger::in_memory();
    let before_event_head = ledger.event_head();
    let stack =
        boot_executor_with_custom_ledger(Arc::clone(&ledger), None, Some(program_store.clone()));
    let executor = Arc::clone(&stack.executor);

    // A program with NO lifecycle row is not a resume CANDIDATE.
    // `execution_lifecycle` has a FOREIGN KEY to `programs` written in the same
    // commit, so the operational candidate scan cannot produce this shape. What
    // this test pins: recovery neither dispatches nor terminalizes such a
    // program, and writes nothing.
    assert!(
        executor.resume_in_flight_runs().unwrap().is_empty(),
        "a program with no lifecycle row must not be resumed, terminalized, or dispatched"
    );
    assert_eq!(ledger.event_head(), before_event_head);
    assert!(program_store.lifecycle(execution_id).unwrap().is_none());
    assert!(program_store.invocation(execution_id).unwrap().is_none());
}

#[tokio::test]
async fn direct_agent_terminalizing_recovery_repairs_evidence_without_provider_recall() {
    let program_store = ExecutionLifecycleFace::in_memory().unwrap();
    let mock = kata_test_utils::MockAgentBackend::with_responses(vec![
        kata_test_utils::MockResponse::Text("original result".to_string()),
    ]);
    let calls = mock.calls_handle();
    let stack =
        boot_executor_for_agent_run_with_lifecycle("default", mock, Some(program_store.clone()));
    let executor = Arc::clone(&stack.executor);
    let original = executor
        .run_agent(AgentRunRequest {
            prompt: "run exactly once".to_string(),
            agent: "default".into(),
            model_hint: None,
            timeout_ms: None,
            output_schema: None,
            allowed_tools: vec![],
            sandbox: None,
        })
        .await
        .expect("original direct-agent run completes");
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "the scripted worker must see exactly one capsule; run was {:?} error={:?}",
        original.status,
        original.error
    );
    let program: kata_program::execution_program::ExecutionProgram = serde_json::from_slice(
        &program_store
            .program_json(original.run_id.0)
            .unwrap()
            .expect("direct-agent checked program retained"),
    )
    .unwrap();

    let interrupted_id = Ulid::new();
    let invocation = ExecutionInvocation::direct_agent();
    program_store
        .admit_current_execution(interrupted_id, &program, &invocation)
        .unwrap();
    persist_execution_admission_evidence(
        executor.dispatcher_for_test().ledger(),
        interrupted_id,
        &program,
        &invocation,
        &[],
    )
    .unwrap();
    program_store
        .mark_running_after_admission(interrupted_id)
        .unwrap();
    program_store
        .begin_terminalization(
            interrupted_id,
            ExecutionLifecycleState::Failed,
            &kata_workflow::execution_program_store::ExecutionTerminalReason::new(
                "agent_run_failed",
                "provider returned an interrupted failure",
            ),
        )
        .unwrap();

    assert_eq!(executor.resume_in_flight_runs().unwrap(), [interrupted_id]);
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "recovery recalled the provider"
    );
    assert_eq!(
        program_store
            .lifecycle(interrupted_id)
            .unwrap()
            .unwrap()
            .state,
        ExecutionLifecycleState::Failed
    );
    let repaired = kata_workflow::attempt_delivery::AttemptDeliveryMapper::new(
        std::sync::Arc::clone(program_store.db()),
    )
    .execution_assignment_states(interrupted_id)
    .expect("the chain answers for the repaired execution");
    assert_eq!(repaired.len(), 1);
    assert_eq!(repaired[0].stage_name.as_str(), "__workflow__");
}

/// A submit whose setup failed latches `Failed` intent with reason code
/// `submit_setup_failed` and the `RemoveSubmitSetupWorkspace` disposition WHILE
/// the execution is still `Admitting` (`terminalize_submit_setup_failure` runs before
/// `mark_running_after_admission`), and only then writes the workflow-level failure.
/// A crash between those writes leaves Terminalizing + Failed + no chain stage.
/// Recovery must finish that closeout — write the `__workflow__` failure and publish
/// `Failed` — without recalling the provider, rather than refuse the code as
/// undeclared.
#[tokio::test]
async fn a_submit_setup_failure_interrupted_before_closeout_is_repaired_on_recovery() {
    let program_store = ExecutionLifecycleFace::in_memory().unwrap();
    let mock = kata_test_utils::MockAgentBackend::with_responses(vec![
        kata_test_utils::MockResponse::Text("original result".to_string()),
    ]);
    let calls = mock.calls_handle();
    let stack =
        boot_executor_for_agent_run_with_lifecycle("default", mock, Some(program_store.clone()));
    let executor = Arc::clone(&stack.executor);
    let original = executor
        .run_agent(AgentRunRequest {
            prompt: "run exactly once".to_string(),
            agent: "default".into(),
            model_hint: None,
            timeout_ms: None,
            output_schema: None,
            allowed_tools: vec![],
            sandbox: None,
        })
        .await
        .expect("original direct-agent run completes");
    let program: kata_program::execution_program::ExecutionProgram = serde_json::from_slice(
        &program_store
            .program_json(original.run_id.0)
            .unwrap()
            .expect("direct-agent checked program retained"),
    )
    .unwrap();

    let interrupted_id = Ulid::new();
    let invocation = ExecutionInvocation::direct_agent();
    program_store
        .admit_current_execution(interrupted_id, &program, &invocation)
        .unwrap();
    persist_execution_admission_evidence(
        executor.dispatcher_for_test().ledger(),
        interrupted_id,
        &program,
        &invocation,
        &[],
    )
    .unwrap();
    assert_eq!(
        program_store
            .lifecycle(interrupted_id)
            .unwrap()
            .unwrap()
            .state,
        ExecutionLifecycleState::Admitting,
        "a submit setup failure latches its intent before Running is authorized"
    );
    program_store
        .begin_terminalization_with_cleanup(
            interrupted_id,
            ExecutionLifecycleState::Failed,
            &kata_workflow::execution_program_store::ExecutionTerminalReason::new(
                "submit_setup_failed",
                "the execution workspace could not be created",
            ),
            kata_workflow::execution_lifecycle::CleanupDisposition::RemoveSubmitSetupWorkspace,
        )
        .unwrap();

    assert_eq!(executor.resume_in_flight_runs().unwrap(), [interrupted_id]);
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "recovery recalled the provider"
    );
    let lifecycle = program_store
        .lifecycle(interrupted_id)
        .unwrap()
        .expect("the repaired execution keeps its lifecycle row");
    assert_eq!(lifecycle.state, ExecutionLifecycleState::Failed);
    assert_eq!(
        lifecycle.terminal_reason.map(|reason| reason.code),
        Some("submit_setup_failed".to_string()),
        "recovery publishes the latched reason, not a substitute"
    );
    let repaired = kata_workflow::attempt_delivery::AttemptDeliveryMapper::new(
        std::sync::Arc::clone(program_store.db()),
    )
    .execution_assignment_states(interrupted_id)
    .expect("the chain answers for the repaired execution");
    assert_eq!(repaired.len(), 1);
    assert_eq!(repaired[0].stage_name.as_str(), "__workflow__");
}

/// A Terminalizing execution whose reason code the closeout does not declare is
/// refused by the generic `unsupported closeout reason code` arm, never repaired.
/// No closeout declares the `scratch_*` codes, so each `failed` one is driven
/// through recovery here.
/// `scratch_completed` is left out only because this fixture's
/// execution has no stage history, which refuses a `Completed` closeout before the
/// code match is reached.
#[tokio::test]
async fn terminalizing_recovery_refuses_an_undeclared_closeout_reason_code() {
    for code in [
        "scratch_failed",
        "scratch_admission_evidence_failed",
        "scratch_workspace_setup_failed",
    ] {
        let program_store = ExecutionLifecycleFace::in_memory().unwrap();
        let mock = kata_test_utils::MockAgentBackend::with_responses(vec![
            kata_test_utils::MockResponse::Text("original result".to_string()),
        ]);
        let calls = mock.calls_handle();
        let stack = boot_executor_for_agent_run_with_lifecycle(
            "default",
            mock,
            Some(program_store.clone()),
        );
        let executor = Arc::clone(&stack.executor);
        let original = executor
            .run_agent(AgentRunRequest {
                prompt: "run exactly once".to_string(),
                agent: "default".into(),
                model_hint: None,
                timeout_ms: None,
                output_schema: None,
                allowed_tools: vec![],
                sandbox: None,
            })
            .await
            .expect("original direct-agent run completes");
        let program: kata_program::execution_program::ExecutionProgram = serde_json::from_slice(
            &program_store
                .program_json(original.run_id.0)
                .unwrap()
                .expect("direct-agent checked program retained"),
        )
        .unwrap();

        let undeclared_id = Ulid::new();
        let invocation = ExecutionInvocation::direct_agent();
        program_store
            .admit_current_execution(undeclared_id, &program, &invocation)
            .unwrap();
        persist_execution_admission_evidence(
            executor.dispatcher_for_test().ledger(),
            undeclared_id,
            &program,
            &invocation,
            &[],
        )
        .unwrap();
        program_store
            .mark_running_after_admission(undeclared_id)
            .unwrap();
        program_store
            .begin_terminalization(
                undeclared_id,
                ExecutionLifecycleState::Failed,
                &kata_workflow::execution_program_store::ExecutionTerminalReason::new(
                    code,
                    "a terminal intent no current closeout declares",
                ),
            )
            .unwrap();

        let error = executor
            .resume_in_flight_runs()
            .expect_err("an undeclared closeout reason code must be refused, not repaired");
        let text = error.to_string();
        assert!(
            text.contains(&format!(
                "unsupported closeout reason code \"{code}\" for outcome Failed"
            )),
            "{code}: {text}"
        );
        assert_eq!(
            program_store
                .lifecycle(undeclared_id)
                .unwrap()
                .unwrap()
                .state,
            ExecutionLifecycleState::Terminalizing,
            "{code}: the refused execution is not closed out"
        );
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "{code}: recovery recalled the provider"
        );
    }
}

#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn run_agent_threads_output_schema_to_worker() {
    let stack = boot_executor_for_agent_run(
        "default",
        kata_test_utils::MockAgentBackend::with_responses(vec![
            kata_test_utils::MockResponse::Json(
                serde_json::json!({"summary": "threaded", "passed": true}),
            ),
        ]),
    );
    let executor = Arc::clone(&stack.executor);

    let result = executor
        .run_agent(AgentRunRequest {
            prompt: "return structured status".to_string(),
            agent: "default".into(),
            model_hint: None,
            timeout_ms: None,
            output_schema: Some(serde_json::json!({
                "type": "object",
                "properties": {
                    "summary": {"type": "string", "maxLength": 200},
                    "passed": {"type": "boolean"}
                },
                "required": ["summary", "passed"],
                "additionalProperties": false
            })),
            allowed_tools: vec![],
            sandbox: None,
        })
        .await
        .unwrap();

    assert_eq!(result.status, AgentRunStatus::Completed);
    let output = result
        .result
        .expect("completed result should include output");
    assert!(output.content.contains("threaded"));
    assert_eq!(output.parsed.unwrap()["passed"], true);
    assert!(result.error.is_none());
    let evidence_rows = executor
        .dispatcher_for_test()
        .ledger()
        .execution_evidence_records(result.run_id.0);
    assert!(
        evidence_rows
            .iter()
            .any(|row| row.evidence.execution_program.is_some()),
        "agent runs must persist checked execution-program evidence"
    );
    assert!(
        executor
            .get_execution(&result.run_id.0.to_string())
            .is_none(),
        "agent runs remain hidden from normal execution views"
    );
}

#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn run_agent_treats_prompt_as_literal_checked_ir() {
    let program_store = ExecutionLifecycleFace::in_memory().unwrap();
    let prompt = "Return this literally: {{ stages.missing.content }}";
    let stack = boot_executor_for_agent_run_with_lifecycle(
        "default",
        kata_test_utils::MockAgentBackend::with_responses(vec![
            kata_test_utils::MockResponse::Echo,
        ]),
        Some(program_store.clone()),
    );
    let executor = Arc::clone(&stack.executor);

    let result = executor
        .run_agent(AgentRunRequest {
            prompt: prompt.to_string(),
            agent: "default".into(),
            model_hint: None,
            timeout_ms: None,
            output_schema: None,
            allowed_tools: vec![],
            sandbox: None,
        })
        .await
        .unwrap();

    assert_eq!(
        result.status,
        AgentRunStatus::Completed,
        "run error: {:?}",
        result.error
    );
    let output = result
        .result
        .expect("completed agent run should include output");
    assert_eq!(output.content, prompt);
    let stored_program = program_store
        .program_json(result.run_id.0)
        .expect("program store read")
        .expect("agent run should persist checked program");
    let stored_program: kata_program::execution_program::ExecutionProgram =
        serde_json::from_slice(&stored_program).expect("stored program should deserialize");
    assert_eq!(stored_program.workflow_name.as_str(), "api.agent_run");
    let checked_stage = stored_program
        .stages
        .get(&StageId(SmolStr::new(AGENT_RUN_STAGE_NAME)))
        .expect("agent run checked stage");
    assert_eq!(
        checked_stage.op.prompt_rendering,
        ExecutionPromptRendering::Literal
    );
    assert!(
        executor
            .get_execution(&result.run_id.0.to_string())
            .is_none(),
        "BYO agent runs are classified by checked-program provenance"
    );
}

#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn submit_without_workers_fails_immediately() {
    // Executor with an empty supervisor. Execution submit must reject
    // via the up-front NoWorkers pre-check before even touching
    // the dispatcher.
    let supervisor = Arc::new(WorkerPoolSupervisor::new());
    let library = Arc::new(WorkflowLibrary::new(vec![]));
    let executor = build_executor(supervisor, library);

    let err = executor
        .submit_execution_program(compile_definition(tiny_definition("no-worker")))
        .unwrap_err();
    assert!(matches!(err, ExecutorError::NoWorkers));
}

/// Register worker `id` on `supervisor` with `caps` and `containment`, over an
/// in-process transport whose worker end is returned for the caller to keep alive.
fn register_one_worker(
    supervisor: &WorkerPoolSupervisor,
    id: &str,
    caps: &[&str],
    containment: kata_types::containment_claim::ClaimedContainment,
) -> InProcessTransport {
    let (home, worker) = InProcessTransport::pair(64);
    let home: Arc<dyn WorkerTransport> = Arc::new(home);
    supervisor.register_worker_with_containment(
        SmolStr::new(id),
        home,
        caps.iter().map(|cap| (*cap).to_owned()).collect(),
        containment,
    );
    worker
}

/// A one-stage program whose stage selects agent `label`.
fn labelled_stage_program(name: &str, label: &str) -> ExecutionProgram {
    let mut definition = tiny_definition(name);
    definition
        .stages
        .get_mut(&StageId(SmolStr::new("only")))
        .expect("only stage exists")
        .agent = AgentSelector::Labelled(SmolStr::new(label));
    compile_definition(definition)
}

/// A stage's agent LABEL is not a placement fact. Under
/// the capsule engine the main resolves `[agents.<label>]` at capsule assembly
/// (`agent_turn_spec`) and the turn runs from the node environment's closure; placement
/// (`Dispatcher::select_capsule_worker`) demands no capability of any worker. A `codex`
/// stage on a pool whose one CERTIFIED worker advertises only `agent:shell` is therefore
/// admitted — not refused `only requires [agent:codex]` — and
/// placement puts it on that worker. The control: the same stage on a pool whose one
/// worker advertises `agent:codex` but states no containment is refused, naming the
/// stage and the certified container every capsule needs, before an execution exists.
#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn a_stage_label_no_worker_advertises_is_not_a_capacity_refusal() {
    let supervisor = Arc::new(WorkerPoolSupervisor::new());
    let executor = build_executor(
        Arc::clone(&supervisor),
        Arc::new(WorkflowLibrary::new(vec![])),
    );

    let _shell_only = register_one_worker(
        &supervisor,
        "shell-only",
        &["agent:shell"],
        kata_workflow::test_harness::rig_worker_containment(),
    );
    executor
        .submit_execution_program(labelled_stage_program("codex-on-shell-only", "codex"))
        .expect("no worker label is demanded: a certified worker can run the capsule");
    assert_eq!(
        executor
            .dispatcher_for_test()
            .select_capsule_worker()
            .expect("placement finds the certified worker"),
        "shell-only",
        "placement puts the capsule on the worker that advertises no `agent:codex`"
    );

    supervisor.unregister_worker("shell-only");
    let _uncontained = register_one_worker(
        &supervisor,
        "uncontained",
        &["agent:shell", "agent:codex"],
        kata_types::containment_claim::ClaimedContainment::unstated_no_handshake(),
    );
    let before = executor.list_executions().len();
    let err = executor
        .submit_execution_program(labelled_stage_program("codex-uncontained", "codex"))
        .expect_err("no live worker can contain the capsule");
    assert!(
        matches!(&err, ExecutorError::WorkerCapacityUnavailable(message)
            if message.contains("codex-uncontained")
                && message.contains("CERTIFIED CONTAINMENT")
                && message.contains("to place `only`")),
        "unexpected error: {err:?}"
    );
    assert_eq!(
        executor.list_executions().len(),
        before,
        "capacity preflight must reject before indexing or spawning an execution"
    );
}

/// The capacity preflight and capsule placement ask ONE
/// question (`Dispatcher::capsule_worker_count` and `Dispatcher::select_capsule_worker`
/// read one `CAPSULE_PLACEMENT`), so over every constructed pool a submission of a
/// labelled model stage is admitted EXACTLY when placement finds a worker. The pools vary
/// the two facts a worker states — its labels and its containment claim — one worker at a
/// time and together, so a preflight that demanded a label (or no containment) would
/// disagree with placement on some row. Placement is read off the executor's own
/// dispatcher, the door every capsule attempt is placed through; one executor serves
/// every row, its pool replaced between them.
#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn the_capacity_preflight_admits_exactly_where_capsule_placement_places() {
    use kata_types::containment_claim::ClaimedContainment;
    /// One worker: its id, its advertised capabilities, its containment claim.
    type Worker = (&'static str, Vec<&'static str>, ClaimedContainment);
    let certified = kata_workflow::test_harness::rig_worker_containment;
    let pools: Vec<(&str, Vec<Worker>)> = vec![
        ("empty", vec![]),
        (
            "uncertified, labelled",
            vec![(
                "uncertified-labelled",
                vec!["agent:shell", "agent:default"],
                ClaimedContainment::unstated_no_handshake(),
            )],
        ),
        (
            "certified, unlabelled",
            vec![("certified-unlabelled", vec!["agent:shell"], certified())],
        ),
        (
            "certified, labelled",
            vec![(
                "certified-labelled",
                vec!["agent:shell", "agent:default"],
                certified(),
            )],
        ),
        (
            "an uncertified labelled worker beside a certified unlabelled one",
            vec![
                (
                    "beside-labelled",
                    vec!["agent:shell", "agent:default"],
                    ClaimedContainment::unstated_no_handshake(),
                ),
                ("beside-certified", vec!["agent:shell"], certified()),
            ],
        ),
    ];
    let supervisor = Arc::new(WorkerPoolSupervisor::new());
    let executor = build_executor(
        Arc::clone(&supervisor),
        Arc::new(WorkflowLibrary::new(vec![])),
    );
    let mut worker_ends = Vec::new();
    let mut registered: Vec<&str> = Vec::new();
    let mut verdicts = Vec::new();
    for (pool, workers) in pools {
        for id in registered.drain(..) {
            supervisor.unregister_worker(id);
        }
        for (id, caps, containment) in workers {
            worker_ends.push(register_one_worker(&supervisor, id, &caps, containment));
            registered.push(id);
        }
        let placed = executor
            .dispatcher_for_test()
            .select_capsule_worker()
            .is_ok();
        let admitted = executor
            .submit_execution_program(labelled_stage_program("model-stage", "default"))
            .is_ok();
        assert_eq!(
            admitted, placed,
            "{pool}: the preflight admitted={admitted} where placement placed={placed}"
        );
        verdicts.push(admitted);
    }
    assert!(
        verdicts.contains(&true) && verdicts.contains(&false),
        "non-vacuity: some pool is admitted and some refused; {verdicts:?}"
    );
}

/// The capacity preflight demands a worker only for a stage a
/// worker RUNS. A `sleep()`, a `memory_snapshot()` and a `subworkflow()` are all
/// resolved by the main, and this parent's bound child is a memory snapshot the
/// main resolves too, so the program is admitted on a pool whose one live worker
/// advertises no `agent:*` label and no certified containment. The control — a
/// plain shell stage on the SAME pool — is refused by name (its capsule needs a
/// certified container), so the admission is the skip and not a rig that refuses
/// nothing.
#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn a_program_of_main_resolved_stages_needs_no_eligible_worker() {
    use tempfile::TempDir;
    let (home, _worker) = InProcessTransport::pair(64);
    let home: Arc<dyn WorkerTransport> = Arc::new(home);
    let supervisor = Arc::new(WorkerPoolSupervisor::new());
    supervisor.register_worker(SmolStr::new("labelless"), Arc::clone(&home));
    let lib_dir = TempDir::new().unwrap();
    std::fs::write(lib_dir.path().join("child.star"), MAIN_ONLY_CHILD).unwrap();
    std::fs::write(
        lib_dir.path().join("main-only.star"),
        r#"
memory_context = memory_snapshot(id = "memory_context", kind = "task", status = "active")
nap = sleep(id = "nap", for_ms = 1, depends_on = [memory_context])
sub = subworkflow(id = "sub", pack = "child", depends_on = [nap])
workflow("main-only", root = [memory_context])
"#,
    )
    .unwrap();
    std::fs::write(
        lib_dir.path().join("needs-shell.star"),
        r#"
only = stage(id = "only", agent = "shell", run = "true")
workflow("needs-shell", root = only)
"#,
    )
    .unwrap();
    let executor = build_executor(
        supervisor,
        Arc::new(WorkflowLibrary::new(vec![lib_dir.path().to_path_buf()])),
    );

    let control = executor
        .compile_ref_execution_program("needs-shell")
        .expect("the control compiles");
    let err = executor
        .submit_execution_program(control)
        .expect_err("a shell stage's capsule needs a certified worker this pool lacks");
    assert!(
        matches!(&err, ExecutorError::WorkerCapacityUnavailable(message)
            if message.contains("CERTIFIED CONTAINMENT") && message.contains("to place `only`")),
        "unexpected control error: {err:?}"
    );

    let program = executor
        .compile_ref_execution_program("main-only")
        .expect("the main-resolved pack compiles");
    executor
        .submit_execution_program(program)
        .expect("no stage of this program or its child is run by a worker, so none is demanded");
}

/// A bound child the main resolves entirely: one memory snapshot.
const MAIN_ONLY_CHILD: &str = "ctx = memory_snapshot(id = \"ctx\", kind = \"task\", status = \"active\")\nworkflow(\"child\", root = ctx)\n";

/// The empty-pool half: a program the main resolves entirely
/// is admitted with NO live worker at all — sleeps and memory snapshots, and a
/// `subworkflow()` whose bound child is itself main-only. Two refusals on the
/// same empty pool bound the admission: a plain shell stage is refused
/// `NoWorkers`, and so is a parent whose bound child runs a shell stage — the
/// preflight reads the child, and a worker runs the child's stage.
#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn a_program_of_sleeps_and_snapshots_needs_no_live_worker() {
    use tempfile::TempDir;
    let supervisor = Arc::new(WorkerPoolSupervisor::new());
    let lib_dir = TempDir::new().unwrap();
    std::fs::write(
        lib_dir.path().join("shell-child.star"),
        "only = stage(id = \"only\", agent = \"shell\", run = \":\")\nworkflow(\"shell-child\", root = only)\n",
    )
    .unwrap();
    std::fs::write(lib_dir.path().join("child.star"), MAIN_ONLY_CHILD).unwrap();
    std::fs::write(
        lib_dir.path().join("snapshot-and-sleep.star"),
        r#"
memory_context = memory_snapshot(id = "memory_context", kind = "task", status = "active")
nap = sleep(id = "nap", for_ms = 1, depends_on = [memory_context])
workflow("snapshot-and-sleep", root = [memory_context])
"#,
    )
    .unwrap();
    std::fs::write(
        lib_dir.path().join("invokes-a-shell-child.star"),
        r#"
memory_context = memory_snapshot(id = "memory_context", kind = "task", status = "active")
sub = subworkflow(id = "sub", pack = "shell-child", depends_on = [memory_context])
workflow("invokes-a-shell-child", root = [memory_context])
"#,
    )
    .unwrap();
    std::fs::write(
        lib_dir.path().join("invokes-a-main-only-child.star"),
        r#"
memory_context = memory_snapshot(id = "memory_context", kind = "task", status = "active")
sub = subworkflow(id = "sub", pack = "child", depends_on = [memory_context])
workflow("invokes-a-main-only-child", root = [memory_context])
"#,
    )
    .unwrap();
    std::fs::write(
        lib_dir.path().join("needs-shell.star"),
        r#"
only = stage(id = "only", agent = "shell", run = "true")
workflow("needs-shell", root = only)
"#,
    )
    .unwrap();
    let executor = build_executor(
        supervisor,
        Arc::new(WorkflowLibrary::new(vec![lib_dir.path().to_path_buf()])),
    );

    for refused in ["needs-shell", "invokes-a-shell-child"] {
        let program = executor
            .compile_ref_execution_program(refused)
            .expect("the control compiles");
        let err = executor
            .submit_execution_program(program)
            .expect_err("a worker runs a stage of this program, and the pool is empty");
        assert!(
            matches!(err, ExecutorError::NoWorkers),
            "{refused}: unexpected error: {err:?}"
        );
    }
    assert!(
        executor.list_executions().is_empty(),
        "both controls must be refused before an execution exists"
    );

    for admitted in ["snapshot-and-sleep", "invokes-a-main-only-child"] {
        let program = executor
            .compile_ref_execution_program(admitted)
            .expect("the main-resolved pack compiles");
        executor
            .submit_execution_program(program)
            .unwrap_or_else(|err| {
                panic!(
                    "{admitted}: the main resolves every stage of this program and its child, \
                 so no worker is demanded: {err:?}"
                )
            });
    }
    assert_eq!(executor.list_executions().len(), 2);
}

/// The preflight
/// reads a subworkflow child's stages off the child program the parent's check bound —
/// at any depth — and demands, for each stage a worker runs, what capsule placement
/// demands: a live worker with certified containment, and no label. A parent whose
/// grandchild runs an `agent = "default"` model stage is refused, naming the stage and
/// the bound subworkflow it sits in, on a pool whose only worker advertises
/// `agent:default` but states no containment; the same parent is admitted on a pool
/// whose certified worker advertises only `agent:shell` (the label is something
/// placement never asks about). The parent's and the middle child's own
/// stages are memory snapshots, a sleep and subworkflows, so the demand can only have
/// come from the grandchild.
#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn a_subworkflow_parent_demands_a_certified_worker_for_its_bound_childs_stages() {
    use tempfile::TempDir;
    let lib_dir = TempDir::new().unwrap();
    std::fs::write(
        lib_dir.path().join("model-grandchild.star"),
        "only = stage(id = \"only\", prompt = \"hi\", agent = \"default\")\nworkflow(\"model-grandchild\", root = only)\n",
    )
    .unwrap();
    std::fs::write(
        lib_dir.path().join("middle.star"),
        r#"
ctx = memory_snapshot(id = "ctx", kind = "task", status = "active")
deeper = subworkflow(id = "deeper", pack = "model-grandchild", depends_on = [ctx])
workflow("middle", root = [ctx])
"#,
    )
    .unwrap();
    std::fs::write(
        lib_dir.path().join("parent.star"),
        r#"
ctx = memory_snapshot(id = "ctx", kind = "task", status = "active")
nap = sleep(id = "nap", for_ms = 1, depends_on = [ctx])
sub = subworkflow(id = "sub", pack = "middle", depends_on = [nap])
workflow("parent", root = [ctx])
"#,
    )
    .unwrap();
    let library = Arc::new(WorkflowLibrary::new(vec![lib_dir.path().to_path_buf()]));

    let supervisor = Arc::new(WorkerPoolSupervisor::new());
    let executor = build_executor(Arc::clone(&supervisor), library);
    let _uncontained = register_one_worker(
        &supervisor,
        "uncontained",
        &["agent:shell", "agent:default"],
        kata_types::containment_claim::ClaimedContainment::unstated_no_handshake(),
    );
    let program = executor
        .compile_ref_execution_program("parent")
        .expect("the parent compiles, binding its child and grandchild");
    let Err(err) = executor.submit_execution_program(program) else {
        panic!("the grandchild's model stage needs a certified worker, and none states one");
    };
    assert!(
        matches!(&err, ExecutorError::WorkerCapacityUnavailable(message)
            if message.contains("`only` of bound subworkflow `model-grandchild`")
                && message.contains("CERTIFIED CONTAINMENT")),
        "unexpected error: {err:?}"
    );
    assert!(
        executor.list_executions().is_empty(),
        "the refusal comes before an execution exists"
    );

    supervisor.unregister_worker("uncontained");
    let _unlabelled = register_one_worker(
        &supervisor,
        "unlabelled",
        &["agent:shell"],
        kata_workflow::test_harness::rig_worker_containment(),
    );
    let program = executor
        .compile_ref_execution_program("parent")
        .expect("the parent compiles");
    executor
        .submit_execution_program(program)
        .expect("a live certified worker can run the grandchild's capsule; no label is asked");
}

/// The two in-process admissions —
/// a workspace effect (`park`, `commit`) and a forge export — are run by the
/// main, never placed on a worker, so a program whose only stages they are is
/// admitted with NO live worker and no `agent:workspace_effect` advertised
/// anywhere. The control on the same empty pool, one shell stage beside the
/// same effects, is refused `NoWorkers`.
#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn a_program_of_workspace_effects_and_a_forge_export_needs_no_worker() {
    let effects_only = |extra: &str| {
        kata_program::execution_program::compile_starlark_execution_program(
            &format!(
                r#"
snap = stage(id = "snap", agent = "workspace_effect", op = "commit")
park = stage(id = "park", agent = "workspace_effect", op = "park", depends_on = [snap])
publish = stage(id = "publish", agent = "workspace_effect", op = "forge_export", depends_on = [snap])
{extra}
workflow("effects-only", root = [snap, publish], worktree_isolated = True)
"#
            ),
            "effects-only.star",
            &[],
        )
        .expect("the effects pack compiles")
    };

    let (_control_tmp, control_backend) = jj_fixture();
    let executor = build_executor_with_workspace_provider(control_backend);
    let err = executor
        .submit_execution_program(effects_only(
            "seed = stage(id = \"seed\", agent = \"shell\", run = \"true\", depends_on = [snap])",
        ))
        .expect_err("the shell stage is run by a worker, and the pool is empty");
    assert!(
        matches!(err, ExecutorError::NoWorkers),
        "unexpected control error: {err:?}"
    );

    // A program that exports its candidate needs a LANDABLE target, so this
    // half forks a repository with a trunk (an unborn one is refused
    // `target_not_landable` at admission, before any worker question).
    let tmp = tempfile::tempdir().expect("tempdir");
    kata_test_utils::git::init_git_repo_at(tmp.path());
    let backend = Arc::new(
        <kata_vcs::JjBackend as kata_vcs::VcsBackend>::open(tmp.path()).expect("open jj backend"),
    );
    let executor = build_executor_with_workspace_provider(backend);
    executor
        .submit_execution_program(effects_only(""))
        .expect("the main performs every stage of this program, so no worker is demanded");
}

#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn compile_ref_missing_returns_not_found() {
    let stack = boot_executor();
    let executor = Arc::clone(&stack.executor);
    let err = executor
        .compile_ref_execution_program("does-not-exist")
        .unwrap_err();
    assert!(matches!(err, ExecutorError::RefNotFound(_)));
}

#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn compile_ref_and_submit_roundtrips_through_library() {
    // Build a library over a tempdir with one Starlark workflow, then
    // drive a full submit through the executor. Proves the
    // workflow-ref submission path the HTTP handler uses works
    // without the HTTP layer.
    use tempfile::TempDir;
    let lib_dir = TempDir::new().unwrap();
    std::fs::write(
        lib_dir.path().join("sample.star"),
        r#"
only = stage(id = "only", prompt = "hi", agent = "default")
workflow("sample", root = only)
"#,
    )
    .unwrap();

    let stack = common::boot_executor_with_library(
        Arc::new(WorkflowLibrary::new(vec![lib_dir.path().to_path_buf()])),
        None,
    );
    let executor = Arc::clone(&stack.executor);

    let program = executor.compile_ref_execution_program("sample").unwrap();
    let id = executor.submit_execution_program(program).unwrap();
    let rec = wait_terminal(&executor, &id).await;
    assert_eq!(rec.status, ExecutionStatus::Completed);
    assert_eq!(rec.workflow_name, "sample");
}

#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn compile_ref_preserves_human_request_extensions() {
    use tempfile::TempDir;
    let lib_dir = TempDir::new().unwrap();
    std::fs::write(
        lib_dir.path().join("checked.star"),
        r#"
only = stage(id = "only", prompt = "hi", agent = "default")
workflow(
    "checked",
    root = only,
    max_human_requests = 1,
    human_requests = [
        human_request(
            "HR-executor",
            question = "Need input?",
            default_assumption = "Continue.",
        ),
    ],
)
"#,
    )
    .unwrap();

    let (home, _worker) = InProcessTransport::pair(64);
    let home = Arc::new(home);
    let supervisor = Arc::new(WorkerPoolSupervisor::new());
    supervisor.register_worker_with_containment(
        SmolStr::new("lib-test"),
        Arc::clone(&home) as Arc<dyn WorkerTransport>,
        vec!["agent:default".to_string()],
        kata_workflow::test_harness::rig_worker_containment(),
    );
    let library = Arc::new(WorkflowLibrary::new(vec![lib_dir.path().to_path_buf()]));
    let executor = build_executor(Arc::clone(&supervisor), library);

    let program = executor.compile_ref_execution_program("checked").unwrap();
    assert_eq!(program.workflow_name.as_str(), "checked");
    assert_eq!(program.human_request_queue.requests.len(), 1);
    assert_eq!(
        program.human_request_queue.requests[0].id.as_str(),
        "HR-executor"
    );
}

#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn submit_persists_human_request_execution_evidence() {
    let stack = boot_executor();
    let executor = Arc::clone(&stack.executor);
    let checked = parse_inline_starlark_checked(
        r#"
only = stage(id = "only", prompt = "hi", agent = "default")
workflow(
    "hrq-runtime",
    root = only,
    max_human_requests = 2,
    human_requests = [
        human_request(
            "HR-runtime",
            stage = "only",
            priority = "high",
            question = "Should runtime evidence carry this request?",
            default_assumption = "Carry it as nonblocking evidence.",
            context = "Operator can answer through later steering.",
        ),
    ],
)
"#,
        "hrq_runtime.star",
        &[],
    )
    .expect("workflow parses");

    let id = executor
        .submit_execution_program(compile_checked_definition(checked))
        .expect("checked submit succeeds");
    let rec = wait_terminal(&executor, &id).await;

    assert_eq!(rec.status, ExecutionStatus::Completed);
    assert_eq!(rec.evidence.human_requests.len(), 1);
    let request = &rec.evidence.human_requests[0];
    assert_eq!(request.id, "HR-runtime");
    assert_eq!(request.stage.as_deref(), Some("only"));
    assert_eq!(request.priority, "high");
    assert!(!request.blocking);
    assert_eq!(request.status, "default_assumption_active");
    assert_eq!(
        request.default_assumption,
        "Carry it as nonblocking evidence."
    );
    assert!(
        request
            .projection
            .contains("HR-runtime [only]: Should runtime evidence carry this request?")
    );
}

#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn human_request_answer_exact_id_updates_execution_evidence() {
    let stack = boot_executor();
    let executor = Arc::clone(&stack.executor);
    let def = parse_inline_starlark_checked(
        r#"
only = stage(id = "only", prompt = "hi", agent = "default")
workflow(
    "hrq-answer-runtime",
    root = only,
    max_human_requests = 1,
    human_requests = [
        human_request(
            "HR-answer-runtime",
            stage = "only",
            priority = "medium",
            question = "Which production path should answer this?",
            default_assumption = "Use the default path until answered.",
        ),
    ],
)
"#,
        "hrq_answer_runtime.star",
        &[],
    )
    .expect("workflow parses");

    let id = executor
        .submit_execution_program(compile_checked_definition(def))
        .expect("submit succeeds");
    let rec = wait_terminal(&executor, &id).await;
    assert_eq!(
        rec.evidence.human_requests[0].status,
        "default_assumption_active"
    );

    let execution_id = Ulid::from_string(&id).unwrap();
    let answered = executor
        .answer_human_request(
            execution_id,
            ExecutionHumanRequestAnswerRequest {
                request_id: "HR-answer-runtime".to_string(),
                answer_summary: "Use the narrow REST and client answer path.".to_string(),
                answered_by_steering_id: Some(42),
            },
            Some(&kata_types::approval::ApprovalPrincipal::UnauthenticatedLoopback),
        )
        .expect("exact id answer persists");
    assert_eq!(answered.status, "answered");
    assert_eq!(answered.human_request.id, "HR-answer-runtime");
    assert_eq!(answered.human_request.status, "answered");
    assert_eq!(
        answered.human_request.answer_summary.as_deref(),
        Some("Use the narrow REST and client answer path.")
    );
    assert_eq!(answered.human_request.answered_by_steering_id, Some(42));
    assert!(answered.human_request.answered_at_ms.is_some());

    let rec = executor
        .get_execution(&id)
        .expect("execution remains visible");
    assert_eq!(rec.evidence.human_requests.len(), 1);
    let request = &rec.evidence.human_requests[0];
    assert_eq!(request.status, "answered");
    assert_eq!(request.answered_by_steering_id, Some(42));
    assert!(
        request
            .projection
            .contains("Answer: Use the narrow REST and client answer path.")
    );
}

#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn blocking_human_request_parks_then_resumes_on_answer() {
    // End-to-end: a blocking human-request parks its target
    // stage durably (AwaitingApproval), and answering it resumes the stage so it
    // completes with the operator answer rendered into the prompt.
    let stack = boot_executor();
    let executor = Arc::clone(&stack.executor);
    let def = parse_inline_starlark_checked(
        r#"
only = stage(id = "only", prompt = "Chosen: {{ human_requests.items[0].effective_answer }} ({{ human_requests.items[0].answer_source }})", agent = "default")
workflow(
    "blocking-park-resume",
    root = only,
    max_human_requests = 1,
    human_requests = [
        human_request(
            "HR-block",
            stage = "only",
            priority = "high",
            question = "Ship v1 or v2?",
            default_assumption = "v1",
            blocking = True,
        ),
    ],
)
"#,
        "blocking_park_resume.star",
        &[],
    )
    .expect("workflow parses");

    let id = executor
        .submit_execution_program(compile_checked_definition(def))
        .expect("submit succeeds");
    let execution_id = Ulid::from_string(&id).unwrap();

    // 1. Park: the blocking request parks its input wait on the authority chain
    //    and holds the stage in the orchestrator — no capsule attempt is claimed
    //    or dispatched while the request is unanswered.
    wait_input_await_park(&stack, execution_id, "only").await;
    let parked_record = executor.get_execution(&id).expect("execution visible");
    let request = parked_record
        .evidence
        .human_requests
        .iter()
        .find(|request| request.id == "HR-block")
        .expect("the parked request's evidence row");
    assert_eq!(
        request.status, "awaiting_input",
        "the record must show the request parked on its input wait"
    );
    assert!(
        stack
            .dispatcher
            .execution_stage_states(execution_id)
            .expect("read stage states")
            .iter()
            .all(|state| state.stage_name.as_str() != "only"),
        "no attempt may exist for the held stage while its input wait is parked"
    );
    // The execution as a whole is still Running while parked.
    assert_eq!(parked_record.status, ExecutionStatus::Running);

    // 2. Answer → resume. The answer must un-park the stage and re-dispatch it.
    let answered = executor
        .answer_human_request(
            execution_id,
            ExecutionHumanRequestAnswerRequest {
                request_id: "HR-block".to_string(),
                answer_summary: "v2".to_string(),
                answered_by_steering_id: Some(7),
            },
            Some(&kata_types::approval::ApprovalPrincipal::UnauthenticatedLoopback),
        )
        .expect("answering the blocking request resumes the stage");
    assert_eq!(answered.status, "answered");
    assert!(answered.human_request.blocking);

    // 3. Completion with the answer in the resumed prompt.
    let rec = wait_terminal(&executor, &id).await;
    assert_eq!(rec.status, ExecutionStatus::Completed, "rec: {rec:?}");
    assert_eq!(
        stack.mock.delivered_prompt("only").as_deref(),
        Some("Chosen: v2 (operator)"),
        "resumed prompt must render the operator answer, not the default"
    );
}

#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn blocking_answer_after_terminalization_is_refused_without_write() {
    let stack = boot_executor();
    let executor = Arc::clone(&stack.executor);
    let definition = parse_inline_starlark_checked(
        r#"
only = stage(id = "only", prompt = "Chosen: {{ human_requests.items[0].effective_answer }}", agent = "default")
workflow(
    "blocking-terminal-refusal",
    root = only,
    max_human_requests = 1,
    human_requests = [
        human_request(
            "HR-terminal",
            stage = "only",
            priority = "high",
            question = "Continue?",
            default_assumption = "no",
            blocking = True,
        ),
    ],
)
"#,
        "blocking_terminal_refusal.star",
        &[],
    )
    .expect("workflow parses");
    let id = executor
        .submit_execution_program(compile_checked_definition(definition))
        .expect("submit succeeds");
    let execution_id = Ulid::from_string(&id).expect("execution id");
    wait_input_await_park(&stack, execution_id, "only").await;
    executor
        .execution_lifecycle()
        .mark_terminal(execution_id, ExecutionLifecycleState::Failed)
        .expect("terminalize workflow while stale input gate remains");

    let error = executor
        .answer_human_request(
            execution_id,
            ExecutionHumanRequestAnswerRequest {
                request_id: "HR-terminal".to_string(),
                answer_summary: "yes".to_string(),
                answered_by_steering_id: Some(9),
            },
            Some(&kata_types::approval::ApprovalPrincipal::UnauthenticatedLoopback),
        )
        .expect_err("a wait on a terminal execution must refuse the answer outright");
    // Under `oci` the input-wait answer door refuses post-terminal
    // (`main_resolution_execution_terminal`): the answer is the wait's accepted
    // outcome, and no outcome lands after the execution's own is published —
    // nothing is written, which is STRONGER than record-but-do-not-redispatch:
    // there is no evidence to misread.
    assert!(
        matches!(&error, ExecutorError::InputRequestConflict(message)
            if message.contains("main_resolution_execution_terminal")),
        "{error:?}"
    );
    let record = executor
        .get_execution(&id)
        .expect("execution evidence remains visible");
    let request = record
        .evidence
        .human_requests
        .iter()
        .find(|request| request.id == "HR-terminal")
        .expect("human request evidence");
    assert_eq!(
        request.answer_summary.as_deref(),
        None,
        "a refused answer writes no accepted outcome"
    );
    // Terminalizing the execution resolves the parked wait with it — an
    // `AwaitingInput` row on a terminal execution is exactly the wedged shape
    // the resolution exists to prevent — so what the refused answer must not
    // have done is DISPATCH the wait's stage. The scripted worker's delivered
    // log is the independent record of that.
    assert!(
        stack
            .mock
            .delivered()
            .iter()
            .all(|(stage, _)| stage != "only"),
        "a terminalized execution's parked input wait must not be dispatched by the refused answer"
    );
}

// ── Blocking input-await self-heal on timeout ───────────────────────────────

/// Helper: poll the authority chain until the blocking request targeting
/// `stage` has parked its input wait — under `oci` the durable park is the
/// main-executor wait attempt in `AwaitingInput`.
async fn wait_input_await_park(stack: &ExecutorStack, execution_id: Ulid, stage: &str) {
    for _ in 0..200 {
        if stack
            .db
            .parked_main_waits(kata_core::operational::ParkedMainWaitScope::Execution(
                execution_id,
            ))
            .expect("read parked main waits")
            .iter()
            .any(|wait| wait.state == kata_core::operational::AttemptLifecycle::AwaitingInput)
        {
            return;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    panic!("{stage} never parked an input wait on the authority chain");
}

/// (a) A blocking request with NO `timeout_ms` is block-until-
/// answered. Even after the sweep runs, the stage stays parked forever — the
/// self-heal must never fire without a declared deadline.
#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn input_await_no_timeout_never_self_heals() {
    let stack = boot_executor();
    let executor = Arc::clone(&stack.executor);
    let def = parse_inline_starlark_checked(
        r#"
only = stage(id = "only", prompt = "Chosen: {{ human_requests.items[0].effective_answer }} ({{ human_requests.items[0].answer_source }})", agent = "default")
workflow(
    "input-await-no-timeout",
    root = only,
    max_human_requests = 1,
    human_requests = [
        human_request(
            "HR-block",
            stage = "only",
            priority = "high",
            question = "Ship v1 or v2?",
            default_assumption = "v1",
            blocking = True,
        ),
    ],
)
"#,
        "input_await_no_timeout.star",
        &[],
    )
    .expect("workflow parses");

    let id = executor
        .submit_execution_program(compile_checked_definition(def))
        .expect("submit succeeds");
    let execution_id = Ulid::from_string(&id).unwrap();
    wait_input_await_park(&stack, execution_id, "only").await;

    // Drive the sweep directly — repeatedly. A no-timeout park has no deadline,
    // so every pass must be a no-op.
    let now = i64::try_from(kata_types::time::now_ms()).expect("the clock fits");
    for _ in 0..5 {
        let healed = stack
            .dispatcher
            .sweep_due_waits(now)
            .expect("due-wait sweep");
        assert!(healed.is_empty(), "no-timeout park must never self-heal");
    }
    // The wait is still parked; the execution is still Running, not completed.
    assert!(
        stack
            .db
            .parked_main_waits(kata_core::operational::ParkedMainWaitScope::Execution(
                execution_id,
            ))
            .expect("read parked main waits")
            .iter()
            .any(|wait| { wait.state == kata_core::operational::AttemptLifecycle::AwaitingInput }),
        "the input wait must remain parked when no timeout was declared"
    );
    assert_eq!(
        executor.get_execution(&id).expect("visible").status,
        ExecutionStatus::Running
    );
}

/// (b) A short-`timeout_ms` parked stage that is never answered self-heals: once
/// the durable deadline (`awaiting_approval_at_ms + timeout_ms`) is in the past,
/// the due-wait sweep resumes it with `default_assumption` and it
/// completes — with the prompt rendering `timeout_default` provenance.
#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn input_await_timeout_self_heals_with_default_assumption() {
    let stack = boot_executor();
    let executor = Arc::clone(&stack.executor);
    let def = parse_inline_starlark_checked(
        r#"
only = stage(id = "only", prompt = "Chosen: {{ human_requests.items[0].effective_answer }} ({{ human_requests.items[0].answer_source }})", agent = "default")
workflow(
    "input-await-timeout-heal",
    root = only,
    max_human_requests = 1,
    human_requests = [
        human_request(
            "HR-block",
            stage = "only",
            priority = "high",
            question = "Ship v1 or v2?",
            default_assumption = "v1",
            blocking = True,
            timeout_ms = 20,
        ),
    ],
)
"#,
        "input_await_timeout_heal.star",
        &[],
    )
    .expect("workflow parses");

    let id = executor
        .submit_execution_program(compile_checked_definition(def))
        .expect("submit succeeds");
    let execution_id = Ulid::from_string(&id).unwrap();
    wait_input_await_park(&stack, execution_id, "only").await;

    // Cross the 20ms deadline (sub-second; no multi-second real sleep) then drive
    // the `oci` self-heal directly — `Dispatcher::sweep_due_waits`, the due-wait
    // leg of the deadline sweep. The parked wait carries its durable
    // `wait_deadline_ms`; the first pass at or past it accepts the request's
    // `default_assumption` tagged `timeout_default`. The rig runs no
    // deadline-sweep ticker, so this call is the pass under observation.
    tokio::time::sleep(Duration::from_millis(60)).await;
    let now = i64::try_from(kata_types::time::now_ms()).expect("the clock fits");
    let healed = stack
        .dispatcher
        .sweep_due_waits(now)
        .expect("due-wait sweep reads the plane");
    assert_eq!(healed.len(), 1, "expired park must self-heal exactly once");

    let rec = wait_terminal(&executor, &id).await;
    assert_eq!(rec.status, ExecutionStatus::Completed, "rec: {rec:?}");
    assert_eq!(
        stack.mock.delivered_prompt("only").as_deref(),
        Some("Chosen: v1 (timeout_default)"),
        "resumed prompt must render default_assumption tagged timeout_default"
    );
    // Audit trail: the request evidence is marked auto_defaulted with no operator.
    let answered = rec
        .evidence
        .human_requests
        .iter()
        .find(|r| r.id == "HR-block")
        .expect("request evidence present");
    assert!(answered.auto_defaulted, "self-heal must tag auto_defaulted");
    assert!(
        answered.answered_by_steering_id.is_none(),
        "self-heal has no operator steering id"
    );
    assert_eq!(answered.answer_summary.as_deref(), Some("v1"));
}

/// (c) Idempotency / answer-wins: a real operator answer BEFORE the deadline
/// un-parks the stage; a later sweep then finds nothing parked and no-ops — the
/// operator answer is never overwritten by the timeout default.
#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn input_await_real_answer_wins_sweep_is_noop() {
    let stack = boot_executor();
    let executor = Arc::clone(&stack.executor);
    let def = parse_inline_starlark_checked(
        r#"
only = stage(id = "only", prompt = "Chosen: {{ human_requests.items[0].effective_answer }} ({{ human_requests.items[0].answer_source }})", agent = "default")
workflow(
    "input-await-answer-wins",
    root = only,
    max_human_requests = 1,
    human_requests = [
        human_request(
            "HR-block",
            stage = "only",
            priority = "high",
            question = "Ship v1 or v2?",
            default_assumption = "v1",
            blocking = True,
            timeout_ms = 20,
        ),
    ],
)
"#,
        "input_await_answer_wins.star",
        &[],
    )
    .expect("workflow parses");

    let id = executor
        .submit_execution_program(compile_checked_definition(def))
        .expect("submit succeeds");
    let execution_id = Ulid::from_string(&id).unwrap();
    wait_input_await_park(&stack, execution_id, "only").await;

    // Operator answers and the stage resumes BEFORE any sweep.
    executor
        .answer_human_request(
            execution_id,
            ExecutionHumanRequestAnswerRequest {
                request_id: "HR-block".to_string(),
                answer_summary: "v2".to_string(),
                answered_by_steering_id: Some(7),
            },
            Some(&kata_types::approval::ApprovalPrincipal::UnauthenticatedLoopback),
        )
        .expect("operator answer resumes the stage");
    let rec = wait_terminal(&executor, &id).await;
    assert_eq!(rec.status, ExecutionStatus::Completed);

    // Now run the sweep well past the original deadline. It must be a no-op: the
    // stage is no longer parked, and the evidence already carries the operator
    // answer — never the timeout default.
    tokio::time::sleep(Duration::from_millis(40)).await;
    let now = i64::try_from(kata_types::time::now_ms()).expect("the clock fits") + 700_000;
    let healed = stack
        .dispatcher
        .sweep_due_waits(now)
        .expect("due-wait sweep");
    assert!(
        healed.is_empty(),
        "answer-first must leave the sweep nothing to do"
    );

    assert_eq!(
        stack.mock.delivered_prompt("only").as_deref(),
        Some("Chosen: v2 (operator)"),
        "operator answer must win; never overwritten by the timeout default"
    );
    let answered = executor
        .get_execution(&id)
        .expect("visible")
        .evidence
        .human_requests
        .into_iter()
        .find(|r| r.id == "HR-block")
        .expect("request evidence present");
    assert!(
        !answered.auto_defaulted,
        "operator answer must NOT be tagged auto_defaulted"
    );
    assert_eq!(answered.answered_by_steering_id, Some(7));
}

/// Discriminator soundness: a stage
/// that is BOTH `approval = true` AND the target of a `blocking + timeout_ms`
/// request, whose `approval_reason` happens to start with the input-await park
/// prefix, parks as a REAL operator approval gate. The timeout sweep must NOT
/// mis-classify it via the (spoofable) reason string and auto-approve it — the
/// `!approval_required` checked-program guard keeps it parked until an operator
/// acts.
#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn input_await_timeout_never_auto_approves_a_real_approval_gate() {
    let stack = boot_executor();
    let executor = Arc::clone(&stack.executor);
    let def = parse_inline_starlark_checked(
        r#"
gated = stage(
    id = "gated",
    prompt = "Chosen: {{ human_requests.items[0].effective_answer }}",
    approval = True,
    approval_reason = "awaiting input: operator must confirm", agent = "default")
workflow(
    "approval-collision-no-self-heal",
    root = gated,
    max_human_requests = 1,
    human_requests = [
        human_request(
            "HR-block",
            stage = "gated",
            priority = "high",
            question = "Ship?",
            default_assumption = "v1",
            blocking = True,
            timeout_ms = 20,
        ),
    ],
)
"#,
        "approval_collision_no_self_heal.star",
        &[],
    )
    .expect("workflow parses");

    let id = executor
        .submit_execution_program(compile_checked_definition(def))
        .expect("submit succeeds");
    let execution_id = Ulid::from_string(&id).unwrap();
    // Under `oci` the blocking request parks FIRST — a main-executor input wait
    // (`#op/1`, `AwaitingInput`), before the stage's dispatch decision is even
    // reached. Answering it lets the runner reach the approval-gated dispatch,
    // which parks a CAPSULE gate carrying the operator's "awaiting input: ..."
    // `approval_reason` — the string that collides with the input-await prefix.
    wait_input_await_park(&stack, execution_id, "gated").await;
    executor
        .answer_human_request(
            execution_id,
            ExecutionHumanRequestAnswerRequest {
                request_id: "HR-block".to_string(),
                answer_summary: "v1".to_string(),
                answered_by_steering_id: Some(3),
            },
            Some(&kata_types::approval::ApprovalPrincipal::UnauthenticatedLoopback),
        )
        .expect("answering the blocking request releases the stage to its approval gate");
    let capsule_gate_parked = |stack: &ExecutorStack, execution_id: Ulid| {
        stack
            .dispatcher
            .parked_approval_gates()
            .expect("list parked approval gates")
            .iter()
            .any(|gate| {
                gate.execution_id == execution_id
                    && gate.stage_name.as_str() == "gated"
                    && gate.capsule.is_some()
            })
    };
    // Generous on purpose, on the shared ≥30 s poll contract (`common::wait_terminal`):
    // a hang-catcher, not a latency property.
    for _ in 0..common::TERMINAL_POLL_ATTEMPTS {
        if capsule_gate_parked(&stack, execution_id) {
            break;
        }
        tokio::time::sleep(common::TERMINAL_POLL_INTERVAL).await;
    }
    assert!(
        capsule_gate_parked(&stack, execution_id),
        "gated stage never parked a capsule approval gate"
    );

    // Cross the 20ms deadline, then drive the sweep. The `!approval_required`
    // guard must skip this real approval gate despite the colliding reason.
    tokio::time::sleep(Duration::from_millis(60)).await;
    let now = i64::try_from(kata_types::time::now_ms()).expect("the clock fits") + 700_000;
    let healed = stack
        .dispatcher
        .sweep_due_waits(now)
        .expect("due-wait sweep");
    assert!(
        healed.is_empty(),
        "a real approval gate must never be auto-approved by the input-await timeout sweep"
    );

    // It stays durably parked — an operator must still act.
    assert!(
        capsule_gate_parked(&stack, execution_id),
        "approval gate must remain parked"
    );
}

/// Declaration validation: `timeout_ms` is only meaningful on a blocking
/// request, and must be positive. The parser rejects the inert / nonsensical
/// combinations at compile time.
#[test]
fn timeout_ms_without_blocking_is_rejected() {
    let err = parse_inline_starlark_checked(
        r#"
only = stage(id = "only", prompt = "hi", agent = "default")
workflow(
    "bad-timeout-nonblocking",
    root = only,
    max_human_requests = 1,
    human_requests = [
        human_request(
            "HR-adv",
            priority = "low",
            question = "advisory?",
            default_assumption = "keep default",
            timeout_ms = 1000,
        ),
    ],
)
"#,
        "bad_timeout_nonblocking.star",
        &[],
    )
    .expect_err("timeout_ms without blocking must be rejected");
    assert!(
        format!("{err:?}").contains("timeout_ms is only meaningful with blocking"),
        "unexpected error: {err:?}"
    );
}

#[test]
fn timeout_ms_zero_is_rejected() {
    let err = parse_inline_starlark_checked(
        r#"
only = stage(id = "only", prompt = "hi", agent = "default")
workflow(
    "bad-timeout-zero",
    root = only,
    max_human_requests = 1,
    human_requests = [
        human_request(
            "HR-block",
            stage = "only",
            priority = "high",
            question = "ship?",
            default_assumption = "v1",
            blocking = True,
            timeout_ms = 0,
        ),
    ],
)
"#,
        "bad_timeout_zero.star",
        &[],
    )
    .expect_err("timeout_ms=0 must be rejected");
    // The Starlark human_request() builtin rejects a non-positive timeout with
    // "timeout_ms= must be > 0 ...; got 0" (the removed TOML frontend spelled the
    // same rejection "timeout_ms=0").
    assert!(
        format!("{err:?}").contains("must be > 0"),
        "unexpected error: {err:?}"
    );
}

#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn human_request_answer_unknown_id_is_noop() {
    let stack = boot_executor();
    let executor = Arc::clone(&stack.executor);
    let def = parse_inline_starlark_checked(
        r#"
only = stage(id = "only", prompt = "hi", agent = "default")
workflow(
    "hrq-answer-noop",
    root = only,
    max_human_requests = 1,
    human_requests = [
        human_request(
            "HR-known",
            priority = "low",
            question = "Should this remain unanswered?",
            default_assumption = "Keep default.",
        ),
    ],
)
"#,
        "hrq_answer_noop.star",
        &[],
    )
    .expect("workflow parses");

    let id = executor
        .submit_execution_program(compile_checked_definition(def))
        .expect("submit succeeds");
    let _ = wait_terminal(&executor, &id).await;
    let execution_id = Ulid::from_string(&id).unwrap();
    let err = executor
        .answer_human_request(
            execution_id,
            ExecutionHumanRequestAnswerRequest {
                request_id: "HR-missing".to_string(),
                answer_summary: "Should not attach.".to_string(),
                answered_by_steering_id: Some(77),
            },
            Some(&kata_types::approval::ApprovalPrincipal::UnauthenticatedLoopback),
        )
        .expect_err("unknown request id must fail");
    assert!(matches!(err, ExecutorError::HumanRequestNotFound { .. }));

    let rec = executor
        .get_execution(&id)
        .expect("execution remains visible");
    assert_eq!(rec.evidence.human_requests.len(), 1);
    let request = &rec.evidence.human_requests[0];
    assert_eq!(request.id, "HR-known");
    assert_eq!(request.status, "default_assumption_active");
    assert!(request.answer_summary.is_none());
}

#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn append_external_input_updates_execution_evidence() {
    let stack = boot_executor();
    let executor = Arc::clone(&stack.executor);
    let def = parse_inline_starlark_checked(
        r#"
only = stage(id = "only", prompt = "hi", agent = "default")
workflow(
    "external-input-runtime",
    root = only,
    max_external_input_channels = 1,
    external_input_channels = [
        channel(
            "operator_steering",
            stage = "only",
            expose_as = "steering",
            max_items = 2,
        ),
    ],
)
"#,
        "external_input_runtime.star",
        &[],
    )
    .expect("workflow parses");

    let id = executor
        .submit_execution_program(compile_checked_definition(def))
        .expect("submit succeeds");
    let rec = wait_terminal(&executor, &id).await;
    assert_eq!(rec.status, ExecutionStatus::Completed);
    assert!(rec.evidence.external_inputs.is_empty());

    let execution_id = Ulid::from_string(&id).unwrap();
    let appended = executor
        .append_external_input(
            execution_id,
            ExecutionExternalInputAppendRequest {
                channel: "operator_steering".to_string(),
                text: "Prefer the narrow implementation path.".to_string(),
                input_id: Some("ei-runtime".to_string()),
                source: Some("sidecar".to_string()),
                target_stage: None,
                payload: Some(serde_json::json!({"priority": "high"})),
            },
        )
        .expect("declared channel append persists");
    assert_eq!(appended.status, "appended");
    assert_eq!(appended.external_input.id, "ei-runtime");
    assert_eq!(appended.external_input.channel, "operator_steering");
    assert_eq!(appended.external_input.source.as_deref(), Some("sidecar"));
    assert_eq!(
        appended.external_input.target_stage.as_deref(),
        Some("only")
    );
    assert_eq!(
        appended.external_input.payload.as_ref().unwrap()["priority"],
        "high"
    );

    let rec = executor
        .get_execution(&id)
        .expect("execution remains visible");
    assert_eq!(rec.evidence.external_inputs.len(), 1);
    assert_eq!(rec.evidence.external_inputs[0].id, "ei-runtime");
    assert_eq!(
        rec.evidence.external_inputs[0].projection,
        "operator_steering: Prefer the narrow implementation path."
    );

    let retry = executor
        .append_external_input(
            execution_id,
            ExecutionExternalInputAppendRequest {
                channel: "operator_steering".to_string(),
                text: "Prefer the narrow implementation path.".to_string(),
                input_id: Some("ei-runtime".to_string()),
                source: Some("sidecar".to_string()),
                target_stage: None,
                payload: Some(serde_json::json!({"priority": "high"})),
            },
        )
        .expect("same explicit input id and content is idempotent");
    assert_eq!(retry.status, "already_appended");
    assert_eq!(retry.external_input, appended.external_input);

    let conflict = executor
        .append_external_input(
            execution_id,
            ExecutionExternalInputAppendRequest {
                channel: "operator_steering".to_string(),
                text: "Switch to a different implementation path.".to_string(),
                input_id: Some("ei-runtime".to_string()),
                source: Some("sidecar".to_string()),
                target_stage: None,
                payload: Some(serde_json::json!({"priority": "high"})),
            },
        )
        .expect_err("same explicit input id with different content must fail closed");
    assert!(
        matches!(&conflict, ExecutorError::PolicyDenied(message)
            if message.contains("already appended with different content")),
        "unexpected error: {conflict:?}"
    );

    let rec = executor
        .get_execution(&id)
        .expect("execution remains visible after duplicate attempts");
    assert_eq!(rec.evidence.external_inputs.len(), 1);
    assert_eq!(rec.evidence.external_inputs[0], appended.external_input);
}

#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn append_external_input_rejects_over_limit_text_without_mutation() {
    let stack = boot_executor();
    let executor = Arc::clone(&stack.executor);
    let def = parse_inline_starlark_checked(
        r#"
only = stage(id = "only", prompt = "hi", agent = "default")
workflow(
    "external-input-over-limit",
    root = only,
    max_external_input_channels = 1,
    external_input_channels = [
        channel("operator_steering", max_items = 1),
    ],
)
"#,
        "external_input_over_limit.star",
        &[],
    )
    .expect("workflow parses");

    let id = executor
        .submit_execution_program(compile_checked_definition(def))
        .expect("submit succeeds");
    let rec = wait_terminal(&executor, &id).await;
    assert_eq!(rec.status, ExecutionStatus::Completed);

    let execution_id = Ulid::from_string(&id).unwrap();
    let err = executor
        .append_external_input(
            execution_id,
            ExecutionExternalInputAppendRequest {
                channel: "operator_steering".to_string(),
                text: "x".repeat(EXTERNAL_INPUT_TEXT_MAX_CHARS + 1),
                input_id: None,
                source: None,
                target_stage: None,
                payload: None,
            },
        )
        .expect_err("over-limit external input text must fail");
    let ExecutorError::InvalidDefinition(message) = err else {
        panic!("expected invalid definition, got {err:?}");
    };
    assert!(message.contains("external input text exceeds"), "{message}");

    let rec = executor
        .get_execution(&id)
        .expect("execution remains visible");
    assert!(rec.evidence.external_inputs.is_empty());
}

#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn submit_with_initial_external_inputs_persists_before_runner_progress() {
    let stack = boot_executor();
    let executor = Arc::clone(&stack.executor);
    let def = parse_inline_starlark_checked(
        r#"
only = stage(id = "only", prompt = "controller context count: {{ external_inputs.controller.count }}", agent = "default")
workflow(
    "external-input-initial",
    root = only,
    max_external_input_channels = 1,
    external_input_channels = [
        channel(
            "controller_decision",
            stage = "only",
            expose_as = "controller",
            max_items = 2,
        ),
    ],
)
"#,
        "external_input_initial.star",
        &[],
    )
    .expect("workflow parses");

    let id = executor
        .submit_execution_program_with_initial_external_inputs(
            compile_checked_definition(def),
            vec![ExecutionExternalInputAppendRequest {
                channel: "controller_decision".to_string(),
                text: "Previous wave requested repair with validation evidence.".to_string(),
                input_id: Some("initial-controller-context".to_string()),
                source: Some("factory_controller".to_string()),
                target_stage: None,
                payload: Some(serde_json::json!({"decision": "repair"})),
            }],
        )
        .expect("submit with initial external input succeeds");
    let pre_terminal = executor
        .get_execution(&id)
        .expect("execution evidence visible immediately after submit");
    assert_eq!(pre_terminal.evidence.external_inputs.len(), 1);
    assert_eq!(
        pre_terminal.evidence.external_inputs[0].id,
        "initial-controller-context"
    );

    let rec = wait_terminal(&executor, &id).await;
    assert_eq!(rec.status, ExecutionStatus::Completed);
    assert_eq!(rec.evidence.external_inputs.len(), 1);
    let input = &rec.evidence.external_inputs[0];
    assert_eq!(input.channel, "controller_decision");
    assert_eq!(input.target_stage.as_deref(), Some("only"));
    assert_eq!(input.source.as_deref(), Some("factory_controller"));
    assert_eq!(
        input.payload.as_ref().expect("payload")["decision"],
        "repair"
    );
}

#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn submit_with_initial_external_inputs_rejects_over_limit_text() {
    let stack = boot_executor();
    let executor = Arc::clone(&stack.executor);
    let def = parse_inline_starlark_checked(
        r#"
only = stage(id = "only", prompt = "hi", agent = "default")
workflow(
    "external-input-initial-over-limit",
    root = only,
    max_external_input_channels = 1,
    external_input_channels = [
        channel(
            "controller_decision",
            stage = "only",
            expose_as = "controller",
            max_items = 1,
        ),
    ],
)
"#,
        "external_input_initial_over_limit.star",
        &[],
    )
    .expect("workflow parses");

    let err = executor
        .submit_execution_program_with_initial_external_inputs(
            compile_checked_definition(def),
            vec![ExecutionExternalInputAppendRequest {
                channel: "controller_decision".to_string(),
                text: "x".repeat(EXTERNAL_INPUT_TEXT_MAX_CHARS + 1),
                input_id: None,
                source: None,
                target_stage: None,
                payload: None,
            }],
        )
        .expect_err("over-limit initial external input text must fail");
    let ExecutorError::InvalidDefinition(message) = err else {
        panic!("expected invalid definition, got {err:?}");
    };
    assert!(message.contains("external input text exceeds"), "{message}");
}

#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn append_external_input_unknown_channel_is_not_found_without_mutation() {
    let stack = boot_executor();
    let executor = Arc::clone(&stack.executor);
    let def = parse_inline_starlark_checked(
        r#"
only = stage(id = "only", prompt = "hi", agent = "default")
workflow(
    "external-input-unknown",
    root = only,
    max_external_input_channels = 1,
    external_input_channels = [
        channel("operator_steering", max_items = 1),
    ],
)
"#,
        "external_input_unknown.star",
        &[],
    )
    .expect("workflow parses");

    let id = executor
        .submit_execution_program(compile_checked_definition(def))
        .expect("submit succeeds");
    let _ = wait_terminal(&executor, &id).await;
    let execution_id = Ulid::from_string(&id).unwrap();
    let err = executor
        .append_external_input(
            execution_id,
            ExecutionExternalInputAppendRequest {
                channel: "missing".to_string(),
                text: "Should not attach.".to_string(),
                input_id: None,
                source: None,
                target_stage: None,
                payload: None,
            },
        )
        .expect_err("unknown external channel must fail");
    assert!(matches!(
        err,
        ExecutorError::ExternalInputChannelNotFound { .. }
    ));

    let rec = executor
        .get_execution(&id)
        .expect("execution remains visible");
    assert!(rec.evidence.external_inputs.is_empty());
}

// ---------------------------------------------------------------------------
// The WALK-AWAY as an operator reads it.
//
// `time_bound` / `cost_bound` / `cost_budget("halt", ..)` are kata's headline
// unattended guarantee — *don't run forever, don't spend forever*. A guard that
// FIRES (the durable `#bound-halt-time` row is written, the downstream stage is
// never dispatched) must reach the operator as a failure, never as
// `"status":"completed"`, `"error":null`, `"warnings":[]`, exit code 0.
//
// A runner-level test that asserts on the dispatcher's rows after
// `runner.run()` cannot see that. These assert on the `ExecutionRecord` the API
// returns — through `try_get_execution_by_ulid`, INCLUDING its unconditional
// reassignment of `record.status` from the operational lifecycle, which is
// where the truth would be lost.
// ---------------------------------------------------------------------------

/// A two-stage workflow (`draft` → `review`) carrying one workflow-scope bound.
fn bounded_two_stage_definition(
    name: &str,
    bound: kata_types::bound::Bound,
) -> kata_types::workflow::WorkflowDefinition {
    let mut definition = kata_test_utils::simple_two_stage_workflow();
    definition.name = SmolStr::new(name);
    // `oci` has no unbound-selector form — the shared fixture's `Any` stages
    // rebind to the rig's declared `default` label.
    for stage in definition.stages.values_mut() {
        stage.agent = AgentSelector::Labelled(SmolStr::new("default"));
    }
    definition.bounds = vec![bound];
    definition
}

#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn time_bound_walk_away_is_visible_on_the_execution_record() {
    // COUNTERFACTUAL: revert `failures.extend(self.collect_durable_walkaway_halts()?)`
    // in `WorkflowRunner::finalize_run` and every assertion below fails —
    // `run()` returns `Ok`, `run_submitted_workflow_task` latches the lifecycle
    // `Completed`, and `try_get_execution_by_ulid` overwrites the `Failed` that
    // `aggregate_status` had already derived from the halt row.
    let stack = boot_executor();
    let executor = Arc::clone(&stack.executor);

    // 1ms total-lifetime bound: the dispatch→complete round-trip through the
    // embedded worker is far longer, so the first completion trips it
    // deterministically without any sleep.
    let id = executor
        .submit_execution_program(compile_definition(bounded_two_stage_definition(
            "walkaway-time",
            kata_types::bound::Bound::Time { ms: 1 },
        )))
        .expect("submit should succeed with a live worker");

    let rec = wait_terminal(&executor, &id).await;

    assert_eq!(
        rec.status,
        ExecutionStatus::Failed,
        "a run that walked away from its time bound must NOT read as completed; \
         record was: status={:?} error={:?} warnings={:?}",
        rec.status,
        rec.error,
        rec.warnings
    );
    let error = rec
        .error
        .as_deref()
        .expect("a bound-halted run must carry an operator-readable error");
    assert!(
        error.contains("bound_exceeded"),
        "the error must name the walk-away class, not just say `failed`; got: {error}"
    );
    assert!(
        error.contains("#bound-halt-time"),
        "the error must name WHICH guard stopped the run; got: {error}"
    );

    // The second, independently-derived carrier. `warnings` is projected from the
    // durable rows and no lifecycle arm rewrites it, so the walk-away stays
    // visible even if `status` is ever clobbered again — which is precisely how
    // this defect reached production.
    let warning = rec
        .warnings
        .iter()
        .find(|w| w.starts_with(kata_api::executor::WALKAWAY_HALT_WARNING_PREFIX))
        .unwrap_or_else(|| {
            panic!(
                "the walk-away must be named in `warnings`; got: {:?}",
                rec.warnings
            )
        });
    assert!(
        warning.contains("bound_exceeded") && warning.contains("#bound-halt-time"),
        "the warning must carry the bound reason and the halting row; got: {warning}"
    );
    assert!(
        warning.contains("never dispatched"),
        "nothing else on the record says work was DROPPED — a stage downstream of \
         the halt holds no assignment row, so it is absent from `outputs` and from \
         `agent_invocation_graph` rather than present-and-skipped; got: {warning}"
    );
}

#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn walk_away_downstream_stage_is_absent_not_skipped() {
    // The example workflow's EXPECTED block claimed `after -> Skipped`. It is
    // not: `skip_dependents` is an ORCHESTRATOR transition and mints no ledger
    // row, so the downstream stage has no record entry at all. Pin the real
    // shape so the docs describing it stay honest.
    let stack = boot_executor();
    let executor = Arc::clone(&stack.executor);

    let id = executor
        .submit_execution_program(compile_definition(bounded_two_stage_definition(
            "walkaway-absent",
            kata_types::bound::Bound::Time { ms: 1 },
        )))
        .expect("submit should succeed with a live worker");

    let rec = wait_terminal(&executor, &id).await;
    let execution_id = Ulid::from_string(&id).expect("execution id");
    // The durable census is the attempt rows themselves — `draft` dispatched (the
    // tripping stage), `review` never did, and the `#bound-halt-*` admission is
    // stage-scope metadata, not a dispatch.
    assert_eq!(rec.status, ExecutionStatus::Failed, "rec: {rec:?}");
    let attempts = stack
        .db
        .attempts_for_execution(execution_id)
        .expect("read the attempt census");
    assert!(
        attempts
            .iter()
            .any(|attempt| attempt.row.stage_id == "draft"),
        "the tripping stage must have dispatched; got: {:?}",
        attempts
            .iter()
            .map(|attempt| attempt.row.stage_id.as_str())
            .collect::<Vec<_>>()
    );
    assert!(
        attempts
            .iter()
            .all(|attempt| attempt.row.stage_id != "review"),
        "the skipped downstream stage is never dispatched, so it holds no \
         attempt row; got: {:?}",
        attempts
            .iter()
            .map(|attempt| attempt.row.stage_id.as_str())
            .collect::<Vec<_>>()
    );
    // ... and the synthetic halt row is metadata-only: stage-scope, never a
    // claimed attempt — the record's `error` and `warnings` are therefore the
    // ONLY places the walk-away is legible.
    assert!(
        attempts
            .iter()
            .all(|attempt| !attempt.row.stage_id.contains("#bound-halt-")),
        "a synthetic metadata row must not appear as a claimed attempt"
    );
}

#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn under_limit_bound_still_reads_completed_with_outputs() {
    // The other direction, so the fix cannot be satisfied by failing everything.
    let stack = boot_executor();
    let executor = Arc::clone(&stack.executor);

    let id = executor
        .submit_execution_program(compile_definition(bounded_two_stage_definition(
            "walkaway-under",
            kata_types::bound::Bound::Time { ms: 3_600_000 },
        )))
        .expect("submit should succeed with a live worker");

    let rec = wait_terminal(&executor, &id).await;
    assert_eq!(rec.status, ExecutionStatus::Completed);
    assert!(
        !rec.warnings
            .iter()
            .any(|w| w.starts_with(kata_api::executor::WALKAWAY_HALT_WARNING_PREFIX)),
        "an untripped bound must not warn; got: {:?}",
        rec.warnings
    );
    let outputs = rec.outputs.expect("outputs populated on success");
    assert!(outputs.contains_key("draft") && outputs.contains_key("review"));
}

#[test]
fn parse_inline_starlark_accepts_valid_workflow() {
    let program = parse_inline_starlark_checked(
        r#"
only = stage(id = "only", prompt = "hi", agent = "default")
workflow("inline-star", root = [only])
"#,
        "inline.star",
        &[],
    )
    .expect("valid inline starlark should parse");
    assert_eq!(program.workflow_name.as_str(), "inline-star");
}

#[test]
fn parse_inline_starlark_rejects_invalid() {
    let err = parse_inline_starlark_checked("definitely not valid starlark %%%", "bad.star", &[])
        .unwrap_err();
    assert!(matches!(err, ExecutorError::InvalidDefinition(_)));
}

/// The execution lifecycle row's `(state, terminal_outcome)`, read raw off `path`.
fn raw_lifecycle(path: &std::path::Path, execution: Ulid) -> (String, Option<String>) {
    rusqlite::Connection::open_with_flags(
        path,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .unwrap()
    .query_row(
        "SELECT state, terminal_outcome FROM execution_lifecycle WHERE execution_id = ?1",
        [execution.to_bytes().as_slice()],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )
    .unwrap()
}

/// Poll `execution`'s raw rows, read off `path`, until its closeout settled one
/// way or the other: `Some(last_error)` once a deferred closeout recorded it on
/// the cleanup obligation, `None` once the lifecycle row is terminal.
async fn wait_raw_closeout(path: &std::path::Path, execution: Ulid) -> Option<String> {
    use rusqlite::OptionalExtension as _;
    for _ in 0..TERMINAL_POLL_ATTEMPTS {
        let last_error: Option<String> = rusqlite::Connection::open_with_flags(
            path,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )
        .unwrap()
        .query_row(
            "SELECT last_error FROM execution_cleanup_obligations WHERE execution_id = ?1",
            [execution.to_bytes().as_slice()],
            |row| row.get(0),
        )
        .optional()
        .unwrap()
        .flatten();
        if last_error.is_some() {
            return last_error;
        }
        if !matches!(
            raw_lifecycle(path, execution).0.as_str(),
            "admitting" | "running" | "terminalizing"
        ) {
            return None;
        }
        tokio::time::sleep(TERMINAL_POLL_INTERVAL).await;
    }
    panic!("execution {execution}'s closeout neither deferred nor published");
}

/// An acceptance that admits the execution and then LATCHES its cancel in the window
/// between its admission and its authorization — as an operator cancel of it, or its
/// parent's cancel walk, can.
fn admit_then_latch_cancel(
    face: ExecutionLifecycleFace,
) -> impl Fn(
    Ulid,
    &kata_program::execution_program::ExecutionProgram,
    &ExecutionInvocation,
) -> Result<Acceptance, ExecutorError>
+ Send
+ Sync {
    move |id, program, invocation| {
        face.admit_current_execution(id, program, invocation)
            .map_err(|error| ExecutorError::DurabilityFailed(error.to_string()))?;
        assert!(
            face.db()
                .latch_execution_cancel(id, "operator cancel")
                .map_err(|error| ExecutorError::DurabilityFailed(error.to_string()))?
        );
        Ok(Acceptance::Accepted)
    }
}

/// AN EXECUTION CANCEL-LATCHED BETWEEN ITS ADMISSION AND ITS AUTHORIZATION closes out
/// `cancelled` without running, and is no engine fatal: its authorization is refused (the
/// latch moved it to `terminalizing`), and the submit closes the latched intent out as a
/// restart would instead of reporting a setup failure whose `failed` intent the latch
/// refuses. Read raw.
///
/// **Watched red:** with `close_out_a_cancel_latched_before_running` answering `None`, the
/// execution stays `terminalizing` (the verification review measured the drive guard's
/// fatal on the same mutant: "accepted workflow submit setup ... was dropped before terminal
/// lifecycle publication").
#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn a_cancel_latched_before_authorization_closes_out_cancelled_without_a_fatal() {
    let dir = tempfile::tempdir().unwrap();
    let op_path = dir.path().join("operational.db");
    let face = ExecutionLifecycleFace::open(&op_path).unwrap();
    let stack = boot_executor_with_execution_lifecycle(Some(face.clone()));
    let executor = Arc::clone(&stack.executor);
    let accept = admit_then_latch_cancel(face);
    let id = executor
        .submit_pinned_schedule_execution(
            compile_definition(tiny_definition("latched-before-authorization")),
            serde_json::Map::new(),
            &accept,
        )
        .expect("the accepted execution is the caller's")
        .expect("the acceptance committed");
    let id = Ulid::from_string(&id).unwrap();
    assert_eq!(
        raw_lifecycle(&op_path, id),
        ("cancelled".to_string(), Some("cancelled".to_string()))
    );
    assert_eq!(executor.fatal_reason(), None);
}

/// NIT 4 — A CANCEL LATCHED BEFORE A SUBMIT'S SETUP FAILS closes out `cancelled`, not as a
/// fatal: the execution is cancel-latched between its admission and its authorization AND
/// its admission evidence then fails to persist. The setup failure's `failed` intent is
/// one the latch refuses, so the failed setup closes the latched cancel out instead, as a
/// restart would. Read raw.
///
/// **Watched red:** with the setup-failure path terminalizing `failed` regardless of a
/// latch, the execution stays `terminalizing` and the drive guard reports a fatal.
#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn a_cancel_latched_before_a_failed_submit_setup_closes_out_cancelled_without_a_fatal() {
    let dir = tempfile::tempdir().unwrap();
    let op_path = dir.path().join("operational.db");
    let face = ExecutionLifecycleFace::open(&op_path).unwrap();
    let failing = Arc::new(FailingUnclaimedEvidenceStore::new(true));
    failing.set_fail_claimed_evidence(true);
    let stack = boot_executor_with_custom_ledger(failing.open_ledger(), None, Some(face.clone()));
    let executor = Arc::clone(&stack.executor);
    let accept = admit_then_latch_cancel(face);
    let id = executor
        .submit_pinned_schedule_execution(
            compile_definition(tiny_definition("latched-then-setup-failed")),
            serde_json::Map::new(),
            &accept,
        )
        .expect("the accepted execution is the caller's")
        .expect("the acceptance committed");
    let id = Ulid::from_string(&id).unwrap();
    assert_eq!(executor.fatal_reason(), None);
    assert_eq!(
        raw_lifecycle(&op_path, id),
        ("cancelled".to_string(), Some("cancelled".to_string()))
    );
}
