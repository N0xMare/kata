//! `ExecutionRecord` projection + memory-writeback tests for `kata_api::executor`.
//!
//! Shared boot / mock / build / seed helpers live in `common`.

#![allow(clippy::large_futures)]

mod common;
use common::*;

use std::sync::Arc;

use kata_api::executor::testing::persist_workflow_memory_writebacks;
use kata_api::executor::{
    ExecutionEvidence, ExecutionProgramIdentity, ExecutionRecord, ExecutionStatus,
    execution_record_from_assignments_with_program_and_evidence,
};
use kata_core::InFlightLedger;
use kata_core::operational::{InvocationKind, InvocationRecord, ProgramRecord};
use kata_core::store::{MemoryObjectQuery, SqliteNativeMemoryStore};
use kata_program::execution_program::ExecutionProgram;
use kata_program::library::WorkflowLibrary;
use kata_types::KataResult;
use kata_types::execution::{
    CHECKED_DISPATCH_GUARD_EVIDENCE_SCHEMA_VERSION, CHECKED_DISPATCH_GUARD_ID,
    CHECKED_DISPATCH_POLICY_FIELDS, ExecutionCheckedDispatchGuardEvidence,
    ExecutionCheckedDispatchGuardStatus, ExecutionCheckedDispatchKind,
};
use kata_types::identity_algebra::AdmissionDigest;
use kata_types::memory::{MemoryObjectKind, MemoryObjectStatus, MemoryScope};
use kata_types::primitives::ContentHash;
use smol_str::SmolStr;
use std::time::Duration;
use ulid::Ulid;

/// Project `assignments` with no program identity, no checked program and no
/// typed evidence rows.
fn execution_record_from_assignments(
    execution_id: Ulid,
    workflow_name: String,
    assignments: Vec<kata_workflow::attempt_delivery::ChainAssignmentState>,
) -> ExecutionRecord {
    execution_record_from_assignments_with_program_and_evidence(
        execution_id,
        workflow_name,
        None,
        None,
        assignments,
        Vec::new(),
    )
}

/// A dispatcher whose operational nucleus is ATTACHED.
///
/// # Why the memory-writeback fixtures below need the chain
///
/// `persist_workflow_memory_writebacks` scans COMPLETED stages on the AUTHORITY
/// CHAIN, because that scan decides which declared writebacks apply and
/// whether a `required` one is missing (which fails the run). A fixture that
/// seeded no chain rows would measure nothing at all: the scan returns empty,
/// every writeback silently matches no stage, and the assertions read as green
/// for the wrong reason — a vacuous pass.
///
/// Nothing here reaches past a production gate. Admission is the operational
/// submit door; settlement is `Dispatcher::mark_completed_and_fold_attempt`, the
/// production writer.
struct ChainRig {
    dispatcher: Arc<kata_workflow::dispatcher::Dispatcher>,
    ledger: Arc<InFlightLedger>,
    lifecycle: kata_workflow::execution_lifecycle::ExecutionLifecycleFace,
    cas: kata_core::store::cas::CasStore,
}

impl ChainRig {
    fn new() -> Self {
        Self::with_ledger(InFlightLedger::in_memory())
    }

    fn with_ledger(ledger: Arc<InFlightLedger>) -> Self {
        let supervisor = Arc::new(kata_transport::WorkerPoolSupervisor::new());
        let heartbeat = Arc::new(kata_transport::heartbeat::HeartbeatMonitor::new(
            Duration::from_millis(500),
            Duration::from_millis(500),
        ));
        let lifecycle = kata_workflow::execution_lifecycle::ExecutionLifecycleFace::in_memory()
            .expect("open an in-memory operational nucleus");
        let dispatcher = Arc::new(
            kata_workflow::dispatcher::Dispatcher::new(supervisor, heartbeat, Arc::clone(&ledger))
                .with_execution_lifecycle(lifecycle.clone()),
        );
        let cas_dir = tempfile::tempdir().expect("fixture cas dir").keep();
        let cas =
            kata_core::store::cas::CasStore::open(cas_dir.join("cas.db"), cas_dir.join("cas"))
                .expect("open fixture cas");
        Self {
            dispatcher,
            ledger,
            lifecycle,
            cas,
        }
    }

    /// Admit `execution_id` into the nucleus, as the checked submit door does.
    fn admit(&self, execution_id: Ulid) {
        self.lifecycle
            .db()
            .submit_execution(
                execution_id,
                &ProgramRecord {
                    program_hash: ContentHash::new([11; 32]),
                    schema_version: 4,
                    program_json: b"{}".to_vec(),
                },
                &InvocationRecord {
                    schema_version: 1,
                    kind: InvocationKind::Workflow,
                    admission_digest: AdmissionDigest(ContentHash::new([11; 32])),
                    invocation_json: b"{}".to_vec(),
                },
            )
            .expect("admit the fixture execution into the nucleus");
    }

    /// Settle ONE capsule stage COMPLETED through the production doors
    /// ([`Self::complete_dispatchable_stage`]) — the only class a writeback-
    /// producing stage has under the one engine (no workerless admission
    /// completes).
    ///
    /// The non-vacuity assertion is load-bearing, not decoration: a fixture that
    /// forgot to admit would leave every chain-plane assertion after it
    /// measuring an empty scan.
    fn complete_stage(&self, execution_id: Ulid, stage: &str, output: serde_json::Value) {
        let assignment_id = self.complete_dispatchable_stage(execution_id, stage, output);
        assert!(
            self.dispatcher
                .execution_assignment_states(execution_id)
                .expect("the authority chain answers for the admitted execution")
                .iter()
                .any(|row| row.assignment_id == assignment_id && row.is_completed()),
            "NON-VACUITY: the fixture's completion must be on the AUTHORITY CHAIN, \
             or every writeback assertion below passes because the scan is empty"
        );
    }

    /// A claimed capsule attempt placed, run and COMPLETED.
    ///
    /// The `running` step is not decoration: `completed` is a
    /// `WORKER_ATTRIBUTED_ATTEMPT_STATES` member, so the chain REFUSES a completion
    /// with no placement, and a claim at `pending` genuinely holds no worker. Going
    /// Pending -> Running -> Completed through the three paired production writers
    /// is how a real dispatch reaches a completion; substituting a placement by hand
    /// would be the fabricated attribution `UNATTRIBUTED_WORKER` exists to
    /// keep off this plane.
    fn complete_dispatchable_stage(
        &self,
        execution_id: Ulid,
        stage: &str,
        output: serde_json::Value,
    ) -> Ulid {
        let db = self.lifecycle.db();
        let (assignment_id, frame_json) = kata_workflow::test_harness::seed_claimed_capsule_attempt(
            db,
            &self.cas,
            execution_id,
            ContentHash::new([11; 32]),
            stage,
        );
        db.dispatch_claimed_attempt(
            assignment_id,
            "w1",
            Ulid::new(),
            &kata_core::CommandSpec {
                command_json: frame_json,
            },
        )
        .expect("place the claim on a worker");
        db.advance_attempt(assignment_id, "running")
            .expect("the attempt reaches running");
        db.complete_attempt(assignment_id, &output)
            .expect("the completion settles on the chain");
        assignment_id
    }
}

#[test]
fn from_assignments_empty_yields_pending_record() {
    let execution_id = Ulid::new();
    let rec =
        execution_record_from_assignments(execution_id, "my-workflow".to_string(), Vec::new());
    assert_eq!(rec.id, execution_id.to_string());
    assert_eq!(rec.workflow_name, "my-workflow");
    assert_eq!(rec.status, ExecutionStatus::Pending);
    assert_eq!(rec.worker_id, "pending");
    assert!(rec.outputs.is_none());
    assert!(rec.error.is_none());
    assert!(rec.started_at_ms.is_none());
    assert!(rec.finished_at_ms.is_none());
    assert_eq!(rec.submitted_at_ms, execution_id.timestamp_ms());
}

#[test]
fn from_assignments_all_completed_yields_completed_with_outputs() {
    let execution_id = Ulid::new();
    let a = assignment(
        "first",
        kata_core::AssignmentStatus::Completed {
            worker_id: Some(SmolStr::new("w1")),
        },
        Some(serde_json::json!({"k": "v"})),
    );
    let b = assignment(
        "second",
        kata_core::AssignmentStatus::Completed {
            worker_id: Some(SmolStr::new("w1")),
        },
        Some(serde_json::json!({"k": "v"})),
    );
    let rec = execution_record_from_assignments(execution_id, "p".to_string(), vec![a, b]);
    assert_eq!(rec.status, ExecutionStatus::Completed);
    let outputs = rec.outputs.expect("completed runs must populate outputs");
    assert!(outputs.contains_key("first"));
    assert!(outputs.contains_key("second"));
    assert!(rec.error.is_none());
}

#[test]
fn from_assignments_projects_durable_execution_program_identity() {
    let execution_id = Ulid::new();
    let identity = ExecutionProgramIdentity {
        schema_version: 1,
        program_hash: ContentHash::zero(),
        workflow_class: test_workflow_class(),
    };

    let rec = execution_record_from_assignments_with_program_and_evidence(
        execution_id,
        "p".to_string(),
        None,
        None,
        Vec::new(),
        vec![evidence_record(
            execution_id,
            1,
            ExecutionEvidence {
                execution_program: Some(identity.clone()),
                ..ExecutionEvidence::default()
            },
        )],
    );

    assert_eq!(
        rec.status,
        ExecutionStatus::Pending,
        "metadata-only evidence must not complete the lifecycle"
    );
    assert_eq!(rec.execution_program, Some(identity.clone()));
    assert_eq!(rec.evidence.execution_program, Some(identity));
    assert!(rec.outputs.is_none());
}

#[test]
fn from_assignments_projects_checked_dispatch_guard_evidence() {
    let execution_id = Ulid::new();
    let guard = ExecutionCheckedDispatchGuardEvidence {
        schema_version: CHECKED_DISPATCH_GUARD_EVIDENCE_SCHEMA_VERSION,
        stage_name: "implement".to_string(),
        guard: CHECKED_DISPATCH_GUARD_ID.to_string(),
        status: ExecutionCheckedDispatchGuardStatus::Passed,
        program_hash: ContentHash::zero(),
        workflow_class: test_workflow_class(),
        dispatch_policy_coverage: true,
        dispatch_kind: Some(ExecutionCheckedDispatchKind::ValidationRetry),
        derived_stage_name: Some("implement#validate-1".to_string()),
        approval_required: Some(true),
        model_hint: Some("gpt-5.5".to_string()),
        timeout_ms: Some(120_000),
        allowed_tools: vec!["read_file".to_string()],
        required_capabilities: vec!["network".to_string()],
        policy_fields: CHECKED_DISPATCH_POLICY_FIELDS
            .iter()
            .map(|field| (*field).to_string())
            .collect(),
        diagnostic_codes: Vec::new(),
        error: None,
    };
    let rec = execution_record_from_assignments_with_program_and_evidence(
        execution_id,
        "http-test".to_string(),
        None,
        None,
        Vec::new(),
        vec![evidence_record(
            execution_id,
            1,
            ExecutionEvidence {
                checked_dispatch_guards: vec![guard.clone()],
                ..ExecutionEvidence::default()
            },
        )],
    );

    assert_eq!(rec.evidence.checked_dispatch_guards, vec![guard]);
    assert_eq!(
        rec.status,
        ExecutionStatus::Pending,
        "metadata-only dispatch guard evidence must not complete the lifecycle"
    );
    assert!(rec.outputs.is_none());
}

#[test]
fn from_assignments_preserves_checked_dispatch_guard_evidence_order() {
    let execution_id = Ulid::new();
    let mut failed_guard = ExecutionCheckedDispatchGuardEvidence {
        schema_version: CHECKED_DISPATCH_GUARD_EVIDENCE_SCHEMA_VERSION,
        stage_name: "implement".to_string(),
        guard: CHECKED_DISPATCH_GUARD_ID.to_string(),
        status: ExecutionCheckedDispatchGuardStatus::Failed,
        program_hash: ContentHash::zero(),
        workflow_class: test_workflow_class(),
        dispatch_policy_coverage: false,
        dispatch_kind: Some(ExecutionCheckedDispatchKind::ValidationRetry),
        derived_stage_name: Some("implement#validate-1".to_string()),
        approval_required: None,
        model_hint: None,
        timeout_ms: None,
        allowed_tools: Vec::new(),
        required_capabilities: Vec::new(),
        policy_fields: CHECKED_DISPATCH_POLICY_FIELDS
            .iter()
            .map(|field| (*field).to_string())
            .collect(),
        diagnostic_codes: vec!["stage_missing_from_execution_program".to_string()],
        error: Some("stage missing from checked execution program".to_string()),
    };
    let passed_guard = ExecutionCheckedDispatchGuardEvidence {
        status: ExecutionCheckedDispatchGuardStatus::Passed,
        dispatch_policy_coverage: true,
        approval_required: Some(false),
        diagnostic_codes: Vec::new(),
        error: None,
        ..failed_guard.clone()
    };
    failed_guard.policy_fields = vec!["approval_required".to_string()];

    let first = evidence_record(
        execution_id,
        10,
        ExecutionEvidence {
            checked_dispatch_guards: vec![failed_guard.clone()],
            ..ExecutionEvidence::default()
        },
    );
    let second = evidence_record(
        execution_id,
        20,
        ExecutionEvidence {
            checked_dispatch_guards: vec![passed_guard.clone()],
            ..ExecutionEvidence::default()
        },
    );

    let rec = execution_record_from_assignments_with_program_and_evidence(
        execution_id,
        "http-test".to_string(),
        None,
        None,
        Vec::new(),
        vec![second, first],
    );

    assert_eq!(
        rec.evidence.checked_dispatch_guards,
        vec![failed_guard, passed_guard],
        "checked dispatch guards are append-only evidence ordered by durable metadata rows"
    );
    assert_eq!(rec.status, ExecutionStatus::Pending);
    assert!(rec.outputs.is_none());
}

#[test]
fn from_assignments_any_failed_yields_failed_with_error_message() {
    let execution_id = Ulid::new();
    let completed = assignment(
        "ok",
        kata_core::AssignmentStatus::Completed {
            worker_id: Some(SmolStr::new("w1")),
        },
        Some(serde_json::json!({"ok": true})),
    );
    let failed = assignment(
        "bad",
        kata_core::AssignmentStatus::Failed {
            worker_id: Some(SmolStr::new("w1")),
            reason: "boom".to_string(),
        },
        None,
    );
    let running = assignment(
        "still",
        kata_core::AssignmentStatus::Running {
            worker_id: SmolStr::new("w1"),
        },
        None,
    );
    let rec = execution_record_from_assignments(
        execution_id,
        "p".to_string(),
        vec![completed, failed, running],
    );
    assert_eq!(rec.status, ExecutionStatus::Failed);
    let err = rec.error.expect("failed runs must populate error");
    assert!(err.contains("failed: boom"), "got: {err}");
    assert!(
        err.contains("bad"),
        "error must include stage name; got: {err}"
    );
    assert!(rec.outputs.is_none());
}

/// The record names the share of its running cost that it carries for
/// child executions, from BOTH halves of the population sum (a completed stage's
/// accepted envelope and a failed stage's `terminal_charge`), so
/// `own_cost_micro_usd` is exactly the spend this execution accepted itself. The
/// figures are the fixture's own literals, not kata's arithmetic.
#[test]
fn from_assignments_names_the_child_share_of_its_running_cost() {
    let completed = assignment(
        "invoke_a",
        kata_core::AssignmentStatus::Completed {
            worker_id: Some(SmolStr::new("w1")),
        },
        Some(serde_json::json!({
            "token_usage": {"cost_micro_usd": 100},
            "child_invocation_summary": {"token_usage": {"cost_micro_usd": 1_000}},
        })),
    );
    let mut failed = assignment(
        "invoke_b",
        kata_core::AssignmentStatus::Failed {
            worker_id: Some(SmolStr::new("w1")),
            reason: "child failed".to_string(),
        },
        None,
    );
    failed.terminal_charge = Some(kata_types::metering::TerminalCharge {
        token_usage: None,
        child_invocation_summary: Some(kata_types::metering::ChildInvocationSummary {
            token_usage: kata_types::metering::ChildInvocationUsage { cost_micro_usd: 20 },
            metering: None,
        }),
    });
    let rec =
        execution_record_from_assignments(Ulid::new(), "p".to_string(), vec![completed, failed]);
    assert_eq!(rec.running_cost_micro_usd, 1_120);
    assert_eq!(
        rec.child_cost_micro_usd, 1_020,
        "the child share of both the accepted envelope and the terminal charge"
    );
    assert_eq!(rec.own_cost_micro_usd(), 100);
}

/// A capsule retry chain mints one durable assignment row PER SEAT — the
/// `agent-change` live cell D shape: `panel` seat 0 fails (its refusal is
/// durable truth and stays `failed`), the retry's seat 1 completes. The run's
/// status is the stage's CHAIN HEAD, so the superseded failed seat cannot
/// poison the aggregate — `aggregate_status` collapses each stage's seats to
/// the latest one before classifying.
#[test]
fn from_assignments_a_superseded_failed_seat_does_not_fail_the_run() {
    let execution_id = Ulid::new();
    let mut seat0 = assignment(
        "panel",
        kata_core::AssignmentStatus::Failed {
            worker_id: Some(SmolStr::new("w1")),
            reason: "the capsule's /work delta wrote outside the stage's declared \
                     `produces_files` scope (work_delta_out_of_scope)"
                .to_string(),
        },
        None,
    );
    seat0.settled_seq = 7;
    let mut seat1 = assignment(
        "panel",
        kata_core::AssignmentStatus::Completed {
            worker_id: Some(SmolStr::new("w1")),
        },
        Some(serde_json::json!({"content": "done"})),
    );
    seat1.settled_seq = 12;
    let rec = execution_record_from_assignments(execution_id, "p".to_string(), vec![seat0, seat1]);
    assert_eq!(
        rec.status,
        ExecutionStatus::Completed,
        "the stage's chain head completed; the superseded failed seat is history"
    );
    assert_eq!(
        rec.outputs.as_ref().and_then(|o| o.get("panel")),
        Some(&serde_json::json!({"content": "done"})),
        "the completing seat's output is the stage's output"
    );
}

/// The collapse's other direction: the LATEST seat governs whichever way it
/// lands, so a stage whose last seat failed still fails the run — the error
/// the record surfaces is that seat's message, not an earlier seat's.
#[test]
fn from_assignments_a_failed_chain_head_still_fails_the_run() {
    let execution_id = Ulid::new();
    let mut seat0 = assignment(
        "panel",
        kata_core::AssignmentStatus::Failed {
            worker_id: Some(SmolStr::new("w1")),
            reason: "first seat's refusal".to_string(),
        },
        None,
    );
    seat0.settled_seq = 7;
    let mut seat1 = assignment(
        "panel",
        kata_core::AssignmentStatus::Failed {
            worker_id: Some(SmolStr::new("w1")),
            reason: "the retry's own refusal".to_string(),
        },
        None,
    );
    seat1.settled_seq = 12;
    let rec = execution_record_from_assignments(execution_id, "p".to_string(), vec![seat0, seat1]);
    assert_eq!(rec.status, ExecutionStatus::Failed);
    let err = rec.error.expect("failed runs must populate error");
    assert!(
        err.contains("the retry's own refusal"),
        "the chain head's reason is the run's error; got: {err}"
    );
}

#[test]
fn from_assignments_any_orphaned_yields_failed_with_orphaned_error() {
    let execution_id = Ulid::new();
    let orphaned = assignment(
        "lost",
        kata_core::AssignmentStatus::Orphaned {
            prev_worker: Some(SmolStr::new("w1")),
            reason: "main restart".to_string(),
        },
        None,
    );
    let completed = assignment(
        "ok",
        kata_core::AssignmentStatus::Completed {
            worker_id: Some(SmolStr::new("w1")),
        },
        Some(serde_json::json!({})),
    );
    let rec =
        execution_record_from_assignments(execution_id, "p".to_string(), vec![orphaned, completed]);
    assert_eq!(rec.status, ExecutionStatus::Failed);
    let err = rec.error.expect("orphaned runs must populate error");
    assert!(err.contains("orphaned: main restart"), "got: {err}");
}

#[test]
fn from_assignments_any_running_yields_running() {
    let execution_id = Ulid::new();
    let pending = assignment("p", kata_core::AssignmentStatus::Pending, None);
    let mut running = assignment(
        "r",
        kata_core::AssignmentStatus::Running {
            worker_id: SmolStr::new("w1"),
        },
        None,
    );
    running.started_at_ms = Some(1234);
    let dispatched = assignment(
        "d",
        kata_core::AssignmentStatus::Dispatched {
            worker_id: SmolStr::new("w1"),
        },
        None,
    );
    let rec = execution_record_from_assignments(
        execution_id,
        "p".to_string(),
        vec![pending, running, dispatched],
    );
    assert_eq!(rec.status, ExecutionStatus::Running);
    assert_eq!(rec.started_at_ms, Some(1234));
    assert!(rec.finished_at_ms.is_none());
}

#[test]
fn from_assignments_any_awaiting_approval_yields_running() {
    let execution_id = Ulid::new();
    let a = assignment(
        "review",
        kata_core::AssignmentStatus::AwaitingApproval {
            worker_id: None,
            reason: "needs operator review".to_string(),
        },
        None,
    );
    let rec = execution_record_from_assignments(execution_id, "p".to_string(), vec![a]);
    assert_eq!(rec.status, ExecutionStatus::Running);
    assert!(rec.outputs.is_none());
    assert!(rec.error.is_none());
}

#[test]
fn from_assignments_all_pending_yields_pending() {
    let execution_id = Ulid::new();
    let xs = vec![
        assignment("a", kata_core::AssignmentStatus::Pending, None),
        assignment("b", kata_core::AssignmentStatus::Pending, None),
        assignment("c", kata_core::AssignmentStatus::Pending, None),
    ];
    let rec = execution_record_from_assignments(execution_id, "p".to_string(), xs);
    assert_eq!(rec.status, ExecutionStatus::Pending);
    assert_eq!(rec.worker_id, "pending");
    assert!(rec.outputs.is_none());
}

#[test]
fn from_assignments_completed_output_none_materialises_as_null() {
    let execution_id = Ulid::new();
    let a = assignment(
        "stage_name",
        kata_core::AssignmentStatus::Completed {
            worker_id: Some(SmolStr::new("w1")),
        },
        None,
    );
    let rec = execution_record_from_assignments(execution_id, "p".to_string(), vec![a]);
    let outputs = rec.outputs.expect("completed runs must populate outputs");
    assert_eq!(outputs.get("stage_name"), Some(&serde_json::Value::Null));
}

#[test]
fn from_assignments_finished_at_is_max_across_terminal_assignments() {
    let execution_id = Ulid::new();
    let mut a = assignment(
        "a",
        kata_core::AssignmentStatus::Completed {
            worker_id: Some(SmolStr::new("w1")),
        },
        Some(serde_json::json!({})),
    );
    a.finished_at_ms = Some(1000);
    let mut b = assignment(
        "b",
        kata_core::AssignmentStatus::Completed {
            worker_id: Some(SmolStr::new("w1")),
        },
        Some(serde_json::json!({})),
    );
    b.finished_at_ms = Some(2000);
    let rec = execution_record_from_assignments(execution_id, "p".to_string(), vec![a, b]);
    assert_eq!(rec.finished_at_ms, Some(2000));
}

#[test]
fn from_assignments_started_at_is_min_across_assignments() {
    let execution_id = Ulid::new();
    let mut a = assignment(
        "a",
        kata_core::AssignmentStatus::Running {
            worker_id: SmolStr::new("w1"),
        },
        None,
    );
    a.started_at_ms = Some(500);
    let mut b = assignment(
        "b",
        kata_core::AssignmentStatus::Running {
            worker_id: SmolStr::new("w1"),
        },
        None,
    );
    b.started_at_ms = Some(1500);
    let rec = execution_record_from_assignments(execution_id, "p".to_string(), vec![a, b]);
    assert_eq!(rec.started_at_ms, Some(500));
}

#[test]
fn from_assignments_worker_id_picks_first_attributed() {
    // Stage names are sorted alphabetically before traversal,
    // so "a" → "b" → "c". "a" is Pending (returns None from
    // worker_id()), "b" is the first attributed entry; the
    // aggregator should surface its worker.
    let execution_id = Ulid::new();
    let a_pending = assignment("a", kata_core::AssignmentStatus::Pending, None);
    let b_dispatched = assignment(
        "b",
        kata_core::AssignmentStatus::Dispatched {
            worker_id: SmolStr::new("w1"),
        },
        None,
    );
    let c_completed = assignment(
        "c",
        kata_core::AssignmentStatus::Completed {
            worker_id: Some(SmolStr::new("w2")),
        },
        Some(serde_json::json!({})),
    );
    let rec = execution_record_from_assignments(
        execution_id,
        "p".to_string(),
        vec![a_pending, b_dispatched, c_completed],
    );
    assert_eq!(rec.worker_id, "w1");
}

/// After sorting by `stage_name`,
/// `execution_record_from_assignments` must produce identical output for any
/// permutation of the input vec — without the sort, successive
/// `GET /executions/{id}` polls
/// could return different error messages or worker attributions.
#[test]
fn from_assignments_is_order_independent() {
    let execution_id = Ulid::new();
    let a = assignment(
        "a",
        kata_core::AssignmentStatus::Failed {
            worker_id: Some(SmolStr::new("w1")),
            reason: "first".to_string(),
        },
        None,
    );
    let b = assignment(
        "b",
        kata_core::AssignmentStatus::Failed {
            worker_id: Some(SmolStr::new("w2")),
            reason: "second".to_string(),
        },
        None,
    );
    let forward = execution_record_from_assignments(
        execution_id,
        "p".to_string(),
        vec![a.clone(), b.clone()],
    );
    let reverse = execution_record_from_assignments(execution_id, "p".to_string(), vec![b, a]);
    assert_eq!(forward.status, reverse.status);
    assert_eq!(forward.error, reverse.error);
    assert_eq!(forward.worker_id, reverse.worker_id);
    // Both should pick "a" as the first-in-sorted-order failure.
    assert!(
        forward
            .error
            .as_ref()
            .unwrap()
            .contains("stage a failed: first"),
        "got: {:?}",
        forward.error
    );
}

/// When the orphaned and failed assignments
/// are both present, the one that sorts first by `stage_name`
/// wins the `error` slot. This pins the deterministic tie-break
/// for mixed-failure executions.
#[test]
fn from_assignments_mixed_orphaned_and_failed_picks_lexicographically_first() {
    let execution_id = Ulid::new();
    let a_orphaned = assignment(
        "a_orphaned",
        kata_core::AssignmentStatus::Orphaned {
            prev_worker: None,
            reason: "node crash".to_string(),
        },
        None,
    );
    let b_failed = assignment(
        "b_failed",
        kata_core::AssignmentStatus::Failed {
            worker_id: None,
            reason: "boom".to_string(),
        },
        None,
    );
    let rec = execution_record_from_assignments(
        execution_id,
        "p".to_string(),
        vec![b_failed, a_orphaned],
    );
    assert_eq!(rec.status, ExecutionStatus::Failed);
    let err = rec.error.expect("mixed failure must populate error");
    assert!(
        err.contains("a_orphaned orphaned: node crash"),
        "expected orphaned branch (sorts first), got: {err}"
    );
}

/// `Failed { worker_id: None }` means the
/// assignment failed before any worker was attributed (e.g. the
/// dispatcher found no live workers and orphaned immediately).
/// In that case the aggregator's `worker_id` lookup should
/// traverse past it to the next entry that does have a worker.
#[test]
fn from_assignments_failed_with_no_worker_id_falls_back_to_next_attributed() {
    let execution_id = Ulid::new();
    let a_failed_unattributed = assignment(
        "a",
        kata_core::AssignmentStatus::Failed {
            worker_id: None,
            reason: "no workers".to_string(),
        },
        None,
    );
    let b_running = assignment(
        "b",
        kata_core::AssignmentStatus::Running {
            worker_id: SmolStr::new("w-alive"),
        },
        None,
    );
    let rec = execution_record_from_assignments(
        execution_id,
        "p".to_string(),
        vec![a_failed_unattributed, b_running],
    );
    // Execution-level status is Failed (any Failed wins), but
    // worker_id attribution should fall through to "w-alive".
    assert_eq!(rec.status, ExecutionStatus::Failed);
    assert_eq!(rec.worker_id, "w-alive");
}

/// A `Failed` execution whose assignments
/// carry no `finished_at_ms` (pre-dispatch failure with no wall
/// clock) should produce `finished_at_ms: None`, not panic or
/// default to 0.
#[test]
fn from_assignments_failed_with_no_finished_at_returns_none() {
    let execution_id = Ulid::new();
    let failed = assignment(
        "a",
        kata_core::AssignmentStatus::Failed {
            worker_id: None,
            reason: "no workers".to_string(),
        },
        None,
    );
    // `finished_at_ms` left as the helper's default of None.
    let rec = execution_record_from_assignments(execution_id, "p".to_string(), vec![failed]);
    assert_eq!(rec.status, ExecutionStatus::Failed);
    assert!(rec.finished_at_ms.is_none());
}

/// A `Cancelled` assignment aggregates to
/// `ExecutionStatus::Cancelled`, carrying its finish time and the chain's
/// cancel reason — the aggregate must agree with the lifecycle's
/// `cancelled` terminal on the same rows.
#[test]
fn from_assignments_cancelled_stage_projects_cancelled_execution() {
    let execution_id = Ulid::new();
    let done = assignment(
        "a",
        kata_core::AssignmentStatus::Completed {
            worker_id: Some(SmolStr::new("w")),
        },
        Some(serde_json::json!({"stage": "done"})),
    );
    let mut cancelled = assignment(
        "b",
        kata_core::AssignmentStatus::Cancelled {
            worker_id: Some(SmolStr::new("w")),
            reason: "operator asked for a stop".to_string(),
        },
        None,
    );
    cancelled.finished_at_ms = Some(42);
    let rec =
        execution_record_from_assignments(execution_id, "p".to_string(), vec![done, cancelled]);
    assert_eq!(rec.status, ExecutionStatus::Cancelled);
    assert!(rec.is_terminal());
    assert_eq!(
        rec.error.as_deref(),
        Some("stage b cancelled: operator asked for a stop")
    );
    assert_eq!(rec.finished_at_ms, Some(42));
    assert!(
        rec.outputs.is_none(),
        "the aggregate outputs map publishes on Completed only — a cancelled run \
         keeps its completed sibling's output on the chain, not the wire record"
    );
}

/// A realistic single-stage happy-path run
/// where the mock worker output is shaped like the integration
/// test expects (`outputs["only"]["stage"]` as a string). This
/// pins the wire contract an HTTP client reads.
#[test]
fn from_assignments_single_stage_output_matches_integration_contract_shape() {
    let execution_id = Ulid::new();
    let only = assignment(
        "only",
        kata_core::AssignmentStatus::Completed {
            worker_id: Some(SmolStr::new("http-test")),
        },
        Some(serde_json::json!({"stage": "mock output"})),
    );
    let rec = execution_record_from_assignments(execution_id, "http-test".to_string(), vec![only]);
    assert_eq!(rec.status, ExecutionStatus::Completed);
    assert_eq!(rec.workflow_name, "http-test");
    assert_eq!(rec.worker_id, "http-test");
    let outputs = rec.outputs.expect("completed run must have outputs");
    assert!(
        outputs["only"]["stage"].is_string(),
        "expected outputs['only']['stage'] to be a string, got: {:?}",
        outputs["only"]
    );
    assert!(rec.error.is_none());
}

#[test]
fn from_assignments_merges_controller_application_evidence_by_application_id() {
    let execution_id = Ulid::new();
    let mut failed = controller_application(
        "advance:decision-wave-1",
        "decision-wave-1",
        "repair",
        "advance",
        false,
    );
    failed.error = Some("submit failed".to_string());
    let mut applied = controller_application(
        "advance:decision-wave-1",
        "decision-wave-1",
        "repair",
        "advance",
        true,
    );
    applied.applied_at_ms = failed.applied_at_ms + 1;
    applied.next_execution_id = Some("01HZZZZZZZZZZZZZZZZZZZZZZY".to_string());

    let first = kata_core::ExecutionEvidenceRecord {
        id: Ulid::new(),
        execution_id,
        created_at_ms: 1,
        evidence: ExecutionEvidence {
            controller_applications: vec![failed],
            ..ExecutionEvidence::default()
        },
    };
    let second = kata_core::ExecutionEvidenceRecord {
        id: Ulid::new(),
        execution_id,
        created_at_ms: 2,
        evidence: ExecutionEvidence {
            controller_applications: vec![applied.clone()],
            ..ExecutionEvidence::default()
        },
    };

    let rec = execution_record_from_assignments_with_program_and_evidence(
        execution_id,
        "factory-application".to_string(),
        None,
        None,
        Vec::new(),
        vec![first, second],
    );

    assert_eq!(rec.evidence.controller_applications, vec![applied]);
    assert!(rec.outputs.is_none());
}

#[test]
fn from_assignments_parses_controller_and_closeout_evidence_from_content_json() {
    let execution_id = Ulid::new();
    let controller = assignment(
        "controller",
        kata_core::AssignmentStatus::Completed {
            worker_id: Some(SmolStr::new("codex")),
        },
        Some(serde_json::json!({
            "content": r#"{"decision_id":"decision-content","decision":"park","next_action":"park candidate","evidence":["validated"]}"#
        })),
    );
    let closeout = assignment(
        "closeout",
        kata_core::AssignmentStatus::Completed {
            worker_id: Some(SmolStr::new("codex")),
        },
        Some(serde_json::json!({
            "content": r#"{"outcome":"complete","next_action":"stop","evidence":["done"],"remaining":[]}"#
        })),
    );

    let rec = execution_record_from_assignments(
        execution_id,
        "content-evidence".to_string(),
        vec![controller, closeout],
    );

    assert_eq!(rec.status, ExecutionStatus::Completed);
    assert_eq!(rec.evidence.controller_decisions.len(), 1);
    let decision = &rec.evidence.controller_decisions[0];
    assert_eq!(decision.decision_id, "decision-content");
    assert_eq!(decision.decision, "park");
    assert_eq!(decision.next_action.as_deref(), Some("park candidate"));
    assert_eq!(decision.evidence, vec!["validated".to_string()]);

    assert_eq!(rec.evidence.closeout_reports.len(), 1);
    let closeout = &rec.evidence.closeout_reports[0];
    assert_eq!(closeout.outcome.as_deref(), Some("complete"));
    assert_eq!(closeout.next_action.as_deref(), Some("stop"));
    assert_eq!(closeout.evidence, vec!["done".to_string()]);
}

#[test]
fn validation_memory_writeback_upserts_criterion_objects_idempotently() {
    let program = parse_inline_starlark_checked(
        r#"
validate = stage(id = "validate", agent = "shell", run = "true")
workflow(
    "validation-memory-writeback",
    root = validate,
    validation_criteria = [
        validation_criterion(
            "vc-build",
            stage = "validate",
            description = "Workspace builds successfully.",
            commands = ["cargo check"],
            evidence = ["cargo check passed"],
        ),
    ],
)
"#,
        "validation_memory_writeback.star",
        &[],
    )
    .expect("parse definition");
    let execution_id = Ulid::new();
    let candidate_fingerprint = ContentHash::new([0x55; 32]);
    let candidate_content_hash = ContentHash::new([0x77; 32]);
    let mut validate = assignment("validate", kata_core::AssignmentStatus::Pending, None);
    bind_assignment_to_execution(&mut validate, execution_id);
    let rig = ChainRig::new();
    rig.admit(execution_id);
    rig.complete_stage(
        execution_id,
        "validate",
        serde_json::json!({
            "status": "passed",
            "criteria": [{
                "criterion_id": "vc-build",
                "status": "passed",
                "candidate": {
                    "execution_id": execution_id.to_string(),
                    "fingerprint": candidate_fingerprint,
                    "content_hash": candidate_content_hash,
                    "workspace_backend": "jj",
                    "dirty": true,
                    "changed_paths": ["src/lib.rs"]
                },
                "evidence": ["cargo check passed"],
            }],
            "commands": ["cargo check"],
            "evidence": ["cargo check passed"],
        }),
    );
    let store = SqliteNativeMemoryStore::open_in_memory().expect("open memory store");

    let applied =
        persist_workflow_memory_writebacks(&store, execution_id, &program, &rig.dispatcher)
            .expect("validation memory writeback applies");
    assert_eq!(applied, 1);
    let snapshot = store
        .snapshot(
            Some(MemoryObjectKind::ValidationCriterion),
            Some(MemoryObjectStatus::Active),
        )
        .expect("snapshot validation memory");
    assert_eq!(snapshot.object_count, 1);
    let object = &snapshot.objects[0];
    assert_eq!(object.kind, MemoryObjectKind::ValidationCriterion);
    assert_eq!(object.status, MemoryObjectStatus::Active);
    assert_eq!(object.body["criterion_id"], "vc-build");
    assert_eq!(object.body["runtime"]["status"], "passed");
    assert_eq!(object.body["runtime"]["satisfied"], true);
    assert_eq!(
        object.body["runtime"]["candidate"]["fingerprint"],
        candidate_fingerprint.to_string()
    );
    assert_eq!(
        object.body["runtime"]["candidate"]["content_hash"],
        candidate_content_hash.to_string()
    );
    assert_eq!(
        object.body["runtime"]["candidate"]["changed_paths"][0],
        "src/lib.rs"
    );
    assert_eq!(object.body["declared"]["commands"][0], "cargo check");
    let execution_id_string = execution_id.to_string();
    assert_eq!(
        object.provenance.execution_id.as_deref(),
        Some(execution_id_string.as_str())
    );
    assert_eq!(object.revision, 1);

    let applied =
        persist_workflow_memory_writebacks(&store, execution_id, &program, &rig.dispatcher)
            .expect("duplicate validation memory writeback is idempotent");
    assert_eq!(applied, 0);
    let object = store
        .get(object.id.as_str())
        .expect("get validation memory object")
        .expect("validation memory object exists");
    assert_eq!(object.revision, 1);
}

#[test]
fn validation_memory_writeback_records_typed_waiver_satisfaction() {
    let program = parse_inline_starlark_checked(
        r#"
validate = stage(id = "validate", agent = "shell", run = "true")
workflow(
    "validation-memory-waiver",
    root = validate,
    validation_criteria = [
        validation_criterion(
            "vc-waived",
            stage = "validate",
            description = "Criterion can be explicitly waived.",
            commands = ["cargo check"],
            evidence = ["operator approval"],
        ),
    ],
)
"#,
        "validation_memory_waiver.star",
        &[],
    )
    .expect("parse definition");

    let bare_execution_id = Ulid::new();
    let mut bare_validate = assignment("validate", kata_core::AssignmentStatus::Pending, None);
    bind_assignment_to_execution(&mut bare_validate, bare_execution_id);
    let bare_rig = ChainRig::new();
    bare_rig.admit(bare_execution_id);
    bare_rig.complete_stage(
        bare_execution_id,
        "validate",
        serde_json::json!({
            "status": "passed",
            "criteria": [{
                "criterion_id": "vc-waived",
                "status": "waived_by_policy",
                "source": "policy",
                "evidence": ["bare waiver is not authoritative"]
            }]
        }),
    );
    let bare_store = SqliteNativeMemoryStore::open_in_memory().expect("open bare memory store");
    assert_eq!(
        persist_workflow_memory_writebacks(
            &bare_store,
            bare_execution_id,
            &program,
            &bare_rig.dispatcher
        )
        .expect("bare waiver writeback applies"),
        1
    );
    let bare_snapshot = bare_store
        .snapshot(
            Some(MemoryObjectKind::ValidationCriterion),
            Some(MemoryObjectStatus::Active),
        )
        .expect("snapshot bare waiver validation memory");
    assert_eq!(
        bare_snapshot.objects[0].body["runtime"]["status"],
        "waived_by_policy"
    );
    assert_eq!(bare_snapshot.objects[0].body["runtime"]["satisfied"], false);
    assert!(bare_snapshot.objects[0].body["runtime"]["waiver"].is_null());

    let typed_execution_id = Ulid::new();
    let mut typed_validate = assignment("validate", kata_core::AssignmentStatus::Pending, None);
    bind_assignment_to_execution(&mut typed_validate, typed_execution_id);
    let typed_rig = ChainRig::new();
    typed_rig.admit(typed_execution_id);
    typed_rig.complete_stage(
        typed_execution_id,
        "validate",
        serde_json::json!({
            "status": "passed",
            "criteria": [{
                "criterion_id": "vc-waived",
                "status": "waived_by_policy",
                "source": "policy",
                "waiver": {
                    "source": "operator",
                    "reason": "operator accepted this proof gap",
                    "approved_by": "operator",
                    "approved_at_ms": 1234,
                    "evidence": ["operator approval KATA-1"]
                }
            }]
        }),
    );
    let typed_store = SqliteNativeMemoryStore::open_in_memory().expect("open typed memory store");
    assert_eq!(
        persist_workflow_memory_writebacks(
            &typed_store,
            typed_execution_id,
            &program,
            &typed_rig.dispatcher
        )
        .expect("typed waiver writeback applies"),
        1
    );
    let typed_snapshot = typed_store
        .snapshot(
            Some(MemoryObjectKind::ValidationCriterion),
            Some(MemoryObjectStatus::Active),
        )
        .expect("snapshot typed waiver validation memory");
    assert_eq!(
        typed_snapshot.objects[0].body["runtime"]["status"],
        "waived_by_policy"
    );
    assert_eq!(typed_snapshot.objects[0].body["runtime"]["satisfied"], true);
    assert_eq!(
        typed_snapshot.objects[0].body["runtime"]["waiver"]["source"],
        "operator"
    );
    assert_eq!(
        typed_snapshot.objects[0].body["runtime"]["waiver"]["reason"],
        "operator accepted this proof gap"
    );
}

/// THE REQUIRED WRITEBACK READS THE AMENDED OUTPUT, OR IT FAILS A RUN WHOSE
/// EVERY STAGE COMPLETED.
///
/// The production sequence this reproduces, end to end:
///
/// 1. the agent emits FENCED JSON in `content` — no `parsed` key;
/// 2. `mark_completed_and_fold_attempt` settles that raw envelope on both planes;
/// 3. `validate_and_inject_parsed` strips the fence and the runner AMENDS the
///    completion with the augmented envelope;
/// 4. terminalization calls `persist_workflow_memory_writebacks`, whose
///    `parsed_stage_output` looks for `"parsed"` first and otherwise re-parses
///    `content` — which is still fenced, so the re-parse fails;
/// 5. `writeback.required` therefore trips `required_memory_writeback_error`, and
///    `WorkflowExecutor` turns that into `Err` for the whole execution.
///
/// # RED, in this test, before the amendment lands
///
/// The first `persist_workflow_memory_writebacks` call below is the RED and it is
/// asserted as an `Err` naming the required writeback — the state the whole run
/// is in if the amendment never reaches the chain, because the row reader then
/// has no amendment to serve: `required memory writeback findings failed for
/// stage validate: stage output has no parsed JSON object`.
#[test]
fn required_memory_writeback_reads_the_amended_output_rather_than_failing_the_run() {
    let program = parse_inline_starlark_checked(
        r#"
validate = stage(id = "validate", prompt = "validate", agent = "worker")
workflow(
    "required-writeback-amendment",
    root = validate,
    max_memory_writebacks = 1,
    memory_writebacks = [
        memory_writeback(
            "findings",
            stage = "validate",
            field = "memory_writebacks",
            kinds = ["finding"],
            statuses = ["active"],
            max_objects = 2,
            required = True,
        ),
    ],
)
"#,
        "required_writeback_amendment.star",
        &[],
    )
    .expect("parse definition");
    let execution_id = Ulid::new();
    let mut validate = assignment("validate", kata_core::AssignmentStatus::Pending, None);
    bind_assignment_to_execution(&mut validate, execution_id);

    let rows = serde_json::json!([{
        "id": "finding-fenced",
        "kind": "finding",
        "status": "active",
        "title": "Fenced envelope finding",
        "body": {"summary": "the agent fenced its JSON"},
        "tags": ["validation"]
    }]);
    let fenced = format!(
        "```json\n{}\n```",
        serde_json::to_string(&serde_json::json!({ "memory_writebacks": rows.clone() }))
            .expect("the fenced payload serializes")
    );
    let raw = serde_json::json!({ "content": fenced.clone() });
    let augmented = serde_json::json!({
        "content": fenced,
        "parsed": { "memory_writebacks": rows },
    });

    let rig = ChainRig::new();
    rig.admit(execution_id);
    let assignment_id = rig.complete_dispatchable_stage(execution_id, "validate", raw.clone());

    // NON-VACUITY, ASSERTED BEFORE THE BEHAVIOR UNDER TEST. The un-amended
    // completion must genuinely be the fenced envelope with no `parsed`, or the
    // failure below would be some other defect wearing this test's name.
    let before = rig
        .dispatcher
        .execution_assignment_states(execution_id)
        .expect("the authority chain answers for the admitted execution");
    let before_row = before
        .iter()
        .find(|row| row.assignment_id == assignment_id)
        .expect("the chain holds the completion");
    assert_eq!(
        before_row.output(),
        Some(&raw),
        "NON-VACUITY: the completion starts on the RAW fenced envelope"
    );
    assert!(
        before_row
            .output()
            .is_some_and(|output| output.get("parsed").is_none()),
        "NON-VACUITY: the raw envelope carries no `parsed`, which is the whole \
         reason the amendment exists"
    );

    // THE RED. Without the amendment on the chain, the required writeback fails
    // the execution even though its stage completed successfully.
    let red_store = SqliteNativeMemoryStore::open_in_memory().expect("open memory store");
    let red =
        persist_workflow_memory_writebacks(&red_store, execution_id, &program, &rig.dispatcher)
            .expect_err("a fenced, un-amended envelope trips the required writeback");
    assert!(
        red.to_string()
            .contains("required memory writeback findings"),
        "the RED is the required-writeback refusal, named: {red}"
    );

    // THE AMENDMENT, through the chain's amend door.
    rig.lifecycle
        .db()
        .amend_attempt_outcome(
            assignment_id,
            &serde_json::to_vec(&augmented).expect("encode the amendment"),
        )
        .expect("the amendment lands on the chain");

    let store = SqliteNativeMemoryStore::open_in_memory().expect("open memory store");
    let applied =
        persist_workflow_memory_writebacks(&store, execution_id, &program, &rig.dispatcher)
            .expect("the amended completion satisfies the required writeback");
    assert_eq!(applied, 1, "the declared writeback row is applied");
    let findings = store
        .snapshot(
            Some(MemoryObjectKind::Finding),
            Some(MemoryObjectStatus::Active),
        )
        .expect("snapshot findings");
    assert_eq!(findings.object_count, 1);
    assert_eq!(
        findings.objects[0].title.as_deref(),
        Some("Fenced envelope finding")
    );

    // And the row reader itself now serves the amended envelope, which is the
    // fact every other moved kata-api consumer reads.
    let after = rig
        .dispatcher
        .execution_assignment_states(execution_id)
        .expect("the authority chain answers for the admitted execution");
    assert_eq!(
        after
            .iter()
            .find(|row| row.assignment_id == assignment_id)
            .and_then(|row| row.output().cloned()),
        Some(augmented),
        "the row reader serves the AMENDED completion"
    );
}

// ---- Shared writeback fixture for the scope-isolation tests below ----

/// A one-stage pack whose `validate` stage declares a bounded `finding`
/// writeback. Its `memory_scope` is the `Global` default; the scope tests override
/// `program.memory_scope` to drive a scoped write through the real path.
fn typed_writeback_program() -> ExecutionProgram {
    let source = r#"
s = stage(id = "validate", prompt = "validate", agent = "worker")
workflow(
    "typed-writeback",
    root = s,
    max_memory_writebacks = 1,
    memory_writebacks = [
        memory_writeback(
            "findings",
            stage = "validate",
            field = "memory_writebacks",
            kinds = ["finding"],
            statuses = ["active"],
            max_objects = 2,
        ),
    ],
)
"#;
    parse_inline_starlark_checked(source, "typed_writeback.star", &[])
        .expect("typed writeback program compiles")
}

/// Drive a single `finding` writeback row carrying `row_body` through the
/// terminal writeback membrane against a fresh in-memory store.
fn drive_finding_writeback(
    program: &ExecutionProgram,
    row_body: serde_json::Value,
) -> (KataResult<usize>, SqliteNativeMemoryStore) {
    let execution_id = Ulid::new();
    let mut validate = assignment("validate", kata_core::AssignmentStatus::Pending, None);
    bind_assignment_to_execution(&mut validate, execution_id);
    let rig = ChainRig::new();
    rig.admit(execution_id);
    rig.complete_stage(
        execution_id,
        "validate",
        serde_json::json!({
            "status": "passed",
            "memory_writebacks": [{
                "id": "finding-row",
                "kind": "finding",
                "status": "active",
                "title": "A finding",
                "body": row_body,
                "tags": ["validation"]
            }]
        }),
    );
    let store = SqliteNativeMemoryStore::open_in_memory().expect("open memory store");
    let result = persist_workflow_memory_writebacks(&store, execution_id, program, &rig.dispatcher);
    (result, store)
}

// ---- Scope isolation flows end-to-end ----

/// A filtered read that reproduces EXACTLY the query the runtime read site
/// (`materialize_memory_selector_from_store` in kata-workflow) issues for a reader
/// whose base scope yields `window` — the `scope IN (ancestors_inclusive)` filter.
/// `None` reproduces the flat read (every scope visible).
fn read_finding_ids_scoped(
    store: &SqliteNativeMemoryStore,
    window: Option<Vec<MemoryScope>>,
) -> Vec<String> {
    let mut ids = store
        .query_objects(MemoryObjectQuery {
            kinds: vec![MemoryObjectKind::Finding],
            statuses: vec![MemoryObjectStatus::Active],
            query: None,
            limit: None,
            scope_window: window,
        })
        .expect("scoped read")
        .into_iter()
        .map(|object| object.id)
        .collect::<Vec<_>>();
    ids.sort();
    ids
}

/// End-to-end isolation: execution A at `Workflow{p,a}` writes
/// a memory object through the REAL runtime writeback path
/// (`persist_workflow_memory_writebacks`). A sibling reader at `Workflow{p,b}`
/// reading through the runtime read query does NOT see A's object; a reader at A's
/// own scope DOES. Isolation flows through production code, not just the store
/// unit test.
///
/// Non-vacuous: a writeback that hardcoded `scope = Global` would land A's object
/// at `Global` — visible to B's window (which includes
/// `Global`) — making the `stored.scope == Workflow{p,a}` and "B is empty"
/// assertions both FAIL.
#[test]
fn workflow_scoped_writeback_isolates_from_sibling_reader() {
    let mut program = typed_writeback_program();
    let scope_a = MemoryScope::Workflow {
        project: "p".to_string(),
        workflow: "a".to_string(),
    };
    let scope_b = MemoryScope::Workflow {
        project: "p".to_string(),
        workflow: "b".to_string(),
    };
    program.memory_scope = scope_a.clone();

    let (result, store) = drive_finding_writeback(
        &program,
        serde_json::json!({"summary": "workflow A finding"}),
    );
    assert_eq!(result.expect("A's writeback applies"), 1);

    // The REAL writeback landed the object at A's scope (not Global).
    let a_ids = read_finding_ids_scoped(&store, Some(scope_a.ancestors_inclusive()));
    assert_eq!(a_ids.len(), 1, "A sees its own object");
    let stored = store.get(&a_ids[0]).expect("get").expect("object present");
    assert_eq!(
        stored.scope, scope_a,
        "the runtime writeback must land at the execution's scope, not Global"
    );

    // Sibling B is isolated: its window ({Workflow{p,b}, Project{p}, Global})
    // excludes A's Workflow{p,a} object.
    let b_ids = read_finding_ids_scoped(&store, Some(scope_b.ancestors_inclusive()));
    assert!(
        b_ids.is_empty(),
        "a sibling workflow must NOT see A's scoped object, saw {b_ids:?}"
    );

    // A Global reader's window ({Global}) also does not see a deeper
    // Workflow-scoped object — visibility reaches ancestors, never descendants.
    let global_ids =
        read_finding_ids_scoped(&store, Some(MemoryScope::Global.ancestors_inclusive()));
    assert!(
        global_ids.is_empty(),
        "a Global reader does not see a deeper Workflow-scoped object, saw {global_ids:?}"
    );
}

/// Default-preservation companion at the WRITE path: the default `Global`
/// execution scope (every pack) lands the writeback at `Global`, and BOTH the
/// flat (`None`) read and the
/// default `Global`-window read return the identical object — proving the default
/// changes nothing observable. Guards against a factory regression.
#[test]
fn default_global_writeback_read_matches_flat_read() {
    let program = typed_writeback_program();
    assert_eq!(
        program.memory_scope,
        MemoryScope::Global,
        "every pack resolves to the Global default (no pack declares a tier)"
    );

    let (result, store) =
        drive_finding_writeback(&program, serde_json::json!({"summary": "default finding"}));
    assert_eq!(result.expect("default writeback applies"), 1);

    let flat = read_finding_ids_scoped(&store, None);
    let global_window =
        read_finding_ids_scoped(&store, Some(MemoryScope::Global.ancestors_inclusive()));
    assert_eq!(
        flat, global_window,
        "the default Global-window read must be byte-identical to the flat read"
    );
    assert_eq!(
        flat.len(),
        1,
        "the default writeback landed one Global finding"
    );
    let stored = store.get(&flat[0]).expect("get").expect("present");
    assert_eq!(
        stored.scope,
        MemoryScope::Global,
        "the default execution writes Global scope"
    );
}

#[test]
fn workflow_memory_writeback_evidence_failure_blocks_memory_mutation() {
    let program = parse_inline_starlark_checked(
        r#"
validate = stage(id = "validate", agent = "shell", run = "true")
workflow(
    "workflow-memory-writeback-fail-closed",
    root = validate,
    max_memory_writebacks = 1,
    memory_writebacks = [
        memory_writeback(
            "validation-findings",
            stage = "validate",
            field = "memory_writebacks",
            kinds = ["finding"],
            statuses = ["active"],
            max_objects = 1,
        ),
    ],
)
"#,
        "workflow_memory_writeback_fail_closed.star",
        &[],
    )
    .expect("parse definition");
    let execution_id = Ulid::new();
    let mut validate = assignment("validate", kata_core::AssignmentStatus::Pending, None);
    bind_assignment_to_execution(&mut validate, execution_id);
    let failing_store = Arc::new(FailingUnclaimedEvidenceStore::new(false));
    failing_store.set_fail_memory_writeback_evidence(true);
    let rig = ChainRig::with_ledger(failing_store.open_ledger());
    rig.admit(execution_id);
    rig.complete_stage(
        execution_id,
        "validate",
        serde_json::json!({
            "memory_writebacks": [{
                "id": "finding-build",
                "kind": "finding",
                "status": "active",
                "title": "Build proof exists",
                "body": {"summary": "cargo check passed"}
            }]
        }),
    );
    let memory = SqliteNativeMemoryStore::open_in_memory().expect("open memory store");

    let err = persist_workflow_memory_writebacks(&memory, execution_id, &program, &rig.dispatcher)
        .expect_err("memory writeback evidence failure must block native memory mutation");
    assert!(
        err.to_string()
            .contains("injected memory writeback evidence append failure"),
        "{err}"
    );
    let findings = memory
        .snapshot(
            Some(MemoryObjectKind::Finding),
            Some(MemoryObjectStatus::Active),
        )
        .expect("snapshot findings");
    assert_eq!(
        findings.object_count, 0,
        "native memory must not mutate before pending evidence is durable"
    );
    assert!(
        rig.ledger
            .execution_evidence_records(execution_id)
            .iter()
            .all(|row| row.evidence.memory_writebacks.is_empty()),
        "failed pending evidence append must not leave memory writeback evidence rows"
    );
}

#[test]
fn workflow_memory_writeback_final_evidence_failure_leaves_visible_pending_and_retries() {
    let program = parse_inline_starlark_checked(
        r#"
validate = stage(id = "validate", agent = "shell", run = "true")
workflow(
    "workflow-memory-writeback-retry",
    root = validate,
    max_memory_writebacks = 1,
    memory_writebacks = [
        memory_writeback(
            "validation-findings",
            stage = "validate",
            field = "memory_writebacks",
            kinds = ["finding"],
            statuses = ["active"],
            max_objects = 1,
        ),
    ],
)
"#,
        "workflow_memory_writeback_retry.star",
        &[],
    )
    .expect("parse definition");
    let execution_id = Ulid::new();
    let mut validate = assignment("validate", kata_core::AssignmentStatus::Pending, None);
    bind_assignment_to_execution(&mut validate, execution_id);
    let failing_store = Arc::new(FailingUnclaimedEvidenceStore::new(false));
    failing_store.set_fail_memory_writeback_evidence_after_successes(1);
    let rig = ChainRig::with_ledger(failing_store.open_ledger());
    rig.admit(execution_id);
    rig.complete_stage(
        execution_id,
        "validate",
        serde_json::json!({
            "memory_writebacks": [{
                "id": "finding-build",
                "kind": "finding",
                "status": "active",
                "title": "Build proof exists",
                "body": {"summary": "cargo check passed"}
            }]
        }),
    );
    let memory = SqliteNativeMemoryStore::open_in_memory().expect("open memory store");

    let err = persist_workflow_memory_writebacks(&memory, execution_id, &program, &rig.dispatcher)
        .expect_err("final memory writeback evidence failure should surface");
    assert!(
        err.to_string()
            .contains("injected memory writeback evidence append failure"),
        "{err}"
    );
    let findings = memory
        .snapshot(
            Some(MemoryObjectKind::Finding),
            Some(MemoryObjectStatus::Active),
        )
        .expect("snapshot findings");
    assert_eq!(
        findings.object_count, 1,
        "native memory mutation may exist after durable pending evidence"
    );
    let pending_record = execution_record_from_assignments_with_program_and_evidence(
        execution_id,
        "workflow-memory-writeback-retry".to_string(),
        None,
        None,
        kata_workflow::attempt_delivery::AttemptDeliveryMapper::new(std::sync::Arc::clone(
            rig.lifecycle.db(),
        ))
        .execution_assignment_states(execution_id)
        .expect("the chain answers"),
        rig.ledger.execution_evidence_records(execution_id),
    );
    assert_eq!(pending_record.evidence.memory_writebacks.len(), 1);
    assert_eq!(
        pending_record.evidence.memory_writebacks[0].action,
        "pending"
    );

    failing_store.set_fail_memory_writeback_evidence(false);
    let applied =
        persist_workflow_memory_writebacks(&memory, execution_id, &program, &rig.dispatcher)
            .expect("retry should reconcile final memory writeback evidence");
    assert_eq!(
        applied, 0,
        "retry observes the already-applied native memory object"
    );
    let recovered_record = execution_record_from_assignments_with_program_and_evidence(
        execution_id,
        "workflow-memory-writeback-retry".to_string(),
        None,
        None,
        kata_workflow::attempt_delivery::AttemptDeliveryMapper::new(std::sync::Arc::clone(
            rig.lifecycle.db(),
        ))
        .execution_assignment_states(execution_id)
        .expect("the chain answers"),
        rig.ledger.execution_evidence_records(execution_id),
    );
    assert_eq!(recovered_record.evidence.memory_writebacks.len(), 1);
    assert_eq!(
        recovered_record.evidence.memory_writebacks[0].action,
        "applied"
    );
}

#[test]
fn required_workflow_memory_writeback_invalid_row_fails_without_memory_mutation() {
    let program = parse_inline_starlark_checked(
        r#"
validate = stage(id = "validate", agent = "shell", run = "true")
workflow(
    "workflow-memory-writeback-required-invalid",
    root = validate,
    max_memory_writebacks = 1,
    memory_writebacks = [
        memory_writeback(
            "validation-findings",
            stage = "validate",
            field = "memory_writebacks",
            kinds = ["finding"],
            statuses = ["active"],
            max_objects = 1,
            required = True,
        ),
    ],
)
"#,
        "workflow_memory_writeback_required_invalid.star",
        &[],
    )
    .expect("parse definition");
    let execution_id = Ulid::new();
    let mut validate = assignment("validate", kata_core::AssignmentStatus::Pending, None);
    bind_assignment_to_execution(&mut validate, execution_id);
    let rig = ChainRig::new();
    rig.admit(execution_id);
    rig.complete_stage(
        execution_id,
        "validate",
        serde_json::json!({
            "memory_writebacks": [{
                "id": "finding-build",
                "kind": "unsupported_kind",
                "status": "active",
                "title": "Build proof exists"
            }]
        }),
    );
    let memory = SqliteNativeMemoryStore::open_in_memory().expect("open memory store");

    let err = persist_workflow_memory_writebacks(&memory, execution_id, &program, &rig.dispatcher)
        .expect_err("required invalid writeback row must fail terminal writeback phase");
    assert!(
        err.to_string()
            .contains("required memory writeback validation-findings failed for stage validate"),
        "{err}"
    );
    let findings = memory
        .snapshot(
            Some(MemoryObjectKind::Finding),
            Some(MemoryObjectStatus::Active),
        )
        .expect("snapshot findings");
    assert_eq!(findings.object_count, 0);
    let record = execution_record_from_assignments_with_program_and_evidence(
        execution_id,
        "workflow-memory-writeback-required-invalid".to_string(),
        None,
        None,
        kata_workflow::attempt_delivery::AttemptDeliveryMapper::new(std::sync::Arc::clone(
            rig.lifecycle.db(),
        ))
        .execution_assignment_states(execution_id)
        .expect("the chain answers"),
        rig.ledger.execution_evidence_records(execution_id),
    );
    assert_eq!(record.evidence.memory_writebacks.len(), 1);
    assert_eq!(record.evidence.memory_writebacks[0].action, "rejected");
}

#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn required_workflow_memory_writeback_missing_field_marks_execution_failed() {
    let memory = Arc::new(SqliteNativeMemoryStore::open_in_memory().expect("open memory store"));
    let stack = boot_executor_with_library_and_memory_store(
        Arc::new(WorkflowLibrary::new(vec![])),
        None,
        Arc::clone(&memory),
    );
    let executor = Arc::clone(&stack.executor);
    let program = parse_inline_starlark_checked(
        r#"
only = stage(id = "only", prompt = "complete without memory_writebacks", agent = "default")
workflow(
    "workflow-memory-writeback-required-missing",
    root = only,
    max_memory_writebacks = 1,
    memory_writebacks = [
        memory_writeback(
            "validation-findings",
            stage = "only",
            field = "memory_writebacks",
            kinds = ["finding"],
            statuses = ["active"],
            max_objects = 1,
            required = True,
        ),
    ],
)
"#,
        "workflow_memory_writeback_required_missing.star",
        &[],
    )
    .expect("parse definition");
    let id = executor
        .submit_execution_program(program)
        .expect("checked workflow should submit");

    let rec = wait_terminal(&executor, &id).await;
    assert_eq!(rec.status, ExecutionStatus::Failed);
    assert!(
        rec.error
            .as_deref()
            .is_some_and(|error| error.contains("required memory writeback")),
        "expected required memory writeback terminal error, got {:?}",
        rec.error
    );
    assert!(
        rec.evidence
            .memory_writebacks
            .iter()
            .any(|row| row.writeback_id == "validation-findings"
                && row.action == "rejected"
                && row.reason.as_deref().is_some_and(
                    |reason| reason.contains("required memory writeback field missing")
                )),
        "required writeback rejection evidence should be visible: {:?}",
        rec.evidence.memory_writebacks
    );
    let findings = memory
        .snapshot(
            Some(MemoryObjectKind::Finding),
            Some(MemoryObjectStatus::Active),
        )
        .expect("snapshot findings");
    assert_eq!(findings.object_count, 0);
}

/// An accepted agent turn's session-evidence row reaches the OPERATOR RECORD —
/// the same `ExecutionRecord.evidence` `kata run show`, `GET /executions/{id}`
/// and the SDK's `observe` all project — through the production evidence door,
/// on the wire shape the operator parses, and a re-projected row folds to
/// itself rather than duplicating.
#[test]
fn an_agent_turns_session_evidence_is_on_the_record_the_operator_reads() {
    let rig = ChainRig::new();
    let execution_id = Ulid::new();
    rig.admit(execution_id);
    let attempt_id = Ulid::new();
    let turn = kata_types::execution::ExecutionAgentTurnEvidence {
        stage_id: "probe".to_string(),
        attempt_id: attempt_id.to_string(),
        adapter: "nanocode_openai".to_string(),
        model_reported: Some("vendor/small".to_string()),
        session_evidence_artifact_id: ContentHash::new([0x77; 32]).to_string(),
        session_evidence_object_id: "9f86d081884c7d659a2feaa0c55ad015".to_string(),
        session_evidence_size_bytes: 128,
    };
    rig.ledger
        .append_execution_evidence_claimed(
            execution_id,
            "agent_turn:probe",
            ExecutionEvidence {
                agent_turns: vec![turn.clone()],
                ..ExecutionEvidence::default()
            },
        )
        .expect("the evidence door admits the row")
        .expect("the claim is first owner");

    let record = execution_record_from_assignments_with_program_and_evidence(
        execution_id,
        "agent-evidence-surface".to_string(),
        None,
        None,
        kata_workflow::attempt_delivery::AttemptDeliveryMapper::new(std::sync::Arc::clone(
            rig.lifecycle.db(),
        ))
        .execution_assignment_states(execution_id)
        .expect("the chain answers"),
        rig.ledger.execution_evidence_records(execution_id),
    );
    assert_eq!(
        record.evidence.agent_turns,
        vec![turn.clone()],
        "the row the acceptance wrote projects verbatim"
    );

    // The WIRE the operator reads — `kata run show` emits exactly this
    // serialization: `evidence.agent_turns[].session_evidence_*` names the
    // Private CAS blob.
    let wire = serde_json::to_value(&record).expect("the record serializes");
    assert_eq!(
        wire["evidence"]["agent_turns"][0]["session_evidence_object_id"],
        serde_json::json!("9f86d081884c7d659a2feaa0c55ad015"),
        "the blob's object id is on the wire: {wire}"
    );
    assert_eq!(
        wire["evidence"]["agent_turns"][0]["stage_id"],
        serde_json::json!("probe")
    );
    assert_eq!(
        wire["evidence"]["agent_turns"][0]["attempt_id"],
        serde_json::json!(attempt_id.to_string())
    );

    // One accepted attempt writes ONE row; a replay serving it again folds to
    // itself rather than reporting the turn twice.
    rig.ledger
        .append_execution_evidence_claimed(
            execution_id,
            "agent_turn:probe:replay",
            ExecutionEvidence {
                agent_turns: vec![turn],
                ..ExecutionEvidence::default()
            },
        )
        .expect("the replayed row is admitted")
        .expect("a second claim key is owned");
    let record = execution_record_from_assignments_with_program_and_evidence(
        execution_id,
        "agent-evidence-surface".to_string(),
        None,
        None,
        kata_workflow::attempt_delivery::AttemptDeliveryMapper::new(std::sync::Arc::clone(
            rig.lifecycle.db(),
        ))
        .execution_assignment_states(execution_id)
        .expect("the chain answers"),
        rig.ledger.execution_evidence_records(execution_id),
    );
    assert_eq!(
        record.evidence.agent_turns.len(),
        1,
        "one row per accepted attempt, not per evidence row served"
    );
}
