//! The `expansion` operational plane — the durable main-resolved
//! claim/resolve/recovery surface of `crates/core/src/operational/expansion.rs`,
//! exercised against the real SQLite store and read back through a SECOND raw
//! rusqlite handle, never kata's own reader.
//!
//! The cells pin the substrate an `ExpandBounded` (a `loop(..)`, a
//! `topology(..)`, a bounded fanout) resolves through under `oci`: the claim's
//! `pending` main attempt carrying its durable spec, the spec-coherence
//! refusal, the converge/terminal latches that make the claim the
//! double-spend guard, the resolve's acceptance of the expansion occurrence,
//! the pending enumeration a restart re-drives from, and the
//! terminalization drain that cannot leave an expansion `pending` on a
//! published outcome.

use std::sync::Arc;

use kata_core::operational::{
    ExpansionClaimOutcome, ExpansionSpec, JoinFanIn, MainAttemptSpec, MainResolution,
    OccurrenceBinding, expansion_spec,
};
use kata_core::store::cas::CasStore;
use kata_core::{InvocationKind, InvocationRecord, OperationalDb, ProgramRecord, SubmitOutcome};
use kata_types::execution_contract::{OccurrenceRef, OperationContractId, OperationPath};
use kata_types::primitives::ContentHash;
use kata_types::work_tree_head::WorkTreeHeadCoordinate;
use ulid::Ulid;

fn program() -> ProgramRecord {
    ProgramRecord {
        program_hash: ContentHash::new([0xC0; 32]),
        schema_version: 4,
        program_json: b"{}".to_vec(),
    }
}

fn invocation() -> InvocationRecord {
    InvocationRecord {
        schema_version: 1,
        kind: InvocationKind::Workflow,
        admission_digest: kata_types::identity_algebra::AdmissionDigest(ContentHash::new(
            [0xA1; 32],
        )),
        invocation_json: b"{}".to_vec(),
    }
}

struct Rig {
    dir: tempfile::TempDir,
    db: Arc<OperationalDb>,
}

fn rig() -> Rig {
    let dir = tempfile::tempdir().unwrap();
    let cas = Arc::new(CasStore::open(dir.path().join("cas.db"), dir.path().join("cas")).unwrap());
    let db =
        OperationalDb::open_with_cas(dir.path().join("operational.db"), Arc::clone(&cas)).unwrap();
    Rig {
        dir,
        db: Arc::new(db),
    }
}

fn submit(rig: &Rig, execution: Ulid) {
    match rig
        .db
        .submit_execution(execution, &program(), &invocation())
        .unwrap()
    {
        SubmitOutcome::Submitted { .. } | SubmitOutcome::AlreadySubmitted => {}
    }
}

fn raw(rig: &Rig) -> rusqlite::Connection {
    rusqlite::Connection::open(rig.dir.path().join("operational.db"))
        .expect("the raw reader opens the operational db")
}

/// The attempt spec for an `ExpandBounded` claimed at `path` — `stage_id` is
/// the path's `#op/<…>` spelling by construction, matching the coherence the
/// claim checks.
fn spec(execution: Ulid, path: Vec<u32>) -> MainAttemptSpec {
    let path = OperationPath(path);
    MainAttemptSpec {
        stage_id: path.program_operation_stage_id(),
        occurrence: OccurrenceBinding::new(
            OccurrenceRef::new(
                kata_types::workflow::ExecutionId(execution),
                ContentHash::new([0xB7; 32]),
                OperationContractId(ContentHash::new([0x5E; 32])),
                path,
            ),
            None,
            None,
        ),
    }
}

/// A spec coherent with `spec`'s binding BY CONSTRUCTION — `operation` renders
/// the binding's contract id and `path` re-encodes its coordinate — so the
/// positive cells exercise the claim, not its coherence refusal.
fn expansion(spec: &MainAttemptSpec) -> ExpansionSpec {
    ExpansionSpec {
        operation: hex::encode(spec.occurrence.operation_contract_id()),
        path: OperationPath::from_canonical_bytes(&spec.occurrence.operation_path())
            .expect("the fixture binding's path re-decodes"),
        stage: "worker".to_owned(),
        template: vec![OperationPath(vec![1]), OperationPath(vec![2])],
        maximum: 3,
        policy: hex::encode([0x9E; 32]),
    }
}

/// `(executor, projected state, finished?)` for one attempt, read raw.
fn raw_attempt(rig: &Rig, attempt_id: Ulid) -> Option<(String, String, bool)> {
    raw(rig)
        .query_row(
            "SELECT a.executor, p.state, a.finished_at_ms IS NOT NULL
               FROM attempts a
               JOIN attempt_projection p
                 ON p.execution_id = a.execution_id AND p.stage_id = a.stage_id
                AND p.attempt_ordinal = a.attempt_ordinal
              WHERE a.attempt_id = ?1",
            [attempt_id.to_bytes().as_slice()],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, bool>(2)?,
                ))
            },
        )
        .ok()
}

/// The attempt's stored blob, read raw.
fn raw_blob(rig: &Rig, attempt_id: Ulid) -> Option<Vec<u8>> {
    raw(rig)
        .query_row(
            "SELECT assignment_json FROM attempts WHERE attempt_id = ?1",
            [attempt_id.to_bytes().as_slice()],
            |row| row.get::<_, Vec<u8>>(0),
        )
        .ok()
}

/// `(accepted?, accepting attempt)` for the fixture occurrence, read raw.
fn raw_occurrence(rig: &Rig, spec: &MainAttemptSpec) -> Option<(Option<Vec<u8>>,)> {
    raw(rig)
        .query_row(
            "SELECT accepted_attempt_id FROM occurrences WHERE occurrence_id = ?1",
            [spec.occurrence.occurrence_id().as_slice()],
            |row| Ok((row.get::<_, Option<Vec<u8>>>(0)?,)),
        )
        .ok()
}

fn claim(rig: &Rig, execution: Ulid, attempt_id: Ulid, path: Vec<u32>) -> ExpansionClaimOutcome {
    let spec = spec(execution, path);
    rig.db
        .claim_expansion_attempt(attempt_id, &spec, &expansion(&spec))
        .expect("the fixture expansion claims")
}

#[test]
fn an_expansion_claim_writes_a_pending_main_attempt_carrying_its_spec() {
    let rig = rig();
    let execution = Ulid::new();
    submit(&rig, execution);
    let attempt = Ulid::new();
    let spec = spec(execution, vec![0]);
    let expansion = expansion(&spec);

    let outcome = rig
        .db
        .claim_expansion_attempt(attempt, &spec, &expansion)
        .expect("claim");
    assert!(
        matches!(outcome, ExpansionClaimOutcome::Claimed { claim_seq } if claim_seq > 0),
        "a fresh claim reports the claiming transition, got {outcome:?}"
    );

    let (executor, state, finished) = raw_attempt(&rig, attempt).expect("the attempt row exists");
    assert_eq!(executor, "main");
    assert_eq!(state, "pending");
    assert!(!finished);
    assert_eq!(
        expansion_spec(&raw_blob(&rig, attempt).expect("the blob persists"))
            .expect("the stored spec decodes"),
        Some(expansion),
        "the claim's own durable spec rides the row"
    );
    let (accepted,) = raw_occurrence(&rig, &spec).expect("the occurrence minted");
    assert!(accepted.is_none(), "a claimed expansion accepts nothing");
}

#[test]
fn an_expansion_claim_converges_on_a_live_attempt() {
    let rig = rig();
    let execution = Ulid::new();
    submit(&rig, execution);
    let first = Ulid::new();
    claim(&rig, execution, first, vec![0]);

    let outcome = rig
        .db
        .claim_expansion_attempt(
            Ulid::new(),
            &spec(execution, vec![0]),
            &expansion(&spec(execution, vec![0])),
        )
        .expect("a convergent claim is not an error");
    assert_eq!(
        outcome,
        ExpansionClaimOutcome::AlreadyLive {
            attempt_id: first,
            state: "pending".to_owned()
        }
    );
    let count: i64 = raw(&rig)
        .query_row(
            "SELECT count(*) FROM attempts WHERE stage_id = '#op/0'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(count, 1, "convergence mints no second attempt");
}

#[test]
fn an_expansion_claim_converges_on_the_accepted_occurrence() {
    let rig = rig();
    let execution = Ulid::new();
    submit(&rig, execution);
    let first = Ulid::new();
    claim(&rig, execution, first, vec![0]);
    rig.db
        .resolve_expansion_attempt(
            first,
            &MainResolution::Complete {
                output: &serde_json::json!({"expansion": {"resolution": "approved"}}),
            },
        )
        .expect("the resolve lands");

    let spec = spec(execution, vec![0]);
    let outcome = rig
        .db
        .claim_expansion_attempt(Ulid::new(), &spec, &expansion(&spec))
        .expect("converging on an accepted occurrence is not an error");
    assert_eq!(
        outcome,
        ExpansionClaimOutcome::AlreadyAccepted { attempt_id: first }
    );
}

#[test]
fn a_failed_expansion_is_the_recorded_verdict_not_a_re_drive() {
    let rig = rig();
    let execution = Ulid::new();
    submit(&rig, execution);
    let first = Ulid::new();
    claim(&rig, execution, first, vec![0]);
    rig.db
        .resolve_expansion_attempt(
            first,
            &MainResolution::Fail {
                reason: "member 2 failed",
                terminal_charge: None,
            },
        )
        .expect("the failed resolution lands");

    let spec = spec(execution, vec![0]);
    let outcome = rig
        .db
        .claim_expansion_attempt(Ulid::new(), &spec, &expansion(&spec))
        .expect("the recorded verdict is an outcome, not an error");
    assert_eq!(
        outcome,
        ExpansionClaimOutcome::RecordedTerminal {
            attempt_id: first,
            state: "failed".to_owned()
        },
        "a terminal expansion attempt at the coordinate is the adjudicated answer"
    );
    let count: i64 = raw(&rig)
        .query_row(
            "SELECT count(*) FROM attempts WHERE stage_id = '#op/0'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(count, 1, "no second generation is minted over the verdict");
}

#[test]
fn a_completed_resolution_accepts_the_occurrence_once() {
    let rig = rig();
    let execution = Ulid::new();
    submit(&rig, execution);
    let attempt = Ulid::new();
    let spec = spec(execution, vec![0]);
    claim(&rig, execution, attempt, vec![0]);

    let output = serde_json::json!({"expansion": {"resolution": "exhausted", "on_max": "accept"}});
    let seq = rig
        .db
        .resolve_expansion_attempt(attempt, &MainResolution::Complete { output: &output })
        .expect("resolve")
        .expect("a pending attempt resolves");
    assert!(seq > 0);

    let (_, state, finished) = raw_attempt(&rig, attempt).expect("the row");
    assert_eq!(state, "completed");
    assert!(finished);
    let (accepted,) = raw_occurrence(&rig, &spec).expect("the occurrence row");
    assert_eq!(
        accepted.as_deref(),
        Some(attempt.to_bytes().as_slice()),
        "the resolving attempt accepts the expansion occurrence"
    );
    assert_eq!(
        rig.db
            .accepted_attempt_output(execution, attempt)
            .expect("the accepted output reads"),
        Some(output.clone()),
        "the expansion record rides the accepted output"
    );

    // A lapsed premise writes nothing — a recovery re-resolve converges.
    assert_eq!(
        rig.db
            .resolve_expansion_attempt(attempt, &MainResolution::Complete { output: &output })
            .expect("a re-resolve is not an error"),
        None
    );
}

#[test]
fn an_incoherent_spec_is_refused_and_writes_nothing() {
    let rig = rig();
    let execution = Ulid::new();
    submit(&rig, execution);

    for mutate in ["operation", "path", "stage_id"] {
        let attempt = Ulid::new();
        let mut spec = spec(execution, vec![0]);
        let mut expansion = expansion(&spec);
        match mutate {
            "operation" => expansion.operation = hex::encode([0xFF; 32]),
            "path" => expansion.path = OperationPath(vec![9]),
            "stage_id" => spec.stage_id = "worker".to_owned(),
            _ => unreachable!(),
        }
        let error = rig
            .db
            .claim_expansion_attempt(attempt, &spec, &expansion)
            .expect_err("a spec disagreeing with its binding is refused");
        assert!(
            error.to_string().contains("refuses the expansion spec"),
            "{mutate}: the refusal names itself: {error}"
        );
        assert!(
            raw_attempt(&rig, attempt).is_none(),
            "{mutate}: the refused claim wrote no attempt row"
        );
    }
}

#[test]
fn a_capsule_binding_is_refused_for_an_expansion() {
    let rig = rig();
    let execution = Ulid::new();
    submit(&rig, execution);
    let attempt = Ulid::new();
    let path = OperationPath(vec![0]);
    let spec = MainAttemptSpec {
        stage_id: path.program_operation_stage_id(),
        occurrence: OccurrenceBinding::new(
            OccurrenceRef::new(
                kata_types::workflow::ExecutionId(execution),
                ContentHash::new([0xB7; 32]),
                OperationContractId(ContentHash::new([0x5E; 32])),
                path,
            ),
            None,
            Some(kata_types::execution_contract::CapsuleId(ContentHash::new(
                [0x07; 32],
            ))),
        ),
    };
    let error = rig
        .db
        .claim_expansion_attempt(attempt, &spec, &expansion(&spec))
        .expect_err("an expansion is main-resolved; a capsule binding is a worker fact");
    assert!(
        error.to_string().contains("capsule"),
        "the capsule refusal names itself: {error}"
    );
    assert!(raw_attempt(&rig, attempt).is_none());
}

#[test]
fn pending_expansion_attempts_enumerate_specs_not_other_main_attempts() {
    let rig = rig();
    let execution = Ulid::new();
    submit(&rig, execution);
    let first = Ulid::new();
    let second = Ulid::new();
    claim(&rig, execution, first, vec![0]);
    claim(&rig, execution, second, vec![1]);
    // A parked main WAIT at another coordinate is not an expansion: it must
    // not be enumerated.
    let parked = Ulid::new();
    let wait_spec = spec(execution, vec![7]);
    rig.db
        .claim_main_attempt(
            parked,
            &wait_spec,
            kata_core::operational::MainWait::Timer(kata_types::wait::WaitDeadline::AfterClaim {
                delay_ms: 60_000,
            }),
        )
        .expect("the timer wait claims parked");

    let pending = rig
        .db
        .pending_expansion_attempts(execution)
        .expect("enumerate");
    assert_eq!(
        pending.iter().map(|p| p.attempt_id).collect::<Vec<_>>(),
        vec![first, second],
        "exactly the pending expansions, in claim order"
    );
    assert_eq!(pending[0].spec, expansion(&spec(execution, vec![0])));
    assert_eq!(pending[1].spec, expansion(&spec(execution, vec![1])));
    assert_eq!(pending[0].stage_id, "#op/0");
    assert_eq!(pending[1].stage_id, "#op/1");

    // A resolved expansion leaves the enumeration — the live set is what a
    // restart re-drives.
    rig.db
        .resolve_expansion_attempt(
            first,
            &MainResolution::Complete {
                output: &serde_json::json!({"expansion": {"resolution": "approved"}}),
            },
        )
        .unwrap();
    let pending = rig.db.pending_expansion_attempts(execution).unwrap();
    assert_eq!(
        pending.iter().map(|p| p.attempt_id).collect::<Vec<_>>(),
        vec![second]
    );
}

#[test]
fn an_expansion_pending_at_terminalization_is_settled_cancelled() {
    let rig = rig();
    let execution = Ulid::new();
    submit(&rig, execution);
    let attempt = Ulid::new();
    claim(&rig, execution, attempt, vec![0]);

    rig.db
        .begin_terminalization(
            execution,
            kata_core::LifecycleState::Cancelled,
            b"{\"reason\":\"operator cancel\"}",
        )
        .expect("the terminalizing latch lands");
    // Latched, not yet published: the runner still owes the expansion its end,
    // so the enumeration it drives from still reads it.
    assert_eq!(
        rig.db
            .pending_expansion_attempts(execution)
            .unwrap()
            .iter()
            .map(|pending| pending.attempt_id)
            .collect::<Vec<_>>(),
        vec![attempt],
        "a latched execution's pending expansion is still driven"
    );
    rig.db
        .finish_terminalization(execution)
        .expect("the drain settles the pending expansion in the publishing commit");

    let (_, state, finished) = raw_attempt(&rig, attempt).expect("the row");
    assert_eq!(
        state, "cancelled",
        "a pending expansion never reads `pending` on a terminal execution"
    );
    assert!(finished);
    assert!(
        rig.db
            .pending_expansion_attempts(execution)
            .unwrap()
            .is_empty(),
        "a published execution's expansions are settled, none left to drive"
    );
}

#[test]
fn a_claim_in_a_terminal_execution_is_refused_by_name() {
    let rig = rig();
    let execution = Ulid::new();
    submit(&rig, execution);
    rig.db
        .begin_terminalization(
            execution,
            kata_core::LifecycleState::Cancelled,
            b"{\"reason\":\"operator cancel\"}",
        )
        .unwrap();
    rig.db.finish_terminalization(execution).unwrap();

    let attempt = Ulid::new();
    let spec = spec(execution, vec![0]);
    let error = rig
        .db
        .claim_expansion_attempt(attempt, &spec, &expansion(&spec))
        .expect_err("nothing is claimed after the outcome is published");
    assert!(
        error
            .to_string()
            .contains("main_resolution_execution_terminal"),
        "the refusal is named: {error}"
    );
    assert!(raw_attempt(&rig, attempt).is_none());
}

#[test]
fn a_claim_under_terminalization_refuses_at_the_claim_write() {
    let rig = rig();
    let execution = Ulid::new();
    submit(&rig, execution);
    rig.db
        .begin_terminalization_with_cleanup(
            execution,
            kata_core::LifecycleState::Cancelled,
            &serde_json::to_vec(&serde_json::json!({"reason": "operator cancel"})).unwrap(),
            "converge_absent",
        )
        .expect("the terminalizing latch lands");

    let attempt = Ulid::new();
    let spec = spec(execution, vec![0]);
    let error = rig
        .db
        .claim_expansion_attempt(attempt, &spec, &expansion(&spec))
        .expect_err("a claim under terminalizing refuses by name");
    assert!(
        error.to_string().contains("claim_after_terminal_intent"),
        "the terminalizing refusal is named: {error}"
    );
    assert!(raw_attempt(&rig, attempt).is_none());
}

#[test]
fn a_worker_attempt_is_not_an_expansion_resolution_target() {
    let rig = rig();
    let execution = Ulid::new();
    submit(&rig, execution);
    let worker = Ulid::new();
    rig.db
        .claim_attempt(
            execution,
            worker,
            &kata_core::operational::AttemptClaimSpec {
                stage_id: "build".to_owned(),
                assignment_json: b"{\"capsule\":{\"stage_name\":\"build\"}}".to_vec(),
                initial_state: "pending".to_owned(),
                run_ordinal: 0,
                worker_id: None,
                occurrence: OccurrenceBinding::for_test(execution, "build"),
            },
        )
        .expect("a worker attempt claims");
    let error = rig
        .db
        .resolve_expansion_attempt(
            worker,
            &MainResolution::Complete {
                output: &serde_json::json!({}),
            },
        )
        .expect_err("a worker attempt cannot resolve through the main door");
    assert!(
        error.to_string().contains("executor"),
        "the executor refusal names itself: {error}"
    );
}

#[test]
fn an_expansion_may_not_be_claimed_and_resolved_in_one_transaction() {
    let rig = rig();
    let execution = Ulid::new();
    submit(&rig, execution);
    let attempt = Ulid::new();
    let spec = spec(execution, vec![0]);
    // The atomic door is for operations whose resolution needs no outside fact;
    // an expansion resolves on member acceptances that cannot exist inside its
    // own claiming transaction, so it is refused by name like the wait kinds.
    let error = rig
        .db
        .claim_and_resolve_main_attempt(
            attempt,
            &spec,
            kata_core::operational::MainOperation::Expansion,
            &MainResolution::Complete {
                output: &serde_json::json!({"expansion": {}}),
            },
        )
        .expect_err("an expansion resolves on facts its claiming transaction cannot hold");
    assert!(
        error.to_string().contains("claim and resolve"),
        "the refusal is named: {error}"
    );
    assert!(raw_attempt(&rig, attempt).is_none());
}

const PRINCIPAL: kata_types::approval::ApprovalPrincipal =
    kata_types::approval::ApprovalPrincipal::UnauthenticatedLoopback;

/// The `Exhausted { on_max: Escalate }` record a bound-spent loop's park
/// carries — the exact JSON an `approve` resolves the gate `completed` with.
fn escalate_record(spec: &MainAttemptSpec) -> serde_json::Value {
    serde_json::json!({
        "expansion": {
            "operation": hex::encode(spec.occurrence.operation_contract_id()),
            "path": spec.stage_id,
            "stage": "worker",
            "resolution": {"outcome": "exhausted", "iterations": 2, "on_max": "escalate"},
            "members": [{"iteration": 0, "member": 0, "stage": "worker",
                          "occurrence": hex::encode([0x11; 32])}],
            "verdicts": [{"iteration": 0, "verdict": "refine", "feedback": "more"},
                          {"iteration": 1, "verdict": "refine", "feedback": "still more"}]
        }
    })
}

#[test]
fn an_approved_expansion_gate_resolves_completed_with_the_parked_record() {
    let rig = rig();
    let execution = Ulid::new();
    submit(&rig, execution);
    rig.db.mark_running(execution).unwrap();
    let attempt = Ulid::new();
    let spec = spec(execution, vec![0]);
    claim(&rig, execution, attempt, vec![0]);
    let record = escalate_record(&spec);
    rig.db
        .park_expansion_attempt(attempt, "loop bound spent under escalate", &record)
        .unwrap();

    // The operator's gate list names the loop and the record it would adopt.
    let gates = rig.db.parked_expansion_gates(execution).unwrap();
    assert_eq!(gates.len(), 1);
    assert_eq!(gates[0].attempt_id, attempt);
    assert_eq!(gates[0].spec.stage, "worker");
    assert_eq!(gates[0].spec.maximum, 3);
    assert_eq!(
        gates[0].record, record,
        "the gate carries the decision it would adopt"
    );

    let approve = kata_core::operational::ExpansionApprovalDecision {
        principal: &PRINCIPAL,
        verdict: kata_core::operational::ExpansionVerdict::Approve,
    };
    let outcome = rig
        .db
        .decide_expansion_approval(attempt, &approve)
        .expect("the parked gate approves");
    assert!(
        matches!(
            outcome,
            kata_core::operational::CapsuleApprovalOutcome::Approved { .. }
        ),
        "the decision records approved: {outcome:?}"
    );
    let (_, state, finished) = raw_attempt(&rig, attempt).expect("the row");
    assert_eq!(state, "completed");
    assert!(finished);
    let (accepted,) = raw_occurrence(&rig, &spec).expect("the occurrence row");
    assert_eq!(
        accepted.as_deref(),
        Some(attempt.to_bytes().as_slice()),
        "the adopted decision accepts the expansion occurrence"
    );
    assert_eq!(
        rig.db.accepted_attempt_output(execution, attempt).unwrap(),
        Some(record),
        "the accepted output is byte-for-byte the record the park carried"
    );

    // Write-once: same verdict replays, the opposite refuses by name.
    let outcome = rig
        .db
        .decide_expansion_approval(attempt, &approve)
        .expect("the recorded approve replays");
    assert!(matches!(
        outcome,
        kata_core::operational::CapsuleApprovalOutcome::AlreadyApproved
    ));
    let reject = kata_core::operational::ExpansionApprovalDecision {
        principal: &PRINCIPAL,
        verdict: kata_core::operational::ExpansionVerdict::Reject { reason: "no" },
    };
    let err = rig
        .db
        .decide_expansion_approval(attempt, &reject)
        .expect_err("an approved gate refuses the opposite verdict");
    assert!(
        err.to_string().contains("approval_already_decided"),
        "{err}"
    );
}

#[test]
fn a_rejected_expansion_gate_resolves_failed_with_the_operators_reason() {
    let rig = rig();
    let execution = Ulid::new();
    submit(&rig, execution);
    rig.db.mark_running(execution).unwrap();
    let attempt = Ulid::new();
    let spec = spec(execution, vec![0]);
    claim(&rig, execution, attempt, vec![0]);
    rig.db
        .park_expansion_attempt(
            attempt,
            "loop bound spent under escalate",
            &escalate_record(&spec),
        )
        .unwrap();

    let reject = kata_core::operational::ExpansionApprovalDecision {
        principal: &PRINCIPAL,
        verdict: kata_core::operational::ExpansionVerdict::Reject {
            reason: "no good, restart workflow",
        },
    };
    let outcome = rig
        .db
        .decide_expansion_approval(attempt, &reject)
        .expect("the parked gate rejects");
    assert!(
        matches!(
            outcome,
            kata_core::operational::CapsuleApprovalOutcome::Rejected { .. }
        ),
        "{outcome:?}"
    );
    let (_, state, finished) = raw_attempt(&rig, attempt).expect("the row");
    assert_eq!(state, "failed");
    assert!(finished);
    let (accepted,) = raw_occurrence(&rig, &spec).expect("the occurrence row");
    assert!(
        accepted.is_none(),
        "a rejected gate accepts no occurrence — the loop is failed, not adopted"
    );
    assert_eq!(
        rig.db.attempt_terminal_reason(attempt).unwrap().as_deref(),
        Some("rejected: no good, restart workflow")
    );

    // Write-once in the other direction too.
    let outcome = rig
        .db
        .decide_expansion_approval(attempt, &reject)
        .expect("the recorded reject replays");
    assert!(matches!(
        outcome,
        kata_core::operational::CapsuleApprovalOutcome::AlreadyRejected
    ));
    let approve = kata_core::operational::ExpansionApprovalDecision {
        principal: &PRINCIPAL,
        verdict: kata_core::operational::ExpansionVerdict::Approve,
    };
    let err = rig
        .db
        .decide_expansion_approval(attempt, &approve)
        .expect_err("a rejected gate refuses the opposite verdict");
    assert!(
        err.to_string().contains("approval_already_decided"),
        "{err}"
    );
}

#[test]
fn decide_expansion_approval_refuses_what_is_not_a_parked_gate() {
    let rig = rig();
    let execution = Ulid::new();
    submit(&rig, execution);
    rig.db.mark_running(execution).unwrap();
    let approve = kata_core::operational::ExpansionApprovalDecision {
        principal: &PRINCIPAL,
        verdict: kata_core::operational::ExpansionVerdict::Approve,
    };

    // No such attempt.
    let err = rig
        .db
        .decide_expansion_approval(Ulid::new(), &approve)
        .expect_err("an unknown attempt refuses by name");
    assert!(
        err.to_string().contains("approval_gate_not_parked"),
        "{err}"
    );

    // A pending (never parked) expansion attempt.
    let pending = Ulid::new();
    claim(&rig, execution, pending, vec![0]);
    let err = rig
        .db
        .decide_expansion_approval(pending, &approve)
        .expect_err("a still-driving expansion is no parked gate");
    assert!(
        err.to_string().contains("approval_gate_not_parked"),
        "{err}"
    );

    // A non-expansion main attempt parked awaiting approval — a parked main
    // wait is not this door's gate.
    let worker = Ulid::new();
    rig.db
        .claim_attempt(
            execution,
            worker,
            &kata_core::operational::AttemptClaimSpec {
                stage_id: "build".to_owned(),
                assignment_json: b"{\"capsule\":{\"stage_name\":\"build\"}}".to_vec(),
                initial_state: "pending".to_owned(),
                run_ordinal: 0,
                worker_id: None,
                occurrence: OccurrenceBinding::for_test(execution, "build"),
            },
        )
        .expect("a worker attempt claims");
    let err = rig
        .db
        .decide_expansion_approval(worker, &approve)
        .expect_err("a worker attempt is no expansion gate");
    assert!(
        err.to_string().contains("approval_gate_not_parked"),
        "{err}"
    );

    // A first decision while the execution is not running.
    let other = Ulid::new();
    submit(&rig, other);
    let attempt = Ulid::new();
    rig.db
        .claim_expansion_attempt(
            attempt,
            &spec(other, vec![0]),
            &expansion(&spec(other, vec![0])),
        )
        .unwrap();
    rig.db
        .park_expansion_attempt(
            attempt,
            "loop bound spent under escalate",
            &escalate_record(&spec(other, vec![0])),
        )
        .unwrap();
    let err = rig
        .db
        .decide_expansion_approval(attempt, &approve)
        .expect_err("a parked gate under `admitting` refuses by name");
    assert!(
        err.to_string().contains("approval_execution_not_running"),
        "{err}"
    );
}

#[test]
fn a_parked_expansion_gate_leaves_the_live_set_and_refuses_non_pendings() {
    let rig = rig();
    let execution = Ulid::new();
    submit(&rig, execution);
    let attempt = Ulid::new();
    claim(&rig, execution, attempt, vec![0]);

    let seq = rig
        .db
        .park_expansion_attempt(
            attempt,
            "loop bound spent under escalate",
            &escalate_record(&spec(execution, vec![0])),
        )
        .expect("a pending expansion parks")
        .expect("the park writes a transition");
    assert!(seq > 0);
    let (_, state, finished) = raw_attempt(&rig, attempt).expect("the row");
    assert_eq!(state, "awaiting_approval");
    assert!(!finished);
    assert!(
        rig.db
            .pending_expansion_attempts(execution)
            .unwrap()
            .is_empty(),
        "a parked gate is not re-driven — it moves only on the operator's decision"
    );

    // The parked FRAME carries the reason, the record an approve adopts, and
    // the `delivery` snapshot every main-side frame carries — without it the
    // replay's durable-facts decode refuses the frame.
    let park_payload: serde_json::Value = raw(&rig)
        .query_row(
            "SELECT payload_json FROM transitions
              WHERE attempt_id = ?1 AND resulting_state = 'awaiting_approval'
              ORDER BY seq DESC LIMIT 1",
            [attempt.to_bytes().as_slice()],
            |row| row.get::<_, Vec<u8>>(0),
        )
        .map(|bytes| serde_json::from_slice(&bytes).expect("the park frame is JSON"))
        .expect("the park frame row reads");
    assert_eq!(
        park_payload["reason"].as_str(),
        Some("loop bound spent under escalate")
    );
    assert_eq!(park_payload["expansion_gate"], serde_json::json!(true));
    assert!(
        park_payload["record"]["expansion"]["resolution"]["on_max"].as_str() == Some("escalate"),
        "the park carries the record its approve adopts: {park_payload}"
    );
    assert!(
        park_payload["delivery"]["awaiting_approval_at_ms"].is_number(),
        "the parked frame carries the finalized delivery snapshot: {park_payload}"
    );

    // A lapsed premise converges: the park over `awaiting_approval` writes
    // nothing and answers None.
    assert_eq!(
        rig.db
            .park_expansion_attempt(
                attempt,
                "again",
                &escalate_record(&spec(execution, vec![0])),
            )
            .expect("a convergent park is not an error"),
        None
    );

    // A resolved expansion cannot park either — the verdict stands.
    let resolved = Ulid::new();
    claim(&rig, execution, resolved, vec![1]);
    rig.db
        .resolve_expansion_attempt(
            resolved,
            &MainResolution::Complete {
                output: &serde_json::json!({"expansion": {"resolution": "approved"}}),
            },
        )
        .unwrap();
    assert_eq!(
        rig.db
            .park_expansion_attempt(
                resolved,
                "too late",
                &escalate_record(&spec(execution, vec![1])),
            )
            .expect("a resolved attempt's park converges"),
        None
    );
}

#[test]
fn park_expansion_attempt_refuses_by_name_what_it_cannot_hold() {
    let rig = rig();
    let execution = Ulid::new();
    submit(&rig, execution);
    let attempt = Ulid::new();
    claim(&rig, execution, attempt, vec![0]);

    // A blank reason is refused before the transaction opens — a parked gate
    // exists to be read.
    let error = rig
        .db
        .park_expansion_attempt(attempt, "   ", &escalate_record(&spec(execution, vec![0])))
        .expect_err("a gate with nothing to say is a driver mistake");
    assert!(error.to_string().contains("empty"), "{error}");
    let (_, state, _) = raw_attempt(&rig, attempt).expect("the row");
    assert_eq!(state, "pending", "the refused park wrote nothing");

    // A gate with no record to adopt is the same category of mistake.
    let error = rig
        .db
        .park_expansion_attempt(attempt, "reason", &serde_json::Value::Null)
        .expect_err("a gate carrying no decision cannot park");
    assert!(error.to_string().contains("null"), "{error}");

    // An unknown attempt.
    let error = rig
        .db
        .park_expansion_attempt(
            Ulid::new(),
            "reason",
            &escalate_record(&spec(execution, vec![9])),
        )
        .expect_err("an attempt that does not exist cannot park");
    assert!(error.to_string().contains("no attempt"), "{error}");

    // A worker attempt is a category error, not a lapsed premise.
    let worker = Ulid::new();
    rig.db
        .claim_attempt(
            execution,
            worker,
            &kata_core::operational::AttemptClaimSpec {
                stage_id: "build".to_owned(),
                assignment_json: b"{\"capsule\":{\"stage_name\":\"build\"}}".to_vec(),
                initial_state: "pending".to_owned(),
                run_ordinal: 0,
                worker_id: None,
                occurrence: OccurrenceBinding::for_test(execution, "build"),
            },
        )
        .expect("a worker attempt claims");
    let error = rig
        .db
        .park_expansion_attempt(
            worker,
            "reason",
            &escalate_record(&spec(execution, vec![8])),
        )
        .expect_err("a worker attempt cannot hold a main-resolved gate");
    assert!(error.to_string().contains("worker attempt"), "{error}");
}

#[test]
fn the_spec_decoder_refuses_a_missing_spec_and_skips_non_expansions() {
    // A `main` blob of another operation is not an expansion.
    let join = serde_json::json!({"main": {"operation": "join"}})
        .to_string()
        .into_bytes();
    assert_eq!(expansion_spec(&join).unwrap(), None);
    // A worker blob likewise.
    let worker = br#"{"capsule":{"stage_name":"build"}}"#.to_vec();
    assert_eq!(expansion_spec(&worker).unwrap(), None);
    // An `expansion` blob carrying no `spec` is a stored-record fault — the
    // claim writes it.
    let bare = serde_json::json!({"main": {"operation": "expansion"}})
        .to_string()
        .into_bytes();
    let error = expansion_spec(&bare).expect_err("a spec-less expansion row is corrupt");
    assert!(error.to_string().contains("carries no spec"), "{error}");
    // Garbage is a fault, not a miss.
    assert!(expansion_spec(b"not json").is_err());
}

/// **The merging settle refuses a non-object output and resolves an
/// object once.** `resolve_expansion_attempt_merging` adds the merged delta as a
/// KEY beside the record, so a non-object output is refused with nothing written;
/// an object resolves the pending attempt `completed` (no `/work` state here, so the
/// merge is `Unchanged` and no delta key is added); a re-resolve of the lapsed
/// premise answers `None`.
///
/// **Would red if:** the object guard were inverted (the nightly mutation sample's
/// `delete !` survivor) — the object output is refused and the attempt stays pending.
#[test]
fn the_merging_settle_refuses_a_non_object_and_resolves_an_object_once() {
    let rig = rig();
    let execution = Ulid::new();
    submit(&rig, execution);
    let attempt = Ulid::new();
    let spec = spec(execution, vec![0]);
    claim(&rig, execution, attempt, vec![0]);
    let fanin = JoinFanIn {
        parent: WorkTreeHeadCoordinate::root(),
        inputs: Vec::new(),
    };

    let refusal = rig
        .db
        .resolve_expansion_attempt_merging(attempt, &serde_json::json!("not a record"), &fanin)
        .expect_err("a non-object output is refused");
    assert!(
        refusal.to_string().contains("non-object output"),
        "refused by name: {refusal}"
    );
    let (_, state, _) = raw_attempt(&rig, attempt).expect("the row");
    assert_eq!(state, "pending", "the refusal wrote nothing");

    let output = serde_json::json!({"expansion": {"resolution": "settled"}});
    let seq = rig
        .db
        .resolve_expansion_attempt_merging(attempt, &output, &fanin)
        .expect("resolve")
        .expect("a pending attempt resolves");
    assert!(seq > 0);
    let (_, state, finished) = raw_attempt(&rig, attempt).expect("the row");
    assert_eq!((state.as_str(), finished), ("completed", true));
    let (accepted,) = raw_occurrence(&rig, &spec).expect("the occurrence row");
    assert_eq!(accepted.as_deref(), Some(attempt.to_bytes().as_slice()));
    assert_eq!(
        rig.db
            .accepted_attempt_output(execution, attempt)
            .expect("the accepted output reads"),
        Some(output.clone()),
        "no /work state: the record is accepted verbatim, no delta key"
    );
    assert_eq!(
        rig.db
            .resolve_expansion_attempt_merging(attempt, &output, &fanin)
            .expect("a re-resolve is not an error"),
        None,
        "a lapsed premise answers None"
    );
}
