//! The capsule APPROVAL DOOR on the operational plane, observed
//! through a SECOND raw rusqlite handle.
//!
//! Every durable assertion reads `operational.db` through a read-only connection this
//! file opens itself; the typed readers are the subject, never the witness.
//!
//! The gate is parked through the production verb
//! (`OperationalDb::claim_attempt_parked_for_approval`) over a capsule DECLARED through
//! the production verbs, so the door reads a plane the authorization built.

use std::path::Path;
use std::sync::Arc;

use kata_core::operational::{
    APPROVAL_ALREADY_DECIDED, APPROVAL_DECISION_REQUIRED, APPROVAL_EXECUTION_NOT_RUNNING,
    APPROVAL_GATE_ALREADY_LIVE, APPROVAL_GATE_NOT_PARKED, ApprovalVerdict, ApprovedDispatch,
    ArtifactDeclaration, AttemptClaimSpec, CapsuleApprovalDecision, CapsuleApprovalOutcome,
    CapsuleDeclaration, CasRootOwner, OccurrenceBinding, approval_decision_key,
};
use kata_core::store::cas::CasStore;
use kata_core::{CommandSpec, InvocationKind, InvocationRecord, OperationalDb, ProgramRecord};
use kata_types::approval::ApprovalPrincipal;
use kata_types::execution_contract::{
    ArtifactPrivacy, ArtifactRef, Capsule, CapsuleBudgets, CapsuleNetwork, CapsuleProcess,
    EnvironmentId, GuestAccess, GuestMapping, GuestPath, OccurrenceRef, OperationContractId,
    OperationPath, PlatformId, PreparedActionId,
};
use kata_types::idempotency::canonicalize_args;
use kata_types::identity_algebra::AdmissionDigest;
use kata_types::primitives::ContentHash;
use kata_types::workflow::ExecutionId;
use ulid::Ulid;

const ENVIRONMENT_ID: [u8; 32] = [0x5A; 32];
const STAGE_ULID: &str = "01JZZZZZZZZZZZZZZZZZZZZZE1";
const PROGRAM_HASH: [u8; 32] = [0xB1; 32];
const REASON: &str = "Protected action: approve before it runs";

/// A capsule-arm at-rest frame, spelled by hand: `kata-core` does not see `DispatchFrame`.
const CAPSULE_FRAME: &[u8] = br#"{"capsule":{"attempt_id":"01JZZZZZZZZZZZZZZZZZZZZZH1",
    "occurrence_id":"0101010101010101010101010101010101010101010101010101010101010101",
    "capsule":{"id":"0202020202020202020202020202020202020202020202020202020202020202",
    "object":"0303030303030303030303030303030303030303030303030303030303030303",
    "size_bytes":512},"lease_epoch":0}}"#;

struct Gate {
    _dir: tempfile::TempDir,
    op_path: std::path::PathBuf,
    cas: Arc<CasStore>,
    db: Arc<OperationalDb>,
    attempt_id: Ulid,
    occurrence: OccurrenceRef,
    capsule: Capsule,
}

fn raw(path: &Path) -> rusqlite::Connection {
    rusqlite::Connection::open_with_flags(
        path,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .unwrap()
}

fn count(gate: &Gate, sql: &str) -> i64 {
    raw(&gate.op_path)
        .query_row(sql, [], |row| row.get(0))
        .unwrap()
}

fn program() -> ProgramRecord {
    let program_hash = ContentHash::new(PROGRAM_HASH);
    ProgramRecord {
        program_hash,
        schema_version: 4,
        program_json: canonicalize_args(&serde_json::json!({
            "schema_version": 4,
            "program_hash": program_hash.to_string(),
        })),
    }
}

fn invocation() -> InvocationRecord {
    let invocation_json = canonicalize_args(&serde_json::json!({
        "schema_version": 1,
        "kind": "workflow",
    }));
    InvocationRecord {
        schema_version: 1,
        kind: InvocationKind::Workflow,
        admission_digest: AdmissionDigest(ContentHash::new(
            *blake3::hash(&invocation_json).as_bytes(),
        )),
        invocation_json,
    }
}

/// Submit, declare the `/work` artifact, the environment and the capsule through the
/// production verbs, then PARK one attempt at the capsule's occurrence.
fn parked_gate() -> Gate {
    let dir = tempfile::tempdir().unwrap();
    let op_path = dir.path().join("operational.db");
    let cas = Arc::new(CasStore::open(dir.path().join("cas.db"), dir.path().join("cas")).unwrap());
    let db = Arc::new(OperationalDb::open_with_cas(&op_path, Arc::clone(&cas)).unwrap());
    let execution_id = Ulid::new();
    db.submit_execution(execution_id, &program(), &invocation())
        .unwrap();
    db.mark_running(execution_id).unwrap();

    let input = cas.put_durable(b"approval-fixture-work-tree").unwrap();
    let input_ref = ArtifactRef::new(input.object_id(), input.size(), ArtifactPrivacy::Private);
    db.declare_artifact(
        &ArtifactDeclaration::for_durable_object(
            &input_ref,
            CasRootOwner::Execution(execution_id),
            &input,
        )
        .unwrap(),
    )
    .unwrap();
    let manifest = cas.put_durable(b"approval-fixture-environment").unwrap();
    db.declare_environment(
        &kata_core::operational::EnvironmentDeclaration::for_staged_root(
            ENVIRONMENT_ID,
            &manifest,
            [0x5C; 32],
            "approval-fixture",
            [0x04; 32],
            STAGE_ULID,
        )
        .unwrap(),
    )
    .unwrap();

    let occurrence = OccurrenceRef::new(
        ExecutionId(execution_id),
        ContentHash::new(PROGRAM_HASH),
        OperationContractId(ContentHash::new([0x6C; 32])),
        OperationPath(vec![0]),
    );
    let capsule = Capsule::new(
        occurrence.id(),
        PreparedActionId(ContentHash::new([0x02; 32])),
        EnvironmentId(ContentHash::new(ENVIRONMENT_ID)),
        PlatformId(ContentHash::new([0x04; 32])),
        vec![GuestMapping {
            artifact: input_ref.id(),
            guest_path: GuestPath::new("/work").unwrap(),
            access: GuestAccess::ReadWrite,
        }],
        CapsuleProcess::Command {
            argv: vec!["sh".into(), "-c".into(), "deploy".into()],
        },
        CapsuleNetwork::Offline,
        None,
        CapsuleBudgets {
            wall_time_ms: 30_000,
            output_bytes: 1 << 20,
            memory_bytes: 512 * 1024 * 1024,
            process_count: 64,
            result_bytes: 1 << 20,
            result_entries: 16,
            work_delta_bytes: kata_types::execution_contract::CAPSULE_WORK_DELTA_BYTES,
            work_delta_entries: kata_types::execution_contract::CAPSULE_WORK_DELTA_ENTRIES,
        },
        None,
    )
    .unwrap();
    let bytes = serde_json::to_vec(&capsule).unwrap();
    let durable = cas.put_durable(&bytes).unwrap();
    db.declare_capsule(
        &CapsuleDeclaration::for_durable_object(&capsule, &bytes, &durable).unwrap(),
    )
    .unwrap();

    let attempt_id = Ulid::new();
    db.claim_attempt_parked_for_approval(
        execution_id,
        attempt_id,
        &AttemptClaimSpec {
            stage_id: "deploy".to_string(),
            assignment_json: CAPSULE_FRAME.to_vec(),
            initial_state: "awaiting_approval".to_string(),
            run_ordinal: 0,
            worker_id: None,
            occurrence: OccurrenceBinding::new(
                occurrence.clone(),
                Some(capsule.action()),
                Some(capsule.id()),
            ),
        },
        REASON,
    )
    .expect("the gated claim parks");
    Gate {
        _dir: dir,
        op_path,
        cas,
        db,
        attempt_id,
        occurrence,
        capsule,
    }
}

fn command() -> CommandSpec {
    CommandSpec {
        command_json: b"{\"kind\":\"dispatch\"}".to_vec(),
    }
}

fn approve(gate: &Gate, worker: &str) -> kata_types::error::KataResult<CapsuleApprovalOutcome> {
    let choose = || {
        Ok(ApprovedDispatch {
            worker_id: worker.to_owned(),
            command_id: Ulid::new(),
            command: command(),
        })
    };
    gate.db.decide_capsule_approval(
        gate.attempt_id,
        &CapsuleApprovalDecision {
            principal: &ApprovalPrincipal::Token {
                issued_for: "operator-cli".to_owned(),
            },
            capsule_id: gate.capsule.id().0.0,
            verdict: ApprovalVerdict::Approve(&choose),
        },
    )
}

fn reject(gate: &Gate) -> kata_types::error::KataResult<CapsuleApprovalOutcome> {
    gate.db.decide_capsule_approval(
        gate.attempt_id,
        &CapsuleApprovalDecision {
            principal: &ApprovalPrincipal::UnauthenticatedLoopback,
            capsule_id: gate.capsule.id().0.0,
            verdict: ApprovalVerdict::Reject {
                reason: "not today",
            },
        },
    )
}

/// `(commands, dispatched transitions, decisions)`, raw.
fn dispatch_facts(gate: &Gate) -> (i64, i64, i64) {
    (
        count(gate, "SELECT count(*) FROM attempt_commands"),
        count(
            gate,
            "SELECT count(*) FROM transitions WHERE kind = 'dispatched'",
        ),
        count(
            gate,
            "SELECT count(*) FROM transitions WHERE kind = 'approval_decided'",
        ),
    )
}

/// The PARK is the claim's own transaction: ONE `claimed` transition lands the attempt
/// in `awaiting_approval` with the operator-visible reason on its payload, and the
/// ADOPTION read — the one `authorize_attempt`'s occurrence recovery dispatches from —
/// does not answer it, while the gated path's read does.
///
/// **Would red if:** `undispatched_attempt_at_occurrence` stopped excluding the parked
/// state (it would answer the gate, and a re-presentation would dispatch it).
#[test]
fn the_adoption_read_never_answers_a_parked_gate() {
    let gate = parked_gate();
    let (state, reason, kind): (String, String, String) = raw(&gate.op_path)
        .query_row(
            "SELECT resulting_state, json_extract(payload_json, '$.reason'), kind \
               FROM transitions WHERE attempt_id = ?1",
            [gate.attempt_id.to_bytes().as_slice()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .expect("exactly one attempt-scope transition: the parking claim");
    assert_eq!(
        (state.as_str(), reason.as_str(), kind.as_str()),
        ("awaiting_approval", REASON, "claimed")
    );
    assert_eq!(
        gate.db
            .undispatched_attempt_at_occurrence(gate.occurrence.id().0.0)
            .unwrap(),
        None,
        "the adoption read must never answer a parked gate"
    );
    assert_eq!(
        gate.db
            .parked_capsule_attempt_at_occurrence(gate.occurrence.id().0.0)
            .unwrap(),
        Some(gate.attempt_id),
        "the gated path's read answers it"
    );
}

/// DEFENSE IN DEPTH: no caller can dispatch a parked capsule attempt through the
/// ordinary door — it is refused `approval_decision_required` and writes nothing.
///
/// **Would red if:** `dispatch_claimed_attempt_in_tx` dropped
/// `refuse_a_parked_capsule_without_a_decision`.
#[test]
fn the_core_refuses_to_dispatch_a_parked_capsule_without_a_decision() {
    let gate = parked_gate();
    let refusal = gate
        .db
        .dispatch_claimed_attempt(gate.attempt_id, "w-1", Ulid::new(), &command())
        .expect_err("a parked capsule has no decision to dispatch under")
        .to_string();
    assert!(refusal.contains(APPROVAL_DECISION_REQUIRED), "{refusal}");
    assert_eq!(dispatch_facts(&gate), (0, 0, 0));
}

/// APPROVE: one decision, recorded under the attempt's idempotency key with the principal
/// and the capsule, and EXACTLY ONE dispatch after it — in one commit. A second approve
/// answers `AlreadyApproved` and issues no second command.
///
/// **Would red if:** the door stopped reading the prior verdict (the second approve would
/// meet a `dispatched` attempt and refuse, or — without the premise — record a second
/// command for another worker).
#[test]
fn approve_records_one_decision_and_exactly_one_dispatch() {
    let gate = parked_gate();
    let first = approve(&gate, "w-1").expect("the gate is approved");
    let CapsuleApprovalOutcome::Approved {
        decision_seq,
        dispatch_seq,
    } = first
    else {
        panic!("a first approve records: {first:?}");
    };
    assert!(
        decision_seq < dispatch_seq,
        "the decision precedes its dispatch"
    );
    assert_eq!(dispatch_facts(&gate), (1, 1, 1));
    let (key, principal, capsule, seq): (Vec<u8>, String, String, i64) = raw(&gate.op_path)
        .query_row(
            "SELECT idempotency_key, json_extract(payload_json, '$.principal.issued_for'), \
                    json_extract(payload_json, '$.capsule_id'), seq \
               FROM transitions WHERE kind = 'approval_decided'",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .unwrap();
    assert_eq!(key, approval_decision_key(gate.attempt_id).to_vec());
    assert_eq!(principal, "operator-cli");
    assert_eq!(capsule, gate.capsule.id().0.to_string());
    assert_eq!(seq, decision_seq);
    let (worker, dispatched_at): (Option<String>, Option<i64>) = raw(&gate.op_path)
        .query_row(
            "SELECT worker_id, dispatched_at_ms FROM attempts WHERE attempt_id = ?1",
            [gate.attempt_id.to_bytes().as_slice()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!(worker.as_deref(), Some("w-1"));
    assert!(dispatched_at.is_some());

    let again = approve(&gate, "w-2").expect("a repeated approve is not an error");
    assert_eq!(again, CapsuleApprovalOutcome::AlreadyApproved);
    assert_eq!(
        dispatch_facts(&gate),
        (1, 1, 1),
        "a second approve issues no second command, for any worker"
    );
}

/// APPROVE AFTER REJECT is refused `approval_already_decided`, and writes nothing.
#[test]
fn approve_after_reject_is_refused() {
    let gate = parked_gate();
    assert!(matches!(
        reject(&gate).unwrap(),
        CapsuleApprovalOutcome::Rejected { .. }
    ));
    let refusal = approve(&gate, "w-1")
        .expect_err("a rejected gate cannot be approved")
        .to_string();
    assert!(refusal.contains(APPROVAL_ALREADY_DECIDED), "{refusal}");
    assert_eq!(dispatch_facts(&gate), (0, 0, 1));
    assert_eq!(
        reject(&gate).unwrap(),
        CapsuleApprovalOutcome::AlreadyRejected
    );
}

/// REJECT AFTER APPROVE is refused `approval_already_decided`, and writes nothing.
#[test]
fn reject_after_approve_is_refused() {
    let gate = parked_gate();
    approve(&gate, "w-1").unwrap();
    let before = count(&gate, "SELECT count(*) FROM transitions");
    let refusal = reject(&gate)
        .expect_err("an approved gate cannot be rejected")
        .to_string();
    assert!(refusal.contains(APPROVAL_ALREADY_DECIDED), "{refusal}");
    assert_eq!(count(&gate, "SELECT count(*) FROM transitions"), before);
}

/// REJECT: the decision and a `failed` terminal naming the rejection, PROVEN NOT
/// PERFORMED, in one commit — and not one command.
#[test]
fn reject_fails_the_stage_proven_not_performed_with_no_command() {
    let gate = parked_gate();
    let CapsuleApprovalOutcome::Rejected {
        decision_seq,
        failed_seq,
    } = reject(&gate).unwrap()
    else {
        panic!("a reject records");
    };
    assert!(decision_seq < failed_seq);
    let (state, reason): (String, String) = raw(&gate.op_path)
        .query_row(
            "SELECT resulting_state, json_extract(payload_json, '$.reason') FROM transitions \
              WHERE attempt_id = ?1 AND folds_projection = 1 ORDER BY seq DESC LIMIT 1",
            [gate.attempt_id.to_bytes().as_slice()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!(state, "failed");
    assert!(
        reason.starts_with("rejected: not today") && reason.contains("PROVEN NOT PERFORMED"),
        "{reason}"
    );
    let principal: String = raw(&gate.op_path)
        .query_row(
            "SELECT json_extract(payload_json, '$.principal.kind') FROM transitions \
              WHERE kind = 'approval_decided'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(principal, "unauthenticated_loopback");
    assert_eq!(dispatch_facts(&gate), (0, 0, 1));
}

/// A decision naming a capsule the occurrence is NOT bound to is refused, and writes
/// nothing: the operator approves what they were shown or nothing.
#[test]
fn a_decision_naming_another_capsule_is_refused() {
    let gate = parked_gate();
    let choose = || {
        Ok(ApprovedDispatch {
            worker_id: "w-1".to_owned(),
            command_id: Ulid::new(),
            command: command(),
        })
    };
    let refusal = gate
        .db
        .decide_capsule_approval(
            gate.attempt_id,
            &CapsuleApprovalDecision {
                principal: &ApprovalPrincipal::UnauthenticatedLoopback,
                capsule_id: [0x99; 32],
                verdict: ApprovalVerdict::Approve(&choose),
            },
        )
        .expect_err("another capsule's decision is refused")
        .to_string();
    assert!(refusal.contains(APPROVAL_GATE_NOT_PARKED), "{refusal}");
    assert_eq!(dispatch_facts(&gate), (0, 0, 0));
}

/// A writer handle on the gate's plane, for the cells that forge a premise the verbs
/// cannot produce.
fn raw_writer(gate: &Gate) -> rusqlite::Connection {
    let conn = rusqlite::Connection::open(&gate.op_path).unwrap();
    conn.pragma_update(None, "busy_timeout", 5_000i64).unwrap();
    conn
}

/// The EXECUTION IS RUNNING is part of the decision's premise, read under its own writer
/// lock: once `begin_terminalization` has latched an outcome, neither verdict is recorded
/// — refused `approval_execution_not_running` — and nothing is written: no decision, no
/// command, no dispatch.
///
/// **Would red if:** `decide_capsule_approval` stopped reading the lifecycle in its
/// transaction (`Ok(Approved { .. })`, one command into a cancelled
/// execution).
#[test]
fn no_decision_is_recorded_once_the_execution_has_latched_an_outcome() {
    let gate = parked_gate();
    gate.db
        .begin_terminalization(
            gate.db
                .attempt(gate.attempt_id)
                .unwrap()
                .unwrap()
                .execution_id,
            kata_core::LifecycleState::Cancelled,
            b"{\"reason\":\"operator\"}",
        )
        .unwrap();
    for refusal in [
        approve(&gate, "w-1").expect_err("an approve into a cancelled execution is refused"),
        reject(&gate).expect_err("and so is a reject"),
    ] {
        let refusal = refusal.to_string();
        assert!(
            refusal.contains(APPROVAL_EXECUTION_NOT_RUNNING) && refusal.contains("terminalizing"),
            "{refusal}"
        );
    }
    assert_eq!(dispatch_facts(&gate), (0, 0, 0));
}

/// A gate whose row CARRIES A DISPATCH (`dispatched_at_ms` set, no command — a shape no
/// verb writes) is not a parked gate: refused `approval_gate_not_parked`, nothing written.
///
/// **Would red if:** the premise stopped checking the row's own dispatch stamp.
#[test]
fn a_parked_gate_carrying_a_dispatch_stamp_is_refused() {
    let gate = parked_gate();
    raw_writer(&gate)
        .execute(
            "UPDATE attempts SET dispatched_at_ms = 1 WHERE attempt_id = ?1",
            [gate.attempt_id.to_bytes().as_slice()],
        )
        .unwrap();
    let refusal = approve(&gate, "w-1")
        .expect_err("a stamped gate is not parked")
        .to_string();
    assert!(
        refusal.contains(APPROVAL_GATE_NOT_PARKED) && refusal.contains("carries a dispatch"),
        "{refusal}"
    );
    assert_eq!(dispatch_facts(&gate), (0, 0, 0));
}

/// A `main` frame parked at an occurrence bound to a capsule (the blob rewritten under a
/// capsule park — a shape no verb writes) is refused `approval_gate_not_parked`: this door
/// decides the capsule arm only, and nothing is written.
///
/// **Would red if:** the premise stopped checking the frame's arm (answering
/// `Ok(Approved { .. })`).
#[test]
fn a_main_frame_parked_with_a_capsule_binding_is_refused() {
    let gate = parked_gate();
    raw_writer(&gate)
        .execute(
            "UPDATE attempts SET assignment_json = ?1 WHERE attempt_id = ?2",
            rusqlite::params![
                br#"{"main":{"stage_id":"deploy"}}"#.as_slice(),
                gate.attempt_id.to_bytes().as_slice()
            ],
        )
        .unwrap();
    let refusal = approve(&gate, "w-1")
        .expect_err("a main frame is not this door's gate")
        .to_string();
    assert!(
        refusal.contains(APPROVAL_GATE_NOT_PARKED) && refusal.contains("`main` arm"),
        "{refusal}"
    );
    assert_eq!(dispatch_facts(&gate), (0, 0, 0));
}

/// The decision and its dispatch are ONE commit: a fault at the commit leaves neither,
/// and the next decision records both.
#[test]
fn a_failed_decision_commit_leaves_no_decision_and_no_dispatch() {
    let gate = parked_gate();
    gate.db.arm_commit_fault();
    approve(&gate, "w-1").expect_err("the armed commit fails");
    assert_eq!(dispatch_facts(&gate), (0, 0, 0));
    assert!(matches!(
        approve(&gate, "w-1").unwrap(),
        CapsuleApprovalOutcome::Approved { .. }
    ));
    assert_eq!(dispatch_facts(&gate), (1, 1, 1));
}

/// The park an operator is shown: the reason off the parking claim, and the capsule
/// decoded from its own bytes — argv, the `/work` mapping and the environment.
#[test]
fn the_park_reads_back_the_reason_and_the_bound_capsule() {
    let gate = parked_gate();
    let park = gate
        .db
        .capsule_approval_park(gate.attempt_id)
        .unwrap()
        .expect("the attempt is a parked capsule gate");
    assert_eq!(park.reason, REASON);
    assert_eq!(park.capsule.id(), gate.capsule.id());
    assert_eq!(park.capsule.process(), gate.capsule.process());
    approve(&gate, "w-1").unwrap();
    assert!(
        gate.db
            .capsule_approval_park(gate.attempt_id)
            .unwrap()
            .is_none(),
        "an approved gate is no longer parked"
    );
}

/// The park door refuses its non-occurrence shapes before any write: a
/// non-`awaiting_approval` initial state and a blank reason.
#[test]
fn the_park_door_refuses_a_non_parked_state_and_a_blank_reason() {
    let gate = parked_gate();
    let execution = gate
        .db
        .attempt(gate.attempt_id)
        .unwrap()
        .unwrap()
        .execution_id;
    let spec = |state: &str| AttemptClaimSpec {
        stage_id: "deploy".to_string(),
        assignment_json: CAPSULE_FRAME.to_vec(),
        initial_state: state.to_string(),
        run_ordinal: 0,
        worker_id: None,
        occurrence: OccurrenceBinding::new(
            gate.occurrence.clone(),
            Some(gate.capsule.action()),
            Some(gate.capsule.id()),
        ),
    };
    let before = count(&gate, "SELECT count(*) FROM transitions");
    for (claim, reason) in [(spec("pending"), REASON), (spec("awaiting_approval"), "  ")] {
        gate.db
            .claim_attempt_parked_for_approval(execution, Ulid::new(), &claim, reason)
            .expect_err("refused");
    }
    assert_eq!(count(&gate, "SELECT count(*) FROM transitions"), before);
}

/// The park door parks at most one live gate per occurrence, and the CAPSULE arm only: a
/// second park at an occurrence whose gate is still parked is refused
/// `approval_gate_already_live` under the writer lock; once that gate is decided (rejected
/// — terminal), a non-capsule frame with the capsule binding is still refused before any write,
/// and a capsule park is admitted.
///
/// **Would red if:** the door took any frame (`Ok(ClaimedAttempt { .. })` for the
/// non-capsule frame) or admitted a second live gate (`attempt_ordinal: 1`).
#[test]
fn the_park_door_parks_one_live_capsule_gate_per_occurrence() {
    let gate = parked_gate();
    let execution = gate
        .db
        .attempt(gate.attempt_id)
        .unwrap()
        .unwrap()
        .execution_id;
    let claim = |frame: &[u8]| AttemptClaimSpec {
        stage_id: "deploy".to_string(),
        assignment_json: frame.to_vec(),
        initial_state: "awaiting_approval".to_string(),
        run_ordinal: 0,
        worker_id: None,
        occurrence: OccurrenceBinding::new(
            gate.occurrence.clone(),
            Some(gate.capsule.action()),
            Some(gate.capsule.id()),
        ),
    };
    let before = count(&gate, "SELECT count(*) FROM transitions");
    let refusal = gate
        .db
        .claim_attempt_parked_for_approval(execution, Ulid::new(), &claim(CAPSULE_FRAME), REASON)
        .expect_err("a second live gate at one occurrence")
        .to_string();
    assert!(
        refusal.contains(APPROVAL_GATE_ALREADY_LIVE)
            && refusal.contains(&gate.attempt_id.to_string()),
        "{refusal}"
    );
    assert_eq!(count(&gate, "SELECT count(*) FROM transitions"), before);
    assert_eq!(count(&gate, "SELECT count(*) FROM attempts"), 1);

    // Decided (rejected, terminal): the occurrence holds no live gate, so only the frame
    // check stands between a non-capsule frame and a park.
    reject(&gate).unwrap();
    let before = count(&gate, "SELECT count(*) FROM transitions");
    let refusal = gate
        .db
        .claim_attempt_parked_for_approval(
            execution,
            Ulid::new(),
            &claim(br#"{"main":{"stage_id":"deploy"}}"#),
            REASON,
        )
        .expect_err("a main frame is not parked here")
        .to_string();
    assert!(refusal.contains("not the CAPSULE arm"), "{refusal}");
    assert_eq!(count(&gate, "SELECT count(*) FROM transitions"), before);
    gate.db
        .claim_attempt_parked_for_approval(execution, Ulid::new(), &claim(CAPSULE_FRAME), REASON)
        .expect("a decided gate's occurrence parks a new one");
    assert_eq!(count(&gate, "SELECT count(*) FROM attempts"), 2);
}

/// Re-point the gate's `capsules` row at `body`, published into the gate's own content
/// store — the forged premise of a stored capsule the main's verbs would never declare.
fn repoint_capsule_object(gate: &Gate, body: &serde_json::Value) {
    let durable = gate.cas.put_durable(&canonicalize_args(body)).unwrap();
    let updated = raw_writer(gate)
        .execute(
            "UPDATE capsules SET capsule_object_id = ?1 WHERE capsule_id = ?2",
            rusqlite::params![
                durable.object_id().as_bytes(),
                gate.capsule.id().0.as_bytes()
            ],
        )
        .unwrap();
    assert_eq!(updated, 1, "the gate's capsule row names the new object");
}

/// **A stored capsule at another execution-contract schema is refused with the
/// data-directory recourse, and only that one.** The parked gate's `capsules` row is
/// re-pointed at its own capsule's body stamped `schema_version` 11 — a record no binary
/// that opens this data directory wrote, since every contract-schema bump moves the
/// operational schema — and reading the gate back (`capsule_approval_park`, through the
/// main's `authorized_capsule`) refuses naming the version and ending with
/// [`EARLIER_SCHEMA_RECOURSE`]. Re-pointed instead at the body with one budget edited at
/// this build's schema, the read refuses by the capsule's own identity and offers no
/// recourse: that body failed for another reason.
///
/// **Would red if:** the main's durable capsule read dropped the recourse (the stamped
/// read names no fresh data directory), or appended it to every decode failure (the
/// edited body's refusal carries it).
///
/// [`EARLIER_SCHEMA_RECOURSE`]: kata_types::execution_contract::EARLIER_SCHEMA_RECOURSE
#[test]
fn a_stored_capsule_at_another_contract_schema_is_refused_with_the_data_directory_recourse() {
    use kata_types::execution_contract::EARLIER_SCHEMA_RECOURSE;
    let gate = parked_gate();
    gate.db
        .capsule_approval_park(gate.attempt_id)
        .unwrap()
        .expect("the fixture's gate reads back first");

    let mut stamped = serde_json::to_value(&gate.capsule).unwrap();
    stamped["schema_version"] = serde_json::json!(11);
    repoint_capsule_object(&gate, &stamped);
    let refusal = gate
        .db
        .capsule_approval_park(gate.attempt_id)
        .expect_err("a capsule body stamped 11 is refused")
        .to_string();
    assert!(
        refusal.contains("schema_version 11 is not supported")
            && refusal.contains(EARLIER_SCHEMA_RECOURSE),
        "the refusal names the version and the one recourse a directory this binary \
         opens has: {refusal}"
    );

    let mut edited = serde_json::to_value(&gate.capsule).unwrap();
    edited["budgets"]["wall_time_ms"] = serde_json::json!(999_999);
    repoint_capsule_object(&gate, &edited);
    let refusal = gate
        .db
        .capsule_approval_park(gate.attempt_id)
        .expect_err("an edited capsule body is refused")
        .to_string();
    assert!(
        refusal.contains("does not decode as a capsule")
            && !refusal.contains(EARLIER_SCHEMA_RECOURSE),
        "a body at this build's schema that fails its decode is offered no \
         data-directory recourse: {refusal}"
    );
}
