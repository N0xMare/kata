//! The `workspace_effect` operational plane — the durable main-resolved
//! claim/park/decide/resolve surface of
//! `crates/core/src/operational/workspace_effect.rs`, exercised against the
//! real SQLite store and read back through a SECOND raw rusqlite handle, never
//! kata's own reader.
//!
//! The cells pin the mutation surface the workflow suite cannot reach on its
//! own: the spec decoder's positive AND negative arms, the candidate
//! compare-and-swap inside `resolve_workspace_effect_attempt`, the approval
//! gate's running-execution / parked-state / scope re-binding refusals and its
//! write-once verdict, and the terminal-intent claim's named refusal.

use std::sync::Arc;

use kata_core::operational::{
    CapsuleApprovalOutcome, HeadCommitAdvance, MainAttemptSpec, MainResolution, OccurrenceBinding,
    WorkspaceEffectApprovalDecision, WorkspaceEffectClaimOutcome, WorkspaceEffectGateScope,
    WorkspaceEffectSpec, WorkspaceEffectVerdict, workspace_effect_spec,
};
use kata_core::store::cas::CasStore;
use kata_core::{InvocationKind, InvocationRecord, OperationalDb, ProgramRecord, SubmitOutcome};
use kata_types::approval::ApprovalPrincipal;
use kata_types::execution::CandidateTreePin;
use kata_types::execution_contract::{OccurrenceRef, OperationContractId, OperationPath};
use kata_types::primitives::ContentHash;
use kata_types::tree_artifact::TreeManifest;
use kata_types::workflow::WorkspaceEffectOp;
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
    cas: Arc<CasStore>,
}

fn rig() -> Rig {
    let dir = tempfile::tempdir().unwrap();
    let cas = Arc::new(CasStore::open(dir.path().join("cas.db"), dir.path().join("cas")).unwrap());
    let db =
        OperationalDb::open_with_cas(dir.path().join("operational.db"), Arc::clone(&cas)).unwrap();
    Rig {
        dir,
        db: Arc::new(db),
        cas,
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

/// One stage coordinate — `ship`, `main`-executor by the workspace_effect
/// operation tag the claim writes.
fn spec(execution: Ulid) -> MainAttemptSpec {
    stage_spec(execution, "ship", vec![0])
}

/// The same attempt shape on a named stage and occurrence path — a second
/// `workspace_effect` claim needs both distinct (an occurrence converges).
fn stage_spec(execution: Ulid, stage: &str, path: Vec<u32>) -> MainAttemptSpec {
    MainAttemptSpec {
        stage_id: stage.to_string(),
        occurrence: OccurrenceBinding::new(
            OccurrenceRef::new(
                kata_types::workflow::ExecutionId(execution),
                ContentHash::new([0xB7; 32]),
                OperationContractId(ContentHash::new([0x5E; 32])),
                OperationPath(path),
            ),
            None,
            None,
        ),
    }
}

fn effect(op: WorkspaceEffectOp, candidate: &str) -> WorkspaceEffectSpec {
    WorkspaceEffectSpec {
        op,
        label: None,
        target: format!("ref-{candidate}"),
        candidate_commit: candidate.to_owned(),
        delivered_commit: format!("delivered-{candidate}"),
        candidate_tree_id: format!("tree-{candidate}"),
        pin: CandidateTreePin::Unpinned,
        forge: None,
        forge_remote: None,
    }
}

/// Declare a `kind='tree'` artifact — a head row's `work_tree_artifact_id`
/// may only name a declared row.
fn declare_tree(rig: &Rig, execution: Ulid) -> [u8; 32] {
    let manifest = TreeManifest::new(Vec::new()).unwrap();
    let bytes = manifest.manifest_bytes().unwrap();
    let durable = rig.cas.put_durable(&bytes).unwrap();
    let declaration = kata_core::operational::ArtifactDeclaration::for_durable_tree(
        &manifest,
        kata_types::execution_contract::ArtifactPrivacy::Public,
        kata_core::operational::CasRootOwner::Execution(execution),
        &durable,
    )
    .unwrap();
    rig.db.declare_artifact(&declaration).unwrap();
    kata_types::execution_contract::ArtifactRef::new(
        durable.object_id(),
        durable.size(),
        kata_types::execution_contract::ArtifactPrivacy::Public,
    )
    .id()
    .0
    .0
}

/// The attempt's projected state, read off the raw handle.
fn raw_state(rig: &Rig, attempt_id: Ulid) -> Option<String> {
    use rusqlite::OptionalExtension as _;
    raw(rig)
        .query_row(
            "SELECT p.state FROM attempt_projection p
               JOIN attempts a
                 ON a.execution_id = p.execution_id AND a.stage_id = p.stage_id
                AND a.attempt_ordinal = p.attempt_ordinal
              WHERE a.attempt_id = ?1",
            [attempt_id.to_bytes().as_slice()],
            |row| row.get(0),
        )
        .optional()
        .expect("the projection row reads")
}

/// The claim's recorded spec blob, read off the raw handle.
fn raw_blob(rig: &Rig, attempt_id: Ulid) -> Vec<u8> {
    raw(rig)
        .query_row(
            "SELECT assignment_json FROM attempts WHERE attempt_id = ?1",
            [attempt_id.to_bytes().as_slice()],
            |row| row.get(0),
        )
        .expect("the attempt's assignment blob")
}

/// The head row's recorded `(candidate, committed)` commits, read off the raw
/// handle.
fn raw_candidate(rig: &Rig, execution: Ulid) -> (String, String) {
    raw(rig)
        .query_row(
            "SELECT candidate_commit_id, committed_commit_id FROM execution_work_tree_heads \
             WHERE execution_id = ?1 AND branch = ''",
            [execution.to_bytes().as_slice()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .expect("the head row reads raw")
}

fn gate_scope(effect: &WorkspaceEffectSpec) -> WorkspaceEffectGateScope {
    WorkspaceEffectGateScope {
        op: effect.op.as_str().to_owned(),
        target: effect.target.clone(),
        candidate_commit: effect.candidate_commit.clone(),
        candidate_tree_id: effect.candidate_tree_id.clone(),
    }
}

const PRINCIPAL: ApprovalPrincipal = ApprovalPrincipal::UnauthenticatedLoopback;

/// The claim records the spec INSIDE the assignment blob, and
/// `workspace_effect_spec` answers `Some` only for the `workspace_effect`
/// operation frame — the decoder's positive arm and its refusal of every
/// other operation tag.
#[test]
fn a_workspace_effect_claim_records_a_spec_the_decoder_names() {
    let rig = rig();
    let execution = Ulid::new();
    submit(&rig, execution);
    let effect = effect(WorkspaceEffectOp::Commit, "cand-claim");

    let attempt_id = Ulid::new();
    let outcome = rig
        .db
        .claim_workspace_effect_attempt(attempt_id, &spec(execution), &effect, None)
        .unwrap();
    assert!(
        matches!(outcome, WorkspaceEffectClaimOutcome::Claimed { .. }),
        "a fresh claim is pending: {outcome:?}"
    );

    let decoded = workspace_effect_spec(&raw_blob(&rig, attempt_id))
        .unwrap()
        .expect("the recorded blob decodes to the workspace_effect spec");
    assert_eq!(decoded.op.as_str(), "commit");
    assert_eq!(decoded.target, effect.target);
    assert_eq!(decoded.candidate_commit, effect.candidate_commit);
    assert_eq!(decoded.delivered_commit, effect.delivered_commit);
    assert_eq!(decoded.candidate_tree_id, effect.candidate_tree_id);

    // The negative arm — a frame whose operation is anything else is NOT the
    // effect's spec, and a claim that recorded it must not answer one.
    assert!(
        workspace_effect_spec(br#"{"main":{"operation":"child_invocation","spec":{}}}"#)
            .unwrap()
            .is_none(),
        "another main operation decodes to no workspace_effect spec"
    );

    // The pending sweep's own enumeration names the attempt with its spec.
    let pending = rig.db.pending_workspace_effects(execution).unwrap();
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].attempt_id, attempt_id);
    assert_eq!(pending[0].spec.candidate_commit, "cand-claim");
}

/// A `commit` resolve carries the head row's `candidate_commit_id` and
/// `committed_commit_id` forward by compare-and-swap INSIDE the resolve commit:
/// the fresh pair lands only when the row still names the candidate the
/// attempt was claimed against, and a stale expectation is the
/// `workspace_effect_candidate_moved` refusal — the whole transaction, resolve
/// included, rolls back.
#[test]
fn a_commit_resolve_swaps_the_head_candidate_and_names_a_moved_one() {
    let rig = rig();
    let execution = Ulid::new();
    submit(&rig, execution);
    let artifact = declare_tree(&rig, execution);
    rig.db
        .record_work_tree_head(execution, "", artifact, "cand-one")
        .unwrap();

    let attempt_id = Ulid::new();
    rig.db
        .claim_workspace_effect_attempt(
            attempt_id,
            &spec(execution),
            &effect(WorkspaceEffectOp::Commit, "cand-one"),
            None,
        )
        .unwrap();
    let output = serde_json::json!({"content": "{}", "stop_reason": "effect_applied"});
    rig.db
        .resolve_workspace_effect_attempt(
            attempt_id,
            Some(&HeadCommitAdvance {
                expected_candidate: "cand-one",
                new_candidate: "cand-two",
                committed_commit: "committed-one",
            }),
            &MainResolution::Complete { output: &output },
        )
        .expect("the resolve commits")
        .expect("a pending attempt resolves");

    assert_eq!(
        raw_candidate(&rig, execution),
        ("cand-two".to_owned(), "committed-one".to_owned()),
        "the resolve advanced the recorded candidate and committed commit in the same commit"
    );
    assert_eq!(raw_state(&rig, attempt_id).as_deref(), Some("completed"));

    // A second attempt resolving against the STALE candidate refuses by name
    // and leaves both its own attempt and the head row untouched.
    let stale = Ulid::new();
    rig.db
        .claim_workspace_effect_attempt(
            stale,
            &stage_spec(execution, "ship-again", vec![1]),
            &effect(WorkspaceEffectOp::Commit, "cand-two"),
            None,
        )
        .unwrap();
    let err = rig
        .db
        .resolve_workspace_effect_attempt(
            stale,
            Some(&HeadCommitAdvance {
                expected_candidate: "cand-one",
                new_candidate: "cand-three",
                committed_commit: "committed-two",
            }),
            &MainResolution::Complete { output: &output },
        )
        .expect_err("a stale expected candidate refuses by name");
    assert!(
        err.to_string().contains("workspace_effect_candidate_moved"),
        "the moved-candidate refusal is named: {err}"
    );
    assert_eq!(
        raw_state(&rig, stale).as_deref(),
        Some("pending"),
        "the refused resolve rolls its own resolution back"
    );
    assert_eq!(
        raw_candidate(&rig, execution),
        ("cand-two".to_owned(), "committed-one".to_owned())
    );
}

/// The gate: a claim with `approval` parks `awaiting_approval` carrying the
/// scope the operator is asked about; `decide_workspace_effect_approval`
/// refuses a decision on anything else — a not-running execution, a not-parked
/// attempt, or a scope that names another candidate/op/ref — and the verdict
/// is write-once: approve un-parks to `pending`, a second approve answers
/// `AlreadyApproved`, and the opposite verdict refuses `approval_already_decided`.
#[test]
fn a_parked_gate_decides_only_its_own_scope_and_decides_once() {
    let rig = rig();
    let execution = Ulid::new();
    submit(&rig, execution);
    rig.db.mark_running(execution).unwrap();
    let effect = effect(WorkspaceEffectOp::Park, "cand-gated");

    let attempt_id = Ulid::new();
    let outcome = rig
        .db
        .claim_workspace_effect_attempt(
            attempt_id,
            &spec(execution),
            &effect,
            Some("operator must approve"),
        )
        .unwrap();
    assert!(
        matches!(
            outcome,
            WorkspaceEffectClaimOutcome::ParkedForApproval { .. }
        ),
        "the gated claim parks: {outcome:?}"
    );
    assert_eq!(
        raw_state(&rig, attempt_id).as_deref(),
        Some("awaiting_approval")
    );

    // The parked FRAME carries the attempt's `delivery` snapshot — the
    // replay's durable-facts decode requires it of every projection-folding
    // attempt frame, and a gate park without it stored an undecodable frame.
    let park_payload: serde_json::Value = raw(&rig)
        .query_row(
            "SELECT payload_json FROM transitions
              WHERE attempt_id = ?1 AND resulting_state = 'awaiting_approval'
              ORDER BY seq DESC LIMIT 1",
            [attempt_id.to_bytes().as_slice()],
            |row| row.get::<_, Vec<u8>>(0),
        )
        .map(|bytes| serde_json::from_slice(&bytes).expect("the park frame is JSON"))
        .expect("the park frame row reads");
    assert!(
        park_payload["delivery"]["awaiting_approval_at_ms"].is_number(),
        "the parked frame carries the finalized delivery snapshot: {park_payload}"
    );
    assert_eq!(
        park_payload["reason"].as_str(),
        Some("operator must approve")
    );
    assert!(park_payload["workspace_effect_gate"].is_object());

    // The parked row advertises exactly the scope the claim recorded.
    let gates = rig.db.parked_workspace_effect_gates(execution).unwrap();
    assert_eq!(gates.len(), 1);
    assert_eq!(gates[0].attempt_id, attempt_id);
    assert_eq!(gates[0].scope.op, "park");
    assert_eq!(gates[0].scope.target, effect.target);
    assert_eq!(gates[0].scope.candidate_commit, "cand-gated");
    assert_eq!(gates[0].scope.candidate_tree_id, effect.candidate_tree_id);

    let approve = WorkspaceEffectApprovalDecision {
        principal: &PRINCIPAL,
        verdict: WorkspaceEffectVerdict::Approve,
    };
    // Each wrong scope field refuses by name — the decision is bound to the
    // parked scope, field by field.
    for scope in [
        WorkspaceEffectGateScope {
            candidate_commit: "another-candidate".to_owned(),
            ..gate_scope(&effect)
        },
        WorkspaceEffectGateScope {
            op: "promote".to_owned(),
            ..gate_scope(&effect)
        },
        WorkspaceEffectGateScope {
            target: "some/other-ref".to_owned(),
            ..gate_scope(&effect)
        },
    ] {
        let err = rig
            .db
            .decide_workspace_effect_approval(attempt_id, &approve, &scope)
            .expect_err("a scope the gate did not park refuses");
        assert!(
            err.to_string().contains("approval_gate_not_parked"),
            "the scope mismatch refuses by name: {err}"
        );
    }
    assert_eq!(
        raw_state(&rig, attempt_id).as_deref(),
        Some("awaiting_approval"),
        "a refused decision writes nothing"
    );

    // The exact scope approves: the attempt un-parks to `pending` in the
    // decision's own commit.
    let outcome = rig
        .db
        .decide_workspace_effect_approval(attempt_id, &approve, &gate_scope(&effect))
        .expect("the parked scope's approve lands");
    assert!(
        matches!(outcome, CapsuleApprovalOutcome::Approved { .. }),
        "the decision records approved: {outcome:?}"
    );
    assert_eq!(raw_state(&rig, attempt_id).as_deref(), Some("pending"));

    // Write-once: the SAME verdict again answers `Already*` and the OPPOSITE
    // verdict refuses by name — a decision can never be re-decided.
    let outcome = rig
        .db
        .decide_workspace_effect_approval(attempt_id, &approve, &gate_scope(&effect))
        .expect("the recorded approve replays as AlreadyApproved");
    assert!(
        matches!(outcome, CapsuleApprovalOutcome::AlreadyApproved),
        "the verdict is write-once: {outcome:?}"
    );
    let reject = WorkspaceEffectApprovalDecision {
        principal: &PRINCIPAL,
        verdict: WorkspaceEffectVerdict::Reject {
            reason: "operator veto",
        },
    };
    let err = rig
        .db
        .decide_workspace_effect_approval(attempt_id, &reject, &gate_scope(&effect))
        .expect_err("the opposite verdict after approve refuses");
    assert!(
        err.to_string().contains("approval_already_decided"),
        "the write-once refusal is named: {err}"
    );
}

/// A claim that ARRIVES after the outcome latch refuses by name
/// (`claim_after_terminal_intent`) and writes nothing — the latch's half of
/// the terminal-intent boundary for the workspace_effect door. (The claim's
/// settle-on-insert leg answers `dispatch_after_terminal_intent` shapes on
/// attempts claimed BEFORE the latch; the dispatch-side cell lives in
/// `operational_dispatch_terminal_intent.rs`.)
#[test]
fn a_claim_after_the_cancel_latch_refuses_by_name_and_writes_nothing() {
    let rig = rig();
    let execution = Ulid::new();
    submit(&rig, execution);
    rig.db
        .latch_execution_cancel(execution, "operator cancel")
        .expect("the cancel latch closes");

    let attempt_id = Ulid::new();
    let err = rig
        .db
        .claim_workspace_effect_attempt(
            attempt_id,
            &spec(execution),
            &effect(WorkspaceEffectOp::Commit, "cand-late"),
            None,
        )
        .expect_err("a claim arriving after the latch refuses by name");
    assert!(
        err.to_string().contains("claim_after_terminal_intent"),
        "the terminal-intent refusal is named: {err}"
    );
    assert_eq!(
        raw_state(&rig, attempt_id),
        None,
        "the refused claim wrote no attempt row"
    );
    assert!(
        rig.db
            .pending_workspace_effects(execution)
            .unwrap()
            .is_empty(),
        "the sweep never sees a refused claim"
    );
}

/// A claim landing while the execution is TERMINALIZING is refused by name at
/// the claim's own transition write (`claim_after_terminal_intent`) — before
/// the post-insert terminal-intent fence `refuse_start_after_terminal_intent_in_tx`
/// can ever observe the latch. That ordering is the invariant this cell pins:
/// the second fence's `Settled`/`Declined` arms only matter for a DISPATCH of
/// an already-claimed attempt, not for the claim's own transaction, whose
/// earlier refusal rolls the whole write back.
#[test]
fn a_claim_under_terminalization_refuses_at_the_claim_write() {
    use kata_core::LifecycleState;
    let rig = rig();
    let execution = Ulid::new();
    submit(&rig, execution);
    rig.db
        .begin_terminalization_with_cleanup(
            execution,
            LifecycleState::Cancelled,
            &serde_json::to_vec(&serde_json::json!({"reason": "operator cancel"})).unwrap(),
            "converge_absent",
        )
        .expect("the terminalizing latch lands");

    let attempt_id = Ulid::new();
    let err = rig
        .db
        .claim_workspace_effect_attempt(
            attempt_id,
            &spec(execution),
            &effect(WorkspaceEffectOp::Commit, "cand-drain"),
            None,
        )
        .expect_err("a claim under terminalizing refuses by name");
    assert!(
        err.to_string().contains("claim_after_terminal_intent"),
        "the terminalizing refusal is named: {err}"
    );
    assert_eq!(
        raw_state(&rig, attempt_id),
        None,
        "the refused claim wrote no attempt row"
    );
}
