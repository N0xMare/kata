//! The main-side `/work` apply's CORE legs on the real
//! plane: `MainOperation::WorkApply` claims at `#apply/<stage>`, the head
//! row's candidate commit, the pending-apply sweep enumeration, the
//! base-stale refusal, the head advance inside the resolving transaction, and
//! the successor gate.
//!
//! Provider mechanics (jj apply/classify/repair) are kata-vcs's cells; these
//! cells pin the durable choreography — claim, dedup, record, advance, gate —
//! so a reader can verify it without trusting the driver.

use kata_core::operational::{
    AttemptClaimSpec, CapsuleDeclaration, CapsuleResultAdoption, ExecutionWorkTreeHead,
    MainAttemptSpec, OccurrenceBinding, OperationalDb, PendingWorkApply, WORK_DELTA_BASE_STALE,
    WorkApplyClaimOutcome, WorkTreeHeadAdvance, WorkerCompletionInput,
};
use kata_core::store::cas::CasStore;
use kata_core::{InvocationKind, InvocationRecord, ProgramRecord};
use kata_types::execution_contract::{
    ArtifactId, ArtifactPrivacy, ArtifactRef, Capsule, CapsuleNetwork, CapsuleProcess,
    OccurrenceId, OccurrenceRef, OperationContractId, OperationPath, work_apply_operation_contract,
    work_apply_stage_id,
};
use kata_types::primitives::ContentHash;
use kata_types::tree_artifact::{TreeEntry, TreeEntryMode, TreeManifest, TreeNode, TreePath};
use kata_types::tree_delta::{TreeChange, TreeChangeKind, TreeDelta};
use std::sync::Arc;
use ulid::Ulid;

const STAGE: &str = "digest";
const MEMBER: &[u8] = b"the worker wrote this\n";

struct Planes {
    _dir: tempfile::TempDir,
    db: Arc<OperationalDb>,
    cas: Arc<CasStore>,
}

fn planes() -> Planes {
    let dir = tempfile::tempdir().unwrap();
    let cas = Arc::new(CasStore::open(dir.path().join("cas.db"), dir.path().join("cas")).unwrap());
    let db = Arc::new(
        OperationalDb::open_with_cas(dir.path().join("operational.db"), Arc::clone(&cas)).unwrap(),
    );
    Planes { _dir: dir, db, cas }
}

fn program() -> ProgramRecord {
    let program_hash = ContentHash::new([0xA7; 32]);
    ProgramRecord {
        program_hash,
        schema_version: 4,
        program_json: kata_types::idempotency::canonicalize_args(&serde_json::json!({
            "schema_version": 4,
            "program_hash": program_hash.to_string(),
            "program": 1,
        })),
    }
}

fn invocation() -> InvocationRecord {
    let invocation_json = kata_types::idempotency::canonicalize_args(&serde_json::json!({
        "schema_version": 1,
        "kind": "workflow",
        "inputs": [1],
    }));
    InvocationRecord {
        schema_version: 1,
        kind: InvocationKind::Workflow,
        admission_digest: kata_types::identity_algebra::AdmissionDigest(ContentHash::new(
            *blake3::hash(&invocation_json).as_bytes(),
        )),
        invocation_json,
    }
}

fn occurrence_ref(execution_id: Ulid) -> OccurrenceRef {
    OccurrenceRef::new(
        kata_types::workflow::ExecutionId(execution_id),
        ContentHash::new([0xA7; 32]),
        OperationContractId(ContentHash::new([0x6C; 32])),
        OperationPath(vec![0]),
    )
}

fn capsule(occurrence: OccurrenceId, work: ArtifactId) -> Capsule {
    use kata_types::execution_contract::{
        CapsuleBudgets, EnvironmentId, GuestAccess, GuestMapping, GuestPath, PlatformId,
        PreparedActionId,
    };
    Capsule::new(
        occurrence,
        PreparedActionId(ContentHash::new([0x02; 32])),
        EnvironmentId(ContentHash::new([0x03; 32])),
        PlatformId(ContentHash::new([0x04; 32])),
        vec![GuestMapping {
            artifact: work,
            guest_path: GuestPath::new("/work").unwrap(),
            access: GuestAccess::ReadWrite,
        }],
        CapsuleProcess::Command {
            argv: vec!["sh".into(), "-c".into(), "echo done > /work/r".into()],
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
    .unwrap()
}

/// Publish `/work`'s base manifest — one existing file `old.txt` — and declare
/// it for the execution: `execution_work_tree_heads.work_tree_artifact_id`
/// references `artifacts`, so a head may only name a declared row.
fn work_tree(planes: &Planes, execution_id: Ulid) -> ArtifactRef {
    let member = planes.cas.put_durable(b"old contents\n").unwrap();
    let manifest = TreeManifest::new(vec![TreeEntry {
        path: TreePath::new("old.txt").unwrap(),
        node: TreeNode::File {
            mode: TreeEntryMode::Regular,
            object: member.object_id(),
            size_bytes: member.size(),
        },
    }])
    .unwrap();
    let receipt = planes
        .cas
        .put_durable(&manifest.manifest_bytes().unwrap())
        .unwrap();
    planes
        .db
        .declare_artifact(
            &kata_core::operational::ArtifactDeclaration::for_durable_tree(
                &manifest,
                ArtifactPrivacy::Public,
                kata_core::operational::CasRootOwner::Execution(execution_id),
                &receipt,
            )
            .unwrap(),
        )
        .unwrap();
    ArtifactRef::new(receipt.object_id(), receipt.size(), ArtifactPrivacy::Public)
}

fn submit(planes: &Planes, execution_id: Ulid) {
    planes
        .db
        .submit_execution(execution_id, &program(), &invocation())
        .unwrap();
}

const ENVIRONMENT_ID: [u8; 32] = [0x03; 32];
const STAGE_ULID: &str = "01JZZZZZZZZZZZZZZZZZZZZZE1";

fn declare_environment(planes: &Planes) {
    if planes.db.environment(ENVIRONMENT_ID).unwrap().is_some() {
        return;
    }
    let manifest = planes
        .cas
        .put_durable(b"work-apply-fixture-environment-manifest")
        .unwrap();
    planes
        .db
        .declare_environment(
            &kata_core::operational::EnvironmentDeclaration::for_staged_root(
                ENVIRONMENT_ID,
                &manifest,
                [0x5C; 32],
                "work-apply-fixture",
                [0x04; 32],
                STAGE_ULID,
            )
            .unwrap(),
        )
        .unwrap();
}

/// A delta against `base` writing `r` = MEMBER — the non-empty apply's input.
fn delta(planes: &Planes, base: &ArtifactRef) -> (ArtifactRef, TreeDelta) {
    let member = planes.cas.put_durable(MEMBER).unwrap();
    let delta = TreeDelta::new(
        base.clone(),
        vec![TreeChange {
            path: TreePath::new("r").unwrap(),
            change: TreeChangeKind::Write {
                node: TreeNode::File {
                    mode: TreeEntryMode::Regular,
                    object: member.object_id(),
                    size_bytes: member.size(),
                },
            },
        }],
    )
    .unwrap();
    let receipt = planes
        .cas
        .put_durable(&delta.delta_bytes().unwrap())
        .unwrap();
    (
        ArtifactRef::new(
            receipt.object_id(),
            receipt.size(),
            ArtifactPrivacy::Private,
        ),
        delta,
    )
}

/// Land a capsule completion whose accepted outcome carries `delta` as its
/// `/work` delta — the sweep's enumeration input.
fn accept_capsule_with_delta(
    planes: &Planes,
    execution_id: Ulid,
    occurrence: &OccurrenceRef,
    work: &ArtifactRef,
    delta_ref: &ArtifactRef,
) {
    let capsule = capsule(occurrence.id(), work.id());
    let bytes = serde_json::to_vec(&capsule).unwrap();
    let durable = planes.cas.put_durable(&bytes).unwrap();
    planes
        .db
        .declare_capsule(
            &CapsuleDeclaration::for_durable_object(&capsule, &bytes, &durable).unwrap(),
        )
        .unwrap();
    let attempt_id = Ulid::new();
    let claimed = planes
        .db
        .claim_attempt(
            execution_id,
            attempt_id,
            &AttemptClaimSpec {
                stage_id: STAGE.to_string(),
                assignment_json: b"{\"capsule\":{\"stage_name\":\"digest\"}}".to_vec(),
                initial_state: "pending".to_string(),
                run_ordinal: 0,
                worker_id: None,
                occurrence: OccurrenceBinding::new(
                    occurrence.clone(),
                    Some(capsule.action()),
                    Some(capsule.id()),
                )
                .with_work_tree(work.id().0.0),
            },
        )
        .unwrap();
    planes
        .db
        .record_main_side_transition(
            attempt_id,
            &kata_core::operational::MainSideTransition {
                worker_id: Some("w-1"),
                ..kata_core::operational::MainSideTransition::bare("running")
            },
        )
        .unwrap();
    let member = planes.cas.put_durable(b"result\n").unwrap();
    let manifest = TreeManifest::new(vec![TreeEntry {
        path: TreePath::new("r").unwrap(),
        node: TreeNode::File {
            mode: TreeEntryMode::Regular,
            object: member.object_id(),
            size_bytes: member.size(),
        },
    }])
    .unwrap();
    let receipt = planes
        .cas
        .put_durable(&manifest.manifest_bytes().unwrap())
        .unwrap();
    let result = ArtifactRef::new(
        receipt.object_id(),
        receipt.size(),
        ArtifactPrivacy::Private,
    );
    let capture = |bytes: &[u8]| {
        let receipt = planes.cas.put_durable(bytes).unwrap();
        ArtifactRef::new(
            receipt.object_id(),
            receipt.size(),
            ArtifactPrivacy::Private,
        )
    };
    let stdout = capture(b"{}\n");
    let stderr = capture(b"");
    planes
        .db
        .adopt_and_accept_capsule_completion(
            &CapsuleResultAdoption {
                execution_id,
                occurrence_id: occurrence.id(),
                result: result.clone(),
                stdout: stdout.clone(),
                stderr: stderr.clone(),
                work_delta: Some(delta_ref.clone()),
                agent: None,
                capture_exceeded: false,
                egress_refusals: vec![],
            },
            |adopted| WorkerCompletionInput {
                execution_id,
                attempt_id,
                attempt_ordinal: claimed.attempt_ordinal,
                lease_epoch: 0,
                worker_id: "w-1".to_string(),
                output: kata_core::operational::capsule_result_output(
                    adopted,
                    &result,
                    Some(0),
                    &stdout,
                    &stderr,
                    false,
                    None,
                ),
            },
        )
        .unwrap();
}

/// The rig: an execution, its recorded head, and one accepted capsule
/// completion carrying a delta against that head.
fn rig_with_pending_apply() -> (
    Planes,
    Ulid,
    PendingWorkApply,
    TreeDelta,
    ExecutionWorkTreeHead,
) {
    let planes = planes();
    declare_environment(&planes);
    let execution_id = Ulid::new();
    submit(&planes, execution_id);
    let work = work_tree(&planes, execution_id);
    let head = planes
        .db
        .record_work_tree_head(execution_id, "basecommit", work.id().0.0, "wccommit")
        .unwrap();
    let occurrence = occurrence_ref(execution_id);
    let (delta_ref, delta) = delta(&planes, &work);
    accept_capsule_with_delta(&planes, execution_id, &occurrence, &work, &delta_ref);
    let pending = planes.db.pending_work_applies(execution_id).unwrap();
    assert_eq!(pending.len(), 1, "one pending apply owes the delta");
    (planes, execution_id, pending[0].clone(), delta, head)
}

fn apply_spec(execution_id: Ulid, row: &PendingWorkApply) -> MainAttemptSpec {
    MainAttemptSpec {
        stage_id: work_apply_stage_id(&row.stage_id),
        occurrence: OccurrenceBinding::new(
            OccurrenceRef::new(
                kata_types::workflow::ExecutionId(execution_id),
                ContentHash::new(row.program_hash),
                work_apply_operation_contract(OperationContractId(ContentHash::new(
                    row.operation_contract_id,
                ))),
                OperationPath::from_canonical_bytes(&row.operation_path).unwrap(),
            ),
            None,
            None,
        ),
    }
}

/// The applied tree the resolving advance names, published and declared the
/// way `publish_applied_tree` does it.
fn applied_artifact(planes: &Planes, execution_id: Ulid) -> [u8; 32] {
    let member = planes.cas.put_durable(MEMBER).unwrap();
    let manifest = TreeManifest::new(vec![
        TreeEntry {
            path: TreePath::new("old.txt").unwrap(),
            node: TreeNode::File {
                mode: TreeEntryMode::Regular,
                object: member.object_id(),
                size_bytes: member.size(),
            },
        },
        TreeEntry {
            path: TreePath::new("r").unwrap(),
            node: TreeNode::File {
                mode: TreeEntryMode::Regular,
                object: member.object_id(),
                size_bytes: member.size(),
            },
        },
    ])
    .unwrap();
    let bytes = manifest.manifest_bytes().unwrap();
    let durable = planes.cas.put_durable(&bytes).unwrap();
    let declaration = kata_core::operational::ArtifactDeclaration::for_durable_tree(
        &manifest,
        ArtifactPrivacy::Private,
        kata_core::operational::CasRootOwner::Execution(execution_id),
        &durable,
    )
    .unwrap();
    let artifact_id = declaration.artifact_id();
    planes.db.declare_artifact(&declaration).unwrap();
    artifact_id
}

/// A stage's accepted completion recorded a `/work` delta → the sweep lists a
/// pending apply at the stage's coordinate, and the successor gate holds.
#[test]
fn an_accepted_completion_carrying_a_delta_is_the_sweep_input() {
    let (planes, execution_id, row, delta, _head) = rig_with_pending_apply();
    assert_eq!(row.stage_id, STAGE);
    let delta_bytes = delta.delta_bytes().unwrap();
    let delta_object = kata_types::cache::object_id_for_canonical_bytes(&delta_bytes);
    assert_eq!(
        delta_object.0,
        planes
            .db
            .artifact(row.work_delta_artifact_id)
            .unwrap()
            .unwrap()
            .object_id,
        "the row names the recorded delta artifact"
    );
    assert!(
        planes
            .db
            .pending_work_apply_for_stage(execution_id, STAGE)
            .unwrap(),
        "a delta-carrying stage holds its dependents until the apply resolves"
    );
    assert!(
        !planes
            .db
            .pending_work_apply_for_stage(execution_id, "other")
            .unwrap(),
        "a stage without a pending apply does not gate"
    );
}

/// `stage_recorded_work_delta` — the oci closeout observation's recorded
/// source — names the stage's accepted delta artifact and nothing else.
#[test]
fn stage_recorded_work_delta_names_the_accepted_stages_delta() {
    let (planes, execution_id, row, _delta, _head) = rig_with_pending_apply();
    assert_eq!(
        planes
            .db
            .stage_recorded_work_delta(execution_id, STAGE)
            .unwrap()
            .map(|artifact| artifact.0),
        Some(row.work_delta_artifact_id),
        "the stage's accepted delta is the recorded answer"
    );
    assert!(
        planes
            .db
            .stage_recorded_work_delta(execution_id, "other")
            .unwrap()
            .is_none(),
        "a stage with no recorded delta answers none"
    );
}

/// The claim binds a `#apply/<stage>` occurrence under the derived contract; a
/// same-shape second claimant converges on the live attempt, a re-keyed claim
/// refuses.
#[test]
fn a_work_apply_claim_binds_the_apply_occurrence_and_reclaims_converge() {
    let (planes, execution_id, row, _delta, head) = rig_with_pending_apply();
    let spec = apply_spec(execution_id, &row);
    let attempt_id = Ulid::new();
    let claim = planes
        .db
        .claim_work_apply_attempt(attempt_id, &spec, "", head.work_tree_artifact_id)
        .expect("the first claim claims");
    assert!(
        matches!(claim, WorkApplyClaimOutcome::Claimed { ref head, .. } if head.candidate_commit_id == "wccommit"),
        "the first claim is fresh and fenced on the recorded head: {claim:?}"
    );
    // Same shape, fresh attempt id: the occurrence's live apply is the recorded
    // one — the double-spend guard, not a second claim.
    let reclaim = planes
        .db
        .claim_work_apply_attempt(Ulid::new(), &spec, "", head.work_tree_artifact_id)
        .unwrap();
    assert!(
        matches!(reclaim, WorkApplyClaimOutcome::AlreadyLive { attempt_id: a, .. } if a == attempt_id),
        "a same-shape claim while the first is pending converges on it: {reclaim:?}"
    );
    // A claim under a TAKEN attempt id but a different shape refuses — the
    // occurrence coordinate here is the operation path, since the apply
    // occurrence is (apply contract, stage path).
    let divergent = MainAttemptSpec {
        stage_id: work_apply_stage_id(&row.stage_id),
        occurrence: OccurrenceBinding::new(
            OccurrenceRef::new(
                kata_types::workflow::ExecutionId(execution_id),
                ContentHash::new(row.program_hash),
                work_apply_operation_contract(OperationContractId(ContentHash::new(
                    row.operation_contract_id,
                ))),
                OperationPath(vec![9]),
            ),
            None,
            None,
        ),
    };
    let err = planes
        .db
        .claim_work_apply_attempt(attempt_id, &divergent, "", head.work_tree_artifact_id)
        .expect_err("a mismatched claim under a taken attempt id refuses");
    assert!(matches!(err, kata_types::KataError::Validation(_)), "{err}");
}

/// Two members of ONE authored stage — a loop's iteration 0
/// and iteration 1 worker — share the stage's contract and its `#apply/<stage>`
/// spelling; their occurrence paths differ. A TERMINAL apply at iteration 0's
/// member path is iteration 0's recorded answer, not the stage's: the sweep
/// must still enumerate iteration 1's owed apply and its claim must still be
/// fresh. The latches that answered "is this stage's apply settled?" by stage
/// name collapse the second member's apply into the first's verdict.
#[test]
fn member_applies_under_one_stage_name_are_path_distinct() {
    let planes = planes();
    declare_environment(&planes);
    let execution_id = Ulid::new();
    submit(&planes, execution_id);
    let work = work_tree(&planes, execution_id);
    let head = planes
        .db
        .record_work_tree_head(execution_id, "basecommit", work.id().0.0, "wccommit")
        .unwrap();
    // Members of one stage mint occurrences of the stage's own contract at
    // CHILD paths of the expansion's — `expand.child(N).child(m)` — which is
    // exactly `(7, iteration, 0)` here: the stage contract is shared, the
    // coordinate is not.
    let member = |iteration: u32| {
        OccurrenceRef::new(
            kata_types::workflow::ExecutionId(execution_id),
            ContentHash::new([0xA7; 32]),
            OperationContractId(ContentHash::new([0x6C; 32])),
            OperationPath(vec![7, iteration, 0]),
        )
    };
    let (delta0, _delta0) = delta(&planes, &work);
    accept_capsule_with_delta(&planes, execution_id, &member(0), &work, &delta0);
    let (delta1, _delta1) = delta(&planes, &work);
    accept_capsule_with_delta(&planes, execution_id, &member(1), &work, &delta1);
    let pending = planes.db.pending_work_applies(execution_id).unwrap();
    assert_eq!(
        pending.len(),
        2,
        "each member occurrence owes its own apply: {pending:?}"
    );
    // Iteration 0's apply claims, then records a TERMINAL verdict — a stale
    // base — without accepting.
    let spec0 = apply_spec(execution_id, &pending[0]);
    assert_eq!(pending[0].operation_path, member(0).path.canonical_bytes());
    let attempt0 = Ulid::new();
    let claimed0 = planes
        .db
        .claim_work_apply_attempt(attempt0, &spec0, "", head.work_tree_artifact_id)
        .unwrap();
    assert!(
        matches!(claimed0, WorkApplyClaimOutcome::Claimed { .. }),
        "iteration 0's apply claims: {claimed0:?}"
    );
    planes
        .db
        .fail_work_apply_attempt(attempt0, "the delta's base is spent")
        .unwrap();
    // Iteration 1's member is still owed: its apply occurrence is neither
    // accepted nor terminal — the sweep must name exactly its row.
    let pending = planes.db.pending_work_applies(execution_id).unwrap();
    let paths: Vec<OperationPath> = pending
        .iter()
        .map(|row| OperationPath::from_canonical_bytes(&row.operation_path).unwrap())
        .collect();
    assert_eq!(
        paths,
        vec![OperationPath(vec![7, 1, 0])],
        "only iteration 1's member is still owed: {paths:?}"
    );
    // And its claim is FRESH, not the recorded-terminal answer of the sibling
    // member's apply under the same `#apply/<stage>` name.
    let spec1 = apply_spec(execution_id, &pending[0]);
    let claim1 = planes
        .db
        .claim_work_apply_attempt(Ulid::new(), &spec1, "", head.work_tree_artifact_id)
        .expect("iteration 1's apply claims");
    assert!(
        matches!(claim1, WorkApplyClaimOutcome::Claimed { .. }),
        "iteration 1's apply is a fresh claim, not a converged terminal: {claim1:?}"
    );
}

/// A resolved apply advances the head — artifact AND candidate, atomically —
/// drains the sweep, and releases the successor gate.
#[test]
fn resolving_the_apply_advances_the_head_and_leaves_the_sweep() {
    let (planes, execution_id, row, _delta, head) = rig_with_pending_apply();
    let spec = apply_spec(execution_id, &row);
    let attempt_id = Ulid::new();
    planes
        .db
        .claim_work_apply_attempt(attempt_id, &spec, "", head.work_tree_artifact_id)
        .unwrap();
    let new_artifact = applied_artifact(&planes, execution_id);
    let advance = WorkTreeHeadAdvance {
        work_tree_artifact_id: new_artifact,
        candidate_commit_id: "appliedwc".to_owned(),
        expected_head_seq: head.head_seq,
        expected_artifact_id: head.work_tree_artifact_id,
    };
    planes
        .db
        .resolve_work_apply_attempt(
            attempt_id,
            "",
            Some(&advance),
            &serde_json::json!({"ok": true}),
        )
        .unwrap();
    let moved = planes
        .db
        .execution_work_tree_head(execution_id)
        .unwrap()
        .unwrap();
    assert_eq!(moved.candidate_commit_id, "appliedwc");
    assert_eq!(moved.work_tree_artifact_id, new_artifact);
    assert_eq!(moved.head_seq, head.head_seq + 1);
    assert!(
        planes
            .db
            .pending_work_applies(execution_id)
            .unwrap()
            .is_empty()
    );
    assert!(
        !planes
            .db
            .pending_work_apply_for_stage(execution_id, STAGE)
            .unwrap(),
        "the resolved apply releases the gate"
    );
    assert!(
        planes
            .db
            .work_apply_accepted(execution_id, row.operation_contract_id, &row.operation_path)
            .unwrap(),
        "the apply occurrence is accepted"
    );
}

/// A delta whose base is not the recorded head fails the apply attempt with
/// `work_delta_base_stale` — a second delta over a moved head is refused, never
/// re-based.
#[test]
fn a_delta_against_a_moved_head_fails_with_work_delta_base_stale() {
    let (planes, execution_id, row, _delta, head) = rig_with_pending_apply();
    let spec = apply_spec(execution_id, &row);
    let attempt_id = Ulid::new();
    let outcome = planes
        .db
        .claim_work_apply_attempt(attempt_id, &spec, "", [0x55; 32])
        .unwrap();
    match outcome {
        WorkApplyClaimOutcome::StaleBase { reason, .. } => {
            assert!(reason.contains(WORK_DELTA_BASE_STALE), "{reason}");
        }
        other => panic!("a stale-based claim is the refusal arm: {other:?}"),
    }
    let attempt = planes.db.attempt(attempt_id).unwrap().unwrap();
    assert!(
        attempt.finished_at_ms.is_some(),
        "the stale apply attempt is recorded terminal, not retried"
    );
    assert!(
        planes
            .db
            .pending_work_applies(execution_id)
            .unwrap()
            .is_empty()
    );
    let unchanged = planes
        .db
        .execution_work_tree_head(execution_id)
        .unwrap()
        .unwrap();
    assert_eq!(unchanged.head_seq, head.head_seq);
}

/// A failed resolve is the effect's recorded outcome; the head does not move.
#[test]
fn a_failed_resolve_is_recorded_and_the_head_stays() {
    let (planes, execution_id, row, _delta, head) = rig_with_pending_apply();
    let spec = apply_spec(execution_id, &row);
    let attempt_id = Ulid::new();
    planes
        .db
        .claim_work_apply_attempt(attempt_id, &spec, "", head.work_tree_artifact_id)
        .unwrap();
    planes
        .db
        .fail_work_apply_attempt(
            attempt_id,
            "work_apply_candidate_diverged: the workspace moved",
        )
        .unwrap();
    let attempt = planes.db.attempt(attempt_id).unwrap().unwrap();
    assert!(attempt.finished_at_ms.is_some());
    let unchanged = planes
        .db
        .execution_work_tree_head(execution_id)
        .unwrap()
        .unwrap();
    assert_eq!(unchanged.head_seq, head.head_seq);
    assert_eq!(unchanged.candidate_commit_id, head.candidate_commit_id);
    // A re-drive does not resurrect a settled attempt.
    let reclaim = planes
        .db
        .claim_work_apply_attempt(Ulid::new(), &spec, "", head.work_tree_artifact_id)
        .unwrap();
    assert!(
        !matches!(reclaim, WorkApplyClaimOutcome::Claimed { .. }),
        "a failed apply is not re-claimed: {reclaim:?}"
    );
}

/// The head advance is a compare-and-swap on the read state: a stale
/// expectation refuses `work_tree_head_divergent` and writes nothing.
#[test]
fn the_head_advance_is_checked_against_the_read() {
    let (planes, execution_id, row, _delta, head) = rig_with_pending_apply();
    let spec = apply_spec(execution_id, &row);
    let attempt_id = Ulid::new();
    planes
        .db
        .claim_work_apply_attempt(attempt_id, &spec, "", head.work_tree_artifact_id)
        .unwrap();
    let new_artifact = applied_artifact(&planes, execution_id);
    let error = planes
        .db
        .resolve_work_apply_attempt(
            attempt_id,
            "",
            Some(&WorkTreeHeadAdvance {
                work_tree_artifact_id: new_artifact,
                candidate_commit_id: "other".to_owned(),
                // The caller read head_seq but pretends the row already moved.
                expected_head_seq: head.head_seq + 1,
                expected_artifact_id: head.work_tree_artifact_id,
            }),
            &serde_json::json!({"ok": true}),
        )
        .expect_err("a stale head expectation refuses");
    assert!(
        error.to_string().contains(WORK_DELTA_BASE_STALE),
        "the moved-head refusal is the named stale boundary: {error}"
    );
    let unchanged = planes
        .db
        .execution_work_tree_head(execution_id)
        .unwrap()
        .unwrap();
    assert_eq!(
        unchanged.head_seq, head.head_seq,
        "the refused advance did not land"
    );
    assert!(
        !planes
            .db
            .work_apply_accepted(execution_id, row.operation_contract_id, &row.operation_path)
            .unwrap(),
        "a refused resolve does not accept the occurrence"
    );
}
