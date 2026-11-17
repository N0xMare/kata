//! Closed-world verifier proofs for the seven-axis checked execution class.
//!
//! The centerpiece is the exhaustive 1,728-tuple sweep: every enum-value
//! combination is verified against an INDEPENDENT transcription of the
//! closed-world matrix (a flat conjunction, structurally distinct from the
//! sequential [`CheckedExecutionClass::validate`]), across representative op
//! contexts, and the valid set is asserted to be EXACTLY the closed-world matrix
//! plus the two op-gated admissions.

use super::*;

use Computation::{ProcessAction, PureTransform, WaitForInput};
use Containment::{Contained, HostUnconfined, InProcess};
use Determinism::{Deterministic, Nondeterministic};
use ExternalIssuance::{DurableActivity, None as IssNone};
use Network::{BrokeredOnly, Offline, Unrestricted};
use PreCommitRecovery::{
    AwaitRecordedInput, ManualResolution, RecomputeAllowed, ReconcileRequired,
};
use Workspace::{DeclaredOutputs, MutableCandidate, None as WsNone, ReadOnly};

/// Every tuple in the 1,728-element product space, in a stable order.
fn all_tuples() -> Vec<CheckedExecutionClass> {
    let mut out = Vec::with_capacity(1728);
    for &computation in Computation::ALL {
        for &determinism in Determinism::ALL {
            for &containment in Containment::ALL {
                for &workspace in Workspace::ALL {
                    for &network in Network::ALL {
                        for &external_issuance in ExternalIssuance::ALL {
                            for &pre_commit_recovery in PreCommitRecovery::ALL {
                                out.push(CheckedExecutionClass {
                                    computation,
                                    determinism,
                                    containment,
                                    workspace,
                                    network,
                                    external_issuance,
                                    pre_commit_recovery,
                                });
                            }
                        }
                    }
                }
            }
        }
    }
    out
}

/// INDEPENDENT transcription of the ADR-0001 closed-world matrix as a flat
/// conjunction of row implications — deliberately written in a different shape
/// than the sequential `validate_closed_world` so a shared bug is unlikely to
/// hide in both. A tuple is closed-world valid iff every implication holds.
#[allow(clippy::nonminimal_bool, clippy::too_many_lines)]
fn expected_valid_closed_world(c: CheckedExecutionClass) -> bool {
    // R1 — PureTransform base row.
    let r1 = c.computation != PureTransform
        || (c.determinism == Deterministic
            && c.containment == InProcess
            && c.workspace == WsNone
            && c.network == Offline
            && c.external_issuance == IssNone
            && c.pre_commit_recovery == RecomputeAllowed);
    // R2 — WaitForInput base row.
    let r2 = c.computation != WaitForInput
        || (c.determinism == Nondeterministic
            && c.containment == InProcess
            && c.workspace == WsNone
            && c.network == Offline
            && c.external_issuance == IssNone
            && c.pre_commit_recovery == AwaitRecordedInput);
    // R3 — ProcessAction requires an explicit host posture.
    let r3 = c.computation != ProcessAction || matches!(c.containment, Contained | HostUnconfined);
    // R4 — Deterministic forbids a live network.
    let r4 = c.determinism != Deterministic || c.network == Offline;
    // R5 — InProcess row.
    let r5 = c.containment != InProcess
        || (matches!(c.computation, PureTransform | WaitForInput)
            && c.workspace != MutableCandidate);
    // R6 — HostUnconfined row.
    let r6 = c.containment != HostUnconfined
        || (matches!(c.workspace, WsNone | MutableCandidate) && c.network == Unrestricted);
    // R7 — ReadOnly requires a Contained provider.
    let r7 = c.workspace != ReadOnly || c.containment == Contained;
    // R8 — DeclaredOutputs requires a Contained provider.
    let r8 = c.workspace != DeclaredOutputs || c.containment == Contained;
    // R9 — MutableCandidate requires a placed provider.
    let r9 = c.workspace != MutableCandidate || matches!(c.containment, Contained | HostUnconfined);
    // R10 — BrokeredOnly row.
    let r10 = c.network != BrokeredOnly
        || (c.determinism == Nondeterministic
            && c.containment == Contained
            && c.external_issuance == DurableActivity);
    // R11 — Unrestricted row.
    let r11 = c.network != Unrestricted
        || (c.determinism == Nondeterministic && c.external_issuance == DurableActivity);
    // R12 — issuance None excludes a live network.
    let r12 = c.external_issuance != IssNone || c.network == Offline;
    // R13 — DurableActivity forbids RecomputeAllowed.
    let r13 = c.external_issuance != DurableActivity || c.pre_commit_recovery != RecomputeAllowed;
    // R14 — RecomputeAllowed requires issuance None.
    let r14 = c.pre_commit_recovery != RecomputeAllowed || c.external_issuance == IssNone;
    // R15 — AwaitRecordedInput requires WaitForInput.
    let r15 = c.pre_commit_recovery != AwaitRecordedInput || c.computation == WaitForInput;
    // R16 — ReconcileRequired requires DurableActivity.
    let r16 = c.pre_commit_recovery != ReconcileRequired || c.external_issuance == DurableActivity;
    // R17 — ManualResolution requires DurableActivity.
    let r17 = c.pre_commit_recovery != ManualResolution || c.external_issuance == DurableActivity;
    r1 && r2
        && r3
        && r4
        && r5
        && r6
        && r7
        && r8
        && r9
        && r10
        && r11
        && r12
        && r13
        && r14
        && r15
        && r16
        && r17
}

/// Independent expectation for `validate(class, op)`: the op-gated admissions
/// layered over the closed-world matrix.
fn expected_valid(c: CheckedExecutionClass, op: CheckedOpContext) -> bool {
    if c == CheckedExecutionClass::ADMISSION_RECORDED_LOCAL_MUTATION {
        return op.is_workspace_provider_op();
    }
    if c == CheckedExecutionClass::ADMISSION_ADAPTER_ISSUANCE {
        return op.is_adapter_op();
    }
    expected_valid_closed_world(c)
}

/// The op contexts the sweep exercises: Standard (no admission), all three
/// workspace-provider ops (admission 1), and the adapter op (admission 2).
const SWEEP_OPS: &[CheckedOpContext] = &[
    CheckedOpContext::Standard,
    CheckedOpContext::WorkspacePark,
    CheckedOpContext::WorkspacePromote,
    CheckedOpContext::WorkspaceCommit,
    CheckedOpContext::ForgeLand,
];

/// ADR-0001 required proof 5 — the exhaustive sweep. Every one of the 1,728
/// tuples, across every representative op context, is verified against the
/// independent matrix transcription; the valid set is EXACTLY the closed-world
/// matrix plus the two op-gated admissions, and every refusal is well-formed
/// (a stable R-code and one of the seven axes).
#[test]
fn exhaustive_sweep_matches_the_closed_world_matrix_plus_admissions() {
    let tuples = all_tuples();
    assert_eq!(
        tuples.len(),
        1728,
        "the axis product space is 3·2·3·4·3·2·4"
    );

    let valid_codes = [
        "R1", "R2", "R3", "R4", "R5", "R6", "R7", "R8", "R9", "R10", "R11", "R12", "R13", "R14",
        "R15", "R16", "R17", "R18", "R19",
    ];

    for &op in SWEEP_OPS {
        let mut valid_count = 0usize;
        for class in &tuples {
            let got = class.validate(op);
            let want = expected_valid(*class, op);
            assert_eq!(
                got.is_ok(),
                want,
                "validate disagrees with the independent matrix for {class:?} under op={}",
                op.label()
            );
            match got {
                Ok(()) => valid_count += 1,
                Err(refusal) => {
                    assert!(
                        valid_codes.contains(&refusal.code),
                        "refusal code {} is not a named diagnostic (R1..R19)",
                        refusal.code
                    );
                    // The axis is one of the seven (total by construction — the
                    // assert documents the contract).
                    assert!(!Axis::label(refusal.axis).is_empty());
                }
            }
        }

        // The closed-world matrix admits exactly 46 base tuples. A
        // workspace-provider op adds admission 1 (→47); the adapter op adds
        // admission 2 (→47); Standard adds neither (46).
        let expected = if op.is_workspace_provider_op() || op.is_adapter_op() {
            47
        } else {
            46
        };
        assert_eq!(
            valid_count,
            expected,
            "valid tuple count for op={} must be {expected}",
            op.label()
        );
    }
}

/// The closed-world base (no admission) valid set is 46 tuples, and NEITHER
/// admission tuple is in it (both become valid only via their op gate).
#[test]
fn closed_world_base_is_46_and_excludes_both_admissions() {
    let base_valid = all_tuples()
        .into_iter()
        .filter(|c| c.validate(CheckedOpContext::Standard).is_ok())
        .count();
    assert_eq!(base_valid, 46);

    assert!(
        CheckedExecutionClass::ADMISSION_RECORDED_LOCAL_MUTATION
            .validate(CheckedOpContext::Standard)
            .is_err(),
        "admission 1 must not be base-valid"
    );
    assert!(
        CheckedExecutionClass::ADMISSION_ADAPTER_ISSUANCE
            .validate(CheckedOpContext::Standard)
            .is_err(),
        "admission 2 must not be base-valid"
    );
}

/// Every content-cache-eligible class is a valid class (the derived predicate
/// can never green an invalid combination).
#[test]
fn cache_eligible_implies_valid() {
    for class in all_tuples() {
        if class.is_content_cache_eligible() {
            assert!(
                class.validate(CheckedOpContext::Standard).is_ok(),
                "cache-eligible class must be valid: {class:?}"
            );
        }
    }
}

// ── CONFINEMENT vs CACHEABILITY — the predicate the split needs, measured ──

/// The predicate that `ExecutionProgramStage::should_confine_to_declared_inputs`
/// MEANS, transcribed here rather than minted on [`CheckedExecutionClass`].
///
/// It reads: *nothing in this class's DECLARED semantics requires an undeclared,
/// ambient host input, so holding the action to its declared input closure
/// cannot be the reason it fails to start.* That is
/// [`CheckedExecutionClass::is_content_cache_eligible`]'s conjunction with the
/// WORKSPACE conjunct removed and nothing else changed — every remaining
/// conjunct is an INPUT property (what the action is; whether its inputs are all
/// identified; whether a provider can fence them; whether a live network can
/// supply one; whether an effect already escaped that recomputation would
/// re-issue), while [`Workspace`] is an OUTPUT axis about what may be WRITTEN
/// and who bounds the write set.
///
/// # Why this is a test-local transcription and NOT a `pub fn` on the class
///
/// [`confinement_predicate_is_strictly_wider_than_cacheability_by_one_valid_tuple`]
/// proves the two selections are NOT the same set over the closed-world matrix,
/// so repointing `should_confine_to_declared_inputs` at this predicate would not
/// be behaviour-preserving at the durable decode boundary. A `pub fn` no
/// production path calls would read as a control that nobody can invoke ("a
/// named recourse nobody can invoke, which is worse than an absent one because
/// it reads as a control"). So the predicate lives here, in the proof that
/// decides whether it may ship.
fn needs_no_ambient_host_input(c: CheckedExecutionClass) -> bool {
    c.computation == ProcessAction
        && c.determinism == Deterministic
        && c.containment == Contained
        && c.network == Offline
        && c.external_issuance == IssNone
        && c.pre_commit_recovery == RecomputeAllowed
}

/// The ONE tuple that separates the two selections: a `Contained`, `Deterministic`,
/// `Offline`, non-issuing, recomputable `ProcessAction` holding an UNBOUNDED
/// writable tree.
///
/// It is closed-world VALID — R3 admits `ProcessAction + Contained`, R9 admits
/// `MutableCandidate + Contained`, and no other row constrains the pair — and it
/// is refused by the cacheability conjunct only because `MutableCandidate` is an
/// output-side classification.
const UNBOUNDED_WRITE_HERMETIC: CheckedExecutionClass = CheckedExecutionClass {
    computation: ProcessAction,
    determinism: Deterministic,
    containment: Contained,
    workspace: MutableCandidate,
    network: Offline,
    external_issuance: IssNone,
    pre_commit_recovery: RecomputeAllowed,
};

/// **The two selections differ by exactly one tuple.** Repointing
/// `ExecutionProgramStage::should_confine_to_declared_inputs` from
/// `is_content_cache_eligible` onto [`needs_no_ambient_host_input`] is NOT
/// set-preserving over the closed-world matrix: it admits EXACTLY ONE tuple
/// more, [`UNBOUNDED_WRITE_HERMETIC`].
///
/// # The matrix admits that tuple
///
/// It is tempting to assume *"no valid class is `Contained + Deterministic + Offline +
/// no-issuance + RecomputeAllowed` while carrying `MutableCandidate`"*. That is FALSE, and the
/// matrix is what says so: R3 requires `ProcessAction` to be `Contained` or `HostUnconfined` and
/// R9 requires `MutableCandidate` to be `Contained` or `HostUnconfined` — both are satisfied by
/// `Contained`, and NO row forbids the combination.
///
/// The tuple is reachable from the derivation too: every `fs = "workspace-rw"`
/// stage under a contained, offline, deterministic executor with no ENFORCED
/// output closure DERIVES it —
/// `kata_program::execution_program::execution_class`'s
/// `tests::confinement_is_decided_without_the_workspace_axis_over_the_whole_derivation`
/// asserts that REACHABILITY as its first, non-vacuity clause. Only the matrix
/// half is this test's subject.
///
/// # Why the distinction is load-bearing rather than pedantic
///
/// `ExecutionProgramStage::execution_class` is a HASHED, DURABLE field, and
/// `ExecutionProgram::validate_carried_stage_execution_classes` deliberately
/// admits any tuple the closed-world matrix accepts — its own doc says it *"does
/// not require the carried class to EQUAL today's derivation … a program written
/// before such a change can carry a tuple that is valid, that the runtime can
/// honour, and that today's derivation would no longer produce"*. The runtime
/// then reads the CARRIED tuple for every axis verdict. So the decode door
/// admits [`UNBOUNDED_WRITE_HERMETIC`] BY CONTRACT, not by oversight, and the
/// repoint would silently move such a stage onto the hermetic declared-inputs
/// arm. That is a containment change with no test observing it.
///
/// # Why this test is a change detector and not a pin of a defect
///
/// Nothing here asserts the gap SHOULD exist. It asserts its exact size and
/// membership, so that (a) collapsing it — by dropping the workspace conjunct
/// from `is_content_cache_eligible`, which is the naive spelling of the same
/// repoint — goes RED here, and (b) GROWING it, by relaxing any other conjunct
/// or any matrix row, also goes RED. The gap is the whole decision, so the
/// decision cannot move without a test failing.
///
/// # What has to happen for the repoint to be sound
///
/// The gap tuple is EXACTLY the tuple a hermetic `workspace-rw` shell stage
/// derives, so the repoint changes those stages' confinement. It therefore
/// needs ONE change with ONE guard — a test that fixes a hermetic
/// `workspace-rw` shell stage's directive across the repoint — never a
/// "behaviour-preserving" repoint on its own.
#[test]
fn confinement_predicate_is_strictly_wider_than_cacheability_by_one_valid_tuple() {
    // Every tuple valid under SOME representative op — the closed-world base
    // plus the two op-gated admissions.
    let valid: Vec<CheckedExecutionClass> = all_tuples()
        .into_iter()
        .filter(|c| SWEEP_OPS.iter().any(|op| c.validate(*op).is_ok()))
        .collect();
    assert_eq!(
        valid.len(),
        48,
        "46 closed-world base tuples + 2 op-gated admissions"
    );

    // `containment == Contained` is a conjunct BOTH predicates already carry, so
    // each selection is its predicate alone. The redundancy is written out rather
    // than assumed.
    let cacheable: Vec<CheckedExecutionClass> = valid
        .iter()
        .copied()
        .filter(|c| c.containment == Contained && c.is_content_cache_eligible())
        .collect();
    let confinable: Vec<CheckedExecutionClass> = valid
        .iter()
        .copied()
        .filter(|c| c.containment == Contained && needs_no_ambient_host_input(*c))
        .collect();
    for c in valid.iter().copied() {
        assert_eq!(
            c.is_content_cache_eligible(),
            c.containment == Contained && c.is_content_cache_eligible(),
            "the certified-container conjunct is redundant against cacheability for {c:?}"
        );
        assert_eq!(
            needs_no_ambient_host_input(c),
            c.containment == Contained && needs_no_ambient_host_input(c),
            "the certified-container conjunct is redundant against confinement for {c:?}"
        );
    }

    // NON-VACUITY: both selections are non-empty, so the comparison below is a
    // real observation and not two empty sets agreeing.
    assert_eq!(
        cacheable.len(),
        3,
        "cacheable ∩ Contained = {{scratch, workspace-ro, workspace-rw-deterministic}}: {cacheable:#?}"
    );
    assert_eq!(
        confinable.len(),
        4,
        "the same three plus the unbounded-write tuple: {confinable:#?}"
    );

    // STRICTLY WIDER, in the safe direction: dropping a conjunct can only add.
    let only_cacheable: Vec<CheckedExecutionClass> = cacheable
        .iter()
        .copied()
        .filter(|c| !confinable.contains(c))
        .collect();
    assert!(
        only_cacheable.is_empty(),
        "dropping a conjunct must never REMOVE a member; removed: {only_cacheable:#?}"
    );

    // …and the widening is EXACTLY the one named tuple.
    let only_confinable: Vec<CheckedExecutionClass> = confinable
        .iter()
        .copied()
        .filter(|c| !cacheable.contains(c))
        .collect();
    assert_eq!(
        only_confinable,
        vec![UNBOUNDED_WRITE_HERMETIC],
        "the repoint's widening must be exactly the unbounded-write hermetic tuple"
    );

    // The gap tuple is admitted by the decode door — this is WHY the gap is
    // reachable rather than theoretical.
    assert!(
        UNBOUNDED_WRITE_HERMETIC
            .validate(CheckedOpContext::Standard)
            .is_ok(),
        "the gap tuple is closed-world VALID, so a durable program may carry it"
    );
    assert!(
        !UNBOUNDED_WRITE_HERMETIC.is_content_cache_eligible(),
        "the gap tuple is refused the content cache — an unbounded write set is \
         not a captured output closure, and THAT refusal is correct"
    );
    assert!(
        UNBOUNDED_WRITE_HERMETIC.is_workspace_mutating(),
        "non-vacuity: the gap tuple really is the unbounded-write one"
    );
}

/// TASK 4 — a model/agent stage is excluded from declared-input confinement by
/// TWO INDEPENDENT conjuncts, so relaxing either one alone cannot start
/// confining agent stages.
///
/// # FAILURE MODE
///
/// `should_confine_to_declared_inputs`'s doc records the measurement (this
/// kernel, bubblewrap 0.9.0, `claude` 2.1.228): a CONFINED wrap binds no `$HOME`
/// at all, so `command -v claude` is NOT RESOLVABLE and the stage cannot launch.
/// A model stage's containment is `Contained` or `HostUnconfined`, and the
/// latter is refused at compile by `[containment] require_contained_model_stages`
/// (shipped default `true`) — so confining model stages leaves no way to author
/// a working agent stage at all.
///
/// # The two conjuncts, and why one is not enough
///
/// `derive_process_class` sets `determinism = Nondeterministic` for every model
/// executor unconditionally, and `external_issuance = DurableActivity` whenever
/// `is_model || network != Offline`. R13 then forces `pre_commit_recovery` off
/// `RecomputeAllowed`. So a model class fails `Deterministic`, fails
/// `issuance None`, and fails `RecomputeAllowed` — three ways, at least two of
/// them independent of the network posture. A future edit that relaxed exactly
/// one would still not admit an agent stage, and this test is what says so.
#[test]
fn a_model_class_fails_confinement_on_two_independent_conjuncts() {
    // ADR-0001's canonical model-backed candidate editor.
    let model_editor = CheckedExecutionClass {
        computation: ProcessAction,
        determinism: Nondeterministic,
        containment: Contained,
        workspace: MutableCandidate,
        network: Unrestricted,
        external_issuance: DurableActivity,
        pre_commit_recovery: ReconcileRequired,
    };
    assert!(model_editor.validate(CheckedOpContext::Standard).is_ok());
    assert!(!needs_no_ambient_host_input(model_editor));
    assert!(!model_editor.is_content_cache_eligible());

    // Conjunct 1 — determinism. Repair ONLY the issuance/recovery axes and the
    // class is still refused, because a model executor is never `Deterministic`.
    let issuance_repaired = CheckedExecutionClass {
        network: Offline,
        external_issuance: IssNone,
        pre_commit_recovery: RecomputeAllowed,
        ..model_editor
    };
    assert!(
        issuance_repaired
            .validate(CheckedOpContext::Standard)
            .is_ok(),
        "non-vacuity: the repaired tuple must be VALID, or the refusal below is \
         about validity rather than about the predicate"
    );
    assert!(
        !needs_no_ambient_host_input(issuance_repaired),
        "determinism alone still excludes a model class"
    );

    // Conjunct 2 — issuance. Repair determinism AND the network it drags with it
    // (R4 forbids `Deterministic + Unrestricted`, so repairing determinism alone
    // would produce an INVALID tuple and the refusal below would be about
    // validity rather than about issuance). What is left failing is then exactly
    // the issuance pair, because a model call binds a `DurableActivity` claim.
    let determinism_repaired = CheckedExecutionClass {
        determinism: Deterministic,
        network: Offline,
        ..model_editor
    };
    assert!(
        determinism_repaired
            .validate(CheckedOpContext::Standard)
            .is_ok(),
        "non-vacuity: the repaired tuple must be VALID, or the refusal below is \
         about validity rather than about the predicate"
    );
    assert_eq!(
        (
            determinism_repaired.external_issuance,
            determinism_repaired.pre_commit_recovery,
        ),
        (DurableActivity, ReconcileRequired),
        "the ONLY axes still failing are the issuance pair"
    );
    assert!(
        !needs_no_ambient_host_input(determinism_repaired),
        "issuance alone still excludes a model class"
    );

    // Both repaired together IS admitted — which is exactly why neither may be
    // relaxed silently. This is the non-vacuity that makes the two assertions
    // above statements about the predicate rather than about a constant `false`.
    let both_repaired = CheckedExecutionClass {
        determinism: Deterministic,
        network: Offline,
        external_issuance: IssNone,
        pre_commit_recovery: RecomputeAllowed,
        ..model_editor
    };
    assert!(
        needs_no_ambient_host_input(both_repaired),
        "non-vacuity: repairing BOTH conjuncts admits the class — so the \
         predicate is a verdict, not a constant"
    );
    // …and that fully-repaired tuple is precisely the gap tuple, which is the
    // second reason the repoint is not free: the only way to make a model
    // stage's SHAPE confinable is to make it stop being a model stage.
    assert_eq!(both_repaired, UNBOUNDED_WRITE_HERMETIC);
}

// ── op-gated admission proofs (counterexamples a–d) ────────────────────────

/// Admission 1 is valid ONLY for a workspace-provider op; the SAME
/// tuple under a non-workspace op refuses (R18) — counterexample (a).
#[test]
fn admission1_is_op_gated() {
    let class = CheckedExecutionClass::ADMISSION_RECORDED_LOCAL_MUTATION;
    // Valid for each workspace-provider op.
    for op in [
        CheckedOpContext::WorkspacePark,
        CheckedOpContext::WorkspacePromote,
        CheckedOpContext::WorkspaceCommit,
    ] {
        assert!(
            class.validate(op).is_ok(),
            "admission 1 valid for {}",
            op.label()
        );
    }
    // Refused for a bare/standard op and for the adapter op.
    for op in [CheckedOpContext::Standard, CheckedOpContext::ForgeLand] {
        let err = class
            .validate(op)
            .expect_err("admission-1 shape without a workspace op refuses");
        assert_eq!(err.code, "R18");
        assert_eq!(err.axis, Axis::Containment);
    }
}

/// Admission 2 is valid ONLY for an adapter op. counterexample (c): a
/// model-call op (Standard) claiming the same InProcess tuple refuses (R19).
#[test]
fn admission2_is_op_gated_and_refuses_model_inprocess() {
    let class = CheckedExecutionClass::ADMISSION_ADAPTER_ISSUANCE;
    assert!(class.validate(CheckedOpContext::ForgeLand).is_ok());
    // A model/agent call is Standard, not an adapter op — InProcess refuses.
    for op in [CheckedOpContext::Standard, CheckedOpContext::WorkspacePark] {
        let err = class
            .validate(op)
            .expect_err("admission-2 shape without an adapter op refuses");
        assert_eq!(err.code, "R19");
        assert_eq!(err.axis, Axis::Containment);
    }
}

/// Counterexample (b): an admission-2 tuple with
/// `workspace=MutableCandidate` (not the exact `None` tuple) refuses even under
/// the adapter op — the candidate binds as a tree-id input, never a held grant.
#[test]
fn admission2_refuses_mutable_candidate() {
    let class = CheckedExecutionClass {
        workspace: MutableCandidate,
        ..CheckedExecutionClass::ADMISSION_ADAPTER_ISSUANCE
    };
    let err = class
        .validate(CheckedOpContext::ForgeLand)
        .expect_err("admission 2 with MutableCandidate is not the exact tuple");
    // Falls through to the matrix: ProcessAction + InProcess refuses at R3.
    assert_eq!(err.code, "R3");
    assert_eq!(err.axis, Axis::Containment);
}

/// Counterexample (d): a `ProcessAction + InProcess` tuple WITHOUT
/// `DurableActivity` refuses (it is not the admission-2 tuple; the matrix
/// refuses ProcessAction+InProcess at R3) — even under the adapter op.
#[test]
fn process_action_inprocess_without_durable_activity_refuses() {
    let class = CheckedExecutionClass {
        computation: ProcessAction,
        determinism: Nondeterministic,
        containment: InProcess,
        workspace: WsNone,
        network: Unrestricted,
        external_issuance: IssNone,
        pre_commit_recovery: ManualResolution,
    };
    for op in [CheckedOpContext::ForgeLand, CheckedOpContext::Standard] {
        let err = class
            .validate(op)
            .expect_err("ProcessAction+InProcess without DurableActivity");
        assert_eq!(err.code, "R3", "op={}", op.label());
    }
}

// ── Anchor tuples: named examples ──────────────────────────────────────────

#[test]
fn named_example_tuples_are_valid() {
    // Model-backed candidate editor.
    let model_editor = CheckedExecutionClass {
        computation: ProcessAction,
        determinism: Nondeterministic,
        containment: Contained,
        workspace: MutableCandidate,
        network: Unrestricted,
        external_issuance: DurableActivity,
        pre_commit_recovery: ReconcileRequired,
    };
    assert!(model_editor.validate(CheckedOpContext::Standard).is_ok());
    assert_eq!(model_editor.external_issuance, DurableActivity);
    assert!(!model_editor.is_content_cache_eligible());
    assert!(model_editor.is_workspace_mutating());

    // Hermetic shell build — content-cacheable.
    let shell_build = CheckedExecutionClass {
        computation: ProcessAction,
        determinism: Deterministic,
        containment: Contained,
        workspace: DeclaredOutputs,
        network: Offline,
        external_issuance: IssNone,
        pre_commit_recovery: RecomputeAllowed,
    };
    assert!(shell_build.validate(CheckedOpContext::Standard).is_ok());
    assert!(shell_build.is_content_cache_eligible());

    // Human gate — a main-owned durable wait.
    let human_gate = CheckedExecutionClass {
        computation: WaitForInput,
        determinism: Nondeterministic,
        containment: InProcess,
        workspace: WsNone,
        network: Offline,
        external_issuance: IssNone,
        pre_commit_recovery: AwaitRecordedInput,
    };
    assert!(human_gate.validate(CheckedOpContext::Standard).is_ok());
    assert!(!human_gate.is_content_cache_eligible());
    assert!(!human_gate.is_workspace_mutating());

    // Pure transform — main-owned typed value.
    let pure = CheckedExecutionClass {
        computation: PureTransform,
        determinism: Deterministic,
        containment: InProcess,
        workspace: WsNone,
        network: Offline,
        external_issuance: IssNone,
        pre_commit_recovery: RecomputeAllowed,
    };
    assert!(pure.validate(CheckedOpContext::Standard).is_ok());
    assert!(
        !pure.is_content_cache_eligible(),
        "PureTransform is not a ProcessAction"
    );

    // BrokeredOnly is a VALID combination (R10), and never refused at validity.
    // It is not refused ANYWHERE ELSE either — see
    // `brokered_only_is_accepted_if_carried_enforced_as_profile_and_refused_nowhere`
    // below.
    let brokered = CheckedExecutionClass {
        computation: ProcessAction,
        determinism: Nondeterministic,
        containment: Contained,
        workspace: ReadOnly,
        network: BrokeredOnly,
        external_issuance: DurableActivity,
        pre_commit_recovery: ReconcileRequired,
    };
    assert!(
        brokered.validate(CheckedOpContext::Standard).is_ok(),
        "BrokeredOnly must not be refused at validity"
    );
    assert!(!brokered.is_content_cache_eligible());
}

/// What is true of a `BrokeredOnly` class — pinned so a claim that it is
/// *"refused at placement (no certified broker)"* cannot come back as prose.
///
/// # Why a test
///
/// No code refuses such a class at placement. Such a claim would be unreachable
/// rather than mis-enforced — nothing mints the class, so no run would be
/// wrongly admitted — and a promise with no enforcement point has no failing case
/// to catch it. This test gives it one.
///
/// # The three facts
///
/// * **ACCEPTED IF CARRIED** — [`CheckedExecutionClass::validate`] admits the R10
///   combination, so a durable program whose stage already carries
///   `BrokeredOnly` revalidates clean.
/// * **REFUSED NOWHERE** — placement reads no class at all: `kata_workflow`'s
///   `Dispatcher::select_capsule_worker` takes no argument and asks every
///   capsule's worker the one constant `CAPSULE_PLACEMENT` (no capability, a
///   certified container). A question that reads no class cannot refuse on its
///   network axis. That is a signature, not a value, so this half carries no
///   assertion here.
/// * **ENFORCED AS PROFILE** — what a worker enforces is
///   [`crate::sandbox::NetPolicy`], whose shipped set has no brokered spelling at
///   all, so a carried `BrokeredOnly` changes nothing at the boundary.
#[test]
fn brokered_only_is_accepted_if_carried_enforced_as_profile_and_refused_nowhere() {
    let carried = CheckedExecutionClass {
        computation: ProcessAction,
        determinism: Nondeterministic,
        containment: Contained,
        workspace: ReadOnly,
        network: BrokeredOnly,
        external_issuance: DurableActivity,
        pre_commit_recovery: ReconcileRequired,
    };

    // ACCEPTED IF CARRIED.
    assert!(
        carried.validate(CheckedOpContext::Standard).is_ok(),
        "R10 admits this combination; a carried BrokeredOnly stage \
         revalidates rather than being turned away"
    );

    // ENFORCED AS PROFILE — the enforced posture cannot even spell it.
    let shipped: Vec<&str> = crate::sandbox::NetPolicy::SHIPPED
        .iter()
        .map(crate::sandbox::NetPolicy::label)
        .collect();
    assert_eq!(
        shipped,
        ["host", "offline"],
        "MEASURED CHANGE: the shipped enforced postures moved. `BrokeredOnly` is \
         reachable exactly when one of these spells it, and that is the moment a real \
         placement refusal becomes writable."
    );
    assert!(
        !shipped.contains(&Network::BrokeredOnly.label()),
        "a shipped NetPolicy now spells `{}`, so the class is no longer unreachable and \
         the accepted-if-carried / enforced-as-profile / refused-nowhere statement must \
         be re-decided",
        Network::BrokeredOnly.label(),
    );
}

// ── Per-rule refusal witnesses (axis + code) ───────────────────────────────

/// Each non-subsumed matrix/admission rule has a witness tuple that triggers it
/// with the right code and axis. R5/R7/R8/R9/R12/R14 are transitively SUBSUMED
/// by earlier rows (an InProcess/HostUnconfined workspace conflict is caught by
/// the computation or HostUnconfined row first; a live-network + issuance-None
/// conflict is caught by the BrokeredOnly/Unrestricted rows; a RecomputeAllowed +
/// issuance conflict is caught by the DurableActivity row). They remain in
/// `validate` as a faithful, defensive transcription of the ADR-0001 matrix
/// rows, and the sweep proves their constraints still hold on the valid set.
#[test]
fn each_refusal_rule_has_a_witness() {
    let base_pure = CheckedExecutionClass::ADMISSION_RECORDED_LOCAL_MUTATION; // PT tuple, ws=MC
    let cases: &[(CheckedExecutionClass, &str, Axis)] = &[
        // R1 — PureTransform determinism conflict.
        (
            CheckedExecutionClass {
                workspace: WsNone,
                determinism: Nondeterministic,
                ..base_pure
            },
            "R1",
            Axis::Determinism,
        ),
        // R2 — WaitForInput recovery conflict.
        (
            CheckedExecutionClass {
                computation: WaitForInput,
                determinism: Nondeterministic,
                containment: InProcess,
                workspace: WsNone,
                network: Offline,
                external_issuance: IssNone,
                pre_commit_recovery: RecomputeAllowed,
            },
            "R2",
            Axis::PreCommitRecovery,
        ),
        // R3 — ProcessAction + InProcess.
        (
            CheckedExecutionClass {
                computation: ProcessAction,
                determinism: Deterministic,
                containment: InProcess,
                workspace: WsNone,
                network: Offline,
                external_issuance: IssNone,
                pre_commit_recovery: RecomputeAllowed,
            },
            "R3",
            Axis::Containment,
        ),
        // R4 — Deterministic + Unrestricted.
        (
            CheckedExecutionClass {
                computation: ProcessAction,
                determinism: Deterministic,
                containment: Contained,
                workspace: WsNone,
                network: Unrestricted,
                external_issuance: IssNone,
                pre_commit_recovery: RecomputeAllowed,
            },
            "R4",
            Axis::Network,
        ),
        // R6 — HostUnconfined with a ReadOnly workspace claim.
        (
            CheckedExecutionClass {
                computation: ProcessAction,
                determinism: Nondeterministic,
                containment: HostUnconfined,
                workspace: ReadOnly,
                network: Unrestricted,
                external_issuance: DurableActivity,
                pre_commit_recovery: ReconcileRequired,
            },
            "R6",
            Axis::Workspace,
        ),
        // R10 — BrokeredOnly declared with issuance None (BrokeredOnly is a
        // durable activity). The determinism/containment sub-checks of R10 are
        // subsumed by R4/R1/R2/R3; the issuance sub-check is the witnessable one.
        (
            CheckedExecutionClass {
                computation: ProcessAction,
                determinism: Nondeterministic,
                containment: Contained,
                workspace: WsNone,
                network: BrokeredOnly,
                external_issuance: IssNone,
                pre_commit_recovery: RecomputeAllowed,
            },
            "R10",
            Axis::ExternalIssuance,
        ),
        // R11 — Unrestricted without DurableActivity (issuance None).
        (
            CheckedExecutionClass {
                computation: ProcessAction,
                determinism: Nondeterministic,
                containment: Contained,
                workspace: WsNone,
                network: Unrestricted,
                external_issuance: IssNone,
                pre_commit_recovery: RecomputeAllowed,
            },
            "R11",
            Axis::ExternalIssuance,
        ),
        // R13 — DurableActivity with RecomputeAllowed.
        (
            CheckedExecutionClass {
                computation: ProcessAction,
                determinism: Nondeterministic,
                containment: Contained,
                workspace: WsNone,
                network: Offline,
                external_issuance: DurableActivity,
                pre_commit_recovery: RecomputeAllowed,
            },
            "R13",
            Axis::PreCommitRecovery,
        ),
        // R15 — AwaitRecordedInput on a non-WaitForInput computation.
        (
            CheckedExecutionClass {
                computation: ProcessAction,
                determinism: Nondeterministic,
                containment: Contained,
                workspace: WsNone,
                network: Offline,
                external_issuance: DurableActivity,
                pre_commit_recovery: AwaitRecordedInput,
            },
            "R15",
            Axis::Computation,
        ),
        // R16 — ReconcileRequired without DurableActivity.
        (
            CheckedExecutionClass {
                computation: ProcessAction,
                determinism: Nondeterministic,
                containment: Contained,
                workspace: WsNone,
                network: Offline,
                external_issuance: IssNone,
                pre_commit_recovery: ReconcileRequired,
            },
            "R16",
            Axis::ExternalIssuance,
        ),
        // R17 — ManualResolution without DurableActivity.
        (
            CheckedExecutionClass {
                computation: ProcessAction,
                determinism: Nondeterministic,
                containment: Contained,
                workspace: WsNone,
                network: Offline,
                external_issuance: IssNone,
                pre_commit_recovery: ManualResolution,
            },
            "R17",
            Axis::ExternalIssuance,
        ),
    ];

    for (class, code, axis) in cases {
        let err = class
            .validate(CheckedOpContext::Standard)
            .expect_err("witness tuple must refuse");
        assert_eq!(err.code, *code, "wrong code for {class:?}");
        assert_eq!(err.axis, *axis, "wrong axis for code {code}");
    }
}

// ── Predicate unit tests ───────────────────────────────────────────────────

#[test]
fn admission_predicates() {
    assert!(CheckedOpContext::WorkspacePark.is_workspace_provider_op());
    assert!(CheckedOpContext::WorkspacePromote.is_workspace_provider_op());
    assert!(CheckedOpContext::WorkspaceCommit.is_workspace_provider_op());
    assert!(!CheckedOpContext::WorkspacePark.is_adapter_op());
    assert!(CheckedOpContext::ForgeLand.is_adapter_op());
    assert!(!CheckedOpContext::ForgeLand.is_workspace_provider_op());
    assert!(!CheckedOpContext::Standard.is_workspace_provider_op());
    assert!(!CheckedOpContext::Standard.is_adapter_op());
}

#[test]
fn admission1_is_never_content_cache_eligible() {
    // Recorded local mutation is never content-cacheable.
    assert!(!CheckedExecutionClass::ADMISSION_RECORDED_LOCAL_MUTATION.is_content_cache_eligible());
    assert!(CheckedExecutionClass::ADMISSION_RECORDED_LOCAL_MUTATION.is_workspace_mutating());
    // Adapter issuance requires a durable claim.
    assert_eq!(
        CheckedExecutionClass::ADMISSION_ADAPTER_ISSUANCE.external_issuance,
        ExternalIssuance::DurableActivity
    );
    assert!(
        !CheckedExecutionClass::ADMISSION_ADAPTER_ISSUANCE.is_workspace_mutating(),
        "a forge land binds the candidate as an input, not a held mutation"
    );
}

/// `is_in_process` — the predicate the capacity preflight skips on — holds for
/// EXACTLY four valid classes over the whole tuple space and every op: R2's base
/// row, the two op-gated admissions, and
/// R1's pure-transform base row (minted by no derivation today). Each is a
/// class the main runs and no worker is placed for.
#[test]
fn is_in_process_holds_for_exactly_the_main_run_classes() {
    let ops = [
        CheckedOpContext::Standard,
        CheckedOpContext::WorkspacePark,
        CheckedOpContext::WorkspacePromote,
        CheckedOpContext::WorkspaceCommit,
        CheckedOpContext::ForgeLand,
    ];
    let mut holding: Vec<CheckedExecutionClass> = all_tuples()
        .into_iter()
        .filter(|c| ops.iter().any(|&op| c.validate(op).is_ok()))
        .filter(|c| c.is_in_process())
        .collect();
    holding.sort_by_key(|c| format!("{c:?}"));
    let mut expected = vec![
        CheckedExecutionClass::MAIN_RESOLVED_WAIT,
        CheckedExecutionClass::ADMISSION_RECORDED_LOCAL_MUTATION,
        CheckedExecutionClass::ADMISSION_ADAPTER_ISSUANCE,
        CheckedExecutionClass {
            computation: Computation::PureTransform,
            determinism: Determinism::Deterministic,
            containment: Containment::InProcess,
            workspace: Workspace::None,
            network: Network::Offline,
            external_issuance: ExternalIssuance::None,
            pre_commit_recovery: PreCommitRecovery::RecomputeAllowed,
        },
    ];
    expected.sort_by_key(|c| format!("{c:?}"));
    assert_eq!(holding, expected);
}

// ── Serde round-trips (the type is serialized in the later identity flip) ──

#[test]
fn axis_serde_is_snake_case() {
    assert_eq!(
        serde_json::to_string(&Containment::HostUnconfined).unwrap(),
        "\"host_unconfined\""
    );
    assert_eq!(
        serde_json::to_string(&Workspace::MutableCandidate).unwrap(),
        "\"mutable_candidate\""
    );
    assert_eq!(
        serde_json::to_string(&PreCommitRecovery::AwaitRecordedInput).unwrap(),
        "\"await_recorded_input\""
    );
    assert_eq!(
        serde_json::to_string(&ExternalIssuance::DurableActivity).unwrap(),
        "\"durable_activity\""
    );
    // Labels match the serde representation.
    assert_eq!(Containment::HostUnconfined.label(), "host_unconfined");
    assert_eq!(Network::BrokeredOnly.label(), "brokered_only");
    assert_eq!(Axis::ExternalIssuance.label(), "external_issuance");
    assert_eq!(CheckedOpContext::ForgeLand.label(), "forge_land");
}

#[test]
fn class_round_trips_through_serde() {
    for class in all_tuples() {
        let json = serde_json::to_string(&class).unwrap();
        let back: CheckedExecutionClass = serde_json::from_str(&json).unwrap();
        assert_eq!(class, back);
    }
    // A representative on-the-wire shape.
    let json = serde_json::to_value(CheckedExecutionClass::ADMISSION_ADAPTER_ISSUANCE).unwrap();
    assert_eq!(json["computation"], "process_action");
    assert_eq!(json["containment"], "in_process");
    assert_eq!(json["network"], "unrestricted");
    assert_eq!(json["pre_commit_recovery"], "reconcile_required");
}

/// Build an axis's COMPLETE variant domain from a list the COMPILER proves is
/// exhaustive, and return it as a slice for comparison against that axis's `ALL`.
///
/// This exists because `axis_all_and_label!` (`execution_class.rs`) takes the
/// `ALL` array and the `label()` match arms as SEPARATE arguments. Adding a
/// variant to an axis breaks `label()`'s match at compile time, but nothing
/// forces the author to widen `$all` in the same edit — so a variant could be
/// added to an axis, omitted from `ALL`, and the 1,728-tuple sweep would keep
/// passing over a silently smaller domain (its hardcoded product is exactly what
/// the un-widened `ALL` consts still yield). The arity assertions this guard used
/// to make were hardcoded numbers that were never updated either, so the guard
/// could observe nothing and still be satisfied.
///
/// ONE variant list here drives BOTH an exhaustive `match` and the returned
/// domain. Omitting a variant from the list fails to COMPILE (E0004), and the
/// only way to fix that is to widen the list — which widens the domain the
/// assertions below compare `ALL` against. So a variant missing from `ALL` is a
/// test FAILURE that cannot be silenced by leaving a number stale.
macro_rules! axis_domain {
    ($ty:ty, [$($variant:path),+ $(,)?]) => {{
        // Exhaustiveness anchor. Adding a variant to `$ty` without adding it to
        // the list below is a compile error HERE, on the same list that builds
        // `DOMAIN` — the two cannot drift apart.
        fn assert_exhaustive(value: $ty) {
            match value {
                $( $variant => () ),+
            }
        }
        const DOMAIN: &[$ty] = &[$($variant),+];
        for &value in DOMAIN {
            assert_exhaustive(value);
        }
        DOMAIN
    }};
}

/// Assert that `all` (an axis's `ALL` const) is exactly `domain` (the
/// compiler-verified complete variant set) as a multiset: nothing omitted,
/// nothing duplicated.
fn assert_axis_domain<T: PartialEq + core::fmt::Debug>(axis: &str, all: &[T], domain: &[T]) {
    for variant in domain {
        assert!(
            all.contains(variant),
            "{axis}::ALL omits the variant {variant:?}. Every axis value must appear in \
             ALL — it is the domain the 1,728-tuple exhaustive sweep enumerates over, so an \
             omitted variant silently shrinks the \"exhaustive\" matrix. Add it to the \
             `axis_all_and_label!` array in execution_class.rs."
        );
        assert_eq!(
            all.iter().filter(|value| *value == variant).count(),
            1,
            "{axis}::ALL lists the variant {variant:?} more than once, which double-counts \
             it in the exhaustive sweep."
        );
    }
    assert_eq!(
        all.len(),
        domain.len(),
        "{axis}::ALL has {} entries but the axis has {} variants",
        all.len(),
        domain.len()
    );
}

/// Every axis's `ALL` const holds EXACTLY that axis's variants — the guard that
/// a variant added to an axis but omitted from `ALL` cannot pass. See
/// [`axis_domain!`] for why a hardcoded arity could not detect that.
#[test]
fn every_axis_all_array_holds_exactly_the_axis_variants() {
    assert_axis_domain(
        "Computation",
        Computation::ALL,
        axis_domain!(
            Computation,
            [
                Computation::PureTransform,
                Computation::ProcessAction,
                Computation::WaitForInput,
            ]
        ),
    );
    assert_axis_domain(
        "Determinism",
        Determinism::ALL,
        axis_domain!(
            Determinism,
            [Determinism::Deterministic, Determinism::Nondeterministic]
        ),
    );
    assert_axis_domain(
        "Containment",
        Containment::ALL,
        axis_domain!(
            Containment,
            [
                Containment::InProcess,
                Containment::Contained,
                Containment::HostUnconfined,
            ]
        ),
    );
    assert_axis_domain(
        "Workspace",
        Workspace::ALL,
        axis_domain!(
            Workspace,
            [
                Workspace::None,
                Workspace::ReadOnly,
                Workspace::DeclaredOutputs,
                Workspace::MutableCandidate,
            ]
        ),
    );
    assert_axis_domain(
        "Network",
        Network::ALL,
        axis_domain!(
            Network,
            [
                Network::Offline,
                Network::BrokeredOnly,
                Network::Unrestricted,
            ]
        ),
    );
    assert_axis_domain(
        "ExternalIssuance",
        ExternalIssuance::ALL,
        axis_domain!(
            ExternalIssuance,
            [ExternalIssuance::None, ExternalIssuance::DurableActivity]
        ),
    );
    assert_axis_domain(
        "PreCommitRecovery",
        PreCommitRecovery::ALL,
        axis_domain!(
            PreCommitRecovery,
            [
                PreCommitRecovery::RecomputeAllowed,
                PreCommitRecovery::AwaitRecordedInput,
                PreCommitRecovery::ReconcileRequired,
                PreCommitRecovery::ManualResolution,
            ]
        ),
    );
}
