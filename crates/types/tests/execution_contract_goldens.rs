//! Pinned identity vectors for `kata_types::execution_contract`.
//!
//! These literals are the external witness for every identity in that module:
//! the in-module tests only compare kata's answer to kata's answer, so they
//! cannot see a domain tag, a field name, a field order, or an enum tag change.
//! A diff here means some id rotated — either intended (bump
//! `EXECUTION_CONTRACT_SCHEMA_VERSION` and re-pin every vector) or a defect.
//!
//! Every vector below was re-pinned at the v5 → v6 bump, which `WaitOperation::Input`
//! and `RuntimeOperation::Invoke` naming a checked child PROGRAM (not a pack name)
//! required — as every vector was re-pinned at each bump before it. The schema version
//! is part of every domain tag precisely so a shape change rotates the whole family by
//! construction rather than by remembering to: at the v6 bump, before a single literal
//! moved, THIRTEEN of the fourteen tests in this file went red, together with the
//! contract-folding vector in `nix_environment_goldens.rs`
//! (`the_environment_id_over_the_pinned_closure_is_pinned`), the one in
//! `tree_artifact_goldens.rs` (`the_artifact_id_of_a_two_entry_tree_is_pinned`) and the
//! `WorkerMessage` serde-conformance hash in `crates/transport/conformance.toml`, which is
//! the proof that no family's tag was missed. The fourteenth,
//! `operation_path_canonical_bytes_are_pinned`, stayed green on purpose — it pins an
//! ENCODING rather than an identity and carries no domain tag, which its own comment
//! states. The two v6 families (`input_request_selector`, the `Input` wait) were pinned
//! at the same bump.

use kata_types::bound::Bound;
use kata_types::cache::ActionManifest;
use kata_types::effect::EffectKind;
use kata_types::execution_contract::{
    ActionExecutor, ArtifactPrivacy, ArtifactRef, Capsule, CapsuleBudgets, CapsuleNetwork,
    CapsuleProcess, EXECUTION_CONTRACT_SCHEMA_VERSION, EnvironmentRef, ExecuteOperation,
    GuestAccess, GuestMapping, GuestPath, InputRequestFields, OccurrenceRef, OperationContract,
    OperationPath, OperationSourceMap, PlatformRef, PreparedAction, PreparedActionId,
    RuntimeOperation, WaitOperation, branch_route_selector, input_request_selector,
    loop_policy_selector,
};
use kata_types::primitives::ContentHash;
use kata_types::review_loop::{LoopVerdictConfig, OnMaxAction, ReviewLoop};
use kata_types::source::SourceSpan;
use kata_types::workflow::{BranchArm, BranchRoute, ExecutionId, StageId, WorkspaceEffectOp};
use smol_str::SmolStr;
use ulid::Ulid;

fn hash(byte: u8) -> ContentHash {
    ContentHash::new([byte; 32])
}

#[test]
fn schema_version_is_the_one_these_vectors_were_pinned_under() {
    assert_eq!(EXECUTION_CONTRACT_SCHEMA_VERSION, 14);
}

#[test]
fn operation_contract_id_vectors_are_pinned() {
    let execute = OperationContract::new(
        StageId(SmolStr::new("build")),
        RuntimeOperation::Execute(ExecuteOperation {
            executor: ActionExecutor::Agent {
                drivers: vec![SmolStr::new("claude"), SmolStr::new("codex")],
            },
            contract_hash: hash(0x11),
        }),
    );
    assert_eq!(
        execute.id().0.to_string(),
        "50575244e489f06fe2956f8458cce87db689ab5be8d0a3e0ca1591ddf99e8d4e"
    );

    let command = OperationContract::new(
        StageId(SmolStr::new("test")),
        RuntimeOperation::Execute(ExecuteOperation {
            executor: ActionExecutor::Command,
            contract_hash: hash(0x22),
        }),
    );
    assert_eq!(
        command.id().0.to_string(),
        "8f785e523d54cb836d259dd524002f7135cc78bb46205bcd38ff2c992154aba9"
    );

    let effect = effect_contract(WorkspaceEffectOp::Park);
    assert_eq!(
        effect.id().0.to_string(),
        "a8a8c71974b70656ab14ecb58950c8894ec9bc48e4cfd34027e3158d0a8486c9"
    );

    // The effect OP is part of the identity: two effect stages can carry the same
    // `contract_hash` (the hashed contract excludes prompt text, and park and
    // promote derive the same class), so `effect_kind` alone would alias a park
    // onto a promote. This second vector is the external witness for that.
    let promote = effect_contract(WorkspaceEffectOp::Promote);
    assert_eq!(
        promote.id().0.to_string(),
        "12ded22e175a9fcb735e6ec643b1e5276a6e3b4763f494ed887d986302e8ec87"
    );
    assert_ne!(effect.id(), promote.id());
}

/// A SOURCE MAP IS NOT CONTRACT MATERIAL. `OperationSourceMap` carries the
/// authoring span, and an operation's identity is taken over the CONTRACT's own
/// fields — so the same contract described by two source maps, one with a span and
/// one without, keeps the one pinned id. This is the external witness that a
/// whitespace-only re-indent of a pack cannot rotate an operation id or invalidate
/// a cached result.
#[test]
fn a_source_map_span_is_provenance_and_never_enters_the_operation_id() {
    let contract = OperationContract::new(
        StageId(SmolStr::new("test")),
        RuntimeOperation::Execute(ExecuteOperation {
            executor: ActionExecutor::Command,
            contract_hash: hash(0x22),
        }),
    );
    // The SAME literal the command vector above is pinned to: the id is a
    // function of the contract, and the maps below describe it without touching it.
    assert_eq!(
        contract.id().0.to_string(),
        "8f785e523d54cb836d259dd524002f7135cc78bb46205bcd38ff2c992154aba9"
    );

    let bare = OperationSourceMap {
        operation: contract.id(),
        stage: StageId(SmolStr::new("test")),
        source_hash: hash(0x99),
        authored_label: SmolStr::new("test"),
        span: None,
    };
    let spanned = OperationSourceMap {
        span: Some(SourceSpan {
            file: "pack.star".to_string(),
            line: 12,
            column: 3,
        }),
        ..bare.clone()
    };
    assert_ne!(bare, spanned, "the premise: the two maps really differ");
    assert_eq!(
        bare.operation, spanned.operation,
        "both maps describe the one operation"
    );
    assert_eq!(
        contract.id().0.to_string(),
        "8f785e523d54cb836d259dd524002f7135cc78bb46205bcd38ff2c992154aba9",
        "and the pinned id is untouched by either"
    );
}

/// One effect operation differing from its sibling only in the workspace op.
fn effect_contract(op: WorkspaceEffectOp) -> OperationContract {
    OperationContract::new(
        StageId(SmolStr::new("park")),
        RuntimeOperation::Execute(ExecuteOperation {
            executor: ActionExecutor::Effect {
                effect_kind: EffectKind::WorkspaceEffect,
                op,
            },
            contract_hash: hash(0x33),
        }),
    )
}

/// The branch-route selector is an identity family of its own: it is hashed from
/// the authored route rather than from a contract, so nothing else in this file
/// would catch a changed field name, field order, or domain tag in it.
#[test]
fn branch_route_selector_vector_is_pinned() {
    let route = BranchRoute {
        condition_stage: StageId(SmolStr::new("classify")),
        verdict_field: SmolStr::new("verdict"),
        arms: vec![
            BranchArm {
                tag: SmolStr::new("hold"),
                targets: vec![StageId(SmolStr::new("hold"))],
            },
            BranchArm {
                tag: SmolStr::new("ship"),
                targets: vec![
                    StageId(SmolStr::new("ship")),
                    StageId(SmolStr::new("announce")),
                ],
            },
        ],
    };
    assert_eq!(
        branch_route_selector(&route).to_string(),
        "ea81490053ab8d0465bd3503980d92fdd230496e75169a6c42d05b422f248c65"
    );

    // Arm ORDER is not authored (routes are stored canonically), but an arm's
    // TARGETS are, so a re-targeted arm must rotate the selector.
    let mut retargeted = route.clone();
    retargeted.arms[1].targets = vec![StageId(SmolStr::new("ship"))];
    assert_eq!(
        branch_route_selector(&retargeted).to_string(),
        "509c1134967d0ff7e738ca212618f5f71bea043003566d14942216aba2c4dfc0"
    );
}

#[test]
fn occurrence_id_vector_is_pinned() {
    let occurrence = OccurrenceRef::new(
        ExecutionId(Ulid::from_bytes([7; 16])),
        hash(2),
        OperationContract::new(
            StageId(SmolStr::new("build")),
            RuntimeOperation::Select {
                selector: hash(0x44),
            },
        )
        .id(),
        OperationPath(vec![3, 5]),
    );
    assert_eq!(
        occurrence.id().0.to_string(),
        "5b5b1be4c761f3f92dafc6afcf6ecda565a029691585612fa2a04e2bfe867151"
    );
}

/// The DURABLE COLUMN's byte encoding, pinned as literals.
///
/// `occurrences.operation_path` (operational schema 18) stores exactly these bytes
/// and takes `UNIQUE(execution_id, operation_contract_id, operation_path)` over
/// them, while `OccurrenceId` folds the same bytes field-wise. The in-module
/// `hash_path_folds_exactly_the_canonical_bytes_field_wise` proves the two agree;
/// this is the EXTERNAL witness that the bytes themselves did not move — which that
/// in-module test cannot see, because it compares kata's fold to kata's fold.
///
/// Deliberately NOT derived from `EXECUTION_CONTRACT_SCHEMA_VERSION`: the encoding
/// carries no domain tag (it is the hashed VALUES, not the hash), so a schema bump
/// rotates every id above and leaves these literals alone. A diff here is a stored
/// column change, and every occurrence row already written would be unfindable.
#[test]
fn operation_path_canonical_bytes_are_pinned() {
    assert_eq!(
        OperationPath(Vec::new()).canonical_bytes(),
        vec![0, 0, 0, 0, 0, 0, 0, 0]
    );
    assert_eq!(
        OperationPath(vec![3, 5]).canonical_bytes(),
        vec![2, 0, 0, 0, 0, 0, 0, 0, 3, 0, 0, 0, 5, 0, 0, 0]
    );
    assert_eq!(
        OperationPath(vec![0x0102_0304]).canonical_bytes(),
        vec![1, 0, 0, 0, 0, 0, 0, 0, 0x04, 0x03, 0x02, 0x01]
    );
    assert_eq!(
        OperationPath(vec![u32::MAX, 0]).canonical_bytes(),
        vec![2, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 0xff, 0xff, 0, 0, 0, 0]
    );

    // The empty path and the one-coordinate zero path are DIFFERENT bytes, which is
    // what the count prefix buys: without it both would encode as `[]` and two
    // distinct occurrences would collide on one row.
    assert_ne!(
        OperationPath(Vec::new()).canonical_bytes(),
        OperationPath(vec![0]).canonical_bytes()
    );
}

#[test]
fn prepared_action_id_vector_is_pinned() {
    let prepared = PreparedAction::new(
        OperationContract::new(
            StageId(SmolStr::new("build")),
            RuntimeOperation::Wait(WaitOperation::For { delay_ms: 250 }),
        )
        .id(),
        ActionManifest::new(hash(2), vec![SmolStr::new("out/**")]),
        EnvironmentRef::new(
            ArtifactRef::new(hash(8), 64, ArtifactPrivacy::Public).id(),
            hash(9),
        )
        .id(),
        hash(5),
        PlatformRef::new("x86_64-linux", hash(6)).id(),
    );
    assert_eq!(
        prepared.id().0.to_string(),
        "194d71a3c6e51bfb6a1e1696ca2fd03d17e3582405156b8b905d105dbaf97042"
    );
}

#[test]
fn artifact_environment_and_platform_id_vectors_are_pinned() {
    let artifact = ArtifactRef::new(hash(8), 64, ArtifactPrivacy::Public);
    assert_eq!(
        artifact.id().0.to_string(),
        "45c9e6c6e421d881f29c323a81c7ff201d02222369c383faea357d33a1c84db7"
    );

    let environment = EnvironmentRef::new(artifact.id(), hash(9));
    assert_eq!(
        environment.id().0.to_string(),
        "de91d50e8e0fa607bed55415acbd95e7bc8173dbf706a437546251eee1a19da8"
    );

    let platform = PlatformRef::new("x86_64-linux", hash(6));
    assert_eq!(
        platform.id().0.to_string(),
        "be1b50d3492feb8fe9810e084fbea98fbab58cd92f1089e20d3ae12e24e56757"
    );
}

#[test]
fn capsule_id_vector_is_pinned() {
    let artifact = ArtifactRef::new(hash(8), 64, ArtifactPrivacy::Public);
    let environment = EnvironmentRef::new(artifact.id(), hash(9));
    let platform = PlatformRef::new("x86_64-linux", hash(6));
    let occurrence = OccurrenceRef::new(
        ExecutionId(Ulid::from_bytes([7; 16])),
        hash(2),
        OperationContract::new(
            StageId(SmolStr::new("build")),
            RuntimeOperation::Select {
                selector: hash(0x44),
            },
        )
        .id(),
        OperationPath(vec![3, 5]),
    );
    let capsule = Capsule::new(
        occurrence.id(),
        prepared_action(),
        environment.id(),
        platform.id(),
        vec![
            GuestMapping {
                artifact: artifact.id(),
                guest_path: GuestPath::new("/work/src").unwrap(),
                access: GuestAccess::ReadWrite,
            },
            GuestMapping {
                artifact: artifact.id(),
                guest_path: GuestPath::new("/nix/store").unwrap(),
                access: GuestAccess::ReadOnly,
            },
        ],
        CapsuleProcess::Command {
            argv: pinned_argv(),
        },
        CapsuleNetwork::Offline,
        None,
        CapsuleBudgets {
            wall_time_ms: 10,
            output_bytes: 20,
            memory_bytes: 30,
            process_count: 2,
            result_bytes: 4 * 1024 * 1024,
            result_entries: 128,
            work_delta_bytes: kata_types::execution_contract::CAPSULE_WORK_DELTA_BYTES,
            work_delta_entries: kata_types::execution_contract::CAPSULE_WORK_DELTA_ENTRIES,
        },
        None,
    )
    .expect("distinct guest paths");
    assert_eq!(
        capsule.id().0.to_string(),
        "f64e6000ad550899998a11b4ce324eb7f321837b51aa01438e2e786053df0b43"
    );
}

/// The CONTENT-CACHE key (`Capsule::reuse_key`) over
/// [`single_mapping_capsule`] under one fixed executor term, pinned from
/// outside: its own domain tag (`capsule_reuse`), field names and order, and the
/// term's fold (`kata.execution_platform.executor_term.v1`, sorted named pairs). A
/// second vector over the SAME body at a different occurrence must equal it — the
/// occurrence is the one field the key omits.
#[test]
fn capsule_reuse_key_vector_is_pinned() {
    let executor = kata_types::execution_platform::ExecutorTerm::derive(&[
        ("oci_seccomp_rules", b"golden rules"),
        ("youki_binary_sha256", b"golden youki"),
    ])
    .unwrap();
    assert_eq!(
        executor.digest().to_string(),
        "3b2813d2ee156d4a9fda206c624be18d23e9d09813aa012dbf449cde239f4220"
    );
    let capsule = single_mapping_capsule(GuestAccess::ReadWrite);
    assert_eq!(
        capsule.reuse_key(&executor).0.to_string(),
        "195e9b97a75be9498dd87142ec841cd668f2cc542c44d8ffa8df1492cb58e78e"
    );
    let elsewhere = Capsule::new(
        kata_types::execution_contract::OccurrenceId(hash(0x99)),
        prepared_action(),
        EnvironmentRef::new(
            ArtifactRef::new(hash(8), 64, ArtifactPrivacy::Public).id(),
            hash(9),
        )
        .id(),
        PlatformRef::new("x86_64-linux", hash(6)).id(),
        vec![GuestMapping {
            artifact: ArtifactRef::new(hash(8), 64, ArtifactPrivacy::Public).id(),
            guest_path: GuestPath::new("/work/src").unwrap(),
            access: GuestAccess::ReadWrite,
        }],
        CapsuleProcess::Command {
            argv: pinned_argv(),
        },
        CapsuleNetwork::Offline,
        None,
        CapsuleBudgets {
            wall_time_ms: 10,
            output_bytes: 20,
            memory_bytes: 30,
            process_count: 2,
            result_bytes: 4 * 1024 * 1024,
            result_entries: 128,
            work_delta_bytes: kata_types::execution_contract::CAPSULE_WORK_DELTA_BYTES,
            work_delta_entries: kata_types::execution_contract::CAPSULE_WORK_DELTA_ENTRIES,
        },
        None,
    )
    .unwrap();
    assert_ne!(elsewhere.id(), capsule.id());
    assert_eq!(elsewhere.reuse_key(&executor), capsule.reuse_key(&executor));
}

/// The argument vector every capsule vector in this file is pinned with.
///
/// A shell invocation rather than a bare program, because that is the shape
/// `kata_workflow::capsule_assembly` derives for a shell stage: three elements, the third carrying
/// a space and a redirect, so a per-element fold is distinguishable from a joined-string one.
fn pinned_argv() -> Vec<SmolStr> {
    vec![
        SmolStr::new("sh"),
        SmolStr::new("-c"),
        SmolStr::new("echo hi > /out/hi"),
    ]
}

/// The contract-v5 ARGUMENT VECTOR enters [`Capsule`]'s identity, pinned from
/// outside.
///
/// # What each assertion is the witness for, and why a length prefix is one of them
///
/// `argv` is folded as a COUNT followed by one `hash_field` per element. The count is
/// what makes `["ab"]` and `["a", "b"]` distinguishable given that `hash_field`
/// length-prefixes each element anyway — so it is belt and braces rather than the
/// mechanism, and the pair below proves the elements are folded at all:
///
/// * a DIFFERENT COMMAND rotates the id — otherwise the vector is in the struct and
///   not in the hash, which is the whole defect v5 exists to close;
/// * a REORDERED vector rotates the id — otherwise the fold is order-insensitive,
///   and `sh -c 'rm x'` would share an identity with `-c sh 'rm x'`;
/// * a capsule with an EMPTY argv is unconstructible, so the refusal is not something
///   a downstream renderer reports.
#[test]
fn the_argv_vectors_are_pinned() {
    let baseline = single_mapping_capsule(GuestAccess::ReadWrite);
    assert_eq!(
        baseline.process(),
        &CapsuleProcess::Command {
            argv: pinned_argv(),
        },
        "the accessor must hand back what was folded"
    );

    let other = capsule_with_argv(vec![
        SmolStr::new("sh"),
        SmolStr::new("-c"),
        SmolStr::new("echo bye > /out/hi"),
    ]);
    assert_ne!(
        other.id(),
        baseline.id(),
        "a capsule that runs a DIFFERENT command must not share an id with this one — the whole \
         reason the vector moved into the identity at v5"
    );
    assert_eq!(
        other.id().0.to_string(),
        "c13ee129e2a6f29ed4e1e8e511d323e3994d6042998b5eb4c09112f33719e40d"
    );

    let reordered = capsule_with_argv(vec![
        SmolStr::new("-c"),
        SmolStr::new("sh"),
        SmolStr::new("echo hi > /out/hi"),
    ]);
    assert_ne!(
        reordered.id(),
        baseline.id(),
        "the fold is per-element in ORDER, so a permutation is a different capsule"
    );
    assert_eq!(
        reordered.id().0.to_string(),
        "b306b02abaf62e76a38879f147564a6451c7a2cf4617d6ca4fbe9a4caeaa1e4d"
    );

    let refused = capsule_argv_refusal(Vec::new());
    assert!(
        refused.contains("capsule argv is empty"),
        "an empty argv is refused by the type: {refused}"
    );
    let nul = capsule_argv_refusal(vec![SmolStr::new("sh"), SmolStr::new("a\0b")]);
    assert!(
        nul.contains("argv[1] contains a NUL byte"),
        "a NUL truncates silently at execve, so the type refuses it: {nul}"
    );
}

/// [`single_mapping_capsule`]'s shape with a caller-chosen argv.
fn capsule_with_argv(argv: Vec<SmolStr>) -> Capsule {
    capsule_for_argv(argv).expect("one mapping and a runnable argv")
}

/// The refusal text for an argv [`Capsule::new`] will not accept.
fn capsule_argv_refusal(argv: Vec<SmolStr>) -> String {
    capsule_for_argv(argv)
        .expect_err("an unrunnable argv is refused")
        .to_string()
}

fn capsule_for_argv(argv: Vec<SmolStr>) -> kata_types::error::KataResult<Capsule> {
    Capsule::new(
        OccurrenceRef::new(
            ExecutionId(Ulid::from_bytes([7; 16])),
            hash(2),
            OperationContract::new(
                StageId(SmolStr::new("build")),
                RuntimeOperation::Select {
                    selector: hash(0x44),
                },
            )
            .id(),
            OperationPath(vec![3, 5]),
        )
        .id(),
        prepared_action(),
        EnvironmentRef::new(
            ArtifactRef::new(hash(8), 64, ArtifactPrivacy::Public).id(),
            hash(9),
        )
        .id(),
        PlatformRef::new("x86_64-linux", hash(6)).id(),
        vec![GuestMapping {
            artifact: ArtifactRef::new(hash(8), 64, ArtifactPrivacy::Public).id(),
            guest_path: GuestPath::new("/work/src").unwrap(),
            access: GuestAccess::ReadWrite,
        }],
        CapsuleProcess::Command { argv },
        CapsuleNetwork::Offline,
        None,
        CapsuleBudgets {
            wall_time_ms: 10,
            output_bytes: 20,
            memory_bytes: 30,
            process_count: 2,
            result_bytes: 4 * 1024 * 1024,
            result_entries: 128,
            work_delta_bytes: kata_types::execution_contract::CAPSULE_WORK_DELTA_BYTES,
            work_delta_entries: kata_types::execution_contract::CAPSULE_WORK_DELTA_ENTRIES,
        },
        None,
    )
}

/// Every [`RuntimeOperation`] variant this module can express, so an enum tag, a
/// field name, or a field order that changes in one arm cannot hide behind
/// another arm's coverage. `Execute` lives in the vector above.
#[test]
fn remaining_runtime_operation_id_vectors_are_pinned() {
    let invoke = OperationContract::new(
        StageId(SmolStr::new("fanout")),
        RuntimeOperation::Invoke {
            program: hash(0x65),
            params_hash: hash(0x66),
        },
    );
    assert_eq!(
        invoke.id().0.to_string(),
        "ce268965d1f90b0de42229f934fd362b365833887d9700d45581dcaffd766b03"
    );

    let join = OperationContract::new(
        StageId(SmolStr::new("gather")),
        RuntimeOperation::Join {
            inputs: vec![OperationPath(vec![1]), OperationPath(vec![2, 7])],
        },
    );
    assert_eq!(
        join.id().0.to_string(),
        "d8f9773459221e50e053abb1afe9be89924bd2edfb29cacd512bb42d4ee9e5a9"
    );

    let expand = OperationContract::new(
        StageId(SmolStr::new("fanout")),
        RuntimeOperation::ExpandBounded {
            template: vec![OperationPath(vec![4]), OperationPath(vec![4, 1])],
            maximum: 8,
            policy_hash: hash(0x77),
        },
    );
    assert_eq!(
        expand.id().0.to_string(),
        "aa84c886ae995327f9c2b81ad550bf7365bf1a71bd7f5c5bad199a9186b09c4d"
    );

    // The POLICY is part of the expansion identity: two loops over the same
    // template with the same ceiling can differ in every field the template and
    // the maximum cannot see, so `policy_hash` MUST rotate the id. This second
    // vector is the external witness for that.
    let retuned = OperationContract::new(
        StageId(SmolStr::new("fanout")),
        RuntimeOperation::ExpandBounded {
            template: vec![OperationPath(vec![4]), OperationPath(vec![4, 1])],
            maximum: 8,
            policy_hash: hash(0x78),
        },
    );
    assert_eq!(
        retuned.id().0.to_string(),
        "8526b2e47123252922183b3bc18f04d141898def3a4d7459e4f5da173983785a"
    );
    assert_ne!(expand.id(), retuned.id());

    let delay = OperationContract::new(
        StageId(SmolStr::new("pause")),
        RuntimeOperation::Wait(WaitOperation::For { delay_ms: 250 }),
    );
    assert_eq!(
        delay.id().0.to_string(),
        "01192baf7caa0e8080e93d50f88059308ff2f3c81af733dd4a15bdfdb8162ba1"
    );

    let deadline = OperationContract::new(
        StageId(SmolStr::new("pause")),
        RuntimeOperation::Wait(WaitOperation::Until { epoch_ms: 250 }),
    );
    assert_eq!(
        deadline.id().0.to_string(),
        "477e3b762d76e3f5c1b52e0749dee67a150f070af09c44aedb8a2f30837e3f89"
    );

    // Contract v6: the wait on one blocking human request's answer.
    let input = OperationContract::new(
        StageId(SmolStr::new("decide")),
        RuntimeOperation::Wait(WaitOperation::Input {
            request: hash(0x67),
        }),
    );
    assert_eq!(
        input.id().0.to_string(),
        "d4380aed79111e147a4d7c1189baf358788712a000c207bfa7b10946bff6dad3"
    );
}

/// Contract v6 — [`input_request_selector`] pinned from outside, with every
/// optional field present and then with every optional field absent, so a
/// presence tag that changed spelling is seen here.
#[test]
fn input_request_selector_vectors_are_pinned() {
    let present = InputRequestFields {
        id: "confirm",
        stage: Some("deploy"),
        question: "Ship it?",
        default_assumption: "no",
        timeout_ms: Some(60_000),
        priority: "high",
        context: Some("release notes"),
    };
    assert_eq!(
        input_request_selector(present).to_string(),
        "efa62d7840bd38fbfb2934e76ccdde9a22c34eb03fd45e98aeb2e968520a5fe0"
    );
    let absent = InputRequestFields {
        stage: None,
        timeout_ms: None,
        context: None,
        ..present
    };
    assert_eq!(
        input_request_selector(absent).to_string(),
        "f90c525e72c449c8e7ad92067adddb6272d527c6f4548774c3b963bfcef1802a"
    );
}

/// The privacy and access tags enter their identities, pinned from outside: the
/// in-module tests only ever compare one kata answer to another.
#[test]
fn privacy_and_guest_access_id_vectors_are_pinned() {
    let private = ArtifactRef::new(hash(8), 64, ArtifactPrivacy::Private);
    assert_eq!(
        private.id().0.to_string(),
        "1bfc318cde7d007d656aa16caf64d78b0e645cd2a4f1c86deaf55595cdce6675"
    );

    let read_write = single_mapping_capsule(GuestAccess::ReadWrite);
    assert_eq!(
        read_write.id().0.to_string(),
        "524a7fdcd352cad0cfca15255301a2aceea224590c1c2907b1578c52eac6bc20"
    );

    let read_only = single_mapping_capsule(GuestAccess::ReadOnly);
    assert_eq!(
        read_only.id().0.to_string(),
        "fa691c518ac95b7f3d40bdfdc413b8b09616856c729b093511c732b2a1d65446"
    );
}

/// The two contract-v4 RESULT bounds enter [`Capsule`]'s identity, and enter it
/// SEPARATELY — pinned from outside, because an in-module test could only compare
/// one kata answer to another.
///
/// # Why two vectors and not one
///
/// `result_bytes` and `result_entries` are folded as two `hash_field` entries, so
/// one vector could not distinguish "both are folded" from "one is folded and the
/// other is dead weight in the struct". The pair below differs from
/// [`capsule_id_vector_is_pinned`]'s budgets in exactly one field each, so each
/// literal is the witness for its own field.
#[test]
fn the_result_budget_vectors_are_pinned() {
    let more_bytes = capsule_with_result_budget(8 * 1024 * 1024, 128);
    assert_eq!(
        more_bytes.id().0.to_string(),
        "3d39a4d7db7cd2aa671e6c4bf180219d1fe5b0032a67732255a1a8a9fe31b116"
    );

    let more_entries = capsule_with_result_budget(4 * 1024 * 1024, 256);
    let baseline = capsule_with_result_budget(4 * 1024 * 1024, 128);
    assert_ne!(
        more_bytes.id(),
        baseline.id(),
        "a capsule promising a larger RESULT TREE must not share its id with one promising a smaller one"
    );
    assert_ne!(
        more_entries.id(),
        baseline.id(),
        "a capsule promising more RESULT ENTRIES must not share its id with one promising fewer"
    );
    assert_ne!(
        more_bytes.id(),
        more_entries.id(),
        "the two bounds are folded separately, so raising either must not land on the other's id"
    );
    assert_eq!(
        baseline.id(),
        single_mapping_capsule(GuestAccess::ReadWrite).id(),
        "the baseline is this file's read-write single-mapping vector, so the two vectors above differ from a PINNED value in exactly one budget field each"
    );
    assert_eq!(
        more_entries.id().0.to_string(),
        "6c2276b1f07cf3e951ddd30cb8e03aa3786f14af349f5d4e66289d9dc4eefd7f"
    );
}

/// [`single_mapping_capsule`]'s shape with a caller-chosen RESULT budget, so the
/// two vectors above differ from each other and from the pinned capsule vector in
/// exactly the field under test.
fn capsule_with_result_budget(result_bytes: u64, result_entries: u32) -> Capsule {
    Capsule::new(
        OccurrenceRef::new(
            ExecutionId(Ulid::from_bytes([7; 16])),
            hash(2),
            OperationContract::new(
                StageId(SmolStr::new("build")),
                RuntimeOperation::Select {
                    selector: hash(0x44),
                },
            )
            .id(),
            OperationPath(vec![3, 5]),
        )
        .id(),
        prepared_action(),
        EnvironmentRef::new(
            ArtifactRef::new(hash(8), 64, ArtifactPrivacy::Public).id(),
            hash(9),
        )
        .id(),
        PlatformRef::new("x86_64-linux", hash(6)).id(),
        vec![GuestMapping {
            artifact: ArtifactRef::new(hash(8), 64, ArtifactPrivacy::Public).id(),
            guest_path: GuestPath::new("/work/src").unwrap(),
            access: GuestAccess::ReadWrite,
        }],
        CapsuleProcess::Command {
            argv: pinned_argv(),
        },
        CapsuleNetwork::Offline,
        None,
        CapsuleBudgets {
            wall_time_ms: 10,
            output_bytes: 20,
            memory_bytes: 30,
            process_count: 2,
            result_bytes,
            result_entries,
            work_delta_bytes: kata_types::execution_contract::CAPSULE_WORK_DELTA_BYTES,
            work_delta_entries: kata_types::execution_contract::CAPSULE_WORK_DELTA_ENTRIES,
        },
        None,
    )
    .expect("one mapping is never a duplicate")
}

/// One capsule differing from its sibling only in the guest access mode.
fn single_mapping_capsule(access: GuestAccess) -> Capsule {
    Capsule::new(
        OccurrenceRef::new(
            ExecutionId(Ulid::from_bytes([7; 16])),
            hash(2),
            OperationContract::new(
                StageId(SmolStr::new("build")),
                RuntimeOperation::Select {
                    selector: hash(0x44),
                },
            )
            .id(),
            OperationPath(vec![3, 5]),
        )
        .id(),
        prepared_action(),
        EnvironmentRef::new(
            ArtifactRef::new(hash(8), 64, ArtifactPrivacy::Public).id(),
            hash(9),
        )
        .id(),
        PlatformRef::new("x86_64-linux", hash(6)).id(),
        vec![GuestMapping {
            artifact: ArtifactRef::new(hash(8), 64, ArtifactPrivacy::Public).id(),
            guest_path: GuestPath::new("/work/src").unwrap(),
            access,
        }],
        CapsuleProcess::Command {
            argv: pinned_argv(),
        },
        CapsuleNetwork::Offline,
        None,
        CapsuleBudgets {
            wall_time_ms: 10,
            output_bytes: 20,
            memory_bytes: 30,
            process_count: 2,
            result_bytes: 4 * 1024 * 1024,
            result_entries: 128,
            work_delta_bytes: kata_types::execution_contract::CAPSULE_WORK_DELTA_BYTES,
            work_delta_entries: kata_types::execution_contract::CAPSULE_WORK_DELTA_ENTRIES,
        },
        None,
    )
    .expect("one mapping is never a duplicate")
}

/// The loop-policy selector is an identity family of its own — hashed from the
/// authored [`ReviewLoop`] rather than from a contract — so nothing else in this
/// file would catch a changed field name, field order, or domain tag in it.
#[test]
fn loop_policy_selector_vector_is_pinned() {
    let review_loop = loop_policy();
    assert_eq!(
        loop_policy_selector(&review_loop).to_string(),
        "f1846fdcd59a9d761f59196b22a3abe2c3bfc670a55dffc12187db6c71adb563"
    );

    // Every field is load-bearing, pinned one at a time from OUTSIDE so a field
    // silently dropped from the hash shows up as a COLLISION with the base vector
    // rather than as a rotation nobody notices.
    let mut exhaustion = review_loop.clone();
    exhaustion.on_max = OnMaxAction::Accept;
    assert_eq!(
        loop_policy_selector(&exhaustion).to_string(),
        "49995b69d4b27bc9d473eb404dd728cb44f74467b65487387cd9db18590abc2c"
    );

    let mut bounded = review_loop.clone();
    bounded.bounds = vec![Bound::time(60_000).expect("positive ms")];
    assert_eq!(
        loop_policy_selector(&bounded).to_string(),
        "9b2831e00fd6e514101d7d4093bb3e1b92ae55c4625b4e3fcd9abc56453f7beb"
    );

    let mut vocabulary = review_loop.clone();
    vocabulary.gate_verdict = Some(
        LoopVerdictConfig::new(
            "decision",
            vec![SmolStr::new("promote")],
            vec![SmolStr::new("continue")],
            vec![SmolStr::new("park")],
        )
        .expect("a disjoint, non-empty vocabulary"),
    );
    assert_eq!(
        loop_policy_selector(&vocabulary).to_string(),
        "c6b787cbcc41f7bcfca6128d92cb384657c7fcdb20bb470443917dd8fad001e0"
    );

    // A MULTI-TAG vocabulary, so the tag-set CANONICALIZATION is pinned from
    // outside: with one tag per set the sort is a no-op and this file could not
    // see it.
    let mut multi = review_loop.clone();
    multi.gate_verdict = Some(
        LoopVerdictConfig::new(
            "decision",
            vec![SmolStr::new("promote"), SmolStr::new("stop")],
            vec![SmolStr::new("repair"), SmolStr::new("continue")],
            vec![SmolStr::new("park"), SmolStr::new("ask_human")],
        )
        .expect("a disjoint, non-empty vocabulary"),
    );
    assert_eq!(
        loop_policy_selector(&multi).to_string(),
        "c9ac37aa85cbabbe9599039ff5b4f7e3ba7223a857bee2ef19bbd30cc8255f4f"
    );

    // A tag-set is a CLASSIFICATION, so its order decides nothing: re-listing the
    // same tags must hash IDENTICALLY, or a cosmetic re-ordering of a pack's
    // `gate_verdict` would rotate every expansion identity in it. Each set is
    // reversed here, and the base vector above pins which of the two hashes wins.
    let mut reordered = multi.clone();
    let config = reordered
        .gate_verdict
        .as_mut()
        .expect("the vocabulary is set");
    config.approve.reverse();
    config.refine.reverse();
    config.block.reverse();
    assert_ne!(
        config.refine,
        multi
            .gate_verdict
            .as_ref()
            .expect("the vocabulary is set")
            .refine,
        "the premise: the two spellings really differ as LISTS"
    );
    assert_eq!(
        loop_policy_selector(&reordered),
        loop_policy_selector(&multi),
        "a reordered tag set is the same set, so the same policy hash"
    );

    // Nor does MULTIPLICITY decide anything: `classify` asks only whether a tag is
    // a member, so a repeated tag is the same set and must hash identically.
    let mut repeated = multi.clone();
    repeated
        .gate_verdict
        .as_mut()
        .expect("the vocabulary is set")
        .approve
        .push(SmolStr::new("promote"));
    assert_eq!(
        repeated
            .gate_verdict
            .as_ref()
            .expect("the vocabulary is set")
            .approve
            .len(),
        3,
        "the premise: the list really carries the duplicate"
    );
    assert_eq!(
        loop_policy_selector(&repeated),
        loop_policy_selector(&multi),
        "a repeated tag is the same set, so the same policy hash"
    );

    // `None` is NOT `Some(DEFAULT_ROLLOVER_AFTER_ITERATIONS)`: one says "whatever
    // this build defaults to", the other pins a window the author chose. Pinning
    // both proves the distinction survives.
    let mut rollover = review_loop.clone();
    rollover.rollover_after_iterations =
        Some(kata_types::review_loop::DEFAULT_ROLLOVER_AFTER_ITERATIONS);
    assert_eq!(
        loop_policy_selector(&rollover).to_string(),
        "ea50e14b667601df682a4f5d45a2052781b07049447d962aba2e3850e49ab434"
    );
    assert_ne!(
        loop_policy_selector(&rollover),
        loop_policy_selector(&review_loop)
    );

    // An ABSENT `gate_verdict` is the default vocabulary, because the runtime's
    // verdict read resolves both through the same accessor. Two spellings of one
    // policy, so one hash — the deliberate other half of the rollover rule above.
    let mut spelled_out = review_loop.clone();
    spelled_out.gate_verdict = Some(LoopVerdictConfig::default_verdict());
    assert_eq!(
        loop_policy_selector(&spelled_out),
        loop_policy_selector(&review_loop),
        "an explicit default vocabulary is the same policy as an absent one"
    );
}

/// One review loop, the base every policy vector above varies by one field.
fn loop_policy() -> ReviewLoop {
    ReviewLoop {
        worker_stage: SmolStr::new("implement"),
        reviewer_stage: SmolStr::new("review"),
        max_iterations: 3,
        on_max: OnMaxAction::Fail,
        bounds: Vec::new(),
        gate_verdict: None,
        body_stages: Vec::new(),
        rollover_after_iterations: None,
    }
}

fn prepared_action() -> PreparedActionId {
    PreparedActionId(hash(0x55))
}

/// **The operator guide states this build's execution contract version.** Its
/// "Durable formats and upgrades" list names the contract an operator's capsules
/// are identified under; a bump that left the guide behind told operators the
/// previous number. Read off the guide's file, not off any kata answer.
///
/// **Would red if:** `EXECUTION_CONTRACT_SCHEMA_VERSION` moved and the guide did not.
#[test]
fn the_operator_guide_states_the_execution_contract_version() {
    let guide = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../docs/product/operator-guide.md"
    ))
    .expect("the operator guide is readable");
    let stated =
        format!("**The execution contract is at version {EXECUTION_CONTRACT_SCHEMA_VERSION}**");
    assert!(
        guide.contains(&stated),
        "docs/product/operator-guide.md does not state {stated:?}"
    );
}
