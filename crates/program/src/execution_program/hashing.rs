//! Stable hashing and cache-key derivation for the checked execution program.
//!
//! The domain-separated blake3 hashers that mint the workflow-class identity,
//! stage contract hashes, and prompt hashes, plus the generic stable-JSON
//! hashing primitive they build on. The whole-program hash MATERIAL structs are
//! assembled inline in [`super::lowering`] (their construction site).

use std::collections::BTreeMap;

use kata_types::execution::{WORKFLOW_CLASS_IDENTITY_SCHEMA_VERSION, WorkflowClassIdentity};
use kata_types::execution_class::CheckedExecutionClass;
use kata_types::primitives::{ContentHash, FixedBytes};
use kata_types::workflow::StageId;
use serde::Serialize;
use smol_str::SmolStr;

use super::{
    EXECUTION_PROGRAM_SCHEMA_VERSION, ExecutionInvocationEnvelope, ExecutionOutputContract,
    ExecutionProgramSource, ExecutionProgramStage, ExecutionPromptRendering, ExecutionStageOp,
    ExecutionStageOpKind, ExecutionStagePolicies,
};

#[derive(Serialize)]
struct WorkflowClassHashMaterial<'a> {
    schema_version: u32,
    source: &'a ExecutionProgramSource,
    program_hash: ContentHash,
    stage_identities: Vec<WorkflowClassStageIdentity<'a>>,
}

#[derive(Serialize)]
struct WorkflowClassStageIdentity<'a> {
    stage_id: &'a StageId,
    prompt_hash: Option<ContentHash>,
    contract_hash: ContentHash,
}

pub(super) fn workflow_class_identity(
    source: &ExecutionProgramSource,
    program_hash: ContentHash,
    stages: &BTreeMap<StageId, ExecutionProgramStage>,
) -> WorkflowClassIdentity {
    let stage_identities = stages
        .values()
        .map(|stage| WorkflowClassStageIdentity {
            stage_id: &stage.stage_id,
            prompt_hash: stage.op.prompt_hash,
            contract_hash: stage.contract_hash,
        })
        .collect::<Vec<_>>();
    WorkflowClassIdentity {
        schema_version: WORKFLOW_CLASS_IDENTITY_SCHEMA_VERSION,
        id: hash_stable_json_with_domain(
            b"kata.workflow.workflow_class.v1\0",
            &WorkflowClassHashMaterial {
                schema_version: WORKFLOW_CLASS_IDENTITY_SCHEMA_VERSION,
                source,
                program_hash,
                stage_identities,
            },
        ),
    }
}

#[derive(Serialize)]
struct PromptHashMaterial<'a> {
    schema_version: u32,
    prompt_rendering: ExecutionPromptRendering,
    prompt_template: &'a str,
}

pub(super) fn prompt_template_hash(
    prompt_template: &str,
    prompt_rendering: ExecutionPromptRendering,
) -> Option<ContentHash> {
    if prompt_template.trim().is_empty() {
        return None;
    }

    Some(hash_stable_json_with_domain(
        b"kata.workflow.stage_prompt.v1\0",
        &PromptHashMaterial {
            schema_version: EXECUTION_PROGRAM_SCHEMA_VERSION,
            prompt_rendering,
            prompt_template,
        },
    ))
}

#[derive(Serialize)]
struct StageContractHashMaterial<'a> {
    schema_version: u32,
    stage_id: &'a StageId,
    op_kind: ExecutionStageOpKind,
    agent: &'a SmolStr,
    #[serde(skip_serializing_if = "Option::is_none")]
    agent_label: Option<&'a SmolStr>,
    // Fold the agent fallback panel into the stage contract hash so the
    // checked contract commits to the full ordered panel — every member the
    // dispatcher may advance to at failure-retry is authorized under this one
    // hash. Skip-if-empty keeps single-agent stages free of the field.
    #[serde(skip_serializing_if = "<[SmolStr]>::is_empty")]
    agent_panel: &'a [SmolStr],
    prompt_rendering: ExecutionPromptRendering,
    depends_on: &'a [StageId],
    outputs: &'a [ExecutionOutputContract],
    // The hashed seven-axis execution class is part of the checked stage
    // contract — a semantic-axis change (containment/network/issuance/…) rotates
    // stage identity even when the authoring knobs are byte-identical.
    execution_class: CheckedExecutionClass,
    policies: &'a ExecutionStagePolicies,
    invocation_envelope: &'a ExecutionInvocationEnvelope,
}

pub(super) fn stage_contract_hash(
    stage_id: &StageId,
    op: &ExecutionStageOp,
    depends_on: &[StageId],
    outputs: &[ExecutionOutputContract],
    policies: &ExecutionStagePolicies,
    invocation_envelope: &ExecutionInvocationEnvelope,
    execution_class: CheckedExecutionClass,
) -> ContentHash {
    hash_stable_json_projected(
        b"kata.workflow.stage_contract.v1\0",
        &StageContractHashMaterial {
            schema_version: EXECUTION_PROGRAM_SCHEMA_VERSION,
            stage_id,
            op_kind: op.kind,
            agent: &op.agent,
            agent_label: op.agent_label.as_ref(),
            agent_panel: &op.agent_panel,
            prompt_rendering: op.prompt_rendering,
            depends_on,
            outputs,
            execution_class,
            policies,
            invocation_envelope,
        },
        // The only SandboxProfile inside a stage contract is the
        // inline ref carried in `policies.sandbox` — strip its placement brand.
        |material| {
            if let Some(policies) = material.get_mut("policies") {
                project_policies_sandbox(policies);
            }
        },
    )
}

/// Hash the whole-program material after stripping the out-of-hash placement
/// brand from EVERY SandboxProfile projection it embeds — the named
/// `sandbox_profiles` map AND each stage's inline `policies.sandbox`.
pub(super) fn hash_program_material<T: Serialize>(value: &T) -> ContentHash {
    hash_stable_json_projected(
        b"kata.workflow.execution_program.v1\0",
        value,
        project_program_hash_material,
    )
}

fn hash_stable_json_with_domain<T: Serialize>(domain: &[u8], value: &T) -> ContentHash {
    let bytes = serde_json::to_vec(value).expect("execution program hash material serializes");
    hash_domain_bytes(domain, &bytes)
}

/// Serialize `value`, apply a placement-brand `project`ion to the resulting JSON
/// tree, then hash the projected bytes. The projection is the ONE place the
/// out-of-hash brand (`exec`) is removed from a hashed SandboxProfile —
/// see [`strip_sandbox_placement_brand`].
fn hash_stable_json_projected<T: Serialize>(
    domain: &[u8],
    value: &T,
    project: impl FnOnce(&mut serde_json::Value),
) -> ContentHash {
    let mut json = serde_json::to_value(value).expect("execution program hash material serializes");
    project(&mut json);
    let bytes = serde_json::to_vec(&json).expect("projected hash material serializes");
    hash_domain_bytes(domain, &bytes)
}

fn hash_domain_bytes(domain: &[u8], bytes: &[u8]) -> ContentHash {
    let mut hasher = blake3::Hasher::new();
    hasher.update(domain);
    hasher.update(&(bytes.len() as u64).to_le_bytes());
    hasher.update(bytes);
    let digest = hasher.finalize();
    FixedBytes::new(*digest.as_bytes())
}

/// Strip the out-of-hash PLACEMENT BRAND from a
/// serialized SandboxProfile projection: `exec` (the containment-provider brand,
/// a placement hint chosen after checking requirements — never authored
/// identity). `fs`/`net`/`secrets`/
/// `image` STAY: workspace + secret + toolchain-identity contract. The
/// `SandboxProfile` struct KEEPS `exec` for dispatch equality; only the HASH
/// projection drops it, so re-placing a stage onto another backend never
/// rotates a program or contract hash.
fn strip_sandbox_placement_brand(profile: &mut serde_json::Value) {
    if let Some(obj) = profile.as_object_mut() {
        obj.remove("exec");
    }
}

/// Strip the placement brand from the inline SandboxRef carried in a hashed
/// `policies.sandbox` — a `{"kind":"inline","data":<profile>}` tag/content
/// shape. A `named` ref carries no profile bytes here; its profile is projected
/// in the whole-program `sandbox_profiles` map instead.
fn project_policies_sandbox(policies: &mut serde_json::Value) {
    if let Some(sandbox) = policies.get_mut("sandbox")
        && sandbox.get("kind").and_then(serde_json::Value::as_str) == Some("inline")
        && let Some(data) = sandbox.get_mut("data")
    {
        strip_sandbox_placement_brand(data);
    }
}

/// Strip the placement brand from EVERY SandboxProfile inside the whole-program
/// hash material: the named `sandbox_profiles` map (each value is a profile) and
/// each embedded stage's inline `policies.sandbox`.
///
/// A subworkflow stage's bound child needs no projection: `BoundChildProgram` serializes
/// as its `program_hash` alone (`bound_children`), and the child's hash already folds its
/// body under this same projection. `BoundChildProgram`'s invariant is what makes the
/// hash a sufficient stand-in — no value of that type holds a body that does not
/// re-derive it.
fn project_program_hash_material(material: &mut serde_json::Value) {
    if let Some(profiles) = material
        .get_mut("sandbox_profiles")
        .and_then(serde_json::Value::as_object_mut)
    {
        for profile in profiles.values_mut() {
            strip_sandbox_placement_brand(profile);
        }
    }
    if let Some(stages) = material
        .get_mut("stages")
        .and_then(serde_json::Value::as_object_mut)
    {
        for stage in stages.values_mut() {
            if let Some(policies) = stage.get_mut("policies") {
                project_policies_sandbox(policies);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The placement brand: the one field the projection must STRIP.
    const PLACEMENT_BRAND: &[&str] = &["exec"];

    /// The hashed contract: every other field, which the projection must KEEP.
    ///
    /// `toolchain` is CONTRACT, not brand, and the distinction is the one
    /// this list exists to force. `exec` is stripped because it names
    /// WHERE an action is placed, never what it computes: re-placing
    /// a stage from one backend to another must not rotate a hash. A toolchain
    /// requirement is the opposite — it names the bytes the stage EXECUTES, so
    /// two stages that require different compilers are two different actions and
    /// sharing a `contract_hash` between them would alias them — a stale cache
    /// hit. Hashed.
    /// `rootfs` JOINS this list, and the argument is
    /// `toolchain`'s ONE STEP STRONGER: a declared ROOT is more of a stage's
    /// meaning than a compiler is, not less. Classifying it as placement would
    /// make a declared userland invisible to stage identity — the same stale-hit
    /// shape at root scale. Costs no shipped pack a hash: the field is
    /// `Option` + `skip_serializing_if`, so an unauthored `rootfs` contributes
    /// ZERO bytes and every profile in the corpus serializes byte-identically —
    /// the attribute is load-bearing rather than stylistic. Do not "tidy" it
    /// away.
    const HASHED_CONTRACT: &[&str] = &[
        "fs",
        "net",
        "image",
        "secrets",
        "locked",
        "toolchain",
        "rootfs",
        "requires",
    ];

    /// A `SandboxProfile` with EVERY field populated, built as a struct literal
    /// with no `..Default::default()`.
    ///
    /// This replaces a hand-written `serde_json::json!` fixture. That
    /// fixture was the tautological shape — a fixed JSON object checked against a
    /// fixed kept-list, so a NEW `SandboxProfile` field was simply absent from the
    /// fixture, never presented to the projection, and silently hashed with nobody
    /// having decided whether it is a brand or a contract. The guard could not
    /// fail on the one case it exists to catch.
    ///
    /// The struct literal makes that unrepresentable rather than merely detected:
    /// a new field is a MISSING-FIELD COMPILE ERROR here, and
    /// [`projection_classifies_every_sandbox_profile_field`] then forces it into
    /// exactly one of the two lists above.
    fn every_field_profile() -> serde_json::Value {
        let profile = kata_types::sandbox::SandboxProfile {
            exec: kata_types::sandbox::ExecBackend::Oci,
            fs: kata_types::sandbox::FsPolicy::WorkspaceRw,
            net: kata_types::sandbox::NetPolicy::Offline,
            secrets: [(
                "TOKEN".to_string(),
                kata_types::sandbox::SecretRef::Env("TOKEN".to_string()),
            )]
            .into_iter()
            .collect(),
            locked: false,
            image: Some(kata_types::sandbox::SandboxImage {
                reference: "toolchain:1".to_string(),
                cpus: None,
                memory_mb: None,
            }),
            // `Some`, not `None` — the field is `skip_serializing_if`, so a
            // `None` here would leave it out of the serialized object and the
            // completeness assertion below would pass while never having seen it.
            // "Every field populated" has to mean populated.
            toolchain: kata_types::sandbox::ToolchainRequirement::parse(
                "store:1111111111111111111111111111111111111111111111111111111111111111",
            ),
            // `Some`, for the reason above — and a
            // DIFFERENT hex from `toolchain`'s, which is the load-bearing half:
            // with the same address in both fields a projection that SWAPPED
            // them, or that stripped one and duplicated the other, would leave
            // the serialized object identical and both assertions below green.
            // Two fields carrying one value cannot tell the two fields apart.
            rootfs: kata_types::sandbox::ToolchainRequirement::parse(
                "store:2222222222222222222222222222222222222222222222222222222222222222",
            ),
            // Non-empty for the same reason: an empty list is
            // skipped on serialization and the completeness check would never
            // see the field.
            requires: vec!["cargo".to_owned()],
        };
        serde_json::to_value(profile).expect("a sandbox profile serializes")
    }

    /// COMPLETENESS. Every serialized field of a fully-populated real
    /// `SandboxProfile` is classified as either placement brand or hashed
    /// contract — no field may be neither.
    ///
    /// A fixed-JSON fixture could not make this assertion. Adding a
    /// field to `SandboxProfile` fails here until somebody decides, in this
    /// file, whether it belongs to placement (stripped, so two profiles differing
    /// only in it hash the same) or to the contract (hashed, so they do not).
    #[test]
    fn projection_classifies_every_sandbox_profile_field() {
        let profile = every_field_profile();
        let serialized: std::collections::BTreeSet<&str> = profile
            .as_object()
            .expect("a profile serializes to an object")
            .keys()
            .map(String::as_str)
            .collect();
        let classified: std::collections::BTreeSet<&str> = PLACEMENT_BRAND
            .iter()
            .chain(HASHED_CONTRACT.iter())
            .copied()
            .collect();
        assert_eq!(
            serialized, classified,
            "every SandboxProfile field must be classified as placement brand (stripped from the \
             hash) or hashed contract (kept). An unclassified field is silently hashed with nobody \
             having decided it should be — which is exactly the question this projection \
             exists to answer"
        );
    }

    /// The projection strips ONLY the placement brand
    /// (`exec`) from every hashed SandboxProfile, and KEEPS the
    /// workspace/egress/toolchain contract (`fs`/`net`/`image`) and the operator
    /// secret contract (`secrets`). Direct Value-level proof, independent of any
    /// source provenance (which the whole-program hash separately commits to).
    #[test]
    fn projection_strips_only_the_placement_brand() {
        let profile = every_field_profile;
        // (a) a bare profile projection.
        let mut p = profile();
        strip_sandbox_placement_brand(&mut p);
        let obj = p.as_object().unwrap();
        for brand in PLACEMENT_BRAND {
            assert!(
                !obj.contains_key(*brand),
                "{brand} (placement) must be stripped"
            );
        }
        for kept in HASHED_CONTRACT {
            assert!(
                obj.contains_key(*kept),
                "{kept} must be KEPT (contract identity)"
            );
        }

        // (b) the whole-program material walk: named `sandbox_profiles` map AND a
        // stage's inline `policies.sandbox` both get projected; a `named` ref is
        // left untouched (its profile lives in the map).
        let mut material = serde_json::json!({
            "sandbox_profiles": { "s": profile() },
            "stages": {
                "inline_stage": { "policies": { "sandbox": {"kind": "inline", "data": profile()} } },
                "named_stage": { "policies": { "sandbox": {"kind": "named", "data": "s"} } }
            }
        });
        project_program_hash_material(&mut material);
        assert!(material["sandbox_profiles"]["s"].get("exec").is_none());
        assert!(material["sandbox_profiles"]["s"].get("fs").is_some());
        let inline = &material["stages"]["inline_stage"]["policies"]["sandbox"]["data"];
        assert!(inline.get("exec").is_none(), "inline brand stripped");
        assert!(inline.get("fs").is_some(), "inline fs kept");
        // A named ref carries no profile bytes to project.
        assert_eq!(
            material["stages"]["named_stage"]["policies"]["sandbox"]["data"],
            serde_json::json!("s")
        );
    }

    // -----------------------------------------------------------------------
    // The stage CONTRACT reaches the CONTENT-CACHE KEY, field by field
    // -----------------------------------------------------------------------

    /// The pack every row below re-hashes against — one hermetic shell stage, so
    /// the op / envelope / execution class the material folds come from the real
    /// lowering rather than from a fixture that could describe a stage the
    /// compiler never produces.
    const ONE_STAGE_PACK: &str = r#"
s = stage(id = "s", agent = "shell", run = "echo hi")
workflow("policies-field-coverage", root = s)
"#;

    fn checked_stage() -> ExecutionProgramStage {
        super::super::compile_starlark_execution_program(
            ONE_STAGE_PACK,
            "policies_field_coverage.star",
            &[],
        )
        .expect("the one-stage pack compiles")
        .stages
        .remove(&StageId(SmolStr::new("s")))
        .expect("the checked program carries stage s")
    }

    fn sandbox_ref(fs: kata_types::sandbox::FsPolicy) -> kata_types::sandbox::SandboxRef {
        kata_types::sandbox::SandboxRef::Inline(Box::new(kata_types::sandbox::SandboxProfile {
            exec: kata_types::sandbox::ExecBackend::Oci,
            fs,
            net: kata_types::sandbox::NetPolicy::Offline,
            secrets: std::collections::BTreeMap::new(),
            locked: false,
            image: None,
            toolchain: None,
            rootfs: None,
            requires: Vec::new(),
        }))
    }

    /// Fixture A — EVERY field populated with a non-default value, as a struct
    /// literal with NO `..Default::default()`.
    ///
    /// The literal is the compile-time half of this guard, exactly as
    /// [`every_field_profile`] is for `SandboxProfile`: adding a field to
    /// [`ExecutionStagePolicies`] is a MISSING-FIELD COMPILE ERROR here, so the
    /// author cannot leave the new field unconsidered.
    fn policies_a() -> ExecutionStagePolicies {
        ExecutionStagePolicies {
            cache_policy: kata_types::cache::CachePolicy::ContentCache,
            approval_required: true,
            approval_reason: Some("reason-a".to_string()),
            model_hint: Some(SmolStr::new("model-a")),
            timeout_ms: 1_000,
            output_bytes: Some(1 << 20),
            work_delta_bytes: Some(8 << 20),
            work_delta_entries: Some(512),
            output_schema: Some(serde_json::json!({"type": "object"})),
            allowed_tools: vec![SmolStr::new("Bash")],
            required_capabilities: vec![SmolStr::new("cap-a")],
            sandbox: Some(sandbox_ref(kata_types::sandbox::FsPolicy::WorkspaceRo)),
            working_tree: Some("/wt/a".to_string()),
            validate_retries: 1,
            validate_feedback_template: Some("feedback-a".to_string()),
            cost_budget: kata_types::BudgetPolicy::Warn {
                limit_micro_usd: 10,
            },
            progress_visibility: kata_types::workflow::ProgressVisibility::Summary,
            // NOT the default: the default is `skip_serializing_if`, so a
            // fixture holding it would leave the field out of A's serialized
            // object and the mutation/serialization cross-check below would
            // compare a 14-key surface against a 15-mutation list and pass for
            // the wrong reason. `ZeroSuccess` is the default and `Content` the
            // authored opt-out, so this fixture holds `Content`. The cross-check
            // counts the serialized surface and fails the moment a field goes
            // invisible to serde.
            exit_policy: kata_types::workflow::ShellExitPolicy::Content,
        }
    }

    /// Fixture B — the same struct with EVERY field DIFFERENT from
    /// [`policies_a`]. Same compile-time property, and the per-field
    /// `assert_ne!` below proves the "different" claim rather than trusting it.
    fn policies_b() -> ExecutionStagePolicies {
        ExecutionStagePolicies {
            cache_policy: kata_types::cache::CachePolicy::ModelReuse,
            approval_required: false,
            approval_reason: Some("reason-b".to_string()),
            model_hint: Some(SmolStr::new("model-b")),
            timeout_ms: 2_000,
            output_bytes: Some(2 << 20),
            work_delta_bytes: Some(16 << 20),
            work_delta_entries: Some(1024),
            output_schema: Some(serde_json::json!({"type": "string"})),
            allowed_tools: vec![SmolStr::new("Read")],
            required_capabilities: vec![SmolStr::new("cap-b")],
            // Differs in `fs`, a HASHED-CONTRACT field: `exec` is the
            // placement brand and is STRIPPED by `project_policies_sandbox`, so
            // a pair differing only in it would (correctly) hash equal and
            // this row would report a hole that is not one.
            sandbox: Some(sandbox_ref(kata_types::sandbox::FsPolicy::WorkspaceRw)),
            working_tree: Some("/wt/b".to_string()),
            validate_retries: 2,
            validate_feedback_template: Some("feedback-b".to_string()),
            cost_budget: kata_types::BudgetPolicy::Halt {
                limit_micro_usd: 20,
            },
            progress_visibility: kata_types::workflow::ProgressVisibility::Full,
            // The OTHER spelling from `policies_a`'s, and it is the DEFAULT — so
            // B omits the field where A serializes it. That asymmetry is fine
            // and is what the pair needs: only A's serialized surface is counted
            // against the mutation list, and the per-field `assert_ne!` below
            // compares `Some("content")` against `None`.
            exit_policy: kata_types::workflow::ShellExitPolicy::ZeroSuccess,
        }
    }

    /// `(field name, A with exactly that ONE field taken from B)` for EVERY field
    /// of [`ExecutionStagePolicies`].
    ///
    /// Built by EXHAUSTIVELY DESTRUCTURING B with no `..` rest pattern, which is
    /// the second compile-time gate: adding a field to the struct makes this
    /// pattern fail to compile (`pattern does not mention field ...`), and a
    /// binding introduced and then not used trips `unused_variables` — so a new
    /// field cannot be silently bound and dropped either.
    fn one_field_mutations() -> Vec<(&'static str, ExecutionStagePolicies)> {
        let ExecutionStagePolicies {
            cache_policy,
            approval_required,
            approval_reason,
            model_hint,
            timeout_ms,
            output_bytes,
            work_delta_bytes,
            work_delta_entries,
            output_schema,
            allowed_tools,
            required_capabilities,
            sandbox,
            working_tree,
            validate_retries,
            validate_feedback_template,
            cost_budget,
            progress_visibility,
            exit_policy,
        } = policies_b();
        let with = |mutate: &dyn Fn(&mut ExecutionStagePolicies)| {
            let mut policies = policies_a();
            mutate(&mut policies);
            policies
        };
        vec![
            ("cache_policy", with(&|p| p.cache_policy = cache_policy)),
            (
                "approval_required",
                with(&|p| p.approval_required = approval_required),
            ),
            (
                "approval_reason",
                with(&|p| p.approval_reason.clone_from(&approval_reason)),
            ),
            (
                "model_hint",
                with(&|p| p.model_hint.clone_from(&model_hint)),
            ),
            ("timeout_ms", with(&|p| p.timeout_ms = timeout_ms)),
            ("output_bytes", with(&|p| p.output_bytes = output_bytes)),
            (
                "work_delta_bytes",
                with(&|p| p.work_delta_bytes = work_delta_bytes),
            ),
            (
                "work_delta_entries",
                with(&|p| p.work_delta_entries = work_delta_entries),
            ),
            (
                "output_schema",
                with(&|p| p.output_schema.clone_from(&output_schema)),
            ),
            (
                "allowed_tools",
                with(&|p| p.allowed_tools.clone_from(&allowed_tools)),
            ),
            (
                "required_capabilities",
                with(&|p| p.required_capabilities.clone_from(&required_capabilities)),
            ),
            ("sandbox", with(&|p| p.sandbox.clone_from(&sandbox))),
            (
                "working_tree",
                with(&|p| p.working_tree.clone_from(&working_tree)),
            ),
            (
                "validate_retries",
                with(&|p| p.validate_retries = validate_retries),
            ),
            (
                "validate_feedback_template",
                with(&|p| {
                    p.validate_feedback_template
                        .clone_from(&validate_feedback_template);
                }),
            ),
            (
                "cost_budget",
                with(&|p| p.cost_budget.clone_from(&cost_budget)),
            ),
            (
                "progress_visibility",
                with(&|p| p.progress_visibility = progress_visibility),
            ),
            ("exit_policy", with(&|p| p.exit_policy = exit_policy)),
        ]
    }

    /// EVERY field of [`ExecutionStagePolicies`] reaches the stage
    /// `contract_hash` AND, through it, the OPERATION IDENTITY — the term the
    /// prepared action (and so the capsule reuse key) folds.
    ///
    /// # The class this exists to stop recurring
    ///
    /// The contract hash folds the whole policies struct, and the reuse key
    /// folds the contract hash, so a policy field that stayed out of
    /// `contract_hash` would be a band an author could invert while reuse went
    /// on serving the
    /// envelope recorded under the old one. `exit_policy` is the instance:
    /// outside the hash, arming `zero_success` on a stage whose `exit 1` had been
    /// swallowed as content would serve the recorded Completed envelope and the
    /// gate would never fire.
    ///
    /// # What defeats this guard
    ///
    /// Three inputs, named rather than hidden:
    ///
    /// 1. A new field on [`StageContractHashMaterial`] that is NOT an
    ///    `ExecutionStagePolicies` field — the material is hand-assembled and
    ///    this row enumerates only the policies struct.
    /// 2. A change that keeps `OperationContract::id` folding the contract hash
    ///    while the production lowering stops PASSING it. This row calls the
    ///    same fold `operation_lowering` builds
    ///    (`ExecuteOperation::contract_hash`), so it sees the function but not
    ///    the call site.
    /// 3. A field whose A/B fixture values are accidentally equal — closed by the
    ///    per-field `assert_ne!` on the two serialized values, and, for a field
    ///    serde cannot see at all, by the count cross-check below.
    #[test]
    fn every_policies_field_reaches_the_stage_contract_hash_and_the_operation_identity() {
        use kata_types::execution_contract::{
            ActionExecutor, ExecuteOperation, OperationContract, RuntimeOperation,
        };
        use kata_types::workflow::StageId;

        let stage = checked_stage();
        let hash_of = |policies: &ExecutionStagePolicies| {
            stage_contract_hash(
                &stage.stage_id,
                &stage.op,
                &stage.depends_on,
                &stage.outputs,
                policies,
                &stage.invocation_envelope,
                stage.execution_class,
            )
        };
        // The IDENTITY link: `contract_hash` lands on `ExecuteOperation`, whose
        // contract `id()` is `PreparedAction.operation` — the reuse-identity
        // term — with everything else held fixed.
        let id_of = |policies: &ExecutionStagePolicies| {
            OperationContract::new(
                StageId(smol_str::SmolStr::new("s")),
                RuntimeOperation::Execute(ExecuteOperation {
                    executor: ActionExecutor::Command,
                    contract_hash: hash_of(policies),
                }),
            )
            .id()
        };

        let a = policies_a();
        let baseline = hash_of(&a);
        let baseline_id = id_of(&a);

        let a_json = serde_json::to_value(&a).expect("policies serialize");
        let b_json = serde_json::to_value(policies_b()).expect("policies serialize");
        let a_obj = a_json.as_object().expect("policies serialize to an object");
        let b_obj = b_json.as_object().expect("policies serialize to an object");

        let mutations = one_field_mutations();

        // CROSS-CHECK. A is fully non-default, so every field serde can see
        // appears in its object; the mutation list is exhaustive by
        // destructuring. If the two counts disagree, a field exists that serde
        // does not emit (`#[serde(skip)]`) — which is also a field the contract
        // hash cannot fold, so it must be caught here rather than discovered as a
        // stale hit.
        assert_eq!(
            mutations.len(),
            a_obj.len(),
            "the exhaustive one-field mutation list and the SERIALIZED policies surface must \
             have the same size. They differ, which means a field is invisible to serde (and \
             therefore to `stage_contract_hash`, which hashes the serialized material) — \
             mutations={:?} serialized={:?}",
            mutations.iter().map(|(name, _)| *name).collect::<Vec<_>>(),
            a_obj.keys().collect::<Vec<_>>()
        );

        for (field, mutated) in mutations {
            // The fixtures really do differ in this field (absence counts:
            // `exit_policy = Content` is skip-serialized).
            assert_ne!(
                a_obj.get(field),
                b_obj.get(field),
                "fixture defect: policies_a and policies_b agree on `{field}`, so the \
                 assertions below would pass without observing anything"
            );
            assert_ne!(
                baseline,
                hash_of(&mutated),
                "changing `ExecutionStagePolicies::{field}` must rotate the stage \
                 contract_hash — the checked stage identity the dispatcher enforces"
            );
            assert_ne!(
                baseline_id,
                id_of(&mutated),
                "changing `ExecutionStagePolicies::{field}` must rotate the operation \
                 identity. It does not, so an author can invert this band and reuse \
                 will answer from the envelope recorded under the old contract — a hit \
                 never reaches the dispatcher's contract-hash check, which is the only \
                 other place this field is enforced"
            );
        }
    }

    /// THE CONTRACT-HASH EXCLUSION DISCIPLINE — the provenance/divert fields a
    /// checked stage carries that are deliberately NOT terms of its contract.
    ///
    /// [`ExecutionProgramStage::subworkflow`], [`ExecutionProgramStage::durable_sleep`],
    /// [`ExecutionProgramStage::synthesized`],
    /// [`ExecutionProgramStage::workspace_effect_op`] and
    /// [`ExecutionProgramStage::authored_span`] each say where a stage CAME FROM,
    /// or that the runner DIVERTS it before dispatch — never what it must
    /// compute. Folding one into `contract_hash` would rotate a stage's checked
    /// identity, and invalidate every cached result recorded under it, for a
    /// change that does not change the work: for `authored_span` that is a
    /// whitespace-only re-indent of the pack, which is why the field belongs on
    /// this list rather than in [`ExecutionStagePolicies`].
    ///
    /// The exclusion is STRUCTURAL: [`stage_contract_hash`] takes its material
    /// field by field and not one of these five is a parameter. This row exists so
    /// that widening that parameter list — the one change that would silently
    /// break the discipline — reds here instead of surfacing as a cache miss
    /// storm. Its other half is the `assert_ne!` on the serialized stage bytes:
    /// each field IS inside `program_hash` (taken over the serialized stages), so
    /// a "fix" that made a field invisible to serde would red too.
    #[test]
    fn provenance_fields_stay_out_of_the_stage_contract_hash() {
        let baseline = checked_stage();
        let hash_of = |stage: &ExecutionProgramStage| {
            stage_contract_hash(
                &stage.stage_id,
                &stage.op,
                &stage.depends_on,
                &stage.outputs,
                &stage.policies,
                &stage.invocation_envelope,
                stage.execution_class,
            )
        };
        let bytes_of = |stage: &ExecutionProgramStage| {
            serde_json::to_vec(stage).expect("a checked stage serializes")
        };
        let base_hash = hash_of(&baseline);
        let base_bytes = bytes_of(&baseline);

        // One mutation per excluded field, each a value the baseline cannot
        // already hold (the baseline is a plain hermetic shell stage, so every
        // one of these is `None` on it).
        let mut mutations: Vec<(&'static str, ExecutionProgramStage)> = Vec::new();
        for (field, apply) in [
            (
                "subworkflow",
                Box::new(|stage: &mut ExecutionProgramStage| {
                    let child = super::super::compile_starlark_execution_program(
                        "only = stage(id = \"only\", agent = \"shell\", run = \":\")\n\
                         workflow(\"child\", root = only)\n",
                        "child.star",
                        &[],
                    )
                    .expect("the child compiles");
                    stage.subworkflow = Some(super::super::SubworkflowSpec {
                        pack: SmolStr::new("child"),
                        params: serde_json::Map::new(),
                        bound: super::super::BoundChildProgram::bind(child)
                            .expect("a compiled child binds"),
                    });
                }) as Box<dyn Fn(&mut ExecutionProgramStage)>,
            ),
            (
                "durable_sleep",
                Box::new(|stage: &mut ExecutionProgramStage| {
                    stage.durable_sleep = Some(kata_types::wait::DurableSleep::For { ms: 1_000 });
                }),
            ),
            (
                "synthesized",
                Box::new(|stage: &mut ExecutionProgramStage| {
                    stage.synthesized = Some(kata_types::workflow::SynthesizedStage::ParallelJoin);
                }),
            ),
            (
                "workspace_effect_op",
                Box::new(|stage: &mut ExecutionProgramStage| {
                    stage.workspace_effect_op = Some(kata_types::workflow::WorkspaceEffectOp::Park);
                }),
            ),
            (
                "authored_span",
                Box::new(|stage: &mut ExecutionProgramStage| {
                    stage.authored_span = Some(kata_types::source::SourceSpan {
                        file: "moved.star".to_owned(),
                        line: 4_242,
                        column: 7,
                    });
                }),
            ),
        ] {
            let mut mutated = baseline.clone();
            apply(&mut mutated);
            mutations.push((field, mutated));
        }

        for (field, mutated) in mutations {
            assert_ne!(
                base_bytes,
                bytes_of(&mutated),
                "fixture defect: setting `ExecutionProgramStage::{field}` did not change the serialized stage, so the assertion below would pass without observing anything (and the field would be invisible to `program_hash`)"
            );
            assert_eq!(
                base_hash,
                hash_of(&mutated),
                "`ExecutionProgramStage::{field}` reached the stage contract_hash. It is provenance about where the stage came from, or a pre-dispatch divert marker — not a term of the contract the stage must satisfy. Folding it in rotates checked stage identity and discards every cached result under the old hash for a change that does not change the work"
            );
        }
    }

    /// Non-vacuity for the row above: the identity link is real, not a constant.
    /// Two DIFFERENT contract hashes must give two different operation ids, and
    /// one contract hash must give one id.
    #[test]
    fn the_contract_hash_is_a_live_component_of_the_operation_identity() {
        use kata_types::execution_contract::{
            ActionExecutor, ExecuteOperation, OperationContract, RuntimeOperation,
        };
        use kata_types::workflow::StageId;

        let id = |contract: kata_types::primitives::ContentHash| {
            OperationContract::new(
                StageId(smol_str::SmolStr::new("s")),
                RuntimeOperation::Execute(ExecuteOperation {
                    executor: ActionExecutor::Command,
                    contract_hash: contract,
                }),
            )
            .id()
        };
        let a = kata_types::primitives::ContentHash::new([0x11; 32]);
        let b = kata_types::primitives::ContentHash::new([0x22; 32]);
        assert_ne!(id(a), id(b));
        assert_eq!(id(a), id(a));
    }
}
