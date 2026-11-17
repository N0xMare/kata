//! Derive a stage's [`CheckedExecutionClass`] from the authored surface.
//!
//! This is the WORKFLOW-side lowering of the seven-axis model
//! ([`kata_types::execution_class`]): it maps
//! the existing authored surface of one checked stage — its resolved executor,
//! declared sandbox (filesystem + network policy), and (for the in-process
//! backend) its workspace-provider operation — onto the seven orthogonal axes
//! and the op discriminator ([`CheckedOpContext`]).
//!
//! # Two values, one matrix: the DERIVED class and the CARRIED class
//!
//! The seven-axis class is not a compile-local side projection. It is a
//! REQUIRED, hashed field on
//! every checked stage ([`ExecutionProgramStage::execution_class`]), and the
//! runtime's verdict readers — cache eligibility, workspace mutation, certified
//! containment, orphan re-executability — all read that CARRIED field rather
//! than re-deriving anything.
//!
//! So there are two distinct values, and the distinction is load-bearing:
//!
//! * the **derived** class — what [`derive_execution_class`] computes right now,
//!   from this binary's derivation table; and
//! * the **carried** class — what a given `ExecutionProgramStage` actually holds.
//!
//! At compile they are the same value by construction: lowering fills the field
//! from [`derive_execution_class_from_parts`] over the same parts. They can
//! differ only on a program this binary did not compile — a durable
//! `ExecutionProgram` decoded back from the store, which is why
//! [`ExecutionProgram::validate_carried_stage_execution_classes`] validates the
//! CARRIED value: it is the one the runtime obeys.
//!
//! The op discriminator ([`CheckedOpContext`]) is the half that genuinely stays
//! compile-local — it is never serialized, so a decoded program cannot carry one
//! and it is always re-derived from the stage's own checked operation.
//!
//! The derivation is also proven EQUIVALENT to the stage-level derived
//! predicates:
//!
//! - [`CheckedExecutionClass::is_content_cache_eligible`] ≡
//!   [`ExecutionProgramStage::is_content_cacheable`], and
//! - [`CheckedExecutionClass::is_workspace_mutating`] ≡ the stage's hashed
//!   `execution_class.is_workspace_mutating()`
//!
//! for every stage of every shipped pack (the sole modeled exception is a forge
//! `land`/export stage — see the derivation table). The equivalence is by
//! construction: the derivation keys the determinism/workspace axes on exactly
//! the conditions those predicates key on.
//!
//! # Derivation table
//!
//! The class is a function of the resolved EXECUTOR and the resolved SANDBOX
//! (filesystem + network). The executor is one of: an opaque model/agent call,
//! a deterministic `shell` command, or the in-process main-owned
//! `workspace_effect` backend (whose sub-operation — `park`/`promote`/`commit`
//! vs `forge_export` — is recovered from the checked directive prompt).
//!
//! ## Executor → computation / issuance base
//!
//! | Executor | computation | determinism base | issuance base |
//! |---|---|---|---|
//! | `workspace_effect` park/promote/commit | `PureTransform` | `Deterministic` | `None` (admission 1) |
//! | `workspace_effect` `forge_export` (land) | `ProcessAction` | `Nondeterministic` | `DurableActivity` (admission 2) |
//! | `shell` | `ProcessAction` | *net-derived* (below) | *net-derived* (below) |
//! | model / agent (any LLM backend) | `ProcessAction` | `Nondeterministic` | `DurableActivity` |
//! | *main-resolved wait* — `sleep()`, a `parallel()` join | `WaitForInput` | `Nondeterministic` | `None` (R2) |
//! | *main-resolved invocation* — `subworkflow()` (`Invoke`) | `WaitForInput` | `Nondeterministic` | `None` (R2) |
//! | *main-resolved read* — `memory_snapshot()` | `WaitForInput` | `Nondeterministic` | `None` (R2) |
//!
//! The three main-resolved rows are decided by the stage's PAYLOAD
//! ([`StagePayload`]), before the executor is read: a sleep, a join and a
//! memory snapshot still carry the inert `shell`/`:` op the frontend's defaults
//! give them, and a subworkflow the `any` agent, but the main resolves each
//! in-process — from a committed timer, its joined inputs, the child
//! execution's terminal publication, its own memory store — and never runs that
//! op, so its class is R2's base row in full
//! ([`CheckedExecutionClass::MAIN_RESOLVED_WAIT`]) whatever its op or sandbox
//! say. The op and the materialized sandbox are still CARRIED, inert; lowering
//! a main-resolved stage to carry neither would need a checked-program schema
//! bump.
//!
//! The two `workspace_effect` rows are the exact-tuple op-gated admissions
//! ([`CheckedExecutionClass::ADMISSION_RECORDED_LOCAL_MUTATION`],
//! [`CheckedExecutionClass::ADMISSION_ADAPTER_ISSUANCE`]):
//! admission 1 (`PureTransform + Deterministic + InProcess + MutableCandidate +
//! Offline + None + RecomputeAllowed`) under a workspace-provider op; admission 2
//! (`ProcessAction + Nondeterministic + InProcess + None + Unrestricted +
//! DurableActivity + ReconcileRequired`) under the forge-land adapter op — the
//! candidate binds as a tree-id INPUT (`workspace = None`), never a held grant.
//!
//! ## Sandbox exec brand + net → containment / network (shell & model)
//!
//! | Sandbox | containment | network |
//! |---|---|---|
//! | none authored — MATERIALIZED at lowering ([`materialize_sandbox`]) | `Contained` | `Offline` for `shell`, `Unrestricted` for a model |
//! | `exec = oci`, `net = offline` | `Contained` | `Offline` for `shell`, `Unrestricted` for a model |
//! | `exec = oci`, `net = host` | `Contained` | `Unrestricted` |
//! | `sandbox = "host"` (`exec = host`) | `HostUnconfined` | *net-derived* (a model: `Unrestricted`) |
//! | named ref, unresolved | `HostUnconfined` | `Unrestricted` |
//!
//! A MODEL stage's network is `Unrestricted` under either `net`: its turn talks
//! to its model provider from the process hosting the worker whatever its
//! capsule may reach, so `Offline` ("construction removes network") would be a
//! guarantee the stage does not get. What a given node's capsule gets is its
//! node-resolved posture
//! (`kata_types::execution_contract::CapsuleNetworkPosture`) — `kata check`'s
//! preflight and the execution record state it.
//!
//! There is no "none declared" row. A process stage (`shell` or model)
//! that authors no `sandbox=` is lowered to an EXPLICIT inline
//! [`SandboxProfile::confined_default`] by [`materialize_sandbox`] BEFORE the
//! class is derived, so no durable stage ever carries `None` on a process
//! executor; the only stages that carry `None` are the in-process
//! `workspace_effect` ones, whose class is a constant admission tuple that
//! reads no sandbox at all. [`derive_execution_class_from_parts`] therefore
//! REFUSES a process stage handed `None` ([`UnmaterializedSandbox`]) rather
//! than reading it as host-unconfined.
//!
//! Containment DERIVATION reads the brand alone: it says what containment the
//! stage asks for; whether THIS build can deliver it (`oci` off Linux cannot) is
//! the separate question `ExecBackend::provider_posture()` answers.
//!
//! ## No ambient input
//!
//! The derivation reads only the stage's authored parts — never the
//! environment. Under the one engine no containment-defeat lever has a reader,
//! so folding the class on one would refuse more than any mechanism enforces.
//!
//! Containment follows the `exec` BRAND, not mere sandbox presence. Only a
//! real container runtime (`oci`) certifies `Contained`;
//! `exec = "host"` runs with full ambient host authority and certifies nothing,
//! so it derives `HostUnconfined` even under a declared fs/net policy. The
//! declared fs/net still drive the workspace/network axes — so a `host` profile
//! LABELLED `workspace-ro`/`offline` derives ReadOnly/Offline against a
//! HostUnconfined containment and is then refused at load (R7/R8 require
//! `Contained`; R6 forbids Offline under `HostUnconfined`): an unenforced
//! containment/ro/offline label is a lie. The brand itself stays out-of-hash
//! placement; it is the derived containment AXIS that is hashed.
//!
//! ## Filesystem policy → workspace axis (whenever a policy is declared)
//!
//! Applies whenever a filesystem policy is declared — under `Contained`
//! (`oci`) OR under a declared `HostUnconfined` (`exec = host`);
//! only the no-sandbox / unresolved case (no declared policy) skips it.
//!
//! | `FsPolicy` | workspace |
//! |---|---|
//! | `Scratch` | `None` (the canonical empty tree, its delta never applied — vacuous closure) |
//! | `WorkspaceRo` | `ReadOnly` |
//! | `WorkspaceRw`, deterministic ∧ output closure BOUND | `DeclaredOutputs` |
//! | `WorkspaceRw`, otherwise | `MutableCandidate` (a writable tree nobody bounded) |
//! | `Host` | `MutableCandidate` (writes host state) |
//! | `Custom`, all mounts read-only | `ReadOnly` |
//! | `Custom`, any writable, deterministic ∧ bound | `DeclaredOutputs` |
//! | `Custom`, any writable, otherwise | `MutableCandidate` |
//! | *no sandbox / unresolved* (`HostUnconfined`) | `MutableCandidate` |
//!
//! "output closure BOUND" is the two-part conjunct
//! [`workspace_from_fs`] takes as `write_closure_bound`: the stage DECLARES a
//! non-empty `produces_files=` closure AND the resolved backend
//! ([`kata_types::sandbox::ExecBackend::enforces_declared_write_closure`])
//! turns that declaration into an installed bound.
//!
//! [`kata_types::sandbox::ExecBackend::enforces_declared_write_closure`]
//! answers `true` for [`kata_types::sandbox::ExecBackend::Oci`] (`Host` stays
//! `false`), earned rather than asserted — the capsule route's
//! adoption judge (`Dispatcher::judge_work_delta_scope`) refuses any `/work`
//! delta outside the declared closure (`work_delta_out_of_scope`). So the
//! first `DeclaredOutputs` row (`WorkspaceRw`) is reachable for a stage that
//! is `exec="oci"`, `net="offline"`, deterministic, AND declares a
//! non-empty `produces_files=` closure —
//! `workflows/smoke/sandbox-smoke-shell-write-closure.star` is the shipped
//! worked example.
//!
//! `fs = workspace-rw` and `Deterministic` ALONE never mint `DeclaredOutputs`:
//! [`kata_types::execution_class::Workspace::DeclaredOutputs`] means *"a
//! certified provider **enforces and captures** the output set"*, and the class
//! is content-cache eligible, so claiming it where nothing enforces the set
//! would collapse two dispatches that wrote different trees onto one cache key.
//! The rule is the CONJUNCTION — writable filesystem ∧ deterministic ∧ the
//! stage DECLARES an output closure ∧ the resolved backend ENFORCES one — with
//! `MutableCandidate` (a writable tree nobody bounded, refused the content
//! cache) everywhere the conjunction fails. `derive_execution_class_from_parts`
//! therefore takes the stage's `produces_files` closure as an argument.
//!
//! Confinement does not follow cacheability:
//! `ExecutionProgramStage::should_confine_to_declared_inputs` reads
//! `class_needs_no_ambient_host_input` — the same six axes MINUS the workspace
//! one — so demoting a stage to `MutableCandidate` costs it cache eligibility
//! and never its confinement. See
//! [`ExecutionProgramStage::should_confine_to_declared_inputs`]'s own doc.
//!
//! A model editor with `workspace-rw` is `MutableCandidate` (the
//! candidate-editor tuple). That split is what keeps
//! `is_content_cache_eligible` ≡ `is_content_cacheable` on the shipped hermetic
//! packs while a model editor stays never-cacheable.
//!
//! ## Determinism (shell only)
//!
//! A `shell` executor is `Deterministic` iff it is `Contained`, `Offline`, and
//! its filesystem does not reach the host. A `shell` reaching a live network
//! (`net = host` → `Unrestricted`) or with no sandbox (`HostUnconfined`) is
//! `Nondeterministic` and carries a `DurableActivity`-class recovery posture:
//! the closed-world matrix forbids `Deterministic + Unrestricted`, so an
//! outbound `curl` under `net = host` is never blindly re-executed mid-crash.
//! Model executors
//! are always `Nondeterministic`.
//!
//! ## Pre-commit recovery
//!
//! | issuance | executor | recovery |
//! |---|---|---|
//! | `None` | any | `RecomputeAllowed` |
//! | `DurableActivity` | model | `ReconcileRequired` (today the attempt's terminal verdict decides a redo; ADR 0002) |
//! | `DurableActivity` | shell (`net = host` / host-unconfined) | `ManualResolution` (no adapter observation contract) |
//! | admission 1 (park/promote/commit) | — | `RecomputeAllowed` |
//! | admission 2 (forge land) | — | `ReconcileRequired` |

use std::collections::BTreeMap;
use std::fmt;

use kata_types::agent::is_deterministic_agent_label;
use kata_types::execution_class::{
    CheckedExecutionClass, CheckedOpContext, ClassRefusal, Computation, Containment, Determinism,
    ExternalIssuance, Network, PreCommitRecovery, Workspace,
};
use kata_types::sandbox::{ExecBackend, FsPolicy, NetPolicy, SandboxProfile, SandboxRef};
use kata_types::workflow::{
    StageId, SynthesizedStage, WORKSPACE_EFFECT_AGENT_LABEL, WorkspaceEffect, WorkspaceEffectOp,
};

use super::{ExecutionProgram, ExecutionProgramStage, ExecutionStageOp};

/// A stage's derived seven-axis class together with the op
/// discriminator it must be [`validate`](CheckedExecutionClass::validate)d
/// against. Both are compile-local — neither is persisted or hashed.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct DerivedExecutionClass {
    /// The seven orthogonal semantic axes.
    pub class: CheckedExecutionClass,
    /// The checked-operation discriminator gating the op-gated admissions.
    pub op: CheckedOpContext,
}

impl DerivedExecutionClass {
    /// Verify the derived class against the closed-world matrix under its op.
    /// Every shipped-pack stage MUST derive a valid tuple.
    pub fn validate(self) -> Result<(), kata_types::execution_class::ClassRefusal> {
        self.class.validate(self.op)
    }
}

/// The resolved executor family a stage routes to.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Executor {
    /// A deterministic `shell` command executor.
    Shell,
    /// An opaque model/agent (LLM) call.
    Model,
    /// The in-process main-owned `workspace_effect` backend, park/promote/commit.
    WorkspaceMutation(WorkspaceEffectOp),
    /// The in-process main-owned `workspace_effect` forge `land`/export.
    ForgeExport,
}

/// The resolved sandbox posture for a shell/model stage.
enum SandboxResolution {
    /// A named profile that does not resolve — host-unconfined, assuming the
    /// worst. (An ABSENT sandbox is not a member: lowering
    /// materializes one, and [`resolve_sandbox`] takes the
    /// reference by value rather than as an `Option`.)
    HostUnconfined,
    /// A declared, resolved sandbox with an exec brand, filesystem, and network
    /// policy. `exec` is read to decide containment: only a real container
    /// runtime (`oci`) certifies `Contained`; `exec = "host"`
    /// certifies nothing and derives `HostUnconfined`.
    Declared {
        exec: ExecBackend,
        fs: FsPolicy,
        net: NetPolicy,
    },
}

/// What a stage's own payload IS, as the class derivation reads it: the stage's
/// op, or a MAIN-RESOLVED operation that never runs one.
///
/// A durable `sleep()`, a `parallel()` join barrier, a `subworkflow()` and a
/// `memory_snapshot()` carry the frontend's inert defaults (`shell`/`:` for the
/// first two and the snapshot, the `any` agent for a subworkflow), but the
/// runtime lowers them to `RuntimeOperation::Wait` / `::Join` / `::Invoke` /
/// `::MemorySnapshot` and the main resolves each from a committed fact — a
/// timer, the joined inputs, the child's terminal publication, its own memory
/// store (`runner::dispatch::main_resolved`). Reading their class off that op
/// would call them `ProcessAction`s — the shape a worker runs — which is what
/// R2's `WaitForInput` row exists to say they are not.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum StagePayload {
    /// The stage's op is what runs: a shell/model process or an in-process
    /// workspace effect, classified by [`classify_executor`].
    Op,
    /// A durable sleep, a join barrier, a subworkflow invocation or a memory
    /// snapshot, resolved by the main.
    MainResolved,
}

/// The four routing markers [`StagePayload::of`] reads, named so neither call
/// site can hand them over in the wrong order. Both the authored
/// `StageDefinition` and the assembled [`ExecutionProgramStage`] carry each one.
#[derive(Clone, Copy, Debug)]
pub(crate) struct PayloadMarkers {
    pub(crate) durable_sleep: bool,
    pub(crate) synthesized: Option<SynthesizedStage>,
    pub(crate) subworkflow: bool,
    pub(crate) memory_snapshot: bool,
}

impl StagePayload {
    /// The ONE reading of the markers that make a stage main-resolved, shared by
    /// the lowering (which holds the authored definition) and every
    /// assembled-stage caller ([`Self::of_stage`]). Each caller fills
    /// [`PayloadMarkers`] from its own struct, so the two could still disagree by
    /// one dropping a marker;
    /// `derived_predicates_bridge_the_stage_predicates_on_every_shipped_pack` pins that they agree,
    /// by requiring the re-derived class to equal the carried one on every shipped stage. The set
    /// is exactly the main-resolved arms of `stage_payload_operation` that run no op: `Invoke`,
    /// `Join`, `Wait`, `MemorySnapshot`.
    pub(crate) fn of(markers: PayloadMarkers) -> Self {
        let PayloadMarkers {
            durable_sleep,
            synthesized,
            subworkflow,
            memory_snapshot,
        } = markers;
        if durable_sleep
            || synthesized == Some(SynthesizedStage::ParallelJoin)
            || subworkflow
            || memory_snapshot
        {
            Self::MainResolved
        } else {
            Self::Op
        }
    }

    fn of_stage(stage: &ExecutionProgramStage) -> Self {
        Self::of(PayloadMarkers {
            durable_sleep: stage.is_durable_sleep(),
            synthesized: stage.synthesized,
            subworkflow: stage.subworkflow.is_some(),
            memory_snapshot: stage.memory_snapshot.is_some(),
        })
    }
}

/// Derive the seven-axis [`CheckedExecutionClass`] and op discriminator for a
/// checked stage. See the module-level derivation table. Thin wrapper over
/// [`derive_execution_class_from_parts`] — used by the bridge tests and any
/// caller holding a fully-assembled stage.
pub fn derive_execution_class(
    stage: &ExecutionProgramStage,
    profiles: &BTreeMap<String, SandboxProfile>,
) -> Result<DerivedExecutionClass, UnmaterializedSandbox> {
    derive_execution_class_from_parts(
        StagePayload::of_stage(stage),
        &stage.op,
        stage.policies.sandbox.as_ref(),
        profiles,
        &stage.produces_files,
    )
}

/// A process stage (`shell` or model) reached the derivation carrying NO
/// sandbox reference — the one shape lowering makes impossible for
/// anything this binary lowers, and the shape every decode door refuses
/// ([`ExecutionProgram::validate_carried_stage_execution_classes`]).
///
/// It is an error rather than a `HostUnconfined` reading because, read as
/// unconfined, a `Contained` class with no directive would be placed with no
/// sandbox and run with full ambient host authority under a key that says it
/// was confined.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UnmaterializedSandbox {
    /// The agent selector the stage routes to, for the refusal.
    pub agent: String,
}

impl fmt::Display for UnmaterializedSandbox {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "a process-spawning stage (agent {:?}) carries no sandbox directive at all. Every \
             shell/model stage is lowered \
             with an explicit sandbox — the confined default, or `sandbox = \"host\"` — so a \
             stage without one was not produced by this binary's lowering and cannot be \
             placed",
            self.agent
        )
    }
}

impl std::error::Error for UnmaterializedSandbox {}

/// MATERIALIZE the sandbox an unauthored process stage
/// runs under, ONCE, at the boundary where a pack becomes a checked program.
///
/// # The rule, by executor
///
/// * `workspace_effect` (park/promote/commit/forge export) — `authored`
///   unchanged, which is always `None`: the DSL refuses `sandbox=` on an
///   effect, and the class is an in-process admission tuple that reads no
///   sandbox.
/// * `shell` and a MODEL executor alike — `authored`, or
///   [`SandboxProfile::confined_default`]: `fs = workspace-ro`, `net =
///   offline`, exactly what `sandbox_profile()` with no arguments declares.
///   * A plain `run=` derives `Contained + Deterministic + Offline +
///     ReadOnly`, which is content-cache eligible by class. This holds because
///     `resolve_run_alias_agent` (`crates/program/src/dsl/graph_globals.rs`)
///     lowers `run=` with no `agent=` to the shell label, so a plain `run=`
///     is judged a shell, not a model executor.
///   * A model stage is `ExternalIssuance::DurableActivity`,
///     `Nondeterministic` and `Unrestricted` whatever `net` says
///     ([`derive_process_class`]), so `net` decides nothing in its class; in
///     the capsule it decides only whether the node's `[node] egress_allow`
///     is reached (`capsule_rules::capsule_network_for`). The default leaves
///     the node's egress out: a model stage reaches it only by authoring `net
///     = "host"`. Because the class is `Nondeterministic`,
///     `should_confine_to_declared_inputs` is `false`, so the toolchain-only
///     `PATH` / no-`$HOME` arm that would strip the agent CLI is never
///     selected for it.
///
/// # Why here and not late
///
/// The sandbox is not resolved at dispatch, the way the node-default root is:
/// the root is a MACHINE fact a frozen IR may not name, the posture is an
/// AUTHORED one. Left `None`, the
/// same durable program would mean different things on different kata builds,
/// which is a stage-identity rotation wearing a default's clothes.
#[must_use]
pub(crate) fn materialize_sandbox(
    op: &ExecutionStageOp,
    authored: Option<SandboxRef>,
) -> Option<SandboxRef> {
    match classify_executor(op) {
        Executor::WorkspaceMutation(_) | Executor::ForgeExport => authored,
        Executor::Shell | Executor::Model => {
            Some(authored.unwrap_or_else(|| {
                SandboxRef::Inline(Box::new(SandboxProfile::confined_default()))
            }))
        }
    }
}

/// The op discriminator a stage is judged under. Compile-local, never
/// persisted, and a function of the stage's OPERATION alone — it reads no
/// sandbox, which is why the decode doors can recover it for any stage,
/// including one whose sandbox they are about to refuse.
#[must_use]
pub(crate) fn derive_op_context(op: &ExecutionStageOp) -> CheckedOpContext {
    match classify_executor(op) {
        Executor::WorkspaceMutation(effect_op) => workspace_provider_op(effect_op),
        Executor::ForgeExport => CheckedOpContext::ForgeLand,
        Executor::Shell | Executor::Model => CheckedOpContext::Standard,
    }
}

/// Derive the seven-axis class from the raw authored PARTS — the stage's op, its
/// declared sandbox reference, and its declared output closure — BEFORE an
/// [`ExecutionProgramStage`] is assembled. This is the lowering construction
/// site's entry: the class is derived here and folded into the stage's contract
/// hash, so it cannot depend on a stage that does not yet exist. The class is a
/// pure function of exactly these inputs (the same executor + sandbox + output
/// closure the verdict predicates read), so the `&ExecutionProgramStage` wrapper
/// is behavior-identical.
///
/// # `produces_files` is a PARAMETER, not a `bool`, and that is deliberate
///
/// The workspace axis depends on whether the stage
/// declares an output closure. The derivation needs only the closure's
/// EMPTINESS today, so a boolean parameter would compile — and would move
/// the summarisation to the two call sites, where a caller can summarise it
/// wrongly and nothing catches it. Handing over the set itself makes that
/// failure inexpressible, and it is the set a tighter future rule (a closure
/// that must RESOLVE, a closure the provider echoes back) will need anyway.
///
/// # `sandbox` is an `Option` only because an effect stage has none
///
/// A process executor handed `None` is REFUSED ([`UnmaterializedSandbox`]):
/// the lowering materializes a sandbox for every process stage before this is
/// called ([`materialize_sandbox`]), and the decode doors refuse a durable
/// stage that lacks one, so the `Err` is unreachable from either — which is the
/// point of making it an error rather than a reading.
pub(crate) fn derive_execution_class_from_parts(
    payload: StagePayload,
    op: &ExecutionStageOp,
    sandbox: Option<&SandboxRef>,
    profiles: &BTreeMap<String, SandboxProfile>,
    produces_files: &[smol_str::SmolStr],
) -> Result<DerivedExecutionClass, UnmaterializedSandbox> {
    if payload == StagePayload::MainResolved {
        return Ok(DerivedExecutionClass {
            class: CheckedExecutionClass::MAIN_RESOLVED_WAIT,
            op: CheckedOpContext::Standard,
        });
    }
    Ok(match classify_executor(op) {
        Executor::WorkspaceMutation(effect_op) => DerivedExecutionClass {
            class: CheckedExecutionClass::ADMISSION_RECORDED_LOCAL_MUTATION,
            op: workspace_provider_op(effect_op),
        },
        Executor::ForgeExport => DerivedExecutionClass {
            class: CheckedExecutionClass::ADMISSION_ADAPTER_ISSUANCE,
            op: CheckedOpContext::ForgeLand,
        },
        executor @ (Executor::Shell | Executor::Model) => {
            let Some(sandbox) = sandbox else {
                return Err(UnmaterializedSandbox {
                    agent: op.agent.to_string(),
                });
            };
            DerivedExecutionClass {
                class: derive_process_class(
                    executor,
                    resolve_sandbox(sandbox, profiles),
                    produces_files,
                ),
                op: CheckedOpContext::Standard,
            }
        }
    })
}

/// True iff this stage's resolved executor is an opaque **model/agent** call —
/// neither the deterministic `shell` command executor nor the in-process
/// main-owned `workspace_effect` backend.
///
/// This is the executor-identity question, and it delegates to
/// [`classify_executor`] — the SAME function the seven-axis derivation routes
/// on — so there is exactly one definition of "model stage" in the crate. It is
/// deliberately NOT a second reading of the agent label: a label read as an
/// approximation of a CLASS property disagrees with the class
/// for authorable configurations. Here the label is not approximating a class
/// property; "which executor does this stage route to" is the label's own
/// meaning, and the class cannot answer it (a `net = "host"` shell and a model
/// call derive the same `ProcessAction + Nondeterministic` axes).
#[must_use]
pub fn stage_executor_is_model(stage: &ExecutionProgramStage) -> bool {
    matches!(classify_executor(&stage.op), Executor::Model)
}

/// True iff this stage routes to the in-process, main-owned `workspace_effect`
/// backend.
///
/// The ONE public reading of that question, delegating to the same
/// [`op_is_workspace_effect`] predicate [`classify_executor`] uses — a second
/// hand-written label check is exactly the drift this crate has already paid for.
#[must_use]
pub fn stage_routes_to_workspace_effect(stage: &ExecutionProgramStage) -> bool {
    op_is_workspace_effect(&stage.op)
}

/// Classify a stage's resolved executor from its op. The in-process
/// `workspace_effect` backend is detected by the canonical agent-label
/// predicate [`op_is_workspace_effect`]; its sub-operation is recovered from the checked
/// directive prompt so forge `land` (admission 2) is distinguished from
/// candidate mutation (admission 1).
fn classify_executor(op: &ExecutionStageOp) -> Executor {
    if op_is_workspace_effect(op) {
        // A workspace_effect stage carries its op in the checked directive
        // prompt (`WorkspaceEffect::directive_prompt` round-trips through
        // `from_directive_prompt`). An unparseable prompt conservatively falls
        // back to a candidate mutation (admission 1), never to adapter issuance.
        return match WorkspaceEffect::from_directive_prompt(&op.prompt_template) {
            Some(effect) if effect.op == WorkspaceEffectOp::ForgeExport => Executor::ForgeExport,
            Some(effect) => Executor::WorkspaceMutation(effect.op),
            None => Executor::WorkspaceMutation(WorkspaceEffectOp::Park),
        };
    }
    if op_is_deterministic_executor(op) {
        Executor::Shell
    } else {
        Executor::Model
    }
}

/// True iff `op` routes to the in-process, main-owned `WorkspaceEffect` backend:
/// its label is the canonical [`WORKSPACE_EFFECT_AGENT_LABEL`].
fn op_is_workspace_effect(op: &ExecutionStageOp) -> bool {
    op.agent_label.as_deref() == Some(WORKSPACE_EFFECT_AGENT_LABEL)
        || op.agent.as_str() == WORKSPACE_EFFECT_AGENT_LABEL
}

/// True iff `op` routes to a deterministic command executor (shell), not an LLM
/// agent. Mirrors [`ExecutionProgramStage::is_deterministic_executor`]'s label
/// check against the same canonical [`is_deterministic_agent_label`].
fn op_is_deterministic_executor(op: &ExecutionStageOp) -> bool {
    op.agent_label
        .as_deref()
        .is_some_and(is_deterministic_agent_label)
        || is_deterministic_agent_label(op.agent.as_str())
}

/// Map a candidate workspace-provider op onto the admission-1 op discriminator.
fn workspace_provider_op(op: WorkspaceEffectOp) -> CheckedOpContext {
    match op {
        WorkspaceEffectOp::Promote => CheckedOpContext::WorkspacePromote,
        WorkspaceEffectOp::Commit => CheckedOpContext::WorkspaceCommit,
        // ForgeExport never reaches here (it is routed to Executor::ForgeExport
        // before this call); it shares Park's arm only as an exhaustive fallback.
        WorkspaceEffectOp::Park | WorkspaceEffectOp::ForgeExport => CheckedOpContext::WorkspacePark,
    }
}

/// Resolve a stage's sandbox reference to its exec brand, filesystem and
/// network policy, or host-unconfined when a NAMED profile does not resolve.
///
/// There is no `None => HostUnconfined` arm: an unauthored sandbox is
/// materialized at lowering ([`materialize_sandbox`]) and never reaches a
/// derivation as `None`, and a defensive branch nothing can enter is the kind
/// of code a reader trusts and a flip then silently re-activates. The one
/// `HostUnconfined` reading — an unresolved NAME — is a real condition
/// (`parser::validate` refuses it for an authored pack; a decoded program can
/// still carry one).
fn resolve_sandbox(
    sandbox: &SandboxRef,
    profiles: &BTreeMap<String, SandboxProfile>,
) -> SandboxResolution {
    let profile = match sandbox {
        SandboxRef::Inline(profile) => Some(profile.as_ref()),
        SandboxRef::Named(name) => profiles.get(name),
    };
    match profile {
        Some(profile) => SandboxResolution::Declared {
            exec: profile.exec.clone(),
            fs: profile.fs.clone(),
            net: profile.net.clone(),
        },
        // An unresolved named profile is treated conservatively as
        // host-unconfined, assuming the worst.
        None => SandboxResolution::HostUnconfined,
    }
}

/// Derive the class for a `shell` or `model` [`Computation::ProcessAction`]
/// stage from its resolved sandbox posture.
fn derive_process_class(
    executor: Executor,
    resolution: SandboxResolution,
    produces_files: &[smol_str::SmolStr],
) -> CheckedExecutionClass {
    let is_model = matches!(executor, Executor::Model);

    let (containment, network, fs, write_closure_bound) = match resolution {
        SandboxResolution::HostUnconfined => (
            Containment::HostUnconfined,
            Network::Unrestricted,
            None,
            // An unresolved named profile resolves no provider, so there is
            // nothing that could install a bound whatever the stage declared.
            false,
        ),
        SandboxResolution::Declared { exec, fs, net } => {
            // A MODEL stage's network is never `Offline` here, whatever `net`
            // says: its turn talks to its model provider from the process
            // hosting the worker. `Unrestricted` claims nothing; the
            // node-resolved posture is the capsule's own
            // (`CapsuleNetworkPosture`).
            let network = match net {
                NetPolicy::Offline if !is_model => Network::Offline,
                NetPolicy::Offline | NetPolicy::Host => Network::Unrestricted,
            };
            // The two halves of "the output set is
            // BOUND", asked of the two authorities that own them: the STAGE
            // (did it declare a closure at all?) and the resolved BACKEND (does
            // the runtime this build resolves for it turn that declaration into
            // an installed write-confinement?). Both must answer yes before the
            // workspace axis may claim `DeclaredOutputs`, whose own definition
            // is "a certified provider enforces and captures the output set".
            //
            // FAILS CLOSED on purpose: an unbounded write set derives
            // `MutableCandidate`, which is never content-cache eligible. A
            // missing bound then costs a cache miss; a claimed-but-absent bound
            // would collapse two dispatches that wrote DIFFERENT trees onto one
            // key and serve the second the first's result.
            let write_closure_bound =
                !produces_files.is_empty() && exec.enforces_declared_write_closure();
            // Containment follows the exec BRAND, not mere sandbox
            // presence. Only a real container runtime certifies `Contained`;
            // `exec = "host"` runs with full ambient host authority and can
            // certify NOTHING, so it derives `HostUnconfined` even though a
            // filesystem/network POLICY is declared. The declared fs/net still
            // drive the workspace/network axes below — so a `host` profile that
            // LABELS `workspace-ro`/`offline` derives ReadOnly/Offline against a
            // HostUnconfined containment and is then refused by the closed-world
            // matrix (R7/R8 require Contained; R6 forbids Offline under
            // HostUnconfined): an unenforced containment/ro/offline label is a
            // lie, and refusing it is correct.
            let containment = match exec {
                ExecBackend::Host => Containment::HostUnconfined,
                ExecBackend::Oci => Containment::Contained,
            };
            (containment, network, Some(fs), write_closure_bound)
        }
    };

    // Determinism: only a shell that is contained, offline, and does not
    // reach the host filesystem is deterministic. A host-unconfined shell (no
    // sandbox OR exec="host") is never deterministic; model calls never are.
    // `FsPolicy::reaches_host_state` owns this question, exhaustively —
    // including `FsPolicy::Custom` (a custom mount of `/` reaches host state).
    let fs_reaches_host = fs.as_ref().is_some_and(FsPolicy::reaches_host_state);
    let determinism = if !is_model
        && containment == Containment::Contained
        && network == Network::Offline
        && !fs_reaches_host
    {
        Determinism::Deterministic
    } else {
        Determinism::Nondeterministic
    };

    // The workspace axis follows the DECLARED filesystem policy whenever one is
    // present, regardless of containment — a `host`-exec profile that declares
    // `workspace-ro` derives ReadOnly (then R7-refused), and one that declares
    // `scratch` derives None (a valid HostUnconfined+scratch stage that still
    // mutates the host). Only the no-sandbox / unresolved case (fs = None) has
    // no declared policy and defaults conservatively to the mutating candidate.
    let workspace = match &fs {
        Some(fs) => workspace_from_fs(fs, determinism, write_closure_bound),
        None => Workspace::MutableCandidate,
    };

    // Issuance: an effect can escape through a model, or through any live
    // (non-offline) network. A hermetic offline shell issues nothing.
    let external_issuance = if is_model || network != Network::Offline {
        ExternalIssuance::DurableActivity
    } else {
        ExternalIssuance::None
    };

    let pre_commit_recovery = match external_issuance {
        ExternalIssuance::None => PreCommitRecovery::RecomputeAllowed,
        // A model call is classed ReconcileRequired: whether a lost attempt may be
        // redone is decided from its recorded terminal verdict (no per-adapter
        // observation policy exists yet; ADR 0002). An opaque host-unconfined /
        // net=host shell has no adapter observation contract, so its ambiguity
        // needs operator resolution.
        ExternalIssuance::DurableActivity if is_model => PreCommitRecovery::ReconcileRequired,
        ExternalIssuance::DurableActivity => PreCommitRecovery::ManualResolution,
    };

    CheckedExecutionClass {
        computation: Computation::ProcessAction,
        determinism,
        containment,
        workspace,
        network,
        external_issuance,
        pre_commit_recovery,
    }
}

/// Map a resolved filesystem policy onto the workspace axis.
///
/// A writable filesystem is [`Workspace::DeclaredOutputs`] only when the stage
/// is `Deterministic` AND its output set is BOUND (`write_closure_bound`);
/// otherwise it is [`Workspace::MutableCandidate`] — a writable tree nobody
/// bounded, never content-cache eligible.
///
/// # Why `determinism` alone is not enough
///
/// The axis `DeclaredOutputs` MEANS "a certified provider enforces and captures
/// the output set" and is content-cache eligible, so a writable arm keyed on
/// `determinism` ALONE would let a hermetic build stage carry a bound nothing
/// installed. `write_closure_bound` is the missing conjunction — the stage
/// declared an output closure (`ExecutionProgramStage::produces_files`) AND the
/// resolved provider bounds writes to one
/// ([`kata_types::sandbox::ExecBackend::enforces_declared_write_closure`]) —
/// computed once in [`derive_process_class`] from the two authorities that own
/// its halves. It is `true` for a stage on an `oci` profile that declares a
/// non-empty `produces_files=` closure: the capsule route's adoption judge
/// (`Dispatcher::judge_work_delta_scope`, `work_delta_out_of_scope`) earns the
/// `oci` answer by refusing any `/work` delta outside the closure. The DECODE
/// door's admission-by-contract is unaffected either way.
///
/// # Confinement does not ride on this axis
///
/// `ExecutionProgramStage::should_confine_to_declared_inputs` reads the
/// cacheability conjunction MINUS the workspace clause, which is strictly WIDER
/// over the closed-world matrix by exactly one tuple: `ProcessAction +
/// Deterministic + Contained + MutableCandidate + Offline + issuance None +
/// RecomputeAllowed` — precisely the tuple an unbounded writable deterministic
/// stage derives here. So a stage that is `MutableCandidate` loses content-cache
/// eligibility and KEEPS confinement;
/// [`confinement_is_decided_without_the_workspace_axis_over_the_whole_derivation`](tests)
/// (`crates/program/src/execution_program/execution_class_tests.rs`) pins that
/// over the whole derivation.
///
/// A stage that wants `DeclaredOutputs` has to declare its outputs AND run on a
/// provider that enforces them.
fn workspace_from_fs(
    fs: &FsPolicy,
    determinism: Determinism,
    write_closure_bound: bool,
) -> Workspace {
    let writable_workspace = |det: Determinism| match det {
        Determinism::Deterministic if write_closure_bound => Workspace::DeclaredOutputs,
        Determinism::Deterministic | Determinism::Nondeterministic => Workspace::MutableCandidate,
    };
    match fs {
        FsPolicy::Scratch => Workspace::None,
        FsPolicy::WorkspaceRo => Workspace::ReadOnly,
        FsPolicy::WorkspaceRw => writable_workspace(determinism),
        FsPolicy::Host => Workspace::MutableCandidate,
        FsPolicy::Custom { mounts } => {
            if mounts.iter().any(|mount| mount.writable) {
                writable_workspace(determinism)
            } else {
                Workspace::ReadOnly
            }
        }
    }
}

// ---------------------------------------------------------------------------
// The ONE seven-axis validity gate
// ---------------------------------------------------------------------------

/// One stage whose CARRIED seven-axis class the closed-world matrix
/// refuses.
///
/// Typed rather than stringly because the two kinds of caller need different
/// closing advice over the same finding: the compiler's reader has the `.star`
/// in front of them and can change it; the durable decoder's reader has only a
/// blob written by some other binary and cannot.
///
/// The COMPLETE tuple rides on the refusal, not just the first conflicting axis,
/// for the same reason. `ClassRefusal` names the rule and the one axis that trips
/// it, which is sufficient when the source is at hand; for a decoded program the
/// axes exist nowhere a reader can look them up, so the refusal has to carry
/// them.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct InvalidStageExecutionClass {
    /// The stage whose class was refused.
    pub stage_id: StageId,
    /// The exact tuple the stage carries.
    pub class: CheckedExecutionClass,
    /// The op discriminator it was judged under (re-derived; never persisted).
    pub op: CheckedOpContext,
    /// The first conflicting matrix row, with its stable `R*` code and axis.
    pub refusal: ClassRefusal,
}

impl fmt::Display for InvalidStageExecutionClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "stage \"{}\" has an invalid checked execution class — {}. The tuple it carries is \
             computation={}, determinism={}, containment={}, workspace={}, network={}, \
             external_issuance={}, pre_commit_recovery={}, judged under checked op {}.",
            self.stage_id.0,
            self.refusal,
            self.class.computation.label(),
            self.class.determinism.label(),
            self.class.containment.label(),
            self.class.workspace.label(),
            self.class.network.label(),
            self.class.external_issuance.label(),
            self.class.pre_commit_recovery.label(),
            self.op.label(),
        )
    }
}

impl std::error::Error for InvalidStageExecutionClass {}

/// The operator recourse appended when a DURABLE checked program is refused by
/// [`ExecutionProgram::validate_carried_stage_execution_classes`].
///
/// One constant rather than a string per door, so an operator gets the same
/// instruction whichever decode door refused, and so the two doors cannot drift
/// into describing the same condition differently.
pub const DURABLE_EXECUTION_CLASS_REFUSAL_RECOURSE: &str = "A checked program is validated at COMPILE and again HERE, at the boundary that turns durable \
     bytes back into an executable program. These bytes therefore came from a binary whose \
     derivation or closed-world matrix differed from this one's, and the axes they record are ones \
     this binary cannot honour. The bytes stay readable evidence — inspect them, or finish/cancel \
     the execution with the binary that wrote them.";

impl ExecutionProgram {
    /// Refuse any stage whose CARRIED seven-axis class is not a valid
    /// closed-world tuple under the checked op its operation implies.
    ///
    /// This is the single implementation of the rule that invalid combinations
    /// fail in compile/preflight before a run is created, and every caller in
    /// the workspace routes through it. A second
    /// copy is worse than none: two validators that can disagree turn a refusal
    /// into a coin flip about which one a given path happened to reach.
    ///
    /// # Which class this validates, and why it is the carried one
    ///
    /// [`ExecutionProgramStage::execution_class`] is a hashed, durable field, and
    /// it is what the RUNTIME reads for every verdict it derives from the axes.
    /// Re-deriving the tuple here and validating THAT would check a value no
    /// dispatch decision consults — on a decoded program the two can differ, and
    /// it is the carried one that gets obeyed. So the carried one is the one that
    /// has to be valid.
    ///
    /// The op discriminator is the opposite case: [`CheckedOpContext`] is never
    /// serialized, so a decoded program cannot carry one and it is always
    /// recovered from the stage's own checked operation — the same input, through
    /// the same [`derive_execution_class`], that the compiler uses.
    ///
    /// # What this deliberately does NOT check
    ///
    /// It does not require the carried class to EQUAL today's derivation. That is
    /// a strictly different (and stronger) property, and asserting it here would
    /// refuse durable programs that are perfectly valid: the derivation can
    /// change within one schema version (containment keyed on the `exec` brand
    /// rather than sandbox presence is such a change), so a program written
    /// before such a change can carry a tuple that is valid, that the runtime can honour, and
    /// that today's derivation would no longer produce. Refusing those would
    /// strand running work to no benefit. Validity is the property that has to
    /// hold; agreement with the current derivation is not.
    ///
    /// # Where this is called
    ///
    /// At COMPILE (`compile_execution_program_with_options`) and at DECODE — the
    /// two, and only two, ways an `ExecutionProgram` comes into existence. A
    /// program that never touched durable bytes came from the compiler; one that
    /// did came through a decode door. `durable_program_decode_doors_all_validate`
    /// (`crates/workflow/tests/durable_execution_class_revalidation.rs`) pins the
    /// door list, so a third door is a test failure rather than a silent bypass.
    ///
    /// Decode is the right seam rather than the point of execution because the
    /// refusal has to land *before a run is created*, and because the
    /// alternatives are not total: `checked_admission` looks like a chokepoint but
    /// the executor's recovery path calls it only when an invocation row exists,
    /// and `WorkflowRunner::new_from_program` is after the run exists.
    ///
    /// # Failure
    ///
    /// Returns the FIRST offending stage (`stages` is a `BTreeMap`, so "first" is
    /// stage-id order and the diagnostic is deterministic for a given program).
    ///
    /// # It also refuses a process stage carrying NO sandbox
    ///
    /// Every shell/model stage is lowered with an explicit
    /// sandbox, so a durable program in which one carries `None` was not
    /// produced by this binary's lowering. Admitted on its class alone, such a
    /// program would be placed with no sandbox directive — a `Contained` class
    /// run with full ambient host authority. The check
    /// lives HERE, in the one method every door already calls, so it holds at
    /// every door by the same pin
    /// (`durable_program_decode_doors_all_validate`) rather than by a second
    /// list that could drift from the first.
    ///
    /// The refused set is exactly a stage whose payload is its OP
    /// (`StagePayload::Op`) routing to the `shell` or model executor. A
    /// main-resolved stage — a durable sleep, a join, a subworkflow, a memory
    /// snapshot — is ADMITTED without a sandbox: the runtime routes it by its
    /// marker to a main-resolved operation before any executor is consulted,
    /// so its carried sandbox is never read and nothing is placed under it.
    /// All four carry the R2 `WaitForInput` row.
    /// `a_sandbox_less_main_resolved_stage_is_admitted_and_a_sandbox_less_shell_stage_is_not`
    /// (`crates/workflow/tests/durable_execution_class_revalidation.rs`) pins
    /// both sides.
    pub fn validate_carried_stage_execution_classes(&self) -> Result<(), CarriedStageRefusal> {
        for (stage_id, stage) in &self.stages {
            // Judged under the op the OPERATION implies — recoverable for any
            // stage, including one whose sandbox is refused next.
            let op = derive_op_context(&stage.op);
            if let Err(refusal) = stage.execution_class.validate(op) {
                return Err(CarriedStageRefusal::Class(InvalidStageExecutionClass {
                    stage_id: stage_id.clone(),
                    class: stage.execution_class,
                    op,
                    refusal,
                }));
            }
            if let Err(unmaterialized) = derive_execution_class(stage, &self.sandbox_profiles) {
                return Err(CarriedStageRefusal::UnmaterializedSandbox {
                    stage_id: stage_id.clone(),
                    unmaterialized,
                });
            }
        }
        Ok(())
    }
}

/// What [`ExecutionProgram::validate_carried_stage_execution_classes`] refuses:
/// a stage whose carried class is not a closed-world tuple, or — since schema 4
/// — a process stage that carries no sandbox at all.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CarriedStageRefusal {
    /// The carried seven-axis tuple is not a valid closed-world class.
    Class(InvalidStageExecutionClass),
    /// A shell/model stage carries `policies.sandbox == None`, which no
    /// lowering produces. A main-resolved stage
    /// (sleep, join, subworkflow, memory snapshot) is never refused here: it is
    /// never placed, so it needs no sandbox.
    UnmaterializedSandbox {
        stage_id: StageId,
        unmaterialized: UnmaterializedSandbox,
    },
}

impl fmt::Display for CarriedStageRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Class(invalid) => invalid.fmt(f),
            Self::UnmaterializedSandbox {
                stage_id,
                unmaterialized,
            } => write!(f, "stage \"{}\": {unmaterialized}.", stage_id.0),
        }
    }
}

impl std::error::Error for CarriedStageRefusal {}

#[cfg(test)]
#[path = "execution_class_tests.rs"]
mod tests;
