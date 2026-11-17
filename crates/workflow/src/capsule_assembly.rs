//! CAPSULE ASSEMBLY on the main, and nothing else.
//!
//! [`assemble_capsule`] turns one lowered operation plus its checked stage,
//! resolved sandbox directive, environment, platform and work tree into the pair
//! `(PreparedAction, Capsule)`. That pair is the immutable worker input
//! `docs/architecture/0001-replacement-architecture.md` describes: content-addressed
//! references and guest paths, with no main-host path anywhere in it.
//!
//! # NOTHING HERE ISSUES
//!
//! No row is written, no CAS object is published, no attempt is claimed, no
//! occurrence is minted, and no worker is dialed. This module computes VALUES.
//! The declarations that make a capsule durable (`declare_artifact`,
//! `declare_capsule`) and the authorization that binds one to an attempt belong to
//! the operational authority and to the `authorization` module; assembling
//! ahead of them is what lets the identity be reviewed, pinned and golden-tested
//! before anything depends on it.
//!
//! # The permissions hash, and what it commits to
//!
//! `PreparedAction::permissions` is [`sandbox_permissions_hash`] over the
//! directive, with every `env` key sorted. A directive's `secret_tokens` hold only
//! [`SecretRef`](kata_types::sandbox::SecretRef) declarations — the type has no
//! plaintext form — so every `secrets=` grant reaches the hash as its non-secret
//! declaration, and two actions with different credential grants never share a
//! `PreparedActionId` or a `CapsuleId`.
//!
//! The hashed form is ASSERTED to carry no
//! `shared_filesystem_presumptions()`, as a typed refusal rather than a comment —
//! see [`sandbox_permissions_hash`]'s refused set for the exact pair, and
//! [`assemble_capsule`] for the same check on the directive as GIVEN.
//!
//! # Why the hash is taken over the serialized projection
//!
//! `kata_types::execution_contract`'s identities are field-wise on purpose. This
//! one is deliberately the opposite: it folds the projection's canonical JSON
//! (`canonicalize_args`, which sorts every object key recursively) under
//! [`hash_field`] framing, because a permissions hash must be TOTAL over the
//! directive. A field-wise fold here would silently omit any field a future author
//! adds — a new grant would not rotate the identity of the action it grants — and
//! that is the one failure this hash cannot have. The cost is that the directive's
//! serde encoding becomes load-bearing for this identity, which is why
//! `crates/workflow/tests/capsule_assembly.rs` pins the hex over a fixture
//! directive.

use kata_types::KataResult;
use kata_types::cache::hash_field;
use kata_types::execution_contract::{
    ArtifactId, ArtifactPrivacy, ArtifactRef, CAPSULE_OUTPUT_BYTES, CAPSULE_RESULT_BYTES,
    CAPSULE_RESULT_ENTRIES, CAPSULE_WORK_DELTA_BYTES, CAPSULE_WORK_DELTA_ENTRIES, Capsule,
    CapsuleBudgets, CapsuleGitView, CapsuleProcess, CapsuleWorkView, EnvironmentId, GuestAccess,
    GuestMapping, GuestPath, OccurrenceId, PlatformId, PreparedAction,
};
use kata_types::idempotency::canonicalize_args;
use kata_types::primitives::{ContentHash, FixedBytes};
use kata_types::sandbox::{FsPolicy, SandboxDirective};
use kata_types::tree_artifact::TreeManifest;
use smol_str::SmolStr;

use kata_program::capsule_rules::{
    capsule_credential, capsule_network_for, is_agent_class, is_shell_class, refused,
};
use kata_program::execution_program::{ExecutionProgramStage, LoweredOperation};

/// Domain tag for the permissions hash. Its own tag, never shared with any other
/// digest of a directive: this one names the PERMISSIONS an action was prepared
/// with, and two different projections of one directive must never be able to
/// produce one value.
const PERMISSIONS_DOMAIN: &str = "kata.capsule.permissions.v1";

/// The node-level budget defaults a capsule RECORDS.
///
/// No `Default` impl, deliberately: every construction names both values, so a
/// silently-inherited zero cannot become a budget. Both are recorded INSIDE the
/// capsule and therefore folded into `CapsuleId` — changing a node's default
/// rotates the identity of every capsule assembled after the change, which is the
/// property worth having. A capsule is a promise about the box the action runs in;
/// two capsules that share an id must not be able to differ in that box.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NodeBudgetDefaults {
    /// Memory ceiling for the whole capsule, in bytes.
    pub memory_bytes: u64,
    /// Process (pid) ceiling for the whole capsule.
    pub process_count: u32,
}

/// The CANONICAL EMPTY TREE artifact — what `/out` and `/tmp` are mapped to.
///
/// # Why an artifact and not a `GuestMapping` variant
///
/// "This directory starts empty" could have been a new `GuestAccess` or a
/// `GuestMapping` without an artifact. Both were rejected: a mapping whose
/// `artifact` is optional makes EVERY reader handle a case that carries no bytes,
/// and it breaks the one sentence the capsule contract rests on — a mapping names
/// a content-addressed artifact at a guest path. The empty tree keeps that
/// sentence total. `TreeManifest::new(vec![])` is an accepted manifest (an empty
/// output directory is a real result), its canonical bytes are fixed, so its
/// `ArtifactRef` is a CONSTANT of this build: one object, published once, mapped
/// by every capsule that needs an empty directory.
///
/// # What this function does NOT do
///
/// It does not publish those bytes. A capsule referencing an artifact the CAS does
/// not hold is refused at materialization by name, and making the reference
/// resolvable is the issuing path's obligation (publish the manifest once, declare
/// the artifact) — not this non-issuing module's.
///
/// Privacy is `Public`: the bytes are an empty list, identical on every node, and
/// classifying the absence of content as private would claim a protection with no
/// content to protect.
pub fn empty_tree_artifact() -> KataResult<ArtifactRef> {
    let bytes = TreeManifest::new(Vec::new())?.manifest_bytes()?;
    Ok(ArtifactRef::new(
        kata_types::cache::object_id_for_canonical_bytes(&bytes),
        bytes.len() as u64,
        ArtifactPrivacy::Public,
    ))
}

/// The PERMISSIONS half of a prepared action's identity.
///
/// # Failure — the refused set, stated exactly
///
/// Two things, and nothing else:
///
/// 1. a directive whose `SandboxDirective::shared_filesystem_presumptions()` is
///    non-empty — the refusal names the WIRE POINTER rather than the field, so a
///    carrier added later is reported by the inventory that found it (no field
///    carries one today);
/// 2. a directive that does not serialize — not a policy refusal but a broken
///    type, reported rather than hashed around.
///
/// A merely PERMISSIVE directive (`FsPolicy::Host`, `NetPolicy::Host`) hashes
/// fine: this function computes an identity and does not adjudicate policy.
pub fn sandbox_permissions_hash(directive: &SandboxDirective) -> KataResult<ContentHash> {
    let presumptions = directive.shared_filesystem_presumptions();
    if !presumptions.is_empty() {
        let carriers = presumptions
            .iter()
            .map(|presumption| presumption.wire_pointer.to_string())
            .collect::<Vec<_>>()
            .join(", ");
        return Err(refused(&format!(
            "the directive presumes the main's filesystem at [{carriers}]. A capsule addresses \
             content, so a main-resolved path in the hashed form would make one action identity \
             mean different bytes on two nodes"
        )));
    }

    let value = serde_json::to_value(directive).map_err(|error| {
        refused(&format!(
            "the projected sandbox directive does not serialize: {error}"
        ))
    })?;
    let mut hasher = blake3::Hasher::new();
    hash_field(&mut hasher, PERMISSIONS_DOMAIN, &[]);
    hash_field(&mut hasher, "directive", &canonicalize_args(&value));
    Ok(FixedBytes(*hasher.finalize().as_bytes()))
}

/// A stage command that HAS BEEN RENDERED — the text a shell will actually run.
///
/// # Why a newtype, and what it is a witness for
///
/// [`assemble_capsule`] folds this text into `CapsuleId`, so it must be the bytes the
/// container executes and not the template they came from. Both are `String`, and
/// `stage.op.prompt_template` is in scope at every call site — so a plain `&str`
/// parameter accepts the one value that is WRONG in a way nothing downstream can
/// detect: a capsule whose id commits to `echo {{ stages.build.parsed.name }}` is
/// internally consistent, declares, dispatches, and runs a stage that prints a jinja
/// expression.
///
/// The newtype does not verify anything — it cannot; a rendered command and a template
/// that happens to contain no placeholders are the same bytes. What it does is make the
/// obligation NAMED at the one door where it is discharged, so passing an unrendered
/// template is a deliberate act with the obligation's own words on it rather than an
/// argument in the right position.
///
/// # The one constructor
///
/// [`RenderedCommand::rendered`], and its contract is that the caller has already run
/// the stage's prompt through the ONE renderer this workspace has —
/// `WorkflowRunner::render_checked_prompt`, which dispatches on
/// `ExecutionPromptRendering` and applies the strict minijinja runtime context for a
/// `Template` stage and forwards the bytes for a `Literal` one. A test constructs one
/// explicitly, which is the point: the construction is where a reader asks "rendered by
/// what?".
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RenderedCommand(String);

impl RenderedCommand {
    /// Take text the caller has ALREADY rendered.
    ///
    /// # Contract
    ///
    /// `command` is the output of `WorkflowRunner::render_checked_prompt` (or, in a test, a
    /// literal standing in for it). It is NOT
    /// `ExecutionProgramStage::op::prompt_template` unless that stage's
    /// `prompt_rendering` is `Literal`, in which case the renderer returns those bytes
    /// unchanged and the two coincide.
    ///
    /// The runner's submit paths construct one from `render_checked_prompt`'s output;
    /// the type is the one door the rendering obligation passes through, rather than a
    /// `&str` parameter to get right.
    #[must_use]
    pub fn rendered(command: impl Into<String>) -> Self {
        Self(command.into())
    }

    /// The rendered text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// The guest PROGRAM a shell stage's command is handed to — `argv[0]`.
///
/// A PROGRAM NAME and not a path, resolved by the container runtime against the
/// `PATH` the bound Nix environment's `path_prepend` renders. A store path here would
/// be the one thing a capsule may not carry: an absolute path this node happened to
/// realise, folded into `CapsuleId`, so the identity of an unchanged stage would
/// rotate with the environment's store layout — which
/// `Capsule::environment` already records, structurally, once.
///
/// `sh` and not `bash`: the shell every declared environment in this tree provides is
/// the one POSIX name, and choosing an interpreter a closure may not hold would make
/// the refusal an executable-not-found failure from inside a container rather than a
/// named refusal here.
const SHELL_PROGRAM: &str = "sh";

/// The program names `stage`'s resolved sandbox profile `requires` —
/// empty for a stage with no profile, or one naming a profile `profiles` lacks
/// (which CHECK has already refused).
#[must_use]
pub fn stage_requirements<'a>(
    stage: &'a ExecutionProgramStage,
    profiles: &'a std::collections::BTreeMap<String, kata_types::sandbox::SandboxProfile>,
) -> &'a [String] {
    match stage.policies.sandbox.as_ref() {
        Some(kata_types::sandbox::SandboxRef::Inline(profile)) => &profile.requires,
        Some(kata_types::sandbox::SandboxRef::Named(name)) => profiles
            .get(name.as_str())
            .map_or(&[][..], |profile| profile.requires.as_slice()),
        None => &[],
    }
}

/// Does `stage`'s capsule carry the execution's disposable GIT VIEW at `/work`?
/// Every AGENT stage, and a stage whose
/// profile `requires` the `git` program: a shell stage that runs `git` needs a
/// repository to run it against, and the view is that repository (the run's
/// history to its base commit, a scratch branch the stage may commit on, never
/// the host's checkout).
#[must_use]
pub fn carries_git_view(
    stage: &ExecutionProgramStage,
    profiles: &std::collections::BTreeMap<String, kata_types::sandbox::SandboxProfile>,
) -> bool {
    is_agent_class(stage)
        || stage_requirements(stage, profiles)
            .iter()
            .any(|p| p == "git")
}

/// The ARGUMENT VECTOR one shell stage's capsule commits to.
///
/// # Why the command is a PARAMETER and not read off the stage
///
/// `ExecutionProgramStage::op::prompt_template` is the AUTHORED text, and a stage
/// whose `prompt_rendering` is `Template` (the default for every Starlark-compiled
/// stage) has a command that is a function of RUNTIME CONTEXT — prior stage outputs,
/// review context, workspace reads. There is exactly one renderer for that
/// (`WorkflowRunner::render_checked_prompt`), it runs at dispatch, and a second spelling
/// here would be a second answer to *"what does this stage run"*. So the caller
/// passes the rendered command and this function owns the RULE that turns one into an
/// argv.
///
/// The consequence is stated rather than discovered: because the vector is folded
/// into `CapsuleId`, a template-rendered stage yields a DIFFERENT capsule per
/// rendering. That is correct — two dispatches that run two different commands are
/// two different promises about the box — and it is why the occurrence, not the
/// capsule, is what carries "at most one accepted outcome".
///
/// # Failure — the refused set, stated exactly
///
/// Two things here, and one delegated:
///
/// 1. a stage whose agent is not the deterministic SHELL label. An agent stage
///    runs its kind's init, which the kind fixes and `kata_agent::adapter`
///    speaks to, so this module has no argv to invent for it; a
///    `workspace_effect` stage runs no container at all. Both are refused BY NAME
///    rather than given `sh -c` over a prompt meant for a model.
/// 2. a command that is empty or whitespace only. `sh -c ""` exits 0 having done
///    nothing, so admitting one would make "this stage ran and succeeded" true of a
///    stage with no command — a green nobody authored.
///
/// Delegated to `Capsule::new`: an argument carrying a NUL byte, which truncates
/// silently at `execve`. Stated here so the whole refused set is readable in one
/// place, and NOT re-checked, because two doors for one refusal is two refused sets
/// to keep in agreement.
fn shell_argv(
    stage: &ExecutionProgramStage,
    command: &RenderedCommand,
) -> KataResult<Vec<SmolStr>> {
    let command = command.as_str();
    let label = stage
        .op
        .agent_label
        .as_deref()
        .unwrap_or(stage.op.agent.as_str());
    if !is_shell_class(stage) {
        return Err(refused(&format!(
            "stage {stage_id} selects agent `{label}`, and this door only derives an argument \
             vector for the deterministic `{shell}` class. An agent stage runs the init its kind \
             fixes and a workspace-effect stage runs no container, so handing either one \
             `sh -c <prompt>` would run a model's instructions as a script",
            stage_id = stage.stage_id.0,
            shell = kata_types::agent::BackendType::Shell.label(),
        )));
    }
    if command.trim().is_empty() {
        return Err(refused(&format!(
            "stage {stage_id} renders an empty command. `sh -c \"\"` exits 0 having done nothing, \
             so a capsule over one would make \"the stage ran and succeeded\" true of a stage with \
             no command",
            stage_id = stage.stage_id.0,
        )));
    }
    Ok(vec![
        SmolStr::new(SHELL_PROGRAM),
        SmolStr::new("-c"),
        SmolStr::new(command),
    ])
}

/// One agent stage's TURN SPEC — the `CapsuleProcess::Agent` arm's fields,
/// resolved off the INSTALLED `[agents.<label>]` map
/// ([`kata_types::node_profile::installed_node_agent`]).
///
/// # Why the map is re-read here when CHECK already judged it
///
/// The installed-profile CHECK is the ADMISSION door and this is the assembly
/// door; both answer off the same installed map, which is cold-installed at
/// boot and cannot differ between them. Re-asking rather than threading the
/// judgement through keeps the answer where the value is used: a capsule's
/// turn spec is the launch the worker runs, and the only honest source for it
/// is the node declaration the CHECK admitted. The refused set below is the
/// CHECK's own (`adapter_undeclared` for no block or no adapter;
/// `adapter_unqualified` for a label that names no kind) spelled once more
/// because a hand-built `ExecutionProgramStage` can reach this door without
/// having been checked.
///
/// The launch judgement itself is
/// [`AgentBackendConfig::capsule_launch`](kata_types::config::AgentBackendConfig::capsule_launch)
/// — the same adapter question `refuse_agent_stage_under_capsule_profile`
/// asks at CHECK, answered once on the config and refused here with the stage
/// context attached. Every kind's init is `kata-toolhost`, fixed by the kind,
/// so the turn names its kind and carries no launch vector. The credential's
/// doors are [`capsule_credential`]'s.
///
/// `model` is the stage's authored `model =` hint, falling back to the
/// node's declared `[agents.<name>] model`. `Some("")` is refused by
/// `Capsule::new` (`capsule_agent_model_empty`), so no second door here.
fn agent_turn_spec(
    stage: &ExecutionProgramStage,
    prompt: kata_types::execution_contract::ArtifactId,
) -> KataResult<kata_types::execution_contract::AgentTurnSpec> {
    let label = stage
        .op
        .agent_label
        .as_deref()
        .unwrap_or(stage.op.agent.as_str());
    let config = kata_types::node_profile::installed_node_agent(label).ok_or_else(|| {
        refused(&format!(
            "adapter_undeclared: stage {} selects agent `{label}`, and this node declares no \
             `[agents.{label}]` block at all",
            stage.stage_id.0,
        ))
    })?;
    let adapter = config.capsule_launch().map_err(|problem| {
        refused(&format!(
            "{}: stage {} selects agent `{label}`, whose `[agents.{label}]` {}",
            problem.door(),
            stage.stage_id.0,
            problem.describe(),
        ))
    })?;
    Ok(kata_types::execution_contract::AgentTurnSpec {
        adapter,
        model: stage
            .policies
            .model_hint
            .clone()
            .or_else(|| config.capsule_model().map(SmolStr::new)),
        reasoning_effort: config.capsule_reasoning_effort().map(SmolStr::new),
        output_schema: strict_output_schema(stage, adapter),
        prompt,
        credential: capsule_credential(stage, &config, adapter)?,
        env: config
            .capsule_env()
            .iter()
            .map(|(key, value)| (SmolStr::new(key), SmolStr::new(value)))
            .collect(),
    })
}

/// The strict structured-output schema an agent turn sends its vendor: the
/// stage's `produces=` contract (`policies.output_schema`, the schema the
/// runner validates the answer against) rendered by
/// [`kata_types::strict_output_schema::strict_output_schema`], for a kind whose
/// protocol [carries one](kata_types::agent::AdapterKind::carries_strict_output_schema).
///
/// `None` — no schema sent, the prompt path alone — for a stage with no
/// `produces=` (a flat `outputs` table names free-form type tags, not a
/// schema), for a kind with no channel, and for a contract with no strict
/// rendering ([`kata_types::strict_output_schema::NotStrict`], logged with its
/// reason). Never a partial schema.
fn strict_output_schema(
    stage: &ExecutionProgramStage,
    adapter: kata_types::agent::AdapterKind,
) -> Option<serde_json::Value> {
    if !adapter.carries_strict_output_schema() {
        return None;
    }
    let contract = stage.policies.output_schema.as_ref()?;
    match kata_types::strict_output_schema::strict_output_schema(contract) {
        Ok(schema) => Some(schema),
        Err(not_strict) => {
            tracing::info!(
                stage = %stage.stage_id.0,
                adapter = adapter.as_label(),
                reason = %not_strict,
                "the stage's output contract has no strict rendering; its turn is sent no \
                 output schema and relies on the prompt and kata's validation"
            );
            None
        }
    }
}

/// Assemble the immutable worker input for one lowered operation.
///
/// # The mappings, and why they are exactly three
///
/// * `/work` READ-WRITE over `work_tree` — the candidate tree the action edits;
/// * `/out` READ-WRITE over the [`empty_tree_artifact`] — where a result is
///   written;
/// * `/tmp` READ-WRITE over the same empty tree — scratch.
///
/// The environment closure is NOT a mapping: it is bound by the runtime at its own
/// store paths (`kata_worker::materialize` verifies presence and materializes
/// nothing), so listing it here would be a second, divergent copy of a store
/// object whose path is its identity. `capsule.environment()` is how the capsule
/// names it.
///
/// # The ARGUMENT VECTOR, and why `command` is a parameter
///
/// `argv` is `["sh", "-c", command]` — see [`shell_argv`] for the rule, its two
/// refusals, and why the rendered command arrives from the caller rather than being
/// read off `stage.op.prompt_template`. It is folded into `CapsuleId`, which is the
/// contract-v5 change this door carries out: before it, the bytes a container
/// `execve`d were a parameter of `kata_worker::oci_bundle::spec_for` chosen by
/// whoever called the driver, so two capsules with one id could run two different
/// programs.
///
/// # The budgets, and where each comes from
///
/// * `wall_time_ms` — the stage's `policies.timeout_ms`, which every checked
///   stage carries: an undeclared (or `0`-spelled) `timeout_ms=` became
///   [`kata_types::workflow::DEFAULT_STAGE_TIMEOUT_MS`] at AUTHORING, so this
///   door never has to invent a ceiling and never has to refuse for want of
///   one. A ZERO budget is still refused — it is not a bound, and no frontend
///   can produce it, because `0` at the authoring surface means "take the
///   default" rather than "no wall clock".
/// * `output_bytes` — [`CAPSULE_OUTPUT_BYTES`], the one constant a capsule commits
///   to (see its docs for why it is not the env-overridable process default).
/// * `memory_bytes` / `process_count` — the node's [`NodeBudgetDefaults`],
///   RECORDED in the capsule, so changing a node default rotates the identity of
///   what it changes.
/// * `result_bytes` / `result_entries` — [`CAPSULE_RESULT_BYTES`] and
///   [`CAPSULE_RESULT_ENTRIES`], the bound the ADOPTING side holds the published
///   `/out` tree to. They are in the capsule, and therefore in its id, so the bound
///   a result is checked against is the one the authorization promised rather than
///   whatever the adopting reader was configured with at adoption time.
///
/// # Failure — the refused set, stated exactly
///
/// * a directive that presumes the main's filesystem — checked on the
///   directive AS GIVEN, which is why it catches the workspace key that
///   [`sandbox_permissions_hash`] projects out for the identity;
/// * a directive whose `fs` is [`FsPolicy::Custom`], because a custom mount's
///   `host_path` is a host path with no capsule encoding at all (the inventory
///   above does not enumerate it — `fs` is a policy enum — so it is named here);
/// * a stage whose agent is not the deterministic `shell` label, and a stage whose
///   rendered `command` is empty — both through [`shell_argv`], which owns the rule
///   that turns a command into the `argv` the capsule id folds;
/// * a stage whose `timeout_ms` is zero — unreachable from any frontend, because
///   `parser::resolve_stage_timeout_ms` maps BOTH an omitted `timeout_ms=` and the
///   DSL's `0` sentinel to `DEFAULT_STAGE_TIMEOUT_MS` (a negative literal is
///   refused earlier, in `stage()` itself). Refused here anyway, so a hand-built
///   `ExecutionProgramStage` cannot mint a capsule with no wall-time bound;
/// * a [`NodeBudgetDefaults`] with a zero memory or process ceiling;
/// * whatever [`Capsule::new`] refuses (a duplicate guest path) and whatever
///   [`empty_tree_artifact`] refuses.
///
/// Nothing else. In particular `FsPolicy::Host` and `NetPolicy::Host` are NOT
/// refused here: they name no path, and whether a posture may run at all is the
/// issuance gate's question, which does not exist yet and must not be
/// half-answered here.
pub fn assemble_capsule(
    lowered: &LoweredOperation,
    occurrence: OccurrenceId,
    stage: &ExecutionProgramStage,
    directive: &SandboxDirective,
    command: &RenderedCommand,
    environment: EnvironmentId,
    platform: PlatformId,
    work_tree: ArtifactId,
    budgets: NodeBudgetDefaults,
    agent_prompt: Option<ArtifactId>,
    git_view: Option<CapsuleGitView>,
) -> KataResult<(PreparedAction, Capsule)> {
    refuse_host_paths(directive)?;
    // THE PROCESS ARM — one of two contract shapes, decided by the stage's
    // class: a shell stage's `Command` argv is derived here; an agent stage's
    // `Agent` turn carries the launch argv the node declared and the prompt
    // artifact the caller published, because the capsule's bytes are the
    // authorization's answer, never a worker-side lookup. `agent_prompt` is
    // `Some` exactly for an agent stage — the submit door publishes the
    // rendered prompt and passes its id — and `None` on the shell arm,
    // which does not read it at all.
    let process = if is_shell_class(stage) {
        CapsuleProcess::Command {
            argv: shell_argv(stage, command)?,
        }
    } else {
        let prompt = agent_prompt.ok_or_else(|| {
            refused(&format!(
                "stage {} selects a model/agent class, and the caller published no prompt \
                 artifact to fold into the turn spec — `submit_stage_as_capsule` is the one \
                 door that publishes it, so reaching here without one is a wiring defect, not \
                 a refusal an author can produce",
                stage.stage_id.0,
            ))
        })?;
        CapsuleProcess::Agent(agent_turn_spec(stage, prompt)?)
    };

    let wall_time_ms = stage.policies.timeout_ms;
    if wall_time_ms == 0 {
        return Err(refused(&format!(
            "stage {} carries timeout_ms=0, which is not a wall-time bound a capsule can commit \
             to. No frontend can produce it: an authored `timeout_ms = 0` is refused and an \
             unauthored one becomes DEFAULT_STAGE_TIMEOUT_MS, so reaching here means a stage was \
             built by hand around the frontend",
            stage.stage_id.0
        )));
    }
    if budgets.memory_bytes == 0 || budgets.process_count == 0 {
        return Err(refused(&format!(
            "node budget defaults are memory_bytes={} process_count={}; a zero ceiling is not a \
             bound, it is a capsule that cannot run",
            budgets.memory_bytes, budgets.process_count
        )));
    }

    // ONE CONSTRUCTOR OF A PREPARED ACTION. `authorization::prepare_action` builds
    // the identity — the contract id, the manifest over the checked stage contract
    // hash, the permissions hash — and this function calls it rather than spelling it
    // again. Two spellings of one identity is how a capsule and the authorization
    // that declares it come to name different actions while both look right; see that
    // function's docs for the manifest and command arguments.
    let action =
        crate::authorization::prepare_action(stage, lowered, environment, platform, directive)?;

    let empty = empty_tree_artifact()?;
    let process_count = budgets.process_count;
    let memory_bytes = budgets.memory_bytes;
    // THE NETWORK ARM: the stage's authored `net` posture over the node's
    // `egress_allow`.
    let network = capsule_network_for(
        &directive.net,
        &kata_types::node_profile::installed_node_egress_allow(),
    );
    // THE `/work` ARM — one mapping, two roles, decided by the authored
    // filesystem posture:
    //
    // * a workspace profile (`WorkspaceRo`/`WorkspaceRw`) binds the execution's
    //   durable head `work_tree` read-write — its delta is the workspace
    //   mutation the apply sweep lands;
    // * `Scratch` binds the canonical EMPTY tree `ReadWriteScratch` — a
    //   writable scratch root that exists for exactly one attempt, whose
    //   delta is recorded as evidence and never applied.
    //
    // The access tag is the contract fact every main-side door keys on: the
    // authorization's `/work` role check, the adoption's `scratch_delta_*`
    // outcome keys, and the apply sweep's silence on them all read the one
    // arm this mints.
    let (work_mapped, work_access) = match directive.fs {
        kata_types::sandbox::FsPolicy::Scratch => (empty.id(), GuestAccess::ReadWriteScratch),
        _ => (work_tree, GuestAccess::ReadWrite),
    };
    // THE WORK VIEW — the `oci` confinement for a `reads=`-declaring stage.
    // `should_confine_to_declared_inputs` is the one predicate that decides
    // which stages confine; the non-empty `reads` conjunct mirrors the
    // directive's stamp (an empty closure — `reads = "whole-tree"`'s compiled
    // form — mints no view, and the whole head maps like before). The include
    // list is the shim's union: the declared reads plus, for a workspace the
    // stage may write, the declared `produces_files` — under `ro` a write
    // closure would be a grant to nothing.
    let work_view =
        (stage.should_confine_to_declared_inputs() && !stage.reads.is_empty()).then(|| {
            let mut include = stage.reads.clone();
            if !matches!(directive.fs, FsPolicy::WorkspaceRo) {
                include.extend(stage.produces_files.iter().cloned());
            }
            CapsuleWorkView { include }
        });
    let capsule = Capsule::new(
        occurrence,
        action.id(),
        environment,
        platform,
        vec![
            mapping("/work", work_mapped, work_access)?,
            mapping("/out", empty.id(), GuestAccess::ReadWrite)?,
            mapping("/tmp", empty.id(), GuestAccess::ReadWrite)?,
        ],
        process,
        network,
        git_view,
        CapsuleBudgets {
            wall_time_ms,
            // v7: the AUTHORED combined capture bound, or the cell default when
            // the stage carried no `output_bytes=`. The over-ceiling refusal
            // ran at admission (`capsule_budget_over_node_ceiling`), so the
            // authored value reaching here is inside the node's ceiling.
            output_bytes: stage.policies.output_bytes.unwrap_or(CAPSULE_OUTPUT_BYTES),
            memory_bytes,
            process_count,
            result_bytes: CAPSULE_RESULT_BYTES,
            result_entries: CAPSULE_RESULT_ENTRIES,
            // Carried and authored-or-defaulted; the worker enforces both at
            // delta publish and the main re-checks them at adoption.
            work_delta_bytes: stage
                .policies
                .work_delta_bytes
                .unwrap_or(CAPSULE_WORK_DELTA_BYTES),
            work_delta_entries: stage
                .policies
                .work_delta_entries
                .unwrap_or(CAPSULE_WORK_DELTA_ENTRIES),
        },
        work_view,
    )?;
    Ok((action, capsule))
}

/// One mapping. The guest path is built through `GuestPath::new`, so the three
/// literals above are held to the same refused set as any other path rather than
/// trusted for being literals.
fn mapping(
    guest_path: &str,
    artifact: ArtifactId,
    access: GuestAccess,
) -> KataResult<GuestMapping> {
    Ok(GuestMapping {
        artifact,
        guest_path: GuestPath::new(guest_path)?,
        access,
    })
}

/// Refuse a directive that names a path only the main's filesystem resolves.
///
/// Two clauses, because the two carriers are found by different means and neither
/// covers the other: the INVENTORY
/// (`SandboxDirective::shared_filesystem_presumptions`, whose exhaustive
/// destructure is what makes a future carrier a compile error at its own door),
/// and `fs = custom`, whose `MountSpec::host_path` the inventory deliberately does
/// not enumerate because `fs` is a policy enum rather than a path field.
fn refuse_host_paths(directive: &SandboxDirective) -> KataResult<()> {
    let presumptions = directive.shared_filesystem_presumptions();
    if let Some(first) = presumptions.first() {
        return Err(refused(&format!(
            "the resolved directive names a main-resolved path at {} ({}), and a capsule addresses \
             content rather than this node's filesystem. A `/work` mapping is how a capsule binds \
             a workspace",
            first.wire_pointer, first.path
        )));
    }
    if let FsPolicy::Custom { mounts } = &directive.fs {
        let named = mounts
            .iter()
            .map(|mount| mount.host_path.display().to_string())
            .collect::<Vec<_>>()
            .join(", ");
        return Err(refused(&format!(
            "the resolved directive declares fs = custom with host mount(s) [{named}]. A host path \
             has no encoding in a capsule — every input is an artifact at a guest path — so there \
             is nothing here for this mount to become"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use kata_types::execution_contract::{ArtifactId, CredentialSource, TurnCredentialRef};
    use kata_types::primitives::ContentHash;

    /// **Capsule assembly refuses `nanocode_anthropic` under `subscription`
    /// `credential_mode_unsupported`, as the CHECK does.** A hand-built stage
    /// selecting a `kata_login` subscription block is refused by
    /// `agent_turn_spec` naming the door and the recourse; the
    /// same block under `api_key` assembles a turn carrying that credential.
    ///
    /// **Would red if:** assembly minted a turn the worker can only refuse
    /// after dispatch.
    #[test]
    fn assembly_refuses_nanocode_anthropic_under_subscription() {
        let program = kata_program::execution_program::compile_starlark_execution_program(
            "edit = stage(id = \"edit\", agent = \"coder\", prompt = \"edit\")\n\
             workflow(\"nanocode\", root = [edit])\n",
            "nanocode.star",
            &[],
        )
        .expect("the pack compiles with no node installed");
        let stage = program.stages.values().next().expect("the one stage");
        let install = |mode: &str| {
            let mut agents = std::collections::BTreeMap::new();
            agents.insert(
                "coder".to_owned(),
                kata_types::config::AgentBackendConfig::Harness {
                    model: Some("claude-sonnet-5-5".to_owned()),
                    reasoning_effort: None,
                    adapter: Some("nanocode_anthropic".to_owned()),
                    credential: Some(kata_types::config::AgentCredentialDecl {
                        mode: mode.to_owned(),
                        source: "kata_login".to_owned(),
                    }),
                    env: std::collections::BTreeMap::new(),
                },
            );
            kata_types::node_profile::install_node_agents(agents);
        };
        let prompt = ArtifactId(ContentHash::new([7; 32]));
        install("subscription");
        let refusal = super::agent_turn_spec(stage, prompt)
            .expect_err("a subscription nanocode_anthropic turn assembles")
            .to_string();
        assert!(
            refusal.contains("capsule assembly refused: credential_mode_unsupported: stage edit")
                && refusal.contains("`kata login anthropic --api-key`"),
            "{refusal}"
        );
        install("api_key");
        let turn = super::agent_turn_spec(stage, prompt).expect("an api_key turn assembles");
        assert_eq!(
            turn.credential,
            Some(TurnCredentialRef {
                mode: kata_types::metering::CredentialMode::ApiKey,
                source: CredentialSource::KataLogin,
            })
        );
    }
}
