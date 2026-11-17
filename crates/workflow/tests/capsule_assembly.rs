//! CAPSULE ASSEMBLY: determinism, identity rotation, the
//! named refusals, and the PINNED permissions hash.
//!
//! # Why the golden hex is here rather than in an in-module test
//!
//! `sandbox_permissions_hash` folds the projected directive's canonical JSON, so
//! its value moves when a `SandboxDirective` field is added, renamed, reordered by
//! serde, or re-spelled — and the value is folded into `PreparedActionId`, which is
//! folded into `CapsuleId`. An in-module test comparing kata's answer to kata's
//! answer cannot see any of that. The literal below is the external witness: a diff
//! means every prepared-action and capsule identity this build mints has rotated,
//! which is either intended (re-pin, deliberately) or a defect.

use std::collections::BTreeMap;

use kata_program::execution_program::{
    ExecutionProgram, ExecutionProgramStage, LoweredOperation, compile_starlark_execution_program,
    lower_stage_operation,
};
use kata_types::execution_contract::{
    ArtifactId, CAPSULE_OUTPUT_BYTES, Capsule, EnvironmentId, GuestAccess, OccurrenceId,
    PlatformId, PreparedAction,
};
use kata_types::primitives::ContentHash;
use kata_types::sandbox::{
    ExecBackend, FsPolicy, MountSpec, NetPolicy, SandboxDirective, SandboxImage, SecretRef,
};
use kata_types::workflow::StageId;
use kata_workflow::capsule_assembly::{
    NodeBudgetDefaults, RenderedCommand, assemble_capsule, empty_tree_artifact,
    sandbox_permissions_hash,
};
use smol_str::SmolStr;

/// The RENDERED stage command every capsule in this file is assembled over — see the
/// sibling in `authorization.rs` for why it is constructed explicitly.
fn stage_command() -> RenderedCommand {
    RenderedCommand::rendered("echo assembly")
}
/// The pinned permissions hash of [`fixture_directive`].
///
/// Watched RED against a deliberately wrong literal before it was pinned. The value
/// moves when the fixture's DECLARED `secrets=` grant or `image` changes — exactly the
/// rotation a grant entering an action's permissions is supposed to cause — and when
/// the fixture's confined backend brand changes: the brand is part of what the action
/// runs under, so renaming it rotates the hash.
const FIXTURE_PERMISSIONS_HEX: &str =
    "eed00d051b2cda7a2d2ab3ba74644c4a62af0ea1c8865028e8ed0c6a8c672ec9";

/// A stage that declares a timeout, because a capsule commits to a wall-time
/// bound and a stage that declares none is refused.
const PACK: &str = "a = stage(id = \"a\", run = \":\", agent = \"shell\", timeout_ms = 30000)\n\
     workflow(\"assembly\", root = [a])\n";

fn program() -> ExecutionProgram {
    compile_starlark_execution_program(PACK, "assembly.star", &[])
        .expect("the fixture pack compiles")
}

fn stage(program: &ExecutionProgram) -> &ExecutionProgramStage {
    stage_named(program, "a")
}

fn stage_named<'a>(program: &'a ExecutionProgram, name: &str) -> &'a ExecutionProgramStage {
    program
        .stages
        .iter()
        .find(|(id, _)| id.0.as_str() == name)
        .map(|(_, stage)| stage)
        .expect("the fixture stage is present")
}

fn lowered(program: &ExecutionProgram) -> LoweredOperation {
    lowered_named(program, "a")
}

fn lowered_named(program: &ExecutionProgram, name: &str) -> LoweredOperation {
    lower_stage_operation(program, &StageId(SmolStr::new(name)))
        .expect("the fixture stage lowers to a typed operation")
}

/// A directive with a value in every field that carries one, so the golden covers
/// more than the defaults.
fn fixture_directive() -> SandboxDirective {
    let mut env = BTreeMap::new();
    // Deliberately inserted out of order: the hash sorts keys, so this is what
    // proves it rather than a comment claiming it.
    env.insert("ZED".to_string(), "last".to_string());
    env.insert("ALPHA".to_string(), "first".to_string());
    // A DECLARED secret grant, so the pinned hash witnesses that a `secrets=` grant
    // reaches the permissions identity; a fixture with no grant at all could not see
    // that.
    let mut secret_tokens = BTreeMap::new();
    secret_tokens.insert(
        "FORGE_TOKEN".to_string(),
        SecretRef::Env("KATA_FORGE_TOKEN".to_string()),
    );
    SandboxDirective {
        exec: ExecBackend::Oci,
        fs: FsPolicy::WorkspaceRw,
        net: NetPolicy::Offline,
        env,
        secret_tokens,
        image: Some(SandboxImage {
            reference: "kata/rust-1.93:pinned".to_string(),
            cpus: Some(4),
            memory_mb: Some(4096),
        }),
        confine_to_declared_inputs: true,
        content_cacheable: true,
        read_closure: vec![SmolStr::new("src/**")],
        write_closure: vec![SmolStr::new("out/**")],
        determinism_pinned: true,
    }
}

fn budgets() -> NodeBudgetDefaults {
    NodeBudgetDefaults {
        memory_bytes: 2 * 1024 * 1024 * 1024,
        process_count: 512,
    }
}

fn hash(byte: u8) -> ContentHash {
    ContentHash::new([byte; 32])
}

struct Bindings {
    occurrence: OccurrenceId,
    environment: EnvironmentId,
    platform: PlatformId,
    work_tree: ArtifactId,
    directive: SandboxDirective,
    budgets: NodeBudgetDefaults,
}

fn bindings() -> Bindings {
    Bindings {
        occurrence: OccurrenceId(hash(1)),
        environment: EnvironmentId(hash(2)),
        platform: PlatformId(hash(3)),
        work_tree: ArtifactId(hash(4)),
        directive: fixture_directive(),
        budgets: budgets(),
    }
}

fn assemble(
    program: &ExecutionProgram,
    bindings: &Bindings,
) -> kata_types::KataResult<(PreparedAction, Capsule)> {
    assemble_capsule(
        &lowered(program),
        bindings.occurrence,
        stage(program),
        &bindings.directive,
        &stage_command(),
        bindings.environment,
        bindings.platform,
        bindings.work_tree,
        bindings.budgets,
        None,
        None,
    )
}

// ---------------------------------------------------------------------------

/// Assembly is a pure function of its inputs, and the capsule round-trips through
/// `Capsule::new` with its id recomputed from the body.
///
/// Host-path ABSENCE is not asserted here: no assembly input carries a main host
/// path since the workspace env key left the directive, so an absence check
/// over this fixture would pass by construction. The host path an author could
/// still try to hand the capsule — an `fs = custom` mount — is refused by name in
/// `a_directive_carrying_a_custom_host_mount_is_refused_by_name`.
#[test]
fn assembly_is_deterministic_and_round_trips_through_the_capsule_constructor() {
    let program = program();
    let bindings = bindings();
    let (first_action, first_capsule) = assemble(&program, &bindings).expect("assembly succeeds");
    let (second_action, second_capsule) = assemble(&program, &bindings).expect("assembly succeeds");
    assert_eq!(first_action, second_action);
    assert_eq!(first_capsule, second_capsule);
    assert_eq!(first_capsule.id(), second_capsule.id());

    let encoded = serde_json::to_string(&first_capsule).expect("the capsule serializes");

    // And it decodes back through `Capsule::new`, id recomputed from the body.
    assert_eq!(
        serde_json::from_str::<Capsule>(&encoded).expect("the capsule decodes"),
        first_capsule
    );
}

/// **The fixture SHELL stage mints `Command` + `Offline`.** A `shell` stage
/// authored `net = "offline"` carries the shell vector under the `Command` arm
/// and no route out — the `Agent` arm is an agent stage's (`AGENT_PACK`'s
/// cells), and `Egress` is what an authored `net = "host"` mints
/// (`a_host_net_shell_stage_mints_egress_over_the_nodes_allowlist`).
///
/// **Would red if:** `assemble_capsule` minted either non-default arm for a
/// plain offline shell stage.
#[test]
fn the_assembled_capsule_is_a_command_process_on_the_offline_network() {
    let (_, capsule) = assemble(&program(), &bindings()).expect("assembly succeeds");
    assert_eq!(
        capsule.process(),
        &kata_types::execution_contract::CapsuleProcess::Command {
            argv: vec![
                smol_str::SmolStr::new("sh"),
                smol_str::SmolStr::new("-c"),
                smol_str::SmolStr::new("echo assembly"),
            ],
        },
        "the rendered command arrives as the Command arm's argv"
    );
    assert_eq!(
        capsule.network(),
        &kata_types::execution_contract::CapsuleNetwork::Offline,
        "an authored `net = \"offline\"` mints Offline — `net = \"host\"` mints \
         Egress over the declared authorities"
    );
}

#[test]
fn the_three_mappings_are_work_out_and_tmp_over_the_declared_trees() {
    let program = program();
    let bindings = bindings();
    let (action, capsule) = assemble(&program, &bindings).expect("assembly succeeds");
    let empty = empty_tree_artifact().expect("the empty tree has a reference");

    let mappings: Vec<(&str, ArtifactId, GuestAccess)> = capsule
        .inputs()
        .iter()
        .map(|mapping| {
            (
                mapping.guest_path.as_str(),
                mapping.artifact,
                mapping.access,
            )
        })
        .collect();
    assert_eq!(
        mappings,
        vec![
            ("/out", empty.id(), GuestAccess::ReadWrite),
            ("/tmp", empty.id(), GuestAccess::ReadWrite),
            ("/work", bindings.work_tree, GuestAccess::ReadWrite),
        ],
        "sorted by guest path, /work over the work tree, /out and /tmp over the empty tree"
    );

    assert_eq!(capsule.action(), action.id());
    assert_eq!(capsule.occurrence(), bindings.occurrence);
    assert_eq!(capsule.environment(), bindings.environment);
    assert_eq!(capsule.platform(), bindings.platform);

    let budgets = capsule.budgets();
    assert_eq!(budgets.wall_time_ms, stage(&program).policies.timeout_ms);
    assert_eq!(budgets.output_bytes, CAPSULE_OUTPUT_BYTES);
    assert_eq!(budgets.memory_bytes, bindings.budgets.memory_bytes);
    assert_eq!(budgets.process_count, bindings.budgets.process_count);
}

/// One row of the rotation table: which binding moved, how, and whether moving it
/// must rotate the PREPARED ACTION as well as the capsule. A named type because
/// the tuple is the table's schema, and a reader should see it once.
type RotationRow = (&'static str, Box<dyn Fn(&mut Bindings)>, bool);

/// One field at a time, so a rotation is attributable to the field that moved.
#[test]
fn every_binding_rotates_both_identities() {
    // The net→Host mutation below needs a declared node allowlist: `net =
    // "host"` mints `Egress{installed set}`, and `Capsule::new` refuses an
    // EMPTY egress (`capsule_egress_allowlist_empty`).
    kata_types::node_profile::install_node_egress_allow(std::collections::BTreeSet::from([
        kata_types::execution_contract::EgressAuthority::from_authority_str("api.example.com:443")
            .expect("an authority parses"),
    ]));
    let program = program();
    let base = bindings();
    let (base_action, base_capsule) = assemble(&program, &base).expect("assembly succeeds");

    let mutations: Vec<RotationRow> = vec![
        (
            "occurrence",
            Box::new(|bindings: &mut Bindings| bindings.occurrence = OccurrenceId(hash(9))),
            // An occurrence is NOT part of a prepared action's identity, by
            // contract: equal prepared work must be recognizable across logical
            // occurrences.
            false,
        ),
        (
            "environment",
            Box::new(|bindings: &mut Bindings| bindings.environment = EnvironmentId(hash(9))),
            true,
        ),
        (
            "platform",
            Box::new(|bindings: &mut Bindings| bindings.platform = PlatformId(hash(9))),
            true,
        ),
        (
            "work_tree",
            Box::new(|bindings: &mut Bindings| bindings.work_tree = ArtifactId(hash(9))),
            false,
        ),
        (
            "directive",
            Box::new(|bindings: &mut Bindings| bindings.directive.net = NetPolicy::Host),
            true,
        ),
        (
            "directive.secret_tokens",
            Box::new(|bindings: &mut Bindings| {
                bindings.directive.secret_tokens.insert(
                    "SECOND_TOKEN".to_string(),
                    SecretRef::File("/run/secrets/second".into()),
                );
            }),
            true,
        ),
        (
            "directive.image",
            Box::new(|bindings: &mut Bindings| {
                bindings.directive.image = Some(SandboxImage {
                    reference: "kata/rust-1.93:other".to_string(),
                    cpus: Some(4),
                    memory_mb: Some(4096),
                });
            }),
            true,
        ),
        (
            "memory_bytes",
            Box::new(|bindings: &mut Bindings| bindings.budgets.memory_bytes += 1),
            false,
        ),
        (
            "process_count",
            Box::new(|bindings: &mut Bindings| bindings.budgets.process_count += 1),
            false,
        ),
    ];

    for (name, mutate, rotates_action) in mutations {
        let mut mutated = bindings();
        mutate(&mut mutated);
        let (action, capsule) = assemble(&program, &mutated).expect("assembly succeeds");
        assert_ne!(
            capsule.id(),
            base_capsule.id(),
            "{name} must rotate the capsule id"
        );
        if rotates_action {
            assert_ne!(
                action.id(),
                base_action.id(),
                "{name} must rotate the prepared action id"
            );
        } else {
            assert_eq!(
                action.id(),
                base_action.id(),
                "{name} must NOT rotate the prepared action id"
            );
        }
    }
}

/// **A stage declaring no `timeout_ms` is not refused — it carries the
/// AUTHORING default, and the capsule commits to that.**
///
/// The frontend resolves an undeclared (or `0`-spelled) `timeout_ms=` to
/// `DEFAULT_STAGE_TIMEOUT_MS`, so no frontend can hand this door a stage with no
/// bound. The assertion is over the capsule's own `wall_time_ms`, because
/// "assembly returned Ok" would pass on a capsule committing to any number at all.
#[test]
fn a_stage_declaring_no_timeout_assembles_on_the_authoring_default() {
    let program = compile_starlark_execution_program(
        "a = stage(id = \"a\", run = \":\", agent = \"shell\")\n\
         workflow(\"assembly\", root = [a])\n",
        "no-timeout.star",
        &[],
    )
    .expect("the pack compiles");
    let bindings = bindings();
    let (_, capsule) = assemble(&program, &bindings).expect("assembly succeeds on the default");
    assert_eq!(
        capsule.budgets().wall_time_ms,
        kata_types::workflow::DEFAULT_STAGE_TIMEOUT_MS
    );
}

/// **A ZERO wall clock is refused by name** — the refusal
/// `assemble_capsule` keeps for a wall clock no layer can honour.
///
/// No frontend can produce it: at the authoring surface `0` MEANS "take the
/// default" (`stage()`'s omitted-value sentinel, which
/// `workflows/std/kata/std.star`'s helpers forward), and a negative literal is
/// refused in `stage()` itself. So the only way here is a hand-built
/// `ExecutionProgramStage`, which is exactly what this test builds: the door must
/// not rely on its callers for a bound it commits a container to.
#[test]
fn a_zero_wall_time_bound_is_refused_by_name() {
    let mut program = program();
    let stage_id = StageId(SmolStr::new("a"));
    program
        .stages
        .get_mut(&stage_id)
        .expect("the fixture stage exists")
        .policies
        .timeout_ms = 0;
    let bindings = bindings();
    let error = assemble(&program, &bindings).expect_err("a zero wall clock is not a bound");
    let message = error.to_string();
    assert!(message.contains("capsule assembly refused"), "{message}");
    assert!(message.contains("timeout_ms=0"), "{message}");
}

#[test]
fn a_directive_carrying_a_custom_host_mount_is_refused_by_name() {
    let program = program();
    let mut bindings = bindings();
    bindings.directive.fs = FsPolicy::Custom {
        mounts: vec![MountSpec {
            host_path: "/etc".into(),
            mount_point: "/etc".into(),
            writable: false,
        }],
    };
    let error = assemble(&program, &bindings).expect_err("a custom host mount is refused");
    let message = error.to_string();
    assert!(message.contains("fs = custom"), "{message}");
    assert!(message.contains("/etc"), "{message}");
}

#[test]
fn a_zero_node_budget_is_refused_by_name() {
    let program = program();
    for (memory, processes) in [(0, 8), (1024, 0)] {
        let mut bindings = bindings();
        bindings.budgets = NodeBudgetDefaults {
            memory_bytes: memory,
            process_count: processes,
        };
        let error = assemble(&program, &bindings).expect_err("a zero ceiling is refused");
        assert!(
            error.to_string().contains("a zero ceiling is not a bound"),
            "{error}"
        );
    }
}

/// The golden: the pinned hex, plus the totality the pin exists to protect.
#[test]
fn the_permissions_hash_is_pinned_and_total() {
    let directive = fixture_directive();
    let pinned = sandbox_permissions_hash(&directive).expect("the fixture hashes");
    assert_eq!(pinned.to_string(), FIXTURE_PERMISSIONS_HEX);

    // NOT ignored: every field the directive carries.
    for mutate in [
        (|directive: &mut SandboxDirective| directive.exec = ExecBackend::Host)
            as fn(&mut SandboxDirective),
        |directive: &mut SandboxDirective| directive.fs = FsPolicy::Scratch,
        |directive: &mut SandboxDirective| directive.net = NetPolicy::Host,
        |directive: &mut SandboxDirective| directive.confine_to_declared_inputs = false,
        |directive: &mut SandboxDirective| directive.content_cacheable = false,
        |directive: &mut SandboxDirective| directive.determinism_pinned = false,
        |directive: &mut SandboxDirective| directive.read_closure = vec![SmolStr::new("other/**")],
        |directive: &mut SandboxDirective| directive.write_closure = Vec::new(),
        |directive: &mut SandboxDirective| {
            directive
                .env
                .insert("ALPHA".to_string(), "moved".to_string());
        },
    ] {
        let mut mutated = fixture_directive();
        mutate(&mut mutated);
        assert_ne!(
            sandbox_permissions_hash(&mutated).expect("it hashes"),
            pinned,
            "every field a directive carries must rotate the permissions hash"
        );
    }
}

/// The empty tree is a CONSTANT of this build, and it is the empty manifest's own
/// address — asserted by re-deriving it here from the manifest bytes rather than by
/// calling the function twice.
#[test]
fn the_empty_tree_artifact_is_the_empty_manifests_own_address() {
    let reference = empty_tree_artifact().expect("the empty tree has a reference");
    let bytes = kata_types::tree_artifact::TreeManifest::new(Vec::new())
        .expect("an empty manifest is accepted")
        .manifest_bytes()
        .expect("it serializes");
    assert_eq!(bytes, br#"{"schema_version":2,"entries":[]}"#.to_vec());
    assert_eq!(
        reference.object_id(),
        kata_types::cache::object_id_for_canonical_bytes(&bytes)
    );
    assert_eq!(reference.size_bytes(), bytes.len() as u64);
    assert_eq!(
        reference.id(),
        empty_tree_artifact().expect("stable").id(),
        "the id is a constant, not a per-call value"
    );
}

// ---------------------------------------------------------------------------
// The `Agent` arm
// ---------------------------------------------------------------------------

const AGENT_PACK: &str = "verdict = stage(\n\
     \x20   id = \"verdict\",\n\
     \x20   agent = \"codex\",\n\
     \x20   prompt = \"review the diff\",\n\
     )\n\
     workflow(\"agent-pack\", root = [verdict])\n";

/// Install a `[agents.codex]` declaration for one cell — process-global, as
/// `boot`'s own install is, and per-process under nextest — under kata's own
/// login, the credential every kind can be served by.
fn install_agents(adapter: Option<&str>) {
    let mut agents = std::collections::BTreeMap::new();
    agents.insert(
        "codex".to_owned(),
        kata_types::config::AgentBackendConfig::Harness {
            model: None,
            reasoning_effort: None,
            adapter: adapter.map(str::to_owned),
            credential: Some(kata_types::config::AgentCredentialDecl {
                mode: "api_key".to_owned(),
                source: "kata_login".to_owned(),
            }),
            env: std::collections::BTreeMap::new(),
        },
    );
    kata_types::node_profile::install_node_agents(agents);
}

/// **An agent stage's capsule is the `Agent` turn, naming the NODE-declared
/// adapter, the STAGE-authored model, and the caller-published prompt artifact
/// — never a worker-side lookup.** The `/work` `/out` `/tmp` mappings, budgets,
/// environment and `Offline` network are the shell arm's own.
#[test]
fn an_agent_stage_assembles_an_agent_turn_from_the_node_declaration() {
    install_agents(Some("nanocode_openai"));
    let program = compile_starlark_execution_program(AGENT_PACK, "agent-pack.star", &[])
        .expect("the agent pack compiles (the profile is not installed here)");
    let bindings = bindings();
    let prompt = ArtifactId(hash(7));
    let (_, capsule) = assemble_capsule(
        &lowered_named(&program, "verdict"),
        bindings.occurrence,
        stage_named(&program, "verdict"),
        &bindings.directive,
        &stage_command(),
        bindings.environment,
        bindings.platform,
        bindings.work_tree,
        bindings.budgets,
        Some(prompt),
        None,
    )
    .expect("a declared agent stage assembles");

    let kata_types::execution_contract::CapsuleProcess::Agent(turn) = capsule.process() else {
        panic!(
            "an agent stage's process arm is `Agent`, got {:?}",
            capsule.process()
        );
    };
    assert_eq!(
        turn.adapter,
        kata_types::agent::AdapterKind::NanocodeOpenai,
        "the adapter is the node's declaration, echoed as its KIND"
    );
    assert_eq!(
        turn.prompt, prompt,
        "the prompt is the caller's artifact id"
    );
    assert_eq!(
        capsule.network(),
        &kata_types::execution_contract::CapsuleNetwork::Offline,
        "the network arm is Offline — the fixture's directive authors `net = \"offline\"`"
    );
    // THE ID covers the turn: a second capsule identical but for the prompt is
    // a different capsule.
    let other = kata_types::execution_contract::Capsule::new(
        capsule.occurrence(),
        capsule.action(),
        capsule.environment(),
        capsule.platform(),
        capsule.inputs().to_vec(),
        kata_types::execution_contract::CapsuleProcess::Agent(
            kata_types::execution_contract::AgentTurnSpec {
                adapter: turn.adapter,
                model: turn.model.clone(),
                reasoning_effort: None,
                output_schema: None,
                prompt: ArtifactId(hash(8)),
                credential: turn.credential.clone(),
                env: std::collections::BTreeMap::new(),
            },
        ),
        capsule.network().clone(),
        None,
        capsule.budgets(),
        None,
    )
    .expect("the twin is well formed");
    assert_ne!(
        capsule.id(),
        other.id(),
        "the prompt artifact folds into the capsule id"
    );
}

/// **An agent stage's `reasoning_effort` is the `[agents.<label>]` node's
/// declared value on the assembled turn — a contract fact the adapter
/// delivers, never a worker-side lookup.** The id covers it by the spec's
/// own hash fold.
#[test]
fn an_agent_stage_assembles_the_declared_reasoning_effort() {
    let mut agents = std::collections::BTreeMap::new();
    agents.insert(
        "codex".to_owned(),
        kata_types::config::AgentBackendConfig::Harness {
            model: None,
            reasoning_effort: Some("low".to_owned()),
            adapter: Some("nanocode_openai".to_owned()),
            credential: Some(kata_types::config::AgentCredentialDecl {
                mode: "api_key".to_owned(),
                source: "kata_login".to_owned(),
            }),
            env: std::collections::BTreeMap::new(),
        },
    );
    kata_types::node_profile::install_node_agents(agents);
    let program = compile_starlark_execution_program(AGENT_PACK, "agent-pack.star", &[])
        .expect("the agent pack compiles (the profile is not installed here)");
    let bindings = bindings();
    let (_, capsule) = assemble_capsule(
        &lowered_named(&program, "verdict"),
        bindings.occurrence,
        stage_named(&program, "verdict"),
        &bindings.directive,
        &stage_command(),
        bindings.environment,
        bindings.platform,
        bindings.work_tree,
        bindings.budgets,
        Some(ArtifactId(hash(7))),
        None,
    )
    .expect("a declared agent stage assembles");

    let kata_types::execution_contract::CapsuleProcess::Agent(turn) = capsule.process() else {
        panic!(
            "an agent stage's process arm is `Agent`, got {:?}",
            capsule.process()
        );
    };
    assert_eq!(
        turn.reasoning_effort.as_deref(),
        Some("low"),
        "the node's declared effort reaches the turn spec"
    );
}

/// **The refused set at the assembly door**, in the same names the CHECK
/// answers with: an uninstalled agent label (`adapter_undeclared`), an adapter
/// label that names no kind — a removed vendor adapter's included —
/// (`adapter_unqualified`), and a missing prompt artifact (a wiring defect,
/// refused rather than a turn naming nothing).
#[test]
fn an_agent_stage_is_refused_by_name_at_assembly_for_each_unqualified_case() {
    let program = compile_starlark_execution_program(AGENT_PACK, "agent-pack.star", &[])
        .expect("the agent pack compiles");
    let bindings = bindings();
    let prompt = ArtifactId(hash(7));
    let try_assemble = |prompt: Option<ArtifactId>| {
        assemble_capsule(
            &lowered_named(&program, "verdict"),
            bindings.occurrence,
            stage_named(&program, "verdict"),
            &bindings.directive,
            &stage_command(),
            bindings.environment,
            bindings.platform,
            bindings.work_tree,
            bindings.budgets,
            prompt,
            None,
        )
    };

    // No `[agents.codex]` at all — the uninstalled process's empty map.
    kata_types::node_profile::install_node_agents(std::collections::BTreeMap::new());
    let refusal = try_assemble(Some(prompt))
        .expect_err("an undeclared label is refused")
        .to_string();
    assert!(
        refusal.contains("adapter_undeclared") && refusal.contains("codex"),
        "refused by name, naming the label: {refusal}"
    );

    // An adapter label this build has no contract for.
    for adapter in ["imaginary_adapter", "codex_app_server"] {
        install_agents(Some(adapter));
        let refusal = try_assemble(Some(prompt))
            .expect_err("an unqualified adapter is refused")
            .to_string();
        assert!(
            refusal.contains("adapter_unqualified") && refusal.contains(adapter),
            "refused by name, naming the adapter: {refusal}"
        );
    }

    // A prompt artifact the caller never published.
    install_agents(Some("nanocode_openai"));
    let refusal = try_assemble(None)
        .expect_err("a missing prompt artifact is refused")
        .to_string();
    assert!(
        refusal.contains("prompt"),
        "the wiring defect is named: {refusal}"
    );
}

/// One `[agents.codex]` block declaring nanocode kind `adapter` and an `env`,
/// under the kind's first credential: kata's ChatGPT login for
/// `nanocode_openai`, an `env:` API key for `nanocode_anthropic`.
fn install_nanocode_agent(adapter: &str, env: std::collections::BTreeMap<String, String>) {
    let (mode, source) = match adapter {
        "nanocode_openai" => ("subscription", "kata_login"),
        _ => ("api_key", "env:ANTHROPIC_API_KEY"),
    };
    kata_types::node_profile::install_node_agents(std::collections::BTreeMap::from([(
        "codex".to_owned(),
        kata_types::config::AgentBackendConfig::Harness {
            model: None,
            reasoning_effort: None,
            adapter: Some(adapter.to_owned()),
            credential: Some(kata_types::config::AgentCredentialDecl {
                mode: mode.to_owned(),
                source: source.to_owned(),
            }),
            env,
        },
    )]));
}

/// **A nanocode block that declares no credential is refused at assembly,
/// `credential_undeclared`, by the CHECK's own name.** A hand-built stage can
/// reach this door unchecked; the embedded harness runs in the worker on the
/// credential its block declares and nothing else, so assembly mints no turn
/// the worker could only refuse, and names the `kata login` command.
///
/// **Would red if:** assembly minted a nanocode turn carrying no credential
/// (watched: it did, and the worker refused the turn after launch).
#[test]
fn a_nanocode_block_with_no_credential_is_refused_at_assembly() {
    let program = compile_starlark_execution_program(AGENT_PACK, "agent-pack.star", &[])
        .expect("the agent pack compiles");
    let bindings = bindings();
    for (adapter, login) in [
        ("nanocode_openai", "`kata login openai`"),
        ("nanocode_anthropic", "`kata login anthropic --api-key`"),
    ] {
        kata_types::node_profile::install_node_agents(std::collections::BTreeMap::from([(
            "codex".to_owned(),
            kata_types::config::AgentBackendConfig::Harness {
                model: None,
                reasoning_effort: None,
                adapter: Some(adapter.to_owned()),
                credential: None,
                env: std::collections::BTreeMap::new(),
            },
        )]));
        let refusal = assemble_capsule(
            &lowered_named(&program, "verdict"),
            bindings.occurrence,
            stage_named(&program, "verdict"),
            &bindings.directive,
            &stage_command(),
            bindings.environment,
            bindings.platform,
            bindings.work_tree,
            bindings.budgets,
            Some(ArtifactId(hash(7))),
            None,
        )
        .expect_err(&format!("`{adapter}` with no credential assembles"))
        .to_string();
        assert!(
            refusal.contains("credential_undeclared:")
                && refusal.contains(&format!("adapter `{adapter}`"))
                && refusal.contains(login),
            "{adapter}: refused by the CHECK's name, naming its login: {refusal}"
        );
    }
}

/// **The nanocode kinds at the assembly door: the kind's launch, and nothing
/// the kind fixes.** A hand-built stage can reach assembly unchecked, so this
/// door judges a nanocode block as the CHECK does: it assembles an `Agent` turn
/// of that kind (the capsule's init is `kata-toolhost`, fixed by the kind),
/// carrying its credential reference, in an `Offline` capsule (the model
/// traffic leaves from the process hosting the worker, so the capsule opens no
/// endpoint of its own). An `env.HOME` is refused
/// `capsule_agent_env_channel_owned` (kata renders the capsule's `HOME` for a
/// toolhost kind), by the CHECK's own name.
///
/// **Would red if:** assembly minted a turn the worker refuses, a turn of
/// another kind, or an endpoint into a nanocode capsule.
#[test]
fn a_nanocode_kind_assembles_its_fixed_launch_and_refuses_what_the_kind_fixes() {
    let program = compile_starlark_execution_program(AGENT_PACK, "agent-pack.star", &[])
        .expect("the agent pack compiles");
    let bindings = bindings();
    let assemble = || {
        assemble_capsule(
            &lowered_named(&program, "verdict"),
            bindings.occurrence,
            stage_named(&program, "verdict"),
            &bindings.directive,
            &stage_command(),
            bindings.environment,
            bindings.platform,
            bindings.work_tree,
            bindings.budgets,
            Some(ArtifactId(hash(7))),
            None,
        )
    };
    for (adapter, kind) in [
        (
            "nanocode_openai",
            kata_types::agent::AdapterKind::NanocodeOpenai,
        ),
        (
            "nanocode_anthropic",
            kata_types::agent::AdapterKind::NanocodeAnthropic,
        ),
    ] {
        install_nanocode_agent(adapter, std::collections::BTreeMap::default());
        let (_, capsule) = assemble().unwrap_or_else(|refusal| panic!("{adapter}: {refusal}"));
        let kata_types::execution_contract::CapsuleProcess::Agent(turn) = capsule.process() else {
            panic!("{adapter}: the process arm is Agent");
        };
        assert_eq!(turn.adapter, kind, "{adapter}: the turn's kind");
        assert!(turn.credential.is_some(), "{adapter}: the credential mints");
        assert_eq!(
            capsule.network(),
            &kata_types::execution_contract::CapsuleNetwork::Offline,
            "{adapter}: the capsule opens no endpoint of its own"
        );
        install_nanocode_agent(
            adapter,
            std::collections::BTreeMap::from([("HOME".to_owned(), "/tmp".to_owned())]),
        );
        let refusal = assemble()
            .expect_err(&format!(
                "{adapter}, a declared env.HOME: assembly minted it"
            ))
            .to_string();
        assert!(
            refusal.contains("capsule_agent_env_channel_owned")
                && !refusal.contains("adapter_unqualified"),
            "{adapter}, a declared env.HOME: refused by name: {refusal}"
        );
    }
}

/// The node's `credential` and `env` mint onto the turn — the credential as a
/// REFERENCE (mode + source kind, never a value) and the env as the declared
/// non-secret pairs.
#[test]
fn a_declared_credential_and_env_mint_onto_the_turn() {
    let mut agents = std::collections::BTreeMap::new();
    agents.insert(
        "codex".to_owned(),
        kata_types::config::AgentBackendConfig::Harness {
            model: None,
            reasoning_effort: None,
            adapter: Some("nanocode_openai".to_owned()),
            credential: Some(kata_types::config::AgentCredentialDecl {
                mode: "subscription".to_owned(),
                source: "kata_login".to_owned(),
            }),
            env: std::collections::BTreeMap::from([("TERM".to_owned(), "dumb".to_owned())]),
        },
    );
    kata_types::node_profile::install_node_agents(agents);
    let program = compile_starlark_execution_program(AGENT_PACK, "agent-pack.star", &[])
        .expect("the agent pack compiles");
    let bindings = bindings();
    let prompt = ArtifactId(hash(7));
    let (_, capsule) = assemble_capsule(
        &lowered_named(&program, "verdict"),
        bindings.occurrence,
        stage_named(&program, "verdict"),
        &bindings.directive,
        &stage_command(),
        bindings.environment,
        bindings.platform,
        bindings.work_tree,
        bindings.budgets,
        Some(prompt),
        None,
    )
    .expect("a declared agent stage assembles");
    let kata_types::execution_contract::CapsuleProcess::Agent(turn) = capsule.process() else {
        panic!("the process arm is Agent");
    };
    let reference = turn.credential.as_ref().expect("the credential mints");
    assert_eq!(
        reference.mode,
        kata_types::metering::CredentialMode::Subscription
    );
    assert_eq!(
        reference.source,
        kata_types::execution_contract::CredentialSource::KataLogin
    );
    assert_eq!(
        turn.env.get("TERM").map(smol_str::SmolStr::as_str),
        Some("dumb")
    );
    // And the pair is identity: the SAME stage under an env-less node is a
    // different capsule.
    let mut twin = turn.clone();
    twin.env.clear();
    let other = kata_types::execution_contract::Capsule::new(
        capsule.occurrence(),
        capsule.action(),
        capsule.environment(),
        capsule.platform(),
        capsule.inputs().to_vec(),
        kata_types::execution_contract::CapsuleProcess::Agent(twin),
        capsule.network().clone(),
        None,
        capsule.budgets(),
        None,
    )
    .expect("the twin is well formed");
    assert_ne!(
        capsule.id(),
        other.id(),
        "the declared env folds into identity"
    );
}

/// A SHELL stage's authored `net = "host"` is the node's `[node] egress_allow`
/// — the capsule's network arm is `Egress` over exactly the installed set
/// (the worker CONNECT proxy is the only route out), and a DIFFERENT installed
/// set is a different capsule id. The defense-in-depth twin of the CHECK door:
/// an `Egress` whose installed set is EMPTY is refused by `Capsule::new` as
/// `capsule_egress_allowlist_empty` even when assembly is reached without the
/// `egress_undeclared` door having run.
#[test]
fn a_host_net_shell_stage_mints_egress_over_the_nodes_allowlist() {
    use kata_types::execution_contract::{CapsuleNetwork, EgressAuthority};
    let allow = std::collections::BTreeSet::from([
        EgressAuthority::from_authority_str("api.example.com:443").expect("an authority parses"),
        EgressAuthority::from_authority_str("mirror.corp.example:8443")
            .expect("an authority parses"),
    ]);
    kata_types::node_profile::install_node_egress_allow(allow.clone());
    kata_types::node_profile::mark_node_installed();
    let program = compile_starlark_execution_program(
        "probe = stage(id = \"probe\", agent = \"shell\", run = \"getent hosts x\", \
         sandbox = \"s\", timeout_ms = 30000)\n\
         workflow(\"eg\", root = [probe], sandbox_profiles = \
         {\"s\": sandbox_profile(workspace = \"scratch\", net = \"host\")})\n",
        "eg.star",
        &[],
    )
    .expect("a declared authority admits the host-net stage");
    let mut egress = bindings();
    egress.directive.net = NetPolicy::Host;
    let (_, capsule) = assemble_capsule(
        &lowered_named(&program, "probe"),
        egress.occurrence,
        stage_named(&program, "probe"),
        &egress.directive,
        &stage_command(),
        egress.environment,
        egress.platform,
        egress.work_tree,
        egress.budgets,
        None,
        None,
    )
    .expect("a host-net shell stage assembles over the node's allowlist");
    assert_eq!(
        capsule.network(),
        &CapsuleNetwork::Egress { allowlist: allow },
        "the capsule's only route out is exactly the node's declared set"
    );

    // IDENTITY: the same stage over a different installed set is a different
    // capsule — the allowlist is identity, not ambient.
    let other_set = std::collections::BTreeSet::from([EgressAuthority::from_authority_str(
        "other.example.com:443",
    )
    .unwrap()]);
    kata_types::node_profile::install_node_egress_allow(other_set);
    let (_, other) = assemble_capsule(
        &lowered_named(&program, "probe"),
        egress.occurrence,
        stage_named(&program, "probe"),
        &egress.directive,
        &stage_command(),
        egress.environment,
        egress.platform,
        egress.work_tree,
        egress.budgets,
        None,
        None,
    )
    .expect("the other allowlist assembles too");
    assert_ne!(
        capsule.id(),
        other.id(),
        "the node's allowlist folds into the capsule id"
    );

    // And an EMPTY installed set is refused at the capsule boundary, naming
    // the refusal the `egress_undeclared` CHECK door states earlier.
    kata_types::node_profile::install_node_egress_allow(std::collections::BTreeSet::new());
    let refusal = assemble_capsule(
        &lowered_named(&program, "probe"),
        egress.occurrence,
        stage_named(&program, "probe"),
        &egress.directive,
        &stage_command(),
        egress.environment,
        egress.platform,
        egress.work_tree,
        egress.budgets,
        None,
        None,
    )
    .expect_err("an empty allowlist is `Offline` spelled wrong, not an egress")
    .to_string();
    assert!(
        refusal.contains("capsule_egress_allowlist_empty"),
        "the capsule's own refusal, by name: {refusal}"
    );
    kata_types::node_profile::mark_node_installed();
}

/// **An agent stage's allowlist is the node's `[node] egress_allow`, under
/// `net = "host"`, and nothing under `net = "offline"`.** The model calls leave
/// from the process hosting the worker, so the capsule's own reach is exactly
/// what the stage authors: `host` mints `Egress` over the node's authorities
/// verbatim — the same set the CHECK door requires non-empty — and `offline`
/// mints `Offline`, with no authority of the node's in it.
#[test]
fn a_host_net_agent_stages_allowlist_is_the_nodes_egress_allow() {
    use kata_types::execution_contract::{CapsuleNetwork, EgressAuthority};
    install_agents(Some("nanocode_openai"));
    kata_types::node_profile::install_node_egress_allow(std::collections::BTreeSet::from([
        EgressAuthority::from_authority_str("intranet.corp.example:443")
            .expect("an authority parses"),
    ]));
    let program = compile_starlark_execution_program(AGENT_PACK, "agent-pack.star", &[])
        .expect("the agent pack compiles");

    let mint = |net: NetPolicy| {
        let mut bindings = bindings();
        bindings.directive.net = net;
        let (_, capsule) = assemble_capsule(
            &lowered_named(&program, "verdict"),
            bindings.occurrence,
            stage_named(&program, "verdict"),
            &bindings.directive,
            &stage_command(),
            bindings.environment,
            bindings.platform,
            bindings.work_tree,
            bindings.budgets,
            Some(ArtifactId(hash(7))),
            None,
        )
        .expect("a credentialed agent stage assembles");
        capsule.network().clone()
    };

    let CapsuleNetwork::Egress { allowlist } = mint(NetPolicy::Host) else {
        panic!("`net = \"host\"` mints Egress");
    };
    let hosts: Vec<String> = allowlist
        .iter()
        .map(|a| format!("{}:{}", a.host(), a.port()))
        .collect();
    assert_eq!(
        hosts,
        ["intranet.corp.example:443"],
        "exactly the node's set"
    );
    assert_eq!(
        mint(NetPolicy::Offline),
        CapsuleNetwork::Offline,
        "`net = \"offline\"` adds no node authority"
    );

    kata_types::node_profile::install_node_egress_allow(std::collections::BTreeSet::new());
}

/// A `workspace = "scratch"` capsule maps the canonical EMPTY tree at `/work`
/// with `ReadWriteScratch` access — the access tag is the contract fact the
/// authorization's `/work` role check, the adoption's `scratch_delta_*` keys
/// and the apply sweep's silence all key on — never the walked `work_tree` a
/// workspace mapping would name.
#[test]
fn a_scratch_directive_maps_the_empty_tree_read_write_scratch() {
    let program = program();
    let mut scratch = bindings();
    scratch.directive.fs = FsPolicy::Scratch;
    let (_, capsule) = assemble(&program, &scratch).expect("a scratch directive assembles");
    let work = capsule
        .inputs()
        .iter()
        .find(|mapping| mapping.guest_path.as_str() == "/work")
        .expect("/work is mapped");
    assert_eq!(
        work.access,
        GuestAccess::ReadWriteScratch,
        "the scratch /work carries its own access tag"
    );
    assert_eq!(
        work.artifact,
        empty_tree_artifact().unwrap().id(),
        "a scratch /work is the canonical empty tree, not the walked head"
    );
    // The twin arm: a workspace directive maps the SAME path ReadWrite over
    // the execution's head — the access tag, not the guest path, is the
    // contract fact.
    let mut workspace = bindings();
    workspace.directive.fs = FsPolicy::WorkspaceRw;
    let (_, twin) = assemble(&program, &workspace).expect("a workspace directive assembles");
    let twin_work = twin
        .inputs()
        .iter()
        .find(|mapping| mapping.guest_path.as_str() == "/work")
        .expect("/work is mapped");
    assert_eq!(twin_work.access, GuestAccess::ReadWrite);
    assert_eq!(twin_work.artifact, workspace.work_tree);
}

// ---------------------------------------------------------------------------
// The `reads=` work view under `oci`
// ---------------------------------------------------------------------------

/// The fixture shell pack with a declared `reads=` closure and a declared
/// `produces_files=` — the confined stage the view mints on.
const READS_PACK: &str = "a = stage(id = \"a\", run = \":\", agent = \"shell\", \
    sandbox = sandbox_profile(workspace = \"rw\"), \
    reads = [\"src\"], produces_files = [\"kata-out/check.log\"], timeout_ms = 30000)\n\
     workflow(\"assembly\", root = [a])\n";

/// A pack identical to [`PACK`] but for one `reads=` line — the stage pair
/// whose only difference is the closure declaration.
const READS_ONLY_PACK: &str = "a = stage(id = \"a\", run = \":\", agent = \"shell\", \
    reads = [\"src\"], timeout_ms = 30000)\n\
     workflow(\"assembly\", root = [a])\n";

/// **A `reads=`-declaring stage assembles a `CapsuleWorkView` over its own
/// closure.** The stage is the fixture's deterministic shell (the same class
/// `should_confine_to_declared_inputs` admits), the workspace is `rw` in the
/// fixture directive, so the include list is the shim's union: the declared
/// read `src` plus the declared output `kata-out/check.log` — a write the
/// container must reach cannot live outside the view it materializes.
///
/// **Would red if:** the mint dropped `produces_files` under `rw` (the include
/// would name `src` alone), minted on `reads` alone without the confinement
/// predicate, or skipped the sort/dedup (the order below is the mint's).
#[test]
fn a_reads_declaring_stage_assembles_its_declared_work_view() {
    let program = compile_starlark_execution_program(READS_PACK, "reads.star", &[])
        .expect("the reads pack compiles");
    let (_, capsule) = assemble(&program, &bindings()).expect("assembly succeeds");
    let view = capsule
        .work_view()
        .expect("a confined reads stage carries the view");
    assert_eq!(
        view.include,
        [SmolStr::new("kata-out/check.log"), SmolStr::new("src")],
        "the include list is reads ∪ produces_files, mint-sorted"
    );
}

/// **The twin arm: a read-only workspace carries only the reads.** Under
/// `ro` a `produces_files` closure is a grant to nothing — the write closure
/// is omitted whenever the fs policy offers no writable workspace.
///
/// **Would red if:** the `WorkspaceRo` arm were dropped (the include would
/// name `kata-out/check.log` too).
#[test]
fn a_read_only_workspace_view_names_the_reads_only() {
    let program = compile_starlark_execution_program(READS_PACK, "reads.star", &[])
        .expect("the reads pack compiles");
    let mut ro = bindings();
    ro.directive.fs = FsPolicy::WorkspaceRo;
    let (_, capsule) = assemble(&program, &ro).expect("a read-only stage assembles");
    let view = capsule
        .work_view()
        .expect("the confined stage still carries a view");
    assert_eq!(view.include, [SmolStr::new("src")]);
}

/// **No `reads=` means no view** — `reads = "whole-tree"` compiles to the
/// empty closure, and an empty closure mints `None`, so the whole head maps
/// whole (and the capsule keeps its unconfined shape for every stage that
/// never confined).
///
/// **Would red if:** an empty include minted `Some` (the materializer would
/// write nothing), or `reads = "whole-tree"` minted a root-covering view the
/// compiler already said "declared nothing" about.
#[test]
fn a_stage_without_reads_assembles_no_work_view() {
    let (_, capsule) = assemble(&program(), &bindings()).expect("assembly succeeds");
    assert!(
        capsule.work_view().is_none(),
        "an empty closure mints no view — the whole head maps"
    );
    // The scratch arm: a scratch workspace's `/work` is the canonical empty
    // tree and the empty closure mints no view over it either.
    let mut scratch = bindings();
    scratch.directive.fs = FsPolicy::Scratch;
    let (_, capsule) = assemble(&program(), &scratch).expect("a scratch stage assembles");
    assert!(capsule.work_view().is_none());
}

/// **Two stages differing only in `reads=` mint different capsule ids** — the
/// view is folded into the capsule id like every field, because two capsules
/// that show the action different trees are different stages: a reuse that
/// adopted the unconfined capsule's result for the confined one would be a
/// read outside the declared closure.
///
/// **Would red if:** the view dropped out of the hash (the two capsules would
/// share an id and a reuse key).
#[test]
fn two_stages_differing_only_in_reads_mint_different_capsule_ids() {
    let (_, unconfined) = assemble(&program(), &bindings()).expect("assembly succeeds");
    let confined_program = compile_starlark_execution_program(READS_ONLY_PACK, "reads.star", &[])
        .expect("the reads pack compiles");
    let (_, confined) = assemble(&confined_program, &bindings()).expect("assembly succeeds");
    assert_ne!(
        confined.id(),
        unconfined.id(),
        "the declared closure is part of what the capsule IS"
    );
    assert_ne!(
        confined.reuse_key(&kata_workflow::test_harness::oci_rig_executor_term()),
        unconfined.reuse_key(&kata_workflow::test_harness::oci_rig_executor_term()),
        "a confined stage must not adopt an unconfined capsule's result"
    );
}

/// **The shipped `agent-change` pack's `edit` profile assembles offline: the
/// node's `[node] egress_allow` is out of the agent's reach.** The pack's
/// `implement` stage selects the `edit` profile, which authors `net =
/// "offline"` over a writable workspace. Assembled on a node that declares an
/// `egress_allow` authority, with `[agents.change-agent]` a credentialed
/// nanocode agent, its capsule is `Offline`: the profile adds nothing of the
/// node's. The same stage under `net = "host"` would reach the node's
/// authority, which is what the profile keeps out.
///
/// **Would red if:** the pack's `edit` profile went back to `net = "host"`.
#[test]
fn the_agent_change_edit_profile_assembles_offline() {
    const NODE_AUTHORITY: &str = "registry.corp.example:443";
    let pack = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../workflows/std/agent-change.star"),
    )
    .expect("the shipped pack reads");
    let program = compile_starlark_execution_program(&pack, "agent-change.star", &[])
        .expect("the shipped pack compiles");
    let implement = stage_named(&program, "implement");
    let Some(kata_types::sandbox::SandboxRef::Named(profile)) = implement.policies.sandbox.as_ref()
    else {
        panic!(
            "`implement` names a sandbox profile: {:?}",
            implement.policies.sandbox
        );
    };
    let edit = program
        .sandbox_profiles
        .get(profile.as_str())
        .expect("the pack declares the profile `implement` names");
    assert_eq!(
        edit.net,
        NetPolicy::Offline,
        "the `{profile}` profile is offline"
    );
    assert_eq!(
        edit.fs,
        FsPolicy::WorkspaceRw,
        "the `{profile}` profile writes /work"
    );

    let mut agents = std::collections::BTreeMap::new();
    agents.insert(
        "change-agent".to_owned(),
        kata_types::config::AgentBackendConfig::Harness {
            model: None,
            reasoning_effort: None,
            adapter: Some("nanocode_openai".to_owned()),
            credential: Some(kata_types::config::AgentCredentialDecl {
                mode: "subscription".to_owned(),
                source: "kata_login".to_owned(),
            }),
            env: std::collections::BTreeMap::new(),
        },
    );
    kata_types::node_profile::install_node_agents(agents);
    kata_types::node_profile::install_node_egress_allow(std::collections::BTreeSet::from([
        kata_types::execution_contract::EgressAuthority::from_authority_str(NODE_AUTHORITY)
            .expect("a valid authority"),
    ]));
    let bindings = bindings();
    let network_under = |net: NetPolicy| {
        let directive = SandboxDirective {
            fs: edit.fs.clone(),
            net,
            ..fixture_directive()
        };
        let (_, capsule) = assemble_capsule(
            &lowered_named(&program, "implement"),
            bindings.occurrence,
            implement,
            &directive,
            &stage_command(),
            bindings.environment,
            bindings.platform,
            bindings.work_tree,
            bindings.budgets,
            Some(ArtifactId(hash(7))),
            None,
        )
        .expect("the shipped implement stage assembles");
        capsule.network().clone()
    };
    assert_eq!(
        network_under(edit.net.clone()),
        kata_types::execution_contract::CapsuleNetwork::Offline,
        "the offline edit profile reaches nothing of the node's"
    );
    assert!(
        matches!(
            network_under(NetPolicy::Host),
            kata_types::execution_contract::CapsuleNetwork::Egress { allowlist }
                if allowlist.iter().any(|a| format!("{}:{}", a.host(), a.port()) == NODE_AUTHORITY)
        ),
        "the counterfactual: `net = \"host\"` reaches the node's authority"
    );
}

// ---------------------------------------------------------------------------
// T11: the allowlist rule and the posture every face states
// ---------------------------------------------------------------------------

/// The node's own authority every cell installs beside the agent's reach — the
/// one a `net = "offline"` agent capsule must NOT carry.
const NODE_AUTHORITY: &str = "intranet.corp.example:443";

fn node_allow() -> std::collections::BTreeSet<kata_types::execution_contract::EgressAuthority> {
    std::collections::BTreeSet::from([
        kata_types::execution_contract::EgressAuthority::from_authority_str(NODE_AUTHORITY)
            .expect("an authority parses"),
    ])
}

fn spelled(network: &kata_types::execution_contract::CapsuleNetwork) -> Vec<String> {
    match network {
        kata_types::execution_contract::CapsuleNetwork::Offline => Vec::new(),
        kata_types::execution_contract::CapsuleNetwork::Egress { allowlist } => allowlist
            .iter()
            .map(|authority| format!("{}:{}", authority.host(), authority.port()))
            .collect(),
    }
}

/// **The one allowlist rule, per authored `net`, names EXACTLY what each
/// capsule gets.** Authored `net = "offline"` is `Offline` — an agent's model
/// traffic leaves from the process hosting the worker, so no vendor endpoint
/// is ever minted into a capsule — and `net = "host"` is `Egress` over the
/// node's `egress_allow`, with the posture every face states labelling each.
///
/// **Would red if:** the builder minted anything under `offline` (an authored
/// posture silently widened), or anything beyond the node's set under `host`.
#[test]
fn the_allowlist_rule_names_exactly_what_each_net_grants() {
    use kata_program::capsule_rules::capsule_network_for;
    use kata_types::execution_contract::CapsuleNetworkPosture;

    let mint = |net: NetPolicy| {
        let network = capsule_network_for(&net, &node_allow());
        let posture = CapsuleNetworkPosture::of(&network);
        (spelled(&network), posture)
    };

    let (allowlist, posture) = mint(NetPolicy::Offline);
    assert!(allowlist.is_empty(), "{allowlist:?}");
    assert_eq!(posture, CapsuleNetworkPosture::Offline);
    assert_eq!(posture.label(), "offline");

    let (allowlist, posture) = mint(NetPolicy::Host);
    assert_eq!(allowlist, [NODE_AUTHORITY]);
    assert_eq!(
        posture,
        CapsuleNetworkPosture::Egress {
            allowlist: vec![NODE_AUTHORITY.to_owned()]
        }
    );
    assert_eq!(posture.label(), "egress");
}

/// **What `kata check` says a stage's capsule gets is what assembly mints for
/// it** — the preflight posture and the assembled capsule's network, over one
/// installed node whose `egress_allow` names [`NODE_AUTHORITY`], for an agent
/// stage authored `net = "offline"`.
///
/// The posture is read off the preflight the check builds; the capsule off
/// `assemble_capsule`'s own result; both are `Offline`, the node's authority in
/// neither.
#[test]
fn the_check_posture_of_an_offline_agent_stage_is_the_assembled_capsules() {
    use kata_program::preflight::CheckedCapsuleNetwork;
    use kata_types::execution_contract::{CapsuleNetwork, CapsuleNetworkPosture};

    kata_types::node_profile::mark_node_installed();
    let mut agents = std::collections::BTreeMap::new();
    agents.insert(
        "codex".to_owned(),
        kata_program::test_harness::rig_agent_backend_config(),
    );
    kata_types::node_profile::install_node_agents(agents);
    kata_types::node_profile::install_node_egress_allow(node_allow());
    let source = "verdict = stage(\n\
         \x20   id = \"verdict\",\n\
         \x20   agent = \"codex\",\n\
         \x20   prompt = \"review the diff\",\n\
         \x20   sandbox = \"ro\",\n\
         )\n\
         probe = stage(id = \"probe\", agent = \"shell\", run = \"true\", sandbox = \"ro\", depends_on = [\"verdict\"])\n\
         workflow(\"offline-agent\", root = [verdict], sandbox_profiles = \
         {\"ro\": sandbox_profile(workspace = \"ro\", net = \"offline\")})\n";
    let artifact = kata_program::preflight::build_starlark_workflow_compiled_artifact(
        source,
        "offline-agent.star",
        &[],
    )
    .expect("the pack checks on an installed node");
    let posture_of = |name: &str| {
        artifact
            .preflight
            .stages
            .iter()
            .find(|stage| stage.stage == name)
            .unwrap_or_else(|| panic!("no preflight stage {name}"))
            .capsule_networks
            .clone()
    };
    assert_eq!(
        posture_of("verdict"),
        vec![CheckedCapsuleNetwork {
            agent: Some("codex".to_owned()),
            network: CapsuleNetworkPosture::Offline,
        }],
        "the check names the offline agent capsule offline"
    );
    assert_eq!(
        posture_of("probe"),
        vec![CheckedCapsuleNetwork {
            agent: None,
            network: CapsuleNetworkPosture::Offline,
        }]
    );

    let program = &artifact.execution_program;
    let mut bindings = bindings();
    bindings.directive.net = NetPolicy::Offline;
    let (_, capsule) = assemble_capsule(
        &lowered_named(program, "verdict"),
        bindings.occurrence,
        stage_named(program, "verdict"),
        &bindings.directive,
        &stage_command(),
        bindings.environment,
        bindings.platform,
        bindings.work_tree,
        bindings.budgets,
        Some(ArtifactId(hash(7))),
        None,
    )
    .expect("the agent stage assembles");
    assert_eq!(
        capsule.network(),
        &CapsuleNetwork::Offline,
        "the assembled offline agent capsule is Offline"
    );
    kata_types::node_profile::install_node_egress_allow(std::collections::BTreeSet::new());
}

/// **With no node installed the check describes no capsule network** — the
/// agent block, its credential and the node's `egress_allow` are deferred to
/// admission, so a posture here would be a guess.
#[test]
fn a_check_without_a_node_describes_no_capsule_network() {
    let source = "verdict = stage(id = \"verdict\", agent = \"codex\", prompt = \"review\")\n\
         workflow(\"no-node\", root = [verdict])\n";
    let artifact = kata_program::preflight::build_starlark_workflow_compiled_artifact(
        source,
        "no-node.star",
        &[],
    )
    .expect("the pack checks with its node facts deferred");
    assert!(
        !artifact.deferred_node_facts.is_empty(),
        "the agent facts are deferred: {:?}",
        artifact.deferred_node_facts
    );
    assert!(
        artifact
            .preflight
            .stages
            .iter()
            .all(|stage| stage.capsule_networks.is_empty()),
        "no stage is described without a node: {:?}",
        artifact.preflight.stages
    );
}

/// **A fallback panel's every member is described** — `agent = ["codex",
/// "nano"]` under `net = "host"` on a node where both members are
/// `nanocode_openai` blocks under kata's own login. A failure retry runs the
/// stage under the fallback member; the check must name that capsule too,
/// member by member, primary first.
///
/// Read out of the SERIALIZED preflight (the bytes `--format json` and
/// `GET /workflows/{name}` serve), compared to literal sets.
///
/// **Would red if:** the check described only the primary member (the
/// fallback's reach unnamed on every check face).
#[test]
fn the_check_names_every_panel_members_capsule_network() {
    kata_types::node_profile::mark_node_installed();
    let nano = kata_types::config::AgentBackendConfig::Harness {
        model: None,
        reasoning_effort: None,
        adapter: Some("nanocode_openai".to_owned()),
        credential: Some(kata_types::config::AgentCredentialDecl {
            mode: "subscription".to_owned(),
            source: "kata_login".to_owned(),
        }),
        env: std::collections::BTreeMap::new(),
    };
    let mut agents = std::collections::BTreeMap::new();
    agents.insert(
        "codex".to_owned(),
        kata_program::test_harness::rig_agent_backend_config(),
    );
    agents.insert("nano".to_owned(), nano);
    kata_types::node_profile::install_node_agents(agents);
    kata_types::node_profile::install_node_egress_allow(node_allow());
    let source = "review = stage(id = \"review\", agent = [\"codex\", \"nano\"], \
         prompt = \"review it\", sandbox = \"ro\")\n\
         workflow(\"panel-host\", root = [review], sandbox_profiles = \
         {\"ro\": sandbox_profile(workspace = \"ro\", net = \"host\")})\n";
    let artifact = kata_program::preflight::build_starlark_workflow_compiled_artifact(
        source,
        "panel-host.star",
        &[],
    )
    .expect("the panel pack checks on the installed node");
    let review = artifact
        .preflight
        .stages
        .iter()
        .find(|stage| stage.stage == "review")
        .expect("the review stage is in the preflight");
    let served = serde_json::to_value(review).expect("the preflight row serializes");
    assert_eq!(
        served["capsule_networks"],
        serde_json::json!([
            {
                "agent": "codex",
                "network": {"posture": "egress", "allowlist": [NODE_AUTHORITY]},
            },
            {
                "agent": "nano",
                "network": {"posture": "egress", "allowlist": [NODE_AUTHORITY]},
            },
        ]),
        "every panel member's capsule network, primary first: {served}"
    );
    kata_types::node_profile::install_node_egress_allow(std::collections::BTreeSet::new());
}

/// A pack whose `verdict` stage declares a `produces=` contract, compiled
/// through the real DSL, so the schema on the turn comes from the same lowered
/// `output_schema` the runner validates against.
const CONTRACT_PACK: &str = r#"
_VERDICT = contract("Verdict", {
    "verdict": field(enum("approve", "comment")),
    "summary": field(string(max_length = 400)),
    "note": field("string", required = False),
})
verdict = stage(
    id = "verdict",
    agent = "codex",
    prompt = "review the diff",
    produces = _VERDICT,
)
workflow("contract-pack", root = [verdict])
"#;

/// The typed-routing idiom: a variant whose arms are empty contracts.
const ROUTING_CONTRACT_PACK: &str = r#"
verdict = stage(
    id = "verdict",
    agent = "codex",
    prompt = "ship or hold",
    produces = contract("Decision", {
        "verdict": field(variant({
            "ship": contract("Ship", {}),
            "hold": contract("Hold", {}),
        })),
    }),
)
workflow("routing-contract-pack", root = [verdict])
"#;

/// A contract kata admits (32 fields per object, three levels) whose 33 824
/// properties are past strict mode's 5000 — a shape strict mode cannot state.
const OVERSIZED_CONTRACT_PACK: &str = r#"
_LEAF = contract("Leaf", {"f%d" % i: field("bool") for i in range(32)})
_MID = contract("Mid", {"m%d" % i: field(_LEAF) for i in range(32)})
verdict = stage(
    id = "verdict",
    agent = "codex",
    prompt = "fill the table",
    produces = contract("Top", {"t%d" % i: field(_MID) for i in range(32)}),
)
workflow("oversized-contract-pack", root = [verdict])
"#;

fn assembled_turn(pack: &str, adapter: &str) -> kata_types::execution_contract::AgentTurnSpec {
    install_agents(Some(adapter));
    let program = compile_starlark_execution_program(pack, "contract-pack.star", &[])
        .expect("the contract pack compiles");
    let bindings = bindings();
    let (_, capsule) = assemble_capsule(
        &lowered_named(&program, "verdict"),
        bindings.occurrence,
        stage_named(&program, "verdict"),
        &bindings.directive,
        &stage_command(),
        bindings.environment,
        bindings.platform,
        bindings.work_tree,
        bindings.budgets,
        Some(ArtifactId(hash(7))),
        None,
    )
    .expect("a declared agent stage assembles");
    let kata_types::execution_contract::CapsuleProcess::Agent(turn) = capsule.process() else {
        panic!("an agent stage's process arm is `Agent`");
    };
    turn.clone()
}

/// **A `nanocode_openai` stage's `produces=` contract reaches its turn as the
/// strict schema** — the expected value written out from the DSL source above:
/// every property required, the optional `note` nullable, the length bound
/// relaxed into the description, `additionalProperties: false`.
#[test]
fn an_agent_stage_with_a_contract_assembles_the_strict_output_schema() {
    let turn = assembled_turn(CONTRACT_PACK, "nanocode_openai");
    assert_eq!(
        turn.output_schema,
        Some(serde_json::json!({
            "type": "object",
            "properties": {
                "verdict": {"type": "string", "enum": ["approve", "comment"]},
                "summary": {"type": "string", "description": "kata enforces: maxLength 400"},
                "note": {"anyOf": [{"type": "string"}, {"type": "null"}]},
            },
            "required": ["note", "summary", "verdict"],
            "additionalProperties": false,
        }))
    );
}

/// **The routing idiom's empty arms render as the closed empty object** — the
/// expected value written out from the DSL source above.
#[test]
fn an_agent_stage_routing_on_empty_contracts_assembles_the_closed_empty_arms() {
    let turn = assembled_turn(ROUTING_CONTRACT_PACK, "nanocode_openai");
    let arm = |tag: &str| {
        serde_json::json!({
            "type": "object",
            "properties": {tag: {
                "type": "object", "properties": {}, "required": [],
                "additionalProperties": false,
            }},
            "required": [tag],
            "additionalProperties": false,
        })
    };
    assert_eq!(
        turn.output_schema,
        Some(serde_json::json!({
            "type": "object",
            "properties": {"verdict": {"anyOf": [arm("hold"), arm("ship")]}},
            "required": ["verdict"],
            "additionalProperties": false,
        }))
    );
}

/// **No schema rides a contract with no strict rendering, nor a stage with no
/// contract** — each turn keeps the prompt path alone, and none carries a
/// partial schema. (A kind with no schema channel, `nanocode_anthropic`, is
/// refused one by `Capsule::new` itself.)
#[test]
fn no_output_schema_is_assembled_without_a_channel_a_strict_rendering_or_a_contract() {
    let oversized = assembled_turn(OVERSIZED_CONTRACT_PACK, "nanocode_openai");
    assert_eq!(
        oversized.output_schema, None,
        "33 824 properties are past strict mode's limit"
    );
    let program =
        compile_starlark_execution_program(OVERSIZED_CONTRACT_PACK, "contract-pack.star", &[])
            .expect("the oversized pack compiles: kata admits the contract");
    let contract = stage_named(&program, "verdict")
        .policies
        .output_schema
        .as_ref()
        .expect("the stage declares its contract");
    assert_eq!(
        kata_types::strict_output_schema::strict_output_schema(contract),
        Err(kata_types::strict_output_schema::NotStrict::TooManyProperties { count: 33_824 }),
        "the reason is the property limit, not a refusal of the contract"
    );
    let bare = assembled_turn(AGENT_PACK, "nanocode_openai");
    assert_eq!(bare.output_schema, None, "no produces= sends no schema");
}
