//! The capsule rules the CHECK and capsule assembly share, each spelled once so
//! what `kata check` predicts and what assembly mints cannot drift: which class a
//! stage is ([`is_shell_class`], [`is_agent_class`]), the budget defaults a
//! capsule records ([`CAPSULE_DEFAULT_MEMORY_BYTES`], [`CAPSULE_PROCESS_COUNT`]),
//! the credential an agent block names ([`capsule_credential`]), and the network
//! a capsule gets ([`capsule_network_for`], which [`checked_capsule_networks`]
//! states for every check face).
//!
//! Pure: every answer is a function of the checked stage and the installed node
//! facts (`kata_types::node_profile`), and nothing here issues anything.

use kata_types::KataError;
use kata_types::KataResult;
use kata_types::execution_contract::CapsuleNetwork;
use kata_types::sandbox::NetPolicy;

use crate::execution_program::ExecutionProgramStage;

/// The MEMORY bound a capsule records when the stage's own sandbox declares
/// none — see `declared_memory_bytes` in `capsule_submit` for the authored
/// half. 512 MiB is the live rigs' value.
pub const CAPSULE_DEFAULT_MEMORY_BYTES: u64 = 512 * 1024 * 1024;

/// The PROCESS bound a capsule records — no authored value exists for
/// `pids.max` (a `SandboxImage` carries `cpus` and `memory_mb`, no pid
/// field), so the assembly default is the whole declared half of the
/// recorded bound. 64 is the same ceiling the OCI live rigs exercise.
pub const CAPSULE_PROCESS_COUNT: u32 = 64;

pub fn refused(reason: &str) -> KataError {
    KataError::Validation(format!("capsule assembly refused: {reason}"))
}

/// Is this stage the deterministic SHELL class — the one class a capsule's argv can be
/// derived for?
///
/// # ONE predicate, two doors
///
/// Capsule assembly's `shell_argv` refuses on it at ASSEMBLY, and
/// `crate::execution_program::compile`'s installed-execution-profile door refuses on it
/// at CHECK. Two spellings of "is this a shell stage" is how a pack comes to pass the
/// check on an `oci` node and then refuse at the first dispatch — the exact failure the
/// check-time door exists to prevent.
///
/// The selected agent is the LABEL when the stage carries one and the agent otherwise,
/// because that is the value the dispatcher resolves a backend from; a stage that
/// labels a shell backend under another name is the shell class.
#[must_use]
pub fn is_shell_class(stage: &ExecutionProgramStage) -> bool {
    let label = stage
        .op
        .agent_label
        .as_deref()
        .unwrap_or(stage.op.agent.as_str());
    label == kata_types::agent::BackendType::Shell.label()
}

/// Is this stage the AGENT class — the one class whose capsule's process arm
/// is `CapsuleProcess::Agent` and whose `/work` gets the disposable git view?
///
/// Strictly narrower than `!is_shell_class`: a `workspace_effect` stage is no
/// shell stage either, but it runs no capsule at all — it performs in the
/// main. The gate admission publishes the git-history artifact under, and the
/// gate the capsule submit reads the `execution_git_views` row under, must
/// both answer "agent" for exactly the stages a `CapsuleProcess::Agent` arm
/// exists for, which is the non-deterministic set: `shell` AND
/// `workspace_effect` are both out.
#[must_use]
pub fn is_agent_class(stage: &ExecutionProgramStage) -> bool {
    let label = stage
        .op
        .agent_label
        .as_deref()
        .unwrap_or(stage.op.agent.as_str());
    !kata_types::agent::is_deterministic_agent_label(label)
}

/// THE allowlist rule for one capsule's network under `oci` — the one function
/// both capsule assembly (what the capsule GETS) and
/// [`checked_capsule_networks`] (what `kata check` SAYS it gets) call.
///
/// A capsule's network is NEVER the authored `NetPolicy` verbatim: `net =
/// "host"` is the AUTHORED name for "this stage reaches the declared
/// authorities", and the capsule spelling of it is always
/// `CapsuleNetwork::Egress{allowlist}` over exactly `node_egress_allow` — the
/// container's only route out is the worker-owned allowlisting CONNECT proxy;
/// there is no unrestricted host networking arm a `Command` or `Agent` capsule
/// can carry. Under `net = "offline"` it is `Offline`. A shell stage and an
/// agent stage answer alike: an agent's model calls leave from the process
/// hosting the worker, never from its capsule.
///
/// An EMPTY `node_egress_allow` under `net = "host"` mints `Egress{∅}`, which
/// `Capsule::new` refuses as `capsule_egress_allowlist_empty`; the `oci` CHECK
/// refuses the same emptiness earlier as `egress_undeclared`, naming the
/// stage.
///
/// The allowlist is the same set the worker's CONNECT proxy enforces — minted
/// into capsule identity, so a node that widened `egress_allow` is a different
/// capsule, not a different launch of one.
#[must_use]
pub fn capsule_network_for(
    net: &NetPolicy,
    node_egress_allow: &std::collections::BTreeSet<kata_types::execution_contract::EgressAuthority>,
) -> CapsuleNetwork {
    match net {
        NetPolicy::Host => CapsuleNetwork::Egress {
            allowlist: node_egress_allow.clone(),
        },
        NetPolicy::Offline => CapsuleNetwork::Offline,
    }
}

/// The `net` `stage`'s sandbox authors — inline, or through the named profile
/// in `profiles` — or `None` for a stage that carries no sandbox (an
/// in-process stage) or names a profile `profiles` lacks (which CHECK refuses).
#[must_use]
pub fn authored_net(
    stage: &ExecutionProgramStage,
    profiles: &std::collections::BTreeMap<String, kata_types::sandbox::SandboxProfile>,
) -> Option<NetPolicy> {
    match stage.policies.sandbox.as_ref()? {
        kata_types::sandbox::SandboxRef::Inline(profile) => Some(profile.net.clone()),
        kata_types::sandbox::SandboxRef::Named(name) => profiles
            .get(name.as_str())
            .map(|profile| profile.net.clone()),
    }
}

/// The agent label a stage resolves its `[agents.<label>]` block by: its
/// label when it carries one, its agent otherwise.
pub fn stage_agent_label(stage: &ExecutionProgramStage) -> &str {
    stage
        .op
        .agent_label
        .as_deref()
        .unwrap_or(stage.op.agent.as_str())
}

/// What each capsule `stage` can run WILL get as its network on this node, as
/// every check face states it — [`capsule_network_for`] over the installed node
/// facts, labelled by
/// [`kata_types::execution_contract::CapsuleNetworkPosture::of`].
///
/// One row per capsule the stage can dispatch: a shell stage's one capsule
/// (no agent); an agent stage's primary, then — for a fallback panel — every
/// later member, in panel order, because a failure retry advances to each
/// one. A member is judged exactly as the CHECK's agent door judges it: the
/// stage with its `agent_label` set to that member.
///
/// Empty for a stage that runs no capsule (an in-process workspace effect or
/// forge export, a main-resolved wait, join or invocation — every stage whose
/// class is not `Contained`) and on a process with no installed node, where
/// the agent block and the node's `egress_allow` are unknown (`kata check`
/// reports those facts DEFERRED).
///
/// It is the prediction for a dispatch under the node as installed now: the
/// capsule's network is minted at assembly from the same facts, and the
/// execution record states what each declared capsule actually got.
///
/// # Errors
///
/// `adapter_undeclared` / `adapter_unqualified` / `credential_undeclared` (and
/// the launch's other doors) for an agent member whose block cannot name an
/// adapter or a credential — each one the `oci` CHECK refuses first, for the
/// primary and every panel member.
pub fn checked_capsule_networks(
    stage: &ExecutionProgramStage,
    profiles: &std::collections::BTreeMap<String, kata_types::sandbox::SandboxProfile>,
) -> KataResult<Vec<crate::preflight::CheckedCapsuleNetwork>> {
    use kata_types::execution_contract::CapsuleNetworkPosture;
    if !kata_types::node_profile::node_is_installed()
        || stage.execution_class.containment != kata_types::execution_class::Containment::Contained
    {
        return Ok(Vec::new());
    }
    let Some(net) = authored_net(stage, profiles) else {
        return Ok(Vec::new());
    };
    let node_egress_allow = kata_types::node_profile::installed_node_egress_allow();
    let network = capsule_network_for(&net, &node_egress_allow);
    if is_shell_class(stage) {
        return Ok(vec![crate::preflight::CheckedCapsuleNetwork {
            agent: None,
            network: CapsuleNetworkPosture::of(&network),
        }]);
    }
    let mut members = vec![stage.clone()];
    for fallback in stage.op.agent_panel.iter().skip(1) {
        let mut member = stage.clone();
        member.op.agent_label = Some(fallback.clone());
        members.push(member);
    }
    members
        .iter()
        .map(|member| {
            checked_agent_block(member)?;
            Ok(crate::preflight::CheckedCapsuleNetwork {
                agent: Some(stage_agent_label(member).to_owned()),
                network: CapsuleNetworkPosture::of(&network),
            })
        })
        .collect()
}

/// One agent member's installed `[agents.<label>]` block at CHECK: it names an
/// adapter this build carries, launches, and declares a credential that adapter
/// can be served by.
fn checked_agent_block(member: &ExecutionProgramStage) -> KataResult<()> {
    let label = stage_agent_label(member);
    let config = kata_types::node_profile::installed_node_agent(label).ok_or_else(|| {
        refused(&format!(
            "adapter_undeclared: stage {} selects agent `{label}`, and this node declares no \
             `[agents.{label}]` block at all",
            member.stage_id.0,
        ))
    })?;
    let adapter = config.capsule_launch().map_err(|problem| {
        refused(&format!(
            "{}: stage {} selects agent `{label}`, whose `[agents.{label}]` {}",
            problem.door(),
            member.stage_id.0,
            problem.describe(),
        ))
    })?;
    capsule_credential(member, &config, adapter)?;
    Ok(())
}

/// The node config's `[agents.<label>] credential = { mode, source }` as the
/// turn's durable REFERENCE — mode + source kind, never a value. `None`
/// declares no credential; an unrecognized `mode` or `source` is
/// `credential_undeclared` — a machine fact the node must state correctly, as
/// `adapter_undeclared` is for the launch pair. A parsed mode `adapter` cannot
/// be served under in this build (`AdapterKind::serves_credential_mode`:
/// `nanocode_anthropic` under `subscription`) is `credential_mode_unsupported`,
/// and a block that declares none is `credential_undeclared`
/// (`harness_credential_undeclared`: the embedded harness runs in the worker
/// and has no other way to be served): the CHECK's own refusals, re-asked
/// because a hand-built stage can reach this door unchecked.
pub fn capsule_credential(
    stage: &ExecutionProgramStage,
    config: &kata_types::config::AgentBackendConfig,
    adapter: kata_types::agent::AdapterKind,
) -> Result<Option<kata_types::execution_contract::TurnCredentialRef>, KataError> {
    let label = stage
        .op
        .agent_label
        .as_deref()
        .unwrap_or(stage.op.agent.as_str());
    let reference = config.capsule_credential_ref().map_err(|error| {
        KataError::Validation(format!(
            "credential_undeclared: stage {} selects agent `{label}`, whose \
                 `[agents.{label}] credential` is {error}. A credential the build \
                 cannot read is a declaration failure, not an absence.",
            stage.stage_id.0,
        ))
    })?;
    if let Some(reference) = &reference
        && !adapter.serves_credential_mode(reference.mode)
    {
        return Err(refused(
            &kata_types::execution_contract::credential_mode_unsupported(
                &format!("stage {} selects agent `{label}`, whose", stage.stage_id.0),
                adapter,
                reference.mode,
            ),
        ));
    }
    if reference.is_none() {
        return Err(refused(
            &kata_types::execution_contract::harness_credential_undeclared(
                &format!(
                    "stage {} selects agent `{label}`, whose `[agents.{label}]`",
                    stage.stage_id.0
                ),
                adapter,
            ),
        ));
    }
    Ok(reference)
}
