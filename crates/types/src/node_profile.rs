//! The **installed node facts** a process-global CHECK reads.
//!
//! # Why a process-installed value rather than a compile parameter
//!
//! The argument is [`crate::containment_policy`]'s, unchanged, and the knobs
//! are deliberately installed the same way: kata's product boundary is one
//! operator running one authoritative main, so these are properties of the
//! PROCESS, and threading them through the ~40 production and ~200 test call
//! sites of `compile_starlark_execution_program` would only ever carry the
//! one value the node was booted with — while the one call site that kept
//! passing a default would be a compile path the facts silently do not
//! govern.
//!
//! # What a process that does NOT install them means
//!
//! [`mark_node_installed`] is called by `BootRig::boot`'s facts funnel, the
//! single funnel every node start passes through — and it is what flips
//! [`node_is_installed`], the explicit no-node marker. A process that never
//! boots a node — `kata check`, `kata workflows check --all`, `kata build` —
//! keeps `node_is_installed()` at `false`: it has no node config, no durable
//! authority and executes nothing, so a node-less compile is a judgement of
//! the pack alone. Where the CHECK would refuse on a NODE fact the process
//! cannot know — the `[agents]` declarations, the credential pairings, the
//! `[node] *_ceiling` declarations, `[node] egress_allow`, the bound
//! environment's `PATH` programs — it DEFERS: the checking door records each
//! class it skipped in the [`DeferredNodeFact`] set it is handed, the check
//! surface renders the set as its one `not judged without a booted node:` line,
//! and admission on a booted node judges the same arms by name. The bound
//! environment's programs are the one class a `--config` check cannot install
//! either, so that check defers it too.
//!
//! # Reload
//!
//! Cold, for `[containment]`'s reason: the facts are read at every compile
//! and at every dispatch, and swapping them mid-run would make two stages of
//! one execution answer to different admission rules.

use std::sync::atomic::{AtomicBool, Ordering};

/// The explicit no-node marker: `false` until a node installs its facts (the
/// facts funnel calls [`mark_node_installed`]), `true` for the rest of the
/// process's life. Node-dependent CHECK arms read it to DEFER on `kata check`
/// rather than refuse on facts no node declared — see the module doc.
static NODE_INSTALLED: AtomicBool = AtomicBool::new(false);

/// Mark this process as having booted a node — called once by
/// `BootRig::boot`'s facts funnel, the single funnel every node start passes
/// through. The setter is total rather than install-once, for
/// [`crate::containment_policy::install_node_containment_policy`]'s reason: a
/// process boots at most one node, and a total setter lets a test drive both
/// states through this same door instead of reaching past it.
pub fn mark_node_installed() {
    NODE_INSTALLED.store(true, Ordering::Relaxed);
}

/// Whether this process booted a node — the explicit no-node state. A `false` read
/// means the process (`kata check`, `kata workflows check --all`, `kata build`) has
/// no `[node]` facts: the oci door's node-dependent arms defer rather than refuse,
/// filling the [`DeferredNodeFact`] set the compile hands them.
#[must_use]
pub fn node_is_installed() -> bool {
    NODE_INSTALLED.load(Ordering::Relaxed)
}

/// TEST SUPPORT — drop the installed marker, returning the process to the
/// node-less CHECK state. A production process never calls it: once a node
/// installs, it is installed.
#[cfg(any(test, feature = "test-support"))]
pub fn clear_node_installation() {
    NODE_INSTALLED.store(false, Ordering::Relaxed);
}

/// A node-dependent fact class a CHECK did not judge — the typed set the `oci`
/// admission door is handed (`&mut BTreeSet<DeferredNodeFact>`) and fills as it
/// walks each stage, exactly when a door it skipped would have judged that
/// stage. `Ord` is the render order: the check surface's one `not judged
/// without a node:` line and the artifact's `deferred_node_facts` read `as_str`
/// in that order.
///
/// Containment is not a class here: the installed containment policy refuses
/// only a model stage deriving `HostUnconfined`, and the `oci` door refuses
/// every process stage of that derivation (`host_sandbox_unsupported_under_oci`)
/// with or without a node, so a node-less check skips no refusal of it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum DeferredNodeFact {
    /// The `[agents]` declarations — adapter, `argv`, credential pairings, the
    /// effort/env carrier doors, the `cost_bound_unenforceable_*` arms.
    Agents,
    /// The `[node] *_ceiling` declarations — the authored-budget triple and the
    /// recorded `capsule_*` pair ([`NodeBudgetCeilings`]), which a node may
    /// raise, lower or declare.
    Ceilings,
    /// The `[node] egress_allow` authority set.
    Egress,
    /// The bound environment's `PATH` programs — a stage's `requires` list —
    /// deferred by any process that bound no environment, a `--config` check
    /// included.
    Environment,
}

impl DeferredNodeFact {
    /// The stable name the check surface renders.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Agents => "agents",
            Self::Ceilings => "ceilings",
            Self::Egress => "egress",
            Self::Environment => "environment",
        }
    }
}

/// The node's capsule-budget ceilings — the `[node] *_ceiling` triple,
/// installed process-wide at boot because one operator boots one node, and the
/// admission door that reads them is deep in compile and submit paths that have
/// no config parameter. A process that installed no node (`kata check`) judges
/// no stage against them: the doors defer [`DeferredNodeFact::Ceilings`].
///
/// Read by `kata_program::execution_program`'s admission refusal, which checks
/// each stage's AUTHORED `output_bytes` / `work_delta_bytes` /
/// `work_delta_entries` against them by name, and every capsule stage's
/// recorded memory and process bounds against the two `capsule_*` ceilings
/// (`capsule_budget_over_node_ceiling`).
#[derive(Clone, Copy, Debug)]
pub struct NodeBudgetCeilings {
    /// `[node] output_bytes_ceiling` — the combined capture bound's ceiling.
    pub output_bytes: u64,
    /// `[node] work_delta_bytes_ceiling`.
    pub work_delta_bytes: u64,
    /// `[node] work_delta_entries_ceiling`.
    pub work_delta_entries: u32,
    /// `[node] capsule_memory_bytes_ceiling` — the node's DECLARED bound on
    /// the memory box a capsule may record, checked at admission against the
    /// recorded bound (authored `memory_mb` or the assembly default):
    /// `capsule_budget_over_node_ceiling` when either exceeds. `None` = the
    /// node declares no capsule ceiling — kata never invents one.
    pub capsule_memory_bytes: Option<u64>,
    /// `[node] capsule_process_count_ceiling` — the same declared bound on
    /// `pids.max`, checked against the recorded bound: the assembly's 64,
    /// since nothing authors a process bound.
    pub capsule_process_count: Option<u32>,
}

/// The `[node]` defaults verbatim, and the capsule ceilings ABSENT: a node
/// either declares them or it declares none. The installed value until a node
/// installs its own — which no node-less CHECK reads (it defers the class).
pub const DEFAULT_NODE_BUDGET_CEILINGS: NodeBudgetCeilings = NodeBudgetCeilings {
    output_bytes: crate::execution_contract::NODE_OUTPUT_BYTES_CEILING,
    work_delta_bytes: crate::execution_contract::NODE_WORK_DELTA_BYTES_CEILING,
    work_delta_entries: crate::execution_contract::NODE_WORK_DELTA_ENTRIES_CEILING,
    capsule_memory_bytes: None,
    capsule_process_count: None,
};

static NODE_BUDGET_CEILINGS: std::sync::RwLock<NodeBudgetCeilings> =
    std::sync::RwLock::new(DEFAULT_NODE_BUDGET_CEILINGS);

/// Install this node's ceilings — `BootRig::boot`'s call, beside
/// [`mark_node_installed`]'s.
pub fn install_node_budget_ceilings(ceilings: NodeBudgetCeilings) {
    *NODE_BUDGET_CEILINGS.write().unwrap() = ceilings;
}

/// The ceilings this process runs under — the shipped defaults when nothing
/// installed a node's own.
#[must_use]
pub fn installed_node_budget_ceilings() -> NodeBudgetCeilings {
    *NODE_BUDGET_CEILINGS.read().unwrap()
}

/// This node's `[agents.<name>]` map — the adapter + launch argv the `oci` CHECK
/// and the capsule assembler resolve a stage's agent label against.
///
/// Installed the way `mark_node_installed` is, and for its reason: the CHECK
/// (`kata_program::execution_program`'s node-facts door) and the
/// dispatch-time assembly run deep in compile and submit paths with no config
/// parameter, and an uninstalled process observes an EMPTY map — under `oci`
/// every agent stage is then `adapter_undeclared`, which is the honest answer
/// for a node nobody declared agents on.
///
/// The map is read under a `RwLock` and cloned per lookup: a compile holds the
/// config for the duration of one stage's judgement, which is bounded and
/// cannot outlive the lock, so the clone is the cheapest shape that keeps a
/// reader's borrowed config valid across the read.
static NODE_AGENTS: std::sync::RwLock<
    std::collections::BTreeMap<String, crate::config::AgentBackendConfig>,
> = std::sync::RwLock::new(std::collections::BTreeMap::new());

/// Install this node's `[agents]` map — `BootRig::boot`'s call, beside
/// [`mark_node_installed`]'s.
pub fn install_node_agents(
    agents: std::collections::BTreeMap<String, crate::config::AgentBackendConfig>,
) {
    *NODE_AGENTS.write().unwrap() = agents;
}

/// The `[agents.<label>]` config this node declared, or `None` when the label
/// has no block — which the `oci` CHECK refuses `adapter_undeclared` for.
///
/// Returns a CLONE: `AgentBackendConfig` is a plain data enum, the lock is held
/// only for the copy, and no caller may borrow out of a process-global.
#[must_use]
pub fn installed_node_agent(label: &str) -> Option<crate::config::AgentBackendConfig> {
    NODE_AGENTS.read().unwrap().get(label).cloned()
}

/// This node's `[node] egress_allow` — the EXACT `host:port` authorities an
/// authored `net = "host"` names under the `oci` profile, already parsed
/// through [`crate::execution_contract::EgressAuthority::from_authority_str`]
/// at config load.
///
/// Installed the way the agents map is, and for its reason: the `oci` CHECK's
/// `egress_undeclared` door and the dispatch-time capsule assembly run deep in
/// compile and submit paths with no config parameter. An uninstalled process
/// observes an EMPTY set — under `oci` a `net = "host"` shell stage is then
/// `egress_undeclared`, which is the honest answer for a node that declares
/// no reachable authority.
///
/// The set is a `BTreeSet`, installed already parsed and sorted — the same
/// shape [`crate::execution_contract::CapsuleNetwork::Egress`]'s allowlist
/// field carries, so the assembly folds the node answer directly rather than
/// re-validating what config load already proved.
static NODE_EGRESS_ALLOW: std::sync::RwLock<
    std::collections::BTreeSet<crate::execution_contract::EgressAuthority>,
> = std::sync::RwLock::new(std::collections::BTreeSet::new());

/// Install this node's parsed egress allowlist — `BootRig::boot`'s call,
/// beside [`install_node_agents`]'s.
pub fn install_node_egress_allow(
    allow: std::collections::BTreeSet<crate::execution_contract::EgressAuthority>,
) {
    *NODE_EGRESS_ALLOW.write().unwrap() = allow;
}

/// The node's installed egress allowlist — the empty set in a process that
/// never installed one. Returns a CLONE: the lock is held only for the copy,
/// and the `BTreeSet` is what `CapsuleNetwork::Egress` folds.
#[must_use]
pub fn installed_node_egress_allow()
-> std::collections::BTreeSet<crate::execution_contract::EgressAuthority> {
    NODE_EGRESS_ALLOW.read().unwrap().clone()
}

/// The PROGRAM NAMES the environment this node BOUND at boot
/// provides on its guest `PATH` (every executable in the manifest's
/// `path_prepend` directories), or `None` in a process that bound none.
///
/// The `oci` CHECK judges a stage's `sandbox_profile(requires = [..])`
/// against it (`environment_requirement_unmet`); `None` means the process
/// cannot answer (a CLI check on a box with no booted node), and the capsule
/// authorization door judges the same list at dispatch instead
/// (`capsule_requirement_not_in_environment`).
static NODE_ENVIRONMENT_PROGRAMS: std::sync::RwLock<Option<std::collections::BTreeSet<String>>> =
    std::sync::RwLock::new(None);

/// Install the bound environment's `PATH` program names — boot's call, after
/// it binds `[node] environment`.
pub fn install_node_environment_programs(programs: Option<std::collections::BTreeSet<String>>) {
    *NODE_ENVIRONMENT_PROGRAMS.write().unwrap() = programs;
}

/// The bound environment's `PATH` program names, or `None` when this process
/// bound no environment. Returns a CLONE.
#[must_use]
pub fn installed_node_environment_programs() -> Option<std::collections::BTreeSet<String>> {
    NODE_ENVIRONMENT_PROGRAMS.read().unwrap().clone()
}

/// The Nix SYSTEM double this binary's node runs closures for, or `None` on a target
/// ADR-0001 does not name.
///
/// Read off the COMPILE target, not measured at runtime: a closure is executed by this
/// process's own containers on this process's own kernel, so the architecture it must
/// have been built for is the one this binary was built for. `x86_64-linux` is the one
/// initial qualified target; every other target has no platform and an `oci` node on it
/// refuses to declare an environment rather than inventing one.
#[must_use]
pub const fn node_system() -> Option<&'static str> {
    if cfg!(all(target_arch = "x86_64", target_os = "linux")) {
        Some("x86_64-linux")
    } else {
        None
    }
}

/// The domain the node platform PROFILE hash is taken over.
///
/// A [`PlatformRef`](crate::execution_contract::PlatformRef) is `(target, profile)`, and
/// the profile names WHICH qualified execution profile a closure was declared for:
/// ADR-0001's initial one (one operator-run main, local subordinate workers, rootless
/// OCI through the pinned Youki executable, a Nix-prepared rootfs). It is a named
/// constant rather than a measurement because it is a CLAIM about the contract a closure
/// was admitted under, and changing it deliberately rotates every environment id — a
/// second profile is a new constant, never a reinterpretation of this one.
const NODE_PLATFORM_PROFILE_DOMAIN: &[u8] =
    b"kata.platform-profile.v1:owner-main+local-workers:rootless-oci-youki:nix-rootfs";

/// This node's platform: [`node_system`] under the initial profile, or `None` on a
/// target with no system.
#[must_use]
pub fn node_platform() -> Option<crate::execution_contract::PlatformRef> {
    node_system().map(|system| {
        crate::execution_contract::PlatformRef::new(
            system,
            crate::primitives::ContentHash::new(
                *blake3::hash(NODE_PLATFORM_PROFILE_DOMAIN).as_bytes(),
            ),
        )
    })
}
