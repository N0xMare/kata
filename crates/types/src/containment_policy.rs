//! The **installed node containment policy** — the escape from "absence means
//! `HostUnconfined`".
//!
//! An omitted containment declaration resolves conservatively to
//! `HostUnconfined`, and an installed policy may instead require `Contained`
//! and refuse. This module is that installed policy's process-level home. The VALUE comes
//! from `[containment]` in `kata.toml` ([`ContainmentConfig`]); the main
//! installs it once at boot; the workflow compiler reads it when deciding
//! whether to refuse a stage.
//!
//! # Why a process-installed value rather than a compile parameter
//!
//! Kata's product boundary is one operator running one authoritative main
//! (ADR-0001 § "Product and authority"). There is no tenancy, no
//! second main, and no per-workflow override — so this value is a property of
//! the PROCESS, and threading it as an argument through the ~40 production and
//! ~200 test call sites of `compile_starlark_execution_program` /
//! `compile_execution_program_from_file` would only ever carry the one value the
//! node was booted with. Worse, a threaded parameter is a hole-generator: the
//! one call site that keeps passing the default is a compile path the policy
//! silently does not govern.
//!
//! # Who installs it, and what a process that does NOT install it means
//!
//! [`install_node_containment_policy`] is called by `BootRig::boot` — the single
//! funnel every node start passes through (`kata serve`, the MCP host, the
//! recovery rig). A process that never boots a node — `kata
//! check`, `kata workflows check --all`, `kata build` — has no node config, no
//! durable authority, and executes nothing; it observes the OFF default.
//! Enforcement therefore lands exactly where execution authority lands, and
//! `just workflows-check-all` stays green by construction. The OFF default
//! admits nothing an ON node refuses: the one stage the policy refuses — a
//! model stage deriving `HostUnconfined` — the `oci` profile refuses on every
//! compile (`host_sandbox_unsupported_under_oci`), so containment is not among
//! the node fact classes a node-less check names as not judged
//! (`crate::node_profile::DeferredNodeFact`).
//!
//! # The un-installed default is NOT `ContainmentConfig::default()`, on purpose
//!
//! [`ContainmentConfig`]'s default is `true` and the un-installed static is
//! `false`. The difference is the design above rather than an oversight:
//!
//! * [`ContainmentConfig::default()`] — `true` — is what a NODE gets when its
//!   `kata.toml` omits `[containment]`. A node executes, so the policy binds it.
//! * The static below — `false` — is what a process that never installed a
//!   policy observes. Such a process has no node config to have defaulted, so
//!   there is nothing for a config default to say about it.
//!
//! Making the static `true` would mean `kata workflows check` refuses a pack
//! that the operator's own node — with the key set to `false` — would happily
//! run, i.e. an authoring tool answering a question about a node it was never
//! told about. The corollary is worth stating plainly because it can surprise:
//! `kata workflows check --all` passing is NOT a prediction that a default node
//! will accept the pack. `kata doctor` and the node's own boot refusal are the
//! authorities on that.
//!
//! # Reload
//!
//! Cold. A changed `[containment]` value is classified `restart_required` by
//! `kata_core::config_reload::classify_changes`, because the value is read at
//! every compile and swapping it mid-run would make two stages of one execution
//! answer to different admission rules.

use std::sync::atomic::{AtomicBool, Ordering};

use crate::config::ContainmentConfig;

/// The one installed bit. `false` until a boot installs otherwise — see the
/// module docs: this is the NO-NODE value, deliberately not
/// [`ContainmentConfig::default()`] (`true`, the shipped node default).
static REQUIRE_CONTAINED_MODEL_STAGES: AtomicBool = AtomicBool::new(false);

/// Install this node's containment policy. Called once by `BootRig::boot` with
/// the `[containment]` section of the loaded `kata.toml`.
///
/// The setter is total (last write wins) rather than install-once: a process
/// boots at most one node, so production calls it exactly once, and a total
/// setter lets a test drive BOTH arms of the policy through this same door
/// instead of reaching past it into the compiler.
pub fn install_node_containment_policy(policy: ContainmentConfig) {
    REQUIRE_CONTAINED_MODEL_STAGES.store(policy.require_contained_model_stages, Ordering::Relaxed);
}

/// The policy currently installed in this process. Everything OFF in a process
/// that never installed one — which is NOT `ContainmentConfig::default()` any
/// more; see the module docs for why the two deliberately differ.
#[must_use]
pub fn installed_node_containment_policy() -> ContainmentConfig {
    ContainmentConfig {
        require_contained_model_stages: REQUIRE_CONTAINED_MODEL_STAGES.load(Ordering::Relaxed),
    }
}
