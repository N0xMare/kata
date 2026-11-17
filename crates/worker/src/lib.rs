//! `kata-worker` — worker execution scaffolding for the kata runtime.
//!
//! This crate provides [`worker_loop()`] — the one receive-execute-send loop
//! production runs, in every `kata-worker` (the node `kata serve` supervises and
//! each standalone daemon), over its local socket — and the
//! capsule route that resolves, drives, publishes and reports each capsule
//! dispatch frame.
//!
//! (Written `worker_loop()` and not `worker_loop` throughout: the name is BOTH
//! the [`mod@worker_loop`] module and the function re-exported out of it, so the
//! bare form is an ambiguous intra-doc link that rustdoc resolves by DROPPING —
//! the reader would get no link to the function the sentence is about.)
//!
//! See `docs/architecture/0001-replacement-architecture.md` for the full design context.

// The workspace `deny(unsafe_code)` applies, and NOT a crate-level
// `#![forbid(unsafe_code)]`: `forbid` cannot be relaxed below it (an inner
// `#[allow(unsafe_code)]` is E0453, "incompatible with previous forbid"), and
// the spawn-time kernel calls in `process.rs` — its three `pre_exec` hooks:
// the cgroup self-placement write, the fail-closed abort, and
// prctl plus seccomp — are irreducibly `unsafe`. `process.rs` is the one
// module carrying `#[allow(unsafe_code)]`, once per `unsafe` block, each with
// its SAFETY argument; no other module in this crate carries one.

/// The production agent-adapter registry: every adapter this build carries.
pub mod adapter_registry;
/// The `Agent` arm of a capsule attempt's credentials: the declared reference
/// resolved to the in-process carrier the embedded harness takes.
pub mod agent_credential;
mod agent_turn;
/// The OCI route's per-attempt directory as an owned, `flock`ed value, and the
/// worker-start sweep of the ones nobody owns.
pub mod attempt_root;
/// RESOLVE, DRIVE, PUBLISH, REPORT: one capsule dispatch frame executed end to
/// end on this worker.
pub mod capsule_execution;
/// Resolve a capsule dispatch frame into the capsule it names.
pub mod capsule_frame;
/// The capsule attempt's bounded `CapsuleProgress`
/// emitter, the `SessionProgressSink` an agent adapter reports through, and
/// the capture-spool tailer a `Command` capsule's line tails come from.
pub mod capsule_progress;
pub mod capsule_route;
pub mod daemon;
/// The worker's half of the `SCM_RIGHTS` listener handoff the `hand-listener`
/// createContainer hook performs — see the module for the protocol and for why
/// every refusal is `egress_listener_unavailable`.
pub mod egress_handoff;
/// The WORKER-OWNED allowlisting HTTP `CONNECT` proxy an `Egress` capsule's
/// guest reaches its declared authorities through — one per attempt, fed by the
/// listener [`egress_handoff`] inherits from the guest's network namespace.
pub mod egress_proxy;
/// The external-provider DECLARATION channel (name + content address) and the
/// admitted [`execution_route::OciRoute`] the capsule driver runs on.
pub mod execution_route;
/// This build's EXECUTOR TERM: the rendered seccomp rules, the pinned
/// youki's content hash and two reference bundle templates, folded into the capsule
/// reuse key so a kata whose rendered fence changed misses every result keyed under
/// the old one. What it does not cover is the module doc's.
pub mod executor_term;
/// The agent capsule's DISPOSABLE GIT VIEW: the history artifact
/// materialized read-only, the writable scratch git dir configured off it, and
/// the `/work/.git` gitfile — plus the bounded `scratch_commits` evidence read.
pub mod git_view;
pub mod health;
/// The one production `kata_agent::adapter::InteractiveProcess`: an agent
/// capsule's init (`kata-toolhost`) running in a rootless OCI container kata
/// planned, with live stdio over three FIFOs the worker owns.
pub mod interactive_capsule;
/// The LOCAL MATERIALIZER: a capsule's authorized
/// references become real `work`/`out`/`tmp` directories on this worker, through
/// `openat`-relative writes, or are refused by name. Nothing executes here.
pub mod materialize;
/// PLAN the rootless OCI container: the `config.json` kata derives from a
/// capsule and its authorized Nix closure, and the refusals that keep it from
/// describing anything else. The provider applies the plan.
pub mod oci_bundle;
/// The KATA-OWNED parent cgroup a rootless OCI container's
/// leaf is created beneath, so the subtree kata sweeps is the subtree the stage
/// runs in.
pub mod oci_cgroup;
/// The OCI STAGE DRIVER: materialize a capsule, plan its container, place it in
/// a cgroup kata owns, and run it through the provider kata ships. The one
/// composition of the certification, materializer, plan and cgroup, and no
/// fallback on any refusal.
pub mod oci_driver;
/// CERTIFY the rootless-OCI runtime (the pinned youki, its exact-path AppArmor
/// profile, cgroup delegation, and a real container), or refuse it BY NAME.
pub mod oci_runtime;
/// The effective owner's home, resolved from the account record and never
/// from ambient `HOME`: the per-owner root every kata binary of a uid agrees on.
pub mod owner_home;
/// Resolve a capsule's `EnvironmentId` and mapped
/// `ArtifactId`s through the node's planes opened READ-ONLY, recomputing every id from
/// the bytes its row points at.
pub mod plane_index;
pub mod pricing;
/// Provider launch + cgroup teardown primitives: `CommandPrefix` → child
/// with the seccomp fd, declared bounds, and the kata seccomp floor installed
/// fail-closed, and the cgroup-population teardown probe.
pub mod process;
/// The BY-HASH EXTERNAL PROVIDER STORE: an external provider is
/// identified by CONTENT, resolved to a HOST path, and never mounted. It owns
/// the store's whole mechanism — provision, hash, seal, verify.
pub mod provider_store;
/// The SUPERVISOR: kata's side of one external provider process, and the one
/// production install site of the kata seccomp floor on a workload.
pub mod provider_supervisor;
mod recovery;
/// The RESULT half of the capsule plane: `/out` on
/// disk becomes a content-addressed tree artifact the main can adopt.
pub mod result_publication;
/// What this host's cgroup v2 delegation ACTUALLY carries, measured by
/// round trip rather than inferred from a directory existing.
pub mod sandbox_bounds;
pub mod sandbox_posture;
mod start_deadline;
/// The WORKSPACE half of the capsule plane's mutation record:
/// a post-run `/work` becomes a content-addressed [`kata_types::tree_delta::TreeDelta`]
/// the main verifies and records.
pub mod work_delta;
pub mod worker_loop;

pub use execution_route::{
    EXTERNAL_PROVIDER_ADDRESS_ENV, EXTERNAL_PROVIDER_ENV, ExternalProviderAddress,
    ExternalProviderDeclaration, declared_external_provider,
};
pub use health::WorkerHealthSampler;
pub use provider_store::{
    EXTERNAL_PROVIDER_STORE_ENV, NODE_PROVIDER_ENV_KEYS, ProviderStore, ProvisionedProvider,
    ResolvedProvider, UnsealOnDrop, declared_provider_store_root, unseal_tree,
};
pub use provider_supervisor::{
    PROVIDER_BINARY_PREFIX, PROVIDER_CGROUP_LEAF, PROVIDER_CGROUP_PREFIX, ProviderFloor,
    ProviderLaunchSpec, ProviderSupervisor, StageOutcome, outer_cgroup_bounds,
    provider_command_prefix, sweep_stale_provider_cgroups,
};
pub use sandbox_bounds::CgroupController;
pub use sandbox_posture::{
    ContainmentFact, ContainmentLever, ContainmentPosture, ContainmentState, KillSwitchState,
    LeverDirection, log_containment_posture, log_containment_posture_once,
};
pub use worker_loop::worker_loop;
