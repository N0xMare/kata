//! `kata-types` — the shared type surface of the kata runtime.
//!
//! This crate carries every type that crosses a crate boundary: identity,
//! configuration, errors, primitive helpers, workflow
//! definitions, events, and workspace objects.
//!
//! The architecture these types serve is
//! `docs/architecture/0001-replacement-architecture.md`.

#![forbid(unsafe_code)]

// Core primitives, error taxonomy, identity, and configuration.
pub mod config;
pub mod recovery;
// WHO kata commits as. Holds only the part that must be visible to crates
// which do not depend on `kata-vcs` — the identities kata itself can mint and
// the ONE predicate that refuses them at every publish point. Resolving the
// HOST's identity is `kata_vcs::identity`, which shells git.
pub mod commit_identity;
// What a WORKER asserts about its containment capability on Hello.
// A peer's CLAIM, deliberately a different type from the measurement
// `kata_worker::sandbox_posture` folds — see the module's own preamble.
pub mod containment_claim;
// An installed policy may require `Contained` and refuse: the process-level home of the node's
// `[containment]` policy, installed once at boot and read by the workflow compiler's model-stage
// containment refusal.
pub mod containment_policy;
pub mod error;
pub mod git_policy;
pub mod node_profile;
// Seven-axis checked execution class: the orthogonal
// semantic-property model of one checked stage plus its closed-world verifier.
// A derived side projection — not persisted or hashed. Path-qualified
// (`kata_types::execution_class::*`) so its common axis names (`Network`,
// `Workspace`, …) never shadow the flat crate root.
/// The TWO wall clocks one capsule attempt is held to — the worker's and the main's —
/// and the one inequality that orders them, stated as constants both sides read.
pub mod capsule_timing;
pub mod execution_class;
/// Portable, non-issuing operation/action/capsule contracts for checked-program
/// lowering. Kept path-qualified to avoid creating a second runtime surface.
pub mod execution_contract;
// WHO established a fact about an attempt's execution, with a hand-written
// `Deserialize` occupying the trait slot and a shape `#[derive(Default)]` cannot
// compile on. Sibling of `containment_claim`, the template it follows.
// `just derive-refusal-probe` observes the derives really are refused.
pub mod execution_provenance;
// What the executor is, as bytes a key folds: the executor term in the capsule
// reuse key.
pub mod execution_platform;
pub mod identity;
// Canonical execution-identity vocabulary + convergence-refusal algebra
// (program/stage/invocation/attempt/effect/input-set/output-set/tree/cache).
// Distinct from `identity` (the auth/membership plane).
pub mod identity_algebra;
// ADR-0001 trust boundary 5: WHICH exact Nix closure kata authorized,
// as a versioned manifest with its own schema version and closure digest. Pure
// types and hashing — no store I/O and no `nix` invocation. Path-qualified
// (`kata_types::nix_environment::*`) so names like `StorePath`, `Provenance` and
// `RetentionIntent` do not land on the flat crate root.
pub mod nix_environment;
pub mod primitives;
// WHICH exact files one portable TREE artifact is.
// Pure types and refusals — no I/O and no CAS. Path-qualified
// (`kata_types::tree_artifact::*`) so names like `TreePath`, `TreeEntry` and
// `TreeManifest` do not land on the flat crate root.
pub mod tree_artifact;
// The typed DELTA between two tree manifests — a sorted path→change
// list against a named base artifact, pure types and refusals like its sibling.
// Path-qualified for the same reason (`kata_types::tree_delta::*`).
pub mod tree_delta;

// Events, workflow, workspace objects, project/governance, checkpoint,
// cache, execution plan.
pub mod agent;
pub mod bound;
pub mod budget;
pub mod cache;
pub mod effect;
pub mod egress_refusal;
pub mod event;
pub mod idempotency;
pub mod memory;
pub mod metering;
pub mod review_loop;
pub mod sandbox;
// The durable record of one commit an agent wrote on its
// capsule's DISPOSABLE scratch branch — worker-produced, wire-carried on
// `CompletedCapsule`, written by the main inside the accepting transaction.
pub mod scratch_commit;
// The seccomp fence kata DEFINES — the deny-list, its derived partition, and the
// cBPF compiler. The worker and the CLI read it from here.
pub mod sandbox_seccomp;
// `pack.star:LINE:COL` authoring coordinates. Neutral core
// type shared by the workflow definition, the checked IR, and verifier
// diagnostics; `file` is a BASENAME so a span never carries a host path.
pub mod source;
pub mod time;
// The one bound left on a unix socket path once kata addresses it through its
// parent's descriptor: the file name's length.
pub mod unix_socket_name;
// When a main-resolved wait comes due — shared by the checked program that
// lowers a durable sleep and the operational plane that records the deadline.
pub mod wait;
// The coordinate of an execution's `/work` head, shared by the checked program
// that derives it per stage and the operational plane that keys its rows by it.
pub mod work_tree_head;
pub mod worker;
pub mod workflow;
pub mod workspace_awareness;
pub mod youki_pin;

// REST/SSE wire types, here so the SDK and the server share canonical Rust
// definitions instead of each maintaining a per-field mirror.
pub mod approval;
pub mod execution;
pub mod health;
pub mod ledger;

// BYO agent-run wire types.
pub mod agent_run;
pub mod strict_output_schema;

// Typed workflow invocation params (declaration, resolution, durable
// row) and the shared secret-redaction primitive.
pub mod params;
pub mod redaction;

// The execution target: the caller's spec and the frozen, resolved target an
// isolated invocation carries.
pub mod target;

// Shared serde round-trip helpers for the integration tests. Gated
// so it stays off the shipped surface; the self dev-dependency in `Cargo.toml`
// enables `test-support` for this crate's own `tests/`.
#[cfg(any(test, feature = "test-support"))]
pub mod test_support;

// Re-export convention
// --------------------
// Most modules are glob-re-exported into the crate root below so common domain
// types are reachable as `kata_types::Foo`. A deliberate set stays *path-only*
// (declared `pub mod` above but intentionally omitted from the globs below) and
// is reached as `kata_types::<module>::Foo`. This is by design, not oversight:
//
//   - `time`           — clock/duration helpers that read best when qualified.
//   - `agent_run`, `approval`, `execution`, `health`, `ledger`
//                      — REST/SSE wire mirrors kept path-qualified so the flat
//                        crate root stays unambiguous (e.g. the wire
//                        `execution::ExecutionStatus` reads as
//                        `kata_types::execution::…` at every call site).
//
// When adding a module: glob-re-export it here to match its siblings, or leave
// it path-only and extend the list above with the reason.

pub use agent::*;
pub use config::*;
pub use error::*;
pub use identity::*;
// Selective (mirrors the `effect` re-export): the admission digest + the
// convergence primitive at the crate root; the named relation helper stays
// `kata_types::identity_algebra::converge_accepted_event_content`.
pub use bound::{Bound, BoundError, BoundKind, validate_bounds};
pub use budget::{BudgetMode, BudgetPolicy};
pub use cache::*;
pub use effect::EffectKind;
pub use event::*;
pub use idempotency::*;
pub use identity_algebra::{AdmissionDigest, Divergence, converge};
pub use memory::*;
pub use params::{
    InvocationParam, MAX_INVOCATION_PARAMS, MAX_PARAM_VALUE_BYTES, ParamError, ParamProvenance,
    WorkflowParamSpec, param_provenance_evidence, resolve_and_validate_params,
};
pub use primitives::*;
pub use redaction::REDACTED_PLACEHOLDER;
// The metering trichotomy, re-exported flat.
pub use metering::{
    CostCharge, CostEnforcement, EstimateBasis, METERING_UNAVAILABLE_REASON_PREFIX, MeteredCost,
    MeteringQuality, MeteringSummary, ProviderCost, UnmeteredStage, metering_unavailable_reason,
};
pub use review_loop::*;
pub use sandbox::*;
pub use source::SourceSpan;
pub use worker::*;
pub use workflow::*;
pub use workspace_awareness::*;
