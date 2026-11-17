//! The Nix managed-software plane: declare, root, reconcile, release.
//!
//! This module is the Nix-FACING half; `crate::operational::environments` is the durable half,
//! and
//! [`kata_types::nix_environment`] is the pure type half. The split follows
//! ADR-0001's trust boundary 5: Nix owns realization, transport, store
//! verification mechanisms and collection, and kata owns WHICH exact closure was
//! authorized, its binding, its retention intent and its crash-safe coordination
//! with Nix roots.
//!
//! ```text
//!   kata_types::nix_environment   pure types, hashing, refusals; no I/O
//!   environment::nix              the ONE process wrapper; explicit NixStore
//!   environment::declare          the ordered declare sequence
//!   environment::node             the node's boot declaration, bound for every capsule
//!   environment::roots            the on-disk gc-root layout and its sweeps
//!   environment::reconcile        the boot pass, and release
//!   operational::environments     the durable rows and their state machine
//! ```
//!
//! # Invariant
//!
//! No other module the main or a worker runs may spawn `nix` or `nix-store`, and
//! nothing outside [`nix`] ever sees a store selector. (`kata host setup`, an operator
//! command that runs before any main, probes and builds with the Nix CLI through its own
//! exec; it names no store selector and reaches no workload.) That is what makes "the Nix daemon
//! is not exposed to workloads" a checkable property of this tree rather than a
//! convention: there is exactly one door, it takes the store as an argument, and
//! the workload side of the code has no way to name one.

pub mod declare;
pub mod nix;
pub mod node;
pub mod reconcile;
pub mod roots;

pub use declare::{
    DeclarationInput, DeclarationSource, PreparedDeclaration, commit_declaration,
    declare_environment, prepare_declaration,
};
pub use nix::{NixError, NixStore, PathInfo};
pub use node::{
    NODE_ENVIRONMENT_NIX_UNAVAILABLE, NODE_ENVIRONMENT_PLATFORM_MISMATCH,
    NODE_ENVIRONMENT_SUPERSEDED, NODE_ENVIRONMENT_UNPROMOTED, NodeEnvironment,
    bind_node_environment, environment_path_programs,
};
pub use reconcile::{
    ReconcileReport, UnavailableEnvironment, reconcile_environments, release_environment,
};
pub use roots::PromoteOutcome;
