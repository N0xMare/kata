//! `kata-workflow` — the workflow runtime.
//!
//! This crate executes the checked programs `kata-program` compiles: the
//! runner and its dispatcher, admission into the operational plane, capsule
//! assembly and authorization, the result reactor and attempt delivery, the
//! workspace effects and `/work` applies, recovery, and the durable schedule
//! authority. It does **not** call agent backends directly: it produces stage
//! dispatch decisions that the transport layer turns into capsule
//! `DispatchFrame`s and delivers to workers.

// The crate is `unsafe`-free; the crate-level `deny` keeps it so.
#![deny(unsafe_code)]

pub mod admission;
pub mod attempt_delivery;
pub mod authorization;
/// CAPSULE ASSEMBLY: one lowered operation plus its
/// checked stage and resolved sandbox become the immutable `(PreparedAction,
/// Capsule)` worker input. Non-issuing: it writes no row, publishes no object,
/// and claims no attempt.
pub mod capsule_assembly;
pub mod delivery_service;
pub mod dispatcher;
pub mod execution_lifecycle;
pub mod execution_program_store;
pub mod promotion_gate;
pub mod reactor;
pub mod recovery_exchange;
pub mod repo_artifacts;
pub mod runner;
/// The engine-level schedule authority — a declared schedule's durable cursor
/// that survives an engine restart and fires from a sweep, never a
/// process-local timer. What a pack declares is `kata_program::schedule`.
pub mod schedule;
pub mod target_reads;
/// The node rigs the runtime's cells drive (an `oci` main over one data
/// directory, a scripted worker, fixture environments and seeded attempts).
pub mod test_harness;
pub mod workspace_reads;
pub mod worktree_isolation;
