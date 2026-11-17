//! `kata-test-seeded` — kata's seeded deterministic test runs.
//!
//! - `run_seeded`, which wraps
//!   `commonware_runtime::deterministic::Runner` in a seed-management
//!   pattern: an env-captured seed, a labelled root context, and a repro
//!   command printed on panic.
//! - `Seed` newtype for env-driven seed capture.
//!
//! A crate of its own so that commonware's runtime and its dependency closure
//! reach only the test binaries that run seeded bodies, not every consumer of
//! `kata-test-utils`.

#![forbid(unsafe_code)]

pub mod runner;
pub mod seed;

pub use runner::run_seeded;
pub use seed::Seed;
