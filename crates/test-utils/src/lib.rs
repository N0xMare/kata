//! `kata-test-utils` — deterministic test infrastructure for kata.
//!
//! Contents:
//!
//! - `MockAgentBackend` — the response queue the workflow test harness's
//!   scripted capsule worker answers frames from.
//! - `fixtures` — sample builders (dispatch frames, configs) for tests.
//! - `workflow_helpers` — a programmatic workflow builder for tests.
//!
//! This crate is NOT allowed to depend on `kata-core`: `kata-core` takes it
//! as a dev-dependency, and the reverse edge would be circular. Seeded
//! deterministic runs (`run_seeded`, `Seed`) live in `kata-test-seeded`, so
//! commonware's runtime is not linked into every binary that loads this crate.

#![forbid(unsafe_code)]

pub mod capability;
pub mod delegated_scope;
pub mod fixtures;
pub mod git;
// A loopback port held out of the kernel's ephemeral pool while code under
// test binds it by number.
pub mod held_port;
pub mod host_repo;
// Kernel-side open/read observation for cells that must prove a path was
// never opened (the credential opt-in's cells).
pub mod inotify;
// Cross-process per-uid serialization for tests that drive a product
// immutable-SQLite inspection. See the module docs for the false FAIL it removes.
pub mod inspection_lock;
pub mod live;
pub mod mock_agent;
// A spawned main's API endpoint, read off what only that main writes.
pub mod own_main;
/// The runtime half of `#[kata_timeout]`; the macro's expansion calls it.
#[doc(hidden)]
pub mod timeout_watchdog;
pub mod worker_death_fixtures;
pub mod workflow_helpers;
pub mod youki_registry;

pub use capability::{REQUIRE_LIVE_ENV, capability_skip, operator_fixture_dir, require_live};
pub use fixtures::{disabled_auth_config, sample_capsule_assignment};
pub use git::{
    HERMETIC_OVERRIDES, hermetic_git, hermetic_git_in, init_git_repo, init_git_repo_at, run_git,
    write_hermetic_config,
};
pub use host_repo::{HostBindings, HostIdentity, HostRepo, TRUNK_NAMES};
pub use mock_agent::{MockAgentBackend, MockResponse};
pub use worker_death_fixtures::KILL_MID_RUN_WF;
pub use workflow_helpers::simple_two_stage_workflow;

/// `#[kata_timeout(secs = N)]` attribute proc-macro re-exported from
/// `kata-test-macros`. Stack above `#[tokio::test]` (or `#[test]`) to arm a
/// real-time watchdog ([`timeout_watchdog`]) that ends a hung test by name
/// before nextest's kill. See `crates/test-macros/src/lib.rs` for the contract.
pub use kata_test_macros::kata_timeout;
