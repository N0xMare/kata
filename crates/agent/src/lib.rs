//! `kata-agent` — the attempt-scoped agent adapter contract, and the
//! spawn-side [`CommandPrefix`] and [`ResourceBounds`] a worker applies to a
//! child it starts. The one adapter kata ships, the embedded nanocode harness,
//! lives in `kata-agent-nanocode`.

/// The attempt-scoped agent ADAPTER contract: a scope that cannot express a
/// host path, a turn outcome with an ambiguous arm, and the session trait. No
/// adapter, no I/O.
pub mod adapter;
/// The wrapper argv, seccomp floor and resource bounds a worker spawn site
/// applies.
pub mod command_prefix;
/// The resolved resource-bound instruction a spawn site executes, and
/// the confirmed/ambiguous vocabulary a teardown records itself in.
pub mod resource_bounds;

pub use command_prefix::CommandPrefix;
pub use resource_bounds::{
    AmbiguousTeardown, CgroupPlan, ResourceBounds, TeardownOutcome, TeardownProbe,
};
// NO crate-root re-export of the `adapter` surface, deliberately: it is
// addressed through its own namespace (`kata_agent::adapter::…`).
