//! Test-only helpers shared across the `kata-types` integration tests.
//!
//! This module is compiled only under `#[cfg(test)]` (the crate's own unit
//! tests) or when the `test-support` feature is enabled (the self
//! dev-dependency in `Cargo.toml` turns it on for the `tests/` targets, which
//! compile against `kata-types` as an ordinary dependency). It is absent from
//! shipped builds.
//!
//! The serde round-trip idiom — serialize a value, deserialize it back, assert
//! the result is structurally identical — was copy-pasted as a private
//! `json_roundtrip` helper across nearly every `tests/*_tests.rs` file. The
//! canonical shape now lives here once.

use serde::{Deserialize, Serialize};

/// Serialize `v` to JSON, deserialize it back, and assert the round-trip is
/// lossless (`v == back`).
pub fn json_roundtrip<T>(v: T)
where
    T: Serialize + for<'de> Deserialize<'de> + PartialEq + std::fmt::Debug,
{
    let s = serde_json::to_string(&v).expect("serialize");
    let back: T = serde_json::from_str(&s).expect("deserialize");
    assert_eq!(v, back);
}

/// A structurally valid frozen TRUNK target for fixtures that admit an
/// isolated program with NO repository behind them — a rig whose `/work` head
/// and git view are seeded directly, so nothing ever forks from this target.
/// Its head is a placeholder 40-hex id no store holds. A test with a real
/// repository resolves its target through the provider instead
/// (`kata_vcs::test_support::resolve_trunk_target`).
#[must_use]
pub fn fixture_trunk_target() -> crate::target::ExecutionTarget {
    crate::target::ExecutionTarget {
        spec: crate::target::TargetSpec::Trunk,
        head: crate::target::TargetHead::Commit("f".repeat(40)),
        branch: Some("main".to_owned()),
        compare: None,
        pull_request: None,
    }
}
