//! Plain modules shared by this crate's integration tests. Lives under `tests/common/`
//! so cargo treats it as a module (`mod common;`), not a test target, and so
//! `gate_exclusion.rs`'s scan of `tests/*.rs` never reads it as a binary. Nothing here
//! carries a `#[test]`.
//!
//! `#![allow(dead_code)]` because each test binary uses a different subset.
#![allow(dead_code)]

pub mod justfile;
pub mod nextest;
pub mod rust_tree;

use std::path::{Path, PathBuf};

pub fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("crate lives under <repo>/bin/kata-eval")
        .to_path_buf()
}

/// What "this test binary can decline to assert for a HOST reason" is spelled as,
/// and why each spelling counts.
///
/// ONE definition, readable by a human and computable by both checks — two readers
/// disagreeing about what a word means is a defect class of its own, and "requires live
/// capability" is exactly the kind of word that invites it. The definition chosen is
/// **behavioural, not topical**: not "is this test about the sandbox" (a proxy, and
/// proxies drift off their fact) but "can this test return
/// without asserting because of something about the host".
///
/// The first six are the knob that turns such a skip into a failure, or the shared
/// helpers that consult it. The last is the printed marker itself: a binary that emits
/// `SKIP[...]` is declaring a capability skip by the workspace's own convention, and
/// that is the net that caught all five of the binaries `gate_exclusion.rs`'s
/// CONTAINMENT COVERAGE section names — none of them referenced the knob at all, which
/// is precisely what made them invisible.
///
/// Shared: `gate_exclusion.rs` classifies a test BINARY with it (can it decline to
/// assert, so must the containment lane run it?), and `protected_property_ledger.rs`
/// classifies the FILE defining a ledger cell (a `host-free` cell may not live in one).
pub const LIVE_CAPABILITY_MARKERS: &[(&str, &str)] = &[
    (
        "KATA_SANDBOX_REQUIRE_LIVE",
        "names the skip-is-a-FAILURE knob directly",
    ),
    ("REQUIRE_LIVE_ENV", "names the const carrying that knob"),
    ("require_live(", "calls the skip-is-a-FAILURE predicate"),
    (
        "capability_skip(",
        "routes a skip through `kata_test_utils::capability_skip`",
    ),
    (
        "operator_fixture_dir(",
        "routes a skip through `kata_test_utils::capability::operator_fixture_dir` — a FIXTURE \
         absence, which `KATA_SANDBOX_REQUIRE_LIVE` deliberately does not refuse, and which is \
         therefore MORE in need of this guard rather than less: being permitted to skip is not \
         being permitted to hide. A binary whose only early return is a fixture absence prints \
         `SKIP[` at RUNTIME and carries it nowhere in its SOURCE, so without this marker the \
         scan below — which reads source, not output — would not see it at all",
    ),
    (
        "KATA_LIVE_SMOKE",
        "names the product-path skip knob (`just smoke`)",
    ),
    (
        "SKIP[",
        "prints the workspace's capability-skip marker, so it can return without asserting",
    ),
];
