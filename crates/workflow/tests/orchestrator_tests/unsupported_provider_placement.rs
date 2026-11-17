//! Placement must not ACCEPT an exec
//! backend that no runtime in this build can run.
//!
//! # The defect these pin
//!
//! A placement gate that refused only `ExecBackend::Host` for a
//! Contained-class stage would let a backend this build ships no runtime for
//! fall through a `_ => {}` arm, be placed, CLAIMED, and only then fail at the
//! worker as an `Internal` error — a burned attempt and a misattributed late
//! failure.
//!
//! # Where the refusal lands
//!
//! "This build ships no runtime for backend X" is a COMPILE-TIME constant
//! (`ExecBackend::provider_posture`); today only `oci` off Linux answers it.
//! No authoring surface spells a backend (there is no `exec=` keyword), so
//! an authored backend is refused at LOAD by name, and the BYO surface
//! (`ByoExecPolicy`'s `Deserialize`) refuses anything but `host`/`oci`.

use kata_program::execution_program::compile_starlark_execution_program;
use kata_types::sandbox::{ExecBackend, ExecProviderPosture};

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// 1. Load time — the earliest point the fact is knowable
// ---------------------------------------------------------------------------

/// NON-VACUITY, asserted before the behaviour under test: the posture authority
/// really does return more than one answer, so a caller that reads it is not
/// reading a constant. (`UnsupportedInThisBuild` is the off-Linux `oci` answer,
/// pinned per target by `kata_types::sandbox`'s `provider_build_tests`.)
#[test]
fn unsupported_provider_posture_authority_returns_more_than_one_answer() {
    assert_eq!(
        ExecBackend::Oci.provider_posture(),
        ExecProviderPosture::CertifiedContainment,
        "oci is the containment provider this build ships (on Linux)"
    );
    assert_eq!(
        ExecBackend::Host.provider_posture(),
        ExecProviderPosture::Unconfined,
        "host runs with full ambient authority — a runtime exists, containment does not"
    );
    for supported in [ExecBackend::Host, ExecBackend::Oci] {
        assert!(
            supported.unsupported_in_this_build_reason().is_none(),
            "a backend with a runtime must not carry an unsupported reason"
        );
    }
}

#[test]
fn unsupported_provider_authored_firecracker_is_refused_at_load() {
    let err = compile_starlark_execution_program(
        r#"
b = stage(id = "b", agent = "shell", run = "true", sandbox = "vm")
workflow(
    "wf",
    root = [b],
    sandbox_profiles = {"vm": sandbox_profile(exec = "firecracker", net = "offline")},
)
"#,
        "provider_load.star",
        &[],
    )
    .expect_err(
        "a pack declaring an exec backend must not compile — the authoring surface spells \
         no backend at all, so load is the earliest honest refusal",
    );
    let msg = err.to_string();
    assert!(
        msg.contains("Found `exec` extra named parameter(s)"),
        "the refusal must name the keyword the signature lacks rather than a build posture \
         no keyword can select: {msg}"
    );
}
