//! Sample builders for the dispatch frames and configs that workflow / core /
//! transport tests push around.

use smol_str::SmolStr;
use ulid::Ulid;

use kata_transport::types::{CapsuleAssignment, CapsuleRef};
use kata_types::execution_contract::{CapsuleId, OccurrenceId};

/// Thin wrapper around `tempfile::tempdir()` so tests don't have to
/// depend on `tempfile` directly.
///
/// Panics if a temp directory cannot be created — this is a test helper,
/// not production code.
#[must_use]
pub fn tempdir() -> tempfile::TempDir {
    tempfile::tempdir().expect("kata-test-utils: failed to create tempdir")
}

/// Canonical `CapsuleAssignment` builder for transport / workflow / core
/// tests — the only dispatch frame shape that exists.
///
/// `attempt_id`/`execution_id`/`occurrence_id`/`capsule` are fabricated ids,
/// not references a worker can resolve — a frame fixture exercises the socket
/// and fence machinery, never capsule resolution (that door is
/// `kata_worker::capsule_frame`, driven by harnesses that assemble a real
/// capsule).
#[must_use]
pub fn sample_capsule_assignment() -> CapsuleAssignment {
    CapsuleAssignment {
        attempt_id: Ulid::new(),
        execution_id: Ulid::new(),
        occurrence_id: OccurrenceId(kata_types::primitives::ContentHash::new([0x5a; 32])),
        capsule: CapsuleRef {
            id: CapsuleId(kata_types::primitives::ContentHash::new([0x6b; 32])),
            object: kata_types::primitives::ObjectId::new([0x7c; 32]),
            size_bytes: 128,
        },
        lease_epoch: 0,
        placed_on: SmolStr::default(),
        command_id: None,
        effect_domain: None,
        start_deadline_ms: None,
        progress_visibility: kata_types::workflow::ProgressVisibility::Off,
        trace: kata_transport::types::TraceContext::default(),
    }
}

/// An `ApiConfig` with authentication disabled, bound to an ephemeral
/// loopback port, shared by the `kata-api` and `kata` binary integration
/// tests.
#[must_use]
pub fn disabled_auth_config() -> kata_types::config::ApiConfig {
    kata_types::config::ApiConfig {
        bind: "127.0.0.1:0".into(),
        auth: kata_types::config::ApiAuthConfig::Disabled {},
    }
}
