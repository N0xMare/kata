//! Tests for `crates/types/src/identity.rs`. Extracted from the inline
//! `#[cfg(test)]` module.

use kata_types::agent::BackendType;
use kata_types::identity::{WorkerResource, WorkerResourceParseError};
use smol_str::SmolStr;
use std::str::FromStr;

#[test]
fn worker_capability_from_str_shell_no_payload() {
    assert_eq!(
        WorkerResource::from_str("shell").unwrap(),
        WorkerResource::Shell
    );
}

#[test]
fn worker_capability_from_str_network_no_payload() {
    assert_eq!(
        WorkerResource::from_str("network").unwrap(),
        WorkerResource::Network
    );
}

#[test]
fn worker_capability_from_str_kind_is_case_insensitive() {
    // The kind is canonicalised via to_ascii_lowercase before
    // matching, so both `SHELL` and `Network` parse the same as
    // their lowercase forms.
    assert_eq!(
        WorkerResource::from_str("SHELL").unwrap(),
        WorkerResource::Shell
    );
    assert_eq!(
        WorkerResource::from_str("Network").unwrap(),
        WorkerResource::Network
    );
    assert_eq!(
        WorkerResource::from_str("Agent_Backend=harness").unwrap(),
        WorkerResource::AgentBackend(BackendType::Harness)
    );
}

#[test]
fn worker_capability_from_str_agent_backend_each_variant() {
    // `harness` is the one backend a worker can advertise by name; `shell` is
    // its own capability kind and `workspace_effect` runs on no worker.
    assert_eq!(
        WorkerResource::from_str("agent_backend=harness").unwrap(),
        WorkerResource::AgentBackend(BackendType::Harness),
    );
}

#[test]
fn worker_capability_from_str_disk_and_gpu_take_u32() {
    assert_eq!(
        WorkerResource::from_str("disk=64").unwrap(),
        WorkerResource::Disk { min_gb: 64 }
    );
    assert_eq!(
        WorkerResource::from_str("gpu=24").unwrap(),
        WorkerResource::Gpu { min_vram_gb: 24 }
    );
}

#[test]
fn worker_capability_from_str_custom_takes_string_verbatim() {
    // The payload after `custom=` must be preserved exactly,
    // including punctuation. `agent_backend=<label>` is the only
    // form that validates its payload further.
    assert_eq!(
        WorkerResource::from_str("custom=experimental.runtime").unwrap(),
        WorkerResource::Custom(SmolStr::new("experimental.runtime"))
    );
}

#[test]
fn worker_capability_from_str_unknown_kind_rejected() {
    let err = WorkerResource::from_str("teleport").unwrap_err();
    assert!(matches!(
        err,
        WorkerResourceParseError::UnknownKind(ref s) if s == "teleport"
    ));
    // Display lists the accepted forms so the operator can
    // self-correct without grep.
    let msg = err.to_string();
    assert!(msg.contains("teleport"));
    assert!(msg.contains("agent_backend"));
    assert!(msg.contains("shell"));
}

#[test]
fn worker_capability_from_str_unknown_backend_rejected() {
    let err = WorkerResource::from_str("agent_backend=neo_agent").unwrap_err();
    assert!(matches!(
        err,
        WorkerResourceParseError::UnknownBackend(ref s) if s == "neo_agent"
    ));
    let msg = err.to_string();
    assert!(msg.contains("neo_agent"));
    // The "valid backends" list names the label an operator can use.
    assert!(msg.contains("valid backends: harness"), "{msg}");
}

#[test]
fn worker_capability_from_str_missing_payload_rejected() {
    for kind in ["agent_backend", "disk", "gpu", "custom"] {
        let err = WorkerResource::from_str(kind).unwrap_err();
        assert!(
            matches!(err, WorkerResourceParseError::MissingPayload(k) if k == kind),
            "kind {kind:?} should require a payload, got {err:?}"
        );
    }
}

#[test]
fn worker_capability_from_str_unexpected_payload_rejected() {
    for kind in ["shell", "network"] {
        let spec = format!("{kind}=oops");
        let err = WorkerResource::from_str(&spec).unwrap_err();
        assert!(
            matches!(err, WorkerResourceParseError::UnexpectedPayload(k) if k == kind),
            "kind {kind:?} should reject a payload, got {err:?}"
        );
    }
}

#[test]
fn worker_capability_from_str_invalid_number_rejected() {
    for kind in ["disk", "gpu"] {
        let spec = format!("{kind}=lots");
        let err = WorkerResource::from_str(&spec).unwrap_err();
        assert!(
            matches!(
                err,
                WorkerResourceParseError::InvalidNumber { kind: k, ref value }
                    if k == kind && value == "lots"
            ),
            "spec {spec:?} should report InvalidNumber, got {err:?}"
        );
    }
}

#[test]
fn worker_capability_json_roundtrip() {
    let caps = vec![
        WorkerResource::AgentBackend(BackendType::Harness),
        WorkerResource::Disk { min_gb: 64 },
        WorkerResource::Gpu { min_vram_gb: 24 },
        WorkerResource::Network,
        WorkerResource::Shell,
        WorkerResource::Custom(SmolStr::new("custom.runtime")),
    ];
    let j = serde_json::to_string(&caps).unwrap();
    let back: Vec<WorkerResource> = serde_json::from_str(&j).unwrap();
    assert_eq!(caps, back);
}
