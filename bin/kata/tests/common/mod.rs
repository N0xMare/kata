//! Shared fixtures for the CLI integration tests.
//! Referenced via `mod common;` from the sibling test files that need
//! generated-config assertions.
#![allow(dead_code)]

use kata_types::config::AgentBackendConfig;
use std::collections::BTreeMap;

/// Every agent label the generated starter pack selects must be declared by
/// the generated config. `kata init` writes `[agents.default]` (the codex
/// capsule launch) and `[agents.shell]` unconditionally — under the `oci`
/// route the capsule launches inside the node's declared environment, so there
/// is no host fact that could make a generated label undeliverable, and a
/// missing one is `adapter_undeclared` at check.
pub fn assert_factory_agent_labels_are_configured(
    labels: &[String],
    agents: &BTreeMap<String, AgentBackendConfig>,
) {
    assert!(
        !labels.is_empty(),
        "starter should use explicit configured stage labels"
    );
    for label in labels {
        assert!(
            agents.contains_key(label.as_str()),
            "generated config must define stage agent label {label:?}; it declared {:?}",
            agents.keys().collect::<Vec<_>>()
        );
    }
}
