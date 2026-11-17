//! Tests for `crates/types/src/agent.rs`. Extracted from the inline
//! `#[cfg(test)]` module.

use kata_types::agent::{AgentId, BackendType, Prompt};
use kata_types::test_support::json_roundtrip;
use ulid::Ulid;

#[test]
fn agent_id_roundtrip() {
    json_roundtrip(AgentId(Ulid::new()));
}

#[test]
fn backend_type_roundtrip() {
    for variant in [
        BackendType::Harness,
        BackendType::Shell,
        BackendType::WorkspaceEffect,
    ] {
        json_roundtrip(variant);
    }
}

#[test]
fn backend_type_label_matches_serde() {
    // label() is the canonical string stamped on
    // durable ledger `agent_label` fields and `agent:<label>` capability
    // strings. It MUST match the serde snake_case representation.
    for variant in [
        BackendType::Harness,
        BackendType::Shell,
        BackendType::WorkspaceEffect,
    ] {
        let serde_form = serde_json::to_value(variant).unwrap();
        let expected = serde_form.as_str().expect("snake_case string");
        assert_eq!(variant.label(), expected);
    }
}

#[test]
fn backend_type_shell_label_is_shell() {
    // Pin: the shell variant's label MUST be exactly `"shell"`
    // (matching the `agent = "shell"` key authors write in TOML). A
    // drift here would silently break every shell smoke workflow.
    assert_eq!(BackendType::Shell.label(), "shell");
    assert_eq!(
        serde_json::to_value(BackendType::Shell)
            .unwrap()
            .as_str()
            .unwrap(),
        "shell"
    );
}

#[test]
fn prompt_roundtrip() {
    json_roundtrip(Prompt {
        text: "Hello".to_owned(),
        credential: None,
        model_hint: None,
        effort_hint: None,
        output_schema: None,
    });
}

#[test]
fn provider_cost_roundtrip() {
    json_roundtrip(kata_types::metering::ProviderCost::Reported { micro_usd: 1_234 });
    // The OTHER arm must round-trip too. A provider that stated nothing must
    // decode back to `Unstated`, never to a zero charge — the executor's
    // pricing classifier treats those two as different facts.
    json_roundtrip(kata_types::metering::ProviderCost::Unstated);
}
