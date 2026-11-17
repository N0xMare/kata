//! The operator's door to ADR-0001's installed containment policy, walked end
//! to end: `config/kata.example.toml` → `ConfigManager::load` → `KataConfig` →
//! `install_node_containment_policy` → a compile refusal.
//!
//! A policy nobody can switch on is not a policy. These tests refuse to reach
//! past the documented surface: they never construct a `ContainmentConfig`
//! literal, they take it from a parsed `kata.toml`, and they install it with the
//! same call `BootRig::boot` makes. If the TOML key were renamed, dropped from
//! the example, or silently not deserialized, `policy_reaches_the_compiler` goes
//! RED rather than passing on a hand-built struct.
//!
//! The one link these do NOT cover is `BootRig::boot`'s install call itself,
//! which is proven by `boot::tests::boot_installs_the_nodes_containment_policy`
//! (it needs a booted rig, so it lives beside the rig).

use std::path::{Path, PathBuf};

use kata_core::ConfigManager;
use kata_program::execution_program::compile_starlark_execution_program;
use kata_types::config::ContainmentConfig;
use kata_types::containment_policy::{
    install_node_containment_policy, installed_node_containment_policy,
};

/// A no-sandbox model editor: ADR-0001's canonical stage, minus the container.
/// The one authorable unconfined model editor: a stage that authors NO sandbox
/// is confined by default, so the counterexample the
/// policy exists to refuse has to say the reserved word.
const NO_SANDBOX_MODEL_EDITOR: &str = r#"
edit = stage(
    id = "edit",
    prompt = "edit the tree",
    agent = "codex",
    sandbox = "host",
)
workflow("model-editor", root = [edit])
"#;

struct PolicyGuard(ContainmentConfig);

impl PolicyGuard {
    fn install(policy: ContainmentConfig) -> Self {
        let previous = installed_node_containment_policy();
        install_node_containment_policy(policy);
        Self(previous)
    }
}

impl Drop for PolicyGuard {
    fn drop(&mut self) {
        install_node_containment_policy(self.0);
    }
}

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("bin/kata lives two levels below the repo root")
        .to_path_buf()
}

fn shipped_example_config() -> String {
    let path = repo_root().join("config").join("kata.example.toml");
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("reading {}: {e}", path.display()))
}

/// Load a config TOML through the same `ConfigManager` a node boots with.
fn load(text: &str, dir: &Path) -> kata_types::config::KataConfig {
    let path = dir.join("kata.toml");
    std::fs::write(&path, text).expect("write config");
    ConfigManager::load(&path)
        .unwrap_or_else(|e| panic!("ConfigManager::load rejected the config: {e}"))
        .snapshot()
        .as_ref()
        .clone()
}

/// The shipped example config documents the section AND ships it ON, so an
/// operator who copies it gets the default posture.
#[test]
fn the_shipped_example_config_documents_the_knob_and_ships_it_on() {
    let text = shipped_example_config();
    assert!(
        text.contains("[containment]") && text.contains("require_contained_model_stages"),
        "config/kata.example.toml must document the [containment] section — it is the only \
         place an operator learns the knob exists"
    );

    let tmp = tempfile::tempdir().expect("tempdir");
    let cfg = load(&text, tmp.path());
    assert!(
        cfg.containment.require_contained_model_stages,
        "the shipped example must carry the DEFAULT posture: a model/agent stage runs in a \
         certified container. An example that ships the safety default off teaches the \
         opposite to every operator who copies it"
    );
}

/// A config that OMITS the section entirely still loads, and means ON.
///
/// The direction is the point: an operator who never writes the section gets
/// the refusal, because the default they inherit is the safe one. Pinned as a
/// test rather than left to the serde attribute because the failure mode is
/// silent: `#[serde(default)]` (the plain form) would compile, load, and mean
/// `false`, and every other test in this file would still pass while the
/// posture reached only operators who had hand-written the key.
#[test]
fn a_config_written_before_the_section_existed_still_loads_and_now_means_on() {
    let text = shipped_example_config();
    assert!(
        text.contains("[containment]"),
        "fixture assumption: the example carries the section"
    );
    let stripped: String = text
        .lines()
        .filter(|line| {
            !line
                .trim_start()
                .starts_with("require_contained_model_stages")
        })
        .filter(|line| line.trim() != "[containment]")
        .collect::<Vec<_>>()
        .join("\n");
    // The key survives only inside COMMENTS (the section's prose quotes it), and
    // a comment sets nothing. Assert on the settings, so this really is a test
    // of the default rather than of a value the file still carries.
    assert!(
        !stripped
            .lines()
            .any(|line| !line.trim_start().starts_with('#')
                && line.contains("require_contained_model_stages")),
        "fixture assumption: no SETTING line may still name the key, or what loads below is \
         that value and not the default"
    );

    let tmp = tempfile::tempdir().expect("tempdir");
    let cfg = load(&stripped, tmp.path());
    assert!(
        cfg.containment.require_contained_model_stages,
        "an omitted [containment] section must resolve to the safe default (ON) — otherwise \
         the posture reaches only configs that spell the key"
    );
    assert_eq!(
        cfg.containment,
        kata_types::config::ContainmentConfig::default(),
        "the serde default and `ContainmentConfig::default()` must agree; they are two \
         independent spellings of the same default and a drift between them means a \
         programmatically-built config silently disagrees with a loaded one"
    );
}

/// The whole door: flip the documented key in the shipped example, load it the
/// way a node does, install it the way boot does — and the compiler's verdict
/// follows the knob. Under the shipped `oci` profile the policy's refusal still
/// fires FIRST (it precedes the profile's class doors in
/// `compile_starlark_execution_program`), while the OFF arm's opt-out now only
/// admits the pack as far as the profile's own `sandbox = "host"` refusal —
/// which is what proves the policy, not a defect in the fixture, produced the
/// ON arm's verdict: the same source, the same knob value flipped, a DIFFERENT
/// named refusal.
#[test]
fn policy_reaches_the_compiler() {
    let tmp = tempfile::tempdir().expect("tempdir");

    // ON, straight from the shipped example: the no-sandbox editor is REFUSED.
    let on = load(&shipped_example_config(), tmp.path());
    assert!(
        on.containment.require_contained_model_stages,
        "the shipped example must load ON — if this fails the key is not wired to the struct \
         and the whole section is decorative"
    );
    {
        let _guard = PolicyGuard::install(on.containment);
        let err = compile_starlark_execution_program(NO_SANDBOX_MODEL_EDITOR, "editor.star", &[])
            .expect_err("with the shipped default the host-opt-out model editor must be refused");
        let msg = format!("{err}");
        assert!(
            msg.contains("stage \"edit\"") && msg.contains("installed containment policy"),
            "the refusal must name the stage and the policy that caused it; got: {msg}"
        );
        assert!(
            msg.contains("require_contained_model_stages = false"),
            "the refusal must name the knob an operator sets to reverse it; got: {msg}"
        );
    }

    // OFF, by editing exactly the documented key in exactly the documented
    // section — no other change to the file. The policy's opt-out IS honoured:
    // the verdict changes from the policy's refusal to the profile's own
    // `host_sandbox_unsupported_under_oci`, which the policy cannot satisfy —
    // under `oci` the stage's only admission is a confined profile.
    let flipped = shipped_example_config().replace(
        "require_contained_model_stages = true",
        "require_contained_model_stages = false",
    );
    let off = load(&flipped, tmp.path());
    assert!(
        !off.containment.require_contained_model_stages,
        "flipping the documented key back must reach KataConfig, or the escape the refusal \
         message advertises does not exist"
    );

    let _guard = PolicyGuard::install(off.containment);
    let err = compile_starlark_execution_program(NO_SANDBOX_MODEL_EDITOR, "editor.star", &[])
        .expect_err("with the policy's opt-out the profile's own refusal names the stage");
    let msg = format!("{err}");
    assert!(
        msg.contains("host_sandbox_unsupported_under_oci"),
        "the opt-out must change the verdict to the PROFILE's refusal — the same \
         message as the ON arm would mean the knob reached nothing; got: {msg}"
    );
}
