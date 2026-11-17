//! Agent-listing and VCS-preflight rendering tests:
//! `render_agent_listing` default resolution and
//! `render_vcs_preflight` warnings, plus the example-config listing.

use kata::cli::testing::{render_agent_listing, render_vcs_preflight};
use kata_core::ConfigManager;
use kata_types::config::{AgentBackendConfig, VcsConfig};
use std::collections::BTreeMap;
use std::path::Path;

/// `kata config check` must surface the resolved backend
/// for each `[agents.<name>]` entry so operators can verify config
/// edits without booting the full system. The check below pins the
/// shape against the canonical `config/kata.example.toml`, the file
/// `just config-check` exercises.
///
/// `default -> harness`, which makes this file AGREE with `kata init` — if the
/// two disagreed, a pack comment naming either backend as "the default" would
/// be wrong for half the operators reading it.
#[test]
fn config_check_lists_resolved_agent_backends_for_example() {
    // Resolve the example config relative to this crate's manifest
    // directory. `cargo test` (and `just test` via nextest) sets
    // `CARGO_MANIFEST_DIR` to `bin/kata`, so we walk up to the
    // workspace root.
    let manifest = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let example = manifest
        .join("../../config/kata.example.toml")
        .canonicalize()
        .expect("config/kata.example.toml must exist for config-check tests");

    let cfg = ConfigManager::load(&example)
        .expect("example config must parse cleanly")
        .snapshot();

    let lines = render_agent_listing(&cfg.agents, "    ");
    let joined = lines.join("\n");

    assert!(
        joined.contains("default -> harness"),
        "expected `default -> harness` in agent listing — this file must agree with \
         `kata init`; got:\n{joined}"
    );
    assert!(
        joined.contains("[default]"),
        "expected `[default]` marker on the resolved default agent; got:\n{joined}"
    );
    // `[agents.reviewer]` and `[agents.gate]` are the role labels a pack asks for
    // by name; each shares a TYPE with `default` and is free to carry a
    // different model or effort.
    for role in ["reviewer", "gate"] {
        assert!(
            joined.contains(&format!("{role} -> harness")),
            "expected `{role} -> harness` in agent listing; got:\n{joined}"
        );
    }
    assert!(
        joined.contains("model: gpt-6-luna"),
        "expected the configured model in agent listing; got:\n{joined}"
    );
}

/// Unit pin: with no `default` key but a single agent, the
/// sole entry is treated as the default, matching the resolution
/// rule documented in `config/kata.example.toml`.
#[test]
fn render_agent_listing_promotes_sole_entry_to_default() {
    let mut agents: BTreeMap<String, AgentBackendConfig> = BTreeMap::new();
    agents.insert(
        "only".to_string(),
        AgentBackendConfig::Harness {
            model: Some("gpt-test-model".to_string()),
            reasoning_effort: None,
            adapter: None,
            credential: None,
            env: std::collections::BTreeMap::new(),
        },
    );
    let lines = render_agent_listing(&agents, "  ");
    assert_eq!(lines.len(), 1);
    assert!(
        lines[0].contains("only -> harness")
            && lines[0].contains("model: gpt-test-model")
            && lines[0].ends_with("[default]"),
        "sole agent must be marked default; got: {}",
        lines[0]
    );
}

/// Unit pin: with multiple agents and no `default` key, no
/// agent is auto-promoted — operators see the listing without a
/// misleading `[default]` marker.
#[test]
fn render_agent_listing_no_auto_default_for_multiple_unnamed() {
    let mut agents: BTreeMap<String, AgentBackendConfig> = BTreeMap::new();
    agents.insert(
        "alpha".to_string(),
        AgentBackendConfig::Harness {
            model: None,
            reasoning_effort: None,
            adapter: None,
            credential: None,
            env: std::collections::BTreeMap::new(),
        },
    );
    agents.insert("beta".to_string(), AgentBackendConfig::Shell {});
    let lines = render_agent_listing(&agents, "  ");
    assert_eq!(lines.len(), 2);
    for line in &lines {
        assert!(
            !line.contains("[default]"),
            "no agent should be marked default without an explicit `default` key; got: {line}"
        );
    }
    // Codex `model = None` renders as `<default>`; shell has no
    // model field at all, rendering as `<n/a>`.
    assert!(lines[0].contains("alpha -> harness (model: <default>)"));
    assert!(lines[1].contains("beta -> shell (model: <n/a>)"));
}

/// Say so plainly. A config whose single entry is `[agents.shell]` is marked
/// `[default]` by `render_agent_listing`, accurately (the registry's sole-entry
/// rule really does route unqualified stages there) and misleadingly.
/// `kata config check` must state what that config can and cannot run.
#[test]
fn config_check_states_plainly_when_no_model_backed_agent_is_configured() {
    let mut agents: BTreeMap<String, AgentBackendConfig> = BTreeMap::new();
    agents.insert("shell".to_string(), AgentBackendConfig::Shell {});
    let joined = render_agent_listing(&agents, "  ").join("\n");

    assert!(
        joined.contains("shell -> shell"),
        "the entry itself must still be listed; got:\n{joined}"
    );
    assert!(
        joined.contains("NO MODEL-BACKED AGENT IS CONFIGURED"),
        "a config that cannot run a model stage must say so; got:\n{joined}"
    );
    for named in [
        "agent = \"shell\"",
        "std.hello",
        "std.software_factory",
        "adapter_undeclared",
        "[agents.default]",
        "\"nanocode_openai\"",
    ] {
        assert!(
            joined.contains(named),
            "the advisory must name {named:?} — what still runs, what does not, and the block \
             to add; got:\n{joined}"
        );
    }

    // Counterfactual: adding one model-backed entry must silence it, or the
    // advisory is satisfiable by printing unconditionally.
    agents.insert(
        "default".to_string(),
        AgentBackendConfig::Harness {
            model: None,
            reasoning_effort: None,
            adapter: None,
            credential: None,
            env: std::collections::BTreeMap::new(),
        },
    );
    let with_model = render_agent_listing(&agents, "  ").join("\n");
    assert!(
        !with_model.contains("NO MODEL-BACKED AGENT"),
        "a config WITH a model agent must not carry the advisory; got:\n{with_model}"
    );
    assert_eq!(
        render_agent_listing(&agents, "  ").len(),
        2,
        "and must print exactly one line per agent"
    );
}

/// An `[agents]`-less config is the same fact with no rows at all, and must not
/// render as total silence.
#[test]
fn config_check_states_the_same_thing_for_a_config_with_no_agents_at_all() {
    let joined = render_agent_listing(&BTreeMap::new(), "  ").join("\n");
    assert!(
        joined.contains("NO MODEL-BACKED AGENT IS CONFIGURED"),
        "an empty `[agents]` table must not render as silence; got:\n{joined}"
    );
}

#[test]
fn render_vcs_preflight_warns_for_relative_native_jj_repo() {
    let vcs = VcsConfig {
        jj_repo: std::path::PathBuf::from("relative-jj"),
        ..VcsConfig::default()
    };

    let joined = render_vcs_preflight(&vcs, Path::new("/var/lib/kata/data"), "  ").join("\n");
    assert!(
        joined.contains("vcs.jj_repo = relative-jj"),
        "expected jj repo path in VCS preflight; got:\n{joined}"
    );
    assert!(
        joined.contains("vcs.jj_repo.has_jj = false"),
        "expected missing .jj signal in VCS preflight; got:\n{joined}"
    );
    assert!(
        joined.contains("warning: vcs.jj_repo is relative"),
        "expected relative-path warning in VCS preflight; got:\n{joined}"
    );
    assert!(
        joined.contains("warning: native jj provider will initialize vcs.jj_repo"),
        "expected auto-init warning in VCS preflight; got:\n{joined}"
    );
}

/// `kata config check` and `kata doctor` must name the SAME set of paths kata
/// writes into the operator's repository.
///
/// The advisory this replaces hand-retyped "`.jj/` and `/agents/`" beside the
/// code that creates those paths, and printed only while `.jj/` did not exist
/// yet — so it was silent on every repo that had already booted, which is the
/// state the first live gold-loop run was in when it promoted 46 files of kata
/// internals into a fixture's trunk. Both surfaces now read
/// `repo_local_artifact_roots`, and this asserts that identity rather than a
/// third copy of the list.
#[test]
fn the_vcs_preflight_note_names_the_roots_doctor_scores() {
    let vcs = VcsConfig::default();
    // A data dir OUTSIDE the repo, so this test still scores exactly the
    // provider half; the config-determined half has its own test below.
    let joined = render_vcs_preflight(&vcs, Path::new("/var/lib/kata/data"), "  ").join("\n");
    assert!(
        joined.contains("target_repo_ignore"),
        "the preflight must point at the row that VERIFIES this; got:\n{joined}"
    );
    for root in kata_workflow::repo_artifacts::repo_local_artifact_roots() {
        assert!(
            joined.contains(&format!("{root}/")),
            "the preflight must name {root}/; got:\n{joined}"
        );
    }
}

/// REGRESSION. A note naming only the roots the execution-workspace
/// PROVIDER writes would omit `node.data_dir`. `kata init` renders
/// `data_dir = "data"` beside the config, so the default project keeps
/// `operational.db`, `cas/`, `memory.db` and `recovery-generations/**` inside
/// `vcs.jj_repo` — measured landing in the repo's jj working copy on a fixture
/// where `kata doctor` reported `passed=true`.
///
/// COUNTERFACTUAL: revert `render_vcs_preflight` to `repo_local_artifact_roots`
/// and this goes red on the first assertion.
#[test]
fn the_vcs_preflight_note_names_a_data_dir_that_lands_inside_the_repo() {
    let repo = std::path::PathBuf::from("/srv/project");
    let vcs = VcsConfig {
        jj_repo: repo.clone(),
        ..VcsConfig::default()
    };

    let inside = render_vcs_preflight(&vcs, &repo.join(".kata").join("data"), "  ").join("\n");
    assert!(
        inside.contains(".kata/data/"),
        "a data dir inside vcs.jj_repo must be named as something kata writes there; got:\n{inside}"
    );

    // NON-VACUITY: the shipped example config puts it at `~/.kata/data`, outside
    // every repository. Naming it there would refuse operators for a path they
    // never create.
    let outside = render_vcs_preflight(&vcs, Path::new("/home/op/.kata/data"), "  ").join("\n");
    assert!(
        !outside.contains(".kata/data/"),
        "a data dir outside vcs.jj_repo must not be named; got:\n{outside}"
    );
}

// ---- `kata config check` prints resolved stdlib roots ----

/// `kata config check` must surface the resolved workflow stdlib
/// roots so an operator can confirm a fresh-box install materialized the
/// library. Each root carries an `[exists]`/`[missing]` marker; when the
/// KATA_STDLIB_DIR points at a real directory it is listed as `[exists]`.
#[test]
fn render_stdlib_roots_lists_resolved_roots_with_existence_marker() {
    use kata::cli::testing::render_stdlib_roots;
    use kata_program::library::WorkflowLibrary;

    let present = tempfile::tempdir().unwrap();
    let real = present.path().join("real-root");
    std::fs::create_dir_all(&real).unwrap();
    let ghost = present.path().join("ghost-root");

    let library = WorkflowLibrary::new(vec![real.clone(), ghost.clone()]);
    let lines = render_stdlib_roots(&library, "  ");

    let joined = lines.join("\n");
    assert!(
        joined.contains("workflow stdlib roots = 2 configured"),
        "must print a header naming the root count; got:\n{joined}"
    );
    assert!(
        joined.contains(&format!("[exists] {}", real.display())),
        "an existing root must be marked [exists]; got:\n{joined}"
    );
    assert!(
        joined.contains(&format!("[missing] {}", ghost.display())),
        "a missing root must be marked [missing]; got:\n{joined}"
    );
}

/// When EVERY root is absent, the config-check stdlib listing must
/// carry a loud WARNING line naming the degrade — an install that resolves
/// zero workflows cannot be silent.
#[test]
fn render_stdlib_roots_warns_loudly_when_all_roots_missing() {
    use kata::cli::testing::render_stdlib_roots;
    use kata_program::library::WorkflowLibrary;

    let base = tempfile::tempdir().unwrap();
    let a = base.path().join("nope-a");
    let b = base.path().join("nope-b");
    let library = WorkflowLibrary::new(vec![a, b]);
    let lines = render_stdlib_roots(&library, "  ");
    let joined = lines.join("\n");
    assert!(
        joined.contains("WARNING") && joined.contains("ZERO workflows"),
        "all-missing roots must produce a loud WARNING line; got:\n{joined}"
    );
}
