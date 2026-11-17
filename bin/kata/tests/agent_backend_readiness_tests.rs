//! `kata doctor` must FAIL when the config an operator wrote declares an agent
//! entry the capsule route cannot launch — and must say nothing about an agent
//! nobody declared. The row's verdict must name a way out.
//!
//! Under the `oci` route "can this agent run" is a config question, not a host
//! question: `agent_turn_spec` resolves `[agents.<label>]` through
//! `installed_node_agent`, and the capsule's init is `kata-toolhost`, fixed by the
//! kind, inside the node's declared `[node] environment` — never a program on this
//! host's `$PATH`. What a stage selecting `<label>` needs from the entry is the
//! capsule launch — an `adapter` naming a kind — judged by
//! [`kata_types::config::AgentBackendConfig::capsule_launch`], the same
//! function the assembly refuses through. A declared entry that lacks one is
//! `adapter_undeclared` (or `adapter_unqualified`, for a label that names no
//! kind) for every stage that selects it, so doctor reports that refusal
//! before the first run does.
//!
//! Every proof here is a PAIR held on ONE host: the two arms differ only in
//! what the CONFIG declares, which is what keeps `just gate`
//! host-independent — nothing in this file probes a binary, an environment
//! variable, or a network authority.

use std::path::{Path, PathBuf};

use kata::cli::testing::{DoctorStatus, doctor_report_with_logins_dir, no_kata_logins};
use kata::cli::{Cli, Command};

/// Scaffold a real `kata init` project and return its config path plus the
/// generated TOML with any `[agents.default]` table removed.
///
/// Deliberately built from the PRODUCTION generator rather than a hand-written
/// fixture: the row under test reads the config `kata init` actually emits, and
/// a fixture that happened to omit a table would prove nothing about it. The
/// `[agents.default]` block is stripped rather than string-substituted so both
/// arms below share one identical base to differ from.
fn init_project_without_default_agent(dir: &Path) -> (PathBuf, String) {
    let config = dir.join(".kata/kata.toml");
    kata::cli::run(Cli {
        api_url: "http://127.0.0.1:8400".to_string(),
        format: kata::cli::OutputFormat::Human,
        command: Command::Init {
            config: config.clone(),
            force: false,
            print: false,
        },
    })
    .expect("kata init scaffolds a project");

    let text = std::fs::read_to_string(&config).expect("generated config is readable");
    let mut base = String::new();
    let mut skipping = false;
    for line in text.lines() {
        if line.trim_start().starts_with('[') {
            skipping = line.trim() == "[agents.default]";
        }
        if !skipping {
            base.push_str(line);
            base.push('\n');
        }
    }
    assert!(
        !base.contains("\n[agents.default]") && !base.starts_with("[agents.default]"),
        "the base config must declare no default agent:\n{base}"
    );
    assert!(
        base.contains("[agents.shell]"),
        "and must otherwise still be the generated project config:\n{base}"
    );
    (config, base)
}

/// Write `base` back, with a `[agents.default]` harness entry that declares no
/// capsule launch: no `adapter` — the judgement
/// `agent_turn_spec` refuses `adapter_undeclared` under.
fn declare_default_agent_unlaunchable(config: &Path, base: &str) {
    std::fs::write(config, format!("{base}\n[agents.default]\n")).expect("config is writable");
}

/// Write `base` back, with a `[agents.default]` harness entry declaring the
/// embedded harness — `adapter` plus the credential it runs under.
fn declare_default_agent_launchable(config: &Path, base: &str) {
    std::fs::write(
        config,
        format!(
            "{base}\n[agents.default]\nadapter = \"nanocode_openai\"\n\
             credential = {{ mode = \"subscription\", source = \"kata_login\" }}\n"
        ),
    )
    .expect("config is writable");
}

/// `DoctorReport` / `DoctorCheck` are not re-exported through `cli::testing`, so
/// the lookup is a macro over the value rather than a function with a named
/// return type.
macro_rules! row {
    ($report:expr, $name:literal) => {
        $report
            .checks
            .iter()
            .find(|check| check.name == $name)
            .unwrap_or_else(|| {
                panic!(
                    "doctor emitted no `{}` row; it emitted: {:?}",
                    $name,
                    $report
                        .checks
                        .iter()
                        .map(|check| check.name)
                        .collect::<Vec<_>>()
                )
            })
    };
}

/// A declared `[agents.*]` entry that cannot launch a capsule fails the row:
/// every stage selecting it is refused `adapter_undeclared` at check, and
/// doctor's exit contract reports a refusal a route already makes.
#[test]
fn doctor_fails_when_a_declared_agent_cannot_launch_a_capsule() {
    let dir = tempfile::tempdir().unwrap();
    let (config, base) = init_project_without_default_agent(dir.path());
    declare_default_agent_unlaunchable(&config, &base);

    let report = doctor_report_with_logins_dir(&config, &[], no_kata_logins(&config));

    let backends = row!(report, "agent_backends");
    assert_eq!(
        backends.status,
        DoctorStatus::Fail,
        "a DECLARED agent that cannot launch a capsule fails readiness: {backends:?}"
    );
    assert!(
        backends.message.contains("cannot launch a capsule"),
        "the row must say WHY the entry is a finding: {}",
        backends.message
    );
    for recourse in ["adapter", "credential", "shell"] {
        assert!(
            backends.message.contains(recourse),
            "the row must name {recourse:?} as part of the recourse: {}",
            backends.message
        );
    }
    assert_eq!(
        backends.details.get("unmet").map(String::as_str),
        Some("default"),
        "and must name WHICH entry: {backends:?}"
    );
    // The inventory is a DIAGNOSTIC, not the verdict, and it is what the human
    // render prints under the row — `details` alone reaches `--format json` and no
    // operator. It must carry every entry, not only the broken one.
    let inventory = backends.diagnostic.join("\n");
    assert!(
        inventory.contains("[agents.default]") && inventory.contains("[agents.shell]"),
        "the diagnostic must list EVERY configured backend, not just the failure: {inventory}"
    );
    assert!(
        inventory.contains("adapter_undeclared"),
        "and must name the refusal a stage selecting it meets: {inventory}"
    );

    // The label row is unchanged and still passes — `starter_agents` was never
    // wrong about labels; it simply cannot see whether a backend can LAUNCH.
    assert_eq!(row!(report, "starter_agents").status, DoctorStatus::Pass);

    assert!(
        !report.passed,
        "and the exit code must follow the verdict: {report:?}"
    );
    assert!(
        report.failure_count >= 1,
        "counted as a failure: {report:?}"
    );
}

/// The half that proves the check is CONFIG-dependent rather than
/// HOST-dependent — and therefore that `just gate` stays host-independent.
///
/// Same host, one difference of declaration: the arm above NAMES an
/// unlaunchable entry and fails; this arm declares none and must pass. A row
/// that scored the host would behave identically in both.
#[test]
fn doctor_says_nothing_about_an_unlaunchable_agent_no_one_declared() {
    let dir = tempfile::tempdir().unwrap();
    let (config, base) = init_project_without_default_agent(dir.path());

    // Counterfactual first, verbatim: with the block, this config FAILS.
    declare_default_agent_unlaunchable(&config, &base);
    assert_eq!(
        row!(
            doctor_report_with_logins_dir(&config, &[], no_kata_logins(&config)),
            "agent_backends"
        )
        .status,
        DoctorStatus::Fail,
        "the counterfactual must fail, or the pass below proves nothing"
    );

    // Now remove exactly that declaration and change nothing else.
    std::fs::write(&config, &base).expect("config is writable");
    let report = doctor_report_with_logins_dir(&config, &[], no_kata_logins(&config));

    let backends = row!(report, "agent_backends");
    assert_eq!(
        backends.status,
        DoctorStatus::Pass,
        "an agent NO ONE declared is not a finding: {backends:?}"
    );
    assert!(
        !backends.details.contains_key("agent.default"),
        "an undeclared entry must not appear in the inventory: {backends:?}"
    );
    assert!(
        report.passed && report.failure_count == 0,
        "the verdict tracks the config, not the host: {report:?}"
    );

    // The missing model label is reported — as a WARN, because it fails the
    // stages that select it and nothing else. Without this the arm above
    // would be satisfied by doctor going silent about agents altogether.
    let starters = row!(report, "starter_agents");
    assert_eq!(starters.status, DoctorStatus::Warn, "{starters:?}");
    assert_eq!(
        starters.details.get("missing").map(String::as_str),
        Some("default"),
        "and must name the label: {starters:?}"
    );
    assert!(
        starters.message.contains("adapter_undeclared"),
        "naming what actually breaks: {}",
        starters.message
    );
}

/// `kata init` must never scaffold a project that fails its own doctor. This
/// is the claim `just gate`'s host-independence rests on: every doctor
/// invocation the gate reaches reads a config `kata init` generated, so the
/// generated `[agents.default]` must declare a launchable capsule on ANY host.
#[test]
fn a_freshly_generated_project_never_declares_an_unlaunchable_agent() {
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join(".kata/kata.toml");
    kata::cli::run(Cli {
        api_url: "http://127.0.0.1:8400".to_string(),
        format: kata::cli::OutputFormat::Human,
        command: Command::Init {
            config: config.clone(),
            force: false,
            print: false,
        },
    })
    .expect("kata init scaffolds a project");

    let report = doctor_report_with_logins_dir(&config, &[], no_kata_logins(&config));
    let backends = row!(report, "agent_backends");
    assert_eq!(
        backends.status,
        DoctorStatus::Pass,
        "kata init declared an agent the capsule route cannot launch: {backends:?}"
    );
    assert_eq!(
        report.failure_count, 0,
        "a fresh init must be doctor-green on ANY host: {report:#?}"
    );
}

/// The other direction, so the row is not satisfiable by always failing: a
/// harness entry declaring the embedded harness and its credential is what launch
/// looks like.
#[test]
fn doctor_passes_the_backend_row_when_the_capsule_launch_is_declared() {
    let dir = tempfile::tempdir().unwrap();
    let (config, base) = init_project_without_default_agent(dir.path());
    declare_default_agent_launchable(&config, &base);

    let report = doctor_report_with_logins_dir(&config, &[], no_kata_logins(&config));
    let backends = row!(report, "agent_backends");
    assert_eq!(
        backends.status,
        DoctorStatus::Pass,
        "a launchable declaration must not fail: {backends:?}"
    );
    assert!(
        backends
            .details
            .get("agent.default")
            .is_some_and(|detail| detail.contains("nanocode_openai")),
        "the detail must record the adapter that was declared: {backends:?}"
    );
    assert!(!backends.details.contains_key("unmet"));
    assert!(
        backends
            .diagnostic
            .iter()
            .any(|line| line.contains("nanocode_openai")),
        "and the diagnostic must show an operator what was declared: {backends:?}"
    );
}
