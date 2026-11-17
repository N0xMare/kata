//! `kata doctor`'s factory-starter rows under the shipped `oci` profile.
//!
//! The factory packs (`std.software_factory.kata_self_improve` and its
//! preflight) compile under `oci` — their stages were re-authored onto
//! declared capsule profiles — so `oci` is not a downgrade axis: a starter
//! that fails a REAL check fails the same on every (single) profile. What a
//! fresh `kata init` still advises on is the node's own undeclared facts —
//! `[node] environment`, an agent adapter, `egress_allow` — which the
//! `UNDECLARED_NODE_FACT_DOORS` arm reports as `[warn]`, naming the
//! declaration to write. A missing starter FILE and a syntactically broken
//! pack stay hard `[fail]`s, and an explicitly requested `extra_workflows`
//! entry is `Required` always.

use std::path::{Path, PathBuf};

use kata::cli::testing::{DoctorStatus, doctor_report_with_logins_dir, no_kata_logins};
use kata::cli::{Cli, Command, OutputFormat};

const SELF_IMPROVE: &str = "std.software_factory.kata_self_improve";
const SELF_IMPROVE_PREFLIGHT: &str = "std.software_factory.kata_self_improve_preflight";

/// Scaffold a `kata init` project and return its config path.
fn init_project(dir: &Path) -> PathBuf {
    let config = dir.join(".kata").join("kata.toml");
    kata::cli::run(Cli {
        api_url: "http://127.0.0.1:8400".to_string(),
        format: OutputFormat::Human,
        command: Command::Init {
            config: config.clone(),
            force: false,
            print: false,
        },
    })
    .expect("kata init");
    config
}

/// The `workflow_check` rows for the two factory starter packs.
fn factory_workflow_rows(
    config: &Path,
) -> Vec<(
    DoctorStatus,
    String,
    std::collections::BTreeMap<String, String>,
)> {
    let report = doctor_report_with_logins_dir(config, &[], no_kata_logins(config));
    let rows: Vec<_> = report
        .checks
        .iter()
        .filter(|check| check.name == "workflow_check")
        .filter(|check| {
            check.message.contains(SELF_IMPROVE) || check.message.contains(SELF_IMPROVE_PREFLIGHT)
        })
        .map(|check| (check.status, check.message.clone(), check.details.clone()))
        .collect();
    assert_eq!(
        rows.len(),
        2,
        "doctor must publish exactly one workflow_check row per factory starter; \
         rows were {rows:#?}"
    );
    rows
}

fn row(config: &Path, name: &str) -> DoctorStatus {
    doctor_report_with_logins_dir(config, &[], no_kata_logins(config))
        .checks
        .iter()
        .find(|check| check.name == name)
        .map_or_else(
            || panic!("doctor must publish a {name} row"),
            |check| check.status,
        )
}

/// `kata init` writes no `execution_profile` key — omitted parses as `oci`,
/// the only engine — and the factory starters it seeds are checked under it.
#[test]
fn a_scaffolded_config_carries_no_execution_profile_key() {
    let dir = tempfile::tempdir().expect("tempdir");
    let config = init_project(dir.path());
    let text = std::fs::read_to_string(&config).expect("read scaffolded config");
    assert!(
        !text.contains("execution_profile"),
        "the scaffold writes no profile key — absent IS oci: {text}"
    );
    // And the scaffold seeds the factory starters on the same terms as every
    // other pack — they compile under oci, so there is no profile carve-out.
    let workflows = dir.path().join(".kata").join("workflows");
    for file in [
        "std.software_factory.kata_self_improve.star",
        "std.software_factory.kata_self_improve_preflight.star",
    ] {
        assert!(
            workflows.join(file).is_file(),
            "the factory starter {file} is seeded on every scaffold"
        );
    }
}

/// A fresh scaffold's factory rows are never hard failures of the PACKS: the
/// refusal they can carry is an undeclared node fact (`[node] environment`,
/// an agent adapter, an egress authority), which doctor advises with a
/// remedy — it never names a `legacy` node, because no such engine exists and
/// the config loader refuses the spelling.
#[test]
fn a_fresh_oci_init_advises_factory_starters_on_undeclared_node_facts() {
    let dir = tempfile::tempdir().expect("tempdir");
    let config = init_project(dir.path());

    for (status, message, details) in factory_workflow_rows(&config) {
        assert_ne!(
            status,
            DoctorStatus::Fail,
            "a fresh init must not hard-fail a healthy seeded pack: {message}"
        );
        let evidence = format!("{message}\n{details:?}");
        assert!(
            !evidence.contains("legacy"),
            "no advisory names a nonexistent engine as recourse: {evidence}"
        );
        if status == DoctorStatus::Warn {
            assert!(
                evidence.contains("refused on facts this node does not declare")
                    || evidence.contains("optional bundled-stdlib starter"),
                "a factory-starter warn names its real door: {evidence}"
            );
        }
    }
}

/// The file-existence arm is profile-independent again: a missing factory
/// starter file fails on every scaffold, and hello — seeded everywhere —
/// passes.
#[test]
fn a_missing_factory_starter_file_fails_on_the_oci_default() {
    let dir = tempfile::tempdir().expect("tempdir");
    let config = init_project(dir.path());
    let workflows = dir.path().join(".kata").join("workflows");
    for file in [
        "std.software_factory.kata_self_improve.star",
        "std.software_factory.kata_self_improve_preflight.star",
    ] {
        std::fs::remove_file(workflows.join(file)).expect("unseed the factory starter");
    }

    assert_eq!(
        row(&config, "starter_workflow_file"),
        DoctorStatus::Fail,
        "a missing factory starter file is a hard gate"
    );
    assert_eq!(
        row(&config, "starter_preflight_file"),
        DoctorStatus::Fail,
        "a missing preflight file is a hard gate"
    );
    assert_eq!(
        row(&config, "hello_starter_file"),
        DoctorStatus::Pass,
        "hello is seeded and compiled"
    );
}

/// A real fault is a hard gate: a syntax error planted in the project's copy
/// of a factory starter is a pack defect — no undeclared-fact advisory covers
/// it, and the intact sibling's advisory does not excuse it.
#[test]
fn a_factory_starter_with_a_real_fault_still_fails() {
    let dir = tempfile::tempdir().expect("tempdir");
    let config = init_project(dir.path());
    // The project's own workflows root shadows the bundled pack — planting a
    // syntax error there is a pack defect, not an undeclared-fact event.
    let broken = dir
        .path()
        .join(".kata")
        .join("workflows")
        .join("std.software_factory.kata_self_improve.star");
    std::fs::write(&broken, "def broken(:\n").expect("inject a syntax error");

    let report = doctor_report_with_logins_dir(&config, &[], no_kata_logins(&config));
    let rows: Vec<_> = report
        .checks
        .iter()
        .filter(|check| check.name == "workflow_check")
        .filter(|check| check.message.contains(SELF_IMPROVE))
        .collect();
    let broken_row = rows
        .iter()
        .find(|check| check.message.contains(SELF_IMPROVE) && !check.message.contains("preflight"))
        .expect("a workflow_check row for the broken pack");
    assert_eq!(
        broken_row.status,
        DoctorStatus::Fail,
        "a syntax error is a hard gate, not an undeclared-fact advisory: {}",
        broken_row.message
    );
}

/// Green-washing guard: an `extra_workflows` entry is an explicit operator
/// ask — `Required` under every profile — so an unresolvable pack must still
/// `[fail]`, never inherit an advisory arm.
#[test]
fn explicitly_requested_workflow_still_fails() {
    let dir = tempfile::tempdir().expect("tempdir");
    let config = init_project(dir.path());

    let report = doctor_report_with_logins_dir(
        &config,
        &["std.no_such_pack".to_string()],
        no_kata_logins(&config),
    );
    let explicit = report
        .checks
        .iter()
        .find(|check| check.name == "workflow_check" && check.message.contains("std.no_such_pack"))
        .expect("doctor must publish a row for the explicitly requested workflow");
    assert_eq!(
        explicit.status,
        DoctorStatus::Fail,
        "an explicit --check ask stays Required: {}",
        explicit.message
    );
}
