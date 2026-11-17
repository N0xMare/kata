//! `kata init` / `kata doctor` behavior tests:
//! project scaffolding, clobber refusal, force backup, print-only, and
//! doctor-report outcomes.

mod common;
use common::assert_factory_agent_labels_are_configured;

use kata::cli::testing::{DoctorStatus, doctor_report_with_logins_dir, no_kata_logins};
use kata::cli::{Cli, Command};
use kata_core::ConfigManager;
use kata_types::config::AgentBackendConfig;
use kata_types::memory::MemoryProposal;

#[test]
fn init_creates_valid_project_config_and_refuses_clobber() {
    // `kata init` emits no `execution_profile` — the `oci` default
    // stands, and the shipped packs are capsule-mount-shaped, so the
    // in-process compiles below run under `oci` like the seeded config means
    // (the doctor subprocess reads the config itself).
    kata_types::node_profile::mark_node_installed();
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
    .unwrap();

    assert!(config.exists());
    assert!(dir.path().join(".kata/data").is_dir());
    assert!(dir.path().join(".kata/workflows").is_dir());
    assert!(dir.path().join(".kata/product").is_dir());
    assert!(dir.path().join(".kata/memory/inbox").is_dir());
    assert!(dir.path().join(".kata/memory/projections").is_dir());
    assert!(dir.path().join(".kata/product/README.md").exists());
    assert!(dir.path().join(".kata/product/objective.md").exists());
    assert!(dir.path().join(".kata/product/validation.md").exists());
    assert!(dir.path().join(".kata/product/steering.md").exists());
    assert!(
        dir.path()
            .join(".kata/memory/inbox/000-objective.json")
            .exists()
    );
    assert!(
        dir.path()
            .join(".kata/memory/inbox/010-validation-criteria.json")
            .exists()
    );
    let starter = dir
        .path()
        .join(".kata/workflows/std.software_factory.kata_self_improve.star");
    assert!(starter.exists());
    let preflight = dir
        .path()
        .join(".kata/workflows/std.software_factory.kata_self_improve_preflight.star");
    assert!(preflight.exists());

    let cfg = ConfigManager::load(&config).unwrap().snapshot();
    assert_eq!(
        cfg.node.data_dir,
        dir.path().join(".kata/data"),
        "generated config must reopen the directory kata init actually created"
    );
    assert_eq!(
        cfg.vcs.jj_repo,
        dir.path(),
        "foreground and native-service launch must target the project repository"
    );
    assert_eq!(cfg.api.bind, "127.0.0.1:8400");
    assert!(cfg.agents.contains_key("shell"));
    assert!(matches!(
        cfg.agents.get("shell"),
        Some(AgentBackendConfig::Shell { .. })
    ));

    // `[agents.default]` is unconditional under the `oci` route, and the
    // default is kata's embedded harness: `nanocode_openai`, whose launch the
    // kind fixes (its capsule's init is `kata-toolhost`, so no `argv`) and
    // whose credential is kata's own login — a launchable entry on EVERY box.
    let default_agent = cfg
        .agents
        .get("default")
        .expect("kata init must generate `[agents.default]`");
    let adapter = default_agent
        .capsule_launch()
        .expect("the generated `[agents.default]` must declare a launchable capsule");
    assert_eq!(adapter.as_label(), "nanocode_openai");
    let objective_proposal: MemoryProposal = serde_json::from_str(
        &std::fs::read_to_string(dir.path().join(".kata/memory/inbox/000-objective.json")).unwrap(),
    )
    .expect("objective memory proposal should decode");
    assert_eq!(objective_proposal.object.kind.label(), "objective");
    assert_eq!(objective_proposal.object.status.label(), "active");
    let validation_proposal: MemoryProposal = serde_json::from_str(
        &std::fs::read_to_string(
            dir.path()
                .join(".kata/memory/inbox/010-validation-criteria.json"),
        )
        .unwrap(),
    )
    .expect("validation memory proposal should decode");
    assert_eq!(
        validation_proposal.object.kind.label(),
        "validation_criterion"
    );
    assert_eq!(validation_proposal.object.status.label(), "active");

    let repo_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .unwrap();
    // Two-root stdlib split: the generated starter packs load
    // `kata/factory.star` (software_factory_workflow), which lives in the
    // parallel `workflows/kata-factory` bundled root, so both bundled roots must
    // be on the loader whitelist alongside the project `.kata/workflows` root.
    let roots = vec![
        dir.path().join(".kata/workflows"),
        repo_root.join("workflows/std"),
        repo_root.join("workflows/kata-factory"),
    ];
    // Judge the starters as a node that declares the facts no scaffold can
    // invent would: the generated `[agents]` map installed the way `kata check
    // --config`/`kata doctor` install it, a non-empty `[node] egress_allow`
    // for the packs' authored `net = "host"`, and the environment PATH
    // programs their `requires = [..]` name plus the `sh` busybox gives every
    // node environment. A label
    // the generated config does not declare would refuse `adapter_undeclared`
    // here — that door is what `assert_factory_agent_labels_are_configured`
    // audits on the artifact.
    kata_types::node_profile::install_node_agents(cfg.agents.clone());
    kata_types::node_profile::install_node_egress_allow(
        [
            kata_types::execution_contract::EgressAuthority::from_authority_str(
                "static.crates.io:443",
            )
            .expect("authority parses"),
        ]
        .into_iter()
        .collect(),
    );
    kata_types::node_profile::install_node_environment_programs(Some(
        ["cargo", "git", "just", "kata", "python3", "sh"]
            .iter()
            .map(|program| (*program).to_string())
            .collect(),
    ));
    let artifact =
        kata_program::preflight::build_workflow_compiled_artifact_from_file(&starter, &roots)
            .expect("starter factory workflow should compile through bundled stdlib");
    assert_eq!(
        artifact.name.as_str(),
        "std.software_factory.kata_self_improve"
    );
    assert!(artifact.worktree_isolated);
    assert_factory_agent_labels_are_configured(&artifact.agent_labels, &cfg.agents);
    assert_eq!(
        artifact
            .execution_program
            .workflow_pattern
            .as_ref()
            .expect("workflow pattern")
            .name
            .as_str(),
        "software_factory"
    );
    let preflight_artifact =
        kata_program::preflight::build_workflow_compiled_artifact_from_file(&preflight, &roots)
            .expect("starter preflight workflow should compile through bundled stdlib");
    assert_eq!(
        preflight_artifact.name.as_str(),
        "std.software_factory.kata_self_improve_preflight"
    );
    assert!(preflight_artifact.worktree_isolated);
    assert_factory_agent_labels_are_configured(&preflight_artifact.agent_labels, &cfg.agents);
    assert_eq!(
        preflight_artifact
            .execution_program
            .workflow_pattern
            .as_ref()
            .expect("workflow pattern")
            .name
            .as_str(),
        "software_factory"
    );

    let report = doctor_report_with_logins_dir(&config, &[], no_kata_logins(&config));
    // A scaffolded project is not a declared node: `std.hello` — the
    // self-contained shell starter — judges green, and the two factory
    // starters warn `workflow_check` naming exactly the `[node]` facts an
    // operator declares (`egress_allow`, the bound environment, agent
    // adapters/credentials). The warning pair IS the contract: the scaffold's
    // own checks are green — a fresh init must be — and anything beyond the
    // two factory rows would be a regression. `kata doctor` is where an
    // operator learns which declaration their node still owes.
    assert_eq!(
        report.failure_count, 0,
        "a fresh init must be green; the undeclared-fact refusals are advisory: {report:#?}"
    );
    assert!(report.passed);
    let factory_warnings: Vec<_> = report
        .checks
        .iter()
        .filter(|check| {
            check.name == "workflow_check"
                && check.status == DoctorStatus::Warn
                && check
                    .details
                    .get("error")
                    .is_some_and(|error| error.contains("_undeclared"))
        })
        .collect();
    assert_eq!(factory_warnings.len(), 2);
    for check in &factory_warnings {
        let error = check.details.get("error").cloned().unwrap_or_default();
        assert!(
            [
                "egress_undeclared",
                "environment_requirement_unmet",
                "adapter_undeclared",
                "adapter_unqualified",
                "credential_undeclared",
            ]
            .iter()
            .any(|door| error.contains(door)),
            "the refusal names an operator-declared door: {error}"
        );
        for owned in [
            "child_invocation",
            "host_sandbox_unsupported_under_oci",
            "loop_member_not_a_capsule_under_oci",
        ] {
            assert!(
                !error.contains(owned),
                "a scaffold- or pack-owned arm must not fire: {error}"
            );
        }
    }
    assert!(
        report
            .checks
            .iter()
            .any(|check| check.name == "config_validation" && check.status == DoctorStatus::Pass)
    );
    // The default agent runs on kata's own ChatGPT login, which the planted
    // logins directory does not hold: the `kata_login` row WARNs naming the
    // command, read from that directory and never the owner's own.
    let login = report
        .checks
        .iter()
        .find(|check| check.name == "kata_login")
        .expect("the default agent's kata_login row");
    assert_eq!(login.status, DoctorStatus::Warn, "{login:#?}");
    assert!(
        login
            .diagnostic
            .iter()
            .any(|line| line.contains("openai-chatgpt.json: absent; run `kata login openai`")),
        "{login:#?}"
    );
    assert_eq!(
        login.details.get("logins_dir").map(String::as_str),
        Some(
            no_kata_logins(&config)
                .expect("a planted directory")
                .to_string_lossy()
                .as_ref()
        ),
        "the row read the planted directory"
    );
    assert!(
        report.checks.iter().any(
            |check| check.name == "starter_workflow_file" && check.status == DoctorStatus::Pass
        )
    );
    // `std.hello` still judges green — the always-green preflight proves the
    // node can run a confined pack that names nothing undeclared.
    assert!(
        report
            .checks
            .iter()
            .any(|check| check.name == "workflow_check" && check.status == DoctorStatus::Pass),
        "std.hello should compile-check green: {report:#?}"
    );
    // A green report's recourse is the run set: judge every pack, then serve —
    // under a delegated scope, since an undelegated `kata serve` refuses to boot.
    assert!(
        report
            .next_commands
            .iter()
            .any(|command| command == "kata check --all")
            && report.next_commands.iter().any(|command| {
                command.starts_with(
                    "systemd-run --user --scope -p Delegate=yes -- kata serve --config ",
                )
            }),
        "a green doctor names what to run next: {:?}",
        report.next_commands
    );
    serde_json::to_value(&report).expect("doctor report should serialize");

    let err = kata::cli::run(Cli {
        api_url: "http://127.0.0.1:8400".to_string(),
        format: kata::cli::OutputFormat::Human,
        command: Command::Init {
            config,
            force: false,
            print: false,
        },
    })
    .expect_err("init must not clobber an existing config by default");
    assert!(err.to_string().contains("already exists"));
}

#[test]
fn doctor_report_fails_closed_before_init() {
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join(".kata/kata.toml");

    let report = doctor_report_with_logins_dir(&config, &[], no_kata_logins(&config));
    assert!(!report.passed);
    assert!(report.failure_count >= 1);
    assert!(
        report
            .checks
            .iter()
            .any(|check| check.name == "config_file" && check.status == DoctorStatus::Fail)
    );
    assert!(
        report
            .checks
            .iter()
            .any(|check| check.name == "config_validation" && check.status == DoctorStatus::Fail)
    );
    assert!(
        report
            .next_commands
            .iter()
            .any(|command| command.contains("kata init --config"))
    );
}

#[test]
fn init_force_preserves_existing_starter_files_and_backs_up_config() {
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
    .unwrap();

    let starter = dir
        .path()
        .join(".kata/workflows/std.software_factory.kata_self_improve.star");
    let objective = dir.path().join(".kata/product/objective.md");
    std::fs::write(&starter, "# edited starter\n").unwrap();
    std::fs::write(&objective, "# Edited objective\n").unwrap();

    kata::cli::run(Cli {
        api_url: "http://127.0.0.1:8400".to_string(),
        format: kata::cli::OutputFormat::Human,
        command: Command::Init {
            config: config.clone(),
            force: true,
            print: false,
        },
    })
    .unwrap();

    assert_eq!(
        std::fs::read_to_string(&starter).unwrap(),
        "# edited starter\n"
    );
    assert_eq!(
        std::fs::read_to_string(&objective).unwrap(),
        "# Edited objective\n"
    );
    let backups = std::fs::read_dir(config.parent().unwrap())
        .unwrap()
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with("kata.toml.bak."))
        })
        .collect::<Vec<_>>();
    assert_eq!(backups.len(), 1);
}

#[test]
fn init_print_touches_no_filesystem_paths() {
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join(".kata/kata.toml");

    kata::cli::run(Cli {
        api_url: "http://127.0.0.1:8400".to_string(),
        format: kata::cli::OutputFormat::Human,
        command: Command::Init {
            config: config.clone(),
            force: false,
            print: true,
        },
    })
    .unwrap();

    assert!(!config.exists());
    assert!(!dir.path().join(".kata").exists());
}

/// A `teardown_ambiguous` OCI attempt root has an OWNER an operator can see: the
/// driver's own `retain_ambiguous` marks it, and `kata doctor` lists it by path — while a
/// root that was not marked (a live drive's, say) is not reported.
#[test]
fn doctor_lists_oci_attempt_roots_retained_over_an_ambiguous_teardown() {
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
    .unwrap();
    let data_dir = ConfigManager::load(&config)
        .unwrap()
        .snapshot()
        .node
        .data_dir
        .clone();
    let find = || {
        doctor_report_with_logins_dir(&config, &[], no_kata_logins(&config))
            .checks
            .into_iter()
            .find(|check| check.name == "oci_attempt_roots_retained")
            .expect("doctor runs the attempt-root check whenever the config loaded")
    };
    assert_eq!(
        find().status,
        DoctorStatus::Pass,
        "a node that never ran a capsule retains nothing"
    );

    let attempts = kata_worker::attempt_root::attempts_directory(
        &kata_worker::capsule_route::capsule_worker_state(&data_dir),
    );
    // The PRODUCTION writer of the marker, not a hand-written file.
    kata_worker::attempt_root::OwnedAttemptRoot::acquire(&attempts.join("ambiguous-attempt"))
        .unwrap()
        .retain_ambiguous("ambiguous-attempt", "Ambiguous { probe: CgroupPopulation }");
    let _live =
        kata_worker::attempt_root::OwnedAttemptRoot::acquire(&attempts.join("live-attempt"))
            .unwrap();

    let check = find();
    assert_eq!(check.status, DoctorStatus::Warn, "{check:#?}");
    assert!(
        check.message.contains("ambiguous-attempt") && !check.message.contains("live-attempt"),
        "the marked root is named and the unmarked one is not: {check:#?}"
    );
}

/// An OCI attempt root that could NOT be removed has an owner an operator can see: the
/// production `OwnedAttemptRoot::remove` fails on it (its own directory is `0500`, so the
/// walk cannot unlink the file it holds — the unprivileged stand-in for an `EBUSY` mount
/// point or an immutable entry), and `kata doctor`'s `oci_attempt_roots_retained` row
/// names it as a failed removal — still after a worker-start sweep retries it and fails
/// again. Once the sweep CAN remove it, the row passes again and no marker is left in
/// `attempts/`. The root's presence and the directory's entries are read through
/// `std::fs`.
///
/// **Would red if:** a failed removal were only logged (the L3 C-22 defect: the row
/// passed while the root stayed on disk), or a removed root's marker outlived it.
#[test]
fn doctor_lists_an_oci_attempt_root_whose_removal_failed() {
    use std::os::unix::fs::PermissionsExt as _;

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
    .unwrap();
    let data_dir = ConfigManager::load(&config)
        .unwrap()
        .snapshot()
        .node
        .data_dir
        .clone();
    let find = || {
        doctor_report_with_logins_dir(&config, &[], no_kata_logins(&config))
            .checks
            .into_iter()
            .find(|check| check.name == "oci_attempt_roots_retained")
            .expect("doctor runs the attempt-root check whenever the config loaded")
    };
    let worker_state = kata_worker::capsule_route::capsule_worker_state(&data_dir);
    let attempts = kata_worker::attempt_root::attempts_directory(&worker_state);
    let stuck = attempts.join("stuck-attempt");
    let root = kata_worker::attempt_root::OwnedAttemptRoot::acquire(&stuck).unwrap();
    std::fs::write(stuck.join("left"), b"bytes the walk cannot unlink\n").unwrap();
    std::fs::set_permissions(&stuck, std::fs::Permissions::from_mode(0o500)).unwrap();
    root.remove("stuck-attempt", "doctor_cell");
    assert!(stuck.join("left").exists(), "the removal failed, on disk");

    let check = find();
    assert_eq!(check.status, DoctorStatus::Warn, "{check:#?}");
    assert!(
        check.message.contains("stuck-attempt") && check.message.contains("removal failed"),
        "the root that could not be removed is named as such: {check:#?}"
    );

    let swept = kata_worker::attempt_root::sweep_attempt_roots(&worker_state);
    assert!(
        stuck.join("left").exists(),
        "the sweep's retry failed too: {swept:?}"
    );
    let check = find();
    assert!(
        check.status == DoctorStatus::Warn && check.message.contains("stuck-attempt"),
        "a root the sweep still cannot remove stays listed: {check:#?}"
    );

    std::fs::set_permissions(&stuck, std::fs::Permissions::from_mode(0o700)).unwrap();
    let swept = kata_worker::attempt_root::sweep_attempt_roots(&worker_state);
    assert!(
        !stuck.exists(),
        "the sweep removes it once it can: {swept:?}"
    );
    let left: Vec<_> = std::fs::read_dir(&attempts)
        .unwrap()
        .map(|entry| entry.unwrap().file_name())
        .collect();
    assert!(left.is_empty(), "nothing is left beside it: {left:?}");
    assert_eq!(find().status, DoctorStatus::Pass, "the row passes again");
}
