//! CLI parse tests for the build/check/run
//! workflow surface, offline evidence, and backup/restore commands.

use clap::Parser as _;
use kata::cli::{Cli, Command, EvidenceCmd};

#[test]
fn cli_parses_top_level_workflow_build() {
    let cli = Cli::try_parse_from(["kata", "build", "kata-loop-lite"]).unwrap();

    let Command::Build {
        workflow,
        out,
        deny_warnings,
        config,
    } = cli.command
    else {
        panic!("expected build command");
    };

    assert_eq!(workflow, "kata-loop-lite");
    assert!(out.is_none());
    assert!(!deny_warnings);
    assert!(config.is_none());
}

/// `check`/`build` accept `--config` — the door a node's operator (or a
/// smoke's derived config) uses to judge packs as that node would.
#[test]
fn cli_parses_check_and_build_config() {
    let cli =
        Cli::try_parse_from(["kata", "check", "kata-loop-lite", "--config", "k.toml"]).unwrap();
    let Command::Check { config, .. } = cli.command else {
        panic!("expected check command");
    };
    assert_eq!(config, Some(std::path::PathBuf::from("k.toml")));

    let cli = Cli::try_parse_from(["kata", "build", "wf", "--config", "k.toml"]).unwrap();
    let Command::Build { config, .. } = cli.command else {
        panic!("expected build command");
    };
    assert_eq!(config, Some(std::path::PathBuf::from("k.toml")));
}

#[test]
fn cli_parses_top_level_workflow_check() {
    let cli = Cli::try_parse_from(["kata", "check", "kata-loop-lite", "--deny-warnings"]).unwrap();

    let Command::Check {
        workflow,
        all,
        deny_warnings,
        config,
    } = cli.command
    else {
        panic!("expected check command");
    };

    assert_eq!(workflow.as_deref(), Some("kata-loop-lite"));
    assert!(!all);
    assert!(deny_warnings);
    assert!(config.is_none());
}

#[test]
fn cli_parses_offline_evidence_commands() {
    let summary = Cli::try_parse_from([
        "kata",
        "evidence",
        "summary",
        "evidence/latest",
        "--json",
        "--strict",
    ])
    .unwrap();
    assert!(matches!(
        summary.command,
        Command::Evidence {
            cmd: EvidenceCmd::Summary { path, json: true, strict: true }
        } if path.ends_with("evidence/latest")
    ));

    let list = Cli::try_parse_from(["kata", "evidence", "list", "evidence", "--strict"]).unwrap();
    assert!(matches!(
        list.command,
        Command::Evidence {
            cmd: EvidenceCmd::List { path, json: false, strict: true }
        } if path.ends_with("evidence")
    ));
}

#[test]
fn workflow_run_defaults_to_attached_and_has_no_local_face() {
    let workflow = Cli::try_parse_from(["kata", "run", "kata-loop-plan-check-std"]).unwrap();

    let Command::Run {
        cmd,
        workflow,
        submit,
        watch,
        wait,
        include_outputs,
        timeout_secs,
        poll_ms,
        param,
        params_file,
        target,
    } = workflow.command
    else {
        panic!("expected run command");
    };
    assert!(cmd.is_none());
    assert_eq!(workflow.as_deref(), Some("kata-loop-plan-check-std"));
    assert!(!submit);
    assert!(!watch);
    assert!(!wait);
    assert!(!include_outputs);
    assert_eq!(timeout_secs, 60);
    assert_eq!(poll_ms, 500);
    // The typed-invocation-param flags default to empty/unset.
    assert!(param.is_empty());
    assert!(params_file.is_none());
    assert!(
        target.is_none(),
        "no --target means the default trunk target"
    );

    assert!(Cli::try_parse_from(["kata", "run", "--role", "solo"]).is_err());

    // `kata run` has no local face: `--scratch` and `--config` are not its
    // arguments, so clap refuses either at parse — the generic refusal, earlier
    // than any config read. `scratch_refusal.rs` reads the same off the binary.
    for argv in [
        vec!["kata", "run", "sandbox-smoke-shell-offline", "--scratch"],
        vec![
            "kata",
            "run",
            "sandbox-smoke-shell-offline",
            "--config",
            "k.toml",
        ],
        vec!["kata", "run", "list", "--config", "k.toml"],
    ] {
        let error = Cli::try_parse_from(&argv).expect_err("not an argument of `kata run`");
        assert_eq!(
            error.kind(),
            clap::error::ErrorKind::UnknownArgument,
            "{argv:?}: {error}"
        );
    }
}

#[test]
fn cli_parses_api_backed_workflow_run_flags() {
    let submit =
        Cli::try_parse_from(["kata", "run", "sandbox-smoke-shell-offline", "--submit"]).unwrap();
    let Command::Run {
        cmd,
        workflow,
        submit,
        watch,
        wait,
        include_outputs,
        timeout_secs,
        poll_ms,
        param,
        params_file,
        target,
    } = submit.command
    else {
        panic!("expected run command");
    };
    assert!(cmd.is_none());
    assert_eq!(workflow.as_deref(), Some("sandbox-smoke-shell-offline"));
    assert!(submit);
    assert!(!watch);
    assert!(!wait);
    assert!(!include_outputs);
    assert_eq!(timeout_secs, 60);
    assert_eq!(poll_ms, 500);
    // The typed-invocation-param flags default to empty/unset.
    assert!(param.is_empty());
    assert!(params_file.is_none());
    assert!(
        target.is_none(),
        "no --target means the default trunk target"
    );

    let watch = Cli::try_parse_from([
        "kata",
        "run",
        "sandbox-smoke-shell-offline",
        "--watch",
        "--include-outputs",
    ])
    .unwrap();
    let Command::Run {
        workflow,
        submit,
        watch,
        wait,
        include_outputs,
        ..
    } = watch.command
    else {
        panic!("expected run command");
    };
    assert_eq!(workflow.as_deref(), Some("sandbox-smoke-shell-offline"));
    assert!(!submit);
    assert!(watch);
    assert!(!wait);
    assert!(include_outputs);

    let wait = Cli::try_parse_from([
        "kata",
        "run",
        "workflows/std/smoke.toml",
        "--wait",
        "--timeout-secs",
        "10",
        "--poll-ms",
        "100",
    ])
    .unwrap();
    let Command::Run {
        workflow,
        submit,
        watch,
        wait,
        timeout_secs,
        poll_ms,
        ..
    } = wait.command
    else {
        panic!("expected run command");
    };
    assert_eq!(workflow.as_deref(), Some("workflows/std/smoke.toml"));
    assert!(!submit);
    assert!(!watch);
    assert!(wait);
    assert_eq!(timeout_secs, 10);
    assert_eq!(poll_ms, 100);
}

#[test]
fn cli_parses_backup_command() {
    let cli =
        Cli::try_parse_from(["kata", "backup", "--config", "k.toml", "--out", "artifact"]).unwrap();
    let Command::Backup {
        config,
        out,
        recoverable,
    } = cli.command
    else {
        panic!("expected backup command");
    };
    assert_eq!(config, std::path::PathBuf::from("k.toml"));
    assert_eq!(out, std::path::PathBuf::from("artifact"));
    assert!(!recoverable);
}

#[test]
fn cli_parses_restore_command_with_config_flag() {
    let cli = Cli::try_parse_from([
        "kata",
        "restore",
        "--from",
        "artifact",
        "--config",
        "k.toml",
        "--restore-config",
    ])
    .unwrap();
    let Command::Restore {
        from,
        config,
        restore_config,
        recoverable,
        recovery_decisions,
    } = cli.command
    else {
        panic!("expected restore command");
    };
    assert_eq!(from, std::path::PathBuf::from("artifact"));
    assert_eq!(config, std::path::PathBuf::from("k.toml"));
    assert!(restore_config);
    assert!(recovery_decisions.is_none());
    assert!(!recoverable);
}

// Small suites folded into this binary so each costs no link of its own. Each
// keeps its module, so its tests are named `<module>::<test>` here.
#[path = "cli_parse_workflow_tests/workflow_roots_tests.rs"]
mod workflow_roots_tests;
#[path = "cli_parse_workflow_tests/workflows_check_subworkflow_cli.rs"]
mod workflows_check_subworkflow_cli;
