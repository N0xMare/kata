//! CLI parse tests for project/daemon
//! lifecycle: init, health/status/version, watch, events, steering,
//! and native-memory subcommands.

use clap::Parser as _;
use kata::cli::{Cli, Command, MemoryCmd, SteerCmd};

#[test]
fn cli_parses_project_init() {
    let cli = Cli::try_parse_from(["kata", "init", "--config", ".kata/kata.toml"]).unwrap();

    let Command::Init {
        config,
        force,
        print,
    } = cli.command
    else {
        panic!("expected init command");
    };

    assert_eq!(config.to_str(), Some(".kata/kata.toml"));
    assert!(!force);
    assert!(!print);
    assert!(
        Cli::try_parse_from(["kata", "init", "--agent", "codex-stock"]).is_err(),
        "`kata init` writes the embedded harness and takes no --agent"
    );

    let cli = Cli::try_parse_from([
        "kata",
        "doctor",
        "--config",
        ".kata/kata.toml",
        "--workflow",
        "sandbox-smoke-shell-offline",
        "--online",
    ])
    .unwrap();

    let Command::Doctor {
        config,
        workflow,
        online,
    } = cli.command
    else {
        panic!("expected doctor command");
    };

    assert_eq!(config.to_str(), Some(".kata/kata.toml"));
    assert_eq!(workflow, vec!["sandbox-smoke-shell-offline"]);
    assert!(online);
}

#[test]
fn cli_parses_daemon_identity_commands() {
    let health = Cli::try_parse_from(["kata", "health"]).unwrap();
    assert!(matches!(health.command, Command::Health));

    let status = Cli::try_parse_from(["kata", "status"]).unwrap();
    assert!(matches!(status.command, Command::Status));

    let version = Cli::try_parse_from(["kata", "version", "--compare"]).unwrap();
    assert!(matches!(
        version.command,
        Command::Version { compare: true }
    ));
}

#[test]
fn cli_parses_watch() {
    let cli = Cli::try_parse_from([
        "kata",
        "watch",
        "01HZZZZZZZZZZZZZZZZZZZZZZZ",
        "--include-outputs",
    ])
    .unwrap();

    let Command::Watch {
        execution_id,
        current,
        active,
        include_outputs,
        timeout_secs,
    } = cli.command
    else {
        panic!("expected watch command");
    };

    assert_eq!(execution_id.as_deref(), Some("01HZZZZZZZZZZZZZZZZZZZZZZZ"));
    assert!(!current);
    assert!(!active);
    assert!(include_outputs);
    // 0 is not "expire immediately" — it is the documented "follow until
    // terminal" default. An operator watching a long workflow is not hung, so
    // the streaming face stays unbounded in wall-clock unless asked otherwise.
    assert_eq!(
        timeout_secs, 0,
        "the default must be follow-until-terminal, not a wall-clock deadline"
    );

    let current = Cli::try_parse_from(["kata", "watch", "--current", "--active"]).unwrap();
    let Command::Watch {
        execution_id,
        current,
        active,
        include_outputs,
        timeout_secs,
    } = current.command
    else {
        panic!("expected watch command");
    };
    assert!(execution_id.is_none());
    assert!(current);
    assert!(active);
    assert!(!include_outputs);
    assert_eq!(timeout_secs, 0);

    let bounded = Cli::try_parse_from([
        "kata",
        "watch",
        "01HZZZZZZZZZZZZZZZZZZZZZZZ",
        "--timeout-secs",
        "45",
    ])
    .unwrap();
    let Command::Watch { timeout_secs, .. } = bounded.command else {
        panic!("expected watch command");
    };
    assert_eq!(
        timeout_secs, 45,
        "scripts must be able to bound the streaming face without an external `timeout(1)`"
    );

    assert!(
        Cli::try_parse_from(["kata", "watch", "--active"]).is_err(),
        "--active must be scoped to --current"
    );
    assert!(
        Cli::try_parse_from(["kata", "watch", "01HZZZZZZZZZZZZZZZZZZZZZZZ", "--current"]).is_err(),
        "explicit id and --current must conflict"
    );
}

#[test]
fn cli_parses_events() {
    // Bare firehose tail: no execution filter.
    let firehose = Cli::try_parse_from(["kata", "events"]).unwrap();
    let Command::Events {
        filter_execution, ..
    } = firehose.command
    else {
        panic!("expected events command");
    };
    assert!(filter_execution.is_none());

    // Narrowed to a single execution.
    let filtered = Cli::try_parse_from([
        "kata",
        "events",
        "--filter-execution",
        "01HZZZZZZZZZZZZZZZZZZZZZZZ",
    ])
    .unwrap();
    let Command::Events {
        filter_execution, ..
    } = filtered.command
    else {
        panic!("expected events command");
    };
    assert_eq!(
        filter_execution.as_deref(),
        Some("01HZZZZZZZZZZZZZZZZZZZZZZZ")
    );
}

#[test]
fn cli_parses_steering_commands() {
    let human = Cli::try_parse_from([
        "kata",
        "steer",
        "human-requests",
        "--unanswered",
        "--execution-id",
        "01HZZZZZZZZZZZZZZZZZZZZZZZ",
    ])
    .unwrap();
    assert!(matches!(
        human.command,
        Command::Steer {
            cmd: SteerCmd::HumanRequests {
                execution_id: Some(execution_id),
                unanswered: true,
                ..
            }
        } if execution_id == "01HZZZZZZZZZZZZZZZZZZZZZZZ"
    ));

    let answer = Cli::try_parse_from([
        "kata",
        "steer",
        "answer-human-request",
        "01HZZZZZZZZZZZZZZZZZZZZZZZ",
        "HR-1",
        "ship it",
        "--steering-id",
        "7",
    ])
    .unwrap();
    assert!(matches!(
        answer.command,
        Command::Steer {
            cmd: SteerCmd::AnswerHumanRequest {
                execution_id,
                request_id,
                answer_summary,
                steering_id: Some(7),
            }
        } if execution_id == "01HZZZZZZZZZZZZZZZZZZZZZZZ"
            && request_id == "HR-1"
            && answer_summary == "ship it"
    ));

    let external = Cli::try_parse_from([
        "kata",
        "steer",
        "external-inputs",
        "--channel",
        "operator_steering",
    ])
    .unwrap();
    assert!(matches!(
        external.command,
        Command::Steer {
            cmd: SteerCmd::ExternalInputs {
                channel: Some(channel),
                ..
            }
        } if channel == "operator_steering"
    ));

    let append = Cli::try_parse_from([
        "kata",
        "steer",
        "append-external-input",
        "01HZZZZZZZZZZZZZZZZZZZZZZZ",
        "operator_steering",
        "keep it scoped",
        "--input-id",
        "ei-1",
        "--source",
        "operator",
        "--target-stage",
        "plan",
        "--payload-json",
        "{\"priority\":\"high\"}",
    ])
    .unwrap();
    assert!(matches!(
        append.command,
        Command::Steer {
            cmd: SteerCmd::AppendExternalInput {
                execution_id,
                channel,
                text,
                input_id: Some(input_id),
                source: Some(source),
                target_stage: Some(target_stage),
                payload_json: Some(payload_json),
            }
        } if execution_id == "01HZZZZZZZZZZZZZZZZZZZZZZZ"
            && channel == "operator_steering"
            && text == "keep it scoped"
            && input_id == "ei-1"
            && source == "operator"
            && target_stage == "plan"
            && payload_json == "{\"priority\":\"high\"}"
    ));
}

#[test]
fn cli_parses_native_memory_commands() {
    let snapshot = Cli::try_parse_from([
        "kata",
        "memory",
        "snapshot",
        "--kind",
        "task",
        "--status",
        "active",
        "--out-dir",
        ".kata/memory/projection",
    ])
    .unwrap();
    assert!(matches!(
        snapshot.command,
        Command::Memory {
            cmd: MemoryCmd::Snapshot {
                kind: Some(kind),
                kinds: None,
                status: Some(status),
                statuses: None,
                query: None,
                limit: None,
                out_dir: Some(out_dir),
            }
        } if kind == "task"
            && status == "active"
            && out_dir.to_str() == Some(".kata/memory/projection")
    ));
    let snapshot = Cli::try_parse_from([
        "kata",
        "memory",
        "snapshot",
        "--kinds",
        "task,finding",
        "--statuses",
        "active,proposed",
        "--query",
        "recent controller decisions",
        "--limit",
        "4",
    ])
    .unwrap();
    assert!(matches!(
        snapshot.command,
        Command::Memory {
            cmd: MemoryCmd::Snapshot {
                kind: None,
                kinds: Some(kinds),
                status: None,
                statuses: Some(statuses),
                query: Some(query),
                limit: Some(4),
                out_dir: None,
            }
        } if kinds == "task,finding"
            && statuses == "active,proposed"
            && query == "recent controller decisions"
    ));
    assert!(
        Cli::try_parse_from([
            "kata", "memory", "snapshot", "--kind", "task", "--kinds", "risk"
        ])
        .is_err(),
        "--kind and --kinds must conflict"
    );
    assert!(
        Cli::try_parse_from([
            "kata",
            "memory",
            "snapshot",
            "--status",
            "active",
            "--statuses",
            "proposed"
        ])
        .is_err(),
        "--status and --statuses must conflict"
    );

    let get = Cli::try_parse_from(["kata", "memory", "get", "task-1"]).unwrap();
    assert!(matches!(
        get.command,
        Command::Memory {
            cmd: MemoryCmd::Get { id }
        } if id == "task-1"
    ));

    let propose = Cli::try_parse_from([
        "kata",
        "memory",
        "propose",
        "--file",
        ".kata/memory/inbox/task-1.json",
    ])
    .unwrap();
    assert!(matches!(
        propose.command,
        Command::Memory {
            cmd: MemoryCmd::Propose { file }
        } if file.to_str() == Some(".kata/memory/inbox/task-1.json")
    ));

    let inbox = Cli::try_parse_from(["kata", "memory", "import-inbox"]).unwrap();
    assert!(matches!(
        inbox.command,
        Command::Memory {
            cmd: MemoryCmd::ImportInbox {
                dir,
                archive_dir: None,
                delete_processed: false,
            }
        } if dir.to_str() == Some(".kata/memory/inbox")
    ));
    let inbox = Cli::try_parse_from([
        "kata",
        "memory",
        "import-inbox",
        "--dir",
        ".kata/memory/inbox",
        "--archive-dir",
        ".kata/memory/archive",
    ])
    .unwrap();
    assert!(matches!(
        inbox.command,
        Command::Memory {
            cmd: MemoryCmd::ImportInbox {
                dir,
                archive_dir: Some(archive_dir),
                delete_processed: false,
            }
        } if dir.to_str() == Some(".kata/memory/inbox")
            && archive_dir.to_str() == Some(".kata/memory/archive")
    ));
    let inbox =
        Cli::try_parse_from(["kata", "memory", "import-inbox", "--delete-processed"]).unwrap();
    assert!(matches!(
        inbox.command,
        Command::Memory {
            cmd: MemoryCmd::ImportInbox {
                delete_processed: true,
                ..
            }
        }
    ));
    assert!(
        Cli::try_parse_from([
            "kata",
            "memory",
            "import-inbox",
            "--archive-dir",
            ".kata/memory/archive",
            "--delete-processed",
        ])
        .is_err(),
        "--archive-dir and --delete-processed must conflict"
    );
}

/// `kata login` takes the provider as a subcommand and the key only on stdin:
/// no flag carries a key value, `--no-browser` is meaningless beside
/// `--api-key` (every pair of the flow flags refuses too:
/// `contradictory_login_flags_refuse_naming_both`), and the Anthropic login is
/// `--api-key` or nothing.
#[test]
fn cli_parses_login_and_logout() {
    use kata::cli::{LoginCmd, LoginProviderArg};

    let cli = Cli::try_parse_from(["kata", "login", "openai", "--no-browser"]).unwrap();
    assert!(matches!(
        cli.command,
        Command::Login {
            cmd: LoginCmd::Openai {
                api_key: false,
                device_code: false,
                browser: false,
                no_browser: true
            }
        }
    ));
    let cli = Cli::try_parse_from(["kata", "login", "openai", "--api-key"]).unwrap();
    assert!(matches!(
        cli.command,
        Command::Login {
            cmd: LoginCmd::Openai { api_key: true, .. }
        }
    ));
    assert!(Cli::try_parse_from(["kata", "login", "openai", "--api-key", "sk-x"]).is_err());
    assert!(Cli::try_parse_from(["kata", "login", "openai", "--api-key", "--no-browser"]).is_err());
    assert!(Cli::try_parse_from(["kata", "login", "anthropic"]).is_err());
    let cli = Cli::try_parse_from(["kata", "login", "anthropic", "--api-key"]).unwrap();
    assert!(matches!(
        cli.command,
        Command::Login {
            cmd: LoginCmd::Anthropic { api_key: true }
        }
    ));
    let cli = Cli::try_parse_from(["kata", "login", "status"]).unwrap();
    assert!(matches!(
        cli.command,
        Command::Login {
            cmd: LoginCmd::Status { check: false }
        }
    ));
    let cli = Cli::try_parse_from(["kata", "logout", "openai"]).unwrap();
    assert!(matches!(
        cli.command,
        Command::Logout {
            provider: LoginProviderArg::Openai
        }
    ));
    assert!(Cli::try_parse_from(["kata", "logout", "codex"]).is_err());
}
