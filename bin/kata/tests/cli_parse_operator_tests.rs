//! CLI parse tests for the top-level operator
//! views and factory subcommands, plus the `run` operator subcommands.

use clap::Parser as _;
use kata::cli::{Cli, Command, FactoryCmd, RunCmd};

#[test]
fn cli_parses_top_level_operator_views() {
    let approvals = Cli::try_parse_from(["kata", "approvals"]).unwrap();
    assert!(matches!(approvals.command, Command::Approvals));

    let workers = Cli::try_parse_from(["kata", "workers"]).unwrap();
    assert!(matches!(workers.command, Command::Workers));

    let workspace = Cli::try_parse_from(["kata", "workspace"]).unwrap();
    assert!(matches!(workspace.command, Command::Workspace));

    let execution_workspace =
        Cli::try_parse_from(["kata", "execution-workspace", "01HZZZZZZZZZZZZZZZZZZZZZZZ"]).unwrap();
    assert!(matches!(
        execution_workspace.command,
        Command::ExecutionWorkspace {
            execution_id
        } if execution_id == "01HZZZZZZZZZZZZZZZZZZZZZZZ"
    ));

    let replay = Cli::try_parse_from([
        "kata",
        "replay",
        "01HZZZZZZZZZZZZZZZZZZZZZZZ",
        "--include-outputs",
    ])
    .unwrap();
    assert!(matches!(
        replay.command,
        Command::Replay {
            execution_id,
            current: false,
            active: false,
            include_outputs: true
        } if execution_id.as_deref() == Some("01HZZZZZZZZZZZZZZZZZZZZZZZ")
    ));

    let replay_current = Cli::try_parse_from(["kata", "replay", "--current", "--active"]).unwrap();
    assert!(matches!(
        replay_current.command,
        Command::Replay {
            execution_id: None,
            current: true,
            active: true,
            include_outputs: false
        }
    ));
    assert!(
        Cli::try_parse_from(["kata", "replay", "--active"]).is_err(),
        "--active must be scoped to --current"
    );
    assert!(
        Cli::try_parse_from(["kata", "replay", "01HZZZZZZZZZZZZZZZZZZZZZZZ", "--current"]).is_err(),
        "explicit id and --current must conflict"
    );

    let run_summary =
        Cli::try_parse_from(["kata", "run-summary", "01HZZZZZZZZZZZZZZZZZZZZZZZ"]).unwrap();
    assert!(matches!(
        run_summary.command,
        Command::RunSummary {
            execution_id
            ,
            current: false,
            active: false
        } if execution_id.as_deref() == Some("01HZZZZZZZZZZZZZZZZZZZZZZZ")
    ));
    let run_summary_current =
        Cli::try_parse_from(["kata", "run-summary", "--current", "--active"]).unwrap();
    assert!(matches!(
        run_summary_current.command,
        Command::RunSummary {
            execution_id: None,
            current: true,
            active: true
        }
    ));
    assert!(
        Cli::try_parse_from(["kata", "run-summary", "--active"]).is_err(),
        "--active must be scoped to --current"
    );
    assert!(
        Cli::try_parse_from([
            "kata",
            "run-summary",
            "01HZZZZZZZZZZZZZZZZZZZZZZZ",
            "--current"
        ])
        .is_err(),
        "explicit id and --current must conflict"
    );

    let explain = Cli::try_parse_from(["kata", "explain", "01HZZZZZZZZZZZZZZZZZZZZZZZ"]).unwrap();
    assert!(matches!(
        explain.command,
        Command::Explain {
            execution_id,
            current: false,
            active: false,
        } if execution_id.as_deref() == Some("01HZZZZZZZZZZZZZZZZZZZZZZZ")
    ));
    let explain_current =
        Cli::try_parse_from(["kata", "explain", "--current", "--active"]).unwrap();
    assert!(matches!(
        explain_current.command,
        Command::Explain {
            execution_id: None,
            current: true,
            active: true,
        }
    ));
    assert!(
        Cli::try_parse_from(["kata", "explain", "--active"]).is_err(),
        "--active must be scoped to --current"
    );
    assert!(
        Cli::try_parse_from(["kata", "explain", "01HZZZZZZZZZZZZZZZZZZZZZZZ", "--current"])
            .is_err(),
        "explicit id and --current must conflict"
    );

    let report = Cli::try_parse_from(["kata", "report", "01HZZZZZZZZZZZZZZZZZZZZZZZ"]).unwrap();
    assert!(matches!(
        report.command,
        Command::Report {
            execution_id,
            current: false,
            active: false,
            bundle: false,
            bundle_dir: None
        } if execution_id.as_deref() == Some("01HZZZZZZZZZZZZZZZZZZZZZZZ")
    ));
    let report_current = Cli::try_parse_from(["kata", "report", "--current", "--active"]).unwrap();
    assert!(matches!(
        report_current.command,
        Command::Report {
            execution_id: None,
            current: true,
            active: true,
            bundle: false,
            bundle_dir: None
        }
    ));
    let report_bundle = Cli::try_parse_from(["kata", "report", "--current", "--bundle"]).unwrap();
    assert!(matches!(
        report_bundle.command,
        Command::Report {
            execution_id: None,
            current: true,
            active: false,
            bundle: true,
            bundle_dir: None
        }
    ));
    let report_bundle_dir =
        Cli::try_parse_from(["kata", "report", "--current", "--bundle-dir", "out/report"]).unwrap();
    assert!(matches!(
        report_bundle_dir.command,
        Command::Report {
            execution_id: None,
            current: true,
            active: false,
            bundle: false,
            bundle_dir: Some(ref path)
        } if path == std::path::Path::new("out/report")
    ));
    assert!(
        Cli::try_parse_from(["kata", "report", "--active"]).is_err(),
        "--active must be scoped to --current"
    );
    assert!(
        Cli::try_parse_from(["kata", "report", "01HZZZZZZZZZZZZZZZZZZZZZZZ", "--current"]).is_err(),
        "explicit id and --current must conflict"
    );
    assert!(
        Cli::try_parse_from([
            "kata",
            "report",
            "--current",
            "--bundle",
            "--bundle-dir",
            "out"
        ])
        .is_err(),
        "--bundle and --bundle-dir must conflict"
    );

    let factory_status =
        Cli::try_parse_from(["kata", "factory", "status", "01HZZZZZZZZZZZZZZZZZZZZZZZ"]).unwrap();
    assert!(matches!(
        factory_status.command,
        Command::Factory {
            cmd: FactoryCmd::Status {
                execution_id,
                current: false,
                active: false
            }
        } if execution_id.as_deref() == Some("01HZZZZZZZZZZZZZZZZZZZZZZZ")
    ));

    let factory_status_current =
        Cli::try_parse_from(["kata", "factory", "status", "--current", "--active"]).unwrap();
    assert!(matches!(
        factory_status_current.command,
        Command::Factory {
            cmd: FactoryCmd::Status {
                execution_id: None,
                current: true,
                active: true
            }
        }
    ));
    assert!(
        Cli::try_parse_from(["kata", "factory", "status", "--active"]).is_err(),
        "--active must be scoped to --current"
    );
    assert!(
        Cli::try_parse_from([
            "kata",
            "factory",
            "status",
            "01HZZZZZZZZZZZZZZZZZZZZZZZ",
            "--current"
        ])
        .is_err(),
        "explicit id and --current must conflict"
    );

    let factory_report =
        Cli::try_parse_from(["kata", "factory", "report", "01HZZZZZZZZZZZZZZZZZZZZZZZ"]).unwrap();
    assert!(matches!(
        factory_report.command,
        Command::Factory {
            cmd: FactoryCmd::Report {
                execution_id,
                current: false,
                active: false,
                bundle: false,
                bundle_dir: None
            }
        } if execution_id.as_deref() == Some("01HZZZZZZZZZZZZZZZZZZZZZZZ")
    ));
    let factory_report_current = Cli::try_parse_from([
        "kata",
        "factory",
        "report",
        "--current",
        "--active",
        "--bundle",
    ])
    .unwrap();
    assert!(matches!(
        factory_report_current.command,
        Command::Factory {
            cmd: FactoryCmd::Report {
                execution_id: None,
                current: true,
                active: true,
                bundle: true,
                bundle_dir: None
            }
        }
    ));
    let factory_report_bundle_dir = Cli::try_parse_from([
        "kata",
        "factory",
        "report",
        "--current",
        "--bundle-dir",
        "out/factory-report",
    ])
    .unwrap();
    assert!(matches!(
        factory_report_bundle_dir.command,
        Command::Factory {
            cmd: FactoryCmd::Report {
                execution_id: None,
                current: true,
                active: false,
                bundle: false,
                bundle_dir: Some(ref path)
            }
        } if path == std::path::Path::new("out/factory-report")
    ));
    assert!(
        Cli::try_parse_from(["kata", "factory", "report", "--active"]).is_err(),
        "--active must be scoped to --current"
    );
    assert!(
        Cli::try_parse_from([
            "kata",
            "factory",
            "report",
            "01HZZZZZZZZZZZZZZZZZZZZZZZ",
            "--current"
        ])
        .is_err(),
        "explicit id and --current must conflict"
    );
    assert!(
        Cli::try_parse_from([
            "kata",
            "factory",
            "report",
            "--current",
            "--bundle",
            "--bundle-dir",
            "out",
        ])
        .is_err(),
        "--bundle and --bundle-dir must conflict"
    );

    let factory_candidate =
        Cli::try_parse_from(["kata", "factory", "candidate", "01HZZZZZZZZZZZZZZZZZZZZZZZ"])
            .unwrap();
    assert!(matches!(
        factory_candidate.command,
        Command::Factory {
            cmd: FactoryCmd::Candidate {
                execution_id,
                current: false,
                active: false
            }
        } if execution_id.as_deref() == Some("01HZZZZZZZZZZZZZZZZZZZZZZZ")
    ));

    let factory_candidate_current =
        Cli::try_parse_from(["kata", "factory", "candidate", "--current", "--active"]).unwrap();
    assert!(matches!(
        factory_candidate_current.command,
        Command::Factory {
            cmd: FactoryCmd::Candidate {
                execution_id: None,
                current: true,
                active: true
            }
        }
    ));
    assert!(
        Cli::try_parse_from(["kata", "factory", "candidate", "--active"]).is_err(),
        "--active must be scoped to --current"
    );
    assert!(
        Cli::try_parse_from([
            "kata",
            "factory",
            "candidate",
            "01HZZZZZZZZZZZZZZZZZZZZZZZ",
            "--current"
        ])
        .is_err(),
        "explicit id and --current must conflict"
    );

    let factory_apply = Cli::try_parse_from([
        "kata",
        "factory",
        "apply",
        "--current",
        "--decision-id",
        "factory-smoke-controller-001",
        "--name",
        "product-factory-smoke",
    ])
    .unwrap();
    assert!(matches!(
        factory_apply.command,
        Command::Factory {
            cmd: FactoryCmd::Apply {
                execution_id: None,
                current: true,
                active: false,
                decision_id,
                action: None,
                workflow: None,
                channel: None,
                input_id: None,
                source,
                name: Some(name),
                resume_claimed_side_effect: false
            }
        } if decision_id == "factory-smoke-controller-001"
            && name == "product-factory-smoke"
            && source == "factory_controller"
    ));
    let factory_apply_resume = Cli::try_parse_from([
        "kata",
        "factory",
        "apply",
        "--current",
        "--decision-id",
        "factory-smoke-controller-001",
        "--action",
        "advance",
        "--workflow",
        "std.software_factory.retry",
        "--channel",
        "controller_decision",
        "--input-id",
        "factory-retry-input",
        "--source",
        "operator_recovery",
        "--resume-claimed-side-effect",
    ])
    .unwrap();
    assert!(matches!(
        factory_apply_resume.command,
        Command::Factory {
            cmd: FactoryCmd::Apply {
                execution_id: None,
                current: true,
                active: false,
                decision_id,
                action: Some(action),
                workflow: Some(workflow),
                channel: Some(channel),
                input_id: Some(input_id),
                source,
                name: None,
                resume_claimed_side_effect: true
            }
        } if decision_id == "factory-smoke-controller-001"
            && action == "advance"
            && workflow == "std.software_factory.retry"
            && channel == "controller_decision"
            && input_id == "factory-retry-input"
            && source == "operator_recovery"
    ));
    assert!(
        Cli::try_parse_from([
            "kata",
            "factory",
            "apply",
            "01HZZZZZZZZZZZZZZZZZZZZZZZ",
            "--current",
            "--decision-id",
            "factory-smoke-controller-001",
        ])
        .is_err(),
        "explicit id and --current must conflict"
    );

    let factory_finalize = Cli::try_parse_from([
        "kata",
        "factory",
        "finalize",
        "--current",
        "--decision-id",
        "decision-park",
        "--parked-ref",
        "parked/manual-review",
        "--commit-sha",
        "abc123",
        "--reason",
        "operator verified parked ref",
        "--evidence",
        "git show-ref parked/manual-review",
        "--confirm-side-effect",
    ])
    .unwrap();
    assert!(matches!(
        factory_finalize.command,
        Command::Factory {
            cmd: FactoryCmd::Finalize {
                execution_id: None,
                current: true,
                active: false,
                decision_id,
                action: None,
                next_execution_id: None,
                parked_ref: Some(parked_ref),
                commit_sha: Some(commit_sha),
                promoted_ref: None,
                promoted_commit_sha: None,
                source,
                reason,
                evidence,
                confirm_side_effect: true
            }
        } if decision_id == "decision-park"
            && parked_ref == "parked/manual-review"
            && commit_sha == "abc123"
            && source == "factory_controller_finalize"
            && reason == "operator verified parked ref"
            && evidence == vec!["git show-ref parked/manual-review".to_string()]
    ));

    let factory_finalize_promote = Cli::try_parse_from([
        "kata",
        "factory",
        "finalize",
        "01HZZZZZZZZZZZZZZZZZZZZZZZ",
        "--decision-id",
        "decision-promote",
        "--action",
        "promote",
        "--promoted-ref",
        "main",
        "--promoted-commit-sha",
        "def456",
        "--reason",
        "operator verified promoted commit",
        "--evidence",
        "git rev-parse main",
        "--confirm-side-effect",
    ])
    .unwrap();
    assert!(matches!(
        factory_finalize_promote.command,
        Command::Factory {
            cmd: FactoryCmd::Finalize {
                execution_id: Some(execution_id),
                current: false,
                active: false,
                decision_id,
                action: Some(action),
                next_execution_id: None,
                parked_ref: None,
                commit_sha: None,
                promoted_ref: Some(promoted_ref),
                promoted_commit_sha: Some(promoted_commit_sha),
                source,
                reason,
                evidence,
                confirm_side_effect: true
            }
        } if execution_id == "01HZZZZZZZZZZZZZZZZZZZZZZZ"
            && decision_id == "decision-promote"
            && action == "promote"
            && promoted_ref == "main"
            && promoted_commit_sha == "def456"
            && source == "factory_controller_finalize"
            && reason == "operator verified promoted commit"
            && evidence == vec!["git rev-parse main".to_string()]
    ));

    let factory_run = Cli::try_parse_from([
        "kata",
        "factory",
        "run",
        "std.software_factory.smoke",
        "--watch",
    ])
    .unwrap();
    assert!(matches!(
        factory_run.command,
        Command::Factory {
            cmd: FactoryCmd::Run {
                workflow,
                watch: true,
                wait: false,
                include_outputs: false,
                timeout_secs: 60,
                poll_ms: 500,
                ..
            }
        } if workflow == "std.software_factory.smoke"
    ));
    let factory_run_default =
        Cli::try_parse_from(["kata", "factory", "run", "std.software_factory.smoke"]).unwrap();
    assert!(matches!(
        factory_run_default.command,
        Command::Factory {
            cmd: FactoryCmd::Run {
                workflow,
                watch: false,
                wait: false,
                ..
            }
        } if workflow == "std.software_factory.smoke"
    ));
    assert!(
        Cli::try_parse_from([
            "kata",
            "factory",
            "run",
            "std.software_factory.smoke",
            "--watch",
            "--include-outputs"
        ])
        .is_ok(),
        "--include-outputs is valid with --watch"
    );
    let factory_run_wait = Cli::try_parse_from([
        "kata",
        "factory",
        "run",
        "path/to/workflow.star",
        "--wait",
        "--timeout-secs",
        "10",
        "--poll-ms",
        "100",
    ])
    .unwrap();
    assert!(matches!(
        factory_run_wait.command,
        Command::Factory {
            cmd: FactoryCmd::Run {
                workflow,
                watch: false,
                wait: true,
                include_outputs: false,
                timeout_secs: 10,
                poll_ms: 100,
                ..
            }
        } if workflow == "path/to/workflow.star"
    ));
    assert!(
        Cli::try_parse_from([
            "kata",
            "factory",
            "run",
            "std.software_factory.smoke",
            "--watch",
            "--wait"
        ])
        .is_err(),
        "--watch and --wait must conflict"
    );
    assert!(
        Cli::try_parse_from([
            "kata",
            "factory",
            "run",
            "std.software_factory.smoke",
            "--include-outputs"
        ])
        .is_err(),
        "--include-outputs must be scoped to --watch"
    );
    let factory_run_context = Cli::try_parse_from([
        "kata",
        "factory",
        "run",
        "std.software_factory.kata_self_improve",
        "--context",
        "tighten the first wave",
        "--channel",
        "operator_steering",
        "--input-id",
        "initial-steering-1",
        "--source",
        "codex",
        "--target-stage",
        "context",
        "--payload-json",
        "{\"risk\":\"docs_low\"}",
    ])
    .unwrap();
    assert!(matches!(
        factory_run_context.command,
        Command::Factory {
            cmd: FactoryCmd::Run {
                workflow,
                context: Some(context),
                context_file: None,
                channel: Some(channel),
                input_id: Some(input_id),
                source: Some(source),
                target_stage: Some(target_stage),
                payload_json: Some(payload_json),
                ..
            }
        } if workflow == "std.software_factory.kata_self_improve"
            && context == "tighten the first wave"
            && channel == "operator_steering"
            && input_id == "initial-steering-1"
            && source == "codex"
            && target_stage == "context"
            && payload_json == "{\"risk\":\"docs_low\"}"
    ));
    let factory_run_context_file = Cli::try_parse_from([
        "kata",
        "factory",
        "run",
        "std.software_factory.kata_self_improve",
        "--context-file",
        "notes/first-wave.md",
    ])
    .unwrap();
    assert!(matches!(
        factory_run_context_file.command,
        Command::Factory {
            cmd: FactoryCmd::Run {
                workflow,
                context: None,
                context_file: Some(context_file),
                ..
            }
        } if workflow == "std.software_factory.kata_self_improve"
            && context_file.to_str() == Some("notes/first-wave.md")
    ));
    assert!(
        Cli::try_parse_from([
            "kata",
            "factory",
            "run",
            "std.software_factory.kata_self_improve",
            "--context",
            "a",
            "--context-file",
            "b.md"
        ])
        .is_err(),
        "factory run --context and --context-file must conflict"
    );
    assert!(
        Cli::try_parse_from([
            "kata",
            "factory",
            "run",
            "std.software_factory.kata_self_improve",
            "--channel",
            "operator_steering"
        ])
        .is_ok(),
        "factory run option validation rejects channel-without-context at execution time"
    );
    let factory_steer = Cli::try_parse_from([
        "kata",
        "factory",
        "steer",
        "01HZZZZZZZZZZZZZZZZZZZZZZZ",
        "--context",
        "keep the wave bounded",
        "--input-id",
        "steer-1",
    ])
    .unwrap();
    assert!(matches!(
        factory_steer.command,
        Command::Factory {
            cmd: FactoryCmd::Steer {
                execution_id,
                current: false,
                active: false,
                context: Some(context),
                context_file: None,
                channel,
                input_id: Some(input_id),
                source,
                target_stage: None,
                payload_json: None,
            }
        } if execution_id.as_deref() == Some("01HZZZZZZZZZZZZZZZZZZZZZZZ")
            && context == "keep the wave bounded"
            && channel == "operator_steering"
            && input_id == "steer-1"
            && source == "operator"
    ));
    let factory_steer_file = Cli::try_parse_from([
        "kata",
        "factory",
        "steer",
        "--current",
        "--context-file",
        "notes/steering.md",
        "--channel",
        "validation_context",
        "--source",
        "codex",
        "--target-stage",
        "validate",
        "--payload-json",
        "{\"priority\":\"high\"}",
    ])
    .unwrap();
    assert!(matches!(
        factory_steer_file.command,
        Command::Factory {
            cmd: FactoryCmd::Steer {
                execution_id: None,
                current: true,
                active: false,
                context: None,
                context_file: Some(context_file),
                channel,
                input_id: None,
                source,
                target_stage: Some(target_stage),
                payload_json: Some(payload_json),
            }
        } if context_file.to_str() == Some("notes/steering.md")
            && channel == "validation_context"
            && source == "codex"
            && target_stage == "validate"
            && payload_json == "{\"priority\":\"high\"}"
    ));
    assert!(
        Cli::try_parse_from(["kata", "factory", "steer", "--active", "--context", "a"]).is_err(),
        "--active must be scoped to --current"
    );
    assert!(
        Cli::try_parse_from([
            "kata",
            "factory",
            "steer",
            "01HZZZZZZZZZZZZZZZZZZZZZZZ",
            "--current",
            "--context",
            "a"
        ])
        .is_err(),
        "explicit id and --current must conflict"
    );
    assert!(
        Cli::try_parse_from([
            "kata",
            "factory",
            "steer",
            "--current",
            "--context",
            "a",
            "--context-file",
            "b.md"
        ])
        .is_err(),
        "--context and --context-file must conflict"
    );
}

/// `kata events` gains `--since`/`--status` (repeatable or
/// comma-separated) server-side filters plus `--exit-on` (same shape)
/// to block for a matching event instead of streaming forever.
#[test]
fn cli_parses_events_since_status_and_exit_on_flags() {
    let bare = Cli::try_parse_from(["kata", "events"]).unwrap();
    assert!(matches!(
        bare.command,
        Command::Events {
            filter_execution: None,
            status,
            since: None,
            exit_on,
        } if status.is_empty() && exit_on.is_empty()
    ));

    let filtered = Cli::try_parse_from([
        "kata",
        "events",
        "--filter-execution",
        "01HZZZZZZZZZZZZZZZZZZZZZZZ",
        "--since",
        "42",
        "--status",
        "completed",
        "--status",
        "failed",
    ])
    .unwrap();
    assert!(matches!(
        filtered.command,
        Command::Events {
            filter_execution,
            status,
            since: Some(42),
            exit_on,
        } if filter_execution.as_deref() == Some("01HZZZZZZZZZZZZZZZZZZZZZZZ")
            && status == vec!["completed".to_string(), "failed".to_string()]
            && exit_on.is_empty()
    ));

    // Comma-separated values are accepted as an alternative to repeating
    // the flag.
    let comma = Cli::try_parse_from(["kata", "events", "--status", "completed,failed"]).unwrap();
    assert!(matches!(
        comma.command,
        Command::Events { status, .. } if status == vec!["completed".to_string(), "failed".to_string()]
    ));

    let exit_on =
        Cli::try_parse_from(["kata", "events", "--exit-on", "completed,failed,orphaned"]).unwrap();
    assert!(matches!(
        exit_on.command,
        Command::Events { exit_on, .. }
            if exit_on == vec!["completed".to_string(), "failed".to_string(), "orphaned".to_string()]
    ));
}

/// The sysexits-style `KataClientError` variants `kata events
/// --since`/`--exit-on` can surface map to the documented exit codes
/// (65/66), independent of the generic `OpError` (2..=6) contract.
/// Constructed directly rather than through a subprocess — `main`'s
/// `ExitCode`-returning body is not unit-testable from `tests/`, so the
/// mapping is pulled into `cli::exit_code_for_error` for exactly this.
#[test]
fn exit_code_for_error_maps_kata_client_sysexits_variants() {
    use kata::cli::exit_code_for_error;
    use kata_client::KataClientError;

    let sse_closed = anyhow::Error::new(KataClientError::SseClosedWithoutMatch { cause: None });
    assert_eq!(
        exit_code_for_error(&sse_closed),
        65,
        "SseClosedWithoutMatch (kata events --exit-on with no match) must exit 65"
    );

    let cursor_stale = anyhow::Error::new(KataClientError::CursorStale);
    assert_eq!(
        exit_code_for_error(&cursor_stale),
        66,
        "CursorStale (kata events --since past the ledger head) must exit 66"
    );

    // Non-KataClientError anyhow errors fall through to the flat exit 1
    // (no OpError present in the chain).
    let untyped = anyhow::anyhow!("boom");
    assert_eq!(exit_code_for_error(&untyped), 1);
}

/// A typed `/ops` refusal the SDK answers (`kata run forge-reconcile`'s
/// `KataClientError::OperationRefused`) exits with its contract code's exit
/// code — `conflict` 4, `not_found` 3 — not the flat 1.
#[test]
fn exit_code_for_error_maps_an_operation_refusal_to_its_contract_code() {
    use kata::cli::exit_code_for_error;
    use kata_client::KataClientError;
    use kata_op_contract::{OpError, Operation};

    let refused = |error: OpError| {
        exit_code_for_error(&anyhow::Error::new(KataClientError::OperationRefused {
            operation: Operation::ForgeReconcile,
            error,
        }))
    };
    assert_eq!(refused(OpError::conflict("nothing pending")), 4);
    assert_eq!(refused(OpError::not_found("no such execution")), 3);
}

/// `kata run list` selects its full NDJSON records with `--json` (or the global
/// `--format json`) and with no other spelling: `--full` is an unknown argument,
/// refused at parse by clap's own unknown-flag check, naming it.
#[test]
fn run_list_selects_full_records_by_json_alone() {
    let json = Cli::try_parse_from(["kata", "run", "list", "--json"]).unwrap();
    let Command::Run { cmd, .. } = json.command else {
        panic!("expected run command");
    };
    assert!(matches!(cmd, Some(RunCmd::List { json: true, .. })));

    let error = Cli::try_parse_from(["kata", "run", "list", "--full"])
        .expect_err("`--full` is not a `kata run list` flag");
    assert_eq!(
        error.kind(),
        clap::error::ErrorKind::UnknownArgument,
        "{error}"
    );
    assert!(error.to_string().contains("--full"), "{error}");
}

/// A flag that only restates a command's default is not a flag: `kata factory
/// run` submits unless `--watch` or `--wait` is given, and `kata repair-nucleus`
/// reports unless `--apply` is given. Each spelling is refused at parse by
/// clap's own unknown-flag check, naming it.
#[test]
fn default_restating_flags_are_unknown_arguments() {
    for argv in [
        &[
            "kata",
            "factory",
            "run",
            "std.software_factory.smoke",
            "--submit",
        ][..],
        &["kata", "repair-nucleus", "--dry-run"][..],
    ] {
        let flag = argv[argv.len() - 1];
        let error = Cli::try_parse_from(argv).expect_err("a default-restating flag is refused");
        assert_eq!(
            error.kind(),
            clap::error::ErrorKind::UnknownArgument,
            "{error}"
        );
        assert!(error.to_string().contains(flag), "{error}");
    }
}

/// `kata run` has no `reconcile` subcommand: the word is read as a workflow
/// name, and the arguments a reconcile would carry are refused by clap's own
/// unknown-argument check, naming them.
#[test]
fn run_reconcile_is_not_a_subcommand() {
    for (argv, refused) in [
        (
            &[
                "kata",
                "run",
                "reconcile",
                "01HZZZZZZZZZZZZZZZZZZZZZZZ",
                "--claim-key",
                "6b617461",
            ][..],
            "01HZZZZZZZZZZZZZZZZZZZZZZZ",
        ),
        (
            &["kata", "run", "reconcile", "--claim-key", "6b617461"][..],
            "--claim-key",
        ),
    ] {
        let error = Cli::try_parse_from(argv).expect_err("`kata run reconcile` is refused");
        assert_eq!(
            error.kind(),
            clap::error::ErrorKind::UnknownArgument,
            "{error}"
        );
        assert!(error.to_string().contains(refused), "{error}");
    }
}

#[test]
fn cli_parses_run_operator_subcommands() {
    let list = Cli::try_parse_from(["kata", "run", "list"]).unwrap();
    let Command::Run { cmd, workflow, .. } = list.command else {
        panic!("expected run command");
    };
    assert!(matches!(
        cmd,
        Some(RunCmd::List {
            limit: None,
            status: None,
            json: false
        })
    ));
    assert!(workflow.is_none());

    // `kata run list --limit N --status <tags>` must parse the
    // pagination + status-filter flags through to the RunCmd::List variant so
    // the dispatch can forward them to the paginated/filterable endpoint.
    let list_filtered = Cli::try_parse_from([
        "kata",
        "run",
        "list",
        "--limit",
        "5",
        "--status",
        "running,failed",
    ])
    .unwrap();
    let Command::Run { cmd, .. } = list_filtered.command else {
        panic!("expected run command");
    };
    assert!(matches!(
        cmd,
        Some(RunCmd::List {
            limit: Some(5),
            status: Some(s),
            json: false
        }) if s == "running,failed"
    ));

    let show = Cli::try_parse_from(["kata", "run", "show", "01HZZZZZZZZZZZZZZZZZZZZZZZ"]).unwrap();
    let Command::Run { cmd, workflow, .. } = show.command else {
        panic!("expected run command");
    };
    assert!(matches!(
        cmd,
        Some(RunCmd::Show {
            execution_id
        }) if execution_id == "01HZZZZZZZZZZZZZZZZZZZZZZZ"
    ));
    assert!(workflow.is_none());

    let output = Cli::try_parse_from([
        "kata",
        "run",
        "output",
        "01HZZZZZZZZZZZZZZZZZZZZZZZ",
        "plan",
    ])
    .unwrap();
    let Command::Run { cmd, workflow, .. } = output.command else {
        panic!("expected run command");
    };
    assert!(matches!(
        cmd,
        Some(RunCmd::Output {
            execution_id,
            stage: Some(stage)
        }) if execution_id == "01HZZZZZZZZZZZZZZZZZZZZZZZ" && stage == "plan"
    ));
    assert!(workflow.is_none());

    let approve = Cli::try_parse_from([
        "kata",
        "run",
        "approve",
        "01HZZZZZZZZZZZZZZZZZZZZZZZ",
        "assign-1",
    ])
    .unwrap();
    let Command::Run { cmd, workflow, .. } = approve.command else {
        panic!("expected run command");
    };
    assert!(matches!(
        cmd,
        Some(RunCmd::Approve {
            execution_id,
            assignment_id
        }) if execution_id == "01HZZZZZZZZZZZZZZZZZZZZZZZ" && assignment_id == "assign-1"
    ));
    assert!(workflow.is_none());
}

/// The operator run packet's `output_handles[].command` is an argv an operator
/// runs, so it must be an invocation the shipped `kata` parser accepts.
/// `crates/client` declares no `[[bin]]`, so a command naming any other
/// executable advertises a recourse that cannot be invoked. The fixture carries
/// `outputs`, because a packet without them never constructs the array.
///
/// `bin/kata` is the only crate that depends on both `kata-client`
/// and the real clap `Cli`, so it is the only place the coupling can be
/// asserted: `crates/client` can never see the parser.
///
/// Half 2 is the half that cannot go stale — it would also catch
/// `kata run outputs`, `kata stage-output`, or a rename of `RunCmd::Output`.
#[test]
fn operator_packet_output_handle_command_is_a_parseable_kata_invocation() {
    let record: kata_client::types::ExecutionRecord = serde_json::from_value(serde_json::json!({
        "id": "01HZZZZZZZZZZZZZZZZZZZZZZZ",
        "workflow_name": "output-handle-argv",
        "status": "completed",
        "submitted_at_ms": 1_700_000_000_000_u64,
        "started_at_ms": 1_700_000_000_100_u64,
        "finished_at_ms": 1_700_000_000_900_u64,
        "worker_id": "worker-a",
        "outputs": { "closeout": { "summary": "done" } },
        "error": null,
        "running_cost_micro_usd": 0,
        "warnings": [],
    }))
    .expect("execution record fixture deserializes");

    let summary =
        kata_client::operator_projection::run_summary_with_worker_attribution(&record, Vec::new());
    let json = serde_json::to_value(summary).expect("run summary serializes");
    let argv: Vec<String> = serde_json::from_value(json["output_handles"][0]["command"].clone())
        .expect("output handle carries an argv array");

    // Half 1 — the exact argv. Cheap, and it names the defect.
    assert_eq!(argv, vec!["kata", "run", "output", &record.id, "closeout"]);

    // Half 2 — the emitted argv must be an invocation the SHIPPED parser
    // accepts; only the parser can say so.
    let parsed = Cli::try_parse_from(&argv)
        .expect("the command an operator packet prints must parse as a kata invocation");
    let Command::Run { cmd, .. } = parsed.command else {
        panic!("expected `kata run`");
    };
    assert!(matches!(
        cmd,
        Some(RunCmd::Output {
            execution_id,
            stage: Some(stage)
        }) if execution_id == record.id && stage == "closeout"
    ));
}

/// Surface hygiene: no CLI argument help may advertise the deleted
/// `.toml` workflow format. The MCP `tools/list` surface is guarded by
/// `cli::mcp::tools::tests::no_tool_description_advertises_the_deleted_toml_workflow_format`,
/// but that pins none of the clap help — stale `.toml`/`.star` wording lived on
/// `kata factory run`, `kata workflows inspect`, and `kata workflows check` and
/// went unguarded. This walks the whole rendered clap tree and fails on any arg
/// whose help pairs "toml" with the Starlark extension/name, which is exactly
/// the shape of the deleted "path to a `.toml`/`.star` workflow" wording. The
/// legitimate node-config args (`.kata/kata.toml`, `worker.toml`, topology
/// TOML, `~/.codex/config.toml`) mention TOML but never `.star`/"starlark", so
/// they are not flagged.
#[test]
fn no_cli_arg_help_advertises_the_deleted_toml_workflow_format() {
    use clap::CommandFactory as _;

    fn arg_help_text(arg: &clap::Arg) -> String {
        let mut text = String::new();
        if let Some(help) = arg.get_long_help().or_else(|| arg.get_help()) {
            text.push_str(&help.to_string());
        }
        text.to_ascii_lowercase()
    }

    fn walk(cmd: &clap::Command, path: &str, failures: &mut Vec<String>) {
        let here = if path.is_empty() {
            cmd.get_name().to_string()
        } else {
            format!("{path} {}", cmd.get_name())
        };
        for arg in cmd.get_arguments() {
            let help = arg_help_text(arg);
            // The one sanctioned mention: the disambiguating disclaimer that
            // toml is the NODE CONFIG, not a workflow format (`kata run`'s
            // workflow arg). Anything else pairing toml with the workflow
            // surface still fails.
            let advertises_toml_workflow = help.contains("toml")
                && !help.contains("toml is only the node config")
                && (help.contains(".star") || help.contains("starlark"));
            if advertises_toml_workflow {
                failures.push(format!(
                    "`{here}` arg `{}` help advertises the deleted `.toml` \
                     workflow format: {help:?}",
                    arg.get_id()
                ));
            }
        }
        for sub in cmd.get_subcommands() {
            walk(sub, &here, failures);
        }
    }

    let cmd = Cli::command();
    let mut failures = Vec::new();
    walk(&cmd, "", &mut failures);
    assert!(
        failures.is_empty(),
        "CLI help still advertises the deleted `.toml` workflow format:\n{}",
        failures.join("\n")
    );
}

/// The namespace-change proof's instrument parses, defaults to NOT unsharing,
/// and is HIDDEN — the last part being why it sits beside the operator parse
/// tests rather than among them.
///
/// `kata __syscall-probe` exists so a live test can observe this kernel. It is
/// not an operator surface: an operator who found it in `--help` would read it
/// as a diagnostic they are meant to run, and its whole argument set is chosen
/// for a test rig rather than for a person.
///
/// # Non-vacuity
///
/// The hidden assertion is paired with a positive one over the SAME subcommand
/// list — a visible command (`workers`) must be found and must NOT be hidden —
/// so a lookup that silently matched nothing, or a clap upgrade that reported
/// every command as hidden, cannot pass.
///
/// **Would red if:** `hide = true` were dropped from the `#[command(...)]`
/// attribute; the subcommand were renamed without updating the live probe's
/// argv in `crates/worker/tests/sandbox_seccomp_tests.rs`; or
/// `--unshare-userns` gained a default that made the namespace change happen
/// without the caller asking for it.
#[test]
fn cli_parses_the_hidden_syscall_probe() {
    use clap::CommandFactory as _;

    let bare = Cli::try_parse_from(["kata", "__syscall-probe"]).unwrap();
    assert!(matches!(
        bare.command,
        Command::SyscallProbe {
            unshare_userns: false
        }
    ));

    let unshared = Cli::try_parse_from(["kata", "__syscall-probe", "--unshare-userns"]).unwrap();
    assert!(matches!(
        unshared.command,
        Command::SyscallProbe {
            unshare_userns: true
        }
    ));

    let cmd = Cli::command();
    let probe = cmd
        .get_subcommands()
        .find(|s| s.get_name() == "__syscall-probe")
        .expect("the probe subcommand must be reachable on the clap surface");
    assert!(
        probe.is_hide_set(),
        "`__syscall-probe` must stay hidden from `--help`: it is a test instrument, not an \
         operator command"
    );
    let visible = cmd
        .get_subcommands()
        .find(|s| s.get_name() == "workers")
        .expect("premise: `kata workers` is an operator command on the same surface");
    assert!(
        !visible.is_hide_set(),
        "premise failed: if every subcommand reads as hidden, the assertion above is true of \
         a walk that is not seeing the surface"
    );
}

/// `--format json` is the one structured-output switch for every command that
/// has a human renderer: `kata check` emits the `check` operation's versioned
/// `OpEnvelope`, every other command its own document bare. None of those
/// commands takes a per-command `--json`, so a stray `--json` is refused at
/// parse — never accepted and silently ignored — while the same argv spelled
/// with `--format json` parses.
#[test]
fn enveloped_commands_refuse_a_per_command_json_flag() {
    const ID: &str = "01HZZZZZZZZZZZZZZZZZZZZZZZ";
    let commands: [&[&str]; 12] = [
        &["check", "std.hello"],
        &["build", "std.hello"],
        &["doctor"],
        &["explain", ID],
        &["report", ID],
        &["factory", "report", ID],
        &["timeline", ID],
        &["diff", ID, "build"],
        &["usage"],
        &["workflows", "inspect", "std.hello"],
        &["workflows", "check", "std.hello"],
        &["workflows", "schema"],
    ];
    for command in commands {
        let with = |tail: &[&'static str]| {
            let mut argv = vec!["kata"];
            argv.extend_from_slice(command);
            argv.extend_from_slice(tail);
            argv
        };
        let refused = Cli::try_parse_from(with(&["--json"]))
            .expect_err("a per-command `--json` must be refused at parse");
        assert_eq!(
            refused.kind(),
            clap::error::ErrorKind::UnknownArgument,
            "`kata {}` --json: {refused}",
            command.join(" ")
        );
        Cli::try_parse_from(with(&["--format", "json"])).unwrap_or_else(|error| {
            panic!(
                "`kata {} --format json` must parse: {error}",
                command.join(" ")
            )
        });
    }
}

/// **`kata usage` reports spend only: `--probe-logins` is refused at parse.**
/// The LIMITS half — the vendor auth CLIs (`claude auth status`, `codex login
/// status`, `opencode auth list`) run on the operator's machine — is deleted, so
/// `kata usage` names no vendor CLI and the flag that ran them is an unknown
/// argument, not one accepted and ignored. `--since` still parses.
///
/// **Would red if:** the flag came back, as a no-op or otherwise.
#[test]
fn usage_refuses_the_deleted_probe_logins_flag() {
    let refused = Cli::try_parse_from(["kata", "usage", "--probe-logins"])
        .expect_err("`kata usage --probe-logins` must be refused at parse");
    assert_eq!(
        refused.kind(),
        clap::error::ErrorKind::UnknownArgument,
        "{refused}"
    );
    let spend = Cli::try_parse_from(["kata", "usage", "--since", "24h"]).unwrap();
    assert!(
        matches!(spend.command, Command::Usage { ref since, .. } if since == "24h"),
        "{:?}",
        spend.command
    );
}
