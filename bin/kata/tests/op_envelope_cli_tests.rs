//! Acceptance: the global `--format json` emits a schema'd, versioned
//! `OpEnvelope` for `kata check` — the `check` operation's own CLI face — and
//! every other command's own JSON document bare; the human path is the text
//! renderer; and the deterministic exit-code contract holds.
//!
//! These drive the real `kata` binary (`CARGO_BIN_EXE_kata`) so the assertions
//! cover the full parse → dispatch → emit → exit path, not just an internal
//! helper.

use std::process::Command;

/// A bundled stdlib workflow that compiles cleanly through preflight; resolved
/// via the workflow crate's compile-time manifest fallback, so it is found
/// regardless of the test process's working directory. The pack must
/// CHECK under the shipped `oci` default a node-less `kata check` reads —
/// `kata-work-item` is confined.
const BUNDLED_WORKFLOW: &str = "kata-work-item";

fn kata() -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_kata"));
    // A harness-exported `KATA_CONFIG` would silently change what a node-less
    // `check`/`build` judges under — remove it so only the explicit `.env`
    // spelling below ever reaches the binary.
    command.env_remove("KATA_CONFIG");
    command
}

fn run(args: &[&str]) -> std::process::Output {
    kata()
        .args(args)
        .output()
        .expect("spawn kata binary under test")
}

fn parse_stdout_json(output: &std::process::Output) -> serde_json::Value {
    let stdout = String::from_utf8(output.stdout.clone()).expect("stdout is utf8");
    serde_json::from_str(&stdout)
        .unwrap_or_else(|err| panic!("stdout is not JSON: {err}\n---\n{stdout}"))
}

fn assert_ok_envelope(value: &serde_json::Value, expected_op: &str) {
    assert_eq!(value["op"], expected_op, "envelope op tag");
    assert_eq!(value["schema_version"], 1, "envelope schema_version");
    assert_eq!(value["ok"], true, "envelope ok flag");
    assert!(value["data"].is_object(), "envelope carries data payload");
    assert!(value.get("error").is_none(), "no error on success envelope");
}

/// `check --config <kata.toml>` judges under the `[node]` facts that config
/// declares — the same install `BootRig::boot` performs — while a node-less
/// `kata check` defers the agent/egress/environment classes it cannot see.
/// The observable pair: a stage bound to an agent label no node declares is
/// DEFERRED (passes) with no config installed, and refused `adapter_undeclared`
/// BY NAME the moment the generated config's `[agents]` map is installed —
/// `kata init` emits no `execution_profile`, so that judgment lands on the
/// shipped `oci` default.
#[test]
fn check_config_judges_under_the_declared_node_profile() {
    let dir = tempfile::tempdir().expect("temp project dir");
    let cfg = dir.path().join("kata.toml");
    let cfg_str = cfg.to_str().expect("temp path is utf8");
    let init = run(&["init", "--config", cfg_str]);
    assert!(
        init.status.success(),
        "init seeds a config; stderr: {}",
        String::from_utf8_lossy(&init.stderr)
    );

    // A pack whose stage binds a label no `[agents]` block anywhere declares.
    let pack = dir.path().join("undeclared-agent.star");
    std::fs::write(
        &pack,
        r#"s = stage(id = "s", agent = "agent-label-no-node-declares", prompt = "go")
workflow("undeclared-agent", root = [s])
"#,
    )
    .expect("write pack");
    let pack_str = pack.to_str().expect("temp path is utf8");

    // The deferred half: node-less check judges the stage's agent binding as
    // unobserved — the agents class lands in `deferred_node_facts`, not a
    // refusal.
    let deferred = run(&["check", pack_str]);
    assert!(
        deferred.status.success(),
        "a node-less check defers the agents class; stderr: {}",
        String::from_utf8_lossy(&deferred.stderr)
    );

    // The judged half: the same pack under the generated config's installed
    // `[agents]` map — the label has no block, which the `oci` CHECK refuses
    // `adapter_undeclared` for.
    let judged = run(&["check", pack_str, "--config", cfg_str]);
    assert!(
        !judged.status.success(),
        "check --config judges the pack under the config's declared agents"
    );
    let stderr = String::from_utf8_lossy(&judged.stderr);
    assert!(
        stderr.contains("adapter_undeclared"),
        "the refusal names its door: {stderr}"
    );

    // The same door spelled in the environment — how a pack-authored
    // `kata check` validation command, spawned by a stage as a child of the
    // `kata serve` process, inherits the profile of the node it runs inside
    // (the factory smokes export `KATA_CONFIG` beside `KATA_STDLIB_DIR` for
    // exactly this).
    let inherited = kata()
        .args(["check", pack_str])
        .env("KATA_CONFIG", cfg_str)
        .output()
        .expect("spawn kata binary under test");
    assert!(
        !inherited.status.success(),
        "KATA_CONFIG env judges the pack under the config's declared agents"
    );
    let stderr = String::from_utf8_lossy(&inherited.stderr);
    assert!(
        stderr.contains("adapter_undeclared"),
        "the env door refuses by the same name: {stderr}"
    );
}

#[test]
fn check_format_json_emits_op_envelope() {
    let output = run(&["--format", "json", "check", BUNDLED_WORKFLOW]);
    assert!(
        output.status.success(),
        "check of a valid bundled workflow exits 0; stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let value = parse_stdout_json(&output);
    assert_ok_envelope(&value, "check");
    // The envelope `data` is the `check` operation's response.
    assert_eq!(value["data"]["passed"], true);
    assert_eq!(value["data"]["name"], BUNDLED_WORKFLOW);
}

#[test]
fn build_format_json_emits_the_build_document_bare() {
    let output = run(&["--format", "json", "build", BUNDLED_WORKFLOW]);
    assert!(
        output.status.success(),
        "build of a valid bundled workflow exits 0; stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let value = parse_stdout_json(&output);
    assert_eq!(value["build"]["passed"], true);
    assert!(value["execution_program"].is_object());
}

/// `workflows list` ACCEPTED the global `--format json` (clap propagates it, and
/// validates its value) and then dropped it, printing human text at exit 0 — so
/// a caller scripting `--format json` parsed prose as JSON. The defect lived in
/// the wiring between the parsed args and the handler, which is why this drives
/// the real binary rather than the listing builder.
#[test]
fn workflows_list_format_json_emits_the_listing() {
    let output = run(&["--format", "json", "workflows", "list"]);
    assert!(
        output.status.success(),
        "listing the bundled library exits 0; stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let value = parse_stdout_json(&output);

    let workflows = value["workflows"]
        .as_array()
        .unwrap_or_else(|| panic!("listing carries a workflows array; got: {value}"));
    assert!(
        !workflows.is_empty(),
        "the bundled stdlib resolves at least one workflow"
    );
    let bundled = workflows
        .iter()
        .find(|row| row["name"] == BUNDLED_WORKFLOW)
        .unwrap_or_else(|| panic!("{BUNDLED_WORKFLOW} is listed; got: {value}"));
    // The row is the shared REST wire spelling, not a second hand-rolled one.
    assert_eq!(bundled["format"], "starlark");
    assert!(bundled["path"].as_str().is_some_and(|p| {
        std::path::Path::new(p)
            .extension()
            .is_some_and(|ext| ext.eq_ignore_ascii_case("star"))
    }));
    assert!(bundled["root_priority"].is_number());
    assert!(value["roots"].is_array(), "roots table is present");
}

/// The human path keeps its own byte shape — the JSON envelope is additive.
#[test]
fn workflows_list_human_output_is_unchanged() {
    let output = run(&["workflows", "list"]);
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).expect("stdout is utf8");
    assert!(
        stdout.starts_with("workflow library roots (priority order, highest first):"),
        "human listing is the unchanged text renderer; got:\n{stdout}"
    );
    assert!(
        !stdout.contains("schema_version") && !stdout.contains("\"op\""),
        "human path must not emit the JSON envelope; got:\n{stdout}"
    );
}

/// `--format` is parsed for `list` (not merely tolerated): an invalid value is a
/// clap usage error, which is what makes "accepted and then dropped" the precise
/// diagnosis rather than "clap ignored an unknown flag".
#[test]
fn workflows_list_rejects_an_invalid_format_value() {
    let output = run(&["workflows", "list", "--format", "bogus"]);
    assert_eq!(
        output.status.code(),
        Some(2),
        "an invalid --format value is a usage error; stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn human_output_is_unchanged_without_json() {
    let output = run(&["check", BUNDLED_WORKFLOW]);
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).expect("stdout is utf8");
    assert!(
        !stdout.contains("schema_version") && !stdout.contains("\"op\""),
        "human path must not emit the JSON envelope; got:\n{stdout}"
    );
    assert!(
        stdout.starts_with("workflow check:"),
        "human path is the byte-identical text renderer; got:\n{stdout}"
    );
}

/// The `--format` help ADVERTISED an envelope it does not emit: "a schema'd,
/// versioned `OpEnvelope` for every operation that supports structured output".
/// Measured against a live node — `run list`, `run show`, `run current`,
/// `workers` and `status` emit BARE records, and the first three of those five
/// are among the commands an agent reaches for first.
///
/// The help was narrowed rather than the commands enveloped, because
/// `run list`'s raw NDJSON is a deliberate, documented, unit-tested divergence
/// (`run_list_emits_full_records`) whose whole purpose is preserving existing
/// stream consumers, and because `workers`/`status` answer no `Operation` —
/// `emit_ok` accepts only an operation's response type, and minting a variant
/// ahead of a real MCP/REST binding is what that contract's own docs forbid.
///
/// This test pins the narrowing to reality, so a future edit cannot restore the
/// universal claim and cannot let the exemption list name commands that do not
/// exist.
#[test]
fn format_help_advertises_only_the_envelope_it_emits() {
    let output = run(&["--help"]);
    assert!(output.status.success(), "`kata --help` exits 0");
    let help = String::from_utf8(output.stdout).expect("help is utf8");

    assert!(
        !help.contains("for every operation that supports structured output"),
        "`--format`'s help must not universally quantify over operations — five \
         operator read commands emit bare records under `--format json`. Help:\n{help}"
    );

    // The help names `check` as the one ENVELOPING command, and the commands
    // `--format json` serves bare (proved by the tests above for `check`,
    // `build`, `workflows list` and the bare-document cell); each must be real.
    assert!(
        help.contains("`check` — the `check` operation's own CLI face"),
        "the help names `check` as the command whose JSON is an operation's envelope. \
         Help:\n{help}"
    );
    for served in ["check", "build", "doctor", "workflows", "timeline", "usage"] {
        assert!(
            help.contains(served),
            "the help must keep naming `{served}` as a command `--format json` serves"
        );
        assert!(
            subcommand_exists(served),
            "the help names `{served}` under `--format json`, but it is not a subcommand"
        );
    }

    // The commands the help names as EXEMPT must be real too — an exemption
    // list naming a command that does not exist is the same defect one step on.
    for exempt in ["run list", "run show", "run current", "workers", "status"] {
        assert!(
            help.contains(exempt),
            "`--format`'s help must name `{exempt}` as a command it does NOT envelope; \
             that is the measured behaviour and the reason the claim was narrowed. \
             Help:\n{help}"
        );
        assert!(
            subcommand_exists(exempt),
            "the help names `{exempt}` as exempt, but it is not a subcommand path"
        );
    }
}

/// `kata help <path...>` exits 0 for a real (possibly nested) subcommand and
/// non-zero for anything else, so neither list in the `--format` help can rot
/// into naming a command that is gone.
fn subcommand_exists(path: &str) -> bool {
    let mut args = vec!["help"];
    args.extend(path.split(' '));
    run(&args).status.success()
}

#[test]
fn not_found_workflow_exits_3() {
    let output = run(&["check", "no-such-workflow-xyz"]);
    assert_eq!(
        output.status.code(),
        Some(3),
        "an addressed-but-absent workflow maps to the not-found exit code (3); stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn usage_conflict_exits_2() {
    // A workflow argument AND --all is mutually exclusive → usage error (2).
    let output = run(&["check", BUNDLED_WORKFLOW, "--all"]);
    assert_eq!(
        output.status.code(),
        Some(2),
        "mutually-exclusive flags map to the usage exit code (2); stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

/// A reader that closes stdout early (`kata workflows schema | head`) ends the
/// command cleanly: exit 0, no panic. The read end is dropped before the child
/// writes a byte, so its write sees EPIPE whatever the catalog's size — both the
/// human face and the bare `--format json` document.
#[test]
fn workflows_schema_exits_cleanly_when_the_reader_closes_the_pipe() {
    for args in [
        &["workflows", "schema"][..],
        &["--format", "json", "workflows", "schema"][..],
    ] {
        let mut child = kata()
            .args(args)
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .expect("spawn kata binary under test");
        drop(child.stdout.take());
        let output = child.wait_with_output().expect("wait for kata");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            output.status.success() && !stderr.contains("panicked"),
            "`kata {}` must treat a closed stdout as the reader being done: status {:?}, \
             stderr:\n{stderr}",
            args.join(" "),
            output.status,
        );
    }
}

/// **An envelope's `op` tags its `data` with that operation's response schema,
/// and the CLI keeps it.** `kata check --format json` (one workflow, and
/// `--all`) is the `check` operation's own CLI face: its `data` must
/// deserialize as the contract's `CheckResponse` — the type `check`'s published
/// `response_schema` is derived from — and must equal what the MCP `check` tool
/// returns for the same request on the engine-free binding, the document
/// `check_for_contract` builds.
///
/// **Would red if:** the CLI enveloped a document of its own under `op: check`
/// (watched at the base: `data` was the detailed `{name, source, check: {..},
/// execution_program, ..}` report, which `CheckResponse` refuses for its
/// missing `passed`).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn kata_check_json_is_the_check_operations_response() {
    use kata::cli::mcp::{McpBinding, dispatch_tool_enveloped};
    use kata_op_contract::Operation;
    use kata_op_contract::responses::CheckResponse;

    for (args, request) in [
        (
            vec!["--format", "json", "check", BUNDLED_WORKFLOW],
            serde_json::json!({ "workflow": BUNDLED_WORKFLOW }),
        ),
        (
            vec!["--format", "json", "check", "--all"],
            serde_json::json!({ "all": true }),
        ),
    ] {
        let output = run(&args);
        let value = parse_stdout_json(&output);
        assert_eq!(value["op"], "check", "{args:?}: {value}");
        assert_eq!(value["ok"], true, "{args:?}: {value}");
        let response: CheckResponse =
            serde_json::from_value(value["data"].clone()).unwrap_or_else(|error| {
                panic!(
                    "{args:?}: `data` under `op: check` is not a CheckResponse ({error}): {}",
                    value["data"]
                )
            });
        let mcp = dispatch_tool_enveloped(&McpBinding::LocalOnly, Operation::Check, request).await;
        assert_eq!(
            serde_json::to_value(&response).unwrap(),
            mcp.data.expect("the MCP local check answers"),
            "{args:?}: the CLI and MCP faces of `check` return one document"
        );
    }
}

/// **A JSON document that answers no operation carries no envelope.** Each of
/// these commands' `--format json` output is a document of the CLI's own — the
/// build projection, the detailed library check, the listing, the inspection,
/// the DSL catalog — so it is emitted bare: no `op` tag claiming a
/// `response_schema` it does not satisfy, and no `ok`. The commands that need a
/// main or a host fact (`doctor`, `execution-provider`, `explain`, `report`,
/// `timeline`, `diff`, `usage`, the installs) emit through the same
/// `emit_record` and are not run here; what keeps them bare is
/// `the_cli_builds_an_envelope_only_in_emit_ok_and_the_mcp_binding`: `emit_ok`
/// accepts only a sealed contract response type, and no other CLI source may
/// build an `OpEnvelope`.
///
/// **Would red if:** any of them were enveloped again (watched at the base:
/// every one carried `op: check`).
#[test]
fn json_documents_that_answer_no_operation_carry_no_envelope() {
    for args in [
        vec!["--format", "json", "build", BUNDLED_WORKFLOW],
        vec!["--format", "json", "workflows", "check", BUNDLED_WORKFLOW],
        vec!["--format", "json", "workflows", "list"],
        vec!["--format", "json", "workflows", "inspect", BUNDLED_WORKFLOW],
        vec!["--format", "json", "workflows", "schema"],
    ] {
        let output = run(&args);
        assert!(
            output.status.success(),
            "{args:?} exits 0; stderr: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let value = parse_stdout_json(&output);
        assert!(value.is_object(), "{args:?} emits one JSON document");
        assert!(
            value.get("op").is_none() && value.get("ok").is_none(),
            "{args:?} is no operation's response, so it carries no envelope: {}",
            serde_json::to_string(&value)
                .unwrap()
                .chars()
                .take(300)
                .collect::<String>()
        );
    }
}

/// **The CLI builds an `OpEnvelope` in exactly two files.** `cli/output.rs`'s
/// `emit_ok` envelopes only a sealed `OpResponse` under its own `OP`, and
/// `cli/mcp.rs` envelopes a dispatch's value under the operation it dispatched.
/// Every other `--format json` document goes through `emit_record` bare, and
/// `OpEnvelope::ok` takes any tag and any payload, so a re-tag elsewhere
/// (`emit_record(&OpEnvelope::ok(Operation::Observe, &report))`) compiles; this
/// scan is what refuses it.
///
/// Refused set: a non-comment line of any `.rs` file under `bin/kata/src`, other
/// than those two, that names `OpEnvelope` (a call, a struct literal, a `use`,
/// an alias) or glob-imports `kata_op_contract`. Not refused: a hand-written
/// `json!` object spelling an envelope's fields.
///
/// **Would red if:** `run_usage_cmd` or `workflows_check_one`'s detail arm
/// were re-enveloped through `OpEnvelope::ok` (watched red with exactly that).
#[test]
fn the_cli_builds_an_envelope_only_in_emit_ok_and_the_mcp_binding() {
    fn visit(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
        for entry in std::fs::read_dir(dir).expect("read bin/kata/src") {
            let path = entry.expect("dir entry").path();
            if path.is_dir() {
                visit(&path, out);
            } else if path.extension().is_some_and(|extension| extension == "rs") {
                out.push(path);
            }
        }
    }

    let src = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let allowed = [src.join("cli/mcp.rs"), src.join("cli/output.rs")];
    let mut files = Vec::new();
    visit(&src, &mut files);
    assert!(
        files.len() > 50 && allowed.iter().all(|path| files.contains(path)),
        "the scan walked the CLI's sources ({} files)",
        files.len()
    );

    let mut offenders = Vec::new();
    for file in files.iter().filter(|file| !allowed.contains(file)) {
        let text = std::fs::read_to_string(file).expect("read a CLI source");
        for (index, line) in text.lines().enumerate() {
            if line.trim_start().starts_with("//") {
                continue;
            }
            if line.contains("OpEnvelope") || line.contains("kata_op_contract::*") {
                offenders.push(format!("{}:{}: {}", file.display(), index + 1, line.trim()));
            }
        }
    }
    assert!(
        offenders.is_empty(),
        "an `OpEnvelope` built outside `emit_ok` and the MCP binding can tag a document \
         with an operation it does not answer; emit it bare through `emit_record`:\n{}",
        offenders.join("\n")
    );
}

/// **A workflow that does not compile is `usage` (exit 2) on the CLI's check
/// faces**, the class the MCP and REST `check` give the same file: the caller
/// owns the fix. `kata check`, its `--format json` envelope face, and the
/// detailed `kata workflows check` all classify it. A file that compiles but
/// that the verifier rejects is a different case (`workflow check failed`) and
/// is not judged here.
///
/// **Would red if:** the compile failure propagated as an untyped error again
/// (watched at the lane base: every face exited 1).
#[test]
fn a_workflow_that_does_not_compile_is_a_usage_error_on_every_cli_check_face() {
    let dir = tempfile::tempdir().expect("temp dir");
    let broken = dir.path().join("broken.star");
    std::fs::write(&broken, "workflow(\"broken\", root = [\n").expect("write broken pack");
    let broken = broken.to_str().expect("utf-8 path");
    for args in [
        vec!["check", broken],
        vec!["--format", "json", "check", broken],
        vec!["workflows", "check", broken],
    ] {
        let output = run(&args);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert_eq!(
            output.status.code(),
            Some(2),
            "{args:?}: a workflow that does not compile is the caller's to fix (usage, exit 2); \
             stderr: {stderr}"
        );
        assert!(
            stderr.contains("broken.star"),
            "{args:?}: the refusal names the file; stderr: {stderr}"
        );
    }
}

/// **`kata events --exit-on` refuses `--status` by name.** The wait pushes its own
/// `--exit-on` set down as the server-side status filter, so a `--status` beside it
/// was silently dropped. The combination is refused at parse — clap's usage exit, 2 —
/// naming both flags, before any main is asked: the endpoint here accepts no
/// connection, so a command that got past parse would fail on attachment instead.
/// `--status` alone and `--exit-on` alone each still get past parse to that attachment.
///
/// **Would red if:** the combination parsed again (the attachment failure's exit, not 2).
#[test]
fn events_refuses_exit_on_with_status_by_name() {
    let home = tempfile::tempdir().expect("an empty HOME");
    let events = |args: &[&str]| {
        kata()
            .args(["--api-url", "http://127.0.0.1:9", "events"])
            .args(args)
            .env("HOME", home.path())
            .env_remove("KATA_API_URL")
            .env_remove("KATA_API_TOKEN")
            .output()
            .expect("spawn kata binary under test")
    };
    let refused = events(&["--exit-on", "completed", "--status", "failed"]);
    let stderr = String::from_utf8_lossy(&refused.stderr);
    assert_eq!(refused.status.code(), Some(2), "usage exit: {stderr}");
    assert!(
        stderr.contains("--exit-on") && stderr.contains("--status"),
        "the refusal names both flags: {stderr}"
    );
    for alone in [&["--exit-on", "completed"][..], &["--status", "failed"][..]] {
        let output = events(alone);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert_ne!(output.status.code(), Some(2), "{alone:?} parses: {stderr}");
        assert!(
            !stderr.contains("cannot be used with"),
            "{alone:?} is not refused at parse: {stderr}"
        );
    }
}
