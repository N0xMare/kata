//! The shipped `change` pack (`workflows/std/change.star`), end to end on a
//! REAL node: the `agent_change_rig` node (an installed `kata serve` main, an
//! external `kata-worker` holding the rootless-youki route, a jj-colocated
//! git fixture with a LOCAL bare `origin` and a fake `gh` on the main's
//! `PATH`), `nanocode_openai` against a scripted mock model (`mock_model`) as
//! `[agents.default]` — no model budget, every tool call the mock asks for running
//! inside the turn's real container — and the ordinary client path (`kata run
//! --param … --submit`, `kata approvals`, `kata run approve`).
//!
//! # The cells
//!
//! * **The PR** (`the_change_pack_fixes_its_failing_edit_and_opens_one_pr_live`):
//!   plan → implement → test fails (with hostile output) → implement fixes →
//!   test passes → approve → commit → promote → export. Asserted from git,
//!   the bare remote, a fresh clone and the fake `gh`'s record: D2 §5.3's PR
//!   cell, L3a's tip assertion included.
//! * **The PR into a `master` trunk** (`the_change_pack_opens_its_pr_into_a_master_trunk_live`):
//!   the same pack on a repository whose only branch is `master`; the PR's
//!   base is `master`, `kata/<exec>` reaches the remote `master` tracks, and
//!   no `main` exists anywhere — D2 §6 L3(a), live.
//! * **The exhaustion park** (`an_exhausted_change_parks_its_last_candidate_and_lands_nothing_live`):
//!   the tests never pass; the loop exhausts under `accept`, the route takes
//!   `park_unfinished`, `parked/<exec>` holds the LAST iteration's tree, and
//!   nothing lands or is pushed.
//! * **The unjudged closeout park** (`a_loop_bound_that_trips_before_any_test_parks_the_candidate_at_closeout_live`):
//!   the shipped pack with a 1 ms per-loop bound spliced in trips on
//!   iteration 0's `implement`, before any test report; nothing routes, the
//!   run completes, and the closeout parks the candidate at `parked/<exec>`.
//! * **The operator promote onto a renamed trunk** (`an_operator_promote_onto_a_renamed_trunk_is_a_conflict_on_every_face_live`):
//!   a completed run's live candidate, the node's `[vcs] trunk` renamed and
//!   the main restarted; `kata run promote`, `POST …/promote` and the
//!   `promote` op each refuse `target_trunk_renamed` as a conflict, and no
//!   branch moves.
//! * **The mismatch refusal** (`a_byte_written_into_the_parked_candidate_refuses_the_commit_live`):
//!   while the run is parked at `approve`, one byte is written into the
//!   execution workspace on disk; the approve then reaches `commit`, which
//!   refuses `oci_candidate_disk_diverged`, and nothing is committed, landed,
//!   pushed or opened.
//!
//! Nothing here calls kata's internals: every pass criterion is read from
//! git, the filesystem, the fake `gh`'s log or `operational.db` through a
//! second read-only handle.
//!
//! # Host preconditions
//!
//! The sibling `agent_change_live` lane's: `--ignore`d so a host that cannot
//! prove containment fails the lane by name rather than skipping it.
//! `oci-live-smoke` selects this binary.

#![cfg(target_os = "linux")]
mod agent_change_rig;
#[allow(dead_code)]
mod mock_model;
#[path = "../../../crates/agent-nanocode/tests/fixtures/mock_provider.rs"]
#[allow(dead_code)]
mod mock_provider;

use agent_change_rig::nanocode::Harness;
use agent_change_rig::*;
use mock_model::{MockAgent, MockModel, Turn, change_pack_turn, is_plan, mock_node_on};
use std::path::{Path, PathBuf};

/// The shipped pack every cell runs, by path.
const CHANGE_PACK: &str = "workflows/std/change.star";

/// The agent label the pack selects (`agent = "default"` on `plan` and
/// `implement`).
const AGENT: &str = "default";

/// The run's params: the task text both agent prompts render, and the test
/// command `test` runs through `shquote`.
const PARAMS: [(&str, &str); 2] = [
    (
        "task",
        "Make src/app.txt contain exactly the line implemented-change.",
    ),
    ("test_command", "sh tests/check.sh"),
];

/// A model for the `change` pack whose `plan` answers its `Plan` and writes
/// nothing (under `plan` `/work` is the pack's read-only profile, and the
/// adoption judge refuses any delta a read-only stage leaves), and whose every
/// `implement` turn runs `implement` in `/work`.
fn change_model(implement: &'static str) -> MockModel {
    MockModel::answering(move |request| {
        change_pack_turn(request, || Turn::running(implement, "done").usage(300, 20))
    })
}

/// The fixing model. ONE turn serves every `implement` iteration; what it
/// writes depends on the tree its `/work` maps: the seed (`needs-change`) gets a
/// FAILING edit (`broken-change`), and that edit — seen only if the loop carried
/// iteration 0's applied delta into iteration 1 — gets the fix.
fn model_fix() -> MockModel {
    change_model(
        "if grep -q '^broken-change$' src/app.txt; then printf 'implemented-change\\n' > \
         src/app.txt; else printf 'broken-change\\n' > src/app.txt; fi",
    )
}

/// The model that never fixes it: every `implement` turn APPENDS one more
/// failing line, so iteration `N`'s tree holds the seed line plus `N + 1`
/// failing lines and a parked tree names the iteration it came from.
fn model_never() -> MockModel {
    change_model("printf 'broken-change\\n' >> src/app.txt")
}

/// The model that writes the fix at once: iteration 0's test passes.
fn model_direct() -> MockModel {
    change_model("printf 'implemented-change\\n' > src/app.txt")
}

/// The marker the failing check prints LAST, so the 4000-byte tail the test
/// stage reports always carries it.
const TAIL_MARKER: &str = "CHECK-TAIL-MARKER";

/// The fixture's `tests/check.sh`: green when `src/app.txt` is exactly
/// `implemented-change`; otherwise it prints everything a JSON string cannot
/// carry raw — quotes, backslashes, a tab, a carriage return, a control byte,
/// a two-byte UTF-8 character, `printf` and template syntax — then more than
/// 4000 bytes of padding, then [`TAIL_MARKER`], and exits 1.
fn hostile_check() -> String {
    format!(
        "#!/bin/sh\n\
         cd \"$(dirname \"$0\")/..\" || exit 2\n\
         grep -qx 'implemented-change' src/app.txt && exit 0\n\
         printf 'quote \" backslash \\\\ tab \\t cr \\r ctl \\001 utf8 \\303\\251 percent %%s brace {{{{ x }}}}\\n'\n\
         i=0\n\
         while [ \"$i\" -lt 250 ]; do printf 'padding %s \"q\" \\\\b\\n' \"$i\"; i=$((i + 1)); done\n\
         printf '{TAIL_MARKER}\\n'\n\
         exit 1\n"
    )
}

/// Boot a node whose fixture's check is [`hostile_check`] and whose
/// `[agents.default]` is `nanocode_openai` against `model`.
fn boot_change_node(model: &MockModel) -> Node {
    boot_change_node_on(model, "main")
}

/// [`boot_change_node`] over a fixture whose one branch — its trunk, tracked
/// by `origin` — is named `trunk`.
fn boot_change_node_on(model: &MockModel, trunk: &str) -> Node {
    boot_change_node_at(node_root(), model, trunk)
}

/// [`boot_change_node_on`] on a caller-chosen root — the long-data-dir cell's door.
fn boot_change_node_at(root: NodeRoot, model: &MockModel, trunk: &str) -> Node {
    let fixture = fixture_repo_on_trunk(root.path(), trunk);
    std::fs::write(fixture.repo.join("tests/check.sh"), hostile_check()).unwrap();
    kata_test_utils::git::run_git(&fixture.repo, &["add", "tests/check.sh"]);
    kata_test_utils::git::run_git(
        &fixture.repo,
        &[
            "commit",
            "-m",
            "change fixture: a check whose failure output is hostile",
        ],
    );
    kata_test_utils::git::run_git(&fixture.repo, &["push", "origin", trunk]);
    mock_node_on(
        root,
        fixture,
        model,
        &[MockAgent::openai(AGENT)],
        "change-e2e",
        &[],
    )
}

/// A shell stage whose capsule is an `Egress` one: `net = "host"` over the
/// node's `egress_allow`, which [`allow_egress`] declares. Its command dials
/// nothing; what it exercises is the egress plumbing every such capsule's
/// container is created with (the worker's handoff socket, connected by
/// `kata-oci-hook` inside the guest's network namespace).
const EGRESS_PROBE_PACK: &str = r#"
probe = stage(id = "probe", agent = "shell", run = "true", sandbox = "reach")
workflow(
    "egress-probe",
    root = [probe],
    worktree_isolated = True,
    sandbox_profiles = {"reach": sandbox_profile(workspace = "ro", net = "host")},
)
"#;

/// Declare `[node] egress_allow = ["127.0.0.1:9"]` (the discard port, never
/// dialled) on `node`'s config and restart its main and worker on it, so a
/// `net = "host"` stage's capsule is an `Egress` capsule over that one
/// authority. Nanocode's own capsules stay `Offline`: the model's calls leave
/// from the worker.
fn allow_egress(node: &mut Node) {
    let text = std::fs::read_to_string(&node.config).unwrap();
    let declared = text.replacen("[node]\n", "[node]\negress_allow = [\"127.0.0.1:9\"]\n", 1);
    assert_ne!(declared, text, "{TEST}: the config has a `[node]` table");
    std::fs::write(&node.config, declared).unwrap();
    node.main.kill();
    node.restart_main();
    node.restart_worker();
}

/// Every accepted `test` report of the run, in chain order, as the parsed
/// JSON object the stage reported — read off the raw accepting transitions.
fn test_reports(node: &Node, execution: &str) -> Vec<serde_json::Value> {
    let conn = raw_db(&node.root_path.join("data"));
    let payloads: Vec<String> = conn
        .prepare(
            "SELECT CAST(t.payload_json AS TEXT) FROM transitions t \
             JOIN attempts a ON a.attempt_id = t.attempt_id \
             WHERE t.execution_id = ?1 AND a.stage_id = 'test' \
             AND t.resulting_state = 'completed' ORDER BY t.seq",
        )
        .unwrap()
        .query_map(
            [ulid::Ulid::from_string(execution).unwrap().to_bytes()],
            |row| row.get(0),
        )
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    payloads
        .iter()
        .map(|payload| {
            let payload: serde_json::Value = serde_json::from_str(payload).unwrap();
            let output = &payload["output"];
            if output["parsed"].is_object() {
                return output["parsed"].clone();
            }
            let content = output["content"]
                .as_str()
                .unwrap_or_else(|| panic!("{TEST}: a test output with no content: {payload}"));
            // The report is the content's last JSON line — the `printf`.
            content
                .lines()
                .rev()
                .find_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
                .unwrap_or_else(|| panic!("{TEST}: the test content is not a report: {content}"))
        })
        .collect()
}

/// The execution workspace's directory on disk: `<repo>/agents/<exec>`, the
/// jj provider's layout. Asserted to exist — the positive control a write
/// into it needs.
fn execution_workspace(node: &Node, execution: &str) -> PathBuf {
    let path = node.fixture.repo.join("agents").join(execution);
    assert!(
        path.join("src/app.txt").is_file(),
        "{TEST}: the execution workspace is not at {}",
        path.display()
    );
    path
}

fn git_out(repo: &Path, args: &[&str]) -> String {
    let out = kata_test_utils::git::hermetic_git_in(repo)
        .args(args)
        .output()
        .expect("git runs");
    assert!(
        out.status.success(),
        "git {args:?} failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).trim().to_owned()
}

/// **The PR.** D2 §5.3's PR cell on the mock model: the loop refines once
/// (iteration 0's test fails with hostile output, iteration 1's passes), the
/// operator approves, and the committed commit lands on trunk and is pushed
/// and opened as ONE pull request into the trunk the run froze (the fixture's
/// `main`; no pack text names it).
///
/// From OUTSIDE kata:
/// - trunk's tip `C` carries the commit effect's subject, `C^` is trunk
///   before the run, and `C`'s tree differs from `C^`'s (the tip is not the
///   empty child `commit` leaves — L3a);
/// - the bare remote's `kata/<exec>` is `C`, and the fake `gh` recorded
///   exactly one `pr create` with `--base main` and `--head kata/<exec>`;
/// - a fresh clone of the bare remote, checked out at `C`, passes
///   `sh tests/check.sh`;
/// - the raw expansion record is `approved` with verdicts `failed, passed`
///   (one refine), and iteration 0's raw `failed` report carries a feedback
///   that is a JSON string with no `"`, no `\` and no byte outside printable
///   ASCII, ending in the check's last line (G6);
/// - the parked gate, read through `kata approvals`, shows the run's frozen
///   target (equal to the stored invocation's, its head trunk before the run)
///   and its two params (G9);
/// - the mock's own log of the `plan` request carries the `Plan` contract as its
///   strict output schema (`text.format`);
/// - and the shared end state (`assert_final_state`).
#[test]
#[ignore = "live end-to-end smoke; KATA_SANDBOX_REQUIRE_LIVE=1 just oci-live-smoke"]
fn the_change_pack_fixes_its_failing_edit_and_opens_one_pr_live() {
    let model = model_fix();
    the_pr_cell(&boot_change_node(&model), &model);
}

/// **The PR under a 200-byte data directory.** The same cell, every assertion
/// included, on a node whose `[node] data_dir` is at least 200 bytes, and then
/// an `Egress` capsule on the same node: the main's `worker.sock` (`data_dir` +
/// 12) and every `Egress` capsule's `handoff.sock` (`data_dir` + 73, bound by
/// the worker and connected by `kata-oci-hook` inside the guest's network
/// namespace) are both past the kernel's 108-byte `sun_path`, so the runs
/// complete only because both ends address their sockets through a descriptor on
/// the socket's directory. The `change` pack's own capsules are `Offline`, so
/// the handoff is exercised by [`EGRESS_PROBE_PACK`]'s shell stage.
///
/// Watched red one end at a time, each mutation alone: `kata-oci-hook`'s
/// `connect_through_parent` connecting the real path fails the run with `the
/// egress handoff never arrived at the worker's endpoint`;
/// `UnixSocketAddress::resolve` handing out the real path stops the main at
/// `binding local worker capacity at …/worker.sock … path must be shorter than
/// SUN_LEN`; and `egress_handoff::Receiver::bind` binding the real path refuses
/// the turn `plan_refused`, naming the handoff endpoint.
#[test]
#[ignore = "live end-to-end smoke; KATA_SANDBOX_REQUIRE_LIVE=1 just oci-live-smoke"]
fn the_change_pack_opens_its_pr_under_a_200_byte_data_dir_live() {
    let model = model_fix();
    let mut node = boot_change_node_at(long_node_root(200), &model, "main");
    let data_dir = node.root_path.join("data");
    assert!(
        data_dir.as_os_str().len() >= 200,
        "{TEST}: the cell's premise — a data_dir of {} bytes",
        data_dir.as_os_str().len()
    );
    the_pr_cell(&node, &model);

    allow_egress(&mut node);
    let pack = node.root_path.join("egress-probe.star");
    std::fs::write(&pack, EGRESS_PROBE_PACK).unwrap();
    let execution = node.main.submit(&pack);
    let doc = node.main.wait_terminal(&execution);
    assert_eq!(
        doc["status"].as_str(),
        Some("completed"),
        "{TEST}: the Egress capsule's handoff crossed the long data_dir: {doc}"
    );
}

/// One plain HTTP/1.1 GET against the main's API, read without kata's client.
fn http_get(url: &str, path: &str) -> String {
    use std::io::{Read, Write};
    let authority = url
        .strip_prefix("http://")
        .expect("the main's URL is http://");
    let mut stream = std::net::TcpStream::connect(authority).expect("the API accepts");
    write!(
        stream,
        "GET {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n"
    )
    .expect("the request writes");
    let mut response = String::new();
    stream
        .read_to_string(&mut response)
        .expect("the response reads");
    response
}

/// **A capsule's pre-container refusal carries its REASON on every face.** The
/// worker is respawned on a provider entry with no `toolhost/kata-toolhost`
/// member, so the change pack's first agent turn (a nanocode capsule, whose init
/// is the tool host) is refused `toolhost_unavailable` before its container
/// exists, naming what the entry cannot supply.
/// That text — not the label alone — is read from:
/// - the stored record, through a second read-only handle on `operational.db`
///   (the worker's failure in `event_inbox` and the execution's
///   `terminal_reason_json`; the `transitions` row is read host-free by
///   `agent_turn_capsule::a_plan_refused_launch_reaches_the_durable_record_with_its_reason`);
/// - `kata run show` (the CLI face);
/// - `kata watch <exec>`'s terminal snapshot (the observe stream);
/// - `GET /api/v1/executions/<exec>` over a bare TCP socket (the API face).
///
/// Watched red with `refusal_for_failed_launch`'s pre-acceptance arm formatting
/// only the label: the stored `terminal_reason_json` read `...before the container
/// was assigned: provider_unresolved` and nothing else.
#[test]
#[ignore = "live end-to-end smoke; KATA_SANDBOX_REQUIRE_LIVE=1 just oci-live-smoke"]
fn a_pre_container_refusal_carries_its_reason_on_every_face_live() {
    const REASON: &str = "cannot supply a nanocode agent capsule's tool host";
    let model = model_fix();
    let mut node = boot_change_node(&model);
    node.worker.kill();
    let mut env = provision_provider_without_toolhost(&node.root_path);
    env.extend(Harness::OpenaiMock.worker_env(Some(&model.url(Harness::OpenaiMock))));
    node.worker_spec.env = env;
    node.restart_worker();

    let execution = node
        .main
        .submit_with_params(Path::new(CHANGE_PACK), &PARAMS);
    let doc = node.main.wait_terminal(&execution);
    assert_eq!(doc["status"].as_str(), Some("failed"), "{TEST}: {doc}");

    // The stored record, through a second read-only handle.
    let raw = raw_db(&node.root_path.join("data"));
    let id = ulid::Ulid::from_string(&execution).unwrap().to_bytes();
    let terminal: String = raw
        .query_row(
            "SELECT CAST(terminal_reason_json AS TEXT) FROM execution_lifecycle \
             WHERE execution_id = ?1",
            [id],
            |row| row.get(0),
        )
        .expect("the execution's terminal reason");
    let failures: Vec<String> = raw
        .prepare("SELECT CAST(payload_json AS TEXT) FROM event_inbox")
        .unwrap()
        .query_map([], |row| row.get(0))
        .unwrap()
        .map(Result::unwrap)
        .filter(|payload: &String| payload.contains("worker_failure"))
        .collect();
    assert!(
        !failures.is_empty(),
        "{TEST}: the worker's failure is stored"
    );
    for (face, text) in std::iter::once(("terminal_reason_json", terminal.clone())).chain(
        failures
            .iter()
            .map(|f| ("event_inbox worker_failure", f.clone())),
    ) {
        assert!(
            text.contains("toolhost_unavailable") && text.contains(REASON),
            "{TEST}: the stored {face} carries the reason: {text}"
        );
    }

    // `kata run show` — the CLI face of the execution view.
    let shown = kata()
        .args(["--api-url", &node.main.url, "run", "show", &execution])
        .output()
        .expect("kata run show runs");
    let shown = String::from_utf8_lossy(&shown.stdout).into_owned();
    assert!(shown.contains(REASON), "{TEST}: kata run show: {shown}");

    // `kata watch` — the observe stream's terminal snapshot.
    let watched = kata()
        .args(["--api-url", &node.main.url, "watch", &execution])
        .output()
        .expect("kata watch runs");
    let watched = String::from_utf8_lossy(&watched.stdout).into_owned();
    let snapshot = watched
        .lines()
        .rev()
        .find_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
        .unwrap_or_else(|| panic!("{TEST}: kata watch printed no snapshot: {watched}"));
    let watched_error = snapshot["execution"]["error"].as_str().unwrap_or_default();
    assert!(
        watched_error.contains(REASON),
        "{TEST}: kata watch's snapshot error: {snapshot}"
    );

    // The API execution view, read over a bare socket.
    let api = http_get(&node.main.url, &format!("/api/v1/executions/{execution}"));
    assert!(api.starts_with("HTTP/1.1 200"), "{TEST}: {api}");
    assert!(
        api.contains(REASON),
        "{TEST}: the API execution view: {api}"
    );
}

/// The `kata-oci-hook` stand-in `a_hook_that_never_hands_its_listener_is_recorded_as_what_the_worker_saw_live`
/// provisions: `loopback-up` does what the built hook does (`<ip> link set lo
/// up`), and `hand-listener` exits non-zero WITHOUT connecting the handoff
/// socket — the shape of a hook whose connect failed.
const HOOK_THAT_NEVER_CONNECTS: &str = "#!/bin/sh\n\
case \"$1\" in\n\
  loopback-up) exec \"$3\" link set lo up ;;\n\
  hand-listener) echo 'kata-oci-hook stand-in: the handoff socket is never connected' >&2; exit 2 ;;\n\
esac\n\
exit 2\n";

/// **A hook that never hands its listener over is recorded as what the worker
/// saw, never as a hook still waiting.** The node declares an `egress_allow`
/// and the worker is respawned on a provider entry whose `kata-oci-hook` member
/// exits non-zero at `hand-listener` without connecting the handoff socket, so
/// [`EGRESS_PROBE_PACK`]'s `Egress` capsule is accepted and then refused
/// `egress_listener_unavailable` after the worker's handoff budget. The stored
/// record, read through a second read-only handle on
/// `operational.db` (the execution's `terminal_reason_json` and the worker's
/// failure in `event_inbox`), carries the worker's own observation — no fd
/// arrived, so it never sent the ack — and nowhere claims the hook is still
/// waiting: this hook had exited.
///
/// Watched red, in its earlier vendor-egress form, with
/// `HandoffRefusal::TimedOut`'s former text (`…; the hook is still waiting on the
/// ack, so the create cannot have completed`).
#[test]
#[ignore = "live end-to-end smoke; KATA_SANDBOX_REQUIRE_LIVE=1 just oci-live-smoke"]
fn a_hook_that_never_hands_its_listener_is_recorded_as_what_the_worker_saw_live() {
    const OBSERVED: &str = "no listener fd arrived within 30s, so the worker never sent the ack";
    let model = model_fix();
    let mut node = boot_change_node(&model);
    allow_egress(&mut node);
    node.worker.kill();
    node.worker_spec.env =
        provision_provider_with_hook_stand_in(&node.root_path, HOOK_THAT_NEVER_CONNECTS);
    node.restart_worker();

    let pack = node.root_path.join("egress-probe.star");
    std::fs::write(&pack, EGRESS_PROBE_PACK).unwrap();
    let execution = node.main.submit(&pack);
    let doc = node.main.wait_terminal(&execution);
    assert_eq!(doc["status"].as_str(), Some("failed"), "{TEST}: {doc}");

    let raw = raw_db(&node.root_path.join("data"));
    let id = ulid::Ulid::from_string(&execution).unwrap().to_bytes();
    let terminal: String = raw
        .query_row(
            "SELECT CAST(terminal_reason_json AS TEXT) FROM execution_lifecycle \
             WHERE execution_id = ?1",
            [id],
            |row| row.get(0),
        )
        .expect("the execution's terminal reason");
    let failures: Vec<String> = raw
        .prepare("SELECT CAST(payload_json AS TEXT) FROM event_inbox")
        .unwrap()
        .query_map([], |row| row.get(0))
        .unwrap()
        .map(Result::unwrap)
        .filter(|payload: &String| payload.contains("worker_failure"))
        .collect();
    assert!(
        !failures.is_empty(),
        "{TEST}: the worker's failure is stored"
    );
    for (face, text) in std::iter::once(("terminal_reason_json", terminal)).chain(
        failures
            .into_iter()
            .map(|failure| ("event_inbox worker_failure", failure)),
    ) {
        assert!(
            text.contains("egress_listener_unavailable") && text.contains(OBSERVED),
            "{TEST}: the stored {face} names what the worker observed: {text}"
        );
        assert!(
            !text.contains("still waiting"),
            "{TEST}: the stored {face} claims a hook that had exited is still waiting: {text}"
        );
    }
}

/// The PR cell's body, on any booted change node whose model is `model`.
fn the_pr_cell(node: &Node, model: &MockModel) {
    let trunk_before = git_rev(&node.fixture.repo, "main").expect("the seed trunk");
    let execution = node
        .main
        .submit_with_params(Path::new(CHANGE_PACK), &PARAMS);

    let gate = node
        .main
        .next_gate(&execution)
        .expect("the passed arm parks the approve gate");
    assert_eq!(gate["stage_name"].as_str(), Some("approve"));

    // G9: `kata approvals` shows the run's frozen target and its params beside
    // the gate — the target equal to the stored invocation's, read through a
    // second raw handle, and its head trunk before the run, read from git.
    let stored_target: String = raw_db(&node.root_path.join("data"))
        .query_row(
            "SELECT json_extract(CAST(invocation_json AS TEXT), '$.target') FROM invocations \
             WHERE execution_id = ?1",
            [ulid::Ulid::from_string(&execution).unwrap().to_bytes()],
            |row| row.get(0),
        )
        .expect("the stored invocation's target");
    let stored_target: serde_json::Value = serde_json::from_str(&stored_target).unwrap();
    assert_eq!(
        gate["target"], stored_target,
        "{TEST}: the gate shows the frozen target: {gate}"
    );
    assert_eq!(gate["target"]["branch"], "main", "{TEST}: {gate}");
    assert!(
        serde_json::to_string(&gate["target"])
            .unwrap()
            .contains(&trunk_before),
        "{TEST}: the frozen head is trunk before the run: {gate}"
    );
    assert_eq!(
        gate["params"],
        serde_json::json!([
            {"name": PARAMS[0].0, "value": PARAMS[0].1},
            {"name": PARAMS[1].0, "value": PARAMS[1].1},
        ]),
        "{TEST}: the gate shows the run's params: {gate}"
    );

    node.main.decide(&gate, None);
    let doc = node.main.wait_terminal(&execution);
    assert_eq!(
        doc["status"].as_str(),
        Some("completed"),
        "the change run completes: {doc}"
    );

    // ONE refine: iteration 0 failed, iteration 1 passed.
    let (outcome, verdicts) = loop_record(node, &execution);
    assert_eq!(outcome, "approved", "{TEST}: the loop approves");
    assert_eq!(
        verdicts,
        ["failed", "passed"],
        "{TEST}: iteration 0 failed its test and iteration 1 passed it"
    );

    // G6: iteration 0's failed report parsed as JSON, and its feedback is
    // printable ASCII without `"` or `\`, ending in the check's last line.
    let reports = test_reports(node, &execution);
    let failed = reports
        .iter()
        .find(|report| report["status"] == "failed")
        .unwrap_or_else(|| panic!("{TEST}: no failed test report: {reports:?}"));
    assert_eq!(failed["exit_code"], serde_json::json!(1), "{failed}");
    let feedback = failed["feedback"]
        .as_str()
        .unwrap_or_else(|| panic!("{TEST}: the failed report has no feedback: {failed}"));
    assert!(
        feedback
            .bytes()
            .all(|byte| (0x20..0x7f).contains(&byte) && byte != b'"' && byte != b'\\'),
        "{TEST}: the feedback carries a byte the sanitiser should have replaced: {feedback:?}"
    );
    assert!(
        feedback.trim_end().ends_with(TAIL_MARKER),
        "{TEST}: the feedback is the output's TAIL: {feedback:?}"
    );
    // The check printed more than 4000 bytes, so the tail is exactly 4000:
    // `tr` maps byte for byte, and the trailing newline became a space the
    // command substitution keeps.
    assert_eq!(
        feedback.len(),
        4000,
        "{TEST}: the feedback is the output's last 4000 bytes"
    );

    // D2 §5.3: trunk's tip, its parent, its tree.
    let tip = git_rev(&node.fixture.repo, "main").expect("trunk resolves");
    assert_eq!(
        git_out(&node.fixture.repo, &["log", "-1", "--format=%s", &tip]),
        format!("kata workspace_effect commit for execution {execution}"),
        "{TEST}: trunk's tip is the commit effect's commit"
    );
    assert_eq!(
        git_rev(&node.fixture.repo, &format!("{tip}^")).as_deref(),
        Some(trunk_before.as_str()),
        "{TEST}: the tip's parent is trunk before the run — one commit"
    );
    assert_ne!(
        git_rev(&node.fixture.repo, &format!("{tip}^{{tree}}")),
        git_rev(&node.fixture.repo, &format!("{tip}^^{{tree}}")),
        "{TEST}: the tip is not an empty commit"
    );
    assert_eq!(
        git_rev(
            &node.fixture.remote,
            &format!("refs/heads/kata/{execution}")
        )
        .as_deref(),
        Some(tip.as_str()),
        "{TEST}: the bare remote's kata/<exec> is trunk's tip"
    );

    // The fake forge: exactly one `pr create`, base main, head kata/<exec>.
    let gh = std::fs::read_to_string(&node.gh_log).unwrap_or_default();
    let creates: Vec<&str> = gh
        .lines()
        .filter(|line| line.split('|').nth(1) == Some("create"))
        .collect();
    assert_eq!(
        creates.len(),
        1,
        "{TEST}: exactly one `gh pr create`:\n{gh}"
    );
    let args: Vec<&str> = creates[0].split('|').collect();
    let flag = |name: &str| {
        args.iter()
            .position(|arg| *arg == name)
            .and_then(|at| args.get(at + 1).copied())
    };
    assert_eq!(flag("--base"), Some("main"), "{TEST}: {}", creates[0]);
    let head = format!("kata/{execution}");
    assert_eq!(
        flag("--head"),
        Some(head.as_str()),
        "{TEST}: {}",
        creates[0]
    );

    // A fresh clone of the remote, outside kata, at the tip: the tests pass.
    let clone = node.root_path.join("e2-clone");
    let cloned = kata_test_utils::git::hermetic_git_in(&node.root_path)
        .args(["clone", "-q"])
        .arg(&node.fixture.remote)
        .arg(&clone)
        .output()
        .expect("git clone runs");
    assert!(cloned.status.success(), "{TEST}: the fresh clone failed");
    git_out(&clone, &["checkout", "-q", &tip]);
    let check = std::process::Command::new("sh")
        .arg("tests/check.sh")
        .current_dir(&clone)
        .output()
        .expect("sh runs");
    assert!(
        check.status.success(),
        "{TEST}: the fresh clone's tests fail at the tip: {}",
        String::from_utf8_lossy(&check.stdout)
    );

    assert_eq!(
        attempt_count(node, &execution, "park_unfinished"),
        0,
        "{TEST}: the failed arm never ran"
    );

    // The `plan` turn's contract reached the model as its strict output schema:
    // the mock's own log of that request carries `text.format`, a strict JSON
    // schema whose properties are exactly the `Plan` contract's fields.
    let requests = model.requests();
    let plan = requests
        .iter()
        .find(|request| is_plan(request))
        .unwrap_or_else(|| panic!("{TEST}: the mock received no plan request"));
    let format = &plan["text"]["format"];
    assert_eq!(
        (&format["type"], &format["strict"]),
        (&serde_json::json!("json_schema"), &serde_json::json!(true)),
        "{TEST}: the plan request's output format: {format}"
    );
    let mut fields: Vec<&str> = format["schema"]["properties"]
        .as_object()
        .unwrap_or_else(|| panic!("{TEST}: the schema names no properties: {format}"))
        .keys()
        .map(String::as_str)
        .collect();
    fields.sort_unstable();
    assert_eq!(
        fields,
        ["files", "risks", "steps", "summary"],
        "{TEST}: the strict schema is the `Plan` contract's"
    );
    assert_final_state(node, &execution);
}

/// **The PR into a `master` trunk** (D2 §6 L3(a), live). The fixture's only
/// branch is `master`, tracked by `origin`; the model writes the fix at once,
/// the operator approves, and the run commits, lands on `master` and exports.
/// No pack text and no node config names a branch: the base is the trunk the
/// run froze, the remote the one that trunk tracks.
///
/// From OUTSIDE kata:
/// - the fake `gh` recorded exactly one `pr create`, with `--base master` and
///   `--head kata/<exec>`;
/// - the bare remote's `kata/<exec>` is `master`'s landed tip, and the
///   remote's `master` is still the seed (the export pushes only its branch);
/// - `main` exists neither in the repository nor in the remote;
/// - the export claim recorded the remote `origin` (raw `operational.db`
///   through a read-only handle), and the gate showed the frozen target
///   `master`;
/// - and the shared end state on the `master` trunk (`assert_final_state`).
#[test]
#[ignore = "live end-to-end smoke; KATA_SANDBOX_REQUIRE_LIVE=1 just oci-live-smoke"]
fn the_change_pack_opens_its_pr_into_a_master_trunk_live() {
    let model = model_direct();
    let node = boot_change_node_on(&model, "master");
    let seed = git_rev(&node.fixture.repo, "master").expect("the seed trunk");
    let execution = node
        .main
        .submit_with_params(Path::new(CHANGE_PACK), &PARAMS);
    let gate = node
        .main
        .next_gate(&execution)
        .expect("the passed arm parks the approve gate");
    assert_eq!(gate["stage_name"].as_str(), Some("approve"), "{gate}");
    assert_eq!(gate["target"]["branch"], "master", "{TEST}: {gate}");
    node.main.decide(&gate, None);
    let doc = node.main.wait_terminal(&execution);
    assert_eq!(
        doc["status"].as_str(),
        Some("completed"),
        "the change run completes: {doc}"
    );

    let gh = std::fs::read_to_string(&node.gh_log).unwrap_or_default();
    let creates: Vec<&str> = gh
        .lines()
        .filter(|line| line.split('|').nth(1) == Some("create"))
        .collect();
    assert_eq!(
        creates.len(),
        1,
        "{TEST}: exactly one `gh pr create`:\n{gh}"
    );
    let args: Vec<&str> = creates[0].split('|').collect();
    let flag = |name: &str| {
        args.iter()
            .position(|arg| *arg == name)
            .and_then(|at| args.get(at + 1).copied())
    };
    assert_eq!(flag("--base"), Some("master"), "{TEST}: {}", creates[0]);
    let head = format!("kata/{execution}");
    assert_eq!(
        flag("--head"),
        Some(head.as_str()),
        "{TEST}: {}",
        creates[0]
    );

    let tip = git_rev(&node.fixture.repo, "master").expect("master resolves");
    assert_ne!(tip, seed, "{TEST}: the run landed on master");
    assert_eq!(
        git_rev(&node.fixture.remote, &format!("refs/heads/{head}")).as_deref(),
        Some(tip.as_str()),
        "{TEST}: the remote master tracks holds kata/<exec> at the landed tip"
    );
    assert_eq!(
        git_rev(&node.fixture.remote, "refs/heads/master").as_deref(),
        Some(seed.as_str()),
        "{TEST}: the remote's master is untouched — the export pushes only its branch"
    );
    for repo in [&node.fixture.repo, &node.fixture.remote] {
        assert_eq!(
            git_rev(repo, "refs/heads/main"),
            None,
            "{TEST}: no main exists in {}",
            repo.display()
        );
    }
    let claimed_remote: String = raw_db(&node.root_path.join("data"))
        .query_row(
            "SELECT json_extract(CAST(assignment_json AS TEXT), '$.main.spec.forge_remote') \
             FROM attempts WHERE execution_id = ?1 AND stage_id = 'export'",
            [ulid::Ulid::from_string(&execution).unwrap().to_bytes()],
            |row| row.get(0),
        )
        .expect("the export claim's recorded remote");
    assert_eq!(
        claimed_remote, "origin",
        "{TEST}: the claim recorded the tracked remote"
    );
    assert_final_state(&node, &execution);
}

/// **The exhaustion park.** The model never fixes it: all four iterations'
/// tests fail, the loop exhausts under `on_exhaustion = "accept"`, and the
/// route reads the adopted last report — `park_unfinished` parks the
/// candidate and nothing lands.
///
/// From OUTSIDE kata: the raw record (`exhausted`, four `failed` verdicts);
/// `park_unfinished` resolved and `approve` never minted an attempt;
/// `parked/<exec>` is in git and its tree is the FOURTH iteration's (the seed
/// line plus four failing lines, computed by git plumbing); trunk, the bare
/// remote and the forge are untouched (`assert_no_mutation`).
#[test]
#[ignore = "live end-to-end smoke; KATA_SANDBOX_REQUIRE_LIVE=1 just oci-live-smoke"]
fn an_exhausted_change_parks_its_last_candidate_and_lands_nothing_live() {
    let model = model_never();
    let node = boot_change_node(&model);
    let seed = git_rev(&node.fixture.repo, "main").expect("the seed trunk");
    let execution = node
        .main
        .submit_with_params(Path::new(CHANGE_PACK), &PARAMS);
    let doc = node.main.wait_terminal(&execution);

    let (outcome, verdicts) = loop_record(&node, &execution);
    assert_eq!(outcome, "exhausted", "{TEST}: the loop exhausts: {doc}");
    assert_eq!(
        verdicts,
        ["failed", "failed", "failed", "failed"],
        "{TEST}: every one of the four iterations' tests failed"
    );
    assert_eq!(
        completed_transitions(&node, &execution, "park_unfinished", "main_resolved"),
        1,
        "{TEST}: the adopted last report routes the failed arm: {doc}"
    );
    assert_eq!(
        attempt_count(&node, &execution, "approve"),
        0,
        "{TEST}: the passed arm never ran"
    );
    assert_eq!(
        doc["status"].as_str(),
        Some("completed"),
        "an accepted exhaustion that parks completes the run: {doc}"
    );
    assert_no_mutation(&node, &execution);

    let parked = format!("parked/{execution}");
    let parked_rev = git_rev(&node.fixture.repo, &parked)
        .unwrap_or_else(|| panic!("{TEST}: no candidate parked under {parked}"));
    assert_eq!(
        tree_of(&node.fixture.repo, &parked_rev),
        tree_with(
            &node.fixture.repo,
            &seed,
            "src/app.txt",
            "needs-change\nbroken-change\nbroken-change\nbroken-change\nbroken-change\n",
        ),
        "{TEST}: the parked candidate is the fourth iteration's tree"
    );
}

/// **The mismatch refusal.** D2 §5.3's mismatch cell: the run passes its
/// tests and parks at `approve`; one byte is then written into the execution
/// workspace ON DISK, outside every capsule; the operator approves; `commit`
/// refuses the foreign edit by name, `oci_candidate_disk_diverged`, and the
/// run fails.
///
/// From OUTSIDE kata: the raw `commit` failure names the refusal; trunk is
/// unmoved, no `kata/<exec>` reached the bare remote, the fake `gh` ran
/// nothing, and no commit/promote/export effect resolved
/// (`assert_no_mutation`); the closeout's park refused the same foreign edit,
/// so no `parked/<exec>` exists and the workspace stands, foreign byte and
/// all, for inspection.
#[test]
#[ignore = "live end-to-end smoke; KATA_SANDBOX_REQUIRE_LIVE=1 just oci-live-smoke"]
fn a_byte_written_into_the_parked_candidate_refuses_the_commit_live() {
    let model = model_direct();
    let node = boot_change_node(&model);
    let execution = node
        .main
        .submit_with_params(Path::new(CHANGE_PACK), &PARAMS);
    let gate = node
        .main
        .next_gate(&execution)
        .expect("the passed arm parks the approve gate");
    assert_eq!(gate["stage_name"].as_str(), Some("approve"));

    let workspace = execution_workspace(&node, &execution);
    std::fs::write(workspace.join("foreign.txt"), "x").unwrap();

    node.main.decide(&gate, None);
    let doc = node.main.wait_terminal(&execution);
    assert_eq!(
        doc["status"].as_str(),
        Some("failed"),
        "a refused commit fails the run: {doc}"
    );

    let refusal: String = raw_db(&node.root_path.join("data"))
        .query_row(
            "SELECT CAST(payload_json AS TEXT) FROM transitions WHERE execution_id = ?1 \
             AND stage_id = 'commit' AND resulting_state = 'failed'",
            [ulid::Ulid::from_string(&execution).unwrap().to_bytes()],
            |row| row.get(0),
        )
        .expect("the commit effect's failed transition");
    assert!(
        refusal.contains("oci_candidate_disk_diverged"),
        "{TEST}: the commit is refused by name: {refusal}"
    );
    assert_no_mutation(&node, &execution);
    assert_eq!(
        git_rev(&node.fixture.repo, &format!("parked/{execution}")),
        None,
        "{TEST}: the closeout parks no candidate carrying a foreign edit"
    );
    assert_eq!(
        std::fs::read_to_string(workspace.join("foreign.txt"))
            .ok()
            .as_deref(),
        Some("x"),
        "{TEST}: the workspace stands with the foreign byte for inspection"
    );
}

/// **The unjudged closeout park.** The shipped pack with ONE change — a
/// `bounds = [time_bound(1)]` spliced into its `loop()` — so the per-loop
/// bound trips the moment iteration 0's `implement` is accepted, before any
/// test runs: the loop exhausts under `accept` with no report that judged
/// its candidate, so the route takes neither arm and the run completes. The
/// candidate is not left as a completed run's live workspace an operator
/// could promote: the closeout parks it.
///
/// From OUTSIDE kata: the raw record is `exhausted` at one iteration with no
/// verdict; `test`, `approve` and `park_unfinished` never minted an attempt;
/// `parked/<exec>` holds iteration 0's tree (the seed line plus one failing
/// line, computed by git plumbing); the execution workspace is gone from
/// disk; the raw `execution_evidence` records that parked candidate,
/// auto-parked; trunk, the bare remote and the fake `gh` are untouched.
#[test]
#[ignore = "live end-to-end smoke; KATA_SANDBOX_REQUIRE_LIVE=1 just oci-live-smoke"]
fn a_loop_bound_that_trips_before_any_test_parks_the_candidate_at_closeout_live() {
    let model = model_never();
    let node = boot_change_node(&model);
    let seed = git_rev(&node.fixture.repo, "main").expect("the seed trunk");
    let shipped = std::fs::read_to_string(repo_root().join(CHANGE_PACK)).unwrap();
    let bounded = shipped.replacen(
        "on_exhaustion = \"accept\",",
        "on_exhaustion = \"accept\",\n    bounds = [time_bound(1)],",
        1,
    );
    assert_ne!(
        bounded, shipped,
        "{TEST}: the bound is spliced into the loop"
    );
    let pack = node.root_path.join("change.star");
    std::fs::write(&pack, bounded).unwrap();
    let execution = node.main.submit_with_params(&pack, &PARAMS);
    let doc = node.main.wait_terminal(&execution);
    assert_eq!(
        doc["status"].as_str(),
        Some("completed"),
        "a report-less accepted exhaustion completes the run: {doc}"
    );

    let (outcome, verdicts) = loop_record(&node, &execution);
    assert_eq!(outcome, "exhausted", "{TEST}: the bound exhausts the loop");
    assert!(
        verdicts.is_empty(),
        "{TEST}: no test report was ever classified: {verdicts:?}"
    );
    for stage in ["test", "approve", "park_unfinished"] {
        assert_eq!(
            attempt_count(&node, &execution, stage),
            0,
            "{TEST}: {stage} never minted an attempt"
        );
    }
    assert_no_mutation(&node, &execution);

    let parked = format!("parked/{execution}");
    let parked_rev = git_rev(&node.fixture.repo, &parked)
        .unwrap_or_else(|| panic!("{TEST}: the closeout parked no candidate under {parked}"));
    assert_eq!(
        tree_of(&node.fixture.repo, &parked_rev),
        tree_with(
            &node.fixture.repo,
            &seed,
            "src/app.txt",
            "needs-change\nbroken-change\n",
        ),
        "{TEST}: the parked candidate is iteration 0's tree, the one the loop ended on"
    );
    assert!(
        !node.fixture.repo.join("agents").join(&execution).exists(),
        "{TEST}: the parked workspace is gone from disk"
    );
    let evidence: Vec<String> = raw_db(&node.root_path.join("data"))
        .prepare(
            "SELECT CAST(evidence_json AS TEXT) FROM execution_evidence WHERE execution_id = ?1",
        )
        .unwrap()
        .query_map(
            [ulid::Ulid::from_string(&execution).unwrap().to_bytes()],
            |row| row.get(0),
        )
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    assert!(
        evidence.iter().any(|row| {
            let row: serde_json::Value = serde_json::from_str(row).unwrap();
            row["evidence"]["parked_candidate"]["parked_ref"] == parked.as_str()
                && row["evidence"]["parked_candidate"]["commit_sha"] == parked_rev.as_str()
                && row["evidence"]["auto_parked"] == true
        }),
        "{TEST}: the raw evidence records the auto-parked candidate: {evidence:?}"
    );
}

/// A test pack whose run COMPLETES with a live, promotable candidate: a shell
/// `implement` writes the fixture's change into a writable `/work`, and a shell
/// `test` passes the required criterion. Nothing lands it — an operator
/// promote does.
const OPERATOR_PROMOTE_PACK: &str = r#"
_REPORT = contract("Report", {
    "status": field(enum("passed", "failed")),
    "criteria": field(list_of(contract("CriterionResult", {
        "criterion_id": field("string"),
        "status": field(enum("passed", "failed")),
        "evidence": field(list_of("string")),
    }))),
})

implement = stage(
    id = "implement",
    agent = "shell",
    sandbox = "edit",
    run = """printf 'implemented-change\n' > /work/src/app.txt
printf '{"edited": "src/app.txt"}\n'
""",
    outputs = {"edited": "string"},
)

test = stage(
    id = "test",
    agent = "shell",
    sandbox = "verify",
    depends_on = ["implement"],
    run = """RC=0
sh /work/tests/check.sh > /out/check.log 2>&1 || RC=$?
if [ "$RC" -eq 0 ]; then STATUS=passed; else STATUS=failed; fi
printf '{"status": "%s", "criteria": [{"criterion_id": "check", "status": "%s", "evidence": ["check.log"]}]}\n' "$STATUS" "$STATUS"
""",
    produces = _REPORT,
)

workflow(
    "operator-promote",
    root = [implement, test],
    worktree_isolated = True,
    validation_criteria = [validation_criterion(
        "check",
        stage = "test",
        commands = ["sh tests/check.sh"],
        evidence = ["check.log"],
        required = True,
        description = "The fixture's check passes on the candidate.",
    )],
    sandbox_profiles = {
        "edit": sandbox_profile(workspace = "rw", net = "offline"),
        "verify": sandbox_profile(workspace = "ro", net = "offline"),
    },
)
"#;

/// `curl -X POST <url>` with an optional JSON body: `(HTTP status, body)`.
fn post(url: &str, body: Option<&str>) -> (u16, String) {
    let mut command = std::process::Command::new("curl");
    command.args(["-sS", "-X", "POST", "-w", "\n%{http_code}"]);
    if let Some(body) = body {
        command.args(["-H", "content-type: application/json", "-d", body]);
    }
    let out = command.arg(url).output().expect("curl runs");
    let text = String::from_utf8_lossy(&out.stdout).into_owned();
    let (body, status) = text.rsplit_once('\n').expect("curl printed the status");
    (
        status.trim().parse().expect("an HTTP status"),
        body.to_owned(),
    )
}

/// **The operator promote onto a renamed trunk** (the coordinator's L8b
/// ruling and max review #1's deferred finding). A run completes with a live
/// candidate whose admission froze trunk `main`; the operator then names
/// `release` as the node's trunk (`[vcs] trunk`) and restarts the main. Every
/// operator promote face refuses by name, as a CONFLICT, and nothing moves:
/// - the CLI, `kata run promote`, exits nonzero naming `target_trunk_renamed`;
/// - REST, `POST /api/v1/executions/<id>/promote`, answers 409 naming it;
/// - the op face (`POST /api/v1/ops/promote`, the binding MCP shares) answers
///   an error envelope with code `conflict` naming it.
///
/// From OUTSIDE kata: `main` and `release` read back from git unchanged after
/// all three, the candidate's workspace still stands on disk, and no
/// `parked/<exec>` exists. The positive control: before the rename, the
/// workspace stands and trunk is the seed (nothing landed yet).
#[test]
#[ignore = "live end-to-end smoke; KATA_SANDBOX_REQUIRE_LIVE=1 just oci-live-smoke"]
fn an_operator_promote_onto_a_renamed_trunk_is_a_conflict_on_every_face_live() {
    let model = model_direct();
    let mut node = boot_change_node(&model);
    let pack = node.root_path.join("operator-promote.star");
    std::fs::write(&pack, OPERATOR_PROMOTE_PACK).unwrap();
    let execution = node.main.submit(&pack);
    let doc = node.main.wait_terminal(&execution);
    assert_eq!(
        doc["status"].as_str(),
        Some("completed"),
        "the run completes with a live candidate: {doc}"
    );
    let workspace = execution_workspace(&node, &execution);
    assert_eq!(
        git_rev(&node.fixture.repo, "main"),
        git_rev(&node.fixture.remote, "main"),
        "{TEST}: the positive control — nothing landed before the operator acts"
    );

    // The operator renames the node's trunk and restarts the main on the same
    // data directory; the restarted worker re-registers.
    kata_test_utils::git::run_git(&node.fixture.repo, &["branch", "release", "main"]);
    let config = std::fs::read_to_string(&node.config).unwrap();
    let renamed = config.replacen("[vcs]\n", "[vcs]\ntrunk = \"release\"\n", 1);
    assert_ne!(
        renamed, config,
        "{TEST}: the config names the renamed trunk"
    );
    std::fs::write(&node.config, renamed).unwrap();
    node.main.kill();
    node.restart_main();
    node.restart_worker();
    let main_before = git_rev(&node.fixture.repo, "main").unwrap();
    let release_before = git_rev(&node.fixture.repo, "release").unwrap();

    // CLI.
    let cli = kata()
        .args(["--api-url", &node.main.url, "run", "promote", &execution])
        .output()
        .expect("kata run promote runs");
    let cli_text = format!(
        "{}{}",
        String::from_utf8_lossy(&cli.stdout),
        String::from_utf8_lossy(&cli.stderr)
    );
    assert!(
        !cli.status.success() && cli_text.contains("target_trunk_renamed"),
        "{TEST}: `kata run promote` refuses by name: {cli_text}"
    );

    // REST.
    let (status, body) = post(
        &format!("{}/api/v1/executions/{execution}/promote", node.main.url),
        None,
    );
    assert_eq!(status, 409, "{TEST}: REST answers a conflict: {body}");
    assert!(body.contains("target_trunk_renamed"), "{TEST}: {body}");

    // The op face.
    let (status, body) = post(
        &format!("{}/api/v1/ops/promote", node.main.url),
        Some(&format!("{{\"execution_id\": \"{execution}\"}}")),
    );
    assert_eq!(
        status, 200,
        "{TEST}: the op face answers an envelope: {body}"
    );
    let envelope: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(
        envelope["error"]["code"], "conflict",
        "{TEST}: the op face's code is conflict: {envelope}"
    );
    assert!(
        envelope["error"]["message"]
            .as_str()
            .is_some_and(|message| message.contains("target_trunk_renamed")),
        "{TEST}: the op face names the refusal: {envelope}"
    );

    assert_eq!(
        git_rev(&node.fixture.repo, "main").as_deref(),
        Some(main_before.as_str()),
        "{TEST}: main never moved"
    );
    assert_eq!(
        git_rev(&node.fixture.repo, "release").as_deref(),
        Some(release_before.as_str()),
        "{TEST}: release never moved"
    );
    assert!(
        workspace.join("src/app.txt").is_file(),
        "{TEST}: the candidate's workspace stands"
    );
    assert_eq!(
        git_rev(&node.fixture.repo, &format!("parked/{execution}")),
        None,
        "{TEST}: nothing was parked"
    );
}
