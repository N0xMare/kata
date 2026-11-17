//! The deterministic, no-spend twins of N6's nanocode interruption cells
//! (`nanocode_live`), and the positive control of its re-prompt measurement: a
//! REAL node — a `kata serve` main, a `kata-worker` daemon over `local_socket`
//! or the node `kata serve` supervises, a real rootless capsule whose init is
//! the static `kata-toolhost` — running the shipped `agent-change` pack on a nanocode kind
//! whose model is a mock provider on the loopback, reached through the
//! worker's `test-support` endpoint door.
//!
//! A funded cell can only see that a model request is PROBABLY outstanding
//! (the capsule runs no tool, and the hosting process holds a connection to the
//! provider's `:443`, which a websocket also holds between calls). A twin's
//! mock records each request body in its OWN log the moment it is read and
//! never answers (`Reply::Stall`), so the kill lands with a request certainly
//! outstanding — the claim the funded cell cannot make.
//!
//! # What is read, and from where
//!
//! Every verdict is read OUTSIDE kata: the mock's own request log, the
//! capsule's cgroup off the kernel's hierarchy (`cgroup.procs` and each pid's
//! `comm`), the raw chain and attempt rows through a second read-only SQLite
//! handle on `operational.db`, the fixture's git refs and its bare remote, the
//! fake `gh`'s own log, and `/proc` for any live process of the run's
//! containers.
//!
//! # Host preconditions (a skip is a failure)
//!
//! The certified rootless-youki route every OCI live cell uses
//! (`just _containment-preconditions`), the busybox and `git-minimal` closures
//! realised in the host's Nix store, `kata-provider-youki` and `kata-oci-hook`
//! built, the static toolhost (`cargo build -p kata-toolhost --target
//! x86_64-unknown-linux-musl`), and a `test-support` build of `kata` and
//! `kata-worker` (the workspace test build), whose door line each cell reads
//! before it submits.

#![cfg(target_os = "linux")]

mod agent_change_rig;

#[path = "../../../crates/agent-nanocode/tests/fixtures/mock_provider.rs"]
#[allow(dead_code)]
mod mock_provider;

use std::path::Path;
use std::time::{Duration, Instant};

use agent_change_rig::nanocode::{
    Harness, SupervisedNodeMain, accepted_payload, assert_door_open,
    assert_restart_settled_ambiguous_never_redelivered, assert_unknown_charge,
    assert_unmetered_in_run, capsule_cgroup, cgroup_processes, nanocode_node, session_counts,
    stage_transitions, wait_for_live_capsule, wait_until_model_request_outstanding,
};
use agent_change_rig::{
    PACK, TEST, assert_no_container_residue, assert_no_mutation,
    assert_proven_ambiguous_never_redelivered, attempt_count, completed_transitions,
    live_kata_containers,
};
use mock_provider::{MockProvider, Reply};
use serde_json::json;

/// A mock provider served by a runtime of its own, so the blocking rig never
/// starves it.
struct Model {
    mock: MockProvider,
    _runtime: tokio::runtime::Runtime,
}

impl Model {
    fn start(script: Vec<Reply>) -> Self {
        let runtime = tokio::runtime::Runtime::new().expect("a runtime for the mock");
        let mock = runtime.block_on(MockProvider::start(script));
        Self {
            mock,
            _runtime: runtime,
        }
    }

    /// The URL `harness`'s door takes: the Responses base, or the Messages URL.
    fn url(&self, harness: Harness) -> String {
        match harness {
            Harness::AnthropicMock => format!("{}/messages", self.mock.url),
            _ => self.mock.url.clone(),
        }
    }

    /// The mock's own log, as a witness line once it holds `count` bodies.
    fn received(&self, count: usize) -> Vec<String> {
        let received = self.mock.requests().len();
        if received >= count {
            vec![format!("the mock logged {received} request body(ies)")]
        } else {
            Vec::new()
        }
    }
}

/// A raw transition's payload as JSON.
fn parsed(payload: &str) -> serde_json::Value {
    serde_json::from_str(payload).expect("a transition payload is JSON")
}

/// **A worker killed with a model request certainly outstanding settles
/// PROVEN AMBIGUOUS, is never re-delivered, and its request is never re-sent.**
/// The mock logs the turn's first request body and never answers; with that
/// body in its log and the capsule's cgroup holding only the toolhost (no
/// tool runs), the daemon worker is SIGKILLed. The raw failed transition names
/// the death and the ambiguity, a respawned worker claims nothing, the mock
/// received no second body, the attempt's charge is unknown, nothing landed,
/// and no container or `kata.*` cgroup of the node's workers survives.
fn worker_kill_with_a_request_outstanding(harness: Harness) {
    let model = Model::start(vec![Reply::Stall]);
    let mut node = nanocode_node(harness, "change-agent", Some(&model.url(harness)));
    assert_door_open(harness, "worker daemon", &node.worker.log);
    let data = node.root_path.join("data");
    let execution = node.main.submit(Path::new(PACK));
    let container = wait_for_live_capsule(&data, &execution, "implement");
    let capsule = capsule_cgroup(node.worker.pid, &container)
        .unwrap_or_else(|| panic!("{TEST}: no cgroup for {container} beneath the worker's scope"));
    let seen = wait_until_model_request_outstanding(&capsule, Duration::from_millis(500), || {
        model.received(1)
    });
    eprintln!(
        "POSITIVE CONTROL {}: outstanding {seen:?}",
        harness.adapter()
    );
    node.worker.kill();
    let doc = node.main.wait_terminal(&execution);
    assert_eq!(
        doc["status"].as_str(),
        Some("failed"),
        "{TEST}: the ambiguous attempt fails the run: {doc}"
    );
    let reason = assert_proven_ambiguous_never_redelivered(&mut node, &execution);
    eprintln!("SETTLED {}: {reason}", harness.adapter());
    assert_eq!(
        model.mock.requests().len(),
        1,
        "{TEST}: the mock's own log holds the one request body — never re-sent"
    );
    let charge = assert_unknown_charge(&parsed(&reason));
    eprintln!("CHARGE {}: {charge}", harness.adapter());
    assert_unmetered_in_run(&doc, "implement");
    assert_eq!(
        attempt_count(&node, &execution, "implement"),
        1,
        "{TEST}: no second implement attempt row"
    );
    assert_eq!(
        completed_transitions(&node, &execution, "implement", "event_accepted"),
        0,
        "{TEST}: no /work delta was accepted"
    );
    assert_no_mutation(&node, &execution);
    assert_no_container_residue(&node, &execution);
    eprintln!(
        "RUN SHOW {}: {}",
        harness.adapter(),
        serde_json::to_string(&doc).unwrap_or_default()
    );
}

/// [`worker_kill_with_a_request_outstanding`] on the Responses kind.
///
/// **Would red if:** the settle re-delivered the attempt (a second claim, a
/// second body in the mock's log), recorded the killed turn's spend as a
/// known figure, or the kill left the capsule running.
#[test]
#[ignore = "live end-to-end smoke; KATA_SANDBOX_REQUIRE_LIVE=1 just oci-live-smoke"]
fn a_worker_killed_with_a_responses_request_outstanding_settles_ambiguous_live() {
    worker_kill_with_a_request_outstanding(Harness::OpenaiMock);
}

/// [`worker_kill_with_a_request_outstanding`] on the Messages kind.
///
/// **Would red if:** as the Responses twin.
#[test]
#[ignore = "live end-to-end smoke; KATA_SANDBOX_REQUIRE_LIVE=1 just oci-live-smoke"]
fn a_worker_killed_with_a_messages_request_outstanding_settles_ambiguous_live() {
    worker_kill_with_a_request_outstanding(Harness::AnthropicMock);
}

/// **A main killed with its supervised node's model request certainly
/// outstanding settles on restart as PROVEN AMBIGUOUS, "the main restarted",
/// and is never re-claimed.** The worker lives in the node `kata serve`
/// supervises (`type = "supervised_node"`); the main's SIGKILL closes the
/// node's connection, which ends the node and, through its provider, the
/// capsule. The restarted main settles the attempt (`CAPSULE_MAIN_RESTARTED`,
/// which the worker-death settle never writes), claims nothing more after its
/// recovery window, the mock received no second body, the charge is unknown,
/// the capsule's cgroup empties, nothing landed (no `exec-<exec>`, trunk and
/// the remote unmoved, the fake `gh` silent, no commit/promote/export
/// resolved), and no container process or `kata.*` cgroup of either main's
/// node is left.
///
/// **Would red if:** the restart re-delivered the attempt, or settled it as
/// anything but ambiguous.
#[test]
#[ignore = "live end-to-end smoke; KATA_SANDBOX_REQUIRE_LIVE=1 just oci-live-smoke"]
fn a_main_killed_with_its_supervised_nodes_turn_outstanding_settles_ambiguous_on_restart_live() {
    let harness = Harness::OpenaiMock;
    let model = Model::start(vec![Reply::Stall]);
    let mut node = SupervisedNodeMain::boot(harness, "change-agent", Some(&model.url(harness)));
    assert_door_open(harness, "main", &node.main.log);
    let execution = node.main.submit(Path::new(PACK));
    let container = wait_for_live_capsule(&node.data, &execution, "implement");
    let capsule = capsule_cgroup(node.main.child.id(), &container)
        .unwrap_or_else(|| panic!("{TEST}: no cgroup for {container} beneath the main's scope"));
    let seen = wait_until_model_request_outstanding(&capsule, Duration::from_millis(500), || {
        model.received(1)
    });
    eprintln!("POSITIVE CONTROL supervised node: outstanding {seen:?}");
    node.kill_and_restart();
    let reason =
        assert_restart_settled_ambiguous_never_redelivered(&node.data, &execution, "implement");
    eprintln!("SETTLED supervised node: {reason}");
    let doc = node.main.wait_terminal(&execution);
    assert_eq!(
        doc["status"].as_str(),
        Some("failed"),
        "{TEST}: the ambiguous attempt fails the run: {doc}"
    );
    assert_eq!(
        model.mock.requests().len(),
        1,
        "{TEST}: the mock's own log holds the one request body — never re-sent"
    );
    assert_unknown_charge(&parsed(&reason));
    assert_unmetered_in_run(&doc, "implement");
    let deadline = Instant::now() + Duration::from_secs(30);
    while !cgroup_processes(&capsule).is_empty() {
        assert!(
            Instant::now() < deadline,
            "{TEST}: the killed main's capsule still runs {:?}",
            cgroup_processes(&capsule)
        );
        std::thread::sleep(Duration::from_millis(200));
    }
    node.assert_left_nothing(&execution);
}

/// **A worker killed while a tool runs in the capsule empties the capsule's
/// cgroup within 10 s, before any worker restarts.** The mock's first reply
/// is a Code Mode cell running `exec sleep 60` (yielding for 30 s); once the
/// capsule's cgroup holds a process whose `comm` is `sleep`, the daemon worker
/// is SIGKILLed, and the cgroup is read empty within 10 s with no worker
/// running and no recovery sweep: kata's worker-death path ends the capsule.
/// systemd does not: MEASURED, a SIGKILL of a delegated scope's leader leaves
/// the scope's other processes running. The path has two arms, each enough
/// alone (measured: either one disabled, the capsule still empties in about
/// 100 ms), which this cell does not tell apart: the toolhost's stdin EOF
/// (`kata-toolhost`'s "What ends it": its `KillAll`, then its exit as the
/// capsule's init), and `kata-provider-youki`'s `watch` reading its
/// supervisor's frame stream closed (`cancel`: `youki kill <id> KILL`). Then
/// the generic settle: ambiguous, never re-delivered, the charge unknown,
/// nothing landed.
///
/// **Would red if:** the capsule's tool outlived its worker until a restart or
/// a recovery sweep ended it (watched: both arms disabled, the provider
/// ignoring its closed stream and the toolhost waiting 30 s on its EOF).
#[test]
#[ignore = "live end-to-end smoke; KATA_SANDBOX_REQUIRE_LIVE=1 just oci-live-smoke"]
fn a_worker_killed_during_a_tool_call_empties_the_capsule_before_any_restart_live() {
    let harness = Harness::OpenaiMock;
    let model = Model::start(vec![mock_provider::exec_command_reply(
        "r1",
        &json!({"cmd": "exec sleep 60", "yield_time_ms": 30_000}),
        mock_provider::usage(1, 0, 1),
    )]);
    let mut node = nanocode_node(harness, "change-agent", Some(&model.url(harness)));
    assert_door_open(harness, "worker daemon", &node.worker.log);
    let data = node.root_path.join("data");
    let execution = node.main.submit(Path::new(PACK));
    let container = wait_for_live_capsule(&data, &execution, "implement");
    let capsule = capsule_cgroup(node.worker.pid, &container)
        .unwrap_or_else(|| panic!("{TEST}: no cgroup for {container} beneath the worker's scope"));
    let deadline = Instant::now() + Duration::from_secs(120);
    let running = loop {
        let processes = cgroup_processes(&capsule);
        if processes.iter().any(|(_, comm)| comm == "sleep") {
            break processes;
        }
        assert!(
            Instant::now() < deadline,
            "{TEST}: the tool never ran in the capsule: {processes:?}"
        );
        std::thread::sleep(Duration::from_millis(100));
    };
    eprintln!("POSITIVE CONTROL tool call: capsule runs {running:?}");
    // The bound runs from the SIGKILL, not from the reaped exit `kill` waits for.
    let killed = Instant::now();
    node.worker.kill();
    loop {
        let left = cgroup_processes(&capsule);
        if left.is_empty() {
            eprintln!("capsule empty {:?} after the kill", killed.elapsed());
            break;
        }
        assert!(
            killed.elapsed() < Duration::from_secs(10),
            "{TEST}: the capsule still runs {left:?} 10 s after its worker died"
        );
        std::thread::sleep(Duration::from_millis(100));
    }
    eprintln!(
        "before any restart, the run's containers with a live process: {:?}",
        live_kata_containers(&node, &execution)
    );
    let doc = node.main.wait_terminal(&execution);
    assert_eq!(doc["status"].as_str(), Some("failed"), "{TEST}: {doc}");
    let reason = assert_proven_ambiguous_never_redelivered(&mut node, &execution);
    assert_unknown_charge(&parsed(&reason));
    assert_unmetered_in_run(&doc, "implement");
    assert_no_mutation(&node, &execution);
    assert_no_container_residue(&node, &execution);
}

/// **An operator cancel while the model request is outstanding ends the turn
/// `Cancelled`, confirmed by the harness, its charge unknown.** The worker
/// lives, so the recorded outcome is the adapter's own: the raw cancelled
/// transition carries the worker's reason that the harness confirmed the
/// cancel, never that it did not confirm, and the mock received no second body.
///
/// **Would red if:** the cancel were settled as anything but the harness's
/// confirmed cancel.
#[test]
#[ignore = "live end-to-end smoke; KATA_SANDBOX_REQUIRE_LIVE=1 just oci-live-smoke"]
fn an_operator_cancel_with_a_request_outstanding_is_a_confirmed_cancel_live() {
    let harness = Harness::OpenaiMock;
    let model = Model::start(vec![Reply::Stall]);
    let node = nanocode_node(harness, "change-agent", Some(&model.url(harness)));
    assert_door_open(harness, "worker daemon", &node.worker.log);
    let data = node.root_path.join("data");
    let execution = node.main.submit(Path::new(PACK));
    let container = wait_for_live_capsule(&data, &execution, "implement");
    let capsule = capsule_cgroup(node.worker.pid, &container)
        .unwrap_or_else(|| panic!("{TEST}: no cgroup for {container} beneath the worker's scope"));
    wait_until_model_request_outstanding(&capsule, Duration::from_millis(500), || {
        model.received(1)
    });
    let ack = node.main.cancel(&execution);
    eprintln!("CANCEL ack: {ack}");
    let doc = node.main.wait_terminal(&execution);
    assert_eq!(
        doc["status"].as_str(),
        Some("cancelled"),
        "{TEST}: the cancel ends the run: {doc}"
    );
    let transitions = stage_transitions(&data, &execution, "implement");
    eprintln!("IMPLEMENT transitions: {transitions:?}");
    let (_, _, payload) = transitions
        .iter()
        .rev()
        .find(|(_, state, _)| state == "cancelled" || state == "failed")
        .unwrap_or_else(|| panic!("{TEST}: the implement attempt never settled: {transitions:?}"));
    assert!(
        payload.contains("the harness confirmed the cancel")
            && !payload.contains("did not confirm"),
        "{TEST}: the worker recorded the harness's confirmed cancel: {payload}"
    );
    assert_unknown_charge(&parsed(payload));
    assert_unmetered_in_run(&doc, "implement");
    assert_eq!(
        model.mock.requests().len(),
        1,
        "{TEST}: the mock's own log holds the one request body"
    );
    assert_no_mutation(&node, &execution);
    assert_no_container_residue(&node, &execution);
}

/// **The re-prompt MEASUREMENT's counter counts nanocode's empty-response
/// re-prompt, and only it.** The positive control of `nanocode_live`'s
/// measurement: the mock answers the turn's first request with a Code Mode
/// cell running one `exec_command`, its second with a response holding neither
/// a final message nor a call, and its third with the final message. The
/// mock's OWN log is the witness that nanocode re-prompted once: three bodies,
/// the third carrying `<empty_response>`, the second (the tool's output) not.
/// The turn's published session evidence, read raw out of the CAS by the
/// counter the measurement uses (`session_counts`), must then count three
/// completed model calls, the tool call, and ONE re-prompt: the pair the tool
/// call separates is not one.
///
/// **Would red if:** the counter missed a re-prompt or counted a pair a tool
/// call separates (watched: its increment removed, 0; its reset on a tool call
/// removed, 2).
#[test]
#[ignore = "live end-to-end smoke; KATA_SANDBOX_REQUIRE_LIVE=1 just oci-live-smoke"]
fn the_reprompt_counter_counts_an_empty_response_reprompt_live() {
    let harness = Harness::OpenaiMock;
    let model = Model::start(vec![
        mock_provider::exec_command_reply(
            "r1",
            &json!({"cmd": "true"}),
            mock_provider::usage(10, 0, 1),
        ),
        mock_provider::empty_reply("r2", mock_provider::usage(10, 0, 1)),
        mock_provider::message_reply("r3", "DONE", mock_provider::usage(10, 0, 1)),
    ]);
    let node = nanocode_node(harness, "change-agent", Some(&model.url(harness)));
    assert_door_open(harness, "worker daemon", &node.worker.log);
    let data = node.root_path.join("data");
    let execution = node.main.submit(Path::new(PACK));
    let doc = node.main.wait_terminal(&execution);
    let requests = model.mock.requests();
    let reprompt = |request: &serde_json::Value| request.to_string().contains("<empty_response>");
    assert_eq!(
        requests.len(),
        3,
        "{TEST}: the mock's own log holds the turn's three request bodies: {doc}"
    );
    assert!(
        !reprompt(&requests[1]) && reprompt(&requests[2]),
        "{TEST}: the mock's own log shows one re-prompt, the third request"
    );
    let counts = session_counts(&data, &accepted_payload(&data, &execution));
    eprintln!("COUNTED: {counts}");
    assert_eq!(
        counts["published"],
        json!(true),
        "{TEST}: the turn published its session evidence: {counts}"
    );
    assert_eq!(
        (&counts["model_calls_completed"], &counts["reprompts"]),
        (&json!(3), &json!(1)),
        "{TEST}: the counter reads three completed model calls and one re-prompt: {counts}"
    );
    assert!(
        counts["tool_calls"]
            .as_u64()
            .is_some_and(|tools| tools >= 1),
        "{TEST}: the counter reads the tool call between the first two: {counts}"
    );
}
