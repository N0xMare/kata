//! The representative agent workflow, end to end on a REAL node: an installed
//! `kata serve` main, an external `kata-worker` daemon holding the certified
//! rootless-youki route (the one execution engine, so there is no profile to
//! select), and the shipped `workflows/std/agent-change.star` pack driven through
//! the ordinary client path (`kata run --submit`, `kata approvals`, `kata run
//! approve`). The agent is the embedded harness, `nanocode_openai`, whose model is a
//! scripted mock provider on the loopback reached through the worker's
//! `test-support` endpoint door (`mock_model`): no model budget is spent, and every
//! tool call the mock asks for runs inside the turn's real container.
//!
//! # The cell matrix
//!
//! * **A — the happy path** (`the_agent_change_pack_completes_end_to_end_live`):
//!   the model's one `exec_command` inside a REAL container edits the fixture's
//!   `src/`, `test` proves the criterion, `approve` parks, `commit` records,
//!   `promote` lands, `export` pushes `kata/<exec>` to a LOCAL bare remote and opens
//!   ONE PR through a fake `gh` shim. Every assertion reads state OUTSIDE kata: raw
//!   `operational.db`, `git` on the fixture and remote, the shim's log, the
//!   filesystem, `youki list`, the mock's own request log — `kata run show` only
//!   cross-checks.
//! * **B — the interruption matrix** (`a_killed_main_resumes_the_parked_gate_live`,
//!   `a_killed_worker_at_the_parked_gate_resumes_live`): a kill at a durable park
//!   converges on the SAME final state after restart; and
//!   `a_killed_worker_mid_turn_settles_proven_ambiguous_live`: a kill DURING the
//!   turn is terminal `PROVEN AMBIGUOUS`, never re-delivered.
//! * **C — the abort paths** (`a_rejected_gate_lands_nothing_and_parks_the_candidate_live`,
//!   `a_cancel_mid_turn_settles_cancelled_on_worker_death_live`): reject at the
//!   gate and cancel mid-turn both leave the repo, remote and gh untouched — and the
//!   candidate parked, inspectable.
//! * **D — the failure retry** (`a_failed_panel_member_retries_on_the_next_panel_agent_live`):
//!   a two-member `agent = [a, b]` panel whose first member's turn completed out of
//!   its write fence — PERFORMED BUT FAILED, retryable — mints a second capsule on
//!   the next member, which completes and lands its write.
//! * **E — the agent loop** (`an_agent_loop_fixes_its_failing_edit_and_lands_the_last_iterations_tree_live`,
//!   `an_exhausted_agent_loop_parks_its_last_candidate_and_lands_nothing_live`): a
//!   `loop()` whose body is the agent turn and whose gate is the shell test — also
//!   the required criterion and the `route` source. The fixing model writes a
//!   failing edit at iteration 0 and the fix at iteration 1, and trunk's tree is
//!   iteration 1's, computed by git plumbing; the model that never fixes it exhausts
//!   the loop under `on_exhaustion = "accept"`, the route parks `parked/<exec>` and
//!   nothing lands.
//! * **F — the cost bound** (`a_multi_request_turn_trips_the_workflow_cost_bound_live`):
//!   one `nanocode_anthropic` turn of two sampling responses, priced from the
//!   built-in `anthropic` row under its API key, crosses the workflow's `cost_bound`
//!   that its last response alone stays under — the run fails on the bound and its
//!   successor never dispatches.
//! * **G — worker liveness** (`a_worker_stopped_two_seconds_keeps_its_turn_live`,
//!   `a_main_stopped_seven_seconds_keeps_its_workers_turn_live`,
//!   `a_worker_stopped_past_the_deadline_is_settled_naming_its_silence_live`): at the
//!   rigs' 1000/5000 ms, a 2 s SIGSTOP of the worker, or a 7 s one of the main, across
//!   one of the worker's heartbeats keeps the turn; a 12 s stop of the worker settles it
//!   by the heartbeat leg, its recorded reason naming the silence and the stopped process.
//! * **H — model reuse** (`a_second_equal_agent_stage_adopts_the_first_turn_and_runs_no_container_live`):
//!   a second run of an agent stage authoring `cache_policy = "model_reuse"` mints
//!   the equal capsule and adopts the first run's turn: the mock receives no request
//!   for it and no container runs.
//! * **I — a provider failing its response** (`a_provider_failing_its_response_mid_turn_settles_proven_ambiguous_live`):
//!   the mock begins the turn's second response and fails it with a
//!   `response.failed` event after the turn's command ran in the container; the
//!   attempt settles PROVEN AMBIGUOUS, is never re-run, and publishes nothing.
//! * **I′ — a provider cutting its response** (`a_provider_cutting_its_response_mid_turn_is_re_run_then_falls_back_live`):
//!   the mock drops the turn's second response mid-body, on every re-send; each
//!   attempt settles PROVEN NOT PERFORMED, `transient`, charged `unavailable`, is
//!   re-run twice on the same agent, and the fallback member completes the stage.
//! * **J — a split key** (`a_lifted_key_split_across_text_deltas_never_reaches_an_sse_subscriber_live`):
//!   the model streams the stage's own fake key split across two text deltas under
//!   `progress_visibility = "full"`; a bare reader of `GET /api/v1/events` takes
//!   neither the key nor either half in its raw transcript, and no 4-byte window of
//!   it in a `progress` preview, and does take the text after it.
//!
//! # The rig is a node, not a harness
//!
//! Nothing here calls kata's internals: the cell writes `kata.toml` +
//! `worker.toml`, builds a jj-colocated git fixture with a `kata/brief.md`, a
//! local `origin` remote and a fake `gh` on `PATH`, starts the mock, and drives
//! the run exactly as an operator does.
//!
//! # Host preconditions
//!
//! Same as the sibling OCI live lanes: `--ignore`d so a host without the delegated
//! user scope, the pin, the static toolhost (`cargo build -p kata-toolhost --target
//! x86_64-unknown-linux-musl`) or a `test-support` build of `kata-worker` fails the
//! lane with the named refusal rather than silently skipping. `oci-live-smoke`
//! selects this binary.

#![cfg(target_os = "linux")]
mod agent_change_rig;
#[allow(dead_code)]
mod mock_model;
#[path = "../../../crates/agent-nanocode/tests/fixtures/mock_provider.rs"]
#[allow(dead_code)]
mod mock_provider;

use agent_change_rig::nanocode::Harness;
use agent_change_rig::*;
use mock_model::{
    MockAgent, MockModel, SECOND_OPENAI_MODEL, Turn, mock_node, mock_node_on, model_of,
};
use std::path::Path;

// CELL A — the happy path, asserted from OUTSIDE kata
// ---------------------------------------------------------------------------

/// The scripted turn: one `exec_command` inside the container writes the
/// fixture's required edit and commits the tree on the capsule's scratch
/// repository, then the model answers. Each of its two responses reports 600
/// input and 40 output tokens. The scratch commit's subject is the one string the
/// session evidence names and the landed host history never does.
fn turn_a() -> Turn {
    Turn::running(
        "printf 'implemented-change\\n' > src/app.txt && git add -A && \
         git commit -q -m kata-turn-scratch-commit-a1",
        "done",
    )
    .usage(600, 40)
}

/// **Cell A.** The whole `agent-change` run on a real node: a REAL container
/// for the agent turn (the model's `exec_command` writes the change inside
/// `/work`), a deterministic criterion, a parked capsule-bound approval, the
/// workspace-effect commit→promote→export chain to a local bare remote through
/// a fake `gh` — then every outcome read off the filesystem, git and raw
/// `operational.db`, cross-checked against `kata run show`.
#[test]
#[ignore = "the rootless-OCI prerequisite — `just _containment-preconditions`"]
fn the_agent_change_pack_completes_end_to_end_live() {
    let model = MockModel::always(turn_a());
    let node = mock_node(&model, "change-agent");
    let execution = node.main.submit(Path::new(PACK));

    // The run parks at `approve` — and the gate row binds the capsule it
    // authorizes.
    let gate = node
        .main
        .next_gate(&execution)
        .expect("the approve stage parks a gate");
    assert_eq!(gate["stage_name"].as_str(), Some("approve"));
    let capsule_id = gate["capsule"]["capsule_id"]
        .as_str()
        .expect("the gate row names the capsule it binds");
    assert!(
        !capsule_id.is_empty(),
        "the gate's capsule binding is non-empty"
    );

    node.main.decide(&gate, None);
    let doc = node.main.wait_terminal(&execution);
    assert_eq!(
        doc["status"].as_str(),
        Some("completed"),
        "the run completes: {doc}"
    );

    // The approval's decision is recorded against the SAME capsule the gate
    // showed, on the RAW plane.
    {
        let conn = raw_db(&node.root_path.join("data"));
        let approvals: Vec<String> = conn
            .prepare(
                "SELECT CAST(payload_json AS TEXT) FROM transitions \
                 WHERE execution_id = ?1 AND kind = 'approval_decided'",
            )
            .unwrap()
            .query_map(
                [ulid::Ulid::from_string(&execution).unwrap().to_bytes()],
                |row| row.get::<_, String>(0),
            )
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        assert_eq!(
            approvals.len(),
            1,
            "{TEST}: exactly one approval decision is recorded: {approvals:?}"
        );
        let recorded: serde_json::Value = serde_json::from_str(&approvals[0]).unwrap();
        assert_eq!(
            recorded["capsule_id"].as_str(),
            Some(capsule_id),
            "{TEST}: the recorded decision binds the capsule the gate showed"
        );
        // The gate's capsule id is also the approve occurrence's: the
        // occurrence binds its capsule immutably.
        let occurrence_capsule: Option<String> = conn
            .prepare(
                "SELECT hex(o.capsule_id) FROM occurrences o \
                 JOIN attempts a ON a.attempt_id = o.accepted_attempt_id \
                 WHERE o.execution_id = ?1 AND a.stage_id = 'approve'",
            )
            .unwrap()
            .query_map(
                [ulid::Ulid::from_string(&execution).unwrap().to_bytes()],
                |row| row.get::<_, String>(0),
            )
            .unwrap()
            .next()
            .transpose()
            .unwrap()
            .map(|id: String| id.to_ascii_lowercase());
        assert_eq!(
            occurrence_capsule.as_deref(),
            Some(capsule_id),
            "{TEST}: the approve occurrence binds the capsule the gate showed"
        );
    }

    // `kata run show` cross-checked against the mock's own log: the turn made
    // its two model calls, and the agent's usage the document renders is the
    // fold of both responses' reports.
    assert_eq!(
        model.requests().len(),
        2,
        "{TEST}: the mock's own log holds the turn's two requests"
    );
    let implement = &doc["outputs"]["implement"];
    assert_eq!(
        implement["token_usage"]["input"],
        serde_json::json!(1200),
        "the agent stage's recorded usage is the provider's wire reports, summed: {implement}"
    );

    assert_final_state(&node, &execution);

    // THE SCRATCH COMMIT — evidence, never adoption. Two oracles, both
    // outside kata: the fixture's own `git log` answers the landed history
    // and the turn's commit subject is in none of it, and the session
    // evidence blob — named by the accepted turn's `agent_turns` row, read
    // out of the raw CAS — is the ONE durable record that does carry it.
    {
        let log = kata_test_utils::git::hermetic_git_in(&node.fixture.repo)
            .args(["log", "--format=%s", "main"])
            .output()
            .expect("git log on the fixture runs");
        assert!(log.status.success());
        let subjects = String::from_utf8_lossy(&log.stdout).into_owned();
        assert!(
            !subjects.contains("kata-turn-scratch-commit-a1"),
            "{TEST}: the scratch commit's subject is in the host's landed \
             history — the scratch repository leaked into adoption: {subjects}"
        );

        let conn = raw_db(&node.root_path.join("data"));
        let rows: Vec<String> = conn
            .prepare(
                "SELECT CAST(evidence_json AS TEXT) FROM execution_evidence \
                 WHERE execution_id = ?1",
            )
            .unwrap()
            .query_map(
                [ulid::Ulid::from_string(&execution).unwrap().to_bytes()],
                |row| row.get::<_, String>(0),
            )
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        let mut evidence_object = None;
        for row in &rows {
            let record: serde_json::Value = serde_json::from_str(row).unwrap();
            for turn in record["evidence"]["agent_turns"]
                .as_array()
                .into_iter()
                .flatten()
            {
                if turn["stage_id"].as_str() == Some("implement") {
                    evidence_object = turn["session_evidence_object_id"]
                        .as_str()
                        .map(str::to_owned);
                }
            }
        }
        let object_id = evidence_object.unwrap_or_else(|| {
            panic!("{TEST}: the implement turn's accepted evidence names no session blob")
        });
        let bytes = cas_object(&node.root_path.join("data"), &object_id).unwrap_or_else(|| {
            panic!("{TEST}: the named session evidence object {object_id} is not in the CAS")
        });
        let evidence: serde_json::Value =
            serde_json::from_slice(&bytes).expect("the session evidence decodes");
        let commits = evidence["scratch_commits"]
            .as_array()
            .expect("the session evidence carries a scratch_commits array");
        // `elide` stores the field backtick-quoted — the shared rule's
        // spelling — so the assertion asks for the subject, not its frame.
        assert!(
            commits.iter().any(|commit| commit["subject"]
                .as_str()
                .is_some_and(|subject| subject.contains("kata-turn-scratch-commit-a1"))),
            "{TEST}: the turn's scratch commit is not in the session \
             evidence: {evidence}"
        );
    }
}

// ---------------------------------------------------------------------------
// CELLS B + C — durable interruption and the refusal/terminal arms
// ---------------------------------------------------------------------------

/// The turn that holds mid-flight: its first model request is logged and never
/// answered — the deterministic "a turn is LIVE" the kill/cancel cells need.
fn turn_hang() -> Turn {
    Turn::held()
}

/// **Cell B, main arm.** SIGKILL the installed main while the approval gate
/// is parked, restart it on the same data directory, and the SAME parked
/// attempt re-lists — durable state, not memory. The decision lands after
/// the restart and the run completes once: one commit, one promote, one PR.
#[test]
#[ignore = "live end-to-end smoke; KATA_SANDBOX_REQUIRE_LIVE=1 just oci-live-smoke"]
fn a_killed_main_resumes_the_parked_gate_live() {
    let model = MockModel::always(turn_a());
    let mut node = mock_node(&model, "change-agent");
    let execution = node.main.submit(Path::new(PACK));
    let gate = node
        .main
        .next_gate(&execution)
        .expect("the approve stage parks a gate");

    node.main.kill();
    node.restart_main();
    // The worker's transport died with the main and the daemon does not
    // re-dial a rebound socket — a fresh daemon re-registers with the same
    // secret and capabilities.
    node.restart_worker();

    let resumed = node
        .main
        .next_gate(&execution)
        .expect("the gate re-parks after the main's restart");
    assert_eq!(
        resumed["assignment_id"], gate["assignment_id"],
        "{TEST}: the restarted main re-lists the SAME parked attempt"
    );
    node.main.decide(&resumed, None);
    let doc = node.main.wait_terminal(&execution);
    assert_eq!(
        doc["status"].as_str(),
        Some("completed"),
        "the run completes after the main's restart: {doc}"
    );
    assert_final_state(&node, &execution);
}

/// **Cell B, worker arm.** SIGKILL the external worker while the gate is
/// parked — nothing the worker owns is live — respawn it against the same
/// socket and secret, and the decision + downstream effects land once.
#[test]
#[ignore = "live end-to-end smoke; KATA_SANDBOX_REQUIRE_LIVE=1 just oci-live-smoke"]
fn a_killed_worker_at_the_parked_gate_resumes_live() {
    let model = MockModel::always(turn_a());
    let mut node = mock_node(&model, "change-agent");
    let execution = node.main.submit(Path::new(PACK));
    let gate = node
        .main
        .next_gate(&execution)
        .expect("the approve stage parks a gate");

    node.worker.kill();
    node.restart_worker();

    node.main.decide(&gate, None);
    let doc = node.main.wait_terminal(&execution);
    assert_eq!(
        doc["status"].as_str(),
        Some("completed"),
        "the run completes after the worker's restart: {doc}"
    );
    assert_final_state(&node, &execution);
}

/// **Cell B, mid-turn arm.** SIGKILL the worker while its capsule's turn is
/// LIVE — the mock holds its model request deterministically — and the answer is the
/// honest one, by name: the attempt settles `PROVEN AMBIGUOUS` (the main
/// cannot observe what the container did), terminal, and is NOT re-delivered
/// — capsule re-delivery is not implemented, so an unobservable turn is never
/// silently replayed. The run fails, the candidate auto-parks for inspection,
/// and a respawned worker claims NOTHING for the dead occurrence.
#[test]
#[ignore = "live end-to-end smoke; KATA_SANDBOX_REQUIRE_LIVE=1 just oci-live-smoke"]
fn a_killed_worker_mid_turn_settles_proven_ambiguous_live() {
    let model = MockModel::always(turn_hang());
    let mut node = mock_node(&model, "change-agent");
    let execution = node.main.submit(Path::new(PACK));
    kill_worker_mid_turn(&mut node, &execution);
    let doc = node.main.wait_terminal(&execution);
    assert_eq!(
        doc["status"].as_str(),
        Some("failed"),
        "the ambiguous attempt fails the run: {doc}"
    );
    assert_proven_ambiguous_never_redelivered(&mut node, &execution);
    assert_no_mutation(&node, &execution);
}

/// **Cell C, reject arm.** The operator rejects the parked gate — the approve
/// attempt fails by name, the run fails, and the auto-park holds the
/// candidate for inspection while nothing mutates: no commit, no promote,
/// no forge call, trunk unmoved.
#[test]
#[ignore = "live end-to-end smoke; KATA_SANDBOX_REQUIRE_LIVE=1 just oci-live-smoke"]
fn a_rejected_gate_lands_nothing_and_parks_the_candidate_live() {
    let model = MockModel::always(turn_a());
    let node = mock_node(&model, "change-agent");
    let execution = node.main.submit(Path::new(PACK));
    let gate = node
        .main
        .next_gate(&execution)
        .expect("the approve stage parks a gate");

    node.main.decide(&gate, Some("not the change we want"));
    let doc = node.main.wait_terminal(&execution);
    assert_eq!(
        doc["status"].as_str(),
        Some("failed"),
        "a rejected gate fails the run: {doc}"
    );
    assert_no_mutation(&node, &execution);
}

/// **Cell C, cancel arm.** `kata run cancel` during a live turn records the
/// stop durably — and on `local_socket` the delivery is refused, so the stop
/// stands. The worker's death then settles the attempt under the standing
/// stop: `cancelled`, not re-presented.
#[test]
#[ignore = "live end-to-end smoke; KATA_SANDBOX_REQUIRE_LIVE=1 just oci-live-smoke"]
fn a_cancel_mid_turn_settles_cancelled_on_worker_death_live() {
    let model = MockModel::always(turn_hang());
    let mut node = mock_node(&model, "change-agent");
    let execution = node.main.submit(Path::new(PACK));
    wait_until_claimed(&node, &execution, "implement", 1);

    node.main.cancel(&execution);
    node.worker.kill();
    let doc = node.main.wait_terminal(&execution);
    assert_eq!(
        doc["status"].as_str(),
        Some("cancelled"),
        "the standing stop settles the dead attempt cancelled: {doc}"
    );
    assert_no_mutation(&node, &execution);
}

// CELL G — worker liveness: a stall the worker recovers from is not a death
// ---------------------------------------------------------------------------

/// The node every liveness cell boots: the held turn's model, the rig's
/// `heartbeat_interval_ms = 1000` / `heartbeat_grace_ms = 5000`, and a worker that
/// logs each heartbeat it sends (`kata_worker::worker_loop` at `debug`), so a cell
/// can time a stall against the worker's own beats.
fn boot_liveness_node(model: &MockModel) -> Node {
    let root = node_root();
    let fixture = fixture_repo(root.path());
    mock_node_on(
        root,
        fixture,
        model,
        &[MockAgent::openai("change-agent")],
        "agent-change-e2e",
        &[(
            "RUST_LOG".to_owned(),
            "info,kata_worker::worker_loop=debug".to_owned(),
        )],
    )
}

/// Wait until the `implement` turn is provably in flight: claimed on the raw
/// chain AND a live `kata-<capsule>` container the kernel answers for.
fn turn_in_flight(node: &Node, execution: &str) {
    wait_until_claimed(node, execution, "implement", 1);
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
    while live_kata_containers(node, execution).is_empty() {
        assert!(
            std::time::Instant::now() < deadline,
            "{TEST}: the implement turn never held a live container"
        );
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
}

/// How many heartbeats the worker's log says it has sent.
fn beats_sent(node: &Node) -> usize {
    std::fs::read_to_string(&node.worker.log)
        .unwrap_or_default()
        .matches("heartbeat sent")
        .count()
}

/// The instants the worker's next `count` heartbeats appeared in its log, polled
/// every 5 ms: the worker's own cadence, read without asking the main.
fn observe_beats(node: &Node, count: usize) -> Vec<std::time::Instant> {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
    let mut seen = beats_sent(node);
    let mut beats = Vec::new();
    while beats.len() < count {
        assert!(
            std::time::Instant::now() < deadline,
            "{TEST}: the worker logged no heartbeat (is `kata_worker::worker_loop` at debug?)"
        );
        let now = beats_sent(node);
        if now > seen {
            seen = now;
            beats.push(std::time::Instant::now());
        }
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
    beats
}

/// `kill -<signal> <pid>` on a process this cell's node spawned.
fn signal(pid: u32, signal: &str) {
    let status = std::process::Command::new("kill")
        .args([format!("-{signal}"), pid.to_string()])
        .status()
        .expect("kill runs");
    assert!(status.success(), "{TEST}: kill -{signal} {pid} failed");
}

/// A process this cell SIGSTOPped, continued however the cell ends.
struct Stopped(u32);

impl Stopped {
    fn stop(pid: u32) -> Self {
        signal(pid, "STOP");
        Self(pid)
    }
}

impl Drop for Stopped {
    fn drop(&mut self) {
        signal(self.0, "CONT");
    }
}

/// SIGSTOP `pid` for `stall`, starting `lead` before the worker's next heartbeat
/// is due (its cadence read off its own log), so the stall spans that beat;
/// SIGCONT however the stall ends. Returns how many beats the worker logged
/// while `pid` was stopped.
fn stall_across_a_beat(
    node: &Node,
    pid: u32,
    lead: std::time::Duration,
    stall: std::time::Duration,
) -> usize {
    let beats = observe_beats(node, 3);
    let period = (beats[2] - beats[0]) / 2;
    let mut next = beats[2] + period;
    while next < std::time::Instant::now() + lead {
        next += period;
    }
    let start = next
        .checked_sub(lead)
        .expect("the lead is shorter than the host's uptime");
    std::thread::sleep(start.saturating_duration_since(std::time::Instant::now()));
    let before = beats_sent(node);
    let stopped = Stopped::stop(pid);
    std::thread::sleep(stall);
    let during = beats_sent(node) - before;
    drop(stopped);
    eprintln!(
        "{TEST}: stopped pid {pid} for {stall:?}, {lead:?} before a beat due at the worker's \
         {period:?} cadence; the worker logged {during} beat(s) meanwhile"
    );
    during
}

/// The reason on the raw `implement` transition that settled the turn, if any.
fn implement_settlement(node: &Node, execution: &str) -> Option<String> {
    let conn = raw_db(&node.root_path.join("data"));
    conn.query_row(
        "SELECT CAST(payload_json AS TEXT) FROM transitions WHERE execution_id = ?1 \
         AND stage_id = 'implement' AND resulting_state IN ('failed', 'cancelled')",
        [ulid::Ulid::from_string(execution).unwrap().to_bytes()],
        |row| row.get(0),
    )
    .ok()
}

/// After a stall: past the 6 s deadline plus a sweep, the turn is still
/// unsettled on the raw chain and its container still runs. Then the cell
/// cancels it.
fn assert_turn_survived(node: &Node, execution: &str, what: &str) {
    std::thread::sleep(std::time::Duration::from_secs(10));
    assert_eq!(
        implement_settlement(node, execution),
        None,
        "{TEST}: {what}: the live worker's turn was settled"
    );
    assert!(
        !live_kata_containers(node, execution).is_empty(),
        "{TEST}: {what}: the live worker's container no longer runs"
    );
    node.main.cancel(execution);
}

/// **CELL G, the worker arm.** A live worker process stopped for 2 s — 0.5 s before
/// a heartbeat is due, so the stall delays that beat by 1.5 s — keeps its turn. At
/// this node's 1000/5000 ms a worker beating at a fixed 5 s had one second of
/// slack, and this stall settled its running turn `worker local-worker-0 died.
/// PROVEN AMBIGUOUS` (2 of 2 measured); at its main's half-interval cadence it is
/// silent 2.5 s at most.
///
/// **Watched red** on a build with the worker at a fixed 5 s and wall-time silence:
/// the turn was settled `worker local-worker-0 died. PROVEN AMBIGUOUS`.
#[test]
#[ignore = "live end-to-end smoke; KATA_SANDBOX_REQUIRE_LIVE=1 just oci-live-smoke"]
fn a_worker_stopped_two_seconds_keeps_its_turn_live() {
    let model = MockModel::always(turn_hang());
    let node = boot_liveness_node(&model);
    let execution = node.main.submit(Path::new(PACK));
    turn_in_flight(&node, &execution);
    stall_across_a_beat(
        &node,
        node.worker.pid,
        std::time::Duration::from_millis(500),
        std::time::Duration::from_secs(2),
    );
    assert_turn_survived(&node, &execution, "a worker stopped 2 s");
}

/// **CELL G, the main arm.** The MAIN stopped for 7 s across a heartbeat — longer
/// than the 6 s deadline, so whatever the stop's phase, the overdue sweep tick that
/// runs on resume, before the reader has read the beats waiting in the worker's
/// socket, finds more wall time since the last recorded beat than the deadline. The
/// worker logged beats while the main was stopped (the control). Charged as one
/// interval of observed silence, the stop leaves the turn live. A 2 s stop cannot
/// tell the two apart at the half-interval cadence: it leaves at most 2.5 s of
/// wall-time silence.
///
/// **Watched red** with the one-interval cap removed from `HeartbeatMonitor::sweep`
/// and the cadence kept: the live worker's turn was settled by the heartbeat leg.
#[test]
#[ignore = "live end-to-end smoke; KATA_SANDBOX_REQUIRE_LIVE=1 just oci-live-smoke"]
fn a_main_stopped_seven_seconds_keeps_its_workers_turn_live() {
    let model = MockModel::always(turn_hang());
    let node = boot_liveness_node(&model);
    let execution = node.main.submit(Path::new(PACK));
    turn_in_flight(&node, &execution);
    let during = stall_across_a_beat(
        &node,
        node.main.child.id(),
        std::time::Duration::from_millis(500),
        std::time::Duration::from_secs(7),
    );
    assert!(
        during >= 1,
        "{TEST}: the control: the worker sent a beat while the main was stopped"
    );
    assert_turn_survived(&node, &execution, "a main stopped 7 s");
}

/// **CELL G, the bound.** A worker stopped for 12 s — past the 6 s deadline — IS
/// settled, PROVEN AMBIGUOUS, by the heartbeat leg, and the settlement records
/// the leg, its observed silence against the deadline, and the process the
/// kernel reported for the worker's connection as `/proc` found it: stopped.
///
/// **Watched red** on that build: never settled. The worker was stopped before its
/// first beat at the 5 s cadence, so the monitor had no entry for it; the main now
/// starts a worker's clock when its reactor starts.
#[test]
#[ignore = "live end-to-end smoke; KATA_SANDBOX_REQUIRE_LIVE=1 just oci-live-smoke"]
fn a_worker_stopped_past_the_deadline_is_settled_naming_its_silence_live() {
    let model = MockModel::always(turn_hang());
    let node = boot_liveness_node(&model);
    let execution = node.main.submit(Path::new(PACK));
    turn_in_flight(&node, &execution);
    let pid = node.worker.pid;
    let stopped = Stopped::stop(pid);
    std::thread::sleep(std::time::Duration::from_secs(12));
    let settled = implement_settlement(&node, &execution);
    drop(stopped);
    let reason =
        settled.unwrap_or_else(|| panic!("{TEST}: a worker stopped 12 s was never settled"));
    assert!(
        reason.contains("PROVEN AMBIGUOUS")
            && reason.contains("worker local-worker-0 died: no heartbeat for ")
            && reason.contains(" s of observed silence, past its 6.0 s deadline")
            && reason.contains(&format!("its process {pid} exists in state T")),
        "{TEST}: the settlement names the heartbeat leg, its silence and the stopped \
         process: {reason}"
    );
    eprintln!("{TEST}: settled: {reason}");
}

// CELL — the fallback panel's failure retry, live
// ---------------------------------------------------------------------------

/// The panel pack this cell submits — one stage authoring a two-member
/// fallback `agent = [...]` panel (the stage's one-advance failure-retry
/// budget), `rw` `/work`, `produces_files` fencing the second
/// member's write. Written into the node root, not `workflows/` — it is a
/// test pack, not a shipped one.
const PANEL_PACK_LIVE: &str = "p = stage(\n\
     \x20   id = \"panel\",\n\
     \x20   agent = [\"panel-a\", \"panel-b\"],\n\
     \x20   produces_files = [\"b.txt\"],\n\
     \x20   prompt = \"answer\",\n\
     \x20   sandbox = \"work\",\n\
     )\n\
     workflow(\"failure-retry-panel\", root = [p], worktree_isolated = True,\n\
     \x20   sandbox_profiles = {\"work\": sandbox_profile(workspace = \"rw\", net = \"offline\")})\n";

/// The first panel member's turn: complete having written OUTSIDE the
/// `produces_files` fence — the adoption judge refuses the delta WHOLE
/// (`work_delta_out_of_scope`), the attempt settling PERFORMED BUT FAILED — one of
/// the two classes the oci failure-retry whitelist (`failure_is_retryable`)
/// admits. A provider refusal is the WRONG instrument here: a refused agent is
/// never run again anywhere in the panel.
fn turn_panel_a() -> Turn {
    Turn::running(
        "printf 'a-crossed-the-fence\\n' > outside-the-fence.txt",
        "done",
    )
}

/// The retry's turn — the SECOND member's model: write the file
/// `produces_files` fences, complete.
fn turn_panel_b() -> Turn {
    Turn::running("printf 'panel-member-b-wrote-here\\n' > b.txt", "done").usage(10, 5)
}

/// **The live fallback-panel retry.** `panel-a`'s capsule runs inside a real
/// container and its model completes a turn whose write crosses the
/// `produces_files` fence — the adoption judge's whole-delta refusal is
/// PERFORMED BUT FAILED, the retryable class — so the stage's panel advance mints
/// a second capsule on the NEXT member (`panel-b`), whose turn writes `b.txt` and
/// completes. The two members pin different models, so the mock answers each by
/// the model its request names. Asserted from OUTSIDE kata: the raw
/// `operational.db` names exactly two attempts on the stage (base `failed`, the
/// retry `completed`), each occurrence's capsule — read as CAS bytes through the
/// `capsules` row — pins its member's model, the mock's own log holds `panel-a`'s
/// two requests and then `panel-b`'s, and the applied head's candidate commit
/// carries `b.txt`, read by `git` on the fixture.
#[test]
#[ignore = "live end-to-end smoke; KATA_SANDBOX_REQUIRE_LIVE=1 just oci-live-smoke"]
fn a_failed_panel_member_retries_on_the_next_panel_agent_live() {
    let model = MockModel::answering(|request| {
        if model_of(request) == SECOND_OPENAI_MODEL {
            turn_panel_b().reply(request)
        } else {
            turn_panel_a().reply(request)
        }
    });
    let root = node_root();
    let fixture = fixture_repo(root.path());
    let node = mock_node_on(
        root,
        fixture,
        &model,
        &[
            MockAgent::openai("panel-a"),
            MockAgent {
                model: SECOND_OPENAI_MODEL,
                ..MockAgent::openai("panel-b")
            },
        ],
        "agent-change-e2e",
        &[],
    );

    let pack = node.root_path.join("failure-retry-panel.star");
    std::fs::write(&pack, PANEL_PACK_LIVE).unwrap();
    let execution = node.main.submit(&pack);
    let doc = node.main.wait_terminal(&execution);
    assert_eq!(
        doc["status"].as_str(),
        Some("completed"),
        "the retry completes the run: {doc}"
    );

    let conn = raw_db(&node.root_path.join("data"));
    let exec_bytes = ulid::Ulid::from_string(&execution).unwrap().to_bytes();

    // RAW SQLITE: exactly two attempts on the stage's chain — the base seat
    // failed, its `child(1)` retry completed.
    let states: Vec<String> = conn
        .prepare(
            "SELECT p.state FROM attempts a JOIN attempt_projection p \
             ON p.execution_id = a.execution_id AND p.stage_id = a.stage_id \
             AND p.attempt_ordinal = a.attempt_ordinal \
             WHERE a.execution_id = ?1 AND a.stage_id = 'panel' \
             ORDER BY a.attempt_ordinal",
        )
        .unwrap()
        .query_map([exec_bytes.as_slice()], |row| row.get(0))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    assert_eq!(
        states,
        ["failed", "completed"],
        "{TEST}: the chain's two attempts — base failed, retry completed: {states:?}"
    );

    // THE MOCK'S OWN LOG: `panel-a`'s turn (its command, then its answer), then
    // `panel-b`'s — no third member and no second `panel-a` turn.
    let models: Vec<String> = model
        .requests()
        .iter()
        .map(|request| model_of(request).to_owned())
        .collect();
    assert_eq!(
        models,
        [
            agent_change_rig::nanocode::OPENAI_MODEL,
            agent_change_rig::nanocode::OPENAI_MODEL,
            SECOND_OPENAI_MODEL,
            SECOND_OPENAI_MODEL
        ],
        "{TEST}: the mock received panel-a's turn and then panel-b's"
    );

    // THE RETRY'S CAPSULE — each occurrence's `capsule_object_id` read off the
    // `capsules` row, its bytes out of the raw CAS, the decoded
    // `AgentTurnSpec.model` naming its member's model.
    let capsule_objects: Vec<String> = conn
        .prepare(
            "SELECT hex(c.capsule_object_id) FROM capsules c \
             JOIN occurrences o ON o.capsule_id = c.capsule_id \
             WHERE o.execution_id = ?1 ORDER BY o.created_at_ms",
        )
        .unwrap()
        .query_map([exec_bytes.as_slice()], |row| row.get(0))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    assert_eq!(
        capsule_objects.len(),
        2,
        "{TEST}: the stage's chain binds two capsules: {capsule_objects:?}"
    );
    for (object_id, member_model) in capsule_objects.iter().zip([
        agent_change_rig::nanocode::OPENAI_MODEL,
        SECOND_OPENAI_MODEL,
    ]) {
        let bytes = cas_object(&node.root_path.join("data"), object_id)
            .unwrap_or_else(|| panic!("{TEST}: the capsule object {object_id} is not in the CAS"));
        let capsule: kata_types::execution_contract::Capsule =
            serde_json::from_slice(&bytes).expect("the capsule decodes");
        let kata_types::execution_contract::CapsuleProcess::Agent(spec) = capsule.process() else {
            panic!("{TEST}: a panel stage delivers an agent capsule")
        };
        assert_eq!(
            spec.model.as_deref(),
            Some(member_model),
            "{TEST}: capsule {object_id} pins its panel member's model"
        );
    }

    // THE LANDED HEAD — the apply advanced the execution's head row onto a new
    // candidate commit, and `git` (not kata) reads `b.txt` off it.
    let (candidate_commit, head_seq): (String, i64) = conn
        .query_row(
            "SELECT candidate_commit_id, head_seq FROM execution_work_tree_heads \
             WHERE execution_id = ?1",
            [exec_bytes.as_slice()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .expect("{TEST}: the execution's head row");
    assert_eq!(head_seq, 1, "{TEST}: exactly one apply advanced the head");
    let shown = kata_test_utils::git::hermetic_git_in(&node.fixture.repo)
        .args(["show", &format!("{candidate_commit}:b.txt")])
        .output()
        .expect("git show runs");
    assert!(
        shown.status.success(),
        "{TEST}: b.txt is on the landed head"
    );
    assert_eq!(
        String::from_utf8_lossy(&shown.stdout),
        "panel-member-b-wrote-here\n",
        "{TEST}: the landed head carries the retry's write"
    );
}

// ---------------------------------------------------------------------------
// CELL E — a `loop()` whose body is an agent turn
// ---------------------------------------------------------------------------

/// The implement → test → fix loop as a test pack (written into the node
/// root, not shipped): the agent `implement` is the loop BODY, the shell
/// `test` its GATE, and that one gate is also the REQUIRED validation
/// criterion and the `route` source. `on_exhaustion = "accept"` adopts the
/// last iteration's report, so a loop that never goes green reaches the
/// `failed` arm and parks the candidate instead of landing it. Both stages
/// read the invocation's params: the task text reaches the agent's prompt,
/// and the test command reaches `test`'s `run=` through `shquote`.
const LOOP_PACK_LIVE: &str = r#"
_CRITERION_ID = "fixture-check-green"

_TEST_REPORT = contract("TestReport", {
    "status": field(enum("passed", "failed")),
    "exit_code": field("integer"),
    "feedback": field("string"),
    "criteria": field(list_of(contract("CriterionResult", {
        "criterion_id": field("string"),
        "status": field(enum("passed", "failed")),
        "evidence": field(list_of("string")),
    }))),
})

implement = stage(
    id = "implement",
    agent = "change-agent",
    sandbox = "edit",
    produces_files = ["src/**"],
    prompt = """Task: {{ params.task }}
{% if review.iteration > 0 %}Iteration {{ review.iteration }}: the tests FAILED on your last attempt:
{{ review.feedback }}
Fix the cause; do not weaken or delete tests.{% endif %}
Leave your result in the working tree.
""",
)

test = stage(
    id = "test",
    agent = "shell",
    sandbox = "verify",
    depends_on = ["implement"],
    run = """RC=0
cd /work && sh -c {{ params.test_command | shquote }} > /out/check.log 2>&1 || RC=$?
if [ "$RC" -eq 0 ]; then STATUS=passed; else STATUS=failed; fi
printf '{"status": "%s", "exit_code": %s, "feedback": "the check exited %s", "criteria": [{"criterion_id": "fixture-check-green", "status": "%s", "evidence": ["check.log"]}]}\n' "$STATUS" "$RC" "$RC" "$STATUS"
""",
    produces = _TEST_REPORT,
)

loop(
    body = implement,
    gate = test,
    max_iterations = 3,
    on_exhaustion = "accept",
    gate_verdict = {"field": "status", "approve": ["passed"], "refine": ["failed"], "block": ["error"]},
)

approve = stage(
    id = "approve",
    agent = "shell",
    sandbox = "verify",
    depends_on = ["test"],
    approval = True,
    approval_reason = "The loop's last test passed on the candidate. Approve to commit, land and export it.",
    run = """printf '{"decision": "approved"}\n'
""",
    outputs = {"decision": "string"},
)

park_unfinished = stage(
    id = "park_unfinished",
    agent = "workspace_effect",
    op = "park",
    depends_on = ["test"],
)

route(on = test, field = "status", arms = {"passed": approve, "failed": park_unfinished})

commit = stage(id = "commit", agent = "workspace_effect", op = "commit", depends_on = ["approve"])
promote = stage(id = "promote", agent = "workspace_effect", op = "promote", depends_on = ["commit"])
export = stage(
    id = "export",
    agent = "workspace_effect",
    op = "forge_export",
    depends_on = ["promote"],
    title = "agent-loop: a change fixed inside a kata loop",
    body = "Implemented and fixed by the loop's agent body, proven by its test gate, approved, committed, exported.",
)

workflow(
    "agent-loop",
    root = [implement, test],
    worktree_isolated = True,
    params = {
        "task": field(string(max_length = 65536)),
        "test_command": field(string(max_length = 4096)),
    },
    validation_criteria = [
        validation_criterion(
            _CRITERION_ID,
            description = "The fixture's check exits 0 on the loop's final candidate.",
            stage = "test",
            commands = ["sh tests/check.sh"],
            evidence = ["check.log"],
            required = True,
        ),
    ],
    bounds = [time_bound(7200000)],
    sandbox_profiles = {
        "verify": sandbox_profile(workspace = "ro", net = "offline"),
        "edit": sandbox_profile(workspace = "rw", net = "offline"),
    },
)
"#;

/// The loop cells' params: the task text the agent's prompt renders and the
/// command `test` runs.
const LOOP_PARAMS: [(&str, &str); 2] = [
    (
        "task",
        "Make src/app.txt contain exactly the line implemented-change.",
    ),
    ("test_command", "sh tests/check.sh"),
];

/// The fixing model. ONE turn serves every iteration; what it writes depends
/// on the tree the iteration's `/work` maps. Iteration 0 sees the seed
/// (`needs-change`) and writes a FAILING edit (`broken-change`); iteration 1
/// sees that edit — only if the loop carried iteration 0's applied delta into it
/// — and writes the fix.
fn turn_loop_fix() -> Turn {
    Turn::running(
        "if grep -q '^broken-change$' src/app.txt; then printf 'implemented-change\\n' > \
         src/app.txt; else printf 'broken-change\\n' > src/app.txt; fi",
        "done",
    )
    .usage(300, 20)
}

/// The model that never fixes it: every iteration APPENDS one more failing
/// line, so iteration `N`'s tree holds the seed line plus `N + 1` failing lines
/// and a parked tree names the iteration it came from.
fn turn_loop_never() -> Turn {
    Turn::running("printf 'broken-change\\n' >> src/app.txt", "done").usage(300, 20)
}

/// **Cell E, the fix.** A `loop()` whose body is an agent turn runs end to
/// end: iteration 0's model writes a failing edit, the gate reports
/// `failed`, iteration 1's model — reading the edit iteration 0 applied —
/// writes the fix, the gate passes, the route reaches `approve`, and
/// commit → promote → export land and push the fixed tree.
///
/// From OUTSIDE kata: the raw expansion record (`approved`, verdicts
/// `failed, passed`); trunk's tree is exactly the seed tree with iteration
/// 1's `src/app.txt` — computed by git plumbing — and never iteration 0's;
/// and the shared end state (`assert_final_state`: the committed commit is
/// trunk's tip, the export is that commit, one PR).
#[test]
#[ignore = "live end-to-end smoke; KATA_SANDBOX_REQUIRE_LIVE=1 just oci-live-smoke"]
fn an_agent_loop_fixes_its_failing_edit_and_lands_the_last_iterations_tree_live() {
    let model = MockModel::always(turn_loop_fix());
    let node = mock_node(&model, "change-agent");
    let seed = git_rev(&node.fixture.repo, "main").expect("the seed trunk");
    let pack = node.root_path.join("agent-loop.star");
    std::fs::write(&pack, LOOP_PACK_LIVE).unwrap();
    let execution = node.main.submit_with_params(&pack, &LOOP_PARAMS);

    let gate = node
        .main
        .next_gate(&execution)
        .expect("the passed arm parks the approve gate");
    assert_eq!(gate["stage_name"].as_str(), Some("approve"));
    node.main.decide(&gate, None);
    let doc = node.main.wait_terminal(&execution);
    assert_eq!(
        doc["status"].as_str(),
        Some("completed"),
        "the fixed loop completes the run: {doc}"
    );

    let (outcome, verdicts) = loop_record(&node, &execution);
    assert_eq!(outcome, "approved", "{TEST}: the loop approves");
    assert_eq!(
        verdicts,
        ["failed", "passed"],
        "{TEST}: iteration 0 failed its gate and iteration 1 passed it"
    );

    let fixed = tree_with(
        &node.fixture.repo,
        &seed,
        "src/app.txt",
        "implemented-change\n",
    );
    let broken = tree_with(&node.fixture.repo, &seed, "src/app.txt", "broken-change\n");
    let landed = tree_of(&node.fixture.repo, "main");
    assert_eq!(
        landed, fixed,
        "{TEST}: trunk's tree is iteration 1's tree (seed + the fix), computed by git"
    );
    assert_ne!(
        landed, broken,
        "{TEST}: iteration 0's failing tree never lands"
    );
    assert_eq!(
        git_rev(&node.fixture.repo, "main^").as_deref(),
        Some(seed.as_str()),
        "{TEST}: the landed commit's parent is the seed trunk — one commit, not one per \
         iteration"
    );
    assert_eq!(
        attempt_count(&node, &execution, "park_unfinished"),
        0,
        "{TEST}: the failed arm never ran"
    );
    assert_final_state(&node, &execution);
}

/// **Cell E, exhaustion.** The model never fixes it: every iteration's gate
/// reports `failed`, the loop exhausts under `on_exhaustion = "accept"`, and
/// the route reads the adopted last report — the `failed` arm's `park`
/// effect runs. Nothing lands.
///
/// From OUTSIDE kata: the raw expansion record (`exhausted`, three `failed`
/// verdicts); the `park_unfinished` effect resolved on the raw chain and
/// `approve` never minted an attempt; `parked/<exec>` exists in git and its tree is the
/// LAST iteration's (the seed line plus three failing lines — iteration 0's
/// or 1's would hold one or two); trunk, the remote and the
/// forge are untouched (`assert_no_mutation`).
#[test]
#[ignore = "live end-to-end smoke; KATA_SANDBOX_REQUIRE_LIVE=1 just oci-live-smoke"]
fn an_exhausted_agent_loop_parks_its_last_candidate_and_lands_nothing_live() {
    let model = MockModel::always(turn_loop_never());
    let node = mock_node(&model, "change-agent");
    let seed = git_rev(&node.fixture.repo, "main").expect("the seed trunk");
    let pack = node.root_path.join("agent-loop.star");
    std::fs::write(&pack, LOOP_PACK_LIVE).unwrap();
    let execution = node.main.submit_with_params(&pack, &LOOP_PARAMS);
    let doc = node.main.wait_terminal(&execution);

    let (outcome, verdicts) = loop_record(&node, &execution);
    assert_eq!(outcome, "exhausted", "{TEST}: the loop exhausts: {doc}");
    assert_eq!(
        verdicts,
        ["failed", "failed", "failed"],
        "{TEST}: every iteration's gate failed"
    );
    assert_eq!(
        completed_transitions(&node, &execution, "park_unfinished", "main_resolved"),
        1,
        "{TEST}: the accepted last report routes the failed arm — its park effect resolved: \
         {doc}"
    );
    assert_eq!(
        attempt_count(&node, &execution, "approve"),
        0,
        "{TEST}: the passed arm never ran — not even to park at its gate"
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
            "needs-change\nbroken-change\nbroken-change\nbroken-change\n",
        ),
        "{TEST}: the parked candidate is the third iteration's tree (seed + three failing lines)"
    );
}

// CELL F — the cost bound, read by the runner's own halt check
// ---------------------------------------------------------------------------

/// One agent turn under a workflow `cost_bound`, and a successor that runs
/// only if the bound does not trip. The agent is `nanocode_anthropic` on
/// `claude-sonnet-5-5` under an API key, the one kind and credential kata
/// prices (the built-in `anthropic` row).
const COST_BOUND_PACK: &str = r#"
spend = stage(
    id = "spend",
    agent = "change-agent",
    prompt = "run one cell and answer",
)

after = stage(id = "after", agent = "shell", run = "true", depends_on = ["spend"])

workflow("cost-bounded-turn", root = [spend, after], bounds = [cost_bound(0.006)])
"#;

/// A tool-using turn of two sampling responses: a Code Mode cell (1200 in, 80
/// out), then the answer (1500 in, 40 out). At the `claude-sonnet-5-5` row's $2 in
/// and $10 out per million tokens they price at 3200 and 3400 micro-USD.
fn turn_cost(request: &serde_json::Value) -> mock_provider::Reply {
    if mock_model::ran_a_tool(request) {
        Turn::answer("done").usage(1500, 40).messages_reply(request)
    } else {
        Turn::computing("text('ran');", "done")
            .usage(1200, 80)
            .messages_reply(request)
    }
}

/// **Cell F.** A turn's spend is every sampling response it made, and the
/// runner's halt check reads that sum: 3200 + 3400 = 6600 micro-USD crosses
/// `cost_bound(0.006)` (6000 micro-USD, tripped by a strictly greater total),
/// which the last response alone (3400) does not. The run fails on the cost
/// bound and `after` never mints an attempt.
///
/// From OUTSIDE kata: the mock's own log (the turn's two requests), the raw
/// `operational.db` — the accepted `spend` payload's `token_usage` (both
/// responses' tokens and their 6600 micro-USD) and `after`'s attempt count — and
/// the run document's `error`, the `bound_exceeded:` reason naming the cost
/// bound, its 6600 observed and its 6000 limit.
#[test]
#[ignore = "live end-to-end smoke; KATA_SANDBOX_REQUIRE_LIVE=1 just oci-live-smoke"]
fn a_multi_request_turn_trips_the_workflow_cost_bound_live() {
    let model = MockModel::answering(turn_cost);
    let root = node_root();
    let fixture = fixture_repo(root.path());
    let node = mock_node_on(
        root,
        fixture,
        &model,
        &[MockAgent {
            label: "change-agent",
            harness: Harness::AnthropicMock,
            model: agent_change_rig::nanocode::ANTHROPIC_MODEL,
        }],
        "agent-change-e2e",
        &[],
    );
    let pack = node.root_path.join("cost-bounded-turn.star");
    std::fs::write(&pack, COST_BOUND_PACK).unwrap();
    let execution = node.main.submit(&pack);
    let doc = node.main.wait_terminal(&execution);
    assert_eq!(
        model.requests().len(),
        2,
        "{TEST}: the mock's own log holds the turn's two requests: {doc}"
    );

    let payload: String = raw_db(&node.root_path.join("data"))
        .query_row(
            "SELECT CAST(t.payload_json AS TEXT) FROM transitions t \
             JOIN attempts a ON a.attempt_id = t.attempt_id \
             WHERE t.execution_id = ?1 AND a.stage_id = 'spend' \
             AND t.resulting_state = 'completed'",
            [ulid::Ulid::from_string(&execution).unwrap().to_bytes()],
            |row| row.get(0),
        )
        .unwrap_or_else(|error| panic!("{TEST}: `spend` was accepted: {error}; {doc}"));
    let payload: serde_json::Value = serde_json::from_str(&payload).unwrap();
    let usage = &payload["output"]["token_usage"];
    assert_eq!(
        (
            usage["input"].as_u64(),
            usage["output"].as_u64(),
            usage["cost_micro_usd"].as_u64()
        ),
        (Some(2700), Some(120), Some(6600)),
        "{TEST}: the accepted turn is priced on both responses, not the last alone: {payload}"
    );
    assert_eq!(
        attempt_count(&node, &execution, "after"),
        0,
        "{TEST}: the cost bound halted the run before its successor dispatched: {doc}"
    );
    assert_eq!(
        doc["status"].as_str(),
        Some("failed"),
        "{TEST}: the cost bound fails the run: {doc}"
    );
    // The halt's reason, as `kata run show` reports it: the workflow COST bound
    // tripped at the accepted turn's 6600 micro-USD against the pack's 6000.
    assert!(
        doc["error"].as_str().is_some_and(|reason| reason.contains(
            "bound_exceeded: workflow cost bound reached 6600 micro-USD (limit: 6000 micro-USD)"
        )),
        "{TEST}: the run's failure names the cost bound: {doc}"
    );
}

// CELL H — model reuse: an equal agent capsule adopts the first run's turn
// ---------------------------------------------------------------------------

/// An agent stage authoring `cache_policy = "model_reuse"` over a read-only
/// `/work`, its answer typed, and nothing else: two runs of it on one trunk mint
/// equal capsules.
const REUSE_PACK: &str = r#"
verdict = stage(
    id = "verdict",
    agent = "change-agent",
    prompt = "inspect the tree and return a verdict",
    sandbox = "look",
    cache_policy = "model_reuse",
    outputs = {"verdict": "string"},
)

workflow(
    "agent-reuse",
    root = [verdict],
    worktree_isolated = True,
    sandbox_profiles = {"look": sandbox_profile(workspace = "ro", net = "offline")},
)
"#;

/// **Cell H.** Run 1 executes the turn inside a real container; run 2 — same
/// pack, same trunk, same prompt, adapter, model and budgets — mints the equal
/// capsule and ADOPTS run 1's turn instead of running its own.
///
/// From OUTSIDE kata: the mock's own log holds run 1's one request and nothing
/// for run 2; the raw `operational.db` shows run 2's accepting attempt resolved
/// main-side (`executor = 'main'`), no capsule row and no attempt command for
/// run 2 (nothing was dispatched to a worker), and its accepting payload carries
/// run 1's answer, `reused_from` naming run 1, and an authoritative ZERO charge —
/// run 1's spend is never carried twice.
///
/// **Would red if:** run 2 ran its own turn (a second request in the mock's log,
/// a capsule row), named no `reused_from`, or re-charged run 1's tokens.
#[test]
#[ignore = "live end-to-end smoke; KATA_SANDBOX_REQUIRE_LIVE=1 just oci-live-smoke"]
fn a_second_equal_agent_stage_adopts_the_first_turn_and_runs_no_container_live() {
    let model = MockModel::always(Turn::answer("{\"verdict\": \"ship\"}").usage(1200, 80));
    let node = mock_node(&model, "change-agent");
    let pack = node.root_path.join("agent-reuse.star");
    std::fs::write(&pack, REUSE_PACK).unwrap();

    let first = node.main.submit(&pack);
    let doc = node.main.wait_terminal(&first);
    assert_eq!(doc["status"].as_str(), Some("completed"), "run 1: {doc}");
    assert_eq!(
        model.requests().len(),
        1,
        "{TEST}: run 1's turn made one request"
    );

    let second = node.main.submit(&pack);
    let doc = node.main.wait_terminal(&second);
    assert_eq!(doc["status"].as_str(), Some("completed"), "run 2: {doc}");
    assert_eq!(
        model.requests().len(),
        1,
        "{TEST}: the mock received nothing for run 2: its turn was adopted, not run"
    );

    let conn = raw_db(&node.root_path.join("data"));
    let run2 = ulid::Ulid::from_string(&second).unwrap().to_bytes();
    let (executor, capsule_rows, commands): (String, i64, i64) = conn
        .query_row(
            "SELECT
                (SELECT a.executor FROM occurrences o
                   JOIN attempts a ON a.attempt_id = o.accepted_attempt_id
                  WHERE o.execution_id = ?1),
                (SELECT count(*) FROM capsules c JOIN occurrences o
                    ON o.occurrence_id = c.occurrence_id WHERE o.execution_id = ?1),
                (SELECT count(*) FROM attempt_commands WHERE attempt_id IN
                    (SELECT attempt_id FROM attempts WHERE execution_id = ?1))",
            [run2.as_slice()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .expect("run 2's durable footprint is readable");
    assert_eq!(executor, "main", "{TEST}: a reuse is resolved main-side");
    assert_eq!(capsule_rows, 0, "{TEST}: no capsule was declared for run 2");
    assert_eq!(
        commands, 0,
        "{TEST}: no attempt command was ever readied, so nothing was dispatched to a worker"
    );
    let payload: String = conn
        .query_row(
            "SELECT CAST(t.payload_json AS TEXT)
               FROM occurrences o
               JOIN transitions t ON t.attempt_id = o.accepted_attempt_id
                                 AND t.resulting_state = 'completed'
              WHERE o.execution_id = ?1",
            [run2.as_slice()],
            |row| row.get(0),
        )
        .expect("the accepting transition's payload is readable");
    let payload: serde_json::Value = serde_json::from_str(&payload).unwrap();
    let adopted = &payload["output"];
    assert_eq!(
        adopted["reused_from"]["execution"],
        first.as_str(),
        "{TEST}: reused_from names run 1: {adopted}"
    );
    assert!(
        adopted.to_string().contains("ship"),
        "{TEST}: the response is run 1's: {adopted}"
    );
    assert_eq!(
        adopted["token_usage"]["cost"]["quality"], "authoritative",
        "{TEST}: the zero spend is authoritative, not estimated: {adopted}"
    );
    assert_eq!(adopted["token_usage"]["cost"]["micro_usd"], 0);
    assert_eq!(adopted["token_usage"]["input"], 0);
    assert_eq!(adopted["token_usage"]["output"], 0);
    assert_eq!(
        adopted["agent"]["adapter"], "nanocode_openai",
        "{TEST}: the agent band survived the adoption: {adopted}"
    );
}

// ---------------------------------------------------------------------------
// CELL I — a provider failing its response mid-turn
// ---------------------------------------------------------------------------

/// The failed-response cell's pack: one agent stage over a writable, offline
/// `/work`, so a run whose one turn fails has nothing behind it to wait on. Its
/// agent is a two-member fallback panel, so a failed turn has a NEXT seat the
/// runner's failure retry would run it on were its failure retryable: the
/// second member pins [`SECOND_OPENAI_MODEL`], and any request naming that model
/// in the mock's log is a re-run.
const FAILED_RESPONSE_PACK_LIVE: &str = "implement = stage(\n\
     \x20   id = \"implement\",\n\
     \x20   agent = [\"change-agent\", \"fallback-agent\"],\n\
     \x20   prompt = \"Make src/app.txt contain exactly the line implemented-change.\",\n\
     \x20   sandbox = \"edit\",\n\
     )\n\
     workflow(\"provider-failed-response\", root = [implement], worktree_isolated = True,\n\
     \x20   sandbox_profiles = {\"edit\": sandbox_profile(workspace = \"rw\", net = \"offline\")})\n";

/// The line the turn's command writes into `/work` before the model call whose
/// response the provider fails.
const WRITTEN_BEFORE_THE_FAILURE: &str = "written-before-the-failure";

/// The provider's error object the failed response carries: a code nanocode
/// reads as terminal (`is_terminal_response_failure`), so it neither retries
/// nor reconnects the call, and that names neither code kata's
/// `provider_failure` classifies by name.
const FAILED_RESPONSE_CODE: &str = "insufficient_quota";

/// **Cell I — a model provider that fails its response mid-turn leaves the
/// attempt PROVEN AMBIGUOUS: never accepted, never re-run, nothing
/// published.** The turn's first response asks for one `exec_command`, which
/// runs inside the real container and writes `src/app.txt`; the mock then
/// begins the turn's second response — `response.created` and a text delta —
/// and ends it with a `response.failed` event whose error names
/// [`FAILED_RESPONSE_CODE`], over the Responses HTTPS SSE transport the rig's
/// door runs. kata's provider-failure classification (`docs/development/nanocode.md`,
/// "A turn the provider failed"; `kata_agent_nanocode::adapter::session::provider_failure`)
/// makes a turn end a provider failure — refused, or transient and re-run —
/// only on the harness's own typed error: a 4xx answer, retry advice, or a code
/// it names. A `response.failed` event is nanocode's `ResponsesError::Api`
/// stating no HTTP status, and nanocode reads this code as terminal
/// (`is_terminal_response_failure`), so it neither retries nor reconnects the
/// call (`ResponsesRetryPolicy::retry`, `reconnectable`) and gives no retry
/// advice; the turn is `Ambiguous` (the WebSocket twin: `nanocode_qualification`'s
/// `a_websocket_error_event_with_a_4xx_status_is_the_providers_refusal`, its
/// `response.failed` row) and the worker settles it PROVEN AMBIGUOUS: a turn
/// whose answer is unknown may have done anything, so the runner never re-runs
/// it (`uncertainty-not-reissued`) — not even on the stage's fallback panel's
/// next member, the seat its failure retry would otherwise mint — and the run
/// fails. Asserted from OUTSIDE kata: the raw `operational.db` (one attempt on
/// the stage, `failed`, its terminal payload's `verdict` `proven_ambiguous`
/// carrying the provider's failed event, and no `provider_failure`, no
/// accepted attempt, the execution's head never advanced), the mock's own
/// request log (the command, then the failed response, both naming the first
/// member's model, and no third request — no re-send and no request naming the
/// second member's model), and `git` on the fixture (trunk where it was, the
/// turn's write on no commit).
///
/// A response whose connection is cut mid-body is no such trigger: nanocode
/// reports the cut as a retryable transport failure and reconnects the call,
/// so a cut its reconnects do not outlast is the provider's TRANSIENT failure,
/// not an unknown answer (`nanocode_qualification`'s
/// `a_model_connection_dropped_mid_response_is_a_transient_failure`).
///
/// **Would red if:** the failed response were settled PROVEN NOT PERFORMED or
/// classed a provider failure (watched: `agent_turn`'s `Ambiguous` arm settling
/// through `with_verdict(.., ProvenNotPerformed)`), the runner's failure retry
/// admitted PROVEN AMBIGUOUS (watched: `failure_is_retryable` matching
/// `proven_ambiguous`, which ran the panel's second member), nanocode began
/// retrying a terminal `response.failed` (a third request on the first
/// member's model), or the turn's `/work` write were published.
#[test]
#[ignore = "live end-to-end smoke; KATA_SANDBOX_REQUIRE_LIVE=1 just oci-live-smoke"]
fn a_provider_failing_its_response_mid_turn_settles_proven_ambiguous_live() {
    let model = MockModel::answering(|request| {
        if model_of(request) == SECOND_OPENAI_MODEL {
            // The panel's second member: a turn that would complete, so a re-run
            // shows as its request in the log and a run that did not fail.
            Turn::running("true", "done").reply(request)
        } else if mock_model::ran_a_tool(request) {
            mock_provider::Reply::Events(vec![
                serde_json::json!({"type": "response.created", "response": {"id": "failed"}}),
                serde_json::json!({
                    "type": "response.output_text.delta", "output_index": 0, "delta": "do",
                }),
                serde_json::json!({
                    "type": "response.failed",
                    "response": {"id": "failed", "error": {
                        "type": FAILED_RESPONSE_CODE, "code": FAILED_RESPONSE_CODE,
                        "message": "mock: the response failed mid-turn",
                    }},
                }),
            ])
        } else {
            Turn::running(
                &format!("printf '{WRITTEN_BEFORE_THE_FAILURE}\\n' > src/app.txt"),
                "done",
            )
            .reply(request)
        }
    });
    let root = node_root();
    let fixture = fixture_repo(root.path());
    let node = mock_node_on(
        root,
        fixture,
        &model,
        &[
            MockAgent::openai("change-agent"),
            MockAgent {
                model: SECOND_OPENAI_MODEL,
                ..MockAgent::openai("fallback-agent")
            },
        ],
        "agent-change-e2e",
        &[],
    );
    let trunk_before = git_out(&node.fixture.repo, &["rev-parse", &node.fixture.trunk]);
    let pack = node.root_path.join("provider-failed-response.star");
    std::fs::write(&pack, FAILED_RESPONSE_PACK_LIVE).unwrap();
    let execution = node.main.submit(&pack);
    let doc = node.main.wait_terminal(&execution);
    assert_eq!(
        doc["status"].as_str(),
        Some("failed"),
        "{TEST}: an ambiguous turn fails its stage and is not re-run: {doc}"
    );

    // THE MOCK'S OWN LOG: the turn's command, then the response it failed, both
    // on the first member's model — and no third request: neither a re-send nor
    // the panel's second member re-running the stage.
    let requests = model.requests();
    let models: Vec<&str> = requests.iter().map(model_of).collect();
    assert_eq!(
        models,
        [
            agent_change_rig::nanocode::OPENAI_MODEL,
            agent_change_rig::nanocode::OPENAI_MODEL
        ],
        "{TEST}: the mock received the first member's two requests and nothing after \
         the failed response — no request naming the second member's model \
         {SECOND_OPENAI_MODEL}"
    );
    assert!(
        !mock_model::ran_a_tool(&requests[0]) && mock_model::ran_a_tool(&requests[1]),
        "{TEST}: the failed response answered the request carrying the command's output"
    );

    // RAW SQLITE, through a second read-only handle.
    let conn = raw_db(&node.root_path.join("data"));
    let exec_bytes = ulid::Ulid::from_string(&execution).unwrap().to_bytes();
    let attempts: Vec<(Vec<u8>, String)> = conn
        .prepare(
            "SELECT a.attempt_id, p.state FROM attempts a JOIN attempt_projection p \
             ON p.execution_id = a.execution_id AND p.stage_id = a.stage_id \
             AND p.attempt_ordinal = a.attempt_ordinal \
             WHERE a.execution_id = ?1 AND a.stage_id = 'implement' \
             ORDER BY a.attempt_ordinal",
        )
        .unwrap()
        .query_map([exec_bytes.as_slice()], |row| {
            Ok((row.get(0)?, row.get(1)?))
        })
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    assert_eq!(
        attempts
            .iter()
            .map(|(_, state)| state.as_str())
            .collect::<Vec<_>>(),
        ["failed"],
        "{TEST}: exactly one attempt on the stage, failed — no re-run"
    );
    let terminal: String = conn
        .query_row(
            "SELECT CAST(payload_json AS TEXT) FROM transitions \
             WHERE attempt_id = ?1 AND scope = 'attempt' AND resulting_state = 'failed' \
             ORDER BY seq DESC LIMIT 1",
            [attempts[0].0.as_slice()],
            |row| row.get(0),
        )
        .expect("the failed attempt's terminal transition is readable");
    let terminal: serde_json::Value = serde_json::from_str(&terminal).unwrap();
    assert_eq!(
        terminal["verdict"], "proven_ambiguous",
        "{TEST}: a turn whose answer is unknown is PROVEN AMBIGUOUS: {terminal}"
    );
    assert!(
        terminal["provider_failure"].is_null(),
        "{TEST}: the failed response is no provider failure, refused or transient: \
         {terminal}"
    );
    let reason = terminal["reason"].as_str().unwrap_or_default();
    assert!(
        reason.starts_with("the turn's answer is unknown")
            && reason.contains("Responses API returned an error event")
            && reason.contains("response.failed")
            && reason.contains(FAILED_RESPONSE_CODE),
        "{TEST}: the settlement carries the harness's account of the failed response: \
         {terminal}"
    );
    let accepted: Option<Vec<u8>> = conn
        .query_row(
            "SELECT o.accepted_attempt_id FROM occurrences o JOIN attempts a \
             ON a.occurrence_id = o.occurrence_id WHERE a.attempt_id = ?1",
            [attempts[0].0.as_slice()],
            |row| row.get(0),
        )
        .expect("the stage's occurrence row is readable");
    assert_eq!(accepted, None, "{TEST}: an ambiguous turn accepts nothing");
    let head_seq: i64 = conn
        .query_row(
            "SELECT head_seq FROM execution_work_tree_heads WHERE execution_id = ?1",
            [exec_bytes.as_slice()],
            |row| row.get(0),
        )
        .expect("the execution's head row is readable");
    assert_eq!(
        head_seq, 0,
        "{TEST}: no apply advanced the head: the turn's /work delta was never published"
    );

    // GIT, on the fixture: trunk where it was, and the turn's write on no commit.
    assert_eq!(
        git_out(&node.fixture.repo, &["rev-parse", &node.fixture.trunk]),
        trunk_before,
        "{TEST}: trunk did not move"
    );
    assert!(
        git_out(&node.fixture.repo, &["log", "--all", "-p", "--format=%H"])
            .lines()
            .all(|line| !line.contains(WRITTEN_BEFORE_THE_FAILURE)),
        "{TEST}: the turn's write before the failed response reached no commit"
    );
}

/// The line the cut turn's command writes into `/work` before the model call
/// whose response the provider cuts.
const WRITTEN_BEFORE_THE_CUT: &str = "written-before-the-cut";

/// The requests one attempt of the cut cell's first member sends: the call
/// that runs the command, then the call whose response the mock cuts, sent
/// once and re-sent by nanocode five times (`STREAM_MAX_RETRIES`) past the one
/// attempt kata configures.
const CUT_ATTEMPT_REQUESTS: usize = 1 + 6;

/// **Cell I′ — a model provider that cuts its response mid-body, mid-turn,
/// fails the attempt TRANSIENTLY: PROVEN NOT PERFORMED, re-run on the same
/// agent, then on the fallback panel's next member, which completes.** The
/// twin of cell I for the trigger nanocode no longer reports as an unknown
/// answer: the first member's first response asks for one `exec_command`, which
/// writes `src/app.txt` in the real container; the mock then begins the second
/// response — its head declaring the whole body — and drops the connection
/// before the terminal event, on the call and on each of nanocode's re-sends.
/// Since nanocode 8ec3b215 that cut is a retryable transport failure, so the
/// turn ends `ProviderFailed` classed `Transient`
/// (`nanocode_qualification`'s
/// `a_model_connection_dropped_mid_response_is_a_transient_failure`), the
/// worker settles it PROVEN NOT PERFORMED with `provider_failure` `transient`
/// (the capsule is offline), and the runner re-runs the stage on the same agent
/// twice (`TRANSIENT_PROVIDER_RERUNS`, after 30 s and 120 s), then walks to the
/// panel's second member, whose turn completes. Asserted from OUTSIDE kata: the
/// mock's own log (three attempts' [`CUT_ATTEMPT_REQUESTS`] on the first
/// member's model, then requests naming only [`SECOND_OPENAI_MODEL`]), the raw
/// `operational.db` through a second read-only handle (four attempts on the
/// stage, the first three `failed` with `verdict` `proven_not_performed` and
/// `provider_failure` `transient`, each charged `unavailable`, the fourth
/// accepted), and `git` (the cut attempts' write on no commit).
///
/// **Would red if:** the cut were settled PROVEN AMBIGUOUS (as at nanocode
/// 2ac77424: one attempt, the run failed), the runner did not re-run a
/// transient failure or did not walk to the fallback (fewer attempts). The
/// `unavailable` cost holds on the charge before as well (the rig's first
/// call reports no usage); `nanocode_qualification`'s
/// `a_failed_turn_with_a_resent_attempt_is_charged_unknown` pins the charge.
#[test]
#[ignore = "live end-to-end smoke; KATA_SANDBOX_REQUIRE_LIVE=1 just oci-live-smoke"]
fn a_provider_cutting_its_response_mid_turn_is_re_run_then_falls_back_live() {
    let model = MockModel::answering(|request| {
        if model_of(request) == SECOND_OPENAI_MODEL {
            Turn::running("printf 'implemented-change\\n' > src/app.txt", "done").reply(request)
        } else if mock_model::ran_a_tool(request) {
            let mock_provider::Reply::Events(answer) =
                mock_provider::message_reply("cut", "done", mock_provider::usage(10, 0, 1))
            else {
                unreachable!("a message reply is a stream of events")
            };
            mock_provider::Reply::DropMidResponse(answer)
        } else {
            Turn::running(
                &format!("printf '{WRITTEN_BEFORE_THE_CUT}\\n' > src/app.txt"),
                "done",
            )
            .reply(request)
        }
    });
    let root = node_root();
    let fixture = fixture_repo(root.path());
    let node = mock_node_on(
        root,
        fixture,
        &model,
        &[
            MockAgent::openai("change-agent"),
            MockAgent {
                model: SECOND_OPENAI_MODEL,
                ..MockAgent::openai("fallback-agent")
            },
        ],
        "agent-change-e2e",
        &[],
    );
    let pack = node.root_path.join("provider-cut-response.star");
    std::fs::write(&pack, FAILED_RESPONSE_PACK_LIVE).unwrap();
    let execution = node.main.submit(&pack);
    let doc = node.main.wait_terminal(&execution);
    assert_eq!(
        doc["status"].as_str(),
        Some("completed"),
        "{TEST}: the fallback member's re-run completes the stage: {doc}"
    );

    // THE MOCK'S OWN LOG: three attempts on the first member's model, each the
    // command's call and the cut call with nanocode's re-sends of it, then the
    // second member's turn.
    let requests = model.requests();
    let models: Vec<&str> = requests.iter().map(model_of).collect();
    let first = 3 * CUT_ATTEMPT_REQUESTS;
    assert!(
        models.len() > first
            && models[..first]
                .iter()
                .all(|model| *model == agent_change_rig::nanocode::OPENAI_MODEL)
            && models[first..]
                .iter()
                .all(|model| *model == SECOND_OPENAI_MODEL),
        "{TEST}: three attempts of {CUT_ATTEMPT_REQUESTS} requests on the first member, \
         then the second member's: {models:?}"
    );

    // RAW SQLITE, through a second read-only handle.
    let conn = raw_db(&node.root_path.join("data"));
    let exec_bytes = ulid::Ulid::from_string(&execution).unwrap().to_bytes();
    let attempts: Vec<(Vec<u8>, String)> = conn
        .prepare(
            "SELECT a.attempt_id, p.state FROM attempts a JOIN attempt_projection p \
             ON p.execution_id = a.execution_id AND p.stage_id = a.stage_id \
             AND p.attempt_ordinal = a.attempt_ordinal \
             WHERE a.execution_id = ?1 AND a.stage_id = 'implement' \
             ORDER BY a.attempt_ordinal",
        )
        .unwrap()
        .query_map([exec_bytes.as_slice()], |row| {
            Ok((row.get(0)?, row.get(1)?))
        })
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    assert_eq!(
        attempts
            .iter()
            .map(|(_, state)| state.as_str())
            .collect::<Vec<_>>(),
        ["failed", "failed", "failed", "completed"],
        "{TEST}: the cut attempt and its two transient re-runs failed, the fallback completed"
    );
    for (attempt, _) in &attempts[..3] {
        let terminal: String = conn
            .query_row(
                "SELECT CAST(payload_json AS TEXT) FROM transitions \
                 WHERE attempt_id = ?1 AND scope = 'attempt' AND resulting_state = 'failed' \
                 ORDER BY seq DESC LIMIT 1",
                [attempt.as_slice()],
                |row| row.get(0),
            )
            .expect("the failed attempt's terminal transition is readable");
        let terminal: serde_json::Value = serde_json::from_str(&terminal).unwrap();
        assert_eq!(
            terminal["verdict"], "proven_not_performed",
            "{TEST}: the cut is the provider's known failure: {terminal}"
        );
        assert_eq!(
            terminal["provider_failure"], "transient",
            "{TEST}: classed transient: {terminal}"
        );
        assert!(
            terminal["reason"]
                .as_str()
                .unwrap_or_default()
                .contains("connection closed before message completed"),
            "{TEST}: the reason is nanocode's account of the cut: {terminal}"
        );
        assert_eq!(
            terminal["terminal_charge"]["token_usage"]["cost"]["quality"], "unavailable",
            "{TEST}: a re-sent stream may have billed what no event reports: {terminal}"
        );
    }

    // GIT: the cut attempts' write reached no commit.
    assert!(
        git_out(&node.fixture.repo, &["log", "--all", "-p", "--format=%H"])
            .lines()
            .all(|line| !line.contains(WRITTEN_BEFORE_THE_CUT)),
        "{TEST}: the cut attempts' write reached no commit"
    );
}

/// `git <args>` on `repo` under the hermetic prefix; its trimmed stdout.
fn git_out(repo: &Path, args: &[&str]) -> String {
    let out = kata_test_utils::git::hermetic_git_in(repo)
        .args(args)
        .output()
        .expect("git runs");
    assert!(
        out.status.success(),
        "git {args:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).trim().to_owned()
}

// ---------------------------------------------------------------------------
// CELL J — a lifted key split across text deltas, read off the SSE stream
// ---------------------------------------------------------------------------

/// The agent-change pack with `implement`'s progress raised to `full`: the
/// observations' text, not only their heads, reaches event-stream subscribers.
fn full_progress_pack(root: &Path) -> std::path::PathBuf {
    let shipped = std::fs::read_to_string(repo_root().join(PACK)).unwrap();
    let anchor =
        "in the working tree, not in a stash.\n\"\"\",\n    progress_visibility = \"summary\",\n";
    assert_eq!(
        shipped.matches(anchor).count(),
        1,
        "{TEST}: the agent-change pack's `implement` no longer ends on its summary visibility"
    );
    let pack = shipped.replacen(anchor, &anchor.replace("\"summary\"", "\"full\""), 1);
    let path = root.join("agent-change-full.star");
    std::fs::write(&path, pack).unwrap();
    path
}

/// **Cell J.** The model streams the stage's own lifted credential — the fake
/// key the worker's `env:OPENAI_API_KEY` carries — split across two text
/// deltas, under `progress_visibility = "full"`, and it does not reach an SSE
/// subscriber. The mock holds the second delta until the subscriber has read a
/// preview of the first, so the harness cannot join them. The oracle is the raw
/// bytes a bare TCP reader took off `GET /api/v1/events`, never kata's own
/// reading of them: the raw transcript carries neither the key nor either half
/// of it, and no `progress` preview parsed out of it carries a 4-byte window of
/// the key, while a preview carries the text after the key — the positive
/// control that `full` previews reached the reader at all.
///
/// **Would red if:** the progress scrub ran per delta (the second delta's head
/// is the key's tail, whatever frame coalescing keeps).
#[test]
#[ignore = "live end-to-end smoke; KATA_SANDBOX_REQUIRE_LIVE=1 just oci-live-smoke"]
fn a_lifted_key_split_across_text_deltas_never_reaches_an_sse_subscriber_live() {
    const BEFORE: &str = "PRELUDE-MARK ";
    const AFTER: &str = " CODA-MARK";
    let key = agent_change_rig::nanocode::FAKE_OPENAI_KEY;
    let (head, tail) = key.split_at(key.len() / 2);
    // The second delta is held until a subscriber has seen the first: nanocode
    // joins deltas it finds already buffered, so only a pause makes it read
    // the key's head alone.
    let first_seen = mock_provider::Gate::default();
    let gate = first_seen.clone();
    let model = MockModel::answering(move |_request| {
        let delta = |text: String| {
            serde_json::json!({
                "type": "response.output_text.delta",
                "output_index": 0,
                "delta": text,
            })
        };
        mock_provider::Reply::Paused {
            head: vec![
                serde_json::json!({"type": "response.created", "response": {"id": "split"}}),
                delta(format!("{BEFORE}{head}")),
            ],
            gate: gate.clone(),
            rest: vec![
                delta(format!("{tail}{AFTER}")),
                serde_json::json!({
                    "type": "response.output_item.done",
                    "output_index": 0,
                    "item": {
                        "type": "message",
                        "id": "msg_split",
                        "role": "assistant",
                        "content": [{"type": "output_text", "text": "done"}],
                    },
                }),
                serde_json::json!({
                    "type": "response.completed",
                    "response": {"id": "split", "model": "gpt-6-luna", "usage": mock_provider::usage(10, 0, 1)},
                }),
            ],
        }
    });
    let node = mock_node(&model, "change-agent");
    let pack = full_progress_pack(&node.root_path);
    let transcript = node.root_path.join("sse-transcript.txt");
    let sse = SseRecorder::start(node.main.port(), transcript.clone());
    // Progress frames are not replayed to a late subscriber: connect first.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    while !std::fs::read_to_string(&transcript)
        .unwrap_or_default()
        .contains("#connected")
    {
        assert!(
            std::time::Instant::now() < deadline,
            "{TEST}: the SSE recorder never connected"
        );
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    let execution = node.main.submit(&pack);
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(120);
    while !parse_transcript(&std::fs::read_to_string(&transcript).unwrap_or_default())
        .iter()
        .any(|event| event.name == "progress" && event.preview().contains("PRELUDE-MARK"))
    {
        assert!(
            std::time::Instant::now() < deadline,
            "{TEST}: the first delta never reached the subscriber"
        );
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    first_seen.open();
    // No edit lands, so the criterion fails the run: the turn is all this cell needs.
    node.main.wait_terminal(&execution);
    drop(sse);

    let raw = std::fs::read_to_string(&transcript).expect("the transcript is on disk");
    let previews: Vec<String> = parse_transcript(&raw)
        .iter()
        .filter(|event| event.name == "progress")
        .map(|event| event.preview().to_owned())
        .collect();
    assert!(
        previews.iter().any(|preview| preview.contains("CODA-MARK")),
        "{TEST}: no `full` preview of the turn's text reached the subscriber, so the cell \
         proves nothing: {previews:?}"
    );
    for piece in [key, head, tail] {
        assert!(
            !raw.contains(piece),
            "{TEST}: the raw SSE transcript carries `{piece}` of the lifted key"
        );
    }
    for preview in &previews {
        for window in key.as_bytes().windows(4) {
            let window = std::str::from_utf8(window).expect("the key is ASCII");
            assert!(
                !preview.contains(window),
                "{TEST}: a progress preview carries `{window}` of the lifted key: {previews:?}"
            );
        }
    }
}
