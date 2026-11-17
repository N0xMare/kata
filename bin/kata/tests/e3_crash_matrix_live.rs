//! **E3 — the crash / restart matrix** (D2 §5.4), on the `agent_change_rig` node:
//! an installed `kata serve` main plus an external `kata-worker` daemon, the shipped
//! `change` pack, a jj-colocated fixture with a LOCAL bare `origin` and a fake `gh`
//! (P4 may select a real forge instead: [The forge](#the-forge-kata_e3_forge_clone)).
//! After any main kill the worker daemon is restarted too: its transport died with the
//! main, and a fresh daemon re-registers.
//!
//! # The cells
//!
//! | test | case | kill | expected settlement |
//! |---|---|---|---|
//! | `e3_gate_main_kill_live` | `gate-main-kill` | SIGKILL the main at the parked `approve` gate | `resumed-at-gate` |
//! | `e3_gate_worker_kill_live` | `gate-worker-kill` | SIGKILL the worker at the parked gate | `resumed-at-gate` |
//! | `e3_p1_placed_not_sent_live` | `P1` | `operational.after_capsule_dispatched_before_send` on the main | `proven-ambiguous` |
//! | `e3_p2_model_call_in_flight_live` | `P2` | SIGKILL the worker while `implement`'s model call is open in the client-side SSE transcript | `proven-ambiguous` |
//! | `e3_p3_after_turn_before_acceptance_live` | `P3` | `operational.after_container_exited_before_result_published` on the FIRST worker | `proven-ambiguous` |
//! | `e3_p4_between_push_and_pr_live` | `P4` | `operational.after_forge_push_before_pr` on the main | `pr-opened-once` |
//! | `e3_p1_host_live` … `e3_p4_host_live` (in `e3_crash_matrix_host_live`) | `P1-host` … `P4-host` | the whole machine, through `KATA_E3_HOST_KILL_CMD` | the same |
//!
//! An armed boundary fires at its FIRST crossing, so P1 and P3 land on the run's first
//! agent turn (`plan`); P2 targets `implement`, whose `/work` is writable.
//!
//! P3 is WORKER-side. The capsule completion is adopted and accepted in ONE main
//! transaction (`OperationalDb::adopt_and_accept_capsule_completion`) and is never
//! buffered in `event_inbox`, so no main-side point lies between a finished turn and its
//! acceptance that leaves anything durable; and capsule re-delivery is not implemented
//! (the settlement reasons in `kata-workflow`'s `capsule_settlement` say so), so a result
//! the main never committed is never accepted later. D2 §5.4's exactly-once acceptance
//! of such a turn is therefore not claimed while re-delivery is unimplemented. This point
//! is the last moment of the turn a kill can land on: the container has exited, `/out`
//! is on the worker's disk, and no `CompletedCapsule` frame left. The main's
//! worker-death leg settles it PROVEN AMBIGUOUS; it is never re-delivered, and the cell
//! refuses a second attempt row or a second claim ([`judge_p3_counts`]).
//!
//! # Positive controls (a cell lacking one is VOID, never passed)
//!
//! Every fault-injected cell: (1) its `KATA_FAULT_INJECT` value is `operational.<b>` with
//! `<b>` a member of `kata_core::fault_inject::OPERATIONAL_CRASH_BOUNDARIES` — the cell
//! refuses to start otherwise ([`fault_inject_value`]); (2) the killed process's log (the
//! main's, or P3's worker's) carries
//! `[kata-fault-inject] crash point reached: operational.<b>` with `action=abort` (the
//! whole line, [`abort_line`]); (3) its wait status is death by SIGABRT. A cell refuses
//! to start when the caller's environment sets `KATA_FAULT_INJECT` or
//! `KATA_FAULT_INJECT_ACTION`: the rig's processes inherit it, so it would arm the
//! restarted mains and workers too. P2's control is read post hoc from the client-side SSE transcript: the
//! killed attempt's last model-call frame is a start with no later completion and no
//! terminal frame; a run without one is VOID and re-run, at most three tries, then the
//! cell fails `in-flight kill not achieved`. The gate cells' control: no model call is
//! open in the transcript at the kill.
//!
//! The SSE transcript needs progress frames, which the shipped pack does not stream
//! (`progress_visibility` defaults to `off`): every cell submits a copy of
//! `workflows/std/change.star` whose `plan` and `implement` add
//! `progress_visibility = "summary"` and nothing else.
//!
//! # The agent (`KATA_E3_AGENT`)
//!
//! `nanocode-mock` (the default: `nanocode_openai` against a scripted mock provider on
//! the loopback, through the worker's `test-support` endpoint door under a fake key — no
//! model, no spend; `plan` answers its `Plan`, `implement` writes the fix, or for P2
//! holds its first request open), `nanocode-openai` (`nanocode_openai` under kata's own
//! ChatGPT login) or `nanocode-anthropic` (`nanocode_anthropic` under
//! `env:ANTHROPIC_API_KEY`). The same cells run on each; a provider-backed agent spends
//! model budget, so it is refused unless `KATA_E3_FUNDED=1` is also set. The nanocode
//! node reads `KATA_E3_MODEL` / `KATA_E3_EFFORT` (default `gpt-6-luna` / `medium` on
//! OpenAI and the mock, `claude-sonnet-5-5` / `medium` on Anthropic) and provisions the
//! static tool host from `KATA_E3_TOOLHOST` (default: this target directory's musl debug
//! `kata-toolhost`). The host column refuses the mock: the machine's kill ends the test
//! process that serves it.
//!
//! # The forge (`KATA_E3_FORGE_CLONE`)
//!
//! P4 exports to the rig's local bare `origin` through the fake `gh` unless
//! `KATA_E3_FORGE_CLONE` names a local clone of our `kata-e2-fixture` whose `origin` is
//! the real forge. Then P4's node works in a fresh clone of it (`fixture_repo_cloned`:
//! `origin` the clone's URL, the trunk the forge's, the rig's seed committed on top and
//! carried to the forge by the exported branch), its main runs the host's own `gh` (no
//! shim), and P4 reads the forge itself: `git ls-remote origin refs/heads/kata/<exec>` and
//! `gh pr list --state all --head kata/<exec> --json number`. It pushes a branch and opens
//! a pull request there, so it is refused unless `KATA_E3_FUNDED=1` is set too
//! ([`select_forge_clone`]). Only P4 reads it; every other cell, and the host column,
//! stays on the local forge.
//!
//! # Evidence
//!
//! Every cell writes one record per try, in the `docs/evidence/runs/<run-id>/run.toml`
//! shape, under `KATA_E3_EVIDENCE_DIR` (default `target/e3-evidence/`): `run.toml`,
//! `oracle.txt` (every outside-kata read the outcome rests on), `sse-transcript.txt`,
//! `change.star` (the pack copy the run submitted), `tree.txt` (`git rev-parse HEAD`,
//! `HEAD^{tree}` and `git status --porcelain`: a dirty tree is also named in
//! `outcome_source`, since `kata_sha` is then only its base), and for P2 `recourse.txt`
//! (the operator's CLI recourse, run). The record states `kata_sha` and its tree,
//! `kata_tree`. A judged record's `tokens_recorded` is kata's known part, the completed
//! agent attempts' recorded usage read raw, and its `unmetered_calls` the issued calls
//! whose usage is unknown: every call the transcript shows of an attempt that never
//! completed, counted by `CallCount::unmetered` in every judge (P1, the gate cells and P4,
//! which kill no model call, require 0 as an oracle). A VOID record states the control that did not hold as its `void_reason`
//! (`oracle.txt: VOID: …`, the oracle's last line), and `settlement = "other"` with the
//! same reason in `settlement_detail`; the host column's VOIDs are recorded the same way.
//! A mock record names `harness = "nanocode-mock"`, which `just evidence-check` refuses,
//! so a no-spend run can never be committed as evidence. A funded record's SSE transcript
//! carries model-text previews: run `just evidence-sanitize` on it, and read it, before
//! committing.
//!
//! # Where it runs
//!
//! `just oci-live-smoke` runs this binary's process column in L1 (its eighth step, on the
//! mock, with `KATA_E3_AGENT`, `KATA_E3_FUNDED` and `KATA_E3_FORGE_CLONE` unset), and
//! `just e3-crash-matrix` runs it alone, or on a funded agent; its host-free cells ride
//! `just test`. The host column is its own binary,
//! `e3_crash_matrix_host_live`, which no gate runs. Both share the rig in
//! `e3_matrix/`.

#![cfg(target_os = "linux")]
mod agent_change_rig;
mod e3_matrix;
#[allow(dead_code)]
mod mock_model;
#[path = "../../../crates/agent-nanocode/tests/fixtures/mock_provider.rs"]
#[allow(dead_code)]
mod mock_provider;
use agent_change_rig::*;
use e3_matrix::*;
use std::collections::BTreeMap;
use std::os::unix::process::ExitStatusExt as _;
use std::path::PathBuf;
use std::time::Duration;

/// **gate-main-kill.** SIGKILL the main while the run waits at `approve`; the next main
/// and a fresh worker re-list the SAME parked assignment, the decision lands, and the run
/// completes once (one commit, one push, one PR, no residue).
#[test]
#[ignore = "E3 process column: `just oci-live-smoke` (L1) or `just e3-crash-matrix`"]
fn e3_gate_main_kill_live() {
    gate_cell("gate-main-kill", GateKill::Main);
}
/// **gate-worker-kill.** The same, killing the worker daemon at the parked gate.
#[test]
#[ignore = "E3 process column: `just oci-live-smoke` (L1) or `just e3-crash-matrix`"]
fn e3_gate_worker_kill_live() {
    gate_cell("gate-worker-kill", GateKill::Worker);
}
/// **P1, placed not sent.** The main aborts after the plan capsule's placement committed
/// and before its frame was sent. At restart the attempt settles PROVEN AMBIGUOUS and is
/// never re-delivered; the run fails; the transcript shows zero model calls for it.
#[test]
#[ignore = "E3 process column: `just oci-live-smoke` (L1) or `just e3-crash-matrix`"]
fn e3_p1_placed_not_sent_live() {
    let agent = E3Agent::selected();
    let mut cell = Cell::new("P1", agent);
    let env = armed(P1_BOUNDARY, None).unwrap_or_else(|refusal| panic!("{TEST}: {refusal}"));
    cell.oracle
        .note(format!("control 1: KATA_FAULT_INJECT={}", env[0].1));
    let mut e3 = boot_e3(node_root(), agent, (Armed::Main, &env));
    cell.attach(&e3);
    let execution = submit(&e3);
    cell.oracle.note(format!("execution {execution}"));
    // NOT the `claimed` transition: the placement transaction writes it, before the
    // point. A plan attempt the worker reported running had its frame sent.
    let passed = |node: &Node| {
        plan_attempt_state(node, &execution)
            .filter(|state| state != "dispatched" && state != "pending")
            .map(|state| format!("the plan attempt is `{state}`: its frame left the main"))
    };
    if let Err(void) = crash_controls(&mut cell, &mut e3.node, Armed::Main, P1_BOUNDARY, passed) {
        cell.finish(&Ended::Void(void));
        return;
    }
    let state = plan_attempt_state(&e3.node, &execution);
    cell.oracle.note(format!(
        "raw plan attempt state at the crash: {state:?} (the window: dispatched)"
    ));
    if let Err(why) = restart_node(&mut e3) {
        let calls = uncompleted_calls(&e3.sse.events(), agent.call_markers());
        let ended = not_restarted(&mut cell, why, None, &calls);
        cell.finish(&ended);
        return;
    }
    let ended = judge_p1(&mut cell, &mut e3, &execution);
    cell.finish(&ended);
}
/// **P2, model call in flight.** SIGKILL the worker while `implement`'s model call is
/// open in the client-side transcript. PROVEN AMBIGUOUS; no second attempt after the
/// recovery window; no `/work` delta; no container or cgroup left; the killed attempt's
/// usage is unknown and its open call counted as unmetered. A try whose transcript shows
/// no open call at the kill is VOID and re-run, at most three tries.
#[test]
#[ignore = "E3 process column: `just oci-live-smoke` (L1) or `just e3-crash-matrix`"]
fn e3_p2_model_call_in_flight_live() {
    let agent = E3Agent::selected();
    for attempt in 1..=3 {
        if !p2_try(agent) {
            return;
        }
        eprintln!("E3 P2: try {attempt} of 3 was VOID");
    }
    panic!("{TEST}: E3 P2: in-flight kill not achieved in 3 tries");
}
/// **P3, after the turn, before acceptance.** The FIRST worker aborts once `plan`'s
/// container has exited and before it publishes `/out`: the turn is done and no
/// `CompletedCapsule` frame left. The main's worker-death leg settles the attempt PROVEN
/// AMBIGUOUS; a fresh worker re-registers, nothing is re-delivered, there is one attempt
/// row and one claim, and the run fails and auto-parks.
#[test]
#[ignore = "E3 process column: `just oci-live-smoke` (L1) or `just e3-crash-matrix`"]
fn e3_p3_after_turn_before_acceptance_live() {
    let agent = E3Agent::selected();
    let mut cell = Cell::new("P3", agent);
    let env = armed(P3_BOUNDARY, None).unwrap_or_else(|refusal| panic!("{TEST}: {refusal}"));
    cell.oracle.note(format!(
        "control 1: KATA_FAULT_INJECT={} (the first worker)",
        env[0].1
    ));
    let mut e3 = boot_e3(node_root(), agent, (Armed::Worker, &env));
    cell.attach(&e3);
    let execution = submit(&e3);
    cell.oracle.note(format!("execution {execution}"));
    let passed = |node: &Node| {
        (completed_transitions(node, &execution, "plan", "event_accepted") > 0)
            .then(|| "plan's completion was accepted without crossing the point".to_owned())
    };
    if let Err(void) = crash_controls(&mut cell, &mut e3.node, Armed::Worker, P3_BOUNDARY, passed) {
        cell.finish(&Ended::Void(void));
        return;
    }
    note_p3_crash_state(&mut cell, &e3.node, &execution);
    // The main is alive: only the worker restarts.
    let restarted = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        e3.node.restart_worker();
    }));
    if let Err(panic) = restarted {
        let calls = uncompleted_calls(&e3.sse.events(), agent.call_markers());
        let ended = not_restarted(&mut cell, panic_text(&*panic), None, &calls);
        cell.finish(&ended);
        return;
    }
    let ended = judge_p3(&mut cell, &mut e3, &execution, Some(WORKER_DIED));
    cell.finish(&ended);
}
/// **P4, between the push and the PR.** The main aborts after `export` pushed
/// `kata/<exec>` and before it opened the PR. At restart the push's observer reads the
/// remote: exactly one `refs/heads/kata/<exec>` on the remote, equal to the delivered
/// commit, and one PR.
/// The forge is the rig's local bare remote and fake `gh`, or, selected by
/// `KATA_E3_FORGE_CLONE` with `KATA_E3_FUNDED=1` ([`select_forge_clone`]), the real
/// forge behind that clone, run by the host's `gh`.
#[test]
#[ignore = "E3 process column: `just oci-live-smoke` (L1) or `just e3-crash-matrix`"]
fn e3_p4_between_push_and_pr_live() {
    let agent = E3Agent::selected();
    let clone = select_forge_clone(
        std::env::var("KATA_E3_FORGE_CLONE").ok().as_deref(),
        std::env::var("KATA_E3_FUNDED").ok().as_deref(),
    )
    .unwrap_or_else(|refusal| panic!("{TEST}: {refusal}"));
    let mut cell = Cell::new("P4", agent);
    let env = armed(P4_BOUNDARY, None).unwrap_or_else(|refusal| panic!("{TEST}: {refusal}"));
    cell.oracle
        .note(format!("control 1: KATA_FAULT_INJECT={}", env[0].1));
    let root = node_root();
    let fixture = match &clone {
        Some(clone) => fixture_repo_cloned(root.path(), clone),
        None => fixture_repo(root.path()),
    };
    if let Some(clone) = &clone {
        cell.oracle.note(format!(
            "forge: the real forge behind {} (KATA_E3_FORGE_CLONE), the host's gh",
            clone.display()
        ));
    }
    let mut e3 = boot_e3_on(root, fixture, agent, (Armed::Main, &env));
    cell.attach(&e3);
    let execution = submit(&e3);
    cell.oracle.note(format!("execution {execution}"));
    let gate = e3
        .node
        .main
        .next_gate(&execution)
        .expect("the approve stage parks a gate");
    e3.node.main.decide(&gate, None);
    // The wait polls every 200 ms, so only the fake `gh`'s file is read for a main past
    // the point; on the real forge a main that ran past it is VOID at the deadline instead,
    // and the forge's `gh` is asked only by the oracles.
    let passed = |node: &Node| {
        (node.fixture.origin == Origin::LocalBare && pull_requests(node, &execution) > 0)
            .then(|| "a pull request for kata/<exec> already exists".to_owned())
    };
    if let Err(void) = crash_controls(&mut cell, &mut e3.node, Armed::Main, P4_BOUNDARY, passed) {
        cell.finish(&Ended::Void(void));
        return;
    }
    note_p4_crash_state(&mut cell, &e3, &execution);
    if let Err(why) = restart_node(&mut e3) {
        let calls = uncompleted_calls(&e3.sse.events(), agent.call_markers());
        let ended = not_restarted(&mut cell, why, None, &calls);
        cell.finish(&ended);
        return;
    }
    let ended = judge_p4(&mut cell, &mut e3, &execution);
    cell.finish(&ended);
}

// ---------------------------------------------------------------------------
// Host-free cells: the harness's own refusals and tables
// ---------------------------------------------------------------------------

/// Control 1 refuses a name outside the registry — a misspelling, the prefixed form, an
/// empty name — and admits every boundary the cells arm.
#[test]
fn the_fault_value_refuses_a_boundary_outside_the_registry() {
    for misspelled in [
        "after_capsule_dispatched_before_sned",
        "operational.before_accept_event",
        "after_forge_push_before_pull_request",
        "",
    ] {
        let refusal = fault_inject_value(misspelled).expect_err(misspelled);
        assert!(
            refusal.contains("is not a member of"),
            "{misspelled:?}: {refusal}"
        );
    }
    for boundary in [P1_BOUNDARY, P3_BOUNDARY, P4_BOUNDARY] {
        assert_eq!(
            fault_inject_value(boundary).as_deref(),
            Ok(format!("operational.{boundary}").as_str())
        );
    }
}
/// Each nanocode agent's `[agents.default]` block, the mock's included, is one
/// this build's config loads: it deserializes as an agent block, launches its own
/// kind, and parses its credential, so a cell
/// boots its node instead of refusing at config load.
///
/// **Would red if:** the rig wrote a key the config refuses (watched:
/// `type = "claude"` for `nanocode_anthropic`, `unknown variant`; any `type` is
/// now `agent_type_removed`).
#[test]
fn each_nanocode_agent_block_is_a_config_this_build_loads() {
    #[derive(serde::Deserialize)]
    struct Agents {
        #[serde(deserialize_with = "kata_types::config::deserialize_agents")]
        agents: BTreeMap<String, kata_types::config::AgentBackendConfig>,
    }
    for (agent, kind) in [
        (
            E3Agent::Mock,
            kata_types::agent::AdapterKind::NanocodeOpenai,
        ),
        (
            E3Agent::NanocodeOpenai,
            kata_types::agent::AdapterKind::NanocodeOpenai,
        ),
        (
            E3Agent::NanocodeAnthropic,
            kata_types::agent::AdapterKind::NanocodeAnthropic,
        ),
    ] {
        let block = nanocode_agent_decl(agent);
        let parsed: Agents = toml::from_str(&block)
            .unwrap_or_else(|error| panic!("{agent:?}: the block loads: {error}\n{block}"));
        let config = &parsed.agents[AGENT_LABEL];
        let launched = config
            .capsule_launch()
            .unwrap_or_else(|problem| panic!("{agent:?}: the block launches: {problem:?}"));
        assert_eq!(launched, kind, "{agent:?}");
        assert!(
            config
                .capsule_credential_ref()
                .unwrap_or_else(|error| panic!("{agent:?}: the credential parses: {error}"))
                .is_some(),
            "{agent:?}: the block declares its credential"
        );
    }
}
/// The agent selector takes the mock when no agent is named, and refuses an
/// unknown name and either provider-backed nanocode agent without
/// `KATA_E3_FUNDED=1`; the mock needs no opt-in.
#[test]
fn the_agent_selector_refuses_a_funded_agent_without_the_opt_in() {
    for opt_in in [None, Some("1")] {
        assert_eq!(select_agent(None, opt_in), Ok(E3Agent::Mock));
        assert_eq!(
            select_agent(Some("nanocode-mock"), opt_in),
            Ok(E3Agent::Mock)
        );
    }
    for (name, agent) in [
        ("nanocode-openai", E3Agent::NanocodeOpenai),
        ("nanocode-anthropic", E3Agent::NanocodeAnthropic),
    ] {
        for opt_in in [None, Some("0"), Some("yes"), Some("")] {
            let refusal = select_agent(Some(name), opt_in).expect_err("unfunded");
            assert!(refusal.contains("KATA_E3_FUNDED=1"), "{refusal}");
        }
        assert_eq!(select_agent(Some(name), Some("1")), Ok(agent));
    }
    for unknown in ["codex-stock", "fake-codex"] {
        let refusal = select_agent(Some(unknown), Some("1")).expect_err("unknown");
        assert!(refusal.contains("is none of"), "{refusal}");
    }
}
/// The real-forge P4 selector: unset is the local forge; set, it needs a path and
/// `KATA_E3_FUNDED=1`, and refuses anything else by name.
#[test]
fn the_forge_selector_refuses_a_real_forge_without_the_opt_in() {
    assert_eq!(select_forge_clone(None, None), Ok(None));
    assert_eq!(select_forge_clone(None, Some("1")), Ok(None));
    for opt_in in [None, Some("0"), Some("yes"), Some("")] {
        let refusal = select_forge_clone(Some("/clone"), opt_in).expect_err("unfunded");
        assert!(refusal.contains("KATA_E3_FUNDED=1"), "{refusal}");
    }
    let empty = select_forge_clone(Some(""), Some("1")).expect_err("empty");
    assert!(empty.contains("names no clone"), "{empty}");
    assert_eq!(
        select_forge_clone(Some("/clone"), Some("1")),
        Ok(Some(PathBuf::from("/clone")))
    );
}
/// `gh pr list --json number`: an array of numbered entries counts; anything else is
/// refused rather than read as zero.
#[test]
fn the_pull_request_oracle_counts_only_numbered_entries() {
    assert_eq!(pull_request_count(b"[]"), Ok(0));
    assert_eq!(pull_request_count(b"[{\"number\":7}]\n"), Ok(1));
    assert_eq!(
        pull_request_count(b"[{\"number\":7},{\"number\":8}]"),
        Ok(2)
    );
    for refused in [&b""[..], b"{}", b"[{}]", b"[{\"number\":\"7\"}]", b"no"] {
        assert!(pull_request_count(refused).is_err(), "{refused:?}");
    }
}
/// The cells' expected settlements are exactly the evidence check's
/// `EXPECTED_SETTLEMENT` (scripts/evidence-page.py), read from that file.
/// **A VOID record states the control that did not hold, and every record the tree
/// its commit names.** The evidence check refuses a void record without a
/// `void_reason` read from a listed artifact, and any record without `kata_tree`;
/// the record's tree is compared with git's own `rev-parse HEAD^{tree}`, not with the
/// writer's.
#[test]
fn a_void_record_states_its_reason_and_every_record_its_tree() {
    let root = tempfile::tempdir().unwrap();
    let cell = Cell::new("P2", E3Agent::NanocodeOpenai);
    let (outcome, _, dir) = cell.record_in(
        root.path(),
        &Ended::Void("in-flight kill not achieved".to_owned()),
    );
    assert_eq!(outcome, "void");
    let record: toml::Table =
        toml::from_str(&std::fs::read_to_string(dir.join("run.toml")).unwrap()).unwrap();
    let git = std::process::Command::new("git")
        .args(["rev-parse", "HEAD^{tree}"])
        .current_dir(repo_root())
        .output()
        .expect("git runs");
    let tree = String::from_utf8(git.stdout).unwrap().trim().to_owned();
    assert_eq!(tree.len(), 40, "git names the tree: {tree:?}");
    assert_eq!(record["kata_tree"].as_str(), Some(tree.as_str()));
    assert_eq!(
        record["void_reason"].as_str(),
        Some("oracle.txt: VOID: in-flight kill not achieved")
    );
    assert_eq!(record["settlement"].as_str(), Some("other"));
    let oracle = std::fs::read_to_string(dir.join("oracle.txt")).unwrap();
    assert!(
        oracle.contains("outcome: void: VOID: in-flight kill not achieved"),
        "{oracle}"
    );
}
#[test]
fn the_expected_settlements_are_the_evidence_checks() {
    let script = std::fs::read_to_string(repo_root().join("scripts/evidence-page.py")).unwrap();
    let block = script
        .split_once("EXPECTED_SETTLEMENT = {")
        .and_then(|(_, rest)| rest.split_once('}'))
        .map(|(block, _)| block)
        .expect("scripts/evidence-page.py defines EXPECTED_SETTLEMENT");
    let checked: BTreeMap<String, String> = block
        .lines()
        .filter_map(|line| {
            let (case, settlement) = line.trim().trim_end_matches(',').split_once(':')?;
            Some((
                case.trim().trim_matches('"').to_owned(),
                settlement.trim().trim_matches('"').to_owned(),
            ))
        })
        .collect();
    let ours: BTreeMap<String, String> = EXPECTED_SETTLEMENT
        .iter()
        .map(|(case, settlement)| ((*case).to_owned(), (*settlement).to_owned()))
        .collect();
    assert_eq!(ours, checked);
}
/// The transcript reader: an open call is a start whose completion has not arrived, a
/// terminal ledger frame closes it, and a tool frame after the start means the
/// completion was coalesced away.
#[test]
fn the_transcript_reader_finds_an_open_call_and_only_an_open_call() {
    let progress = |ms: u64, assignment: &str, preview: &str| {
        format!(
            "{ms}\tevent: progress\n{ms}\tdata: {{\"assignment_id\":\"{assignment}\",\
             \"stage_name\":\"implement\",\"preview\":\"{preview}\"}}\n{ms}\t\n"
        )
    };
    let nano = E3Agent::NanocodeOpenai.call_markers();
    let open = progress(1, "a", "model_call_started");
    let events = parse_transcript(&open);
    assert_eq!(
        calls_of(&events, "a", nano),
        CallCount {
            started: 1,
            completed: 0,
            unclosed: 0,
            open: true
        }
    );
    let closed = format!("{open}{}", progress(2, "a", "model_call_completed"));
    assert!(!calls_of(&parse_transcript(&closed), "a", nano).open);
    let terminal = format!(
        "{open}3\tevent: ledger\n3\tdata: {{\"assignment_id\":\"a\",\"stage_name\":\
         \"implement\",\"new_status\":{{\"kind\":\"failed\"}}}}\n3\t\n"
    );
    assert!(!calls_of(&parse_transcript(&terminal), "a", nano).open);
    let other = progress(1, "b", "model_call_started");
    assert!(!calls_of(&parse_transcript(&other), "a", nano).open);
    let coalesced = format!(
        "{}{}",
        progress(1, "a", "model_call_started"),
        progress(2, "a", "tool_call: exec_command")
    );
    assert!(!calls_of(&parse_transcript(&coalesced), "a", nano).open);
    let streaming = format!(
        "{}{}",
        progress(1, "a", "model_call_started"),
        progress(2, "a", "agent_message_chunk: hello")
    );
    assert!(calls_of(&parse_transcript(&streaming), "a", nano).open);
    // A start coalesced away behind a chunk is implied by the chunk.
    let chunk_only = progress(1, "a", "agent_message_chunk: hello");
    assert_eq!(
        calls_of(&parse_transcript(&chunk_only), "a", nano),
        CallCount {
            started: 1,
            completed: 0,
            unclosed: 0,
            open: true
        }
    );
}
/// The spend count, README E3's "issued calls whose usage is unknown", on a KILLED
/// attempt, which is every attempt the rig counts (P2's implement, P3's plan): its usage
/// rides the attempt's terminal frame, which the kill prevented, so no call it issued is on
/// any durable row. Completed, failed, cut off, closed only by the next start, or open:
/// each issued call counts, and only a call whose every frame was coalesced away (which
/// the transcript cannot show) does not. P2 and P3 both take this count.
#[test]
fn a_killed_attempts_every_issued_call_is_unmetered() {
    let progress = |ms: u64, preview: &str| {
        format!(
            "{ms}\tevent: progress\n{ms}\tdata: {{\"assignment_id\":\"a\",\
             \"stage_name\":\"implement\",\"preview\":\"{preview}\"}}\n{ms}\t\n"
        )
    };
    let nano = E3Agent::NanocodeOpenai.call_markers();
    let count = |frames: &[&str]| {
        let text: String = frames
            .iter()
            .enumerate()
            .map(|(at, preview)| progress(at as u64, preview))
            .collect();
        calls_of(&parse_transcript(&text), "a", nano)
    };
    // Two completed calls (the first's completion displaced by its tool call), then the
    // call open at the kill: three issued, none metered.
    let killed = count(&[
        "model_call_started",
        "tool_call: exec_command",
        "tool_result: c1",
        "model_call_started",
        "model_call_completed",
        "model_call_started",
    ]);
    assert_eq!(
        (
            killed.started,
            killed.completed,
            killed.open,
            killed.unmetered()
        ),
        (3, 2, true, 3),
        "{killed:?}"
    );
    // A completion whose start was displaced: one call issued.
    let start_hidden = count(&["agent_message_chunk: x", "model_call_completed"]);
    assert_eq!(
        (start_hidden.started, start_hidden.unmetered()),
        (1, 1),
        "{start_hidden:?}"
    );
    // A failed call, then an open one: two issued.
    let failed = count(&[
        "model_call_started",
        "model_call_failed: 502",
        "model_call_started",
    ]);
    assert_eq!(
        (failed.started, failed.unmetered(), failed.open),
        (2, 2, true),
        "{failed:?}"
    );
    // A start right after a start: the first's close is unknown, and it was issued.
    let restarted = count(&["model_call_started", "model_call_started"]);
    assert_eq!(
        (restarted.started, restarted.unclosed, restarted.unmetered()),
        (2, 1, 2),
        "{restarted:?}"
    );
    // A transcript with no frame of the attempt: nothing issued that it can show.
    assert_eq!(count(&[]).unmetered(), 0);
}
/// A frame of `assignment` in `stage`: a progress preview, or a terminal ledger status.
fn frame(ms: u64, stage: &str, assignment: &str, frame: &str) -> String {
    let data = match frame.strip_prefix("ledger:") {
        Some(kind) => format!(
            "event: ledger\n{ms}\tdata: {{\"assignment_id\":\"{assignment}\",\"stage_name\":\
             \"{stage}\",\"new_status\":{{\"kind\":\"{kind}\"}}}}"
        ),
        None => format!(
            "event: progress\n{ms}\tdata: {{\"assignment_id\":\"{assignment}\",\"stage_name\":\
             \"{stage}\",\"preview\":\"{frame}\"}}"
        ),
    };
    format!("{ms}\t{data}\n{ms}\t\n")
}
/// The calls of a killed attempt that completed two calls before the kill: a start closed
/// only by the next start, its completion, and a second completed call, so started 3,
/// completed 2, unclosed 1, none open.
const KILLED_AFTER_TWO_COMPLETIONS: &[&str] = &[
    "model_call_started",
    "model_call_started",
    "model_call_completed",
    "model_call_started",
    "model_call_completed",
];
/// The judges' spend tells the formulas apart: P2's (`p2_spend`, what `judge_p2` records)
/// and P3's (`p3_spend`, what `judge_p3` records) both count every call the killed attempt
/// issued — 3, where started − completed − unclosed reads 0 and started − completed reads 1.
#[test]
fn the_judges_count_a_killed_attempts_completed_calls_as_unmetered() {
    let nano = E3Agent::NanocodeOpenai.call_markers();
    let transcript = |stage: &str| -> String {
        KILLED_AFTER_TWO_COMPLETIONS
            .iter()
            .enumerate()
            .map(|(at, preview)| frame(at as u64, stage, "a", preview))
            .collect()
    };
    let implement = parse_transcript(&transcript("implement"));
    let calls = calls_of(&implement, "a", nano);
    assert_eq!(
        (calls.started, calls.completed, calls.unclosed, calls.open),
        (3, 2, 1, false),
        "{calls:?}"
    );
    let mut oracle = Oracle::default();
    assert_eq!(p2_spend(&mut oracle, &calls), 3, "{:?}", oracle.lines);
    assert!(
        oracle.lines[0].starts_with("spend: issued calls of the killed attempt 3,"),
        "{:?}",
        oracle.lines
    );
    assert_eq!(p3_spend(&parse_transcript(&transcript("plan")), nano), 3);
    // Two plan attempts: each one's issued calls, summed (3 + the second's open 1).
    let second = frame(9, "plan", "b", "model_call_started");
    let two = parse_transcript(&format!("{}{second}", transcript("plan")));
    assert_eq!(p3_spend(&two, nano), 4);
}
/// The cases whose design kills no model call (P1, the gate, P4) COUNT, through the one
/// `CallCount::unmetered`, the calls of every agent attempt that never completed, and their
/// oracle refuses any count but 0. A completed attempt's calls are metered and not counted;
/// a failed one's and an unsettled one's are.
#[test]
fn a_case_that_kills_no_call_counts_its_uncompleted_attempts_and_requires_zero() {
    let nano = E3Agent::NanocodeOpenai.call_markers();
    let text = |frames: &[(&str, &str, &str)]| -> Vec<SseEvent> {
        let joined: String = frames
            .iter()
            .enumerate()
            .map(|(at, (stage, assignment, preview))| frame(at as u64, stage, assignment, preview))
            .collect();
        parse_transcript(&joined)
    };
    let completed = [
        ("plan", "p", "model_call_started"),
        ("plan", "p", "model_call_completed"),
        ("plan", "p", "ledger:completed"),
        ("implement", "i", "model_call_started"),
        ("implement", "i", "model_call_completed"),
        ("implement", "i", "ledger:completed"),
    ];
    let clean = uncompleted_calls(&text(&completed), nano);
    assert_eq!(clean, CallCount::default());
    assert_eq!(none_unmetered(&clean, "the design"), Ok(()));
    // The implement attempt failed after two calls, and a plan attempt never settled with one
    // open: three issued calls of unknown usage, refused.
    let mut killed = completed[..3].to_vec();
    killed.extend([
        ("implement", "i", "model_call_started"),
        ("implement", "i", "model_call_completed"),
        ("implement", "i", "model_call_started"),
        ("implement", "i", "ledger:failed"),
        ("plan", "q", "model_call_started"),
    ]);
    let calls = uncompleted_calls(&text(&killed), nano);
    assert_eq!(
        (
            calls.started,
            calls.completed,
            calls.open,
            calls.unmetered()
        ),
        (3, 1, true, 3),
        "{calls:?}"
    );
    let refusal = none_unmetered(&calls, "the gate kill falls between agent turns")
        .expect_err("three issued calls of unknown usage are refused");
    assert!(
        refusal.starts_with("3 issued model call(s) of unknown usage")
            && refusal.ends_with("where the gate kill falls between agent turns"),
        "{refusal}"
    );
}
/// P3's counts: exactly one attempt row, exactly one claim, no acceptance. No claim at all
/// (the attempt never reached the worker), a second claim, a second attempt row and an
/// accepted result are each refused.
#[test]
fn p3_admits_exactly_one_claimed_attempt_and_no_acceptance() {
    assert_eq!(judge_p3_counts(1, 1, 0), Ok(()));
    for (claims, attempts, accepted) in [(0, 1, 0), (2, 1, 0), (1, 2, 0), (1, 0, 0), (1, 1, 1)] {
        assert!(
            judge_p3_counts(claims, attempts, accepted).is_err(),
            "admitted claims {claims}, attempts {attempts}, accepted {accepted}"
        );
    }
}
/// Controls 2 and 3: only a main that printed the abort line AND died by SIGABRT
/// passes. A SIGKILL, a clean exit, a main stopped and resumed at the point (its
/// marker says `action=stop`, and it too aborts), no line at all, and a main that never
/// died are each VOID.
#[test]
fn the_crash_controls_admit_only_an_abort_at_the_point() {
    let boundary = P1_BOUNDARY;
    let aborted = format!("startup\n{}\n", abort_line(boundary));
    let by_signal = |signal: i32| Ok(std::process::ExitStatus::from_raw(signal));
    let main = Armed::Main;
    assert_eq!(
        judge_crash(main, &aborted, by_signal(SIGABRT), boundary),
        Ok(())
    );
    let killed = judge_crash(main, &aborted, by_signal(SIGKILL), boundary).expect_err("SIGKILL");
    assert!(killed.contains("not death by SIGABRT"), "{killed}");
    let exited = judge_crash(
        main,
        &aborted,
        Ok(std::process::ExitStatus::from_raw(0)),
        boundary,
    )
    .expect_err("exit 0");
    assert!(exited.contains("not death by SIGABRT"), "{exited}");
    let resumed = format!(
        "{} (KATA_FAULT_INJECT=operational.{boundary}, action=stop); stopping process now \
         (SIGSTOP)\n[kata-fault-inject] resumed at operational.{boundary}; aborting process now\n",
        crash_marker(boundary)
    );
    let stopped = judge_crash(main, &resumed, by_signal(SIGABRT), boundary).expect_err("stop");
    assert!(stopped.contains("does not carry"), "{stopped}");
    let other = judge_crash(main, &abort_line(P3_BOUNDARY), by_signal(SIGABRT), boundary)
        .expect_err("another point");
    assert!(other.contains("does not carry"), "{other}");
    let alive =
        judge_crash(main, &aborted, Err("still alive".to_owned()), boundary).expect_err("alive");
    assert!(alive.contains("main never died"), "{alive}");
    // P3's worker: the same controls, named for the worker.
    let worker = judge_crash(
        Armed::Worker,
        &abort_line(P3_BOUNDARY),
        by_signal(SIGKILL),
        P3_BOUNDARY,
    )
    .expect_err("a killed worker");
    assert!(worker.contains("the worker's wait status"), "{worker}");
}
/// The raw failed `implement` transition the 0.0.1 round's process-column P2 recorded
/// (`e3-P2-nanocode-anthropic-20261112T151717Z`): the worker-death leg's settlement.
const P2_WORKER_DIED: &str = r#"{"delivery":{"awaiting_approval_at_ms":null,"child_execution_id":null,"dispatched_at_ms":1794496645061,"finished_at_ms":1794496645418,"last_checkpoint":0,"stage_name":"implement","started_at_ms":1794496645078,"worker_id":"local-worker-0"},"reason":"worker local-worker-0 died: its connection closed (network error: connection closed by peer); its process 1404668 exists in state Z. PROVEN AMBIGUOUS: the main cannot observe whether this capsule's container ran, so the stage may have done anything it was asked. The attempt is settled terminal and NOT re-delivered (capsule re-delivery is not implemented)","terminal_charge":{"token_usage":{"cache_read":0,"cache_savings_micro_usd":0,"cache_write":0,"cost":{"backend":"nanocode_anthropic","model":"claude-sonnet-5-5","quality":"unavailable"},"input":0,"output":0}},"verdict":"proven_ambiguous"}"#;
/// The raw failed `implement` transition the 0.0.1 round's P2-host recorded
/// (`e3-P2-host-nanocode-anthropic-20261112T154509Z`): the restart pass's settlement.
const P2_MAIN_RESTARTED: &str = r#"{"delivery":{"awaiting_approval_at_ms":null,"child_execution_id":null,"dispatched_at_ms":1794498317788,"finished_at_ms":1794498339349,"last_checkpoint":0,"stage_name":"implement","started_at_ms":1794498317815,"worker_id":"local-worker-0"},"reason":"the main restarted. PROVEN AMBIGUOUS: the main cannot observe whether this capsule's container ran, so the stage may have done anything it was asked. The attempt is settled terminal and NOT re-delivered (capsule re-delivery is not implemented)","terminal_charge":{"token_usage":{"cache_read":0,"cache_savings_micro_usd":0,"cache_write":0,"cost":{"backend":"nanocode_anthropic","model":"claude-sonnet-5-5","quality":"unavailable"},"input":0,"output":0}},"verdict":"proven_ambiguous"}"#;

fn chain_row(ordinal: i64, kind: &str, state: &str, payload: &str) -> ChainRow {
    ChainRow {
        attempt_ordinal: Some(ordinal),
        kind: kind.to_owned(),
        resulting_state: state.to_owned(),
        payload: serde_json::from_str(payload).unwrap(),
    }
}

/// One `implement` attempt claimed, dispatched, started and settled `failed` with
/// `failed_payload`: the chain a P2 kill leaves.
fn settled_p2_chain(failed_payload: &str) -> P2Chain {
    P2Chain {
        transitions: vec![
            chain_row(0, "claimed", "pending", "{}"),
            chain_row(0, "dispatched", "dispatched", "{}"),
            chain_row(
                0,
                "attempt_safe_point",
                "attempt_safe_point",
                r#"{"last_checkpoint":0}"#,
            ),
            chain_row(0, "attempt_advanced", "running", "{}"),
            chain_row(0, "attempt_advanced", "failed", failed_payload),
        ],
        attempt_rows: 1,
    }
}

/// P2's settlement judge admits each column's own recorded settlement: the process
/// column's worker death and the host column's main restart (the record P2-host failed
/// on), each PROVEN AMBIGUOUS by its typed `verdict`, one claim, one dispatch, one attempt.
#[test]
fn p2_admits_each_columns_own_ambiguous_settlement() {
    let died = judge_p2_settlement(P2Restart::WorkerDied, &settled_p2_chain(P2_WORKER_DIED));
    assert!(died.is_ok(), "{died:?}");
    let restarted = judge_p2_settlement(
        P2Restart::MainRestarted,
        &settled_p2_chain(P2_MAIN_RESTARTED),
    );
    assert!(restarted.is_ok(), "{restarted:?}");
}

/// P2's settlement judge refuses: a re-delivered attempt (the same claim dispatched a
/// second time, the one attempt row claimed a second time, or a second attempt claimed
/// and minted), an accepted result, a settlement whose typed verdict is not
/// `proven_ambiguous` whatever its reason says, a reason that does not state PROVEN
/// AMBIGUOUS or NOT re-delivered, the other column's settlement leg, a worker-death
/// cause that is not `died`, and a chain with no failed transition or with two. Each negative names
/// the refusal it must meet, so a refusal mutated away leaves its negative admitted or
/// refused by the wrong clause.
#[test]
fn p2_refuses_a_redelivered_attempt_and_any_other_settlement() {
    let redispatched = {
        let mut chain = settled_p2_chain(P2_WORKER_DIED);
        chain
            .transitions
            .insert(4, chain_row(0, "dispatched", "dispatched", "{}"));
        chain
    };
    let reminted = {
        let mut chain = settled_p2_chain(P2_MAIN_RESTARTED);
        chain
            .transitions
            .push(chain_row(1, "claimed", "pending", "{}"));
        chain.attempt_rows = 2;
        chain
    };
    let accepted = {
        let mut chain = settled_p2_chain(P2_WORKER_DIED);
        chain
            .transitions
            .insert(4, chain_row(0, "event_accepted", "completed", "{}"));
        chain
    };
    let not_ambiguous = settled_p2_chain(&P2_MAIN_RESTARTED.replace(
        r#""verdict":"proven_ambiguous""#,
        r#""verdict":"proven_not_performed""#,
    ));
    let unsettled = {
        let mut chain = settled_p2_chain(P2_WORKER_DIED);
        chain.transitions.pop();
        chain
    };
    let reclaimed = {
        let mut chain = settled_p2_chain(P2_WORKER_DIED);
        chain
            .transitions
            .insert(2, chain_row(0, "claimed", "pending", "{}"));
        chain
    };
    let redelivered_in_words =
        settled_p2_chain(&P2_WORKER_DIED.replace("NOT re-delivered", "re-delivered"));
    let unproven_in_words =
        settled_p2_chain(&P2_MAIN_RESTARTED.replace(". PROVEN AMBIGUOUS: ", ". AMBIGUOUS: "));
    let settled_twice = {
        let mut chain = settled_p2_chain(P2_WORKER_DIED);
        chain
            .transitions
            .push(chain_row(0, "attempt_advanced", "failed", P2_WORKER_DIED));
        chain
    };
    let worker_exited = settled_p2_chain(&P2_WORKER_DIED.replace(
        "worker local-worker-0 died: ",
        "worker local-worker-0 exited: ",
    ));
    for (what, restart, chain, refusal) in [
        (
            "a re-dispatch of the one claim",
            P2Restart::WorkerDied,
            redispatched,
            "2 implement dispatches",
        ),
        (
            "a second attempt",
            P2Restart::MainRestarted,
            reminted,
            "2 implement attempt rows",
        ),
        (
            "an accepted result",
            P2Restart::WorkerDied,
            accepted,
            "was accepted",
        ),
        (
            "a typed verdict other than proven_ambiguous",
            P2Restart::MainRestarted,
            not_ambiguous,
            "typed verdict",
        ),
        (
            "the worker-death leg on the host column",
            P2Restart::MainRestarted,
            settled_p2_chain(P2_WORKER_DIED),
            "MainRestarted leg's cause",
        ),
        (
            "the restart leg on the process column",
            P2Restart::WorkerDied,
            settled_p2_chain(P2_MAIN_RESTARTED),
            "WorkerDied leg's cause",
        ),
        (
            "no failed transition",
            P2Restart::WorkerDied,
            unsettled,
            "0 failed implement transitions",
        ),
        (
            "a second failed terminal of the one attempt",
            P2Restart::WorkerDied,
            settled_twice,
            "2 failed implement transitions",
        ),
        (
            "a second claim of the one attempt row",
            P2Restart::WorkerDied,
            reclaimed,
            "2 implement claims",
        ),
        (
            "a reason that does not say NOT re-delivered",
            P2Restart::WorkerDied,
            redelivered_in_words,
            "does not state PROVEN AMBIGUOUS, NOT re-delivered",
        ),
        (
            "a reason that does not say PROVEN AMBIGUOUS",
            P2Restart::MainRestarted,
            unproven_in_words,
            "does not state PROVEN AMBIGUOUS, NOT re-delivered",
        ),
        (
            "a worker that exited, not died, on the process column",
            P2Restart::WorkerDied,
            worker_exited,
            "WorkerDied leg's cause",
        ),
    ] {
        let judged = judge_p2_settlement(restart, &chain);
        assert!(
            judged.as_ref().is_err_and(|why| why.contains(refusal)),
            "{what}: expected a refusal naming {refusal:?}, got {judged:?}"
        );
    }
}
/// The facts of a P2 run that held: a failed status, the settlement recorded as
/// `failed_payload`, its chain, the `/work` heads unchanged and no implement usage row.
fn held_p2_facts(failed_payload: &str) -> P2Facts {
    P2Facts {
        status: "failed".to_owned(),
        failed_reason: Some(failed_payload.to_owned()),
        chain: Ok(settled_p2_chain(failed_payload)),
        heads_after: Ok(p2_heads()),
        usage_rows: Ok(Vec::new()),
    }
}

fn p2_heads() -> Vec<(String, String, i64)> {
    vec![("main".to_owned(), "AB".repeat(16), 1)]
}

/// `judge_p2`'s judgement of what it read, with no node: each column's recorded
/// settlement is observed PROVEN AMBIGUOUS with no violation; the chain it was given is
/// the one judged, for the leg it was given (the host column's settlement under the
/// process leg is refused, naming that leg); every read oracle is judged whatever an
/// earlier one found, so a re-delivered chain, a moved `/work` head and a known usage row
/// are each named; a failed read of the chain, the `/work` heads or the usage rows is a
/// violation; the settled attempt's own known `terminal_charge` is named; and a status
/// other than `failed`, or a failed status with a typed verdict other than
/// `proven_ambiguous`, is observed `other`.
///
/// **Would red if:** `judge_p2_facts` judged a leg other than the one passed; skipped the
/// settlement, the `/work` heads comparison or the usage rows' check; stopped at its first
/// violation; dropped the failure of any one of its three reads; did not judge the settled
/// attempt's own `terminal_charge`; or observed PROVEN AMBIGUOUS without either the
/// `failed` status or the typed verdict.
#[test]
fn p2_judges_every_read_oracle_off_the_facts_it_was_given() {
    let judge = |restart, facts: &P2Facts| {
        judge_p2_facts(
            restart,
            &p2_heads(),
            facts,
            &mut Oracle { lines: Vec::new() },
        )
    };
    for (restart, payload) in [
        (P2Restart::WorkerDied, P2_WORKER_DIED),
        (P2Restart::MainRestarted, P2_MAIN_RESTARTED),
    ] {
        let (settlement, violations) = judge(restart, &held_p2_facts(payload));
        assert_eq!(
            settlement,
            ("proven-ambiguous".to_owned(), None),
            "{restart:?}"
        );
        assert!(violations.is_empty(), "{restart:?}: {violations:?}");
    }
    let (_, other_leg) = judge(P2Restart::WorkerDied, &held_p2_facts(P2_MAIN_RESTARTED));
    assert!(
        other_leg.len() == 1 && other_leg[0].contains("WorkerDied leg's cause"),
        "the host column's settlement under the process leg: {other_leg:?}"
    );
    let mut every = held_p2_facts(P2_WORKER_DIED);
    every
        .chain
        .as_mut()
        .unwrap()
        .transitions
        .insert(4, chain_row(0, "dispatched", "dispatched", "{}"));
    every.heads_after = Ok(vec![("main".to_owned(), "CD".repeat(16), 2)]);
    every.usage_rows = Ok(vec![(
        "attempt_advanced".to_owned(),
        serde_json::json!({"cost": {"quality": "authoritative"}}),
    )]);
    let (_, violations) = judge(P2Restart::WorkerDied, &every);
    for (at, named) in [
        "2 implement dispatches",
        "a /work delta was published",
        "implement transition `attempt_advanced`",
    ]
    .into_iter()
    .enumerate()
    {
        assert!(
            violations.get(at).is_some_and(|why| why.contains(named)),
            "violation {at} names {named:?}: {violations:?}"
        );
    }
    assert_eq!(violations.len(), 3, "{violations:?}");
    // Each read that failed is a violation of its own: the chain, the heads, the usage rows.
    let unreadable = "operational.db does not open read-only".to_owned();
    let mut unread_chain = held_p2_facts(P2_WORKER_DIED);
    unread_chain.chain = Err(unreadable.clone());
    let mut unread_heads = held_p2_facts(P2_WORKER_DIED);
    unread_heads.heads_after = Err(unreadable.clone());
    let mut unread_usage = held_p2_facts(P2_WORKER_DIED);
    unread_usage.usage_rows = Err(unreadable.clone());
    for (read, facts) in [
        ("chain", unread_chain),
        ("/work heads", unread_heads),
        ("usage rows", unread_usage),
    ] {
        let (_, violations) = judge(P2Restart::WorkerDied, &facts);
        assert_eq!(violations, [unreadable.as_str()], "an unread {read}");
    }
    // The settled attempt's OWN terminal_charge, with no usage row anywhere: a known
    // charge is named. The chain stays the recorded one, so nothing else can refuse.
    let mut charged = held_p2_facts(P2_WORKER_DIED);
    charged.failed_reason =
        Some(P2_WORKER_DIED.replace(r#""quality":"unavailable""#, r#""quality":"authoritative""#));
    let (_, violations) = judge(P2Restart::WorkerDied, &charged);
    assert!(
        violations.len() == 1 && violations[0].contains("the killed attempt's usage is recorded"),
        "the settled attempt's own known charge: {violations:?}"
    );
    // The observed settlement needs both the `failed` status and the typed verdict.
    let mut running = held_p2_facts(P2_WORKER_DIED);
    running.status = "running".to_owned();
    let ((observed, detail), _) = judge(P2Restart::WorkerDied, &running);
    assert_eq!(observed, "other");
    assert!(detail.is_some_and(|detail| detail.starts_with("status running")));
    let mut not_ambiguous = held_p2_facts(P2_WORKER_DIED);
    not_ambiguous.failed_reason = Some(P2_WORKER_DIED.replace(
        r#""verdict":"proven_ambiguous""#,
        r#""verdict":"proven_not_performed""#,
    ));
    let ((observed, detail), _) = judge(P2Restart::WorkerDied, &not_ambiguous);
    assert_eq!(
        observed, "other",
        "a failed status with another typed verdict"
    );
    assert!(detail.is_some_and(|detail| detail.starts_with("status failed")));
}

/// The host column's stopped control: every thread `T`. A leader in `T` beside a running
/// thread, an exiting process (`I`/`Z`), and no threads at all are not stopped.
#[test]
fn a_process_is_stopped_only_when_every_thread_is() {
    assert!(all_stopped(&['T', 'T', 'T']));
    assert!(!all_stopped(&['T', 'R', 'T']));
    assert!(!all_stopped(&['I', 'T']));
    assert!(!all_stopped(&['Z']));
    assert!(!all_stopped(&[]));
}
/// The host column's stop control: every thread `T` and no `resumed at` line. A process
/// stopped late, after it printed its resumption (measured on a process-directed
/// SIGSTOP, with no SIGCONT sent), is not stopped at the point.
#[test]
fn a_process_that_ran_past_its_stop_is_not_stopped_at_the_point() {
    let boundary = P1_BOUNDARY;
    let stopped = format!(
        "{} (KATA_FAULT_INJECT=operational.{boundary}, action=stop); stopping process now \
         (SIGSTOP)\n",
        crash_marker(boundary)
    );
    assert_eq!(judge_host_stop(&stopped, &['T', 'T'], boundary), Ok(()));
    let ran_on = format!(
        "{stopped}[kata-fault-inject] resumed at operational.{boundary}; aborting process now\n"
    );
    let refusal = judge_host_stop(&ran_on, &['T', 'T'], boundary).expect_err("ran past");
    assert!(refusal.contains("ran past the point"), "{refusal}");
    let running = judge_host_stop(&stopped, &['T', 'R'], boundary).expect_err("running");
    assert!(running.contains("not stopped"), "{running}");
}
/// The host column reads the armed process's threads until all are `T`: a process that
/// stops itself a moment after the cell first looks (as the point does, after its marker)
/// reads stopped, not VOID.
#[test]
fn a_process_that_stops_a_moment_later_reads_stopped() {
    struct Reaped(std::process::Child);
    impl Drop for Reaped {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
    let child = Reaped(
        std::process::Command::new("sh")
            .args(["-c", "sleep 0.3; kill -STOP $$"])
            .spawn()
            .expect("sh spawns"),
    );
    let states = stopped_thread_states(child.0.id(), Duration::from_secs(10));
    assert!(all_stopped(&states), "{states:?}");
}
/// A caller's `KATA_FAULT_INJECT` or `KATA_FAULT_INJECT_ACTION` refuses the cell; an
/// environment with neither admits it.
#[test]
fn an_inherited_fault_variable_refuses_the_cell() {
    assert_eq!(refuse_inherited_fault_env(|_| None), Ok(()));
    for name in FAULT_ENV {
        let refusal = refuse_inherited_fault_env(|asked| (asked == name).then(|| "stop".into()))
            .expect_err(name);
        assert!(refusal.contains(&format!("{name}=\"stop\"")), "{refusal}");
    }
}
/// D2 §5.4 spend (a): a killed attempt's usage is unknown — no charge, a charge with no
/// usage, or a cost `unavailable` — never an `authoritative` or `estimated` cost, and
/// never usage that states no cost at all.
#[test]
fn a_killed_attempts_charge_must_state_its_usage_unknown() {
    use serde_json::json;
    let usage = |cost: serde_json::Value| json!({ "token_usage": { "input": 0, "cost": cost } });
    assert_eq!(killed_charge_is_unknown(&serde_json::Value::Null), Ok(()));
    assert_eq!(killed_charge_is_unknown(&json!({})), Ok(()));
    assert_eq!(
        killed_charge_is_unknown(&usage(json!({ "quality": "unavailable" }))),
        Ok(())
    );
    for refused in [
        usage(json!({ "quality": "authoritative", "micro_usd": 0 })),
        usage(json!({ "quality": "estimated", "micro_usd": 0 })),
        json!({ "token_usage": { "input": 0, "output": 0 } }),
    ] {
        let refusal = killed_charge_is_unknown(&refused).expect_err("a recorded usage");
        assert!(refusal.contains("not unknown"), "{refusal}");
    }
}
/// A node that did not come back after the kill: when its restarted main exited, the
/// record's detail and outcome source lead with the main's own last `Error:` line (the
/// cause), then the rig's symptom; with no such line, the symptom alone. Read back from the
/// written `run.toml`.
#[test]
fn a_node_that_did_not_come_back_names_the_mains_exit_before_the_symptom() {
    const EXIT: &str = "Error: installed-main workflow authority failed; restart recovery required";
    let serve = format!(
        "INFO booting\nError: an earlier refusal\nWARN recovering\n{EXIT}\n  Caused by: torn\n"
    );
    assert_eq!(main_exit_line(&serve), Some(EXIT));
    assert_eq!(
        main_exit_line("INFO up\n  Error: indented, not the main's exit\n"),
        None
    );
    let symptom = "the worker daemon never registered; its log is /w/kata-worker.log:\ntail";
    for (exit, detail) in [
        (
            Some(EXIT),
            format!(
                "the restarted node did not come up: the restarted main exited (`{EXIT}`); then \
                 the worker daemon never registered; its log is /w/kata-worker.log:"
            ),
        ),
        (
            None,
            "the restarted node did not come up: the worker daemon never registered; its log \
             is /w/kata-worker.log:"
                .to_owned(),
        ),
    ] {
        let root = tempfile::tempdir().unwrap();
        let mut cell = Cell::new("P1-host", E3Agent::NanocodeOpenai);
        let ended = not_restarted(&mut cell, symptom.to_owned(), exit, &CallCount::default());
        let (outcome, _, dir) = cell.record_in(root.path(), &ended);
        assert_eq!(outcome, "fail");
        let record: toml::Table =
            toml::from_str(&std::fs::read_to_string(dir.join("run.toml")).unwrap()).unwrap();
        assert_eq!(record["settlement"].as_str(), Some("other"));
        assert_eq!(record["settlement_detail"].as_str(), Some(detail.as_str()));
        let source = record["outcome_source"].as_str().unwrap();
        assert_eq!(source.contains(EXIT), exit.is_some(), "{source}");
    }
}
/// P1-host / P3-host: the pre-kill read admits exactly a `plan` attempt with no `failed`
/// transition; any recorded settlement (a heartbeat leg that ran before the kill) refuses,
/// and so does a raw read that FAILED (no database, no `transitions` table), which is never
/// read as "unsettled". Each read is real SQLite on a scratch `operational.db`.
#[test]
fn a_host_cell_admits_only_an_attempt_unsettled_at_the_kill() {
    const EXEC: &str = "01M76GVETF8M92KV4NFY3GSJX2";
    let scratch = tempfile::tempdir().unwrap();
    let data = scratch.path();
    let read = || raw_failed_transition(data, EXEC, "plan");

    let refusal = judge_unsettled_at_kill(&read()).expect_err("no database refuses");
    assert!(
        refusal.contains("pre-kill raw read of plan's failed transition failed"),
        "{refusal}"
    );

    let db = rusqlite::Connection::open(data.join("operational.db")).unwrap();
    db.execute_batch("CREATE TABLE other (x)").unwrap();
    let refusal = judge_unsettled_at_kill(&read()).expect_err("no transitions table refuses");
    assert!(refusal.contains("no such table: transitions"), "{refusal}");

    db.execute_batch(
        "CREATE TABLE transitions (seq INTEGER, execution_id BLOB, stage_id TEXT, \
         kind TEXT, resulting_state TEXT, payload_json BLOB)",
    )
    .unwrap();
    assert_eq!(read(), Ok(None));
    assert_eq!(judge_unsettled_at_kill(&read()), Ok(()));

    db.execute(
        "INSERT INTO transitions VALUES (1, ?1, 'plan', 'settled', 'failed', \
         'worker w died: missed heartbeats; PROVEN AMBIGUOUS')",
        [execution_blob(EXEC)],
    )
    .unwrap();
    let refusal = judge_unsettled_at_kill(&read()).expect_err("settled before the kill");
    assert!(
        refusal.contains("already settled before the kill: worker w died"),
        "{refusal}"
    );
}
/// P4-host's forge after the restart, before the main boots: admitted only when it still
/// holds exactly the one `kata/<exec>` it acknowledged, its fsck holds and no pull request
/// exists; a lost, changed or extra ref, a failed fsck, an early pull request, or an arm
/// phase that saw no single acknowledged push each refuse.
#[test]
fn the_host_forge_must_keep_exactly_what_it_acknowledged() {
    let one = vec!["abc\trefs/heads/kata/E".to_owned()];
    let ok: Result<(), String> = Ok(());
    assert_eq!(judge_forge_kept(&one, &one, &ok, 0), Ok(()));
    type Case<'a> = (
        &'a [String],
        &'a [String],
        Result<(), String>,
        usize,
        &'a str,
    );
    let cases: [Case; 6] = [
        (&one, &[], Ok(()), 0, "lost an acknowledged push"),
        (
            &one,
            &["abd\trefs/heads/kata/E".to_owned()],
            Ok(()),
            0,
            "lost an acknowledged push",
        ),
        (
            &one,
            &[one[0].clone(), one[0].clone()],
            Ok(()),
            0,
            "lost an acknowledged push",
        ),
        (
            &one,
            &one,
            Err("exit Some(2): broken".to_owned()),
            0,
            "fsck failed",
        ),
        (&one, &one, Ok(()), 1, "already holds 1 pull request"),
        (&[], &[], Ok(()), 0, "did not see exactly one"),
    ];
    for (at_arm, before_boot, fsck, creates, why) in cases {
        let refusal = judge_forge_kept(at_arm, before_boot, &fsck, creates).expect_err(why);
        assert!(refusal.contains(why), "{refusal}");
    }
}
/// The host column's forge keeps what it acknowledges: a push made under kata's own git
/// settings (`-c core.hooksPath=/dev/null`, as kata's forge export passes them) still runs
/// the bare's hook, which fsyncs the committed ref file and its directory before the push
/// returns, and the bare's config asks git to fsync every object and ref; the fake `gh`
/// fsyncs `gh.log` and its directory on every call. `sync` is a recording stand-in on PATH.
#[test]
fn the_host_forge_fsyncs_what_it_acknowledges() {
    use std::os::unix::fs::PermissionsExt;
    let root = tempfile::tempdir().unwrap();
    let fixture = fixture_repo(root.path());
    let mut cell = Cell::new("P4-host", E3Agent::Mock);
    keep_what_the_forge_acknowledges(&mut cell, &fixture.remote);
    let bin = root.path().join("fake-bin");
    std::fs::create_dir_all(&bin).unwrap();
    let synced = root.path().join("synced.log");
    std::fs::write(
        bin.join("sync"),
        format!("#!/bin/sh\nprintf '%s\\n' \"$@\" >> {}\n", synced.display()),
    )
    .unwrap();
    std::fs::set_permissions(bin.join("sync"), std::fs::Permissions::from_mode(0o755)).unwrap();
    let path = format!(
        "{}:{}",
        bin.display(),
        std::env::var("PATH").unwrap_or_default()
    );
    kata_test_utils::run_git(&fixture.repo, &["branch", "kata/E"]);
    let pushed = kata_test_utils::git::hermetic_git_in(&fixture.repo)
        .env("PATH", &path)
        .args(["push", "origin", "refs/heads/kata/E:refs/heads/kata/E"])
        .output()
        .expect("git push runs");
    assert!(
        pushed.status.success(),
        "{}",
        String::from_utf8_lossy(&pushed.stderr)
    );
    // The bare's OWN config file, the one its receive-pack runs on: a `git config <key>`
    // through `hermetic_git_in` would answer kata's `-c` overrides instead (`core.fsync`
    // and `core.fsyncMethod` among them), which a local push never hands the bare — the
    // hook's fsyncs above ran under kata's `-c core.hooksPath=/dev/null`.
    let config = |key: &str| {
        let out = kata_test_utils::git::hermetic_git()
            .args(["config", "--file"])
            .arg(fixture.remote.join("config"))
            .arg(key)
            .output()
            .expect("git config runs");
        String::from_utf8_lossy(&out.stdout).trim().to_owned()
    };
    assert_eq!(config("core.fsync"), "all");
    assert_eq!(config("core.fsyncMethod"), "fsync");
    let hook_synced = std::fs::read_to_string(&synced).unwrap_or_default();
    assert_eq!(
        hook_synced, "refs/heads/kata/E\nrefs/heads/kata\n",
        "the hook's fsyncs"
    );
    std::fs::remove_file(&synced).unwrap();
    let shim_root = root.path().join("shim");
    let shim = write_gh_shim(&shim_root).join("gh");
    let ran = std::process::Command::new(&shim)
        .env("PATH", &path)
        .args(["pr", "create", "--title", "t"])
        .status()
        .expect("the fake gh runs");
    assert!(ran.success());
    assert_eq!(
        std::fs::read_to_string(&synced).unwrap_or_default(),
        format!(
            "{}\n{}\n",
            shim_root.join("gh.log").display(),
            shim_root.display()
        ),
        "the fake gh's fsyncs"
    );
    assert_eq!(gh_creates_in(&shim_root.join("gh.log")), 1);
}
/// **The rig's reads of the tree it was built from never write git's index.** `kata_tree`
/// (every record's `tree.txt`) and the agent suite's `provenance` read the checkout's
/// `git status`; `bin/kata/build.rs` watches the index, so an index they rewrote would make
/// the next cargo invocation rebuild `kata`: in the E3 host column, the next cell's arm,
/// under the guest runner that holds the key. A fresh clone leaves the index racy (its
/// entries no older than the index file), and a `git status` that may take the index lock
/// refreshes such an index and writes it. The positive control is that plain `git status`,
/// through the same hermetic git: it rewrites this fixture's index, so the index is racy.
#[test]
fn the_rigs_tree_reads_leave_a_racy_index_untouched() {
    let root = tempfile::tempdir().unwrap();
    let repo = root.path();
    kata_test_utils::run_git(repo, &["init", "-q"]);
    std::fs::write(repo.join("tracked.txt"), "tracked\n").unwrap();
    kata_test_utils::run_git(repo, &["add", "tracked.txt"]);
    kata_test_utils::run_git(repo, &["commit", "-qm", "fixture"]);
    let index = repo.join(".git/index");
    // The index's mtime set back to the tracked file's whole second, as a checkout that
    // writes the files and then the index within one second leaves it.
    let make_racy = || {
        let modified = std::fs::metadata(repo.join("tracked.txt"))
            .and_then(|meta| meta.modified())
            .unwrap();
        let second = Duration::from_secs(
            modified
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        );
        std::fs::File::options()
            .write(true)
            .open(&index)
            .and_then(|file| file.set_modified(std::time::UNIX_EPOCH + second))
            .unwrap();
    };
    let index_state = || {
        let modified = std::fs::metadata(&index)
            .and_then(|meta| meta.modified())
            .unwrap();
        (modified, std::fs::read(&index).unwrap())
    };
    let reads: [(&str, &dyn Fn()); 2] = [
        ("kata_tree", &|| {
            let (_, tree) = kata_tree_in(repo);
            assert!(!tree.dirty, "{}", tree.text);
        }),
        ("provenance", &|| {
            let record = agent_change_rig::nanocode::provenance_in(repo);
            assert_eq!(record["working_tree_dirty"], false, "{record}");
        }),
    ];
    for (name, read) in reads {
        make_racy();
        let before = index_state();
        read();
        assert!(
            index_state() == before,
            "{name} rewrote the racy index (its mtime moved from {:?} to {:?})",
            before.0,
            index_state().0
        );
    }
    make_racy();
    let before = index_state();
    let status = kata_test_utils::git::hermetic_git_in(repo)
        .args(["status", "--porcelain"])
        .output()
        .expect("git runs");
    assert!(status.status.success());
    assert!(
        index_state().0 != before.0,
        "the positive control: a plain git status left the index alone, so it was not racy"
    );
}
