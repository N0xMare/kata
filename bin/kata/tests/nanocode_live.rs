//! **N6, the embedded harness's live acceptance**: nanocode turns on REAL
//! providers, through a real node — a `kata serve` main, its worker a
//! `kata-worker` daemon over `local_socket` or the node `kata serve`
//! supervises, each turn's capsule a real rootless container whose init is the
//! static `kata-toolhost`.
//!
//! * `nanocode_openai` × kata's OWN ChatGPT login (`kata login openai`, run by
//!   the owner; kata reads it itself) on `gpt-6-luna` at `medium`;
//! * `nanocode_anthropic` × `env:ANTHROPIC_API_KEY` on `claude-sonnet-5-5` at
//!   `medium`, the key in the cell's own environment from the checkout's
//!   untracked `.env` (`( set -a; . <checkout>/.env; set +a; just
//!   live-nanocode )`).
//!
//! MODEL BUDGET is spent: `just live-nanocode` runs these by hand, never a gate.
//! Each cell's deterministic, no-spend twin is `nanocode_interruption_live`.
//!
//! # What is read, and from where
//!
//! Every verdict is read OUTSIDE kata: git (the commit effect's `exec-<id>`
//! ref, the fixture's trunk, the bare remote through `git ls-remote` and `git
//! show`), the filesystem (no host `/work`), the capsule's cgroup off the
//! kernel's hierarchy, the hosting process's provider connection off `ss`,
//! `ps`, and the raw chain, attempt rows and CAS through second read-only
//! SQLite handles. kata's own login is judged only by kata (the verdict `kata
//! login status --check` gives `openai-chatgpt.json`, which must read `ok`);
//! `~/.codex/auth.json` only by `sha256sum`, compared before and after, never
//! printed. No record a cell writes, and no log the node wrote,
//! may carry a credential shape (`credential_shapes`: the cell never holds the
//! secret it scans for).
//!
//! # Evidence
//!
//! Each cell writes `target/test-logs/live-agents/nanocode-<cell>.json`: the
//! harness, model and execution, the raw usage and charge, the reported model,
//! the session evidence's model-call, tool-call and re-prompt counts, the
//! integrity checks' verdicts, and where the run came from (the checkout's
//! `HEAD`, whether its tree was dirty, the nanocode rev).

#![cfg(target_os = "linux")]

mod agent_change_rig;

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

use agent_change_rig::nanocode::{
    Harness, Outstanding, SupervisedNodeMain, accepted_attempt, accepted_payload,
    assert_door_closed, assert_no_credential_shapes,
    assert_restart_settled_ambiguous_never_redelivered, assert_unknown_charge,
    assert_unmetered_in_run, capsule_cgroup, cgroup_processes, established_connections, find_key,
    nanocode_node, ps_in_capsule, session_counts, stage_chain, stage_containers, stage_transitions,
    wait_for_live_capsule, wait_until_model_request_outstanding, write_evidence,
};
use agent_change_rig::{
    Node, PACK, TEST, assert_final_state, assert_no_container_residue, assert_no_mutation,
    assert_proven_ambiguous_never_redelivered, cas_object, git_rev, git_show, kata,
};
use kata_test_utils::git::hermetic_git_in;
use serde_json::{Value, json};

/// The agent label every pack here names.
const LABEL: &str = "nanocode";

/// The sentence every prompt here ends its turn with, the answer's shape
/// [`one_turn_pack`]'s `outputs` checks, stated in the prompt because nothing
/// else carries it to the model. `answer_shape!()` is [`ANSWER_SHAPE`], the
/// sentence up to the summary's description; `answer_shape!("<description>")`
/// is the whole sentence, a literal each prompt `concat!`s.
macro_rules! answer_shape {
    () => {
        "Your final answer is exactly one JSON object and nothing else, no prose and no code fence: {\"summary\": \"<"
    };
    ($summary:literal) => {
        concat!(answer_shape!(), $summary, ">\"}")
    };
}

/// [`answer_shape!`] up to the summary's description.
const ANSWER_SHAPE: &str = answer_shape!();

/// One `implement` turn of `prompt`, writing `/work` within `hello.txt` and
/// `src/**`, answering `{"summary": string}`, then the `commit` effect that
/// publishes its delta as `exec-<execution>` in the fixture's git.
///
/// Its flat `outputs` table is checked by kata and reaches the model on no
/// adapter: it lowers to no `produces=` contract, so no strict output schema is
/// sent (operator guide, "A stage's `produces=` contract as the turn's output
/// schema"). Every prompt here therefore states the answer's shape itself
/// ([`ANSWER_SHAPE`]), as a pack author must.
fn one_turn_pack(prompt: &str) -> String {
    format!(
        r#"implement = stage(
    id = "implement",
    agent = "{LABEL}",
    sandbox = "edit",
    produces_files = ["hello.txt", "src/**"],
    outputs = {{"summary": "string"}},
    prompt = """{prompt}""",
)
commit = stage(id = "commit", agent = "workspace_effect", op = "commit", depends_on = [implement])
workflow(
    "nanocode-n6",
    root = [implement],
    worktree_isolated = True,
    sandbox_profiles = {{"edit": sandbox_profile(workspace = "rw", net = "offline")}},
)
"#
    )
}

/// Write [`one_turn_pack`] of `prompt` under `root`.
fn write_pack(root: &Path, prompt: &str) -> PathBuf {
    let pack = root.join("nanocode-n6.star");
    std::fs::write(&pack, one_turn_pack(prompt)).unwrap();
    pack
}

/// A1's prompt for each kind: one shell command, one patch of an existing
/// file, each through the kind's own host tool, then the structured answer.
fn a1_prompt(harness: Harness) -> &'static str {
    match harness {
        Harness::OpenaiKataLogin => {
            concat!(
                "Do exactly these three steps, in order, and nothing else.\n\
             1. Run this shell command with your exec_command tool, verbatim: printf hi > /work/hello.txt\n\
             2. Use your apply_patch tool to edit the existing file /work/src/app.txt: replace its one line `needs-change` with `patched-by-nanocode`.\n\
             3. ",
                answer_shape!("one sentence naming both changes")
            )
        }
        Harness::AnthropicApiKey => {
            concat!(
                "Do exactly these three steps, in order, and nothing else.\n\
             1. Run this shell command with your Bash tool, verbatim: printf hi > /work/hello.txt\n\
             2. Use your Edit tool to edit the existing file /work/src/app.txt: replace its one line `needs-change` with `patched-by-nanocode`.\n\
             3. ",
                answer_shape!("one sentence naming both changes")
            )
        }
        _ => unreachable!("A1 runs a funded harness"),
    }
}

/// The prompt that keeps the model generating before any tool call: the
/// window A3, A3m and A5 interrupt.
const LONG_GENERATION: &str = concat!(
    "Before you call any tool, write in your reply a design note of about 2,000 words on how a durable workflow engine should settle a model request that is outstanding when the process holding it dies. Only after the whole note is written, run `printf done > /work/hello.txt` with your exec_command tool, then answer. ",
    answer_shape!("one sentence")
);

/// A4's prompt: a foreground tool call the kill lands inside.
const SLEEP_TOOL: &str = concat!(
    "Use your exec_command tool to run exactly `sleep 60` and wait until it has finished before you do anything else. Then answer. ",
    answer_shape!("one sentence saying the sleep finished")
);

/// The re-prompt measurement's prompt: one tool call, then the answer — a
/// turn shaped like the work the harness is for.
const MEASURE: &str = concat!(
    "Run `ls /work/src` with your exec_command tool, then answer. ",
    answer_shape!("one sentence naming the files you saw")
);

// ---------------------------------------------------------------------------
// Integrity: what the cell checks before and after every run
// ---------------------------------------------------------------------------

/// `sha256sum ~/.codex/auth.json`'s stdout, never printed: the one allowed
/// read of another tool's login, compared before and after. `None` when the
/// file is absent.
fn codex_login_digest() -> Option<String> {
    let path = PathBuf::from(std::env::var_os("HOME").expect("HOME")).join(".codex/auth.json");
    if !path.is_file() {
        return None;
    }
    let out = Command::new("sha256sum")
        .arg(&path)
        .output()
        .expect("sha256sum runs");
    assert!(out.status.success(), "{TEST}: sha256sum failed");
    Some(String::from_utf8_lossy(&out.stdout).into_owned())
}

/// The `test-support` door a `kata` built for tests takes its logins
/// directory from (`kata_worker::owner_home::kata_logins_dir`).
const LOGINS_DOOR: &str = "KATA_TEST_KATA_LOGINS_DIR";

/// kata's own verdict on its ChatGPT login: the label `kata login status
/// --check` gives `openai-chatgpt.json` in its checked section (`ok`, or why
/// not: `absent` among them, which the command's exit does not fail). The
/// lines name the account, so only a label that is one lowercase word is
/// read out, never a line printed or recorded. `logins` points the
/// `test-support` door at another directory.
fn kata_chatgpt_login_verdict(logins: Option<&Path>) -> String {
    let mut command = kata();
    command.args(["login", "status", "--check"]);
    if let Some(dir) = logins {
        command.env(LOGINS_DOOR, dir);
    }
    let out = command.output().expect("kata login status --check runs");
    let file = format!(
        "{}: ",
        kata_agent_nanocode::credential::LoginFile::OpenAiChatGpt.file_name()
    );
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .skip_while(|line| !line.starts_with("checked ("))
        .find_map(|line| line.trim_start().strip_prefix(file.as_str()))
        .and_then(|rest| rest.split_once(':'))
        .map(|(label, _)| label)
        .filter(|label| !label.is_empty() && label.bytes().all(|byte| byte.is_ascii_lowercase()))
        .map_or_else(|| "unread".to_owned(), str::to_owned)
}

/// The integrity a funded run owes, taken before it.
struct Before {
    codex: Option<String>,
}

impl Before {
    fn take() -> Self {
        Self {
            codex: codex_login_digest(),
        }
    }

    /// After the run: `~/.codex/auth.json` byte-identical (kata never lifts
    /// it for nanocode), kata's own ChatGPT login still checks `ok` for the
    /// OpenAI kind, no log carries a credential shape, and no door was open.
    fn after(self, harness: Harness, logs: &[PathBuf]) -> Value {
        assert_eq!(
            codex_login_digest(),
            self.codex,
            "{TEST}: ~/.codex/auth.json changed across a nanocode run"
        );
        let verdict =
            (harness == Harness::OpenaiKataLogin).then(|| kata_chatgpt_login_verdict(None));
        if let Some(verdict) = &verdict {
            assert_eq!(
                verdict, "ok",
                "{TEST}: kata's own ChatGPT login no longer checks `ok` after the run (`kata \
                 login status --check`)"
            );
        }
        for log in logs {
            assert_no_credential_shapes(log);
            assert_door_closed("node", log);
        }
        json!({
            // Asserted above; `null` when the host has no codex login to compare.
            "codex_auth_sha256_unchanged": self.codex.as_ref().map(|_| true),
            "kata_chatgpt_login_verdict": verdict,
            "logs_scanned": logs.len(),
        })
    }
}

// ---------------------------------------------------------------------------
// The raw reads every record carries
// ---------------------------------------------------------------------------

/// The `implement` attempt's settled (failed or cancelled) payload, raw.
fn settled_payload(data: &Path, execution: &str) -> Value {
    let (_, _, payload) = stage_transitions(data, execution, "implement")
        .into_iter()
        .rev()
        .find(|(_, state, _)| state == "failed" || state == "cancelled")
        .unwrap_or_else(|| panic!("{TEST}: the implement attempt never settled"));
    serde_json::from_str(&payload).expect("the settled payload is JSON")
}

/// A completed turn's metering, asserted against the raw accepted payload:
/// usage with `input > 0`, the charge each credential owes (`unavailable`
/// under the ChatGPT subscription, tokens kept; `estimated` under the
/// Anthropic key, which kata prices), and the model the provider reported.
fn assert_metered(harness: Harness, payload: &Value) -> Value {
    let usage = find_key(payload, "token_usage")
        .unwrap_or_else(|| panic!("{TEST}: the accepted turn records no usage: {payload}"))
        .clone();
    assert!(
        usage["input"].as_u64().is_some_and(|input| input > 0),
        "{TEST}: the turn's usage records input tokens: {usage}"
    );
    let quality = match harness {
        Harness::OpenaiKataLogin => "unavailable",
        _ => "estimated",
    };
    assert_eq!(
        usage["cost"]["quality"],
        json!(quality),
        "{TEST}: the {} turn's charge: {usage}",
        harness.adapter()
    );
    let reported = find_key(payload, "model_reported")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();
    assert!(
        reported.starts_with(harness.model()),
        "{TEST}: the provider reported model `{reported}`, not {}",
        harness.model()
    );
    json!({"token_usage": usage, "model_reported": reported})
}

/// Every log the node wrote.
fn node_logs(node: &Node) -> Vec<PathBuf> {
    node.logs().into_iter().map(Path::to_path_buf).collect()
}

/// Wait until a model request to the provider is outstanding from `host`: the
/// capsule runs only its toolhost, and `host` holds an ESTABLISHED connection
/// to a `:443` peer (`ss`), both for 5 s.
fn wait_outstanding(host: u32, capsule: &Path) -> Outstanding {
    wait_until_model_request_outstanding(capsule, Duration::from_secs(5), || {
        established_connections(host, 443)
    })
}

// ---------------------------------------------------------------------------
// A1 — a real turn in a real capsule
// ---------------------------------------------------------------------------

/// A1's body: the turn runs one shell command and one patch through the
/// kind's host tools and answers the structured output; the commit effect
/// publishes the `/work` delta.
///
/// The git check reads the run's published delta: the union of every accepted
/// attempt's `/work` delta, so it does NOT attribute the two changes to the
/// attempt kata settled `implement` on. Under a validation retry that union is
/// the documented design (protected-properties.md, "Validation retry": the
/// invalid attempt's accepted outcome stands and its `/work` delta is applied
/// before the retry mints, and the retry starts from it), so the edits may be
/// the invalid attempt's alone; the structured answer and the metering are read
/// off the settled attempt ([`accepted_attempt`]).
fn a1(harness: Harness, name: &str) {
    let before = Before::take();
    let node = nanocode_node(harness, LABEL, None);
    let data = node.root_path.join("data");
    let pack = write_pack(&node.root_path, a1_prompt(harness));
    let execution = node.main.submit(&pack);
    let doc = node.main.wait_terminal(&execution);
    assert_eq!(
        doc["status"].as_str(),
        Some("completed"),
        "{TEST}: A1 {name}: the run completes: {doc}"
    );
    // GIT: the published delta, every accepted attempt's, holds both changes.
    let published = format!("exec-{execution}");
    assert_eq!(
        git_show(&node.fixture.repo, &published, "hello.txt").as_deref(),
        Some("hi"),
        "{TEST}: A1 {name}: the shell command's file is in the published delta"
    );
    let app = git_show(&node.fixture.repo, &published, "src/app.txt").unwrap_or_default();
    assert!(
        app.contains("patched-by-nanocode") && !app.contains("needs-change"),
        "{TEST}: A1 {name}: the patch is in the published delta: {app:?}"
    );
    // FILESYSTEM: the capsule's /work never touched the host's root.
    assert!(!Path::new("/work").exists(), "{TEST}: the host has a /work");
    // RAW SQLITE: the structured answer and the metering.
    // The attempt kata settled `implement` on: a validation retry's, when the
    // first answer failed the stage's `outputs`.
    let (accepted, payload) = accepted_attempt(&stage_chain(&data, &execution, "implement"));
    // The stage's outputs are that completion's `output.content`, a JSON
    // document the `outputs` table `{"summary": "string"}` was checked against.
    let summary = payload["output"]["content"]
        .as_str()
        .and_then(|content| serde_json::from_str::<Value>(content).ok())
        .and_then(|content| content["summary"].as_str().map(str::to_owned))
        .unwrap_or_else(|| panic!("{TEST}: A1 {name}: no structured summary: {payload}"));
    let metered = assert_metered(harness, &payload);
    // PS + KERNEL: nothing left in the capsule.
    let containers = stage_containers(&data, &execution, "implement");
    assert!(
        !containers.is_empty(),
        "{TEST}: A1 {name}: no capsule recorded"
    );
    for container in &containers {
        assert_eq!(
            ps_in_capsule(container),
            Vec::<String>::new(),
            "{TEST}: A1 {name}: ps lists a process in {container}"
        );
    }
    assert_no_container_residue(&node, &execution);
    let integrity = before.after(harness, &node_logs(&node));
    write_evidence(
        &format!("a1-{name}"),
        &json!({
            "cell": format!("A1 {name}"),
            "execution": execution,
            "adapter": harness.adapter(),
            "model": harness.model(),
            "status": doc["status"],
            "accepted_attempt": accepted,
            "summary": summary,
            "metering": metered,
            "session": session_counts(&data, &payload),
            "integrity": integrity,
        }),
    );
}

/// **A1, Responses × the ChatGPT login.** `exec_command` writes
/// `/work/hello.txt`, `apply_patch` edits `src/app.txt`, the answer matches
/// `{"summary": string}`; the published delta in git holds both changes, the
/// host has no `/work`, the raw accepted payload holds `input > 0`, the charge
/// `unavailable` with the tokens kept and `model_reported` `gpt-6-luna`, `ps`
/// lists nothing in the capsule, kata's login still checks `ok` and
/// `~/.codex/auth.json`'s digest is unchanged.
#[test]
#[ignore = "spends model budget (kata's ChatGPT login); just live-nanocode"]
fn a1_a_real_nanocode_openai_turn_in_a_real_capsule_live() {
    a1(Harness::OpenaiKataLogin, "openai");
}

/// **A1, Messages × the API key.** The same through `Bash` and `Edit` (the
/// Messages kind's host tools), the charge `estimated` (kata prices
/// `claude-sonnet-5-5`), `model_reported` `claude-sonnet-5-5`.
#[test]
#[ignore = "spends model budget (the Anthropic API key); just live-nanocode"]
fn a1_a_real_nanocode_anthropic_turn_in_a_real_capsule_live() {
    a1(Harness::AnthropicApiKey, "anthropic");
}

// ---------------------------------------------------------------------------
// A2 — the shipped agent-change pack, offline, landed on a local bare remote
// ---------------------------------------------------------------------------

/// A2's body: `implement` on the harness (the pack's `edit` profile is
/// `net = "offline"` and the node declares no `egress_allow`), then test →
/// approve → commit → promote → export to the fixture's local bare remote.
fn a2(harness: Harness, name: &str) {
    let before = Before::take();
    let node = nanocode_node(harness, "change-agent", None);
    let config = std::fs::read_to_string(&node.config).unwrap();
    assert!(
        !config.contains("egress_allow"),
        "{TEST}: A2 {name}: the node declares no egress_allow"
    );
    let execution = node.main.submit(Path::new(PACK));
    let gate = node
        .main
        .next_gate(&execution)
        .expect("the approve stage parks a gate");
    node.main.decide(&gate, None);
    let doc = node.main.wait_terminal(&execution);
    assert_eq!(
        doc["status"].as_str(),
        Some("completed"),
        "{TEST}: A2 {name}: the run completes: {doc}"
    );
    assert_final_state(&node, &execution);
    // GIT, from the remote's side: `ls-remote` names the exported ref, and
    // `show` at it holds the change.
    let branch = format!("refs/heads/kata/{execution}");
    let listed = hermetic_git_in(&node.fixture.repo)
        .args(["ls-remote", node.fixture.remote.to_str().unwrap(), &branch])
        .output()
        .expect("git ls-remote runs");
    let listed = String::from_utf8_lossy(&listed.stdout).into_owned();
    let sha = listed
        .split_whitespace()
        .next()
        .unwrap_or_else(|| panic!("{TEST}: A2 {name}: ls-remote lists no {branch}"))
        .to_owned();
    assert_eq!(
        git_show(&node.fixture.remote, &sha, "src/app.txt").as_deref(),
        Some("implemented-change\n"),
        "{TEST}: A2 {name}: the remote's ref holds the change"
    );
    let data = node.root_path.join("data");
    let payload = accepted_payload(&data, &execution);
    let metered = assert_metered(harness, &payload);
    let integrity = before.after(harness, &node_logs(&node));
    write_evidence(
        &format!("a2-{name}"),
        &json!({
            "cell": format!("A2 {name}"),
            "execution": execution,
            "adapter": harness.adapter(),
            "model": harness.model(),
            "status": doc["status"],
            "exported_ref": branch,
            "exported_sha_matches_trunk": git_rev(&node.fixture.repo, &node.fixture.trunk)
                .as_deref() == Some(sha.as_str()),
            "metering": metered,
            "session": session_counts(&data, &payload),
            "integrity": integrity,
        }),
    );
}

/// **A2, Responses × the ChatGPT login.** The shipped `agent-change` pack
/// lands on `nanocode_openai`, offline: the remote's `kata/<exec>` ref holds
/// `implemented-change`, read through `git ls-remote` and `git show`.
#[test]
#[ignore = "spends model budget (kata's ChatGPT login); just live-nanocode"]
fn a2_the_agent_change_pack_lands_on_nanocode_openai_live() {
    a2(Harness::OpenaiKataLogin, "openai");
}

/// **A2, Messages × the API key.** The same on `nanocode_anthropic`.
#[test]
#[ignore = "spends model budget (the Anthropic API key); just live-nanocode"]
fn a2_the_agent_change_pack_lands_on_nanocode_anthropic_live() {
    a2(Harness::AnthropicApiKey, "anthropic");
}

// ---------------------------------------------------------------------------
// A3 / A4 / A5 — interruptions on the daemon worker; A3m on a supervising main
// ---------------------------------------------------------------------------

/// **A3, the worker killed while a model request is outstanding.** The turn
/// generates a long note before any tool call; once the capsule's cgroup holds
/// only the toolhost and `ss` shows the worker ESTABLISHED to the provider's
/// `:443`, both for 5 s, the daemon is SIGKILLed. The claim is "killed with no
/// tool running and the model connection open" (a websocket stays open between
/// calls; `nanocode_interruption_live`'s mock twin makes the certain claim).
/// Settled PROVEN AMBIGUOUS naming the death, never re-delivered, no second
/// attempt row, the charge unknown, nothing published, no container or cgroup
/// left.
#[test]
#[ignore = "spends model budget (kata's ChatGPT login); just live-nanocode"]
fn a3_a_worker_killed_with_a_model_request_outstanding_settles_ambiguous_live() {
    let harness = Harness::OpenaiKataLogin;
    let before = Before::take();
    let mut node = nanocode_node(harness, LABEL, None);
    let data = node.root_path.join("data");
    let pack = write_pack(&node.root_path, LONG_GENERATION);
    let execution = node.main.submit(&pack);
    let container = wait_for_live_capsule(&data, &execution, "implement");
    let capsule = capsule_cgroup(node.worker.pid, &container)
        .unwrap_or_else(|| panic!("{TEST}: no cgroup for {container}"));
    let seen = wait_outstanding(node.worker.pid, &capsule);
    eprintln!("A3 POSITIVE CONTROL: {seen:?}");
    node.worker.kill();
    let doc = node.main.wait_terminal(&execution);
    assert_eq!(doc["status"].as_str(), Some("failed"), "{TEST}: A3: {doc}");
    let reason = assert_proven_ambiguous_never_redelivered(&mut node, &execution);
    let settled = settled_payload(&data, &execution);
    let charge = assert_unknown_charge(&settled);
    assert_unmetered_in_run(&doc, "implement");
    assert_no_mutation(&node, &execution);
    assert_no_container_residue(&node, &execution);
    let integrity = before.after(harness, &node_logs(&node));
    write_evidence(
        "a3-openai",
        &json!({
            "cell": "A3 worker kill, model request outstanding",
            "execution": execution,
            "adapter": harness.adapter(),
            "model": harness.model(),
            "status": doc["status"],
            "witness": {
                "capsule_processes": seen.capsule_processes.len(),
                "provider_connections": seen.connection.len(),
            },
            "settled_reason_names_death_and_ambiguity": reason.contains("AMBIGUOUS"),
            "terminal_charge": charge,
            "tokens_recorded": "unknown",
            "integrity": integrity,
        }),
    );
}

/// **A3m, a main killed while its supervised node's model request is
/// outstanding.** The same witness (the capsule runs only its toolhost; `ss`
/// shows the NODE `kata serve` supervises, which hosts the worker, ESTABLISHED
/// to `:443`), then a SIGKILL of the main, whose node ends with its connection,
/// and a restart on the same data directory: the attempt is settled PROVEN
/// AMBIGUOUS, "the main restarted", no attempt is re-claimed after the recovery
/// window, the capsule's cgroup is empty, the commit effect published no
/// `exec-<exec>` and nothing else landed, and no container process or `kata.*`
/// cgroup of either main's node is left.
#[test]
#[ignore = "spends model budget (kata's ChatGPT login); just live-nanocode"]
fn a3m_a_main_killed_with_its_supervised_nodes_turn_outstanding_settles_on_restart_live() {
    let harness = Harness::OpenaiKataLogin;
    let before = Before::take();
    let mut node = SupervisedNodeMain::boot(harness, LABEL, None);
    let pack = write_pack(node.root.path(), LONG_GENERATION);
    let execution = node.main.submit(&pack);
    let container = wait_for_live_capsule(&node.data, &execution, "implement");
    let host = *node.node_pids.last().expect("the booted main's node");
    let capsule = capsule_cgroup(host, &container)
        .unwrap_or_else(|| panic!("{TEST}: no cgroup for {container}"));
    let seen = wait_outstanding(host, &capsule);
    eprintln!("A3m POSITIVE CONTROL: {seen:?}");
    node.kill_and_restart();
    let reason =
        assert_restart_settled_ambiguous_never_redelivered(&node.data, &execution, "implement");
    let doc = node.main.wait_terminal(&execution);
    assert_eq!(doc["status"].as_str(), Some("failed"), "{TEST}: A3m: {doc}");
    let charge = assert_unknown_charge(&serde_json::from_str(&reason).unwrap_or(Value::Null));
    assert_unmetered_in_run(&doc, "implement");
    let deadline = Instant::now() + Duration::from_secs(30);
    while !cgroup_processes(&capsule).is_empty() {
        assert!(
            Instant::now() < deadline,
            "{TEST}: A3m: the killed main's capsule still runs {:?}",
            cgroup_processes(&capsule)
        );
        std::thread::sleep(Duration::from_millis(200));
    }
    assert_eq!(
        ps_in_capsule(&container),
        Vec::<String>::new(),
        "{TEST}: A3m: ps lists a process in the capsule"
    );
    node.assert_left_nothing(&execution);
    let integrity = before.after(harness, &node.main_logs);
    write_evidence(
        "a3m-openai",
        &json!({
            "cell": "A3m supervising main kill, model request outstanding",
            "execution": execution,
            "adapter": harness.adapter(),
            "model": harness.model(),
            "status": doc["status"],
            "witness": {
                "capsule_processes": seen.capsule_processes.len(),
                "provider_connections": seen.connection.len(),
            },
            "settled_reason_names_restart_and_ambiguity": true,
            "terminal_charge": charge,
            "tokens_recorded": "unknown",
            "integrity": integrity,
        }),
    );
}

/// **A4, the worker killed during a tool call.** The model runs `sleep 60`;
/// once the capsule's cgroup holds a process whose `comm` is `sleep`, the
/// daemon is SIGKILLed, and the capsule's cgroup is read EMPTY within 10 s of
/// the kill and before any worker restarts: kata's worker-death path ends the
/// capsule, not a restart or a recovery sweep, and not systemd, which leaves a
/// killed scope leader's other processes running. That path has two arms,
/// each enough alone, and the cell does not tell them apart: the toolhost's
/// stdin EOF (its `KillAll`, then its exit as the capsule's init), and the
/// provider's read of its closed supervisor stream (`youki kill <id> KILL`).
/// Then the settle A3 asserts.
#[test]
#[ignore = "spends model budget (kata's ChatGPT login); just live-nanocode"]
fn a4_a_worker_killed_during_a_tool_call_empties_the_capsule_live() {
    let harness = Harness::OpenaiKataLogin;
    let before = Before::take();
    let mut node = nanocode_node(harness, LABEL, None);
    let data = node.root_path.join("data");
    let pack = write_pack(&node.root_path, SLEEP_TOOL);
    let execution = node.main.submit(&pack);
    let container = wait_for_live_capsule(&data, &execution, "implement");
    let capsule = capsule_cgroup(node.worker.pid, &container)
        .unwrap_or_else(|| panic!("{TEST}: no cgroup for {container}"));
    let deadline = Instant::now() + Duration::from_secs(240);
    let running = loop {
        let processes = cgroup_processes(&capsule);
        if processes.iter().any(|(_, comm)| comm == "sleep") {
            break processes;
        }
        assert!(
            Instant::now() < deadline,
            "{TEST}: A4: the model never ran the sleep: {processes:?}"
        );
        std::thread::sleep(Duration::from_millis(100));
    };
    eprintln!("A4 POSITIVE CONTROL: capsule runs {running:?}");
    // The bound runs from the SIGKILL, not from the reaped exit `kill` waits for.
    let killed = Instant::now();
    node.worker.kill();
    let emptied = loop {
        let left = cgroup_processes(&capsule);
        if left.is_empty() {
            break killed.elapsed();
        }
        assert!(
            killed.elapsed() < Duration::from_secs(10),
            "{TEST}: A4: the capsule still runs {left:?} 10 s after its worker died"
        );
        std::thread::sleep(Duration::from_millis(100));
    };
    let doc = node.main.wait_terminal(&execution);
    assert_eq!(doc["status"].as_str(), Some("failed"), "{TEST}: A4: {doc}");
    assert_proven_ambiguous_never_redelivered(&mut node, &execution);
    let charge = assert_unknown_charge(&settled_payload(&data, &execution));
    assert_unmetered_in_run(&doc, "implement");
    assert_no_mutation(&node, &execution);
    assert_no_container_residue(&node, &execution);
    let integrity = before.after(harness, &node_logs(&node));
    write_evidence(
        "a4-openai",
        &json!({
            "cell": "A4 worker kill during a tool call",
            "execution": execution,
            "adapter": harness.adapter(),
            "model": harness.model(),
            "status": doc["status"],
            "capsule_empty_after_kill_ms": u64::try_from(emptied.as_millis()).unwrap_or(u64::MAX),
            "terminal_charge": charge,
            "tokens_recorded": "unknown",
            "integrity": integrity,
        }),
    );
}

/// **A5, an operator cancel during a model call; the worker lives.** Once a
/// model request is outstanding (A3's witness), `kata run cancel`: the run is
/// `cancelled`, the raw settled transition carries the worker's own reason
/// that the harness confirmed the cancel, and its charge is the usage so far or
/// `unavailable`, never a bare zero.
#[test]
#[ignore = "spends model budget (kata's ChatGPT login); just live-nanocode"]
fn a5_an_operator_cancel_during_a_model_call_is_confirmed_live() {
    let harness = Harness::OpenaiKataLogin;
    let before = Before::take();
    let node = nanocode_node(harness, LABEL, None);
    let data = node.root_path.join("data");
    let pack = write_pack(&node.root_path, LONG_GENERATION);
    let execution = node.main.submit(&pack);
    let container = wait_for_live_capsule(&data, &execution, "implement");
    let capsule = capsule_cgroup(node.worker.pid, &container)
        .unwrap_or_else(|| panic!("{TEST}: no cgroup for {container}"));
    let seen = wait_outstanding(node.worker.pid, &capsule);
    eprintln!("A5 POSITIVE CONTROL: {seen:?}");
    node.main.cancel(&execution);
    let doc = node.main.wait_terminal(&execution);
    assert_eq!(
        doc["status"].as_str(),
        Some("cancelled"),
        "{TEST}: A5: {doc}"
    );
    let settled = settled_payload(&data, &execution);
    let text = settled.to_string();
    assert!(
        text.contains("the harness confirmed the cancel") && !text.contains("did not confirm"),
        "{TEST}: A5: the worker recorded the harness's confirmed cancel: {settled}"
    );
    let charge = find_key(&settled, "terminal_charge")
        .cloned()
        .unwrap_or_else(|| panic!("{TEST}: A5: the cancel records no charge: {settled}"));
    let quality = charge["token_usage"]["cost"]["quality"].clone();
    assert!(
        quality == json!("unavailable") && charge["token_usage"].get("cost_micro_usd").is_none(),
        "{TEST}: A5: a subscription turn's cancelled charge is unavailable: {charge}"
    );
    assert_no_mutation(&node, &execution);
    assert_no_container_residue(&node, &execution);
    let integrity = before.after(harness, &node_logs(&node));
    write_evidence(
        "a5-openai",
        &json!({
            "cell": "A5 operator cancel during a model call",
            "execution": execution,
            "adapter": harness.adapter(),
            "model": harness.model(),
            "status": doc["status"],
            "terminal_charge": charge,
            "integrity": integrity,
        }),
    );
}

// ---------------------------------------------------------------------------
// The empty-response re-prompt, measured on the real provider
// ---------------------------------------------------------------------------

/// The runs [`the_empty_response_reprompt_is_measured_on_the_real_provider_live`]
/// makes: enough for a count, few enough for the owner's testing spend.
const MEASURED_TURNS: usize = 3;

/// **The empty-response re-prompt, MEASURED on gpt-6-luna.** nanocode (≥
/// 1651198b) answers a Responses reply with neither a final message nor an
/// `exec`/`wait` call by appending one `<empty_response>` message and
/// sampling again inside the same turn: a model call kata's prompt did not
/// cause. Three turns of one tool call and an answer run on one node; for
/// each, the turn's published session evidence (read raw out of the CAS)
/// counts its completed model calls, its tool calls and its re-prompts (a
/// completed call followed by another with no tool call between), and the
/// accepted payload its metered usage. The cell asserts every turn completed
/// and metered (`input > 0`, `unavailable`); the counts are the measurement,
/// written to the evidence record, not a verdict.
#[test]
#[ignore = "spends model budget (kata's ChatGPT login); just live-nanocode"]
fn the_empty_response_reprompt_is_measured_on_the_real_provider_live() {
    let harness = Harness::OpenaiKataLogin;
    let before = Before::take();
    let node = nanocode_node(harness, LABEL, None);
    let data = node.root_path.join("data");
    let pack = write_pack(&node.root_path, MEASURE);
    let mut turns = Vec::new();
    for _ in 0..MEASURED_TURNS {
        let execution = node.main.submit(&pack);
        let doc = node.main.wait_terminal(&execution);
        assert_eq!(
            doc["status"].as_str(),
            Some("completed"),
            "{TEST}: measure: the run completes: {doc}"
        );
        let accepted = accepted_payload(&data, &execution);
        let metered = assert_metered(harness, &accepted);
        let counts = session_counts(&data, &accepted);
        assert!(
            counts["model_calls_completed"]
                .as_u64()
                .is_some_and(|calls| calls >= 1),
            "{TEST}: measure: the turn's session evidence records its model calls: {counts}"
        );
        turns.push(json!({"execution": execution, "metering": metered, "session": counts}));
    }
    let reprompts: u64 = turns
        .iter()
        .filter_map(|turn| turn["session"]["reprompts"].as_u64())
        .sum();
    let calls: u64 = turns
        .iter()
        .filter_map(|turn| turn["session"]["model_calls_completed"].as_u64())
        .sum();
    let integrity = before.after(harness, &node_logs(&node));
    write_evidence(
        "reprompt-measurement-openai",
        &json!({
            "cell": "empty-response re-prompt measurement",
            "adapter": harness.adapter(),
            "model": harness.model(),
            "turns": turns,
            "model_calls_completed": calls,
            "reprompts": reprompts,
            "integrity": integrity,
        }),
    );
    eprintln!(
        "MEASURED: {reprompts} re-prompt(s) over {calls} completed model call(s) in {MEASURED_TURNS} turns"
    );
}

// ---------------------------------------------------------------------------
// Host-free: the reads the funded cells' verdicts and records rest on
// ---------------------------------------------------------------------------

/// **An absent ChatGPT login fails the funded cells' integrity verdict.**
/// `kata login status --check` exits 0 with nothing stored (an absent file
/// fails nothing), so its exit cannot say that kata's login survived a run.
/// The verdict the cells require is the label the command gives
/// `openai-chatgpt.json`, read here off the `test-support` `kata` pointed at
/// an empty logins directory: `absent`, never `ok`. The door is confirmed
/// first by `kata login status`'s own heading, so the owner's login is never
/// read.
///
/// **Would red if:** the verdict were the command's exit code (watched: the
/// empty directory read `ok`).
#[test]
fn an_absent_chatgpt_login_fails_the_integrity_verdict() {
    let logins = tempfile::tempdir().expect("an empty logins directory");
    // Owner-only, as kata requires of its logins directory: with group or
    // world bits every file reads `refused`, not `absent`.
    std::fs::set_permissions(
        logins.path(),
        std::os::unix::fs::PermissionsExt::from_mode(0o700),
    )
    .unwrap();
    let status = kata()
        .args(["login", "status"])
        .env(LOGINS_DOOR, logins.path())
        .output()
        .expect("kata login status runs");
    let heading = String::from_utf8_lossy(&status.stdout)
        .lines()
        .next()
        .unwrap_or_default()
        .to_owned();
    assert_eq!(
        heading,
        format!("kata logins in {}", logins.path().display()),
        "{TEST}: this `kata` does not take its logins directory from {LOGINS_DOOR}; build it \
         with kata-worker's `test-support` (the workspace test build)"
    );
    assert_eq!(
        kata_chatgpt_login_verdict(Some(logins.path())),
        "absent",
        "{TEST}: an empty logins directory's ChatGPT verdict"
    );
}

/// **The rig's raw CAS read returns an object over the store's inline
/// threshold.** kata's own store writes one object inline (its `cas.db` row
/// holds the bytes) and one past `INLINE_THRESHOLD` (a `cas/**` blob file,
/// the row's blob NULL); `cas_object` reads both back byte for byte without
/// kata's reader. A long turn's session evidence is the second kind, and
/// [`session_counts`] reads it so.
///
/// **Would red if:** a missing inline row ended the read before the blob tree
/// was searched (watched: the file-backed object read as absent).
#[test]
fn the_raw_cas_read_returns_an_inline_and_a_file_backed_object() {
    use kata_core::store::cas::{CasStore, INLINE_THRESHOLD};

    let data = tempfile::tempdir().expect("a data directory");
    let store = CasStore::open(data.path().join("cas.db"), data.path().join("cas"))
        .expect("kata's CAS opens");
    let inline = br#"{"events":[]}"#.to_vec();
    let file_backed = vec![b'x'; INLINE_THRESHOLD + 1];
    let inline_id = store.put(&inline).expect("the inline object stores");
    let file_backed_id = store
        .put(&file_backed)
        .expect("the file-backed object stores");
    drop(store);
    assert_eq!(
        cas_object(data.path(), &inline_id.to_string()),
        Some(inline),
        "{TEST}: the inline object reads back"
    );
    let read = cas_object(data.path(), &file_backed_id.to_string());
    assert!(
        read.as_deref() == Some(file_backed.as_slice()),
        "{TEST}: the file-backed object reads back: {:?} bytes read of {}",
        read.as_ref().map(Vec::len),
        file_backed.len()
    );
}

/// The `implement` chain N6 A1 recorded on `nanocode-anthropic` at `4da3b2fe2aa4`
/// (execution `01M784XRE9PVN2223VSYDQ71Q2`; payloads cut to the fields read here):
/// attempt 0 was accepted and its answer failed the stage's `outputs`, so validation
/// retried; attempt 1 was accepted and amended with its `parsed` output.
fn a1_two_attempt_chain() -> Vec<agent_change_rig::nanocode::RawTransition> {
    let attempt_0 = json!({"attempt_ordinal": 0, "output": {"content": "I don't have the output schema in front of me, so this assumes a `summary` field.\n\n```json\n{\"summary\": \"Created /work/hello.txt containing \\\"hi\\\" and edited /work/src/app.txt to replace `needs-change` with `patched-by-nanocode`.\"}\n```"}});
    let answer_1 = "{\"summary\":\"Wrote 'hi' to /work/hello.txt; /work/src/app.txt already read 'patched-by-nanocode' when I opened it, so I made no edit there.\"}";
    let attempt_1 = json!({"attempt_ordinal": 1, "output": {"content": answer_1}});
    let amended_1 = json!({"output": {"content": answer_1, "parsed": serde_json::from_str::<Value>(answer_1).unwrap()}});
    let row = |ordinal: i64, kind: &str, state: &str, payload: &Value| {
        (
            Some(ordinal),
            kind.to_owned(),
            state.to_owned(),
            payload.to_string(),
        )
    };
    let empty = json!({});
    vec![
        row(0, "claimed", "pending", &empty),
        row(0, "dispatched", "dispatched", &empty),
        row(0, "attempt_safe_point", "attempt_safe_point", &empty),
        row(0, "attempt_advanced", "running", &empty),
        row(0, "event_accepted", "completed", &attempt_0),
        row(1, "claimed", "pending", &empty),
        row(1, "dispatched", "dispatched", &empty),
        row(1, "attempt_safe_point", "attempt_safe_point", &empty),
        row(1, "attempt_advanced", "running", &empty),
        row(1, "event_accepted", "completed", &attempt_1),
        row(1, "outcome_amended", "outcome_amended", &amended_1),
    ]
}

/// The rig reads the attempt kata settled the stage on: on A1's recorded two-attempt
/// chain, attempt 1 (the validation retry, whose answer kata amended with `parsed`), never
/// attempt 0, whose answer failed the stage's `outputs`. A single accepted attempt is
/// itself; two amendments are judged by the last; a later attempt, or a last amendment
/// of another attempt, is refused.
///
/// **Would red if:** the rig took the FIRST accepting transition (watched: A1 failed
/// `no structured summary` on attempt 0's prose), or judged the FIRST amendment.
#[test]
fn the_rig_reads_the_attempt_kata_settled_the_stage_on() {
    let chain = a1_two_attempt_chain();
    let (ordinal, payload) = accepted_attempt(&chain);
    assert_eq!(ordinal, 1, "{TEST}: {payload}");
    let summary = payload["output"]["content"]
        .as_str()
        .and_then(|content| serde_json::from_str::<Value>(content).ok())
        .map(|content| content["summary"].clone());
    assert!(
        summary.as_ref().is_some_and(Value::is_string),
        "{TEST}: the settled attempt's answer is the structured summary: {payload}"
    );
    let single: Vec<_> = chain.iter().take(5).cloned().collect();
    assert_eq!(accepted_attempt(&single).0, 0);
    // Two amendments, attempt 0's then the accepted attempt 1's: the LAST one amended is
    // the one judged, so this is admitted.
    let mut amended_twice = chain.clone();
    amended_twice.insert(
        5,
        (
            Some(0),
            "outcome_amended".to_owned(),
            "outcome_amended".to_owned(),
            "{}".to_owned(),
        ),
    );
    assert_eq!(
        accepted_attempt(&amended_twice).0,
        1,
        "{TEST}: two amendments"
    );
    // Refused: a later attempt than the accepted one, and an amendment of another attempt.
    let mut later = chain.clone();
    later.push((
        Some(2),
        "claimed".to_owned(),
        "pending".to_owned(),
        "{}".to_owned(),
    ));
    let mut amended_other = chain.clone();
    amended_other.swap(9, 10);
    amended_other[9].0 = Some(0);
    for (what, chain) in [
        ("a later attempt", later),
        ("an amendment of attempt 0", amended_other),
    ] {
        let taken = std::panic::catch_unwind(|| accepted_attempt(&chain));
        assert!(taken.is_err(), "{TEST}: admitted {what}: {taken:?}");
    }
}

/// Every prompt a one-turn pack here runs states the answer's shape, and the shape it
/// states is the one the pack's `outputs` checks: one JSON object whose only key is a
/// string `summary`. No prompt points the model at an output schema, which no adapter is
/// sent for a flat `outputs` table.
///
/// **Would red if:** a prompt asked for "the JSON object the output schema asks for"
/// (watched: N6 A1's `nanocode-anthropic` attempt 0 answered "I don't have the output
/// schema in front of me", in prose around a fenced object, and failed validation).
#[test]
fn every_one_turn_prompt_states_the_answer_shape_its_outputs_check() {
    assert!(
        one_turn_pack("").contains(r#"outputs = {"summary": "string"},"#),
        "{TEST}: the pack's outputs moved; restate ANSWER_SHAPE"
    );
    for prompt in [
        a1_prompt(Harness::OpenaiKataLogin),
        a1_prompt(Harness::AnthropicApiKey),
        LONG_GENERATION,
        SLEEP_TOOL,
        MEASURE,
    ] {
        assert!(
            !prompt.contains("output schema"),
            "{TEST}: the prompt points at an output schema no adapter is sent: {prompt}"
        );
        let stated = prompt
            .find(ANSWER_SHAPE)
            .map(|at| &prompt[at + ANSWER_SHAPE.len() - r#"{"summary": "<"#.len()..])
            .and_then(|object| object.find(">\"}").map(|end| &object[..end + 3]))
            .unwrap_or_else(|| panic!("{TEST}: the prompt does not state ANSWER_SHAPE: {prompt}"));
        let stated: Value = serde_json::from_str(stated)
            .unwrap_or_else(|error| panic!("{TEST}: {stated} is not JSON: {error}"));
        let keys: Vec<&String> = stated
            .as_object()
            .map(|object| object.keys().collect())
            .unwrap_or_default();
        assert!(
            keys == ["summary"] && stated["summary"].is_string(),
            "{TEST}: the stated shape is not {{\"summary\": string}}: {stated}"
        );
    }
}
