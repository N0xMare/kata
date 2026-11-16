//! The REAL nanocode adapter driving the REAL `kata-toolhost` as the init of a REAL
//! rootless container, its model a mock provider on the host's loopback: no model
//! budget is spent, and no double stands between the adapter's toolhost client and the
//! toolhost's own loop, pipes and process tree.
//!
//! # What these cells prove, and against what
//!
//! nanocode has no vendor binary: its loop is linked into the worker. The one
//! vendor-side binary a nanocode turn meets is the toolhost, so these cells are the
//! nanocode kinds' real-binary qualification row (`crates/agent/tests/
//! qualification_matrix.rs`, `RealBinaryHandshake`): the handshake against the real
//! toolhost's `Hello` for both kinds, and the turn's end (the latch and the `KillAll`
//! or its stdin fallback, `kata_agent_nanocode`'s `session.rs`, "Every turn end")
//! against the real toolhost in a real capsule, where the host-free cells meet a
//! double (`crates/agent-nanocode/tests/fixtures/toolhost_double.rs`). The turn-end
//! cells run the `nanocode_openai` kind, the turn end being one code path for both,
//! and the latch runs on both kinds. A real provider's turn is not this file's: that
//! live acceptance runs through kata and spends model budget, which a maintainer
//! spends by hand.
//!
//! The session is opened the way the worker's agent-turn composition opens it: over
//! the capsule's process half with its stderr already taken, the scope carrying the
//! capsule's mappings, budgets and id. The cells read their verdicts off things that
//! do not share the adapter's code: the mock provider's OWN log of the request bodies
//! it received, the container's `cgroup.procs` read from the kernel's hierarchy, the
//! host's `/proc`, the attempt root's files on the host, and the pinned runtime's own
//! `state`. Each signal a cell sends the capsule's init (`SIGKILL`, `SIGSTOP`,
//! `SIGCONT`) goes from the host to the init's host pid.
//!
//! # It REFUSES on a host that cannot prove containment
//!
//! As its OCI siblings: no certified youki, no installed AppArmor profile or no
//! delegated scope is a FAILURE naming the refusal, never a skip.

#![cfg(target_os = "linux")]

mod common;
#[path = "../../agent-nanocode/tests/fixtures/mock_provider.rs"]
#[allow(dead_code)]
mod mock_provider;
#[path = "common/toolhost_capsule.rs"]
#[allow(dead_code)]
mod toolhost_capsule;

use std::path::PathBuf;
use std::time::{Duration, Instant};

use kata_agent::adapter::session::CancelToken;
use kata_agent::adapter::{
    AgentAdapter, AgentSession, AttemptScope, MayHaveIssued, SessionSeed, TurnOutcome,
};
use kata_agent_nanocode::adapter::TestEndpoint;
use kata_agent_nanocode::{HarnessAuth, NanocodeAdapter};
use kata_types::agent::{AdapterKind, HarnessCredential, Prompt};
use kata_types::primitives::ContentHash;
use kata_worker::interactive_capsule::InteractiveTeardown;
use mock_provider::{
    MockProvider, Reply, claude_code_reply, code_reply, exec_command_reply, message_reply, usage,
};
use nix::sys::signal::Signal;
use nix::unistd::Pid;
use serde_json::json;
use toolhost_capsule::{
    Placed, Rig, cgroup_of, cgroup_tasks, delegated, eventually, runtime_state, stand_in_toolhost,
    toolhost_bin,
};

// kata's Code Mode limits, installed here as the worker installs them, run each
// cell of a nanocode turn in an interpreter process: this binary, re-executed.
kata_code_mode_host::interpreter_entry!();

/// The model each kind's prompt names: one nanocode knows, so its defaults apply.
const OPENAI_MODEL: &str = "gpt-6-luna";
const ANTHROPIC_MODEL: &str = "claude-sonnet-4-6";

/// The bound on a turn the cell expects to end: a regression fails the cell rather
/// than hanging it. A turn end's two bounded steps take at most 5 s each.
const TURN_BOUND: Duration = Duration::from_secs(60);

/// How long the session gives nanocode to confirm a stop it asked for
/// (`TURN_CANCEL_GRACE` in `kata_agent_nanocode`'s `session.rs`): a stop nothing
/// confirms ends the turn only once it expires.
const NANOCODE_CANCEL_GRACE: Duration = Duration::from_secs(5);

/// The line the handshake cells write into the capsule's `/work/AGENTS.md`. The
/// adapter holds no host path of the capsule's `/work`, so the line reaches the
/// model's request only through the toolhost's read of that file.
const INSTRUCTIONS_LINE: &str = "kata-capsule-instructions: answer from inside the capsule";

/// The adapter of `kind`, its model client pointed at `mock` (the Messages URL for
/// the Anthropic kind), one attempt per model call.
fn adapter(kind: AdapterKind, mock: &MockProvider) -> NanocodeAdapter {
    let (adapter, url) = match kind {
        AdapterKind::NanocodeOpenai => (NanocodeAdapter::openai(), mock.url.clone()),
        AdapterKind::NanocodeAnthropic => (
            NanocodeAdapter::anthropic(),
            format!("{}/messages", mock.url),
        ),
    };
    adapter.with_endpoint(TestEndpoint {
        url,
        websocket_url: None,
    })
}

/// A one-message prompt for `kind`: its model, and an `env:`-shaped API key the
/// worker would have loaded before the container launched.
fn prompt(kind: AdapterKind, text: &str) -> Prompt {
    let model = match kind {
        AdapterKind::NanocodeAnthropic => ANTHROPIC_MODEL,
        AdapterKind::NanocodeOpenai => OPENAI_MODEL,
    };
    let auth = HarnessAuth::api_key(kind, "sk-mock-not-a-real-key".to_owned());
    Prompt {
        text: text.to_owned(),
        model_hint: Some(model.into()),
        effort_hint: None,
        output_schema: None,
        credential: Some(HarnessCredential::new(auth)),
    }
}

/// A final answer of `text`, in `kind`'s wire shape.
fn final_reply(kind: AdapterKind, text: &str) -> Reply {
    match kind {
        AdapterKind::NanocodeAnthropic => mock_provider::claude_text_reply(text),
        AdapterKind::NanocodeOpenai => message_reply("final", text, usage(1, 0, 1)),
    }
}

/// One nanocode session over a placed capsule, and the facts read from outside it.
struct Live {
    session: Box<dyn AgentSession>,
    placement: Box<dyn InteractiveTeardown>,
    container: String,
    state: PathBuf,
    attempt_root: PathBuf,
}

impl Live {
    /// Place `rig`'s capsule and open `kind`'s session over it, as the worker does.
    async fn open(rig: &Rig, kind: AdapterKind, mock: &MockProvider, tag: &str) -> Self {
        let capsule = rig.capsule();
        let scope = AttemptScope::new(
            ulid::Ulid::new(),
            SessionSeed::new(ContentHash::new([0x5e; 32])),
            capsule.inputs().to_vec(),
            capsule.budgets(),
            capsule.id(),
            kata_types::redaction::LiftedSecrets::none(),
        );
        let Placed {
            process,
            placement,
            container,
            state,
            attempt_root,
            ..
        } = rig.place(tag).await;
        let session = adapter(kind, mock)
            .open(scope, process)
            .unwrap_or_else(|refusal| panic!("the nanocode adapter refused to open: {refusal}"));
        Self {
            session,
            placement,
            container,
            state,
            attempt_root,
        }
    }

    /// The init's host pid, by the pinned runtime, once it reports the init running:
    /// the placement returns before the runtime has started it, and nothing here reads
    /// its `Hello` (the session does, at the start of `prompt`).
    async fn init_pid(&self) -> u32 {
        let state = eventually(
            Duration::from_secs(10),
            "the pinned runtime reports the capsule's init running",
            || runtime_state(&self.state, &self.container),
            |state| {
                state
                    .as_ref()
                    .is_ok_and(|state| state["status"] == "running" && state["pid"].is_u64())
            },
        )
        .await
        .expect("held only on a state the runtime printed as JSON");
        state["pid"]
            .as_u64()
            .and_then(|pid| u32::try_from(pid).ok())
            .unwrap_or_else(|| panic!("`youki state` names no pid: {state}"))
    }

    fn cgroup(&self) -> PathBuf {
        cgroup_of(&self.container)
    }

    /// One turn of `prompt`, bounded.
    async fn turn(&mut self, prompt: &Prompt) -> TurnOutcome {
        tokio::time::timeout(TURN_BOUND, self.session.prompt(prompt, &CancelToken::new()))
            .await
            .unwrap_or_else(|_| panic!("the turn did not end within {TURN_BOUND:?}"))
    }

    /// `close` the session (`Shutdown`, the wait, `SIGKILL` past it) and tear the
    /// capsule down; both must be CONFIRMED.
    async fn finish(self) {
        let report = self.session.close().await;
        assert!(
            report.teardown().is_confirmed(),
            "the session's close is not confirmed: {report:?}"
        );
        let teardown = self.placement.teardown().await;
        assert!(teardown.is_confirmed(), "{teardown:?}");
    }
}

/// The tasks of `cgroup` whose `comm` is `sleep`, read off the host's `/proc`.
fn sleeps_in(cgroup: &std::path::Path) -> Vec<u32> {
    cgroup_tasks(cgroup)
        .into_iter()
        .filter(|pid| {
            std::fs::read_to_string(format!("/proc/{pid}/comm"))
                .is_ok_and(|comm| comm.trim() == "sleep")
        })
        .collect()
}

/// The state letter of `pid` (`/proc/<pid>/stat`'s third field): `T` when stopped.
fn process_state(pid: u32) -> Option<char> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    stat.rsplit_once(')')?.1.trim_start().chars().next()
}

/// Send `signal` to the host pid `pid` from the host.
fn signal(pid: u32, signal: Signal) {
    nix::sys::signal::kill(
        Pid::from_raw(i32::try_from(pid).expect("a host pid fits i32")),
        signal,
    )
    .unwrap_or_else(|error| panic!("{signal} to the capsule's init {pid}: {error}"));
}

// ---------------------------------------------------------------------------
// The handshake: nanocode's real-binary row
// ---------------------------------------------------------------------------

/// The real toolhost's `Hello` is admitted and the turn runs; a stand-in init's is
/// refused before any frame and any model request.
///
/// 1. The capsule's init is this build's static toolhost, and the host writes
///    [`INSTRUCTIONS_LINE`] into the capsule's `/work/AGENTS.md` (for
///    `nanocode_anthropic`, also the git view's gitfile `/work/.git`) through the
///    attempt root before the turn. `kind`'s turn completes with the mock's own
///    answer, after exactly one model request, and that request, read off the mock's
///    log, carries the line (and, for `nanocode_anthropic`, `Is a git repository:
///    true`): what the real toolhost read in the capsule reached the model.
/// 2. The init is a STAND-IN (`stand_in_toolhost`): a busybox script that writes a
///    `Hello` of this protocol stating an all-zero source digest, then records every
///    byte it reads to `/work/received`. The turn is `Refused{toolhost_mismatch}`; the
///    mock's log holds no request; and the stand-in's record, read off the attempt
///    root after it exited on its stdin's end, holds no byte: the adapter wrote it no
///    frame.
async fn the_real_toolhost_is_admitted_before_the_first_model_request(kind: AdapterKind) {
    kata_agent_nanocode::install_code_mode_limits();
    let mock = MockProvider::start(vec![final_reply(kind, "admitted")]).await;
    let rig = Rig::of_kind(kind, &toolhost_bin());
    let mut live = Live::open(&rig, kind, &mock, "nanocode-hello").await;
    let work = live.attempt_root.join("work");
    std::fs::write(work.join("AGENTS.md"), format!("{INSTRUCTIONS_LINE}\n"))
        .expect("the capsule's AGENTS.md, written through the attempt root");
    let anthropic = kind == AdapterKind::NanocodeAnthropic;
    if anthropic {
        std::fs::write(work.join(".git"), "gitdir: /git\n")
            .expect("the capsule's gitfile, written through the attempt root");
    }
    let outcome = live.turn(&prompt(kind, "answer admitted")).await;
    let TurnOutcome::Completed { response, .. } = &outcome else {
        panic!("the real toolhost's turn completes: {outcome:?}");
    };
    assert_eq!(response, "admitted", "the mock's own answer");
    let requests = mock.requests();
    assert_eq!(requests.len(), 1, "one model request");
    let request = requests[0].to_string();
    assert!(
        request.contains(INSTRUCTIONS_LINE),
        "the capsule's /work/AGENTS.md, read by the real toolhost, reaches the model: {request}"
    );
    if anthropic {
        assert!(
            request.contains("Is a git repository: true"),
            "the capsule's /work/.git, read by the real toolhost, is stated to the model: \
             {request}"
        );
    }
    live.finish().await;

    let scratch = tempfile::tempdir().expect("a scratch directory");
    let mock = MockProvider::start(vec![final_reply(kind, "must never be asked for")]).await;
    let rig = Rig::of_kind(kind, &stand_in_toolhost(scratch.path()));
    let mut live = Live::open(&rig, kind, &mock, "nanocode-stand-in").await;
    let outcome = live.turn(&prompt(kind, "answer")).await;
    let TurnOutcome::Refused { reason } = &outcome else {
        panic!("the stand-in's turn is refused: {outcome:?}");
    };
    assert!(reason.starts_with("toolhost_mismatch"), "{reason}");
    assert!(
        mock.requests().is_empty(),
        "no model request before an admitted Hello: {:?}",
        mock.requests()
    );
    let received = live.attempt_root.join("work/received");
    let report = live.session.close().await;
    assert!(
        report.teardown().is_confirmed(),
        "the stand-in exits on its stdin's end: {report:?}"
    );
    assert_eq!(
        std::fs::read(&received).expect("the stand-in's record"),
        b"",
        "the adapter wrote the mismatched init a frame"
    );
    let teardown = live.placement.teardown().await;
    assert!(teardown.is_confirmed(), "{teardown:?}");
}

/// **A `nanocode_openai` turn admits the real toolhost's `Hello`, and the capsule's
/// `/work/AGENTS.md` it reads reaches the model; a stand-in's `Hello` is refused before
/// any frame or model request.** The nanocode OpenAI kind's real-binary row (the
/// module doc).
///
/// **Would red if:** the toolhost's build stated another digest than the worker's
/// (the real turn is refused), the handshake admitted a `Hello` without checking it
/// (watched: the stand-in reads the adapter's first `ReadFile`, which it never
/// answers, and the turn does not end within its bound), or the project instructions
/// the model is given were not the capsule's file (watched: with the seam's
/// `project_instructions` answering `None` unread, the request lacks the line).
#[test]
#[ignore = "HOST-DEPENDENT (pinned youki, its INSTALLED AppArmor profile, a delegated user \
            scope, the fixture closure realised) AND instrument-dependent (`cargo build -p \
            kata-provider-youki --bin kata-provider-youki` and `cargo build -p kata-toolhost \
            --target x86_64-unknown-linux-musl`). Rides `oci-live-smoke`."]
fn a_nanocode_openai_turn_admits_the_real_toolhost_before_its_first_model_request() {
    delegated(
        "a_nanocode_openai_turn_admits_the_real_toolhost_before_its_first_model_request",
        the_real_toolhost_is_admitted_before_the_first_model_request(AdapterKind::NanocodeOpenai),
    );
}

/// **A `nanocode_anthropic` turn admits the real toolhost's `Hello`, and what it reads
/// of the capsule's `/work/AGENTS.md` and `/work/.git` reaches the model; a stand-in's
/// `Hello` is refused before any frame or model request.** The nanocode Anthropic
/// kind's real-binary row. Only this kind reads `/work/.git` (whether `/work` is a git
/// repository, which its environment states).
///
/// **Would red if:** as its OpenAI twin, or the git fact were not the capsule's
/// (watched: with the seam's `workspace_is_a_git_repository` answering `false` unread,
/// the request lacks `Is a git repository: true`).
#[test]
#[ignore = "HOST-DEPENDENT (pinned youki, its INSTALLED AppArmor profile, a delegated user \
            scope, the fixture closure realised) AND instrument-dependent (`cargo build -p \
            kata-provider-youki --bin kata-provider-youki` and `cargo build -p kata-toolhost \
            --target x86_64-unknown-linux-musl`). Rides `oci-live-smoke`."]
fn a_nanocode_anthropic_turn_admits_the_real_toolhost_before_its_first_model_request() {
    delegated(
        "a_nanocode_anthropic_turn_admits_the_real_toolhost_before_its_first_model_request",
        the_real_toolhost_is_admitted_before_the_first_model_request(
            AdapterKind::NanocodeAnthropic,
        ),
    );
}

// ---------------------------------------------------------------------------
// The turn's end, against the real toolhost
// ---------------------------------------------------------------------------

/// **A completed turn's end leaves only the toolhost in the capsule's cgroup.** A
/// `nanocode_openai` turn: the turn end (`end_turn`) is one code path for both kinds.
/// The model's one tool call starts a job and returns while it runs: a `sleep 600` the
/// session `exec`s, and a second one in a NEW session (`setsid`), outside the
/// session's process group, so no per-session kill reaches it. Both are seen in the
/// container's `cgroup.procs` during the turn. Read the instant `prompt` returned
/// (before `close`), `cgroup.procs` lists exactly the init and neither sleep's pid is
/// alive on the host; after `close` it lists nothing.
///
/// **Would red if:** the turn's end sent no `KillAll` (watched: both sleeps are still
/// listed after `prompt` returned), or the toolhost's `KillAll` reached only the
/// session's group (the `setsid` sleep survives; `toolhost_live`'s
/// `close_leaves_no_task_in_the_cgroup` pins that with frames of its own).
#[test]
#[ignore = "HOST-DEPENDENT (pinned youki, its INSTALLED AppArmor profile, a delegated user \
            scope, the fixture closure realised) AND instrument-dependent (`cargo build -p \
            kata-provider-youki --bin kata-provider-youki` and `cargo build -p kata-toolhost \
            --target x86_64-unknown-linux-musl`). Rides `oci-live-smoke`."]
fn a_completed_turn_leaves_only_the_real_toolhost_in_its_cgroup() {
    delegated(
        "a_completed_turn_leaves_only_the_real_toolhost_in_its_cgroup",
        async {
            kata_agent_nanocode::install_code_mode_limits();
            let kind = AdapterKind::NanocodeOpenai;
            let mock = MockProvider::start(vec![
                exec_command_reply(
                    "r1",
                    &json!({
                        "cmd": "setsid sleep 600 </dev/null >/dev/null 2>&1 & exec sleep 600",
                        "yield_time_ms": 1_000,
                    }),
                    usage(1, 0, 1),
                ),
                final_reply(kind, "done"),
            ])
            .await;
            let rig = Rig::of_kind(kind, &toolhost_bin());
            let mut live = Live::open(&rig, kind, &mock, "nanocode-turn-end").await;
            let init = live.init_pid().await;
            let cgroup = live.cgroup();
            let prompt = prompt(kind, "start the job, then answer done");
            let watch = eventually(
                Duration::from_secs(30),
                "the job's two sleeps run in the capsule",
                || sleeps_in(&cgroup),
                |sleeps| sleeps.len() == 2,
            );
            let (outcome, sleeps) = tokio::join!(live.turn(&prompt), watch);
            assert!(
                matches!(outcome, TurnOutcome::Completed { .. }),
                "{outcome:?}"
            );
            assert_eq!(
                cgroup_tasks(&cgroup),
                [init],
                "the instant the turn ended, the capsule holds only its init"
            );
            for sleep in sleeps {
                assert!(
                    !std::path::Path::new(&format!("/proc/{sleep}")).exists(),
                    "the job's sleep {sleep} outlived the turn"
                );
            }
            assert_eq!(mock.requests().len(), 2, "the tool call, then the answer");
            live.finish().await;
            assert!(cgroup_tasks(&cgroup).is_empty(), "{cgroup:?}");
        },
    );
}

/// **A toolhost killed mid-turn latches the turn: the latch's stop ends it, it is
/// ambiguous naming `toolhost_lost`, the model is asked nothing more, and the capsule
/// is empty.** The model's one tool call runs `sleep 600` in the capsule: on
/// `nanocode_openai` an `exec_command` with a 30 s yield, on `nanocode_anthropic` a
/// Code Mode cell (30 s yield) awaiting a foreground `Bash`. Once that sleep is in the
/// container's `cgroup.procs`, the host `SIGKILL`s the init. The toolhost's stdout
/// ends, and `prompt` returns inside nanocode's cancel grace
/// ([`NANOCODE_CANCEL_GRACE`]) of the signal, `Ambiguous` at `ModelTokens` (the first
/// crossing: the model request that asked for the tool) with evidence naming
/// `toolhost_lost`; the mock's log still holds the ONE request 500 ms later, and the
/// cgroup lists nothing within 10 s, before `close`.
///
/// Two mechanisms keep the model from being asked again, and either alone does: the
/// latch's stop (the gate closes and nanocode is cancelled), and the seam, which parks
/// a call that ends on a broken wire until the turn has ended (`Seam::settled`). So
/// the request count does not see the latch's stop; the turn's duration does. Without
/// the stop nanocode confirms no cancel, and the drive loop ends the turn only once
/// the grace has expired, which it arms at the latch, after the signal. On
/// `nanocode_anthropic` the `ModelTokens` crossing is the Messages client's
/// per-request mark (`MessagesMark` in `session.rs`): nothing else marks a Messages
/// request, so without it the first crossing would be the tool's `ToolCall`.
///
/// **Would red if:** the latch did not stop the turn (watched on `nanocode_openai`:
/// with the latch arm's `stop_turn` removed, the turn ends past the grace), a tool
/// call ending on the broken wire answered the model while the turn ran on (watched on
/// `nanocode_openai`: with the latch's stop and the seam's park both removed, a second
/// request reaches the mock), the outcome map did not read the latch first (watched
/// on `nanocode_openai`: the turn is ambiguous as an unasked cancel, naming no
/// `toolhost_lost`), or a Messages request went unmarked (watched on
/// `nanocode_anthropic`: with `MessagesMark` passing every request on unmarked, the
/// turn is ambiguous at `ToolCall`).
async fn a_toolhost_killed_mid_turn_latches(kind: AdapterKind) {
    kata_agent_nanocode::install_code_mode_limits();
    let tool_call = match kind {
        AdapterKind::NanocodeAnthropic => claude_code_reply(
            "r1",
            "// @exec: {\"yield_time_ms\": 30000}\n\
             await tools.Bash({command: \"exec sleep 600\"});\n\
             text(\"the sleep ended\");",
        ),
        AdapterKind::NanocodeOpenai => exec_command_reply(
            "r1",
            &json!({"cmd": "exec sleep 600", "yield_time_ms": 30_000}),
            usage(1, 0, 1),
        ),
    };
    let mock = MockProvider::start(vec![
        tool_call,
        final_reply(kind, "must never be asked for"),
    ])
    .await;
    let rig = Rig::of_kind(kind, &toolhost_bin());
    let mut live = Live::open(&rig, kind, &mock, "nanocode-latch").await;
    let init = live.init_pid().await;
    let cgroup = live.cgroup();
    let prompt = prompt(kind, "run the command");
    let kill = async {
        eventually(
            Duration::from_secs(30),
            "the tool call's sleep runs in the capsule",
            || sleeps_in(&cgroup),
            |sleeps| !sleeps.is_empty(),
        )
        .await;
        // Read BEFORE the signal: a turn the grace ended reads at least the grace.
        let killed = Instant::now();
        signal(init, Signal::SIGKILL);
        killed
    };
    let turn = async {
        let outcome = live.turn(&prompt).await;
        (outcome, Instant::now())
    };
    let ((outcome, ended), killed) = tokio::join!(turn, kill);
    let TurnOutcome::Ambiguous { issued, evidence } = &outcome else {
        panic!("{kind:?}: a latched turn is ambiguous: {outcome:?}");
    };
    assert_eq!(
        *issued,
        MayHaveIssued::ModelTokens,
        "{kind:?}: the first crossing is the model request"
    );
    assert!(evidence.contains("toolhost_lost"), "{kind:?}: {evidence}");
    let stopped_in = ended.saturating_duration_since(killed);
    assert!(
        stopped_in < NANOCODE_CANCEL_GRACE,
        "{kind:?}: the latched turn ended {stopped_in:?} after the host's SIGKILL, not \
         inside nanocode's {NANOCODE_CANCEL_GRACE:?} cancel grace: no stop the latch asked \
         for was confirmed"
    );
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert_eq!(
        mock.requests().len(),
        1,
        "{kind:?}: the model was asked again after the toolhost was lost"
    );
    eventually(
        Duration::from_secs(10),
        "the capsule is empty before close",
        || cgroup_tasks(&cgroup),
        Vec::is_empty,
    )
    .await;
    let report = live.session.close().await;
    assert!(
        !report.harness_acknowledged_cancel(),
        "{kind:?}: a latch's stop is never an acknowledged cancel: {report:?}"
    );
    let teardown = live.placement.teardown().await;
    assert!(teardown.is_confirmed(), "{kind:?}: {teardown:?}");
}

/// **The latch, on `nanocode_openai`** ([`a_toolhost_killed_mid_turn_latches`]).
#[test]
#[ignore = "HOST-DEPENDENT (pinned youki, its INSTALLED AppArmor profile, a delegated user \
            scope, the fixture closure realised) AND instrument-dependent (`cargo build -p \
            kata-provider-youki --bin kata-provider-youki` and `cargo build -p kata-toolhost \
            --target x86_64-unknown-linux-musl`). Rides `oci-live-smoke`."]
fn a_toolhost_killed_mid_turn_latches_and_the_model_is_asked_nothing_more() {
    delegated(
        "a_toolhost_killed_mid_turn_latches_and_the_model_is_asked_nothing_more",
        a_toolhost_killed_mid_turn_latches(AdapterKind::NanocodeOpenai),
    );
}

/// **The latch, on `nanocode_anthropic`** ([`a_toolhost_killed_mid_turn_latches`]):
/// its first crossing is the Messages request's own mark.
#[test]
#[ignore = "HOST-DEPENDENT (pinned youki, its INSTALLED AppArmor profile, a delegated user \
            scope, the fixture closure realised) AND instrument-dependent (`cargo build -p \
            kata-provider-youki --bin kata-provider-youki` and `cargo build -p kata-toolhost \
            --target x86_64-unknown-linux-musl`). Rides `oci-live-smoke`."]
fn a_toolhost_killed_mid_anthropic_turn_latches_and_the_model_is_asked_nothing_more() {
    delegated(
        "a_toolhost_killed_mid_anthropic_turn_latches_and_the_model_is_asked_nothing_more",
        a_toolhost_killed_mid_turn_latches(AdapterKind::NanocodeAnthropic),
    );
}

/// **A stopped toolhost leaves the turn end's `KillAll` unconfirmed: the turn records
/// it, drops the toolhost's stdin, and once the toolhost runs again it ends the
/// capsule on its own.** A `nanocode_openai` turn, as the completed turn's cell above.
/// The model's first tool call leaves `sleep 600` running past
/// its yield; once the mock holds the second request (that call's result, so its
/// `Started` was read), the host `SIGSTOP`s the init, and the turn's second cell waits
/// 3 s on a timer, touching no tool. The turn completes on the third request. Its end
/// sends `KillAll`, which the stopped toolhost cannot answer within the 5 s grace:
/// `prompt` returns `Completed` with `TurnEnd{kill_all: unconfirmed}` in the session's
/// evidence, the init is still stopped and the sleep still listed (nothing killed it).
/// The host then `SIGCONT`s the init: it reads the `KillAll` and then its stdin's end
/// and exits, so the cgroup lists nothing within 10 s, before `close`, with no signal
/// from the worker.
///
/// **Would red if:** the turn's end kept the toolhost's stdin open after the
/// unconfirmed `KillAll` (watched: once continued the toolhost kills the sleep and
/// stays, the init still listed), or it waited on the stopped toolhost (the turn does
/// not end within its bound), or recorded nothing.
#[test]
#[ignore = "HOST-DEPENDENT (pinned youki, its INSTALLED AppArmor profile, a delegated user \
            scope, the fixture closure realised) AND instrument-dependent (`cargo build -p \
            kata-provider-youki --bin kata-provider-youki` and `cargo build -p kata-toolhost \
            --target x86_64-unknown-linux-musl`). Rides `oci-live-smoke`."]
fn a_stopped_toolhost_leaves_kill_all_unconfirmed_and_its_dropped_stdin_ends_the_capsule() {
    delegated(
        "a_stopped_toolhost_leaves_kill_all_unconfirmed_and_its_dropped_stdin_ends_the_capsule",
        async {
            kata_agent_nanocode::install_code_mode_limits();
            let kind = AdapterKind::NanocodeOpenai;
            let mock = MockProvider::start(vec![
                exec_command_reply(
                    "r1",
                    &json!({"cmd": "exec sleep 600", "yield_time_ms": 250}),
                    usage(1, 0, 1),
                ),
                code_reply(
                    "r2",
                    "await new Promise((resolve) => setTimeout(resolve, 3000));\ntext(\"held\");",
                    usage(1, 0, 1),
                ),
                final_reply(kind, "done"),
            ])
            .await;
            let rig = Rig::of_kind(kind, &toolhost_bin());
            let mut live = Live::open(&rig, kind, &mock, "nanocode-stopped").await;
            let init = live.init_pid().await;
            let cgroup = live.cgroup();
            let prompt = prompt(kind, "start the job, wait, then answer done");
            let stop = async {
                mock.wait_for_requests(2).await;
                signal(init, Signal::SIGSTOP);
                eventually(
                    Duration::from_secs(5),
                    "the init is stopped",
                    || process_state(init),
                    |state| *state == Some('T'),
                )
                .await;
            };
            let (outcome, ()) = tokio::join!(live.turn(&prompt), stop);
            assert!(
                matches!(outcome, TurnOutcome::Completed { .. }),
                "{outcome:?}"
            );
            let turn_end: Vec<String> = live
                .session
                .take_evidence()
                .events
                .iter()
                .filter_map(|event| match event {
                    kata_types::agent::SessionEvidenceEvent::TurnEnd { step, outcome } => {
                        Some(format!("{step}:{outcome}"))
                    }
                    _ => None,
                })
                .collect();
            assert_eq!(turn_end, ["kill_all:unconfirmed"]);
            assert_eq!(process_state(init), Some('T'), "the init is still stopped");
            let sleeps = sleeps_in(&cgroup);
            assert_eq!(sleeps.len(), 1, "nothing killed the job: {sleeps:?}");
            signal(init, Signal::SIGCONT);
            eventually(
                Duration::from_secs(10),
                "the continued toolhost ends the capsule before close",
                || cgroup_tasks(&cgroup),
                Vec::is_empty,
            )
            .await;
            assert_eq!(
                mock.requests().len(),
                3,
                "the job, the timer cell, the answer"
            );
            live.finish().await;
        },
    );
}
