//! The nanocode adapter's cells that need Code Mode on the engine's own
//! IN-PROCESS host: this binary installs no Code Mode limits, so the vendored
//! engine's embedded host runs each cell inline on the task that reads its
//! events (MEASURED at 8ec3b215, `EmbeddedHost::read_event`; at 2ac77424 it ran
//! each on a QuickJS thread of its own), a task kata's platform host spawns on
//! the tokio runtime driving the turn — the configuration no kata worker runs
//! (every worker installs kata's limits, whose backend runs each cell in an
//! interpreter process: `nanocode_qualification`, which runs under them). The
//! cells run a multi-thread runtime, so a cell holding one worker leaves the
//! turn's own tasks the others, and each ends by shutting its runtime down
//! in the background ([`on_a_multi_thread_runtime`]): a worker still inside
//! the step would otherwise hold the runtime's drop, and the cell, until the
//! step ends.
//!
//! What only the in-process host can still produce is a cancel nanocode does
//! NOT confirm: a cell inside one long native step
//! ([`quickjs_threads::A_LONG_NATIVE_STEP`]) holds its worker thread past the
//! interrupt, and nanocode's turn waits on it (MEASURED at 2ac77424, lane
//! ur-u4u5, and again at 8ec3b215). Behind kata's backend the cancel's
//! terminate kills the step's interpreter process, so nanocode confirms the
//! same cancel
//! (`nanocode_qualification::a_cancel_during_a_native_step_is_confirmed_behind_kata_backend`).
//! The adapter's classification of an unconfirmed stop (`unconfirmed_stop`:
//! ambiguous at the crossed class, never `Cancelled`) is the same code on both
//! backends, so these cells pin it here: they are the nanocode kinds'
//! `CancellationUnacknowledged` rows (`crates/agent/tests/qualification_matrix.rs`).
//!
//! The witnesses do not share the adapter's code: the mock's own log, the
//! toolhost double's own log, and the kernel's account of this process's tokio
//! worker threads ([`quickjs_threads::runtime_worker_threads`]).

#[path = "fixtures/mock_provider.rs"]
#[allow(dead_code)]
mod mock_provider;
#[path = "fixtures/openai_turn.rs"]
#[allow(dead_code)]
mod openai_turn;
#[path = "fixtures/quickjs_threads.rs"]
#[allow(dead_code)]
mod quickjs_threads;
#[path = "fixtures/toolhost_double.rs"]
#[allow(dead_code)]
mod toolhost_double;

use std::time::Duration;

use kata_agent::adapter::session::CancelToken;
use kata_agent::adapter::{MayHaveIssued, TurnOutcome};
use kata_agent_nanocode::adapter::TestEndpoint;
use kata_agent_nanocode::{HarnessAuth, NanocodeAdapter};
use kata_types::agent::{HarnessCredential, Prompt};
use mock_provider::{MockProvider, claude_code_reply, claude_text_reply, code_reply, usage};
use openai_turn::{cancellable_turn, open, openai, openai_prompt};
use toolhost_double::DoubleConfig;

/// A Messages model nanocode knows, so its output-token default applies.
const CLAUDE_MODEL: &str = "claude-sonnet-4-6";

/// The Anthropic adapter, pointed at `mock`'s Messages endpoint.
fn anthropic(mock: &MockProvider) -> NanocodeAdapter {
    NanocodeAdapter::anthropic().with_endpoint(TestEndpoint {
        url: format!("{}/messages", mock.url),
        websocket_url: None,
    })
}

/// A prompt for the Anthropic kind.
fn anthropic_prompt(text: &str) -> Prompt {
    let mut prompt = openai_prompt(text);
    prompt.model_hint = Some(CLAUDE_MODEL.into());
    prompt.credential = Some(HarnessCredential::new(HarnessAuth::AnthropicApiKey(
        "sk-ant-mock-not-a-real-key".to_owned(),
    )));
    prompt
}

/// The CPU time, in clock ticks, of each tokio worker thread of this process,
/// read off `/proc`.
fn worker_cpu_ticks() -> std::collections::BTreeMap<u32, u64> {
    quickjs_threads::runtime_worker_threads()
        .into_iter()
        .filter_map(|tid| Some((tid, quickjs_threads::cpu_ticks(tid)?)))
        .collect()
}

/// Runs `cell` on a multi-thread tokio runtime of four workers and shuts the
/// runtime down without waiting for them, as a thread nobody joins was left
/// at 2ac77424: a worker held inside a native step past the cell's end keeps
/// the process, not the cell, running.
fn on_a_multi_thread_runtime(cell: impl std::future::Future<Output = ()>) {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()
        .expect("a multi-thread tokio runtime");
    runtime.block_on(cell);
    runtime.shutdown_background();
}

/// One tokio worker thread of this process is held busy over the next second:
/// it burns at least half of it on CPU, as a cell inside a native step does,
/// which an idle runtime's housekeeping does not.
async fn assert_a_code_mode_cell_runs(path: &str) {
    let before = worker_cpu_ticks();
    tokio::time::sleep(Duration::from_millis(1_000)).await;
    let burned = worker_cpu_ticks()
        .into_iter()
        .map(|(tid, after)| after.saturating_sub(before.get(&tid).copied().unwrap_or(after)))
        .max()
        .unwrap_or(0);
    assert!(
        burned >= 50,
        "{path}: no tokio worker thread burned half a second of CPU while the cell sorts \
         ({burned} ticks at most): the witness sees no cell"
    );
}

/// **A cancel nanocode does not confirm is not reported as a cancel.** The
/// Anthropic model starts a Code Mode cell inside one long native step
/// ([`quickjs_threads::A_LONG_NATIVE_STEP`]), which no interrupt reaches.
/// Once the kernel's account shows a worker thread held burning CPU, the
/// operator cancels; that thread burns CPU through the second after the
/// cancel too, so nanocode did not stop the cell it was asked to stop
/// (MEASURED at 2ac77424 and at 8ec3b215: its turn waits on the cell and
/// confirms nothing).
/// When the 5 s grace expires the turn is ambiguous at `ModelTokens`, naming
/// the unconfirmed stop, `close` reports no acknowledged cancel, and no second
/// model request was made.
///
/// **Would red if:** an unconfirmed stop were reported as a cancel (watched:
/// `Cancelled`).
#[test]
fn an_anthropic_cancel_nanocode_does_not_confirm_is_ambiguous() {
    on_a_multi_thread_runtime(an_anthropic_cancel_nanocode_does_not_confirm());
}

async fn an_anthropic_cancel_nanocode_does_not_confirm() {
    let mock = MockProvider::start(vec![
        claude_code_reply("r1", quickjs_threads::A_LONG_NATIVE_STEP),
        claude_text_reply("must never be asked for"),
    ])
    .await;
    let (mut session, _witness) = open(&anthropic(&mock), DoubleConfig::default());
    let cancel = CancelToken::new();
    let prompt = anthropic_prompt("sort");
    let fire = async {
        mock.wait_for_requests(1).await;
        assert_a_code_mode_cell_runs("before the cancel").await;
        cancel.cancel();
        assert_a_code_mode_cell_runs("after the cancel").await;
    };
    let (outcome, ()) = tokio::join!(cancellable_turn(session.as_mut(), &prompt, &cancel), fire);
    let TurnOutcome::Ambiguous { issued, evidence } = &outcome else {
        panic!("an unconfirmed stop is ambiguous: {outcome:?}");
    };
    assert_eq!(*issued, MayHaveIssued::ModelTokens);
    assert!(
        evidence.contains("nanocode did not confirm within 5 s"),
        "{evidence}"
    );
    assert_eq!(
        mock.requests().len(),
        1,
        "no model request after the cancel"
    );
    let close = tokio::time::timeout(Duration::from_secs(30), session.close())
        .await
        .expect("close is bounded");
    assert!(
        !close.harness_acknowledged_cancel(),
        "nanocode confirmed nothing: {close:?}"
    );
}

/// **A cancel nanocode does not confirm within its grace is ambiguous at the
/// crossed class, never `Cancelled`.** The model's one request starts a Code
/// Mode cell that, inside its 60 s yield, runs one long native sort
/// ([`quickjs_threads::A_LONG_NATIVE_STEP`]), so the cell is the turn's tool
/// call in flight. The operator's cancel fires once the kernel's account sees
/// the cell's QuickJS thread burn CPU (the cancel lands inside the step).
/// MEASURED at 2ac77424 (lane ur-u4u5, this cell's shape and one whose cell
/// yielded before the sort with the next model request stalled), and at
/// 8ec3b215 in this cell's shape: nanocode
/// confirms no cancel while a cell is inside such a step, and `prompt` returns
/// about 10.1 s after the cancel (the 100 ms poll, the 5 s grace, then the turn
/// end's shutdown waiting out its own 5 s on the cell). The one model request
/// (the mock's own log) crossed the watermark at `ModelTokens`, and no tool
/// frame reached the capsule (the double's own log), so the stop is
/// `Ambiguous{ModelTokens}`; `close` reports no acknowledgement, and the sort
/// still burns CPU after the outcome, so the step held through the grace.
///
/// **Would red if:** the grace's expiry on a stop the token asked for were read
/// as the vendor confirming it (watched: `unconfirmed_stop` mapping a token
/// stop to `Cancelled`).
#[test]
fn an_unconfirmed_cancel_is_ambiguous_at_the_crossed_class() {
    on_a_multi_thread_runtime(an_unconfirmed_cancel());
}

async fn an_unconfirmed_cancel() {
    let mock = MockProvider::start(vec![code_reply(
        "r1",
        &format!(
            "// @exec: {{\"yield_time_ms\": 60000}}\n{}",
            quickjs_threads::A_LONG_NATIVE_STEP
        ),
        usage(1, 0, 1),
    )])
    .await;
    let (mut session, witness) = open(&openai(&mock.url, None), DoubleConfig::default());
    let cancel = CancelToken::new();
    let prompt = openai_prompt("sort");
    let fire = async {
        mock.wait_for_requests(1).await;
        assert_a_code_mode_cell_runs("before the cancel").await;
        cancel.cancel();
    };
    let (outcome, ()) = tokio::join!(cancellable_turn(session.as_mut(), &prompt, &cancel), fire);
    assert!(
        matches!(
            &outcome,
            TurnOutcome::Ambiguous {
                issued: MayHaveIssued::ModelTokens,
                evidence,
            } if evidence.contains("did not confirm")
        ),
        "an unconfirmed stop is ambiguous at the class the one model request crossed: \
         {outcome:?}"
    );
    assert_eq!(mock.requests().len(), 1, "one model request left");
    assert!(
        !witness.kinds().contains(&"exec"),
        "no tool frame reached the capsule, so nothing crossed `ToolCall`: {:?}",
        witness.kinds()
    );
    assert_a_code_mode_cell_runs("after the outcome").await;
    let close = session.close().await;
    assert!(
        !close.harness_acknowledged_cancel(),
        "nanocode never confirmed the cancel: {close:?}"
    );
}
