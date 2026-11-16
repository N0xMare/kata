//! The Code Mode wall limit, seen through the nanocode adapter. kata's own
//! 300 s wall is too long for a cell, so this binary installs kata's limits
//! with a 2 s wall, through kata's installer (`kata_code_mode_host::install`,
//! which runs every cell in an interpreter process, this binary re-executed:
//! its entry below), before any agent is built; it is its own binary because
//! that installer is once-only (`install_limits` guards it, so each cell may
//! ask).
//!
//! The witnesses do not share the adapter's code: the mock's log of the
//! request bodies it received (what the model was told), the wall clock, and
//! the kernel's account of this process's interpreter processes.
//!
//! Just before a failed cell's error the vendored guard sends its report of
//! the limit as a Code Mode notification of its own, which the adapter
//! records; the Responses kind hands the model the report as an output of its
//! own for the call, outside nanocode's visible budget for the cell's result,
//! and the Messages kind appends it to the result, where that budget drops it
//! once the text before it fills the budget
//! (`code_mode_output_through_adapter.rs` states both kinds' budgets).

#[path = "fixtures/anthropic_turn.rs"]
mod anthropic_turn;
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

use std::time::{Duration, Instant};

use anthropic_turn::{anthropic, anthropic_prompt};
use kata_agent::adapter::{AgentSession, TurnOutcome};
use kata_agent_nanocode::CODE_MODE_LIMITS;
use kata_code_mode_host::CodeModeLimits;
use kata_code_mode_host::{Program, install};
use kata_types::agent::SessionEvidenceEvent;
use mock_provider::{
    Gate, MockProvider, Reply, call_output, call_outputs, claude_code_reply, claude_text_reply,
    code_reply, message_reply, tool_result_texts, usage, wait_reply,
};
use openai_turn::{bounded, open_scoped, openai, openai_prompt, scope, turn};
use quickjs_threads::{interpreters, once_listed};
use toolhost_double::DoubleConfig;

kata_code_mode_host::interpreter_entry!();

const WALL: Duration = Duration::from_secs(2);

/// The vendored guard's report of a hit of the 2 s wall.
const WALL_REPORT: &str = "Code Mode cell exceeded its 2000 ms wall-time limit";

/// A cell that emits one 70,000-byte text, past both kinds' visible budgets
/// alone (10,000 tokens on the Responses kind, 12,000 on the Messages kind)
/// and past the engine's 64 KiB of pending text (`PENDING_TEXT_BYTES`), so it
/// is sent before the spin, then spins in JavaScript, asking to yield only
/// after 30 s, so the 2 s wall ends it.
const LONG_TEXT_THEN_SPIN: &str = "// @exec: {\"yield_time_ms\": 30000}\n\
     text(\"x\".repeat(70000));\n\
     for (;;) {}";

/// Install kata's limits with the 2 s wall, once for this process.
fn install_limits() {
    static INSTALL: std::sync::Once = std::sync::Once::new();
    INSTALL.call_once(|| {
        install(
            CodeModeLimits {
                cell_wall: WALL,
                ..CODE_MODE_LIMITS
            },
            Program::this_executable(),
        )
        .expect("the only limits this process installs");
    });
}

/// **A model-written cell that spins in JavaScript hits the wall limit, the
/// model is told, kata records it, and the turn goes on.** The cell asks to
/// yield only after 30 s, so nothing but the 2 s wall ends it before then; the
/// next request hands the model the cell's failure, MEASURED: its header, then
/// `Script error:\nCode Mode cell exceeded its 2000 ms wall-time limit`, and
/// the guard's report as an output of its own. The model's second cell then
/// runs, and the turn completes.
///
/// The session's evidence records `CodeModeLimit{wall}`, and no
/// `CodeModeInterpreterEnded`, and its progress sink sees one
/// `code_mode_limit` observation naming the wall.
///
/// The interpreter ends a spinning cell itself, between two of its steps: the
/// error is the wall's alone, not the supervisor's kill `WALL_GRACE` later
/// (whose error goes on `; kata killed its interpreter process 5 s past it`).
/// Each cell runs in an interpreter of its own, reaped when its host drops:
/// the kernel lists one interpreter process while the first cell spins and one
/// other while the second cell waits on a timer, the first one gone (the
/// listing names unreaped interpreters too). The first sample is taken once
/// the kernel lists the first cell's interpreter, and the model's second cell
/// is held until it is: an interpreter process starts on its own schedule, so
/// a sample taken on a sleep instead can land before it is listed (a host
/// under load).
///
/// **Would red if:** the interpreter did not end a spinning cell at its wall
/// (the supervisor's kill ends it, its error naming the kill), the guard sent
/// no report of the hit (no output of its own, nothing recorded), or a cell's
/// interpreter outlived its host (two listed while the second cell waits).
#[tokio::test]
async fn a_spinning_cell_hits_the_wall_limit_and_the_turn_goes_on() {
    install_limits();
    let first_listed = Gate::default();
    let mock = MockProvider::start(vec![
        code_reply(
            "r1",
            "// @exec: {\"yield_time_ms\": 30000}\nfor (;;) {}",
            usage(1, 0, 1),
        ),
        Reply::Gated(
            first_listed.clone(),
            Box::new(code_reply(
                "r2",
                "await new Promise((resolve) => setTimeout(resolve, 1000));\n\
                 text(\"the next cell ran\");",
                usage(1, 0, 1),
            )),
        ),
        message_reply("r3", "DONE", usage(1, 0, 1)),
    ])
    .await;
    let observed = std::sync::Arc::new(Observations::default());
    let (mut session, _witness) = open_scoped(
        &openai(&mock.url, None),
        DoubleConfig::default(),
        scope().with_progress(observed.clone()),
    );

    let prompt = openai_prompt("spin");

    let started = Instant::now();
    let (outcome, (spinning, next_waiting)) =
        tokio::join!(turn(session.as_mut(), &prompt), async {
            let spinning =
                bounded("the first cell's interpreter", once_listed(1, interpreters)).await;
            first_listed.open();
            mock.wait_for_requests(2).await;
            tokio::time::sleep(Duration::from_millis(300)).await;
            (spinning, interpreters())
        });
    let elapsed = started.elapsed();

    let requests = mock.requests();
    assert_eq!(
        requests.len(),
        3,
        "one model call per response: {outcome:?}"
    );
    let outputs = call_outputs(&requests[1], "call_r1");
    let [result, report] = outputs.as_slice() else {
        panic!("the model was told the first cell's result and the report: {outputs:?}");
    };
    let texts: Vec<&str> = result
        .as_array()
        .expect("a content-item result")
        .iter()
        .filter_map(|item| item["text"].as_str())
        .collect();
    let error = format!("Script error:\n{WALL_REPORT}");
    assert!(
        texts.len() == 2 && texts[0].starts_with("Script failed") && texts[1] == error,
        "the spinning cell's result is its header and the wall's error: {texts:?}"
    );
    assert_eq!(*report, serde_json::json!(WALL_REPORT));
    assert_eq!(
        spinning.len(),
        1,
        "one interpreter while the first cell spins: {spinning:?}"
    );
    assert_eq!(
        next_waiting.len(),
        1,
        "one interpreter while the second cell waits: {next_waiting:?}"
    );
    assert!(
        spinning.is_disjoint(&next_waiting),
        "the first cell's interpreter outlived its host: {spinning:?} {next_waiting:?}"
    );
    let next = call_output(&requests[2], "call_r2").expect("the model was told the second cell");
    assert!(
        next.contains("the next cell ran") && !next.contains("Script failed"),
        "the cell after the wall hit ran: {next}"
    );
    assert!(
        matches!(outcome, TurnOutcome::Completed { .. }),
        "a limit hit is a cell outcome, not a turn outcome: {outcome:?}"
    );
    assert!(
        elapsed >= WALL && elapsed < Duration::from_secs(20),
        "the turn took {elapsed:?}: the spin ended by the wall, not the 30 s yield"
    );
    let evidence = session.take_evidence();
    assert!(
        evidence
            .events
            .contains(&kata_types::agent::SessionEvidenceEvent::CodeModeLimit {
                which: "wall".into(),
            }),
        "the evidence records the wall hit: {:?}",
        evidence.events
    );
    assert!(
        !evidence
            .events
            .iter()
            .any(|event| matches!(event, SessionEvidenceEvent::CodeModeInterpreterEnded { .. })),
        "no interpreter ended: {:?}",
        evidence.events
    );
    assert_eq!(
        observed.limits(),
        ["wall"],
        "one `code_mode_limit` progress observation, naming the wall"
    );
    let close = session.close().await;
    assert!(close.is_confirmed(), "{close:?}");
}

/// **A cell that yielded first and then hits the wall is recorded too.** With
/// kata's limits a cell yields to the model long before its wall (nanocode's
/// default `exec` yield is 30 s on the Responses kind and 10 s on the
/// Messages kind, kata's wall 300 s), so a wall hit usually reaches
/// the model in a `wait` result, not the cell's `exec` result. Here the cell
/// spins and yields after 200 ms; the model's `wait` then receives the
/// cell's failure naming the 2 s wall. The session's evidence records
/// `CodeModeLimit{wall}` and the progress sink sees one `code_mode_limit`
/// observation naming the wall, read off the real guard's text.
#[tokio::test]
async fn a_yielded_cell_that_hits_the_wall_is_recorded_from_its_wait() {
    install_limits();
    let mock = MockProvider::start(vec![
        code_reply(
            "r1",
            "// @exec: {\"yield_time_ms\": 200}\nfor (;;) {}",
            usage(1, 0, 1),
        ),
        wait_reply("r2", "1", false, usage(1, 0, 1)),
        message_reply("r3", "DONE", usage(1, 0, 1)),
    ])
    .await;
    let observed = std::sync::Arc::new(Observations::default());
    let (mut session, _witness) = open_scoped(
        &openai(&mock.url, None),
        DoubleConfig::default(),
        scope().with_progress(observed.clone()),
    );
    let prompt = openai_prompt("spin, then wait");

    let outcome = turn(session.as_mut(), &prompt).await;

    let requests = mock.requests();
    assert_eq!(
        requests.len(),
        3,
        "one model call per response: {outcome:?}"
    );
    let yielded = call_output(&requests[1], "call_r1").expect("the model was told the first cell");
    assert!(
        yielded.contains("Script running with cell ID 1") && !yielded.contains("wall-time limit"),
        "the spinning cell yielded before its wall: {yielded}"
    );
    let failed = call_output(&requests[2], "call_r2").expect("the model was told the wait");
    assert!(
        failed.contains("Script failed") && failed.contains("2000 ms wall-time limit"),
        "the wait's result names the wall limit: {failed}"
    );
    assert_eq!(
        call_outputs(&requests[2], "call_r1")
            .into_iter()
            .skip(1)
            .collect::<Vec<_>>(),
        [serde_json::json!(WALL_REPORT)],
        "the wait's request hands the model the guard's report as an output of the cell's own \
         call"
    );
    assert!(
        matches!(outcome, TurnOutcome::Completed { .. }),
        "a limit hit is a cell outcome, not a turn outcome: {outcome:?}"
    );
    let evidence = session.take_evidence();
    assert!(
        evidence
            .events
            .contains(&kata_types::agent::SessionEvidenceEvent::CodeModeLimit {
                which: "wall".into(),
            }),
        "the evidence records the wall hit the wait reported: {:?}",
        evidence.events
    );
    assert_eq!(
        observed.limits(),
        ["wall"],
        "one `code_mode_limit` progress observation, naming the wall"
    );
    let close = session.close().await;
    assert!(close.is_confirmed(), "{close:?}");
}

/// **A wall hit after a text past nanocode's visible budget is told to the
/// model and recorded.** The cell emits one 70,000-byte text, then spins until
/// the 2 s wall. On the Responses kind nanocode joins the cell's texts and its
/// `Script error:` into one text and middle-truncates it to the 10,000-token
/// budget, keeping its head and its tail; the error is the tail, so it
/// survives. MEASURED, the next request's result for the cell: its header,
/// then `Warning: truncated output (original token count: 17517)\nTotal output
/// lines: 3\n\n` and the text's head, `…7517 tokens truncated…`, its tail and
/// `\nScript error:\nCode Mode cell exceeded its 2000 ms wall-time limit`.
/// The guard's report of the wall reaches the model as an output of its own
/// for the call. The evidence records one `CodeModeLimit{wall}`, the progress
/// sink one `code_mode_limit`, and the turn completes.
///
/// **Would red if:** nanocode's truncation dropped or cut the error again (the
/// result no longer ends with it: restate what the model is told), the guard
/// sent no report of a wall hit (no output of its own, nothing recorded), or
/// the adapter read the hit off the visible result as well as off the report
/// (recorded twice).
#[tokio::test]
async fn a_wall_hit_after_a_long_text_is_told_to_the_model_and_recorded() {
    install_limits();
    let mock = MockProvider::start(vec![
        code_reply("r1", LONG_TEXT_THEN_SPIN, usage(1, 0, 1)),
        message_reply("r2", "DONE", usage(1, 0, 1)),
    ])
    .await;
    let observed = std::sync::Arc::new(Observations::default());
    let (mut session, _witness) = open_scoped(
        &openai(&mock.url, None),
        DoubleConfig::default(),
        scope().with_progress(observed.clone()),
    );

    let outcome = turn(session.as_mut(), &openai_prompt("write, then spin")).await;

    let requests = mock.requests();
    assert_eq!(
        requests.len(),
        2,
        "one model call per response: {outcome:?}"
    );
    let outputs = call_outputs(&requests[1], "call_r1");
    let [result, reports @ ..] = outputs.as_slice() else {
        panic!("the model was told the cell");
    };
    let texts: Vec<&str> = result
        .as_array()
        .expect("a content-item result")
        .iter()
        .filter_map(|item| item["text"].as_str())
        .collect();
    let [header, truncated] = texts.as_slice() else {
        panic!("the result is its header and one truncated text: {texts:.400?}");
    };
    assert!(
        header.starts_with("Script failed")
            && truncated.starts_with("Warning: truncated output (original token count: ")
            && truncated.contains(" tokens truncated…")
            && truncated.ends_with(&format!("\nScript error:\n{WALL_REPORT}")),
        "the cell failed and its truncated text ends with the wall's error: {:?}",
        &truncated[truncated.len().saturating_sub(200)..]
    );
    assert_eq!(
        reports.to_vec(),
        [serde_json::json!(WALL_REPORT)],
        "the model is handed the guard's report as an output of its own"
    );
    assert!(
        matches!(outcome, TurnOutcome::Completed { .. }),
        "a limit hit is a cell outcome, not a turn outcome: {outcome:?}"
    );
    assert_eq!(limits_recorded(session.as_mut()), ["wall"]);
    assert_eq!(observed.limits(), ["wall"]);
    let close = session.close().await;
    assert!(close.is_confirmed(), "{close:?}");
}

/// **MEASURED RESIDUAL: on the Messages kind a wall hit after a long text is
/// recorded, and the model is not told why the cell failed.** The same cell on
/// the Anthropic kind, where nanocode's Code Mode applies no budget of its own
/// and the backend bounds the `tool_result`'s blocks in order to 12,000
/// tokens: MEASURED, the next request's `tool_result` for the cell is an error
/// whose texts are its header, the 70,000-byte text middle-truncated (`…5511
/// tokens truncated…`) and `[2 more text blocks omitted]`, the cell's
/// `Script error:` and the guard's report the two dropped, so the wall is
/// named nowhere in it. The guard's notification still reaches the adapter,
/// so the evidence records one `CodeModeLimit{wall}`, and the turn completes.
///
/// **Would red if:** the adapter did not read the Messages kind's
/// `tool.notification` (nothing recorded), or nanocode's Messages backend
/// began to keep the error or deliver the report outside the truncated result
/// (the wall is named: restate the residual).
#[tokio::test]
async fn a_wall_hit_after_a_long_text_on_the_messages_kind_is_recorded_though_untold() {
    install_limits();
    let mock = MockProvider::start(vec![
        claude_code_reply("r1", LONG_TEXT_THEN_SPIN),
        claude_text_reply("DONE"),
    ])
    .await;
    let observed = std::sync::Arc::new(Observations::default());
    let (mut session, _witness) = open_scoped(
        &anthropic(&mock.url),
        DoubleConfig::default(),
        scope().with_progress(observed.clone()),
    );

    let outcome = turn(session.as_mut(), &anthropic_prompt("write, then spin")).await;

    let requests = mock.requests();
    assert_eq!(
        requests.len(),
        2,
        "one model call per response: {outcome:?}"
    );
    let texts = tool_result_texts(&requests[1], "toolu_r1").expect("the model was told the cell");
    let last = texts.last().map_or("", String::as_str);
    assert!(
        texts
            .first()
            .is_some_and(|header| header.starts_with("Script failed"))
            && texts.len() == 3
            && last == "[2 more text blocks omitted]"
            && !texts.iter().any(|text| text.contains("wall-time limit")),
        "the cell failed, and neither its error nor the guard's report survived; its last text \
         is: {last}"
    );
    assert!(
        matches!(outcome, TurnOutcome::Completed { .. }),
        "a limit hit is a cell outcome, not a turn outcome: {outcome:?}"
    );
    assert_eq!(limits_recorded(session.as_mut()), ["wall"]);
    assert_eq!(observed.limits(), ["wall"]);
    let close = session.close().await;
    assert!(close.is_confirmed(), "{close:?}");
}

/// A cell that waits 1.5 s, inside the 2 s wall, then states that it slept.
const SLEEPER: &str = "await new Promise((resolve) => setTimeout(resolve, 1500));\n\
     text(\"slept\");";

/// **A yielded cell that hits the wall while no `wait` observes it is told to
/// no one, and recorded when the turn ends.** On each kind the model starts a
/// cell that spins and yields after 200 ms, then two cells that each sleep
/// 1.5 s, so the first cell's 2 s wall passes while the third runs, and then
/// ends the turn. No request carries the wall: the first cell's result says it
/// is running, and nothing after it names the wall. nanocode ends the turn's
/// cells before it hands back a completed turn, and delivers the queued report
/// then, so the evidence records one `CodeModeLimit{wall}`, after the turn's
/// last model call.
///
/// **Would red if:** the report of a hit no call observed were lost at the
/// turn's end (nothing recorded), or nanocode began to tell the model of it.
#[tokio::test]
async fn a_yielded_cell_no_wait_observes_is_recorded_at_the_turn_end_and_told_to_no_one() {
    install_limits();
    let spin = "// @exec: {\"yield_time_ms\": 200}\nfor (;;) {}";
    let openai_mock = MockProvider::start(vec![
        code_reply("r1", spin, usage(1, 0, 1)),
        code_reply("r2", SLEEPER, usage(1, 0, 1)),
        code_reply("r3", SLEEPER, usage(1, 0, 1)),
        message_reply("r4", "DONE", usage(1, 0, 1)),
    ])
    .await;
    let anthropic_mock = MockProvider::start(vec![
        claude_code_reply("r1", spin),
        claude_code_reply("r2", SLEEPER),
        claude_code_reply("r3", SLEEPER),
        claude_text_reply("DONE"),
    ])
    .await;
    for (kind, mock, adapter, prompt) in [
        (
            "openai",
            &openai_mock,
            openai(&openai_mock.url, None),
            openai_prompt("spin, then sleep twice"),
        ),
        (
            "anthropic",
            &anthropic_mock,
            anthropic(&anthropic_mock.url),
            anthropic_prompt("spin, then sleep twice"),
        ),
    ] {
        let (mut session, _witness) = open_scoped(&adapter, DoubleConfig::default(), scope());
        let outcome = turn(session.as_mut(), &prompt).await;
        let requests = mock.requests();
        assert_eq!(
            requests.len(),
            4,
            "{kind}: one model call per response: {outcome:?}"
        );
        let told = requests
            .iter()
            .map(serde_json::Value::to_string)
            .collect::<String>();
        assert!(
            told.contains("Script running with cell ID 1") && !told.contains("wall-time limit"),
            "{kind}: the model was told the first cell runs, and never of its wall"
        );
        assert!(
            matches!(outcome, TurnOutcome::Completed { .. }),
            "{kind}: {outcome:?}"
        );
        let events = session.take_evidence().events;
        let last_model_call = events
            .iter()
            .rposition(|event| matches!(event, SessionEvidenceEvent::ModelCall { .. }));
        let limits: Vec<usize> = events
            .iter()
            .enumerate()
            .filter(|(_, event)| matches!(event, SessionEvidenceEvent::CodeModeLimit { .. }))
            .map(|(at, _)| at)
            .collect();
        assert_eq!(limits.len(), 1, "{kind}: one limit recorded: {events:?}");
        assert_eq!(
            events[limits[0]],
            SessionEvidenceEvent::CodeModeLimit {
                which: "wall".into()
            },
            "{kind}"
        );
        assert!(
            Some(limits[0]) > last_model_call,
            "{kind}: recorded at the turn's end, after its last model call: {events:?}"
        );
        let close = session.close().await;
        assert!(close.is_confirmed(), "{kind}: {close:?}");
    }
}

/// The limits the session's evidence records, in order.
fn limits_recorded(session: &mut dyn AgentSession) -> Vec<String> {
    session
        .take_evidence()
        .events
        .into_iter()
        .filter_map(|event| match event {
            SessionEvidenceEvent::CodeModeLimit { which } => Some(which.to_string()),
            _ => None,
        })
        .collect()
}

/// Every progress observation the session made, as the worker's sink would see
/// it.
#[derive(Debug, Default)]
struct Observations(std::sync::Mutex<Vec<(&'static str, Option<String>)>>);

impl Observations {
    /// The texts of the `code_mode_limit` observations, in order.
    fn limits(&self) -> Vec<String> {
        self.0
            .lock()
            .expect("observations")
            .iter()
            .filter(|(kind, _)| *kind == "code_mode_limit")
            .filter_map(|(_, text)| text.clone())
            .collect()
    }
}

impl kata_agent::adapter::scope::SessionProgressSink for Observations {
    fn observe(&self, observation: kata_agent::adapter::scope::SessionObservation) {
        self.0
            .lock()
            .expect("observations")
            .push((observation.kind, observation.text));
    }
}
