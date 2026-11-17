//! A Code Mode cell whose interpreter process ends while it runs, and a flood
//! of bound functions, seen through the nanocode adapter, on both kinds, under
//! kata's own limits (`CODE_MODE_LIMITS`, installed by the seam the worker
//! calls at start, which runs every cell in an interpreter process: this
//! binary, re-executed, its entry below).
//!
//! Under QuickJS a model-written bind flood met its out-of-memory defect in
//! `Function.prototype.bind` and ended the process running the cell by
//! SIGSEGV. Under djs a heap hit is uncatchable and the patched engine reports
//! it, so the flood is a heap hit like any other: it ends no interpreter. A
//! cell can end a djs interpreter by SIGABRT (a native recursion past its cell
//! thread's stack, a native allocation past its address-space limit: MEASURED
//! in `kata-code-mode-host`'s `interpreter_process.rs`); here the cell whose
//! interpreter ends has it ended from outside, by SIGKILL, as the kernel's OOM
//! killer ends one (every interpreter runs at `oom_score_adj` 1000, the first
//! the killer picks), so the end lands while the cell waits.
//!
//! The witnesses do not share the adapter's code: the mock's log of the
//! request bodies it received (what the model was told), and the kernel's
//! account of this process's interpreter processes and of its own peak
//! resident set.

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
#[path = "fixtures/resident.rs"]
mod resident;
#[path = "fixtures/toolhost_double.rs"]
#[allow(dead_code)]
mod toolhost_double;

use serde_json::json;

use anthropic_turn::{anthropic, anthropic_prompt};
use kata_agent::adapter::{AgentSession, TurnOutcome};
use kata_agent_nanocode::{CODE_MODE_LIMITS, install_code_mode_limits};
use kata_types::agent::SessionEvidenceEvent;
use mock_provider::{
    Gate, MockProvider, Reply, call_outputs, claude_code_reply, claude_text_reply, code_reply,
    message_reply, tool_result_texts, usage, wait_reply,
};
use openai_turn::{bounded, open, openai, openai_prompt, turn};
use quickjs_threads::{interpreters, once_listed};
use resident::peak_resident_bytes;
use toolhost_double::DoubleConfig;

kata_code_mode_host::interpreter_entry!();

/// A model-written flood of bound functions: it allocates until the heap
/// limit stops it, inside `Function.prototype.bind` sooner or later. Its
/// `exec` yields only after 120 s, past the turn's bound
/// ([`openai_turn::TURN_BOUND`]): the flood takes about 8 s on a quiet host
/// and about 11 s under full-suite load, 19 s with every core busy twice
/// over (MEASURED at 8ec3b215), and at
/// nanocode's default yield, 10 s (`DEFAULT_YIELD`), a slow flood was
/// returned to the model as `Script running with cell ID 2` instead of its
/// heap hit, so the cell's verdict hung on the host's speed.
const BIND_FLOOD: &str = "// @exec: {\"yield_time_ms\": 120000}\nconst fns = [];\n\
     for (;;) fns.push(Math.max.bind(null, fns.length));";

/// A cell that states it ran.
const TEXT: &str = "text(\"a cell ran\");";

/// The vendored guard's report of a heap-limit hit under kata's limits.
fn memory_report() -> String {
    format!(
        "Code Mode cell exceeded its {}-byte memory limit",
        CODE_MODE_LIMITS.memory_bytes
    )
}

/// The cell's error the patched engine gives a heap hit.
const OUT_OF_MEMORY: &str = "Script error:\nScript stopped: the cell ran out of memory.";

/// The interpreter-end and limit records of the session's evidence, in order.
fn ends_recorded(session: &mut dyn AgentSession) -> Vec<SessionEvidenceEvent> {
    session
        .take_evidence()
        .events
        .into_iter()
        .filter(|event| {
            matches!(
                event,
                SessionEvidenceEvent::CodeModeInterpreterEnded { .. }
                    | SessionEvidenceEvent::CodeModeLimit { .. }
            )
        })
        .collect()
}

/// **A bind flood is a heap hit on both kinds: the model is told, kata records
/// the limit, and no interpreter ends.** On each kind the model's cells are
/// [text, bind flood, text]. The flood fails to the model with the patched
/// engine's out-of-memory error and the guard's report of the 256 MiB limit:
/// on the Messages kind the result's texts are its header, `Script error:\n
/// Script stopped: the cell ran out of memory.` and the report; on the
/// Responses kind the result is its header and that error, and the report an
/// output of its own for the call. The text cell after it runs, the turn
/// completes, and the evidence holds one `CodeModeLimit{memory}` per kind and
/// no `CodeModeInterpreterEnded`. MEASURED: about 8 s per flood ([`BIND_FLOOD`]). The flood
/// fills its heap in an interpreter process: this process's peak resident set
/// stays under half the heap limit.
///
/// **Would red if:** djs mishandled an exhausted heap in `bind` (an interpreter
/// end recorded, or the supervisor's report told, in place of the limit), the
/// patched engine stopped reporting a heap hit (no report, nothing recorded),
/// or the cells ran in this process (its peak resident set past half the heap
/// limit).
#[tokio::test]
async fn a_bind_flood_is_a_heap_hit_on_both_kinds_and_ends_no_interpreter() {
    install_code_mode_limits();

    let mock = MockProvider::start(vec![
        claude_code_reply("r1", TEXT),
        claude_code_reply("r2", BIND_FLOOD),
        claude_code_reply("r3", TEXT),
        claude_text_reply("DONE"),
    ])
    .await;
    let (mut session, _witness) = open(&anthropic(&mock.url), DoubleConfig::default());
    let outcome = turn(session.as_mut(), &anthropic_prompt("flood bound functions")).await;
    let requests = mock.requests();
    assert_eq!(
        requests.len(),
        4,
        "anthropic: one model call per response: {outcome:?}"
    );
    let told = tool_result_texts(&requests[2], "toolu_r2").expect("the model was told the flood");
    let [header, error, report] = told.as_slice() else {
        panic!("anthropic: the flood's result is its header, error and report: {told:?}");
    };
    assert!(
        header.starts_with("Script failed") && error == OUT_OF_MEMORY && *report == memory_report(),
        "anthropic: the flood failed on the heap limit: {told:?}"
    );
    let ran = tool_result_texts(&requests[3], "toolu_r3").expect("the model was told cell 3");
    assert!(
        ran.iter().any(|text| text == "a cell ran"),
        "anthropic: the cell after the flood ran: {ran:?}"
    );
    let TurnOutcome::Completed { response, .. } = &outcome else {
        panic!("anthropic: a heap hit is a cell outcome, not a turn outcome: {outcome:?}");
    };
    assert_eq!(response, "DONE");
    assert_eq!(
        ends_recorded(session.as_mut()),
        [SessionEvidenceEvent::CodeModeLimit {
            which: "memory".into()
        }],
        "anthropic: the evidence records the heap hit, and no interpreter end"
    );
    let close = session.close().await;
    assert!(close.is_confirmed(), "anthropic: {close:?}");

    let mock = MockProvider::start(vec![
        code_reply("r1", TEXT, usage(1, 0, 1)),
        code_reply("r2", BIND_FLOOD, usage(1, 0, 1)),
        code_reply("r3", TEXT, usage(1, 0, 1)),
        message_reply("r4", "DONE", usage(1, 0, 1)),
    ])
    .await;
    let (mut session, _witness) = open(&openai(&mock.url, None), DoubleConfig::default());
    let outcome = turn(session.as_mut(), &openai_prompt("flood bound functions")).await;
    let requests = mock.requests();
    assert_eq!(
        requests.len(),
        4,
        "openai: one model call per response: {outcome:?}"
    );
    assert!(header_of(&requests[2], "call_r2").starts_with("Script failed"));
    assert_eq!(
        call_outputs(&requests[2], "call_r2")
            .iter()
            .map(output_texts)
            .collect::<Vec<_>>(),
        [
            vec![header_of(&requests[2], "call_r2"), OUT_OF_MEMORY.to_owned()],
            vec![memory_report()]
        ],
        "openai: the flood failed on the heap limit, and the report follows as an output of its \
         own"
    );
    assert_eq!(
        call_outputs(&requests[3], "call_r3")
            .iter()
            .map(output_texts)
            .collect::<Vec<_>>(),
        [vec![
            header_of(&requests[3], "call_r3"),
            "a cell ran".to_owned()
        ]],
        "openai: the cell after the flood ran"
    );
    let TurnOutcome::Completed { response, .. } = &outcome else {
        panic!("openai: a heap hit is a cell outcome, not a turn outcome: {outcome:?}");
    };
    assert_eq!(response, "DONE");
    assert_eq!(
        ends_recorded(session.as_mut()),
        [SessionEvidenceEvent::CodeModeLimit {
            which: "memory".into()
        }],
        "openai: the evidence records the heap hit, and no interpreter end"
    );
    let close = session.close().await;
    assert!(close.is_confirmed(), "openai: {close:?}");

    let peak = peak_resident_bytes();
    assert!(
        peak < u64::try_from(CODE_MODE_LIMITS.memory_bytes / 2).expect("a byte count"),
        "this process's peak resident set is {peak} bytes: a flood filled its heap here"
    );
}

/// A cell that yields to the model after 200 ms, then waits a minute on a
/// timer, inside kata's 300 s wall: it runs, idle, until something ends it.
const WAITER: &str = "// @exec: {\"yield_time_ms\": 200}\n\
     await new Promise((resolve) => setTimeout(resolve, 60000));\n\
     text(\"the timer fired\");";

/// The supervisor's report of an interpreter ended by SIGKILL.
fn killed_report() -> String {
    format!("{}SIGKILL", kata_code_mode_host::ENDED_BY)
}

/// **A cell whose interpreter process is killed while it runs fails to the
/// model with the supervisor's report, kata records the end, and the turn
/// completes, on both kinds.** On each kind the model starts [`WAITER`], which
/// yields as cell 1 (`Script running with cell ID 1`). Once the model's next
/// request is in, the kernel lists exactly one interpreter process, the
/// waiter's, and this test kills it by SIGKILL; only then does the model's
/// answer, a `wait` on cell 1, go out. The wait's result is the cell's failure,
/// MEASURED: on the Messages kind its texts are its header, `Script
/// error:\nCode Mode's interpreter process ended by SIGKILL` (the supervisor's
/// error) and the supervisor's report, `Code Mode's interpreter process ended
/// by SIGKILL`; on the Responses kind the result is its header and that error,
/// and the report is an output of its own for the cell's `exec` call. Under
/// djs no cell-reachable path that ends an interpreter is measured, so the
/// end comes from outside, as the kernel's OOM killer would deliver it (every
/// interpreter runs at `oom_score_adj` 1000). The model's next cell runs in a
/// new interpreter and its text reaches the model; the turn completes; the
/// evidence holds exactly one `CodeModeInterpreterEnded{SIGKILL}`, and every
/// interpreter process is reaped by the session's close.
///
/// **Would red if:** the supervisor did not report an interpreter that ended
/// while its cell ran (nothing told, nothing recorded), the adapter did not
/// read that report off either kind's `tool.notification` (nothing recorded),
/// an interpreter's end ended Code Mode for the turn (the next cell fails), or
/// the cells ran in this process (no interpreter is ever listed: the bounded
/// listing fails).
#[tokio::test]
async fn a_cell_whose_interpreter_is_killed_fails_to_the_model_and_the_turn_completes_on_both_kinds()
 {
    install_code_mode_limits();
    let report = killed_report();

    let killed = Gate::default();
    let mock = MockProvider::start(vec![
        claude_code_reply("r1", WAITER),
        Reply::Gated(killed.clone(), Box::new(claude_wait_reply("r2", "1"))),
        claude_code_reply("r3", TEXT),
        claude_text_reply("DONE"),
    ])
    .await;
    let (mut session, _witness) = open(&anthropic(&mock.url), DoubleConfig::default());
    let prompt = anthropic_prompt("wait, then go on");
    let (outcome, ()) = tokio::join!(
        turn(session.as_mut(), &prompt),
        kill_the_waiter(&mock, &killed)
    );
    let requests = mock.requests();
    assert_eq!(
        requests.len(),
        4,
        "anthropic: one model call per response: {outcome:?}"
    );
    let running = tool_result_texts(&requests[1], "toolu_r1").expect("the model was told cell 1");
    assert!(
        running
            .first()
            .is_some_and(|header| header.starts_with("Script running with cell ID 1")),
        "anthropic: the waiter yielded as cell 1: {running:?}"
    );
    let ended = tool_result_texts(&requests[2], "toolu_r2").expect("the model was told the wait");
    let [header, error, last] = ended.as_slice() else {
        panic!(
            "anthropic: the wait's result is its header, the cell's error and the report: {ended:?}"
        );
    };
    assert!(
        header.starts_with("Script failed")
            && *error == format!("Script error:\n{report}")
            && *last == report,
        "anthropic: the wait's result names the interpreter's end: {ended:?}"
    );
    let ran = tool_result_texts(&requests[3], "toolu_r3").expect("the model was told cell 3");
    assert!(
        ran.iter().any(|text| text == "a cell ran"),
        "anthropic: the cell after the end ran: {ran:?}"
    );
    let TurnOutcome::Completed { response, .. } = &outcome else {
        panic!(
            "anthropic: an interpreter's end is a cell outcome, not a turn outcome: {outcome:?}"
        );
    };
    assert_eq!(response, "DONE");
    assert_eq!(
        ends_recorded(session.as_mut()),
        [SessionEvidenceEvent::CodeModeInterpreterEnded {
            signal: Some("SIGKILL".into()),
        }],
        "anthropic: the evidence records the end once"
    );
    let close = session.close().await;
    assert!(close.is_confirmed(), "anthropic: {close:?}");
    assert!(
        interpreters().is_empty(),
        "anthropic: every interpreter process was reaped: {:?}",
        interpreters()
    );

    let killed = Gate::default();
    let mock = MockProvider::start(vec![
        code_reply("r1", WAITER, usage(1, 0, 1)),
        Reply::Gated(
            killed.clone(),
            Box::new(wait_reply("r2", "1", false, usage(1, 0, 1))),
        ),
        code_reply("r3", TEXT, usage(1, 0, 1)),
        message_reply("r4", "DONE", usage(1, 0, 1)),
    ])
    .await;
    let (mut session, _witness) = open(&openai(&mock.url, None), DoubleConfig::default());
    let prompt = openai_prompt("wait, then go on");
    let (outcome, ()) = tokio::join!(
        turn(session.as_mut(), &prompt),
        kill_the_waiter(&mock, &killed)
    );
    let requests = mock.requests();
    assert_eq!(
        requests.len(),
        4,
        "openai: one model call per response: {outcome:?}"
    );
    let ended: Vec<Vec<String>> = call_outputs(&requests[2], "call_r2")
        .iter()
        .map(output_texts)
        .collect();
    let [result] = ended.as_slice() else {
        panic!("openai: the wait has one output: {ended:?}");
    };
    let [header, error] = result.as_slice() else {
        panic!("openai: the wait's result is its header and the cell's error: {result:?}");
    };
    assert!(
        header.starts_with("Script failed") && *error == format!("Script error:\n{report}"),
        "openai: the wait's result names the interpreter's end: {result:?}"
    );
    assert_eq!(
        call_outputs(&requests[2], "call_r1")
            .iter()
            .skip(1)
            .map(output_texts)
            .collect::<Vec<_>>(),
        [vec![report.clone()]],
        "openai: the supervisor's report is an output of its own for the cell's call"
    );
    assert_eq!(
        call_outputs(&requests[3], "call_r3")
            .iter()
            .map(output_texts)
            .collect::<Vec<_>>(),
        [vec![
            header_of(&requests[3], "call_r3"),
            "a cell ran".to_owned()
        ]],
        "openai: the cell after the end ran"
    );
    let TurnOutcome::Completed { response, .. } = &outcome else {
        panic!("openai: an interpreter's end is a cell outcome, not a turn outcome: {outcome:?}");
    };
    assert_eq!(response, "DONE");
    assert_eq!(
        ends_recorded(session.as_mut()),
        [SessionEvidenceEvent::CodeModeInterpreterEnded {
            signal: Some("SIGKILL".into()),
        }],
        "openai: the evidence records the end once"
    );
    let close = session.close().await;
    assert!(close.is_confirmed(), "openai: {close:?}");
    assert!(
        interpreters().is_empty(),
        "openai: every interpreter process was reaped: {:?}",
        interpreters()
    );
}

/// Once the model's second request is in (the waiter has yielded, so its cell
/// runs), kills the one interpreter process the kernel lists, the waiter's, by
/// SIGKILL, then lets the model's `wait` go out.
async fn kill_the_waiter(mock: &MockProvider, killed: &Gate) {
    mock.wait_for_requests(2).await;
    let listed = bounded("the waiter's interpreter", once_listed(1, interpreters)).await;
    let [pid] = listed.iter().copied().collect::<Vec<_>>()[..] else {
        panic!("one interpreter while the waiter runs: {listed:?}");
    };
    let pid =
        rustix::process::Pid::from_raw(i32::try_from(pid).expect("a pid")).expect("a nonzero pid");
    rustix::process::kill_process(pid, rustix::process::Signal::KILL)
        .expect("kill the waiter's interpreter");
    killed.open();
}

/// A Messages stream whose content is one Code Mode `wait` call on cell
/// `cell_id`.
fn claude_wait_reply(id: &str, cell_id: &str) -> Reply {
    let input = json!({"cell_id": cell_id}).to_string();
    Reply::Events(vec![
        json!({
            "type": "message_start",
            "message": {
                "id": format!("msg_{id}"), "type": "message", "role": "assistant",
                "model": "claude-mock", "content": [], "stop_reason": null,
                "stop_sequence": null,
                "usage": {"input_tokens": 10, "output_tokens": 1},
            },
        }),
        json!({
            "type": "content_block_start", "index": 0,
            "content_block": {"type": "tool_use", "id": format!("toolu_{id}"), "name": "wait", "input": {}},
        }),
        json!({
            "type": "content_block_delta", "index": 0,
            "delta": {"type": "input_json_delta", "partial_json": input},
        }),
        json!({"type": "content_block_stop", "index": 0}),
        json!({
            "type": "message_delta",
            "delta": {"stop_reason": "tool_use", "stop_sequence": null},
            "usage": {"output_tokens": 3},
        }),
        json!({"type": "message_stop"}),
    ])
}

/// The texts of one Responses output: a bare string, or the `text` of each
/// content item that has one.
fn output_texts(output: &serde_json::Value) -> Vec<String> {
    match output {
        serde_json::Value::String(text) => vec![text.clone()],
        serde_json::Value::Array(items) => items
            .iter()
            .filter_map(|item| item["text"].as_str())
            .map(str::to_owned)
            .collect(),
        other => panic!("an output that is neither text nor content items: {other}"),
    }
}

/// The header of `call_id`'s result in `request` (its first text), which
/// carries the cell's wall time.
fn header_of(request: &serde_json::Value, call_id: &str) -> String {
    call_outputs(request, call_id)
        .first()
        .map(output_texts)
        .and_then(|texts| texts.into_iter().next())
        .unwrap_or_default()
}
