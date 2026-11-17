//! A Code Mode cell whose interpreter process ends, seen through the nanocode
//! adapter, on both kinds, under kata's own limits (`CODE_MODE_LIMITS`,
//! installed by the seam the worker calls at start, which runs every cell in
//! an interpreter process: this binary, re-executed, its entry below).
//!
//! The cell is one a model writes: a flood of bound functions, which under
//! kata's 256 MiB heap meets QuickJS 0.16.2's out-of-memory defect in
//! `Function.prototype.bind` (`code_mode_out_of_memory_defects.rs`) on the
//! Messages kind's heap layout, MEASURED 4 of 4 before the interpreter left
//! the hosting process: a SIGSEGV of the process running the cell, which was
//! the process hosting the worker (then the kata main itself, under the
//! deleted `in_process` worker transport; a `kata-worker` node now).
//!
//! The witnesses do not share the adapter's code: this process running on (the
//! test binary itself would die by the signal), the mock's log of the request
//! bodies it received (what the model was told), and the kernel's account of
//! this process's interpreter processes and threads.

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

use anthropic_turn::{anthropic, anthropic_prompt};
use kata_agent::adapter::{AgentSession, TurnOutcome};
use kata_agent_nanocode::install_code_mode_limits;
use kata_types::agent::SessionEvidenceEvent;
use mock_provider::{
    MockProvider, call_output, claude_code_reply, claude_text_reply, code_reply, message_reply,
    tool_result_texts, usage,
};
use openai_turn::{open, openai, openai_prompt, turn};
use quickjs_threads::{interpreters, quickjs_threads};
use toolhost_double::DoubleConfig;

kata_code_mode_host::interpreter_entry!();

/// A model-written flood of bound functions: it allocates until the heap
/// limit stops it, inside `Function.prototype.bind` sooner or later.
const BIND_FLOOD: &str = "const fns = [];\nfor (;;) fns.push(Math.max.bind(null, fns.length));";

/// A cell that states it ran.
const TEXT: &str = "text(\"a cell ran\");";

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

/// **On the Messages kind, a bind flood ends only its interpreter process: the
/// turn completes, and the evidence records the end.** The model's cells are
/// [text, bind flood, text, bind flood]. Each flood's interpreter process
/// ends by SIGSEGV, and the model is told the cell failed with the
/// supervisor's report naming the signal; the text cell after it runs in a
/// new interpreter; the turn completes with the model's final message, and
/// the evidence holds one `CodeModeInterpreterEnded{SIGSEGV}` per flood. No
/// QuickJS thread ever runs in this process.
///
/// **Would red if:** the cells ran in this process (watched, with kata's
/// backend not installed: the test binary dies by SIGSEGV), or the adapter
/// did not record the supervisor's report.
#[tokio::test]
async fn on_the_messages_kind_a_bind_flood_ends_only_its_interpreter_and_the_turn_completes() {
    install_code_mode_limits();
    let mock = MockProvider::start(vec![
        claude_code_reply("r1", TEXT),
        claude_code_reply("r2", BIND_FLOOD),
        claude_code_reply("r3", TEXT),
        claude_code_reply("r4", BIND_FLOOD),
        claude_text_reply("DONE"),
    ])
    .await;
    let (mut session, _witness) = anthropic_open(&mock.url);

    let outcome = turn(session.as_mut(), &anthropic_prompt("flood bound functions")).await;

    let requests = mock.requests();
    assert_eq!(
        requests.len(),
        5,
        "one model call per response: {outcome:?}"
    );
    let report = format!("{}SIGSEGV", kata_code_mode_host::ENDED_BY);
    for (request, call) in [(2, "toolu_r2"), (4, "toolu_r4")] {
        let told = tool_result_texts(&requests[request], call).expect("the model was told");
        assert!(
            told.iter().any(|text| text.contains(&report)),
            "the flood's result names its interpreter's end: {told:?}"
        );
    }
    let ran = tool_result_texts(&requests[3], "toolu_r3").expect("the model was told cell 3");
    assert!(
        ran.iter().any(|text| text.contains("a cell ran")),
        "the cell after the end ran: {ran:?}"
    );
    let TurnOutcome::Completed { response, .. } = &outcome else {
        panic!("an interpreter's end is a cell outcome, not a turn outcome: {outcome:?}");
    };
    assert_eq!(response, "DONE");
    assert!(quickjs_threads().is_empty(), "{:?}", quickjs_threads());
    let ended = SessionEvidenceEvent::CodeModeInterpreterEnded {
        signal: Some("SIGSEGV".into()),
    };
    assert_eq!(
        ends_recorded(session.as_mut()),
        [ended.clone(), ended],
        "the evidence records each flood's end once"
    );
    let close = session.close().await;
    assert!(close.is_confirmed(), "{close:?}");
    assert!(
        interpreters().is_empty(),
        "every interpreter process was reaped: {:?}",
        interpreters()
    );
}

/// **On the Responses kind, the same cells leave the turn whole: each flood
/// fails to the model and the evidence records how.** The model's cells are
/// [text, bind flood, text, bind flood]: each flood fails to the model, on the
/// heap limit (QuickJS handled the allocation failure) or with the end of its
/// interpreter process; the text cell after it runs; the turn completes, and
/// the evidence holds one record per flood, a `CodeModeLimit{memory}` or a
/// `CodeModeInterpreterEnded`. MEASURED: on this kind's heap layout the flood
/// meets the heap limit, 4 of 4 runs, before and after the interpreter left
/// the hosting process.
///
/// **Would red if:** a flood ended this process, or one of its failures went
/// unrecorded.
#[tokio::test]
async fn on_the_responses_kind_a_bind_flood_fails_to_the_model_and_the_turn_completes() {
    install_code_mode_limits();
    let mock = MockProvider::start(vec![
        code_reply("r1", TEXT, usage(1, 0, 1)),
        code_reply("r2", BIND_FLOOD, usage(1, 0, 1)),
        code_reply("r3", TEXT, usage(1, 0, 1)),
        code_reply("r4", BIND_FLOOD, usage(1, 0, 1)),
        message_reply("r5", "DONE", usage(1, 0, 1)),
    ])
    .await;
    let (mut session, _witness) = open(&openai(&mock.url, None), DoubleConfig::default());

    let outcome = turn(session.as_mut(), &openai_prompt("flood bound functions")).await;

    let requests = mock.requests();
    assert_eq!(
        requests.len(),
        5,
        "one model call per response: {outcome:?}"
    );
    for (request, call) in [(2, "call_r2"), (4, "call_r4")] {
        let told = call_output(&requests[request], call).expect("the model was told");
        assert!(
            told.contains("Script failed"),
            "the flood failed to the model: {told}"
        );
    }
    let ran = call_output(&requests[3], "call_r3").expect("the model was told cell 3");
    assert!(
        ran.contains("a cell ran") && !ran.contains("Script failed"),
        "{ran}"
    );
    let TurnOutcome::Completed { response, .. } = &outcome else {
        panic!("a flood's failure is a cell outcome, not a turn outcome: {outcome:?}");
    };
    assert_eq!(response, "DONE");
    let recorded = ends_recorded(session.as_mut());
    eprintln!("Responses kind, bind floods recorded as: {recorded:?}");
    assert_eq!(recorded.len(), 2, "one record per flood: {recorded:?}");
    let close = session.close().await;
    assert!(close.is_confirmed(), "{close:?}");
}

/// A session on the Anthropic kind over the toolhost double.
fn anthropic_open(url: &str) -> (Box<dyn AgentSession>, toolhost_double::DoubleWitness) {
    open(&anthropic(url), DoubleConfig::default())
}
