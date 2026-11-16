//! The live-worker cap, seen through the nanocode adapter. On native nanocode
//! spawns a Code Mode host for every cell, and kata's installer
//! (`kata_code_mode_host::install`) gives each host an interpreter process of
//! its own, this binary re-executed (its entry below), counted live until it
//! is reaped: so an attempt's running cells are not bounded to one
//! interpreter, and only `CodeModeLimits::live_workers` bounds how many
//! interpreters, each under `memory_bytes`, the process holds. kata's cap of 8
//! would take nine spinning cells to reach, so this binary installs kata's
//! limits with a cap of two, through that installer, before any agent is
//! built; it is its own binary because that installer is once-only.
//!
//! The witnesses do not share the adapter's code: the mock's log of the
//! request bodies it received (what the model was told) and the kernel's
//! account of this process's interpreter processes.
//!
//! A refused cell never had a worker, so no guard reports it: the refusal is
//! the cell's result's only text after its header, always inside nanocode's
//! visible budget, and the adapter reads it off the failed `exec` result, on
//! each kind's result shape.

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

use std::time::Duration;

use serde_json::json;

use anthropic_turn::{anthropic, anthropic_prompt};
use kata_agent::adapter::TurnOutcome;
use kata_agent_nanocode::CODE_MODE_LIMITS;
use kata_code_mode_host::CodeModeLimits;
use kata_code_mode_host::{Program, install};
use mock_provider::{
    Gate, MockProvider, Reply, call_output, claude_code_reply, claude_text_reply, code_reply,
    message_reply, tool_result_texts, usage,
};
use openai_turn::{bounded, open_scoped, openai, openai_prompt, scope, turn};
use quickjs_threads::{interpreters, once_listed};

kata_code_mode_host::interpreter_entry!();
use toolhost_double::DoubleConfig;

/// A cell that spins in JavaScript and yields to the model after 200 ms, so it
/// keeps its worker while the model starts the next one.
const SPINNER: &str = "// @exec: {\"yield_time_ms\": 200}\nwhile (true) {}";

/// A response whose one output is a Code Mode `wait` on cell 1 that yields
/// back after 1 s: it holds the turn open, with the spinning cells live, while
/// the kernel is read.
fn wait_on_the_first_cell(id: &str) -> Reply {
    Reply::Events(vec![
        json!({"type": "response.created", "response": {"id": id}}),
        json!({
            "type": "response.output_item.done",
            "output_index": 0,
            "item": {
                "type": "function_call",
                "id": format!("fc_{id}"),
                "call_id": format!("call_{id}"),
                "name": "wait",
                "arguments": json!({"cell_id": "1", "yield_time_ms": 1000}).to_string(),
            },
        }),
        json!({
            "type": "response.completed",
            "response": {"id": id, "model": "gpt-6-luna", "usage": usage(1, 0, 1)},
        }),
    ])
}

/// **A cell past the live-worker cap fails to the model, and the turn goes
/// on.** The model starts three cells that each spin and yield. The first two
/// each take a worker; the third would need a third worker, past the cap of
/// two, and the next request hands the model its failure naming the cap. The
/// model then waits on the first cell, which holds the turn open: before the
/// turn ends the kernel lists exactly two interpreter processes, the two
/// spinning cells' (both still running: the wait's output says so), and none
/// for the third.
///
/// The listing is read 300 ms past the request that tells the model the third
/// cell's refusal, a window for an interpreter the refused cell would have
/// started to be listed in; and then as soon as the kernel lists the spinning
/// cells' two, with the turn's end held until it is read. Each cell yields to
/// the model on its 200 ms clock, not on its interpreter's start, so a
/// spinning cell's interpreter can still be starting then (a host under load).
///
/// The session's evidence records `CodeModeLimit{workers}` and its progress
/// sink sees one `code_mode_limit` observation naming the workers, read off the
/// vendored guard's own refusal text: a bump that rewords it is red here.
#[tokio::test]
async fn a_cell_past_the_live_worker_limit_fails_to_the_model_and_the_turn_goes_on() {
    install(
        CodeModeLimits {
            live_workers: 2,
            ..CODE_MODE_LIMITS
        },
        Program::this_executable(),
    )
    .expect("the only limits this process installs");
    let sampled = Gate::default();
    let mock = MockProvider::start(vec![
        code_reply("r1", SPINNER, usage(1, 0, 1)),
        code_reply("r2", SPINNER, usage(1, 0, 1)),
        code_reply("r3", SPINNER, usage(1, 0, 1)),
        wait_on_the_first_cell("r4"),
        Reply::Gated(
            sampled.clone(),
            Box::new(message_reply("r5", "DONE", usage(1, 0, 1))),
        ),
    ])
    .await;
    let observed = std::sync::Arc::new(Observations::default());
    let (mut session, _witness) = open_scoped(
        &openai(&mock.url, None),
        DoubleConfig::default(),
        scope().with_progress(observed.clone()),
    );
    let prompt = openai_prompt("spin three");

    let (outcome, after_refusal) = tokio::join!(turn(session.as_mut(), &prompt), async {
        mock.wait_for_requests(4).await;
        tokio::time::sleep(Duration::from_millis(300)).await;
        let listed = bounded(
            "the spinning cells' two interpreters",
            once_listed(2, interpreters),
        )
        .await;
        sampled.open();
        listed
    });

    let requests = mock.requests();
    assert_eq!(
        requests.len(),
        5,
        "one model call per response: {outcome:?}"
    );
    for (index, call) in [(1, "call_r1"), (2, "call_r2")] {
        let yielded = call_output(&requests[index], call).expect("the model was told the cell");
        assert!(
            yielded.contains(&format!("Script running with cell ID {index}")),
            "cell {index} yielded while it spins: {yielded}"
        );
    }
    let refused = call_output(&requests[3], "call_r3").expect("the model was told the third cell");
    assert!(
        refused.contains("already runs 2 Code Mode workers, its limit"),
        "the third cell's output names the worker cap: {refused}"
    );
    let waited = call_output(&requests[4], "call_r4").expect("the model was told the wait");
    assert!(
        waited.contains("Script running with cell ID 1"),
        "the first cell still ran through the wait: {waited}"
    );
    assert_eq!(
        after_refusal.len(),
        2,
        "the two spinning cells' hosts, and none for the refused cell: {after_refusal:?}"
    );
    let TurnOutcome::Completed { response, .. } = &outcome else {
        panic!("a refused cell is a cell outcome, not a turn outcome: {outcome:?}");
    };
    assert_eq!(response, "DONE");
    let evidence = session.take_evidence();
    assert!(
        evidence
            .events
            .contains(&kata_types::agent::SessionEvidenceEvent::CodeModeLimit {
                which: "workers".into(),
            }),
        "the evidence records the worker-cap refusal: {:?}",
        evidence.events
    );
    assert_eq!(
        observed.limits(),
        ["workers"],
        "one `code_mode_limit` progress observation, naming the workers"
    );
    let close = session.close().await;
    assert!(close.is_confirmed(), "{close:?}");
}

/// **On the Messages kind too, a cell past the live-worker cap fails to the
/// model naming the cap, kata records it, and the turn goes on.** The model
/// starts three cells that each spin and yield, on the Anthropic kind under a
/// cap of two: the first two each take a worker and yield, and the next
/// request's `tool_result` for the third is an error whose last text is the
/// guard's refusal naming the cap. The evidence records one
/// `CodeModeLimit{workers}`, read off that result in the Messages kind's own
/// shape (`{content_blocks}`), and the turn completes.
///
/// **Would red if:** the adapter read a `tool.result` only in the Responses
/// kind's shape (nothing recorded on this kind).
#[tokio::test]
async fn on_the_messages_kind_a_cell_past_the_live_worker_limit_is_told_and_recorded() {
    install(
        CodeModeLimits {
            live_workers: 2,
            ..CODE_MODE_LIMITS
        },
        Program::this_executable(),
    )
    .expect("the only limits this process installs");
    let mock = MockProvider::start(vec![
        claude_code_reply("r1", SPINNER),
        claude_code_reply("r2", SPINNER),
        claude_code_reply("r3", SPINNER),
        claude_text_reply("DONE"),
    ])
    .await;
    let observed = std::sync::Arc::new(Observations::default());
    let (mut session, _witness) = open_scoped(
        &anthropic(&mock.url),
        DoubleConfig::default(),
        scope().with_progress(observed.clone()),
    );

    let outcome = turn(session.as_mut(), &anthropic_prompt("spin three")).await;

    let requests = mock.requests();
    assert_eq!(
        requests.len(),
        4,
        "one model call per response: {outcome:?}"
    );
    for (index, tool_use) in [(1, "toolu_r1"), (2, "toolu_r2")] {
        let yielded = tool_result_texts(&requests[index], tool_use)
            .expect("the model was told the cell")
            .join("\n");
        assert!(
            yielded.contains(&format!("Script running with cell ID {index}")),
            "cell {index} yielded while it spins: {yielded}"
        );
    }
    let refused =
        tool_result_texts(&requests[3], "toolu_r3").expect("the model was told the third cell");
    assert!(
        refused
            .first()
            .is_some_and(|header| header.starts_with("Script failed"))
            && refused
                .last()
                .is_some_and(|last| last.contains("already runs 2 Code Mode workers, its limit")),
        "the third cell's result ends with the refusal naming the worker cap: {refused:?}"
    );
    let TurnOutcome::Completed { response, .. } = &outcome else {
        panic!("a refused cell is a cell outcome, not a turn outcome: {outcome:?}");
    };
    assert_eq!(response, "DONE");
    let evidence = session.take_evidence();
    assert!(
        evidence
            .events
            .contains(&kata_types::agent::SessionEvidenceEvent::CodeModeLimit {
                which: "workers".into(),
            }),
        "the evidence records the worker-cap refusal: {:?}",
        evidence.events
    );
    assert_eq!(observed.limits(), ["workers"]);
    let close = session.close().await;
    assert!(close.is_confirmed(), "{close:?}");
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
