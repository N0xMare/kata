//! The Code Mode output limit, and the heap and stack limits hit after a long
//! text, seen through the nanocode adapter, under kata's own limits
//! (`CODE_MODE_LIMITS`: 8 MiB of output, 256 MiB of heap and 1 MiB of
//! interpreter stack per cell), installed by the seam the worker calls at
//! start. The engine's limits are process-global, so this is a
//! binary of its own, like the memory, wall and live-worker twins.
//!
//! The witnesses do not share the adapter's code: the mock's log of the
//! request bodies it received (what the model was told), and the kernel's
//! account of this process's interpreter processes (the installer runs every
//! cell in one, this binary re-executed: its entry below). The guard's
//! messages are read off the real vendored engine, so a bump that rewords one
//! is red here.
//!
//! What reaches the model as a cell's result is nanocode's VISIBLE output of
//! it. Both kinds keep the result's text items in order up to a 12,000-token
//! budget (the Responses kind counts 4 bytes a token, the Messages kind 4
//! UTF-16 units), the result's header and its `Script error:` counted with the
//! cell's text, middle-truncate the item that crosses it, drop the text items
//! after it and append a count of them (`[omitted <n> text items ...]`,
//! `[<n> more text blocks omitted]`); non-text items pass. Code Mode appends a
//! failed cell's `Script error:` last, so once the header and the cell's text
//! fill the budget it is cut or dropped on both kinds. The vendored guard
//! therefore ALSO sends its report of the limit as a Code Mode notification of
//! its own, just before the error. The Responses kind hands the model each
//! notification as an output of its own for the call, truncated on its own, so
//! the report reaches the model there unless nanocode compacts the turn's
//! history first, which rewrites the newest outputs, the report first; the
//! Messages kind appends it to the result as its last text block, which the
//! same truncation drops once the text before it takes the whole budget. On
//! both kinds nanocode emits the notification as a `tool.notification` event,
//! which the adapter records as `CodeModeLimit` whatever the model was shown.

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

use anthropic_turn::{anthropic, anthropic_prompt};
use kata_agent::adapter::{AgentSession, TurnOutcome};
use kata_agent_nanocode::{CODE_MODE_LIMITS, install_code_mode_limits};
use kata_types::agent::SessionEvidenceEvent;
use mock_provider::{
    Gate, MockProvider, Reply, call_output, call_outputs, claude_code_reply, claude_text_reply,
    code_reply, compaction_reply, message_reply, tool_result_texts, usage,
};
use nanocode_code_mode_engine::CELL_EVENT_BYTES;
use openai_turn::{bounded, open_scoped, openai, openai_prompt, scope, turn};
use quickjs_threads::{interpreters, once_listed};
use toolhost_double::DoubleConfig;

// The Code Mode limits this binary installs run each cell in an interpreter
// process: this binary, re-executed.
kata_code_mode_host::interpreter_entry!();

/// A cell that waits 500 ms, then emits 64 KiB image content items until
/// something stops it, and states how many it sent if it ever gets past the
/// loop. Each is charged its payload plus the event cost, and nanocode passes
/// every image item to the model (it replaces this unparseable one with a
/// short text), so the cell's text stays inside nanocode's visible budget.
const IMAGE_FLOOD: &str = "await new Promise((resolve) => setTimeout(resolve, 500));\n\
     const chunk = \"data:image/png;base64,\" + \"A\".repeat(64 * 1024);\n\
     let sent = 0;\n\
     for (let i = 0; i < 1024; i++) { image(chunk); sent += 1; }\n\
     text(`sent ${sent} chunks`);";

/// The bytes of a text that costs exactly kata's output limit: its bytes plus
/// the one event it opens (`CELL_EVENT_BYTES`).
const LIMIT_TEXT: usize = CODE_MODE_LIMITS.cell_emitted_bytes - CELL_EVENT_BYTES;

/// A cell that emits one text of [`LIMIT_TEXT`] bytes, then a 1-byte text,
/// then states that it went on, if it ever gets there.
fn text_flood() -> String {
    format!(
        "text(\"x\".repeat({LIMIT_TEXT}));\n\
         text(\"y\");\n\
         text(\"the cell went on\");"
    )
}

/// The vendored guard's output-limit message under kata's limits: the failed
/// cell's error, and the guard's report of the hit.
fn guard_message() -> String {
    format!(
        "Code Mode cell output exceeded its {}-byte limit",
        CODE_MODE_LIMITS.cell_emitted_bytes
    )
}

/// The vendored guard's report of a heap-limit hit under kata's limits.
fn memory_report() -> String {
    format!(
        "Code Mode cell exceeded its {}-byte memory limit",
        CODE_MODE_LIMITS.memory_bytes
    )
}

/// The vendored guard's report of a stack-limit hit under kata's limits.
fn stack_report() -> String {
    format!(
        "Code Mode cell exceeded its {}-byte interpreter stack limit",
        CODE_MODE_LIMITS.max_stack_bytes
    )
}

/// A cell that emits one 60,000-byte text, then recurses until QuickJS's
/// stack limit throws, uncaught.
const LONG_TEXT_THEN_RECURSE: &str = "text(\"x\".repeat(60000));\n\
     function dive() { dive(); }\n\
     dive();";

const _: () = assert!(
    CODE_MODE_LIMITS.cell_emitted_bytes < 1024 * 64 * 1024,
    "the flood emits past kata's output limit"
);

/// A cell that emits one 60,000-byte text, past nanocode's 12,000-token
/// visible budget alone, then allocates 384 MiB of filled typed arrays, past
/// kata's 256 MiB heap limit, and reports what it holds if it gets there.
const LONG_TEXT_THEN_ALLOCATE: &str = "text(\"x\".repeat(60000));\n\
     const chunks = [];\n\
     for (let i = 0; i < 384; i++) chunks.push(new Uint8Array(1 << 20).fill(1));\n\
     text(`allocated ${chunks.length} MiB`);";

/// The same allocation after a 600-byte text, which fits the visible budget.
const SHORT_TEXT_THEN_ALLOCATE: &str = "text(\"x\".repeat(600));\n\
     const chunks = [];\n\
     for (let i = 0; i < 384; i++) chunks.push(new Uint8Array(1 << 20).fill(1));\n\
     text(`allocated ${chunks.length} MiB`);";

const _: () = assert!(
    CODE_MODE_LIMITS.memory_bytes < 384 << 20,
    "the cells allocate past kata's memory limit"
);

/// A cell that waits a second, then states that it ran.
const NEXT_CELL: &str = "await new Promise((resolve) => setTimeout(resolve, 1000));\n\
     text(\"the next cell ran\");";

/// **A model-written cell that emits past the output limit fails to the model
/// with the guard's message, kata records it, and the turn goes on.** Under
/// kata's 8 MiB limit the model's first cell emits 64 KiB image items, 64 MiB
/// if nothing stopped it; the next request hands the model that cell's failed
/// result, whose LAST text is the vendored guard's output message (`Code Mode
/// cell output exceeded its 8388608-byte limit`), followed by the guard's
/// report of the hit as an output of its own, and the cell never reached its
/// closing text. The model's second cell then runs in the same interpreter
/// process (/proc, read once the kernel lists the first cell's interpreter,
/// the model's second cell held until then, and while the second cell waits),
/// its text reaches the third
/// request, and the turn completes. The interpreter's supervisor, which
/// charges what the cell emits on its own count, does not kill a cell the
/// engine kept within its limit.
///
/// The session's evidence records `CodeModeLimit{output}` once and its
/// progress sink sees one `code_mode_limit` observation naming the output.
#[tokio::test]
async fn a_cell_emitting_past_the_output_limit_fails_to_the_model_and_the_turn_goes_on() {
    install_code_mode_limits();
    let first_listed = Gate::default();
    let mock = MockProvider::start(vec![
        code_reply("r1", IMAGE_FLOOD, usage(1, 0, 1)),
        Reply::Gated(
            first_listed.clone(),
            Box::new(code_reply("r2", NEXT_CELL, usage(1, 0, 1))),
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
    let prompt = openai_prompt("flood");

    let (outcome, (flooding, next_running)) =
        tokio::join!(turn(session.as_mut(), &prompt), async {
            // On the kernel's listing, not on a sleep: an interpreter starts
            // on its own schedule, and only the held second cell could start
            // another.
            let flooding =
                bounded("the first cell's interpreter", once_listed(1, interpreters)).await;
            first_listed.open();
            mock.wait_for_requests(2).await;
            tokio::time::sleep(Duration::from_millis(300)).await;
            (flooding, interpreters())
        });

    let requests = mock.requests();
    assert_eq!(
        requests.len(),
        3,
        "one model call per response: {outcome:?}"
    );
    let failed = call_output(&requests[1], "call_r1").expect("the model was told the first cell");
    let guard = guard_message();
    let last = last_text(&requests[1], "call_r1");
    assert!(
        failed.contains("Script failed")
            && last.starts_with("Script error:\n")
            && last.ends_with(&guard),
        "the first cell's result ends with the guard's output message ({guard}); its last text \
         is: {last}"
    );
    assert_eq!(
        reports(&requests[1], "call_r1"),
        [guard],
        "the model is handed the guard's report as an output of its own"
    );
    assert!(
        !failed.contains("chunks"),
        "the flood ran past the output limit: {}",
        &failed[failed.len().saturating_sub(400)..]
    );
    let next = call_output(&requests[2], "call_r2").expect("the model was told the second cell");
    assert!(
        next.contains("the next cell ran") && !next.contains("Script failed"),
        "the cell after the limit hit ran: {next}"
    );
    let TurnOutcome::Completed { response, .. } = &outcome else {
        panic!("a limit hit is a cell outcome, not a turn outcome: {outcome:?}");
    };
    assert_eq!(response, "DONE");
    assert_eq!(
        flooding.len(),
        1,
        "one interpreter while the first cell waits: {flooding:?}"
    );
    assert_eq!(
        flooding, next_running,
        "the cell after the limit hit ran in another interpreter process"
    );
    assert_eq!(
        limits_recorded(session.as_mut()),
        ["output"],
        "the evidence records the output-limit hit once"
    );
    assert_eq!(
        observed.limits(),
        ["output"],
        "one `code_mode_limit` progress observation, naming the output"
    );
    let close = session.close().await;
    assert!(close.is_confirmed(), "{close:?}");
}

/// **A TEXT flood past the output limit is told to the model and recorded,
/// though nanocode drops the cell's error.** Under kata's 8 MiB limit a cell
/// emits one text that costs exactly the limit, then a 1-byte text: the guard
/// accepts the first and fails the cell on the second. nanocode's visible
/// result keeps only the first 12,000 tokens of its text and ends with
/// `[omitted 1 text items ...]`: the item dropped is the `Script error:`
/// naming the limit. The model is told the hit all the same, by the guard's
/// report, which the next request hands it as an output of its own for the
/// call. The evidence records one `CodeModeLimit{output}`, the progress sink
/// one `code_mode_limit`, and the turn goes on.
///
/// The failure is the output limit's: the text that costs exactly the limit
/// reaches nanocode whole — nanocode keeps its middle-truncated head and tail
/// and names the tokens it cut (`…<n> tokens truncated…`, at nanocode's 4 bytes
/// a token), and the kept bytes plus the cut ones are its bytes, to within a
/// token — and the cell never reaches its closing text. That the limit refuses
/// the very next byte is the engine's own cell's
/// (`code_mode_limits::the_output_limit_admits_its_last_byte_and_refuses_the_next`):
/// the 1-byte text here costs an event too, so it crosses by more than a byte.
/// One text is one item of nanocode's result whatever the host's load: a run of
/// texts reaches it as one item only until nanocode opens its stream of the
/// cell's output, 500 ms into the cell, which splits the run, so a flood of
/// many texts reached the model as a count that depended on the load
/// (MEASURED: 8 of 20 runs beside a CPU hog).
///
/// **Would red if:** the guard sent no report of its own (the model is told a
/// bare `Script failed`), the adapter read the hit off the visible result
/// (nothing recorded), or the guard charged a text more than its bytes and
/// one event (the first text fails the cell and never reaches nanocode).
#[tokio::test]
async fn a_text_flood_past_the_output_limit_is_told_to_the_model_and_recorded() {
    install_code_mode_limits();
    let mock = MockProvider::start(vec![
        code_reply("r1", &text_flood(), usage(1, 0, 1)),
        message_reply("r2", "DONE", usage(1, 0, 1)),
    ])
    .await;
    let observed = std::sync::Arc::new(Observations::default());
    let (mut session, _witness) = open_scoped(
        &openai(&mock.url, None),
        DoubleConfig::default(),
        scope().with_progress(observed.clone()),
    );

    let outcome = turn(session.as_mut(), &openai_prompt("flood text")).await;

    let requests = mock.requests();
    assert_eq!(
        requests.len(),
        2,
        "one model call per response: {outcome:?}"
    );
    let failed = call_output(&requests[1], "call_r1").expect("the model was told the cell");
    let last = last_text(&requests[1], "call_r1");
    assert!(
        failed.contains("Script failed")
            && !failed.contains(&guard_message())
            && !failed.contains("the cell went on")
            && last == "[omitted 1 text items ...]",
        "the text flood failed, and nanocode's visible result dropped the guard's message; its \
         last text is: {last}"
    );
    let flood = output_texts(&requests[1], "call_r1")
        .into_iter()
        .find_map(|text| truncated_bytes(&text))
        .unwrap_or_else(|| panic!("nanocode truncated the flood's text: {failed:.400}"));
    assert!(
        flood.abs_diff(LIMIT_TEXT) < BYTES_PER_TOKEN,
        "the text that costs the output limit reached nanocode whole: {flood} bytes against \
         {LIMIT_TEXT}"
    );
    assert_eq!(
        reports(&requests[1], "call_r1"),
        [guard_message()],
        "the model is handed the guard's report as an output of its own"
    );
    let TurnOutcome::Completed { response, .. } = &outcome else {
        panic!("a limit hit is a cell outcome, not a turn outcome: {outcome:?}");
    };
    assert_eq!(response, "DONE");
    assert_eq!(
        limits_recorded(session.as_mut()),
        ["output"],
        "the evidence records the output-limit hit once"
    );
    assert_eq!(
        observed.limits(),
        ["output"],
        "one `code_mode_limit` progress observation, naming the output"
    );
    let close = session.close().await;
    assert!(close.is_confirmed(), "{close:?}");
}

/// **A heap hit after a text past nanocode's visible budget is told to the
/// model and recorded.** Under kata's limits the model's first cell emits one
/// 60,000-byte text, then allocates past the 256 MiB heap limit. The next
/// request hands the model `Script failed` whose last text is `[omitted 1 text
/// items ...]`: the `Script error:` naming the out-of-memory error is the one
/// item dropped. The guard's report of the memory limit reaches the model as an
/// output of its own. The model's second cell makes the same allocation after
/// a 600-byte text: its result ends with QuickJS's out-of-memory error, and
/// the same report follows it. The evidence records one `CodeModeLimit{memory}`
/// per cell, and the progress sink one `code_mode_limit` per cell. The turn
/// completes.
///
/// **Would red if:** the guard sent no report for a heap hit (the first cell's
/// is told to no one), or the adapter read a hit off the visible result as
/// well as off the report (the second cell's recorded twice).
#[tokio::test]
async fn a_heap_hit_after_a_long_text_is_told_to_the_model_and_recorded() {
    install_code_mode_limits();
    let mock = MockProvider::start(vec![
        code_reply("r1", LONG_TEXT_THEN_ALLOCATE, usage(1, 0, 1)),
        code_reply("r2", SHORT_TEXT_THEN_ALLOCATE, usage(1, 0, 1)),
        message_reply("r3", "DONE", usage(1, 0, 1)),
    ])
    .await;
    let observed = std::sync::Arc::new(Observations::default());
    let (mut session, _witness) = open_scoped(
        &openai(&mock.url, None),
        DoubleConfig::default(),
        scope().with_progress(observed.clone()),
    );

    let outcome = turn(session.as_mut(), &openai_prompt("allocate after text")).await;

    let requests = mock.requests();
    assert_eq!(
        requests.len(),
        3,
        "one model call per response: {outcome:?}"
    );
    let hidden = call_output(&requests[1], "call_r1").expect("the model was told the first cell");
    let hidden_last = last_text(&requests[1], "call_r1");
    assert!(
        hidden.contains("Script failed")
            && !hidden.contains("out of memory")
            && !hidden.contains("allocated")
            && hidden_last == "[omitted 1 text items ...]",
        "the first cell failed and its script error was dropped; its last text is: {hidden_last}"
    );
    assert_eq!(
        reports(&requests[1], "call_r1"),
        [memory_report()],
        "the model is handed the guard's report of the first cell's heap hit"
    );
    let visible = call_output(&requests[2], "call_r2").expect("the model was told the second cell");
    let visible_last = last_text(&requests[2], "call_r2");
    assert!(
        visible.contains("Script failed")
            && visible_last.starts_with("Script error:\n")
            && visible_last.contains("out of memory"),
        "the same allocation after a short text names the heap hit; its last text is: \
         {visible_last}"
    );
    assert_eq!(
        reports(&requests[2], "call_r2"),
        [memory_report()],
        "the second cell's report follows its result"
    );
    let TurnOutcome::Completed { response, .. } = &outcome else {
        panic!("a limit hit is a cell outcome, not a turn outcome: {outcome:?}");
    };
    assert_eq!(response, "DONE");
    assert_eq!(
        limits_recorded(session.as_mut()),
        ["memory", "memory"],
        "the evidence records each cell's heap hit once"
    );
    assert_eq!(
        observed.limits(),
        ["memory", "memory"],
        "one `code_mode_limit` progress observation per cell"
    );
    let close = session.close().await;
    assert!(close.is_confirmed(), "{close:?}");
}

/// **MEASURED RESIDUAL: on the Messages kind a text flood's output-limit hit
/// is recorded, and the model is not told why the cell failed.** The same
/// flood under kata's limits, on the Anthropic kind: the next request's
/// `tool_result` for the cell is an error whose visible blocks keep the
/// header and the middle-truncated flood, then `[<n> more text blocks
/// omitted]`. The dropped blocks are the cell's `Script error:` and the
/// guard's report, which nanocode's Messages backend appends to the same
/// result: neither reaches the model. The guard's notification still reaches
/// the adapter as a `tool.notification` event, so the evidence records one
/// `CodeModeLimit{output}` and the progress sink one `code_mode_limit`; the
/// turn goes on.
///
/// **Would red if:** the adapter read the hit off the visible result (nothing
/// recorded), or nanocode's Messages backend began to deliver a notification
/// outside the truncated result (the report reaches the model: restate the
/// residual).
#[tokio::test]
async fn a_text_flood_on_the_messages_kind_is_recorded_though_its_report_is_dropped() {
    install_code_mode_limits();
    let mock = MockProvider::start(vec![
        claude_code_reply("r1", &text_flood()),
        claude_text_reply("DONE"),
    ])
    .await;
    let observed = std::sync::Arc::new(Observations::default());
    let (mut session, _witness) = open_scoped(
        &anthropic(&mock.url),
        DoubleConfig::default(),
        scope().with_progress(observed.clone()),
    );

    let outcome = turn(session.as_mut(), &anthropic_prompt("flood text")).await;

    let requests = mock.requests();
    assert_eq!(
        requests.len(),
        2,
        "one model call per response: {outcome:?}"
    );
    let texts = tool_result_texts(&requests[1], "toolu_r1").expect("the model was told the cell");
    assert_dropped_past_the_budget(&texts, &guard_message());
    let TurnOutcome::Completed { response, .. } = &outcome else {
        panic!("a limit hit is a cell outcome, not a turn outcome: {outcome:?}");
    };
    assert_eq!(response, "DONE");
    assert_eq!(
        limits_recorded(session.as_mut()),
        ["output"],
        "the evidence records the output-limit hit once"
    );
    assert_eq!(observed.limits(), ["output"]);
    let close = session.close().await;
    assert!(close.is_confirmed(), "{close:?}");
}

/// **On the Messages kind a heap hit is recorded whatever the cell emitted,
/// and its report told to the model only while the result's text before it
/// leaves room in the visible budget (MEASURED RESIDUAL).** The two allocating
/// cells on the Anthropic kind: after the 60,000-byte text the `tool_result`'s
/// visible blocks end with `[<n> more text blocks omitted]`, the cell's
/// out-of-memory error and the guard's report among the dropped; after the
/// 600-byte text, which leaves the header, the text and the error well inside
/// the budget, they end with the cell's `Script error:` naming the
/// out-of-memory error, then the guard's report. The evidence records one
/// `CodeModeLimit{memory}` per cell either way. A cell whose own text fits the
/// budget but leaves the error no room loses both
/// (`a_cell_text_under_the_budget_still_loses_the_reason_and_on_messages_the_report`).
///
/// **Would red if:** the guard sent no report for a heap hit, or the adapter
/// did not read the Messages kind's `tool.notification` (nothing recorded).
#[tokio::test]
async fn a_heap_hit_on_the_messages_kind_is_recorded_and_told_within_the_budget() {
    install_code_mode_limits();
    let mock = MockProvider::start(vec![
        claude_code_reply("r1", LONG_TEXT_THEN_ALLOCATE),
        claude_code_reply("r2", SHORT_TEXT_THEN_ALLOCATE),
        claude_text_reply("DONE"),
    ])
    .await;
    let observed = std::sync::Arc::new(Observations::default());
    let (mut session, _witness) = open_scoped(
        &anthropic(&mock.url),
        DoubleConfig::default(),
        scope().with_progress(observed.clone()),
    );

    let outcome = turn(session.as_mut(), &anthropic_prompt("allocate after text")).await;

    let requests = mock.requests();
    assert_eq!(
        requests.len(),
        3,
        "one model call per response: {outcome:?}"
    );
    let hidden = tool_result_texts(&requests[1], "toolu_r1").expect("the model was told cell 1");
    assert_dropped_past_the_budget(&hidden, &memory_report());
    let visible = tool_result_texts(&requests[2], "toolu_r2").expect("the model was told cell 2");
    let [.., error, report] = visible.as_slice() else {
        panic!("the second cell's result has its error and the report: {visible:?}");
    };
    assert!(
        error.starts_with("Script error:\n") && error.contains("out of memory"),
        "the second cell's error names the heap hit: {error}"
    );
    assert_eq!(*report, memory_report(), "the guard's report follows it");
    let TurnOutcome::Completed { response, .. } = &outcome else {
        panic!("a limit hit is a cell outcome, not a turn outcome: {outcome:?}");
    };
    assert_eq!(response, "DONE");
    assert_eq!(
        limits_recorded(session.as_mut()),
        ["memory", "memory"],
        "the evidence records each cell's heap hit once"
    );
    assert_eq!(observed.limits(), ["memory", "memory"]);
    let close = session.close().await;
    assert!(close.is_confirmed(), "{close:?}");
}

/// **A stack hit after a text past nanocode's visible budget is told to the
/// model and recorded, on the Responses kind; recorded and untold on the
/// Messages kind (MEASURED RESIDUAL).** Under kata's limits a cell emits one
/// 60,000-byte text, then recurses until QuickJS's stack limit throws. On the
/// OpenAI kind the next request's result for it ends with `[omitted 1 text
/// items ...]`, the `RangeError` dropped, and the guard's report of the stack
/// limit follows as an output of its own; on the Anthropic kind the result's
/// visible blocks end with `[<n> more text blocks omitted]`, the error and the
/// report among the dropped. Each kind's evidence records one
/// `CodeModeLimit{stack}`.
///
/// **Would red if:** the guard sent no report for a stack hit, or the adapter
/// read the hit off the visible result.
#[tokio::test]
async fn a_stack_hit_after_a_long_text_is_recorded_on_both_kinds_and_told_on_the_responses_kind() {
    install_code_mode_limits();
    let openai_mock = MockProvider::start(vec![
        code_reply("r1", LONG_TEXT_THEN_RECURSE, usage(1, 0, 1)),
        message_reply("r2", "DONE", usage(1, 0, 1)),
    ])
    .await;
    let (mut session, _witness) = open_scoped(
        &openai(&openai_mock.url, None),
        DoubleConfig::default(),
        scope(),
    );
    let outcome = turn(session.as_mut(), &openai_prompt("write, then recurse")).await;
    let requests = openai_mock.requests();
    assert_eq!(
        requests.len(),
        2,
        "one model call per response: {outcome:?}"
    );
    let failed = call_output(&requests[1], "call_r1").expect("the model was told the cell");
    assert!(
        failed.contains("Script failed")
            && !failed.contains("Maximum call stack size exceeded")
            && last_text(&requests[1], "call_r1") == "[omitted 1 text items ...]",
        "the cell failed and its script error was dropped: {}",
        last_text(&requests[1], "call_r1")
    );
    assert_eq!(reports(&requests[1], "call_r1"), [stack_report()]);
    assert!(
        matches!(outcome, TurnOutcome::Completed { .. }),
        "{outcome:?}"
    );
    assert_eq!(limits_recorded(session.as_mut()), ["stack"]);
    let close = session.close().await;
    assert!(close.is_confirmed(), "{close:?}");

    let anthropic_mock = MockProvider::start(vec![
        claude_code_reply("r1", LONG_TEXT_THEN_RECURSE),
        claude_text_reply("DONE"),
    ])
    .await;
    let (mut session, _witness) = open_scoped(
        &anthropic(&anthropic_mock.url),
        DoubleConfig::default(),
        scope(),
    );
    let outcome = turn(session.as_mut(), &anthropic_prompt("write, then recurse")).await;
    let requests = anthropic_mock.requests();
    assert_eq!(
        requests.len(),
        2,
        "one model call per response: {outcome:?}"
    );
    let texts = tool_result_texts(&requests[1], "toolu_r1").expect("the model was told the cell");
    assert_dropped_past_the_budget(&texts, &stack_report());
    assert!(
        !texts
            .iter()
            .any(|text| text.contains("Maximum call stack size exceeded")),
        "the stack error is dropped too"
    );
    assert!(
        matches!(outcome, TurnOutcome::Completed { .. }),
        "{outcome:?}"
    );
    assert_eq!(limits_recorded(session.as_mut()), ["stack"]);
    let close = session.close().await;
    assert!(close.is_confirmed(), "{close:?}");
}

/// A cell that fills the heap with small objects until QuickJS, unable to
/// allocate even its own out-of-memory error, throws a bare `null`, which the
/// bootstrap cannot report either. It asks to yield only after 300 s, past
/// the turn's `TURN_BOUND`, so its own end answers the model: how long a
/// 256 MiB fill takes is the host's (MEASURED under a 5% CPU quota: past
/// nanocode's 10 s default yield, which told the model `Script running`).
const SMALL_OBJECT_FLOOD: &str = "// @exec: {\"yield_time_ms\": 300000}\n\
     const objects = [];\nfor (;;) objects.push({ i: objects.length });";

/// **A heap hit QuickJS throws as a bare `null` is told to the model and
/// recorded, on both kinds.** Under kata's 256 MiB heap limit the model's cell
/// fills the heap with small objects. The engine's own text for that failure,
/// `embedded QuickJS execution rejected: Exception generated by quickjs:
/// Null"null"`, names no limit (MEASURED). The guard reads the heap of a cell
/// that fails outside the bootstrap's report, finds it exhausted, and names
/// the memory limit: the cell's error is the guard's memory message, its
/// report follows (on the Responses kind as an output of its own, on the
/// Messages kind as the result's last text block), the evidence records one
/// `CodeModeLimit{memory}` per kind, and the turn completes. What the cells
/// after such a hit see is
/// `the_cells_after_heap_hits_run_with_half_the_heap_on_both_kinds`.
///
/// **Would red if:** the guard read such a failure for its text only.
#[tokio::test]
async fn a_heap_hit_quickjs_throws_as_null_is_told_and_recorded_on_both_kinds() {
    install_code_mode_limits();
    let error = format!("Script error:\n{}", memory_report());

    let openai_mock = MockProvider::start(vec![
        code_reply("r1", SMALL_OBJECT_FLOOD, usage(1, 0, 1)),
        message_reply("r2", "DONE", usage(1, 0, 1)),
    ])
    .await;
    let (mut session, _witness) = open_scoped(
        &openai(&openai_mock.url, None),
        DoubleConfig::default(),
        scope(),
    );
    let outcome = turn(session.as_mut(), &openai_prompt("fill the heap")).await;
    let requests = openai_mock.requests();
    assert_eq!(
        requests.len(),
        2,
        "one model call per response: {outcome:?}"
    );
    let failed = call_output(&requests[1], "call_r1").expect("the model was told the cell");
    assert!(
        failed.contains("Script failed") && last_text(&requests[1], "call_r1") == error,
        "the cell's error is the guard's memory message: {failed:.400}"
    );
    assert_eq!(reports(&requests[1], "call_r1"), [memory_report()]);
    let TurnOutcome::Completed { response, .. } = &outcome else {
        panic!("a limit hit is a cell outcome, not a turn outcome: {outcome:?}");
    };
    assert_eq!(response, "DONE");
    assert_eq!(limits_recorded(session.as_mut()), ["memory"]);
    let close = session.close().await;
    assert!(close.is_confirmed(), "{close:?}");

    let anthropic_mock = MockProvider::start(vec![
        claude_code_reply("r1", SMALL_OBJECT_FLOOD),
        claude_text_reply("DONE"),
    ])
    .await;
    let (mut session, _witness) = open_scoped(
        &anthropic(&anthropic_mock.url),
        DoubleConfig::default(),
        scope(),
    );
    let outcome = turn(session.as_mut(), &anthropic_prompt("fill the heap")).await;
    let requests = anthropic_mock.requests();
    assert_eq!(
        requests.len(),
        2,
        "one model call per response: {outcome:?}"
    );
    let texts = tool_result_texts(&requests[1], "toolu_r1").expect("the model was told the cell");
    assert!(
        texts
            .first()
            .is_some_and(|header| header.starts_with("Script failed"))
            && texts.ends_with(&[error, memory_report()]),
        "the cell's error is the guard's memory message, and its report follows: {texts:?}"
    );
    let TurnOutcome::Completed { response, .. } = &outcome else {
        panic!("a limit hit is a cell outcome, not a turn outcome: {outcome:?}");
    };
    assert_eq!(response, "DONE");
    assert_eq!(limits_recorded(session.as_mut()), ["memory"]);
    let close = session.close().await;
    assert!(close.is_confirmed(), "{close:?}");
}

/// A cell that allocates 128 MiB of filled typed arrays, half of kata's heap
/// limit, and says so; like [`SMALL_OBJECT_FLOOD`], it yields only at its end.
const HALF_THE_HEAP: &str = "// @exec: {\"yield_time_ms\": 300000}\n\
     const chunks = [];\n\
     for (let i = 0; i < 128; i++) chunks.push(new Uint8Array(1 << 20).fill(1));\n\
     text(`allocated ${chunks.length} MiB`);";

/// What the model's cells are, in order: a heap flood QuickJS throws as a bare
/// `null`, a cell allocating half the heap, a trivial cell, then the flood and
/// the allocation again.
const AFTER_HEAP_HITS: [&str; 5] = [
    SMALL_OBJECT_FLOOD,
    HALF_THE_HEAP,
    "text(\"the next cell ran\");",
    SMALL_OBJECT_FLOOD,
    HALF_THE_HEAP,
];

/// The text each of [`AFTER_HEAP_HITS`] tells the model, the floods' being
/// the guard's memory message.
fn told_after_heap_hits() -> [String; 5] {
    let error = format!("Script error:\n{}", memory_report());
    [
        error.clone(),
        "allocated 128 MiB".to_owned(),
        "the next cell ran".to_owned(),
        error,
        "allocated 128 MiB".to_owned(),
    ]
}

/// **The cells after heap hits run, with the heap a hit filled, through the
/// adapter, on both kinds.** On one session under kata's limits the model's
/// first cell floods the heap with small objects (the hit QuickJS throws as a
/// bare `null`); its second allocates 128 MiB, half the heap limit; its third
/// writes a text; its fourth floods the heap again and its fifth allocates
/// 128 MiB again. Each request after a flood hands the model that cell's
/// failed result ending with the guard's memory message; each after another
/// cell, that cell's completed result with its text; the turn completes and
/// its evidence records two `CodeModeLimit{memory}`. The process these cells
/// run in is the one hosting the worker, a `kata-worker` node.
///
/// MEASURED before each cell had a runtime of its own: on both kinds every
/// cell after the flood (seven, in a lane probe) failed to the model with
/// `failed to create a fresh embedded QuickJS context: Allocation failed while
/// creating object`; the engine-level twin
/// (`code_mode_limits::heap_hits_end_no_process`) saw the third abort the
/// process instead, by SIGABRT on QuickJS's `gc_decref` assertion, under a heap
/// left with other headroom.
///
/// **Would red if:** a cell ran in the runtime a heap hit filled.
#[tokio::test]
async fn the_cells_after_heap_hits_run_with_half_the_heap_on_both_kinds() {
    install_code_mode_limits();
    let told = told_after_heap_hits();

    let mut script: Vec<_> = (1..)
        .zip(AFTER_HEAP_HITS)
        .map(|(cell, source)| code_reply(&format!("r{cell}"), source, usage(1, 0, 1)))
        .collect();
    script.push(message_reply("r6", "DONE", usage(1, 0, 1)));
    let openai_mock = MockProvider::start(script).await;
    let (mut session, _witness) = open_scoped(
        &openai(&openai_mock.url, None),
        DoubleConfig::default(),
        scope(),
    );
    let outcome = turn(
        session.as_mut(),
        &openai_prompt("fill the heap, then go on"),
    )
    .await;
    let requests = openai_mock.requests();
    assert_eq!(
        requests.len(),
        6,
        "one model call per response: {outcome:?}"
    );
    for (cell, told) in (1..).zip(&told) {
        let call = format!("call_r{cell}");
        let result = call_output(&requests[cell], &call).expect("the model was told the cell");
        let failed = result.contains("Script failed");
        assert!(
            failed == told.starts_with("Script error:")
                && last_text(&requests[cell], &call) == *told,
            "cell {cell} told the model {told:?}: {result:.400}"
        );
    }
    let TurnOutcome::Completed { response, .. } = &outcome else {
        panic!("a limit hit is a cell outcome, not a turn outcome: {outcome:?}");
    };
    assert_eq!(response, "DONE");
    assert_eq!(limits_recorded(session.as_mut()), ["memory", "memory"]);
    let close = session.close().await;
    assert!(close.is_confirmed(), "{close:?}");

    let mut script: Vec<_> = (1..)
        .zip(AFTER_HEAP_HITS)
        .map(|(cell, source)| claude_code_reply(&format!("r{cell}"), source))
        .collect();
    script.push(claude_text_reply("DONE"));
    let anthropic_mock = MockProvider::start(script).await;
    let (mut session, _witness) = open_scoped(
        &anthropic(&anthropic_mock.url),
        DoubleConfig::default(),
        scope(),
    );
    let outcome = turn(
        session.as_mut(),
        &anthropic_prompt("fill the heap, then go on"),
    )
    .await;
    let requests = anthropic_mock.requests();
    assert_eq!(
        requests.len(),
        6,
        "one model call per response: {outcome:?}"
    );
    for (cell, told) in (1..).zip(&told) {
        let texts = tool_result_texts(&requests[cell], &format!("toolu_r{cell}"))
            .expect("the model was told the cell");
        let header = if told.starts_with("Script error:") {
            "Script failed"
        } else {
            "Script completed"
        };
        assert!(
            texts.first().is_some_and(|first| first.starts_with(header)) && texts.contains(told),
            "cell {cell} told the model {told:?}: {texts:?}"
        );
    }
    let TurnOutcome::Completed { response, .. } = &outcome else {
        panic!("a limit hit is a cell outcome, not a turn outcome: {outcome:?}");
    };
    assert_eq!(response, "DONE");
    assert_eq!(limits_recorded(session.as_mut()), ["memory", "memory"]);
    let close = session.close().await;
    assert!(close.is_confirmed(), "{close:?}");
}

/// A cell that emits one 47,900-byte text, 11,975 of nanocode's tokens and so
/// UNDER its 12,000-token visible budget alone, then allocates past kata's
/// heap limit.
const UNDER_BUDGET_TEXT_THEN_ALLOCATE: &str = "text(\"x\".repeat(47900));\n\
     const chunks = [];\n\
     for (let i = 0; i < 384; i++) chunks.push(new Uint8Array(1 << 20).fill(1));";

/// The bytes of the cell's one text.
const UNDER_BUDGET_TEXT: usize = 47_900;

const _: () = assert!(
    UNDER_BUDGET_TEXT.div_ceil(4) < 12_000,
    "the cell's own text fits nanocode's visible budget"
);

/// **MEASURED RESIDUAL: the visible budget counts the result's header and its
/// `Script error:` too, so a cell whose own text fits it can still lose its
/// error's reason, and, on the Messages kind, the report.** Under kata's limits
/// the cell emits 11,975 tokens of text, then hits the heap limit. Both kinds
/// keep the result's text items in order within 12,000 tokens: the header
/// (`Script failed`, its wall time and `Output:`), then the cell's text,
/// whole, which leaves the `Script error:` item fewer tokens than it holds, so
/// both middle-truncate it, past QuickJS's `out of memory`. On the Messages
/// kind no budget is left for the guard's report, the result's last text
/// item: it is dropped, and the result ends with `[1 more text blocks
/// omitted]`. On the Responses kind the report is an output of its own and
/// reaches the model. Each kind's evidence records one `CodeModeLimit{memory}`.
///
/// **Would red if:** nanocode's budget left the header or the error out of its
/// count (the error, or the Messages kind's report, reaches the model: restate
/// the residual), or the adapter read the hit off the visible result.
#[tokio::test]
async fn a_cell_text_under_the_budget_still_loses_the_reason_and_on_messages_the_report() {
    install_code_mode_limits();

    let openai_mock = MockProvider::start(vec![
        code_reply("r1", UNDER_BUDGET_TEXT_THEN_ALLOCATE, usage(1, 0, 1)),
        message_reply("r2", "DONE", usage(1, 0, 1)),
    ])
    .await;
    let (mut session, _witness) = open_scoped(
        &openai(&openai_mock.url, None),
        DoubleConfig::default(),
        scope(),
    );
    let outcome = turn(session.as_mut(), &openai_prompt("write, then allocate")).await;
    let requests = openai_mock.requests();
    assert_eq!(
        requests.len(),
        2,
        "one model call per response: {outcome:?}"
    );
    let texts = output_texts(&requests[1], "call_r1");
    let [header, text, error] = texts.as_slice() else {
        panic!("the result is its header, the cell's text and its error: {texts:.400?}");
    };
    assert!(
        header.starts_with("Script failed")
            && text.len() == UNDER_BUDGET_TEXT
            && error.starts_with("Script error:\n")
            && error.contains(" tokens truncated")
            && !error.contains("out of memory"),
        "the cell's text is kept whole and its error cut past its reason: {error}"
    );
    assert_eq!(
        reports(&requests[1], "call_r1"),
        [memory_report()],
        "the report reaches the model as an output of its own"
    );
    assert!(
        matches!(outcome, TurnOutcome::Completed { .. }),
        "{outcome:?}"
    );
    assert_eq!(limits_recorded(session.as_mut()), ["memory"]);
    let close = session.close().await;
    assert!(close.is_confirmed(), "{close:?}");

    let anthropic_mock = MockProvider::start(vec![
        claude_code_reply("r1", UNDER_BUDGET_TEXT_THEN_ALLOCATE),
        claude_text_reply("DONE"),
    ])
    .await;
    let (mut session, _witness) = open_scoped(
        &anthropic(&anthropic_mock.url),
        DoubleConfig::default(),
        scope(),
    );
    let outcome = turn(session.as_mut(), &anthropic_prompt("write, then allocate")).await;
    let requests = anthropic_mock.requests();
    assert_eq!(
        requests.len(),
        2,
        "one model call per response: {outcome:?}"
    );
    let texts = tool_result_texts(&requests[1], "toolu_r1").expect("the model was told the cell");
    let [header, text, error, omitted] = texts.as_slice() else {
        panic!("the result is its header, text, cut error and nanocode's count: {texts:.400?}");
    };
    assert!(
        header.starts_with("Script failed")
            && text.len() == UNDER_BUDGET_TEXT
            && error.starts_with("Script error:\n")
            && error.contains(" tokens truncated")
            && !error.contains("out of memory")
            && omitted == "[1 more text blocks omitted]",
        "the cell's text is kept whole, its error cut past its reason, and the report \
         dropped: {error} / {omitted}"
    );
    assert!(
        matches!(outcome, TurnOutcome::Completed { .. }),
        "{outcome:?}"
    );
    assert_eq!(limits_recorded(session.as_mut()), ["memory"]);
    let close = session.close().await;
    assert!(close.is_confirmed(), "{close:?}");
}

/// A cell that emits a 60,000-byte text and 1,800 notifications of 4 KiB,
/// 7.4 MB inside kata's 8 MiB output limit and far past any model's context
/// window, then allocates past kata's heap limit.
const NOTIFICATION_FLOOD_THEN_ALLOCATE: &str = "text(\"x\".repeat(60000));\n\
     for (let i = 0; i < 1800; i++) notify(\"n\".repeat(4096));\n\
     const chunks = [];\n\
     for (let i = 0; i < 384; i++) chunks.push(new Uint8Array(1 << 20).fill(1));";

const _: () = assert!(
    60_000 + 1_800 * 4_096 + 1_801 * CELL_EVENT_BYTES < CODE_MODE_LIMITS.cell_emitted_bytes,
    "the flood stays inside kata's output limit"
);

/// nanocode's text for a tool output it rewrote to fit the model's context.
const CONTEXT_PLACEHOLDER: &str = "Output exceeded the available model context and was truncated";

/// **MEASURED RESIDUAL: on the Responses kind the report reaches the model
/// unless nanocode compacts the turn's history first, which rewrites the
/// report.** A cell emits a long text and a notification flood, then hits the
/// heap limit; its outputs (the result, then each notification, the guard's
/// report last) push the turn's history past nanocode's auto-compact
/// threshold, so nanocode compacts before the model's next request. Its
/// compaction request rewrites tool outputs from the newest back to
/// `Output exceeded the available model context and was truncated` until the
/// history fits 95% of the model's context window: the call's last output, the
/// report, is the first rewritten, and the request carries no report. The
/// model's next request carries the compaction item in place of the history,
/// and no report either. The evidence records one `CodeModeLimit{memory}`, and
/// the turn completes.
///
/// **Would red if:** nanocode delivered the report where its compaction keeps
/// it (restate the residual), or the adapter read the hit off what the model
/// was shown (nothing recorded).
#[tokio::test]
async fn on_the_responses_kind_a_compaction_rewrites_the_report_and_the_record_stays() {
    install_code_mode_limits();
    let mock = MockProvider::start(vec![
        code_reply("r1", NOTIFICATION_FLOOD_THEN_ALLOCATE, usage(1, 0, 1)),
        compaction_reply("r2", usage(1, 0, 1)),
        message_reply("r3", "DONE", usage(1, 0, 1)),
    ])
    .await;
    let (mut session, _witness) =
        open_scoped(&openai(&mock.url, None), DoubleConfig::default(), scope());

    let outcome = turn(session.as_mut(), &openai_prompt("notify, then allocate")).await;

    let requests = mock.requests();
    assert_eq!(
        requests.len(),
        3,
        "the cell's call, the compaction, the model's next call: {outcome:?}"
    );
    let compacted = call_outputs(&requests[1], "call_r1");
    assert_eq!(
        compacted.last(),
        Some(&serde_json::Value::String(CONTEXT_PLACEHOLDER.to_owned())),
        "the compaction request rewrote the call's last output ({} outputs)",
        compacted.len()
    );
    assert!(
        compacted.len() == 1 + 1800 + 1,
        "the call's outputs are its result, each notification and the report: {}",
        compacted.len()
    );
    for (index, request) in requests.iter().enumerate().skip(1) {
        assert!(
            !request.to_string().contains(&memory_report()),
            "request {index} carries no report"
        );
    }
    let TurnOutcome::Completed { response, .. } = &outcome else {
        panic!("a limit hit is a cell outcome, not a turn outcome: {outcome:?}");
    };
    assert_eq!(response, "DONE");
    assert_eq!(limits_recorded(session.as_mut()), ["memory"]);
    let close = session.close().await;
    assert!(close.is_confirmed(), "{close:?}");
}

/// A Messages `tool_result` past nanocode's visible budget: an error result
/// (`Script failed`) whose texts end with nanocode's count of the blocks it
/// dropped, and in which `report` appears nowhere.
fn assert_dropped_past_the_budget(texts: &[String], report: &str) {
    let last = texts.last().map_or("", String::as_str);
    assert!(
        texts
            .first()
            .is_some_and(|header| header.starts_with("Script failed"))
            && last.starts_with('[')
            && last.ends_with(" more text blocks omitted]")
            && !texts.iter().any(|text| text.contains(report)),
        "the result ends with nanocode's count of the dropped blocks and carries no report \
         ({report}); its last text is: {last}"
    );
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

/// The notifications the Responses request handed the model as outputs of
/// their own for `call_id`: every output for the call after its result.
fn reports(request: &serde_json::Value, call_id: &str) -> Vec<String> {
    call_outputs(request, call_id)
        .into_iter()
        .skip(1)
        .map(|output| match output {
            serde_json::Value::String(text) => text,
            other => panic!("a notification is a bare text output: {other}"),
        })
        .collect()
}

/// The last text the request handed the model as the result of `call_id`: a
/// bare string output, or the `text` of its last content item that has one.
fn last_text(request: &serde_json::Value, call_id: &str) -> String {
    output_texts(request, call_id).pop().unwrap_or_default()
}

/// nanocode's bytes per token, by which it counts what it truncates.
const BYTES_PER_TOKEN: usize = 4;

/// The bytes a text stood for before nanocode middle-truncated it: the bytes
/// it kept plus the tokens its `…<n> tokens truncated…` marker names, to
/// within a token. `None` for a text nanocode did not truncate.
fn truncated_bytes(text: &str) -> Option<usize> {
    let (head, rest) = text.split_once('…')?;
    let (marker, tail) = rest.split_once('…')?;
    let tokens: usize = marker.strip_suffix(" tokens truncated")?.parse().ok()?;
    Some(head.len() + tail.len() + tokens * BYTES_PER_TOKEN)
}

/// The texts the request handed the model as the result of `call_id`, in
/// order: a bare string output, or the `text` of each content item that has
/// one.
fn output_texts(request: &serde_json::Value, call_id: &str) -> Vec<String> {
    let output = call_outputs(request, call_id)
        .into_iter()
        .next()
        .unwrap_or_else(|| panic!("the request carries {call_id}'s output"));
    match output {
        serde_json::Value::String(text) => vec![text],
        serde_json::Value::Array(items) => items
            .iter()
            .filter_map(|item| item["text"].as_str())
            .map(str::to_owned)
            .collect(),
        other => panic!("an output that is neither text nor content items: {other}"),
    }
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
