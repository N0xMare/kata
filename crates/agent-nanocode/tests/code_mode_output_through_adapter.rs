//! The Code Mode output limit, and the heap and stack limits hit after a long
//! text, seen through the nanocode adapter, under kata's own limits
//! (`CODE_MODE_LIMITS`: 8 MiB of output and 256 MiB of heap per cell, the
//! heap holding djs's call stack too, whose slot limit is djs's own),
//! installed by the seam the worker calls at start. The engine's limits are process-global, so this is a
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
//! it, its header (`Script failed`, its wall time and `Output:`) first, and
//! the two kinds bound it differently. Code Mode appends a failed cell's
//! `Script error:` item after the cell's own items.
//!
//! - The Responses kind: Code Mode itself bounds the cell's items to a
//!   10,000-token budget (4 bytes a token), the header outside it. When every
//!   item is text it joins them, the `Script error:` included, with newlines
//!   into ONE text and middle-truncates that, keeping its head and its tail
//!   (`Warning: truncated output (original token count: <n>)\nTotal output
//!   lines: <l>\n\n<head>…<m> tokens truncated…<tail>`), so the error, at
//!   the tail, survives any text before it. With a non-text item among them it
//!   keeps the text items in order within the budget, middle-truncates the one
//!   that crosses it, drops those after it and appends a count of them
//!   (`[omitted <n> text items ...]`); non-text items pass.
//! - The Messages kind: Code Mode applies no budget; the backend keeps the
//!   `tool_result`'s text blocks in order within 12,000 tokens (4 UTF-16
//!   units a token), the header counted, middle-truncates the block that
//!   crosses it, drops the blocks after it and appends a count of them
//!   (`[<n> more text blocks omitted]`). Once the header and the cell's text
//!   fill the budget the `Script error:` is dropped.
//!
//! The vendored guard ALSO sends its report of the limit as a Code Mode
//! notification of its own, just before the error. The Responses kind hands
//! the model each notification as an output of its own for the call, truncated
//! on its own, so the report reaches the model there unless nanocode compacts
//! the turn's history first, which rewrites the newest outputs, the report
//! first; the Messages kind appends it to the result as its last text block,
//! which the same truncation drops once the text before it takes the whole
//! budget. On both kinds nanocode emits the notification as a
//! `tool.notification` event, which the adapter records as `CodeModeLimit`
//! whatever the model was shown.

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
use kata_code_mode_host::CELL_EVENT_BYTES;
use kata_types::agent::SessionEvidenceEvent;
use mock_provider::{
    Gate, MockProvider, Reply, call_output, call_outputs, claude_code_reply, claude_text_reply,
    code_reply, compaction_reply, message_reply, tool_result_texts, usage,
};
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

/// The interpreter's report of a stack-limit hit, spelled here so one that
/// rewords it is red: djs's call-stack limit is its own slot count, so the
/// report names no size.
fn stack_report() -> String {
    "Code Mode cell exceeded its interpreter stack limit".to_owned()
}

/// djs's error past its call-stack limit.
const STACK_ERROR: &str = "RangeError: Maximum call stack size exceeded";

/// A cell that emits one 60,000-byte text, then recurses until djs's call-stack
/// limit throws, uncaught.
const LONG_TEXT_THEN_RECURSE: &str = "text(\"x\".repeat(60000));\n\
     function dive() { dive(); }\n\
     dive();";

const _: () = assert!(
    CODE_MODE_LIMITS.cell_emitted_bytes < 1024 * 64 * 1024,
    "the flood emits past kata's output limit"
);

/// A cell that emits one 60,000-byte text, past both kinds' visible budgets
/// alone, then allocates 384 MiB of filled typed arrays, past
/// kata's 256 MiB heap limit, and reports what it holds if it gets there.
const LONG_TEXT_THEN_ALLOCATE: &str = "text(\"x\".repeat(60000));\n\
     const chunks = [];\n\
     for (let i = 0; i < 384; i++) chunks.push(new Uint8Array(1 << 20).fill(1));\n\
     text(`allocated ${chunks.length} MiB`);";

/// The same allocation after a 600-byte text, which fits both visible budgets.
const SHORT_TEXT_THEN_ALLOCATE: &str = "text(\"x\".repeat(600));\n\
     const chunks = [];\n\
     for (let i = 0; i < 384; i++) chunks.push(new Uint8Array(1 << 20).fill(1));\n\
     text(`allocated ${chunks.length} MiB`);";

const _: () = assert!(
    CODE_MODE_LIMITS.memory_bytes < 384 << 20,
    "the cells allocate past kata's memory limit"
);

/// The cell's error the patched engine gives a heap hit, which no script can
/// catch.
const OUT_OF_MEMORY: &str = "Script error:\nScript stopped: the cell ran out of memory.";

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
/// closing text. The model's second cell then runs, its text reaches the third
/// request, and the turn completes.
///
/// The session's evidence records `CodeModeLimit{output}` once, and no
/// interpreter end, and its progress sink sees one `code_mode_limit`
/// observation naming the output: the interpreter's supervisor, which charges
/// what the cell emits on its own count, does not kill a cell the engine kept
/// within its limit. Each cell runs in an interpreter of its own, reaped when
/// its host drops: the kernel lists one interpreter process once it first
/// lists one (the model's second cell is held until then), and one other while
/// the second cell waits, the first one gone (the listing names unreaped
/// interpreters too).
///
/// **Would red if:** the supervisor charged a cell more than the engine does
/// (it kills the interpreter: its report is told and an interpreter end
/// recorded), the guard sent no report (no output of its own, nothing
/// recorded), or a cell's interpreter outlived its host (two listed).
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
        next_running.len(),
        1,
        "one interpreter while the second cell waits: {next_running:?}"
    );
    assert!(
        flooding.is_disjoint(&next_running),
        "the first cell's interpreter outlived its host: {flooding:?} {next_running:?}"
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

/// **A TEXT flood past the output limit is told to the model and recorded.**
/// Under kata's 8 MiB limit a cell emits one text that costs exactly the
/// limit, then a 1-byte text: the guard accepts the first and fails the cell
/// on the second. On the Responses kind nanocode joins the flood and the
/// cell's `Script error:` into one text and middle-truncates it to its
/// 10,000-token budget, keeping the head and the tail, and the tail is the
/// error naming the limit. MEASURED, the result: its header, then `Warning:
/// truncated output (original token count: 2097105)\nTotal output lines:
/// 3\n\n`, the flood's head, `…2087105 tokens truncated…`, its tail and
/// `\nScript error:\nCode Mode cell output exceeded its 8388608-byte limit`.
/// The guard's report follows as an output of its own for the call. The
/// evidence records one `CodeModeLimit{output}`, the progress sink one
/// `code_mode_limit`, and the turn goes on.
///
/// The failure is the output limit's: the original token count nanocode
/// names is, exactly, that of the text that costs the limit, a newline and the
/// error (nanocode's 4 bytes a token, rounded up), so that text reached
/// nanocode whole and nothing after it did; and the cell never reaches its
/// closing text. That the limit refuses the very next byte is the engine's
/// own cell's
/// (`code_mode_limits::the_output_limit_admits_its_last_byte_and_refuses_the_next`):
/// the 1-byte text here costs an event too, so it crosses by more than a byte.
///
/// **Would red if:** nanocode's truncation dropped or cut the error again (the
/// text no longer ends with it: restate what the model is told), the guard
/// sent no report of its own (no output of its own, nothing recorded), the
/// adapter read the hit off the visible result as well as off the report
/// (recorded twice), or the guard charged a text more than its bytes and one
/// event (the first text fails the cell and never reaches nanocode: the token
/// count moves).
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
    let error = format!("Script error:\n{}", guard_message());
    let texts = output_texts(&requests[1], "call_r1");
    let [header, truncated] = texts.as_slice() else {
        panic!("the result is its header and one truncated text: {texts:.400?}");
    };
    let original_tokens = (LIMIT_TEXT + 1 + error.len()).div_ceil(BYTES_PER_TOKEN);
    assert!(
        header.starts_with("Script failed")
            && truncated.starts_with(&format!(
                "Warning: truncated output (original token count: {original_tokens})\n\
                 Total output lines: 3\n\n"
            ))
            && truncated.contains(" tokens truncated…")
            && truncated.ends_with(&format!("x\n{error}"))
            && !truncated.contains("the cell went on"),
        "the flood reached nanocode whole and its truncated text ends with the guard's error: \
         {:.200} … {}",
        truncated,
        &truncated[truncated.len().saturating_sub(200)..]
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
/// 60,000-byte text, then allocates past the 256 MiB heap limit. MEASURED, the
/// next request's result for it: its header, then one text, `Warning:
/// truncated output (original token count: 15015)\nTotal output lines:
/// 3\n\n`, the text's head, `…5015 tokens truncated…`, its tail and
/// `\nScript error:\nScript stopped: the cell ran out of memory.`: the
/// Responses kind's truncation keeps the error, at its tail. The guard's
/// report of the memory limit reaches the model as an output of its own. The
/// model's second cell makes the same allocation after a 600-byte text: its
/// result is its header, the text and the same error, untruncated, and the
/// same report follows it. The evidence records one `CodeModeLimit{memory}`
/// per cell, and the progress sink one `code_mode_limit` per cell. The turn
/// completes.
///
/// **Would red if:** nanocode's truncation dropped or cut the error again (the
/// first result no longer ends with it: restate what the model is told), the
/// guard sent no report for a heap hit (no output of its own, nothing
/// recorded), or the adapter read a hit off the visible result as well as off
/// the report (each cell's recorded twice).
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
    let long = output_texts(&requests[1], "call_r1");
    let [header, truncated] = long.as_slice() else {
        panic!("the first cell's result is its header and one truncated text: {long:.400?}");
    };
    assert!(
        header.starts_with("Script failed")
            && truncated.starts_with("Warning: truncated output (original token count: ")
            && truncated.contains(" tokens truncated…")
            && truncated.ends_with(&format!("x\n{OUT_OF_MEMORY}"))
            && !truncated.contains("allocated"),
        "the first cell failed and its truncated text ends with its error: {}",
        &truncated[truncated.len().saturating_sub(200)..]
    );
    assert_eq!(
        reports(&requests[1], "call_r1"),
        [memory_report()],
        "the model is handed the guard's report of the first cell's heap hit"
    );
    let short = output_texts(&requests[2], "call_r2");
    assert!(
        short.len() == 3
            && short[0].starts_with("Script failed")
            && short[1] == "x".repeat(600)
            && short[2] == OUT_OF_MEMORY,
        "the same allocation after a short text: its header, its text and its error: {short:?}"
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
/// flood under kata's limits, on the Anthropic kind, which does not join the
/// cell's texts: MEASURED, the next request's `tool_result` for the cell is an
/// error whose texts are its header, the flood middle-truncated (`…2085099
/// tokens truncated…`) and `[2 more text blocks omitted]`. The two dropped are
/// the cell's `Script error:` and the guard's report, which nanocode's
/// Messages backend appends to the same result: neither reaches the model.
/// The guard's notification still reaches the adapter as a
/// `tool.notification` event, so the evidence records one
/// `CodeModeLimit{output}` and the progress sink one `code_mode_limit`; the
/// turn goes on.
///
/// **Would red if:** the adapter read the hit off the visible result (nothing
/// recorded), or nanocode's Messages backend began to keep the error or
/// deliver the report outside the truncated result (the limit is named:
/// restate the residual).
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
/// texts are its header, the text middle-truncated and `[2 more text blocks
/// omitted]`, the cell's out-of-memory error and the guard's report the two
/// dropped; after the 600-byte text, which leaves the header, the text and the
/// error well inside the budget, they end with the cell's `Script
/// error:\nScript stopped: the cell ran out of memory.`, then the guard's
/// report. The evidence records one `CodeModeLimit{memory}` per cell either
/// way. A cell whose own text fits the budget but leaves the error too little
/// room loses the report
/// (`a_cell_text_under_the_budget_keeps_the_reason_and_on_messages_loses_the_report`).
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
    assert_eq!(
        *error, OUT_OF_MEMORY,
        "the second cell's error names the heap hit"
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
/// 60,000-byte text, then recurses until djs's call-stack limit throws. On the
/// OpenAI kind the next request's result for it is its header and one
/// truncated text whose tail is the cell's error, MEASURED: `…5083 tokens
/// truncated…`, the text's tail, then `\nScript error:\nRangeError: Maximum
/// call stack size exceeded` and ten `at dive (<input>:2:23)` frames; the
/// guard's report of the stack limit follows as an output of its own. On the
/// Anthropic kind the result's texts are its header, the text truncated and
/// `[2 more text blocks omitted]`, the error and the report the two dropped.
/// Each kind's evidence records one `CodeModeLimit{stack}`.
///
/// **Would red if:** the guard sent no report for a stack hit (no output of
/// its own, nothing recorded), the adapter read the hit off the visible result
/// as well as off the report (recorded twice on the Responses kind), or
/// nanocode's truncation dropped the error on the Responses kind or kept it on
/// the Messages kind (restate what the model is told).
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
    let texts = output_texts(&requests[1], "call_r1");
    let [header, truncated] = texts.as_slice() else {
        panic!("the result is its header and one truncated text: {texts:.400?}");
    };
    let error = truncated
        .rsplit_once("x\nScript error:\n")
        .map_or("", |(_, error)| error);
    assert!(
        header.starts_with("Script failed")
            && truncated.starts_with("Warning: truncated output (original token count: ")
            && truncated.contains(" tokens truncated…")
            && error.starts_with(&format!("{STACK_ERROR}\n    at dive (<input>:")),
        "the cell failed and its truncated text ends with its stack error: {}",
        &truncated[truncated.len().saturating_sub(600)..]
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
        !texts.iter().any(|text| text.contains(STACK_ERROR)),
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

/// A cell that fills the heap with small objects until djs's heap limit ends
/// it. It asks to yield only after 300 s, past the turn's `TURN_BOUND`, so its
/// own end answers the model: how long a 256 MiB fill takes is the host's
/// (MEASURED: about 7.5 s on the lane's host; under a 5% CPU quota it once ran
/// past nanocode's default yield, which told the model `Script running`).
const SMALL_OBJECT_FLOOD: &str = "// @exec: {\"yield_time_ms\": 300000}\n\
     const objects = [];\nfor (;;) objects.push({ i: objects.length });";

/// [`SMALL_OBJECT_FLOOD`] inside a `try` whose `catch` writes what it caught,
/// and a closing text after it: the cell's text if a heap hit were catchable.
const CAUGHT_SMALL_OBJECT_FLOOD: &str = "// @exec: {\"yield_time_ms\": 300000}\n\
     const objects = [];\n\
     try { for (;;) objects.push({ i: objects.length }); }\n\
     catch (error) { text(`caught ${error}`); }\n\
     text(\"the cell went on\");";

/// **A heap hit is one no `catch` holds: the cell fails, the model is told,
/// and kata records it, on both kinds.** Under kata's 256 MiB heap limit the
/// model's cell fills the heap with small objects inside a `try` whose
/// `catch` would write what it caught. djs ends the cell on the limit past any
/// `catch`, and kata's patched engine reports the limit. MEASURED: on the
/// Responses kind the result is its header and `Script error:\nScript
/// stopped: the cell ran out of memory.`, and the guard's report an output of
/// its own; on the Messages kind the result's texts are its header, that error
/// and the report. Neither carries the `catch`'s text nor the closing text.
/// The evidence records one `CodeModeLimit{memory}` per kind, and the turn
/// completes. What the cells after such a hit see is
/// `the_cells_after_heap_hits_run_with_half_the_heap_on_both_kinds`.
///
/// **Would red if:** a heap hit reached the cell as an exception its `catch`
/// holds (the caught text, and the closing text, reach the model and the cell
/// completes), or the patched engine stopped reporting a heap hit (no report,
/// nothing recorded).
#[tokio::test]
async fn a_heap_hit_no_catch_holds_is_told_and_recorded_on_both_kinds() {
    install_code_mode_limits();

    let openai_mock = MockProvider::start(vec![
        code_reply("r1", CAUGHT_SMALL_OBJECT_FLOOD, usage(1, 0, 1)),
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
    let texts = output_texts(&requests[1], "call_r1");
    assert!(
        texts.len() == 2 && texts[0].starts_with("Script failed") && texts[1] == OUT_OF_MEMORY,
        "the cell failed on the heap limit, past its catch: {texts:?}"
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
        claude_code_reply("r1", CAUGHT_SMALL_OBJECT_FLOOD),
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
        texts.len() == 3
            && texts[0].starts_with("Script failed")
            && texts[1] == OUT_OF_MEMORY
            && texts[2] == memory_report(),
        "the cell failed on the heap limit, past its catch, and the report follows: {texts:?}"
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

/// What the model's cells are, in order: a heap flood, a cell allocating half
/// the heap, a trivial cell, then the flood and the allocation again.
const AFTER_HEAP_HITS: [&str; 5] = [
    SMALL_OBJECT_FLOOD,
    HALF_THE_HEAP,
    "text(\"the next cell ran\");",
    SMALL_OBJECT_FLOOD,
    HALF_THE_HEAP,
];

/// The text each of [`AFTER_HEAP_HITS`] tells the model, the floods' being
/// the patched engine's out-of-memory error.
fn told_after_heap_hits() -> [String; 5] {
    let error = OUT_OF_MEMORY.to_owned();
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
/// first cell floods the heap with small objects; its second allocates
/// 128 MiB, half the heap limit; its third writes a text; its fourth floods
/// the heap again and its fifth allocates 128 MiB again. Each request after a
/// flood hands the model that cell's failed result ending with `Script
/// error:\nScript stopped: the cell ran out of memory.`; each after another
/// cell, that cell's completed result with its text (`allocated 128 MiB`,
/// `the next cell ran`); the turn completes and its evidence records two
/// `CodeModeLimit{memory}`. Each cell runs in an interpreter process of its
/// own, with a heap of its own: the allocation after a flood starts with the
/// whole heap.
///
/// **Would red if:** a cell ran in the heap a hit filled (the 128 MiB
/// allocation fails on the limit), or a heap hit ended Code Mode for the turn
/// (the cells after it fail).
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

/// A cell that emits one 47,900-byte text, 11,975 tokens at 4 bytes a token
/// and so UNDER the Messages kind's 12,000-token visible budget alone (past the
/// Responses kind's 10,000), then allocates past kata's heap limit.
const UNDER_BUDGET_TEXT_THEN_ALLOCATE: &str = "text(\"x\".repeat(47900));\n\
     const chunks = [];\n\
     for (let i = 0; i < 384; i++) chunks.push(new Uint8Array(1 << 20).fill(1));";

/// The bytes of the cell's one text.
const UNDER_BUDGET_TEXT: usize = 47_900;

const _: () = assert!(
    UNDER_BUDGET_TEXT.div_ceil(4) < 12_000,
    "the cell's own text fits the Messages kind's visible budget"
);

/// **MEASURED RESIDUAL: on the Messages kind the visible budget counts the
/// result's header and its `Script error:` too, so a cell whose own text fits
/// it loses the report, and keeps only a cut of its error.** Under kata's
/// limits the cell emits 11,975 tokens of text, then hits the heap limit. The
/// Messages kind keeps the result's text blocks in order within 12,000 tokens:
/// the header (`Script failed`, its wall time and `Output:`), then the cell's
/// text, whole, which leaves the `Script error:` block fewer tokens than it
/// holds, so it is middle-truncated; its reason is its tail, so it survives
/// the cut (MEASURED: `Script error:\nScript stopped…1 tokens truncated… the
/// cell ran out of memory.`). No budget is left for the guard's report, the
/// result's last block: it is dropped, and the result ends with `[1 more text
/// blocks omitted]`. On the Responses kind the header is outside the budget
/// and the cell's text and error are one text truncated to 10,000 tokens,
/// head and tail: MEASURED, its header, then `Warning: truncated output
/// (original token count: 11990)\nTotal output lines: 3\n\n`, the text's
/// head, `…1990 tokens truncated…`, its tail and the whole error; the report
/// is an output of its own and reaches the model. Each kind's evidence records
/// one `CodeModeLimit{memory}`.
///
/// **Would red if:** nanocode's Messages budget left the header or the error
/// out of its count (the report reaches the model: restate the residual), the
/// Responses kind's truncation dropped or cut the error, or the adapter read
/// the hit off the visible result as well as off the report (recorded twice
/// on the Responses kind).
#[tokio::test]
async fn a_cell_text_under_the_budget_keeps_the_reason_and_on_messages_loses_the_report() {
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
    let [header, truncated] = texts.as_slice() else {
        panic!("the result is its header and one truncated text: {texts:.400?}");
    };
    let original_tokens = (UNDER_BUDGET_TEXT + 1 + OUT_OF_MEMORY.len()).div_ceil(BYTES_PER_TOKEN);
    assert!(
        header.starts_with("Script failed")
            && truncated.starts_with(&format!(
                "Warning: truncated output (original token count: {original_tokens})\n"
            ))
            && truncated.contains(" tokens truncated…")
            && truncated.ends_with(&format!("x\n{OUT_OF_MEMORY}")),
        "the cell's text and error are one truncated text ending with the whole error: {}",
        &truncated[truncated.len().saturating_sub(200)..]
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
            && error.starts_with("Script error:\nScript stopped")
            && error.contains(" tokens truncated…")
            && error.ends_with(" the cell ran out of memory.")
            && omitted == "[1 more text blocks omitted]",
        "the cell's text is kept whole, its error cut keeping its reason, and the report \
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
/// (`Script failed`) whose texts are its header, the cell's text truncated and
/// nanocode's count of the two blocks it dropped (the cell's error and the
/// guard's report), and in which `report` appears nowhere.
fn assert_dropped_past_the_budget(texts: &[String], report: &str) {
    let last = texts.last().map_or("", String::as_str);
    assert!(
        texts.len() == 3
            && texts[0].starts_with("Script failed")
            && texts[1].contains(" tokens truncated…")
            && last == "[2 more text blocks omitted]"
            && !texts.iter().any(|text| text.contains(report)),
        "the result is its header, its truncated text and nanocode's count of the two dropped \
         blocks, and carries no report ({report}); it has {} texts, the last: {last}",
        texts.len()
    );
}

/// The limits the session's evidence records, in order, and any interpreter
/// end it records among them (`interpreter ended by <signal>`), so a cell that
/// expects limits alone is red on an end.
fn limits_recorded(session: &mut dyn AgentSession) -> Vec<String> {
    session
        .take_evidence()
        .events
        .into_iter()
        .filter_map(|event| match event {
            SessionEvidenceEvent::CodeModeLimit { which } => Some(which.to_string()),
            SessionEvidenceEvent::CodeModeInterpreterEnded { signal } => Some(format!(
                "interpreter ended by {}",
                signal.as_deref().unwrap_or("exit")
            )),
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

/// nanocode's bytes per token on the Responses kind, by which it counts what
/// it truncates.
const BYTES_PER_TOKEN: usize = 4;

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
