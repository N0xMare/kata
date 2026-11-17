//! The Code Mode interpreter's stack limit against the thread stack it runs on,
//! seen through the nanocode adapter. QuickJS checks its own stack against
//! `NativeLimits::max_stack_bytes`; nothing checks the native frames around it,
//! so a `thread_stack_bytes` without headroom over that limit lets a deep
//! recursion overflow the QuickJS thread's stack, and Rust's overflow handler
//! aborts the process that thread runs in: with kata's installer, the cell's
//! interpreter process, never the main or the worker daemon. The children
//! below install their limits through the engine alone, so their QuickJS
//! thread runs in the child itself, the one an interpreter process runs.
//!
//! The cell recurses twice, each time until QuickJS's limit throws. First
//! through `Array.prototype.sort`'s comparator: each level is QuickJS's native
//! sort calling back into JavaScript, the widest levels measured. Then through
//! a host call at every level: the cell's `setTimeout` delay is an object whose
//! `valueOf` calls `setTimeout` again, so each level is the bootstrap's
//! wrapper, the engine's native `__nanocodeSetTimeout` (Rust, unchecked), and
//! QuickJS's numeric coercion calling back into JavaScript. It is the one
//! host-call shape that re-enters the interpreter from Rust (the other host
//! functions take strings, which rquickjs does not coerce). A thread stack the
//! cell survives on is one both recursions survive on, so the search below
//! measures the wider of the two. It is a bound for these shapes, not for every
//! recursion a cell can write.
//!
//! The setter is process-wide and once-only, so the cells under a shrunk thread
//! stack run as CHILDREN: this binary re-execs itself to run the turn cell
//! alone with `THREAD_STACK_ENV` naming the child's thread stack. Without it the
//! turn cell installs kata's own limits through the worker's installer.
//!
//! The witnesses do not share the adapter's code: the mock's log of the request
//! bodies it received (what the model was told), the kernel's account of this
//! process's interpreter processes, and the kernel's exit status of the child.

#[path = "fixtures/mock_provider.rs"]
#[allow(dead_code)]
mod mock_provider;
#[path = "fixtures/openai_turn.rs"]
#[allow(dead_code)]
mod openai_turn;
#[path = "fixtures/quickjs_threads.rs"]
mod quickjs_threads;
#[path = "fixtures/toolhost_double.rs"]
#[allow(dead_code)]
mod toolhost_double;

use std::os::unix::process::ExitStatusExt;
use std::process::{Command, Output};
use std::time::Duration;

use kata_agent::adapter::TurnOutcome;
use kata_agent_nanocode::{CODE_MODE_LIMITS, install_code_mode_limits};
use mock_provider::{
    Gate, MockProvider, Reply, call_output, call_outputs, code_reply, message_reply, usage,
};
use nanocode_code_mode_engine::{NativeLimits, set_native_limits};
use openai_turn::{bounded, open, openai, openai_prompt, turn};
use quickjs_threads::{interpreters, once_listed};
use toolhost_double::DoubleConfig;

// The Code Mode limits this binary installs run each cell in an interpreter
// process: this binary, re-executed.
kata_code_mode_host::interpreter_entry!();

/// Set only in a child this binary re-execs: the thread stack, in bytes, its
/// turn cell installs instead of kata's.
const THREAD_STACK_ENV: &str = "KATA_TEST_CODE_MODE_THREAD_STACK_BYTES";

/// The turn cell, by its libtest name, which a child runs alone.
const TURN_CELL: &str = "a_cell_recursing_through_host_calls_to_the_stack_limit_fails_to_the_model_and_the_turn_goes_on";

/// Thread stacks are whole pages.
const PAGE: usize = 4096;

/// The signal Rust's stack-overflow handler ends the process with, after it
/// names the overflowing thread.
const SIGABRT: i32 = 6;

/// A cell that waits 500 ms, recurses through `sort`'s comparator until
/// QuickJS's stack limit throws (any other error ends the cell), then recurses
/// through `setTimeout`'s delay coercion until it throws again, and lets that
/// error end the cell.
const DIVE: &str = "await new Promise((resolve) => setTimeout(resolve, 500));\n\
     function sorting() { [2, 1].sort(() => { sorting(); return 0; }); }\n\
     try { sorting(); } catch (error) {\n\
       if (!`${error}`.includes(\"Maximum call stack size exceeded\")) throw error;\n\
     }\n\
     const deeper = { valueOf() { setTimeout(() => {}, deeper); return 0; } };\n\
     setTimeout(() => {}, deeper);";

/// A cell that waits a second, then runs both recursions counting their
/// levels, caught: the cell reports how deep each got and what stopped it.
const COUNTED_DIVE: &str = "await new Promise((resolve) => setTimeout(resolve, 1000));\n\
     let sorted = 0;\n\
     function sorting() { sorted += 1; [2, 1].sort(() => { sorting(); return 0; }); }\n\
     try { sorting(); } catch (error) { text(`sort depth ${sorted}: ${error}`); }\n\
     let delayed = 0;\n\
     const deeper = { valueOf() { delayed += 1; setTimeout(() => {}, deeper); return 0; } };\n\
     try { setTimeout(() => {}, deeper); } catch (error) {\n\
       text(`setTimeout depth ${delayed}: ${error}`);\n\
     }";

/// QuickJS's own stack-limit error.
const STACK_ERROR: &str = "RangeError: Maximum call stack size exceeded";

/// The limits this process's turn cell runs under: kata's, installed by the
/// worker's installer, or, in a child, kata's with the child's thread stack.
fn install_limits() -> NativeLimits {
    let Ok(bytes) = std::env::var(THREAD_STACK_ENV) else {
        install_code_mode_limits();
        return CODE_MODE_LIMITS;
    };
    let limits = NativeLimits {
        thread_stack_bytes: bytes.parse().expect("a child's thread stack in bytes"),
        ..CODE_MODE_LIMITS
    };
    set_native_limits(limits).expect("the only limits this child installs");
    limits
}

/// **A model-written cell that recurses through host calls until the
/// interpreter's stack limit trips fails to the model, and the turn goes on.**
/// Under kata's limits the model's first cell recurses through `sort`'s
/// comparator, catches the stack error, then recurses through `setTimeout`'s
/// delay coercion; the next request hands the model that cell's failure naming
/// QuickJS's stack error, not a process abort. The model's second cell runs
/// both recursions counted and caught, in the same interpreter process (/proc,
/// read once the kernel lists the first cell's host, the model's second cell
/// held until then, and while the second cell waits before it recurses; in a
/// child, on the same QuickJS thread), and both depths reach the third
/// request; the turn completes. Just before the first cell's error the
/// vendored guard reports the interpreter stack limit, which the model is
/// handed as an output of its own and the evidence records as one
/// `CodeModeLimit{stack}`; the second cell caught both its stack errors, so
/// nothing reports it.
///
/// This is also what a child runs under a shrunk thread stack
/// (`THREAD_STACK_ENV`): there the turn either completes the same way or the
/// process dies by signal.
#[tokio::test]
async fn a_cell_recursing_through_host_calls_to_the_stack_limit_fails_to_the_model_and_the_turn_goes_on()
 {
    let limits = install_limits();
    let first_listed = Gate::default();
    let mock = MockProvider::start(vec![
        code_reply("r1", DIVE, usage(1, 0, 1)),
        Reply::Gated(
            first_listed.clone(),
            Box::new(code_reply("r2", COUNTED_DIVE, usage(1, 0, 1))),
        ),
        message_reply("r3", "DONE", usage(1, 0, 1)),
    ])
    .await;
    let (mut session, _witness) = open(&openai(&mock.url, None), DoubleConfig::default());
    let prompt = openai_prompt("recurse");

    let (outcome, (diving, next_running)) = tokio::join!(turn(session.as_mut(), &prompt), async {
        // On the kernel's listing, not on a sleep: a host starts on its own
        // schedule, and only the held second cell could start another.
        let diving = bounded("the first cell's host", once_listed(1, hosts)).await;
        first_listed.open();
        mock.wait_for_requests(2).await;
        tokio::time::sleep(Duration::from_millis(300)).await;
        (diving, hosts())
    });

    let requests = mock.requests();
    assert_eq!(
        requests.len(),
        3,
        "one model call per response: {outcome:?}"
    );
    let failed = call_output(&requests[1], "call_r1").expect("the model was told the first cell");
    assert!(
        failed.contains("Script failed") && failed.contains(STACK_ERROR),
        "the first cell's output names QuickJS's stack error: {failed}"
    );
    let counted = call_output(&requests[2], "call_r2").expect("the model was told the second cell");
    let sorted = depth(&counted, "sort");
    let delayed = depth(&counted, "setTimeout");
    assert!(
        sorted > 1
            && delayed > 1
            && counted.matches(STACK_ERROR).count() == 2
            && !counted.contains("Script failed"),
        "the cell after the stack hit ran and both recursions stopped at the stack limit: \
         {counted}"
    );
    eprintln!(
        "under max_stack_bytes {} and thread_stack_bytes {}: recursion through sort's \
         comparator {sorted} levels, through setTimeout's delay coercion {delayed} levels",
        limits.max_stack_bytes, limits.thread_stack_bytes
    );
    let TurnOutcome::Completed { response, .. } = &outcome else {
        panic!("a stack hit is a cell outcome, not a turn outcome: {outcome:?}");
    };
    assert_eq!(response, "DONE");
    assert_eq!(
        diving.len(),
        1,
        "one host while the first cell waits: {diving:?}"
    );
    assert_eq!(
        diving, next_running,
        "the cell after the stack hit ran on another host"
    );
    assert_eq!(
        call_outputs(&requests[1], "call_r1")
            .into_iter()
            .skip(1)
            .collect::<Vec<_>>(),
        [serde_json::json!(format!(
            "Code Mode cell exceeded its {}-byte interpreter stack limit",
            limits.max_stack_bytes
        ))],
        "the model is handed the guard's report of the stack limit"
    );
    let evidence = session.take_evidence();
    let recorded: Vec<_> = evidence
        .events
        .iter()
        .filter(|event| {
            matches!(
                event,
                kata_types::agent::SessionEvidenceEvent::CodeModeLimit { .. }
            )
        })
        .collect();
    assert_eq!(
        recorded,
        [&kata_types::agent::SessionEvidenceEvent::CodeModeLimit {
            which: "stack".into(),
        }],
        "the evidence records the first cell's stack hit once: {:?}",
        evidence.events
    );
    let close = session.close().await;
    assert!(close.is_confirmed(), "{close:?}");
}

/// This process's Code Mode hosts as the kernel lists them: its interpreter
/// processes under kata's installer, its QuickJS threads in a child that
/// installed its limits through the engine alone.
fn hosts() -> std::collections::BTreeSet<u32> {
    if std::env::var_os(THREAD_STACK_ENV).is_some() {
        quickjs_threads::quickjs_threads()
    } else {
        interpreters()
    }
}

/// The depth the counted cell reports for the recursion named `label`.
fn depth(counted: &str, label: &str) -> u64 {
    counted
        .split_once(&format!("{label} depth "))
        .and_then(|(_, rest)| rest.split_once(':'))
        .and_then(|(depth, _)| depth.parse().ok())
        .unwrap_or_else(|| panic!("the second cell reports its {label} depth: {counted}"))
}

/// The turn cell, run alone in a child of this binary with `thread_stack_bytes`
/// as its QuickJS thread stack.
fn child(thread_stack_bytes: usize) -> Output {
    Command::new(std::env::current_exe().expect("this test binary"))
        .args(["--exact", TURN_CELL, "--nocapture", "--test-threads=1"])
        .env(THREAD_STACK_ENV, thread_stack_bytes.to_string())
        .output()
        .expect("run the turn cell in a child")
}

/// Whether the child's turn cell passed; panics on any end but a pass or the
/// stack-overflow abort, so a bisection never reads another failure as either.
fn survives(thread_stack_bytes: usize) -> bool {
    let output = child(thread_stack_bytes);
    if output.status.success() {
        return true;
    }
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.signal() == Some(SIGABRT)
            && stderr.contains("'nanocode-code-mode-quickjs'")
            && stderr.contains("has overflowed its stack"),
        "a {thread_stack_bytes}-byte thread stack ended the child neither passing nor by the \
         QuickJS thread's stack overflow: {:?}\n{stderr}",
        output.status
    );
    false
}

/// **RED twin: with no headroom over the interpreter's limit, the same
/// recursions abort the process.** The child runs the turn cell with its
/// QuickJS thread stack equal to `max_stack_bytes`: the native frames around
/// the interpreter's do not fit, the thread overflows its stack before QuickJS's
/// check trips, and the kernel reports the child killed by SIGABRT after Rust
/// names the QuickJS thread as the one that overflowed. This is what kata's
/// headroom prevents, and why the turn cell is not vacuous.
#[test]
fn with_no_thread_stack_headroom_the_same_recursion_aborts_the_process() {
    let output = child(CODE_MODE_LIMITS.max_stack_bytes);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(
        output.status.signal(),
        Some(SIGABRT),
        "the child died by the abort signal: {:?}\n{stderr}",
        output.status
    );
    assert!(
        stderr.contains("thread 'nanocode-code-mode-quickjs'")
            && stderr.contains("has overflowed its stack"),
        "Rust names the QuickJS thread's stack overflow: {stderr}"
    );
}

/// **kata's thread stack leaves MEASURED headroom over the interpreter's
/// limit.** Children search, to the page, the smallest QuickJS thread stack on
/// which the turn cell passes, between `max_stack_bytes` (which aborts: the twin
/// above) and kata's `thread_stack_bytes` (which must pass). That smallest
/// stack is what the wider of the cell's two recursions needs; kata's thread
/// stack must be at least twice it, so a change to `CODE_MODE_LIMITS` that eats
/// the headroom, or a bump that widens the native frames past half of it, is
/// red here.
///
/// MEASURED on this host's test build (the vendored engine, rquickjs and
/// QuickJS at the dev profile's opt-level 2 for dependencies): 1044 KiB, that
/// is `max_stack_bytes` + 20 KiB, set by the `sort` comparator recursion;
/// 1040 KiB aborts. Measured one shape at a time by lane probes, the
/// `setTimeout` recursion, plain JavaScript recursion, a `toJSON` recursion,
/// `String.prototype.replace` and `Proxy` trap callbacks, a
/// `prepareStackTrace` callback, a `text` or `notify` at every level and a tool
/// call with 120-deep input at every level each need `max_stack_bytes` +
/// 16 KiB, and `sort` alone + 20 KiB.
#[test]
fn kata_thread_stack_leaves_measured_headroom_over_the_interpreter_limit() {
    assert!(
        survives(CODE_MODE_LIMITS.thread_stack_bytes),
        "the turn cell passes on kata's own thread stack"
    );
    // Gallop up from `max_stack_bytes` by doubling margins until one passes,
    // then bisect the last step: the stack needed sits a few pages above the
    // limit, so this takes a handful of children where a bisection of the
    // whole range takes a dozen.
    let mut aborts = CODE_MODE_LIMITS.max_stack_bytes;
    assert!(
        !survives(aborts),
        "a thread stack of max_stack_bytes aborts"
    );
    let mut margin = PAGE;
    let mut passes = loop {
        let candidate = CODE_MODE_LIMITS.max_stack_bytes + margin;
        if candidate >= CODE_MODE_LIMITS.thread_stack_bytes {
            break CODE_MODE_LIMITS.thread_stack_bytes;
        }
        if survives(candidate) {
            break candidate;
        }
        aborts = candidate;
        margin *= 2;
    };
    while passes - aborts > PAGE {
        let mid = usize::midpoint(aborts, passes) / PAGE * PAGE;
        if survives(mid) {
            passes = mid;
        } else {
            aborts = mid;
        }
    }
    let needed = passes;
    eprintln!(
        "smallest QuickJS thread stack both recursions survive: {} KiB (max_stack_bytes + {} KiB; \
         {} KiB aborts); kata's thread_stack_bytes {} KiB leaves {} KiB of headroom over it",
        needed / 1024,
        (needed - CODE_MODE_LIMITS.max_stack_bytes) / 1024,
        aborts / 1024,
        CODE_MODE_LIMITS.thread_stack_bytes / 1024,
        (CODE_MODE_LIMITS.thread_stack_bytes - needed) / 1024,
    );
    assert!(
        CODE_MODE_LIMITS.thread_stack_bytes >= 2 * needed,
        "kata's {}-byte QuickJS thread stack is less than twice the {needed} bytes the \
         recursions need",
        CODE_MODE_LIMITS.thread_stack_bytes
    );
}
