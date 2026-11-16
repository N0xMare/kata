//! kata's Code Mode limits, installed by the seam the worker calls at start
//! (`kata_agent_nanocode::install_code_mode_limits`), seen through the nanocode
//! adapter: a mock Responses provider writes the cells, the toolhost double is
//! the capsule, and kata's own `CODE_MODE_LIMITS` are the limits.
//!
//! The witnesses do not share the adapter's code: the engine's own setter
//! (which names the limits it holds), the mock's log of the request bodies it
//! received (what the model was told), and the kernel's account of this
//! process's interpreter processes and of its own peak resident set (`/proc`).
//! The installer runs every cell in an interpreter process, this binary
//! re-executed (its entry below). Each cell calls the installer first, as the
//! worker does, and this binary installs no other limits: the engine's are
//! process-global, so cells under other limits live in their own binaries.

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

use std::time::Duration;

use kata_agent::adapter::TurnOutcome;
use kata_agent_nanocode::{CODE_MODE_LIMITS, install_code_mode_limits};
use kata_code_mode_host::{CodeModeLimits, Program};
use mock_provider::{
    Gate, MockProvider, Reply, call_output, code_reply, message_reply, usage, wait_reply,
};
use openai_turn::{bounded, open, openai, openai_prompt, turn};
use quickjs_threads::{interpreters, once_listed};
use resident::peak_resident_bytes;
use toolhost_double::DoubleConfig;

// The Code Mode limits this binary installs run each cell in an interpreter
// process: this binary, re-executed.
kata_code_mode_host::interpreter_entry!();

/// The installer leaves exactly kata's limits installed: the interpreter host
/// refuses any other limits afterwards and names the ones it holds.
#[test]
fn the_installer_installs_kata_code_mode_limits() {
    install_code_mode_limits();
    install_code_mode_limits();
    let other = CodeModeLimits {
        memory_bytes: CODE_MODE_LIMITS.memory_bytes / 2,
        ..CODE_MODE_LIMITS
    };
    assert_eq!(
        kata_code_mode_host::install(other, Program::this_executable())
            .map_err(|(limits, _)| limits),
        Err(CODE_MODE_LIMITS),
        "the interpreter host holds kata's limits"
    );
}

/// A cell that waits 500 ms, then allocates 384 MiB of filled typed arrays,
/// past the 256 MiB limit, and reports what it holds if it gets there.
const ALLOCATE_384_MIB: &str = "await new Promise((resolve) => setTimeout(resolve, 500));\n\
     const chunks = [];\n\
     for (let i = 0; i < 384; i++) chunks.push(new Uint8Array(1 << 20).fill(1));\n\
     text(`allocated ${chunks.length} MiB`);";

const _: () = assert!(
    CODE_MODE_LIMITS.memory_bytes < 384 << 20,
    "the cell allocates past kata's memory limit"
);

/// A cell that waits a second, then states that it ran.
const NEXT_CELL: &str = "await new Promise((resolve) => setTimeout(resolve, 1000));\n\
     text(\"the next cell ran\");";

/// **A model-written cell that allocates past the memory limit fails as a
/// model-visible error, and the turn goes on.** The model's first cell
/// allocates 384 MiB under kata's 256 MiB limit; the next request hands the
/// model that cell's failure, naming the out-of-memory error, not a result.
/// The model's second cell then runs and its text reaches the third request,
/// and the turn completes with the final message, in this process, which is
/// the one the main runs the harness in. MEASURED, the first cell's result:
/// its header, then `Script error:\nScript stopped: the cell ran out of
/// memory.` (djs's heap hit, which no script can catch).
///
/// The cells run in interpreter processes, never here: this process's peak
/// resident set stays under half the heap limit the first cell filled
/// (MEASURED: about 20 MiB), and the kernel lists exactly one interpreter
/// process when it first lists one (the first cell's, before that cell's
/// 500 ms wait ends in its allocation) and while the second cell waits, each
/// cell's its own: nanocode spawns a host per cell, and kata gives each host
/// an interpreter of its own, reaped when the host is dropped, so the first
/// cell's is gone by then (the listing names unreaped ones too).
///
/// **Would red if:** the cells ran in this process (its peak resident set past
/// half the heap limit, and no interpreter listed), the first cell's
/// interpreter outlived its host (two listed, or the same one), or the patched
/// engine stopped reporting a heap hit (nothing recorded).
#[tokio::test]
async fn a_cell_allocating_past_the_memory_limit_fails_to_the_model_and_the_turn_goes_on() {
    install_code_mode_limits();
    let mock = MockProvider::start(vec![
        code_reply("r1", ALLOCATE_384_MIB, usage(1, 0, 1)),
        code_reply("r2", NEXT_CELL, usage(1, 0, 1)),
        message_reply("r3", "DONE", usage(1, 0, 1)),
    ])
    .await;
    let (mut session, _witness) = open(&openai(&mock.url, None), DoubleConfig::default());
    let prompt = openai_prompt("allocate");

    let (outcome, (allocating, next_running)) =
        tokio::join!(turn(session.as_mut(), &prompt), async {
            // On the listing, not on a sleep: the interpreter starts on its
            // own schedule, and its cell allocates only 500 ms after it starts.
            let allocating =
                bounded("the first cell's interpreter", once_listed(1, interpreters)).await;
            mock.wait_for_requests(2).await;
            tokio::time::sleep(Duration::from_millis(300)).await;
            (allocating, interpreters())
        });

    let requests = mock.requests();
    assert_eq!(
        requests.len(),
        3,
        "one model call per response: {outcome:?}"
    );
    let failed = call_output(&requests[1], "call_r1").expect("the model was told the first cell");
    assert!(
        failed.contains("Script failed")
            && failed.contains("Script error:\\nScript stopped: the cell ran out of memory."),
        "the first cell's output names its memory failure: {failed}"
    );
    assert!(
        !failed.contains("allocated"),
        "the first cell allocated past the limit: {failed}"
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
        allocating.len(),
        1,
        "one interpreter while the first cell waits: {allocating:?}"
    );
    assert_eq!(
        next_running.len(),
        1,
        "one interpreter while the second cell waits: {next_running:?}"
    );
    assert!(
        allocating.is_disjoint(&next_running),
        "the second cell ran in the first cell's interpreter process, which outlived its \
         host: {allocating:?} {next_running:?}"
    );
    let evidence = session.take_evidence();
    assert!(
        evidence
            .events
            .contains(&kata_types::agent::SessionEvidenceEvent::CodeModeLimit {
                which: "memory".into(),
            }),
        "the evidence records the heap-limit hit: {:?}",
        evidence.events
    );
    let close = session.close().await;
    assert!(close.is_confirmed(), "{close:?}");
    let peak = peak_resident_bytes();
    assert!(
        peak < u64::try_from(CODE_MODE_LIMITS.memory_bytes / 2).expect("a byte count"),
        "this process's peak resident set is {peak} bytes: the cell filled its heap here"
    );
}

/// **A terminated cell's interpreter is killed and reaped, and Code Mode goes
/// on for the turn.** The model starts a cell that spins in JavaScript and
/// yields after 200 ms, then calls `wait` with `terminate: true`: nanocode ends
/// that cell by terminating its host, and kata's supervisor kills and reaps
/// the host's interpreter process. The model's next cell runs, on a host of
/// its own, and its text reaches the model. The kernel's process list is the
/// witness: while the first cell spins it lists one interpreter process, and
/// while the third cell waits on a timer one other, the spinning one gone
/// (the listing names unreaped interpreters too, so it was reaped).
///
/// Each sample is taken on the kernel listing an interpreter, and the model's
/// next answer is held until it is taken: the terminate until the first cell's
/// interpreter is listed, the turn's last answer until the third cell's is.
/// An interpreter process starts on its own schedule, so a sample taken on a
/// sleep instead can land before it is listed (a host under load).
///
/// **Would red if:** a terminate left its cell's interpreter running or
/// unreaped (two listed while the third cell waits), or an ended host ended
/// Code Mode for the turn (the third cell fails).
#[tokio::test]
async fn a_terminated_cell_s_interpreter_is_reaped_and_the_next_cell_runs() {
    install_code_mode_limits();
    let first_listed = Gate::default();
    let third_listed = Gate::default();
    let mock = MockProvider::start(vec![
        code_reply(
            "r1",
            "// @exec: {\"yield_time_ms\": 200}\nwhile (true) {}",
            usage(1, 0, 1),
        ),
        Reply::Gated(
            first_listed.clone(),
            Box::new(wait_reply("r2", "1", true, usage(1, 0, 1))),
        ),
        code_reply(
            "r3",
            "await new Promise((resolve) => setTimeout(resolve, 1000));\n\
             text(\"a fresh host ran it\");",
            usage(1, 0, 1),
        ),
        Reply::Gated(
            third_listed.clone(),
            Box::new(message_reply("r4", "DONE", usage(1, 0, 1))),
        ),
    ])
    .await;
    let (mut session, _witness) = open(&openai(&mock.url, None), DoubleConfig::default());
    let prompt = openai_prompt("spin, stop, go on");

    let (outcome, (spinning, waiting)) = tokio::join!(turn(session.as_mut(), &prompt), async {
        // The first cell spins from its start until the terminate the held
        // answer to the second request carries.
        let spinning = bounded("the first cell's interpreter", once_listed(1, interpreters)).await;
        first_listed.open();
        // The terminate has killed and reaped the first cell's interpreter by
        // the third request, which carries its output.
        mock.wait_for_requests(3).await;
        let waiting = bounded("the third cell's interpreter", once_listed(1, interpreters)).await;
        third_listed.open();
        (spinning, waiting)
    });

    let requests = mock.requests();
    assert_eq!(
        requests.len(),
        4,
        "one model call per response: {outcome:?}"
    );
    let yielded = call_output(&requests[1], "call_r1").expect("the model was told the first cell");
    assert!(
        yielded.contains("Script running with cell ID 1"),
        "the spinning cell yielded as cell 1: {yielded}"
    );
    let ended = call_output(&requests[2], "call_r2").expect("the model was told the wait");
    assert!(
        ended.contains("Script terminated"),
        "the terminate ended the cell: {ended}"
    );
    let next = call_output(&requests[3], "call_r3").expect("the model was told the third cell");
    assert!(
        next.contains("a fresh host ran it") && !next.contains("Script failed"),
        "the cell after the ended host ran: {next}"
    );
    assert!(
        matches!(outcome, TurnOutcome::Completed { .. }),
        "{outcome:?}"
    );
    assert_eq!(
        spinning.len(),
        1,
        "one interpreter while the first cell spins: {spinning:?}"
    );
    assert_eq!(
        waiting.len(),
        1,
        "one interpreter while the third cell waits: {waiting:?}"
    );
    assert!(
        spinning.is_disjoint(&waiting),
        "the terminated cell's interpreter process outlived the terminate: {spinning:?} \
         {waiting:?}"
    );
    let close = session.close().await;
    assert!(close.is_confirmed(), "{close:?}");
}
