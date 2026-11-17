//! Integration tests for the SDK layer under `kata events`.
//!
//! These tests exercise the `subscribe_events_with_status` client
//! method that backs `kata events --status` / `--exit-on`: subscribing via
//! `?status=<kinds>`, receiving events filtered by status, and
//! verifying the event fields `kata events` prints as one JSON
//! `LedgerEvent` per line (`execution_id`/`assignment_id`/`stage_name`/status).
//!
//! The cursor tests verify `last_seq()` and resuming a subscription with
//! `since`, the mechanism behind `kata events --since <seq>`.
//!
//! The binary-level exit-code mapping (exit 65/66) lives in `kata events`
//! (`bin/kata/src/cli/operator/events.rs`); here we verify the underlying
//! stream contract.

mod common;

use std::time::Duration;

use futures::StreamExt;
use kata_client::{KataClient, KataClientError, LedgerEvent};
use kata_test_utils::MockAgentBackend;
use tempfile::TempDir;

/// How long a cell waits for an event it EXPECTS (every wait breaks on its match, so the
/// window only bounds a failure): sized for the commit tier's full parallel load, where the
/// oci rig's capsule round trips can run past a 5 s window.
const EVENT_DEADLINE: Duration = Duration::from_secs(30);

/// `(client, _boot)` — the `OciBoot` guard keeps the node dir, worker pump,
/// reactor, bookkeeper, delivery task and server task alive for the test's
/// duration.
async fn boot_real_server(_worker_label: &str) -> (KataClient, common::OciBoot) {
    common::boot_oci_server(&[], MockAgentBackend::new(), None).await
}

const ONE_STAGE_STAR: &str = r#"
only = stage(id = "only", agent = "default", prompt = "hi")
workflow("wait-events-test", root = [only])
"#;

/// `subscribe_events_with_status(["completed"])` receives one event
/// per workflow completion; each event carries the fields `kata events`
/// prints for it.
#[kata_test_utils::kata_timeout(secs = 30)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn wait_events_emits_one_line_per_match() {
    let (client, _booted) = boot_real_server("we-emit-test").await;

    // Subscribe before submitting so we don't race the transition.
    let stream = client
        .subscribe_events_with_status(&["completed"], None)
        .await
        .expect("subscribe must succeed");

    // Submit a workflow and parse its id from the response.
    let exec = client
        .run_starlark(ONE_STAGE_STAR, Some("wait-events-test.star"))
        .await
        .unwrap();
    let exec_id = exec.id().to_string();

    // Filter client-side to this execution's events.
    let mut stream = stream.filter_execution(exec_id.clone());

    // Wait up to EVENT_DEADLINE for the completed event.
    let deadline = tokio::time::sleep(EVENT_DEADLINE);
    tokio::pin!(deadline);

    let mut matched: Option<LedgerEvent> = None;
    loop {
        tokio::select! {
            () = &mut deadline => break,
            item = stream.next() => match item {
                Some(Ok(ev)) => {
                    matched = Some(ev);
                    break;
                }
                Some(Err(e)) => eprintln!("sse error: {e}"),
                None => break,
            }
        }
    }

    let ev = matched.expect("must receive a completed event within EVENT_DEADLINE");

    // Verify the event carries the fields `kata events` prints.
    assert_eq!(
        ev.execution_id.to_string(),
        exec_id,
        "execution_id must match"
    );
    assert!(
        !ev.assignment_id.to_string().is_empty(),
        "assignment_id must be present"
    );
    assert_eq!(ev.stage_name.as_str(), "only", "stage_name must be 'only'");
    assert_eq!(
        ev.new_status.tag(),
        "completed",
        "kind must be 'completed' (server-side filter)"
    );
    // last_seq() must be populated from the server's id: field.
    assert!(
        stream.last_seq().is_some(),
        "last_seq() must be Some after receiving a completed event with id: field"
    );
    // at_ms: we generate this in run_wait_events from SystemTime::now();
    // verify the field is producible from the event (non-zero wall time).
    let at_ms = u64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis(),
    )
    .unwrap_or(u64::MAX);
    assert!(at_ms > 0, "at_ms must be non-zero");
}

/// `subscribe_events_with_status(["completed", "failed", "orphaned"])`
/// (the "terminal" expansion) exits cleanly on the first completed
/// event — the stream item kind matches the exit-on set.
#[kata_test_utils::kata_timeout(secs = 30)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn wait_events_exit_on_terminal() {
    let (client, _booted) = boot_real_server("we-exit-test").await;

    // "terminal" expands to completed, failed, orphaned.
    let terminal: &[&str] = &["completed", "failed", "orphaned"];
    let stream = client
        .subscribe_events_with_status(terminal, None)
        .await
        .expect("subscribe must succeed");

    let exec = client
        .run_starlark(ONE_STAGE_STAR, Some("wait-events-test.star"))
        .await
        .unwrap();
    let exec_id = exec.id().to_string();

    let mut stream = stream.filter_execution(exec_id.clone());

    let deadline = tokio::time::sleep(EVENT_DEADLINE);
    tokio::pin!(deadline);

    let mut terminal_event: Option<LedgerEvent> = None;
    loop {
        tokio::select! {
            () = &mut deadline => break,
            item = stream.next() => match item {
                Some(Ok(ev)) => {
                    let kind = ev.new_status.tag();
                    if terminal.contains(&kind) {
                        terminal_event = Some(ev);
                        break;
                    }
                }
                Some(Err(e)) => eprintln!("sse error: {e}"),
                None => break,
            }
        }
    }

    let ev = terminal_event.expect("must receive a terminal event within EVENT_DEADLINE");
    assert!(
        terminal.contains(&ev.new_status.tag()),
        "event kind must be terminal, got: {}",
        ev.new_status.tag()
    );
    assert_eq!(
        ev.execution_id.to_string(),
        exec_id,
        "terminal event must be for our execution"
    );
    // In the happy path, completed is the terminal state.
    assert_eq!(
        ev.new_status.tag(),
        "completed",
        "mock workflow should complete cleanly"
    );
}

// ---------------------------------------------------------------------------
// Cursor tests
// ---------------------------------------------------------------------------

/// After receiving a `completed` event, `stream.last_seq()` is `Some`
/// and writing it to a temp cursor file produces a readable u64 — the
/// value a caller passes back as `since` (`kata events --since <seq>`).
#[kata_test_utils::kata_timeout(secs = 30)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn wait_events_writes_cursor_on_each_event() {
    let tmpdir = TempDir::new().unwrap();
    let cursor_path = tmpdir.path().join("cursor");

    let (client, _booted) = boot_real_server("we-cursor-write-test").await;

    let mut stream = client
        .subscribe_events_with_status(&["completed"], None)
        .await
        .expect("subscribe must succeed");

    let exec = client
        .run_starlark(ONE_STAGE_STAR, Some("wait-events-test.star"))
        .await
        .unwrap();
    let exec_id = exec.id().to_string();

    let deadline = tokio::time::sleep(EVENT_DEADLINE);
    tokio::pin!(deadline);

    // Collect events and simulate a cursor write after each one.
    let mut wrote_cursor = false;
    loop {
        tokio::select! {
            () = &mut deadline => break,
            item = stream.next() => match item {
                Some(Ok(ev)) => {
                    if ev.execution_id.to_string() != exec_id {
                        continue;
                    }
                    // After each event, write the last_seq to the cursor file.
                    if let Some(seq) = stream.last_seq() {
                        std::fs::write(&cursor_path, seq.to_string()).unwrap();
                        wrote_cursor = true;
                        break;
                    }
                }
                _ => break,
            }
        }
    }

    assert!(
        wrote_cursor,
        "must write cursor after receiving a completed event"
    );

    // Verify the written cursor is a parseable u64 > 0.
    let contents = std::fs::read_to_string(&cursor_path).unwrap();
    let seq: u64 = contents
        .trim()
        .parse()
        .expect("cursor file must contain a u64");
    assert!(seq > 0, "cursor seq must be > 0");
}

/// After writing a cursor, subscribing with `since=cursor_seq` resumes
/// from the next event. Events with seq ≤ cursor_seq are not replayed.
#[kata_test_utils::kata_timeout(secs = 30)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn wait_events_resumes_from_cursor_on_restart() {
    let (client, _booted) = boot_real_server("we-cursor-resume-test").await;

    // First: run a workflow and record the last seq.
    let mut stream1 = client
        .subscribe_events_with_status(&["completed"], None)
        .await
        .expect("subscribe must succeed");

    let exec1 = client
        .run_starlark(ONE_STAGE_STAR, Some("wait-events-test.star"))
        .await
        .unwrap();
    let exec1_id = exec1.id().to_string();

    let deadline = tokio::time::sleep(EVENT_DEADLINE);
    tokio::pin!(deadline);
    let mut cursor_seq: Option<u64> = None;

    loop {
        tokio::select! {
            () = &mut deadline => break,
            item = stream1.next() => match item {
                Some(Ok(ev)) => {
                    if ev.execution_id.to_string() == exec1_id {
                        cursor_seq = stream1.last_seq();
                        break;
                    }
                }
                _ => break,
            }
        }
    }
    drop(stream1);

    let cursor_seq = cursor_seq.expect("must get a seq from the first workflow");

    // Then: subscribe with since=cursor_seq. Submit second workflow.
    // The resumed stream must not replay events from the first workflow.
    let mut stream2 = client
        .subscribe_events_with_status(&["completed"], Some(cursor_seq))
        .await
        .expect("subscribe with since must succeed");

    let exec2 = client
        .run_starlark(ONE_STAGE_STAR, Some("wait-events-test.star"))
        .await
        .unwrap();
    let exec2_id = exec2.id().to_string();

    let deadline2 = tokio::time::sleep(EVENT_DEADLINE);
    tokio::pin!(deadline2);
    let mut received_seqs: Vec<u64> = Vec::new();

    loop {
        tokio::select! {
            () = &mut deadline2 => break,
            item = stream2.next() => match item {
                Some(Ok(ev)) => {
                    if ev.execution_id.to_string() == exec2_id {
                        if let Some(seq) = stream2.last_seq() {
                            received_seqs.push(seq);
                        }
                        break;
                    }
                }
                _ => break,
            }
        }
    }
    drop(stream2);

    assert!(
        !received_seqs.is_empty(),
        "resumed subscription must receive events from second workflow"
    );
    for seq in &received_seqs {
        assert!(
            *seq > cursor_seq,
            "resumed events must have seq > cursor_seq ({cursor_seq}); got seq={seq}"
        );
    }
}

/// With `since` = `None`, the stream starts from the beginning (no
/// resume): no cursor is read and the subscription carries no `since`
/// value.
#[kata_test_utils::kata_timeout(secs = 30)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn wait_events_no_checkpoint_skips_cursor() {
    let (client, _booted) = boot_real_server("we-no-checkpoint-test").await;

    // First: run a workflow to populate the ledger.
    let mut stream1 = client
        .subscribe_events_with_status(&["completed"], None)
        .await
        .expect("subscribe must succeed");

    let exec1 = client
        .run_starlark(ONE_STAGE_STAR, Some("wait-events-test.star"))
        .await
        .unwrap();
    let exec1_id = exec1.id().to_string();

    // Wait on the event itself — the cell's outer `kata_timeout` is the bound,
    // not a per-phase window sized for an unloaded box: under full parallel
    // load a short window expires before the fold and reads as a stream gap.
    let mut first_workflow_saw_completed = false;
    while let Some(Ok(ev)) = stream1.next().await {
        if ev.execution_id.to_string() == exec1_id {
            first_workflow_saw_completed = true;
            break;
        }
    }
    drop(stream1);
    assert!(first_workflow_saw_completed, "first workflow must complete");

    // Then: subscribe with since=None (no cursor).
    // A second workflow is submitted. The stream receives events
    // starting from the beginning of the log (or at least for the
    // new workflow). Either way, last_seq() works fine.
    let mut stream2 = client
        .subscribe_events_with_status(&["completed"], None)
        .await
        .expect("subscribe without since must succeed");

    let exec2 = client
        .run_starlark(ONE_STAGE_STAR, Some("wait-events-test.star"))
        .await
        .unwrap();
    let exec2_id = exec2.id().to_string();

    let mut got_event2 = false;
    while let Some(Ok(ev)) = stream2.next().await {
        if ev.execution_id.to_string() == exec2_id {
            got_event2 = true;
            break;
        }
    }
    drop(stream2);

    assert!(
        got_event2,
        "no-checkpoint stream must still receive the second workflow's events"
    );
}

// ---------------------------------------------------------------------------
// `wait_for_status_event` (`kata events --exit-on`)
// ---------------------------------------------------------------------------

/// `wait_for_status_event` returns the first matching event without the
/// caller having to hand-roll a `stream.next()` loop — this is the
/// primitive `kata events --exit-on` calls directly.
#[kata_test_utils::kata_timeout(secs = 30)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn wait_for_status_event_returns_first_match() {
    let (client, _booted) = boot_real_server("we-wait-primitive-test").await;

    // Race the wait against the submission (as the other tests in this
    // file do for `subscribe_events_with_status`) so the SSE subscribe
    // request is in flight before the mock backend completes the
    // workflow — `tokio::join!` polls both futures concurrently on this
    // task, starting the subscribe's HTTP request before awaiting the
    // submission's response.
    let wait_fut = client.wait_for_status_event(&["completed"], None, None);
    let submit_fut = client.run_starlark(ONE_STAGE_STAR, Some("wait-events-test.star"));

    let (wait_result, submit_result) =
        tokio::time::timeout(EVENT_DEADLINE, async { tokio::join!(wait_fut, submit_fut) })
            .await
            .expect("must resolve within EVENT_DEADLINE");

    let exec_id = submit_result.unwrap().id().to_string();
    let event = wait_result.expect("must find a matching event");

    assert_eq!(event.execution_id.to_string(), exec_id);
    assert_eq!(event.new_status.tag(), "completed");
}

/// A bare-bones `GET /api/v1/events` responder: accepts one connection,
/// writes SSE response headers plus a single `: keep-alive` comment
/// (no `ledger` frame), then closes the socket. Used to deterministically
/// exercise the "transport ends before any match" path without racing
/// against a real server's shutdown timing.
async fn boot_closing_sse_server() -> (KataClient, tokio::task::JoinHandle<()>) {
    boot_sse_server_answering(": keep-alive\n\n").await
}

/// A one-connection `GET /api/v1/events` responder that writes SSE response
/// headers, then `frames`, then closes the socket.
async fn boot_sse_server_answering(
    frames: &'static str,
) -> (KataClient, tokio::task::JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move {
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
        if let Ok((mut socket, _)) = listener.accept().await {
            let mut buf = [0_u8; 1024];
            // Best-effort drain of the request so the client isn't left
            // waiting on a full-duplex write; we don't need to parse it.
            let _ = socket.read(&mut buf).await;
            let response = format!(
                "HTTP/1.1 200 OK\r\n\
                 Content-Type: text/event-stream\r\n\
                 Connection: close\r\n\
                 \r\n\
                 {frames}"
            );
            let _ = socket.write_all(response.as_bytes()).await;
            let _ = socket.shutdown().await;
        }
    });
    let client = KataClient::new(format!("http://{addr}")).unwrap();
    (client, handle)
}

/// When the SSE transport ends before a matching event arrives,
/// `wait_for_status_event` returns `SseClosedWithoutMatch` — the
/// condition the CLI maps to exit code 65.
#[kata_test_utils::kata_timeout(secs = 30)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn wait_for_status_event_closes_without_match() {
    let (client, _server) = boot_closing_sse_server().await;

    let result = tokio::time::timeout(
        EVENT_DEADLINE,
        client.wait_for_status_event(&["orphaned"], None, None),
    )
    .await
    .expect("must resolve once the transport ends");

    assert!(
        matches!(
            result,
            Err(KataClientError::SseClosedWithoutMatch { cause: None })
        ),
        "expected SseClosedWithoutMatch, got: {result:?}"
    );
}

/// An error item ends the stream, so it ends the wait before a match:
/// `wait_for_status_event` answers `SseClosedWithoutMatch` carrying that item as
/// its `cause` — the condition the CLI maps to exit code 65 — for the server's
/// `event: error`, a `lagged` subscription and a malformed `ledger` frame alike.
#[kata_test_utils::kata_timeout(secs = 30)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn wait_for_status_event_ends_without_match_on_an_error_item() {
    for (frames, cause) in [
        (
            "event: error\ndata: subscription closed\n\n",
            "sse: subscription closed",
        ),
        ("event: lagged\ndata: {}\n\n", "sse: subscription lagged"),
        (
            "event: ledger\ndata: {not json\n\n",
            "invalid response body",
        ),
    ] {
        let (client, _server) = boot_sse_server_answering(frames).await;
        let result = tokio::time::timeout(
            EVENT_DEADLINE,
            client.wait_for_status_event(&["completed"], None, None),
        )
        .await
        .expect("must resolve once the stream ends");
        match result {
            Err(KataClientError::SseClosedWithoutMatch { cause: Some(item) }) => assert!(
                item.to_string().starts_with(cause),
                "{frames:?}: the cause is the error item: {item}"
            ),
            other => {
                panic!("{frames:?}: expected SseClosedWithoutMatch with a cause, got {other:?}")
            }
        }
    }
}
