//! `kata events [--filter-execution <id>] [--since <seq>] [--status
//! <status>...] [--exit-on <status>...]` global ledger SSE tail.
//!
//! Peer of `kata watch`: instead of following one execution's aggregate
//! snapshots, this streams the raw `GET /events` firehose, emitting one
//! JSON [`kata_client::LedgerEvent`] per line.
//!
//! * `--status` / `--since` are pushed straight down to the SDK's
//!   [`KataClient::subscribe_events_with_status`] as server-side
//!   filters. An unknown `--status` value surfaces as a 400 from the
//!   server. A `--since` past the current ledger head surfaces as
//!   [`kata_client::KataClientError::CursorStale`], which `kata`'s exit
//!   contract maps to process exit code 66.
//! * Without `--exit-on`, the command streams forever until SIGINT or
//!   the transport closes (does NOT auto-stop on terminal status — use
//!   `kata run wait` for that).
//! * With `--exit-on <status>...`, the command instead waits for the
//!   first event whose status is in that set, prints it, and exits 0.
//!   That set is the wait's server-side status filter, so clap refuses
//!   `--status` beside it (usage, exit 2). If the stream ends before a
//!   match arrives — it closes, or yields the one error item after which
//!   it ends — it returns
//!   [`kata_client::KataClientError::SseClosedWithoutMatch`], mapped to
//!   process exit code 65. This is the CLI surface for the SDK's
//!   `wait_for_status_event` primitive.

use std::io::Write as _;

use anyhow::{Result, anyhow};
use futures::StreamExt as _;
use kata_client::KataClient;

use super::{block_on, client, emit};

/// Dispatch `kata events [--filter-execution <id>] [--since <seq>]
/// [--status <status>...] [--exit-on <status>...]`.
pub(crate) fn run_events_cmd(
    api_url: &str,
    filter_execution: Option<String>,
    status: Vec<String>,
    since: Option<u64>,
    exit_on: Vec<String>,
) -> Result<()> {
    block_on(async move {
        let client = client(api_url)?;
        if exit_on.is_empty() {
            stream_events(&client, filter_execution.as_deref(), &status, since).await
        } else {
            wait_for_exit_on(&client, filter_execution.as_deref(), &exit_on, since).await
        }
    })
}

/// Drive the SSE stream. Writes one JSON `LedgerEvent` per line to
/// stdout until SIGINT or the transport ends. SSE-level errors go to
/// stderr and the loop continues — disconnects end the stream (the SDK
/// does not auto-reconnect).
async fn stream_events(
    client: &KataClient,
    filter_execution: Option<&str>,
    status: &[String],
    since: Option<u64>,
) -> Result<()> {
    let status_refs: Vec<&str> = status.iter().map(String::as_str).collect();
    let stream = client
        .subscribe_events_with_status(&status_refs, since)
        .await?;
    let mut stream = if let Some(id) = filter_execution {
        stream.filter_execution(id.to_string())
    } else {
        stream
    };
    // Race the stream against ctrl_c so the process exits promptly on
    // SIGINT rather than blocking on the next event boundary.
    loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                std::io::stdout()
                    .lock()
                    .flush()
                    .map_err(|e| anyhow!("flushing stdout: {e}"))?;
                return Ok(());
            }
            item = stream.next() => match item {
                Some(Ok(event)) => {
                    // Each event always gets its own line so downstream
                    // NDJSON consumers can parse incrementally.
                    emit(&event)?;
                    std::io::stdout()
                        .lock()
                        .flush()
                        .map_err(|e| anyhow!("flushing stdout: {e}"))?;
                }
                Some(Err(err)) => {
                    // Surface the SSE-level failure but keep going — the
                    // next chunk might still parse. The SDK ends the
                    // stream on transport failure so this loop exits
                    // naturally on real disconnects.
                    eprintln!("kata: sse error: {err}");
                }
                None => return Ok(()),
            }
        }
    }
}

/// `kata events --exit-on <status>...`: block for the first matching
/// event, print it, and return. Propagates
/// `KataClientError::SseClosedWithoutMatch` (exit 65) and
/// `KataClientError::CursorStale` (exit 66) unchanged so `kata`'s main
/// error-to-exit-code mapping can act on them.
async fn wait_for_exit_on(
    client: &KataClient,
    filter_execution: Option<&str>,
    exit_on: &[String],
    since: Option<u64>,
) -> Result<()> {
    let status_refs: Vec<&str> = exit_on.iter().map(String::as_str).collect();
    let event = client
        .wait_for_status_event(&status_refs, since, filter_execution)
        .await?;
    emit(&event)?;
    std::io::stdout()
        .lock()
        .flush()
        .map_err(|e| anyhow!("flushing stdout: {e}"))?;
    Ok(())
}
