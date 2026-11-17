//! `kata watch <execution-id>` event streaming.
//!
//! ## What is bounded here, and what deliberately is not
//!
//! `kata watch` follows an execution to terminal, so "it is still waiting" is
//! usually the feature and not a fault. Three of its waits are faults, and each
//! is bounded:
//!
//! * every request it makes (`observe`, the SSE attach, the worker
//!   attribution fetch) is bounded by the SDK's own transport deadlines —
//!   `KataClient::DEFAULT_CONNECT_TIMEOUT` / `DEFAULT_READ_TIMEOUT`;
//! * a silent event stream is bounded by the same read deadline: the server
//!   keep-alives every `kata_api::rest::events::SSE_KEEP_ALIVE_INTERVAL`, so a
//!   peer that stops writing ends the stream inside the read bound and lands in
//!   the `None` arm below, which reports what it had seen;
//! * a stream that yields errors instead of frames is bounded by
//!   [`MAX_CONSECUTIVE_STREAM_ERRORS`], because "log it and loop" is an
//!   unbounded wait wearing a print statement.
//!
//! What is NOT bounded by default is total wall-clock: an operator watching a
//! four-hour workflow is not hung, and a default deadline would truncate the
//! command's whole purpose. Scripts (and the live smokes) get an explicit
//! `--timeout-secs`, which reports the deadline, the last status seen, and the
//! frame count — never a bare timeout.

use std::io::Write as _;
use std::time::Duration;

use anyhow::{Result, anyhow, bail};
use futures::StreamExt as _;
use kata_client::operator_projection::{
    WatchLine, WorkerAttribution, WorkerAttributionProjection, collect_worker_attribution,
    watch_snapshot_with_worker_attribution,
};
use kata_client::{EventFrame, ExecutionRecord, KataClient};
use kata_types::time::now_ms;

use super::{block_on, client, emit, exit_for_terminal_status, resolve_execution_id};

/// How many consecutive SSE errors `kata watch` absorbs before it stops.
///
/// An error arm that logs and continues with no bound at all is a busy-loop
/// for any stream that fails repeatedly without closing. Three,
/// not one: a single `lagged` frame is a normal, recoverable event (the SDK
/// surfaces it as an error precisely so the caller refetches authoritative
/// state, which the next `observe` does), so stopping on the first would
/// abandon a healthy stream. Three consecutive failures with no intervening
/// frame is a stream that is not going to recover.
const MAX_CONSECUTIVE_STREAM_ERRORS: usize = 3;

/// Dispatch `kata watch <execution-id>`.
pub(crate) fn run_watch_cmd(
    api_url: &str,
    execution_id: Option<String>,
    current: bool,
    active: bool,
    include_outputs: bool,
    timeout_secs: u64,
) -> Result<()> {
    block_on(async move {
        let client = client(api_url)?;
        let execution_id =
            resolve_execution_id(&client, api_url, execution_id, current, active).await?;
        watch_execution(
            &client,
            &execution_id,
            include_outputs,
            watch_deadline(timeout_secs),
        )
        .await
    })
}

/// `--timeout-secs 0` means "follow until terminal" — the interactive default.
///
/// Named rather than inlined because the zero case is the one a reader has to
/// be told about: clap's `default_value_t = 0` would otherwise read as a
/// deadline that fires immediately.
pub(super) const fn watch_deadline(timeout_secs: u64) -> Option<Duration> {
    if timeout_secs == 0 {
        None
    } else {
        Some(Duration::from_secs(timeout_secs))
    }
}

pub(super) async fn watch_execution(
    client: &KataClient,
    execution_id: &str,
    include_outputs: bool,
    deadline: Option<Duration>,
) -> Result<()> {
    const TERMINAL_SETTLE: Duration = Duration::from_millis(250);

    let started = tokio::time::Instant::now();
    let initial = client.observe(execution_id).await?;
    let mut worker_projection = WorkerAttributionProjection::from_attribution(
        collect_worker_attribution(client, execution_id, &initial).await?,
    );
    emit_watch(WatchLine::Snapshot {
        at_ms: now_ms(),
        execution: watch_snapshot_with_worker_attribution(
            &initial,
            include_outputs,
            worker_projection.to_vec(),
        ),
    })?;
    if initial.is_terminal() {
        if let Some(active) =
            active_after_terminal_settle(client, execution_id, &initial, TERMINAL_SETTLE).await?
        {
            emit_watch_snapshot(&active, include_outputs, worker_projection.to_vec())?;
        } else {
            return exit_for_terminal_status(&initial);
        }
    }

    let mut stream = client
        .subscribe_event_frames(Some(execution_id), None)
        .await?
        .filter_execution(execution_id.to_string());

    // Never `select!` on a bare `Option<Sleep>`: a `None` arm that is always
    // ready would spin the loop. Instead the unbounded case arms a timer beyond
    // any process lifetime, which costs one never-firing timer and keeps the
    // select arm uniform. 30 years is the same constant tokio uses for its own
    // (crate-private) `Instant::far_future`, and for its reason: 100 years
    // overflows `Instant` on FreeBSD and 1000 years on macOS.
    const UNBOUNDED_FOLLOW: Duration = Duration::from_hours(24 * 365 * 30);
    let expiry = tokio::time::sleep_until(started + deadline.unwrap_or(UNBOUNDED_FOLLOW));
    tokio::pin!(expiry);

    let mut frames_seen: u64 = 0;
    let mut consecutive_errors: usize = 0;
    let mut last_stream_error: Option<String> = None;

    // A stage's `completed` frame is the LAST ledger frame an execution emits;
    // the execution's own terminal lifecycle write emits none. A watcher that
    // re-reads the record only ON frames can therefore read `running` at that
    // last frame and then wait on a silent stream until its deadline. Measured
    // on `smoke_product_cli_init_main_submit_watch_wait_output_shutdown`
    // under the confined default: the frame landed at +0.9s, the
    // execution was `running` when re-read, and nothing else ever arrived. So
    // the record is ALSO re-read on a quiet cadence, and a terminal read exits
    // through the same settle as a frame-driven one.
    const QUIET_REREAD: Duration = Duration::from_millis(500);
    let mut quiet = tokio::time::interval(QUIET_REREAD);
    quiet.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    loop {
        tokio::select! {
            _ = quiet.tick() => {
                let record = client.observe(execution_id).await?;
                if record.is_terminal()
                    && active_after_terminal_settle(
                        client,
                        execution_id,
                        &record,
                        TERMINAL_SETTLE,
                    )
                    .await?
                    .is_none()
                {
                    emit_watch_snapshot(&record, include_outputs, worker_projection.to_vec())?;
                    return exit_for_terminal_status(&record);
                }
            }
            () = &mut expiry => {
                let waited = deadline.unwrap_or_default();
                let record = client.observe(execution_id).await;
                let status = record.as_ref().map_or_else(
                    |err| format!("<unreadable: {err}>"),
                    |record| format!("{:?}", record.status),
                );
                bail!(
                    "kata watch: execution {execution_id} did not reach a terminal status within \
                     the requested --timeout-secs {}s. Last status seen: {status}; {frames_seen} \
                     event frame(s) arrived while watching{}. The stream was alive (the SDK's own \
                     read bound would have ended it otherwise), so this is a workflow that is \
                     still running, not a broken connection — raise --timeout-secs, or use \
                     `kata run wait` / `kata run-summary {execution_id}` instead of holding a \
                     stream open.",
                    waited.as_secs(),
                    last_stream_error
                        .as_deref()
                        .map_or_else(String::new, |err| format!("; last stream error: {err}")),
                );
            }
            _ = tokio::signal::ctrl_c() => {
                std::io::stdout()
                    .lock()
                    .flush()
                    .map_err(|e| anyhow!("flushing stdout: {e}"))?;
                return Ok(());
            }
            item = stream.next() => {
                if matches!(item, Some(Ok(_))) {
                    frames_seen += 1;
                    consecutive_errors = 0;
                }
                match item {
                    Some(Ok(EventFrame::Ledger(event))) => {
                        worker_projection.record_event(&event);
                        let seq = stream.last_seq();
                        let record = client.observe(execution_id).await?;
                        let terminal = record.is_terminal();
                        emit_watch(WatchLine::Ledger {
                            at_ms: now_ms(),
                            seq,
                            event,
                            execution: watch_snapshot_with_worker_attribution(
                                &record,
                                include_outputs,
                                worker_projection.to_vec(),
                            ),
                        })?;
                        if terminal {
                            if let Some(active) = active_after_terminal_settle(
                                client,
                                execution_id,
                                &record,
                                TERMINAL_SETTLE,
                            )
                            .await?
                            {
                                emit_watch_snapshot(
                                    &active,
                                    include_outputs,
                                    worker_projection.to_vec(),
                                )?;
                            } else {
                                return exit_for_terminal_status(&record);
                            }
                        }
                    }
                    Some(Ok(EventFrame::Progress(event))) => {
                        emit_watch(WatchLine::Progress {
                            at_ms: now_ms(),
                            event,
                        })?;
                    }
                    Some(Ok(EventFrame::ProgressLagged)) => {
                        emit_watch(WatchLine::ProgressLagged { at_ms: now_ms() })?;
                    }
                    Some(Err(err)) => {
                        eprintln!("kata: sse error: {err}");
                        consecutive_errors += 1;
                        last_stream_error = Some(err.to_string());
                        if consecutive_errors >= MAX_CONSECUTIVE_STREAM_ERRORS {
                            bail!(
                                "kata watch: the event stream for execution {execution_id} \
                                 produced {consecutive_errors} consecutive errors with no frame \
                                 in between, so it is not recovering; giving up rather than \
                                 looping on it. Last error: {err}"
                            );
                        }
                    }
                    None => {
                        let record = client.observe(execution_id).await?;
                        let terminal = record.is_terminal();
                        emit_watch(WatchLine::Snapshot {
                            at_ms: now_ms(),
                            execution: watch_snapshot_with_worker_attribution(
                                &record,
                                include_outputs,
                                worker_projection.to_vec(),
                            ),
                        })?;
                        if terminal
                            && active_after_terminal_settle(
                                client,
                                execution_id,
                                &record,
                                TERMINAL_SETTLE,
                            )
                            .await?
                            .is_none()
                        {
                            return exit_for_terminal_status(&record);
                        }
                        // The SDK's read bound is what turns a peer that stops
                        // writing into a closed stream at all, so this arm is
                        // reached ON a bound rather than instead of one — and
                        // it has to say what it had seen, or the operator
                        // learns only that something ended.
                        bail!(
                            "kata watch: the event stream for execution {execution_id} closed \
                             after {frames_seen} frame(s) before the execution reached a terminal \
                             status (last status seen: {:?}){}. A stream that goes silent longer \
                             than the SDK's read bound ends exactly like this, so check that the \
                             main at {} is still serving before re-attaching.",
                            record.status,
                            last_stream_error
                                .as_deref()
                                .map_or_else(String::new, |err| format!("; last stream error: {err}")),
                            client.base_url(),
                        );
                    }
                }
            }
        }
    }
}
/// The execution aggregate is ledger-derived, so a DAG can briefly look
/// terminal between one stage completing and the runner inserting the next
/// ready assignment. Return the active settled snapshot when that gap is
/// observed; otherwise return `None` so the caller can exit.
async fn active_after_terminal_settle(
    client: &KataClient,
    execution_id: &str,
    candidate: &ExecutionRecord,
    settle: Duration,
) -> Result<Option<ExecutionRecord>> {
    if !candidate.is_terminal() {
        return Ok(None);
    }
    tokio::time::sleep(settle).await;
    let settled = client.observe(execution_id).await?;
    if settled.is_terminal() {
        Ok(None)
    } else {
        Ok(Some(settled))
    }
}
fn emit_watch(line: WatchLine) -> Result<()> {
    emit(&line)?;
    std::io::stdout()
        .lock()
        .flush()
        .map_err(|e| anyhow!("flushing stdout: {e}"))?;
    Ok(())
}
fn emit_watch_snapshot(
    record: &ExecutionRecord,
    include_outputs: bool,
    worker_attribution: Vec<WorkerAttribution>,
) -> Result<()> {
    emit_watch(WatchLine::Snapshot {
        at_ms: now_ms(),
        execution: watch_snapshot_with_worker_attribution(
            record,
            include_outputs,
            worker_attribution,
        ),
    })
}
