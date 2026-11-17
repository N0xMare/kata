//! Durable event-log replay / SSE relay.

use super::{
    Arc, InFlightLedger, KataResult, LedgerEvent, LedgerLogEvent, ReceiverStream, RecvError,
    ReliableLedgerStream, debug, mpsc,
};

impl InFlightLedger {
    /// The delivery plane's ALLOCATION counter: the highest sequence this
    /// process has RESERVED, whether or not the row at it ever committed.
    /// Returns `0` when nothing has been reserved yet.
    ///
    /// It is the PLANE's counter rather than this struct's, so it also covers a
    /// sequence [`DeliveryProjector::project`](crate::operational::delivery::DeliveryProjector::project)
    /// reserved — one allocator, one
    /// reading of how far it has gone.
    ///
    /// # This is NOT the SSE resumption bound
    ///
    /// The reservation happens BEFORE the commit (reserve, then insert), so an
    /// aborted transition burns a permanent hole and this counter sits one above
    /// a sequence no row was ever written at. A client cannot have RECEIVED that
    /// value, so admitting `?since=` up to it accepts a cursor the log cannot
    /// answer and the stream then waits on a frame that will never exist.
    /// [`Self::delivery_head`] is the resumption bound, and it is
    /// `MAX(sequence)` — the projector's own words: *the high water governs
    /// ALLOCATION; the head governs RESUMPTION.*
    ///
    /// Test accessor: no production path reads the allocation counter from
    /// outside the plane, but the cells that prove a refused or read-only call
    /// reserves nothing assert through it. Never production.
    #[cfg(any(test, feature = "test-support"))]
    #[doc(hidden)]
    pub fn event_head(&self) -> u64 {
        self.delivery.reserved_head()
    }

    /// The DELIVERY head SSE bounds `?since=` against.
    ///
    /// Delegates to [`DeliveryProjector::delivery_head`](crate::operational::delivery::DeliveryProjector::delivery_head),
    /// which is `MAX(sequence)` on `ledger_events.db`: the highest value any
    /// client can actually have been handed. ONE construction — the projector
    /// owns the delivery plane's ordering, so this reader and the writer that
    /// will allocate above it cannot come to disagree about where the plane ends.
    ///
    /// # Failure
    ///
    /// PROPAGATES. An unreadable delivery plane is not a head of `0`: reporting
    /// `0` would 416 every resuming client, and reporting the allocation counter
    /// would admit cursors the plane cannot serve. The caller decides, and both
    /// production callers surface it.
    pub fn delivery_head(&self) -> KataResult<u64> {
        self.delivery.delivery_head()
    }

    /// The delivery plane's durable cursor.
    ///
    /// Exposed so the NON-RECLAMATION latch is assertable against a production
    /// ledger rather than only against a hand-opened projector: `open` is what
    /// seeds and raises `delivery_high_water`, so a ledger that did not adopt the
    /// projector has no latch and a post-compaction reopen would re-issue
    /// sequences live clients had already passed.
    pub fn delivery_cursor(&self) -> KataResult<crate::operational::delivery::DeliveryCursor> {
        self.delivery.cursor()
    }

    /// Commit a complete global authority batch, then notify resumable readers.
    /// A delivery failure never rolls back the authority which produced it.
    pub fn commit_delivery_batch(
        &self,
        dispositions: &[crate::operational::delivery::DeliveryDisposition],
    ) -> KataResult<Vec<u64>> {
        let mut notifications = Vec::new();
        for disposition in dispositions {
            if let crate::operational::delivery::DeliveryDisposition::Publish(frame) = disposition {
                let envelope: LedgerLogEvent = serde_json::from_value(frame.event.payload.clone())
                    .map_err(|error| {
                        kata_types::KataError::Storage(format!(
                            "invalid delivery envelope: {error}"
                        ))
                    })?;
                let event = envelope.as_ledger_event().ok_or_else(|| {
                    kata_types::KataError::Storage("unsupported delivery envelope".to_string())
                })?;
                notifications.push(event);
            }
        }
        let sequences = self.delivery.project(dispositions)?;
        for (seq, event) in sequences.iter().copied().zip(notifications) {
            if event.new_status.is_terminal() {
                metrics::counter!("kata_workflow_stages_total", "status" => event.new_status.tag().to_string()).increment(1);
            }
            #[cfg(any(test, feature = "test-support"))]
            if let Some(hook) = &self.after_append_hook {
                hook();
            }
            // This sequence-free bus is best-effort. Only the reliable stream
            // promises durable backfill across commit-before-notify failure.
            let _ = self.events.send(event.clone());
            let _ = self.seq_events.send((seq, event));
        }
        Ok(sequences)
    }

    /// Raw projector fixture for commit-before-notification crash regressions.
    /// Production uses `commit_delivery_batch`, including subscriber notification.
    #[cfg(any(test, feature = "test-support"))]
    #[doc(hidden)]
    pub fn project_delivery_frames(
        &self,
        frames: &[crate::operational::delivery::DeliveryDisposition],
    ) -> KataResult<Vec<u64>> {
        self.delivery.project(frames)
    }

    /// Subscribe to a reliable, ordered, deduplicated `LedgerEvent` stream.
    ///
    /// - `since = None` — replay from sequence 1, then tail.
    /// - `since = Some(s)` — replay from `s + 1`, then tail.
    ///
    /// On broadcast `Lagged`: the relay task logs a warning, re-subscribes,
    /// and re-syncs from the durable event log so no transitions are dropped.
    /// Seam invariant: `seq_events.subscribe()` before the head read —
    /// any event published in the window between those two calls lands in
    /// the live receiver and is deduplicated by the `seq <= last_seen` guard.
    /// Dropping the returned stream self-terminates the relay task.
    pub fn subscribe_ledger_reliable(self: &Arc<Self>, since: Option<u64>) -> ReliableLedgerStream {
        // Subscribe before reading head_seq (seam-race invariant).
        let mut live_rx = self.seq_events.subscribe();
        let head_seq = self.delivery.reserved_head();

        let (tx, rx) = mpsc::channel::<(u64, Arc<LedgerEvent>)>(256);
        let ledger = Arc::clone(self);

        tokio::spawn(async move {
            let mut last_seen: u64 = since.unwrap_or(0);

            if head_seq > 0 {
                let start = since.map_or(1, |s| s + 1);
                if !paginate_ledger_to_sender(&ledger, &tx, start, head_seq, &mut last_seen).await {
                    return;
                }
            }

            let mut reconciliation = tokio::time::interval(std::time::Duration::from_millis(100));
            reconciliation.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                let notification = tokio::select! {
                    () = tx.closed() => return,
                    _ = reconciliation.tick() => {
                        let Ok(head) = ledger.delivery_head() else { continue; };
                        if !paginate_ledger_to_sender(&ledger, &tx, last_seen.saturating_add(1), head, &mut last_seen).await {
                            return;
                        }
                        continue;
                    },
                    notification = live_rx.recv() => notification,
                };
                match notification {
                    Ok((seq, _event)) => {
                        if seq <= last_seen {
                            continue;
                        }
                        // A notification is a wakeup, not proof that every lower
                        // committed sequence was notified before it.
                        if !paginate_ledger_to_sender(
                            &ledger,
                            &tx,
                            last_seen.saturating_add(1),
                            seq,
                            &mut last_seen,
                        )
                        .await
                        {
                            return;
                        }
                    }
                    Err(RecvError::Lagged(skipped)) => {
                        tracing::warn!(
                            skipped,
                            last_seen,
                            "sse.lagged: broadcast lagged; re-syncing from durable ledger log"
                        );
                        live_rx = ledger.seq_events.subscribe();
                        let resync_head = ledger.delivery.reserved_head();
                        if !paginate_ledger_to_sender(
                            &ledger,
                            &tx,
                            last_seen + 1,
                            resync_head,
                            &mut last_seen,
                        )
                        .await
                        {
                            return;
                        }
                    }
                    Err(RecvError::Closed) => return,
                }
            }
        });

        ReceiverStream::new(rx)
    }
}

/// Paginate the ledger's durable event log from `start_seq` through
/// `end_seq` (inclusive), forwarding each new `LedgerEvent` to `tx` and
/// updating `last_seen`. Returns `false` if the consumer dropped the
/// stream (mpsc send failed), `true` in all other cases (including log
/// errors — a corrupt row is skipped rather than aborting the stream).
async fn paginate_ledger_to_sender(
    ledger: &InFlightLedger,
    tx: &mpsc::Sender<(u64, Arc<LedgerEvent>)>,
    start_seq: u64,
    end_seq: u64,
    last_seen: &mut u64,
) -> bool {
    const PAGE: usize = 1000;
    let mut next_seq = start_seq;
    while next_seq <= end_seq {
        let page = match ledger.event_log.read_from(next_seq, PAGE) {
            Ok(p) => p,
            Err(e) => {
                tracing::warn!(error = %e, next_seq, "ledger: paginate page failed");
                return true;
            }
        };
        if page.is_empty() {
            return true;
        }
        let page_len = page.len();
        let mut max_seq: u64 = next_seq;
        for (seq, event) in page {
            if seq > max_seq {
                max_seq = seq;
            }
            if seq <= *last_seen {
                continue;
            }
            *last_seen = seq;
            // The durable payload is the versioned `LedgerLogEvent`
            // envelope. Decode it and project back onto the flat wire type.
            // A future/unknown schema version decodes to `Unknown` and yields
            // `None` here — an older reader skips a frame it cannot interpret
            // rather than erroring the whole SSE relay.
            let log_event: LedgerLogEvent = match serde_json::from_value(event.payload) {
                Ok(e) => e,
                Err(e) => {
                    debug!(seq, error = %e, "ledger: corrupt event in log, skipping");
                    continue;
                }
            };
            let Some(ledger_event) = log_event.as_ledger_event() else {
                debug!(
                    seq,
                    schema_version = log_event.schema_version(),
                    "ledger: unknown event schema version in log, skipping"
                );
                continue;
            };
            if tx.send((seq, Arc::new(ledger_event))).await.is_err() {
                return false;
            }
        }
        if page_len < PAGE {
            return true;
        }
        next_seq = max_seq + 1;
    }
    true
}
