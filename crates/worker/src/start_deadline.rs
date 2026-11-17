/// Epoch-ms sentinel for "the worker has been free to pick up work since
/// forever" — i.e. it has never held a live slot yet (fresh boot, or idle
/// after draining its queue). Passing this to
/// [`expired_start_deadline_reason_at`] makes the reaper behave exactly like a
/// pure time-in-queue check: nothing is exempt, so an idle/dead worker still
/// trips an already-expired deadline.
pub(crate) const SLOT_NEVER_OCCUPIED: u64 = 0;

/// Decide whether a freshly dequeued attempt must be failed for missing its
/// start deadline, given when the worker's slot last became free.
///
/// The head-of-line exemption. The start deadline is meant to
/// measure worker *unresponsiveness*, not time-in-queue. With a single
/// worker slot (the supervised node alone), a second submitted run sits queued behind a
/// long-running stage; naively comparing `now` against the dispatch-time
/// deadline reaps that queued run even though the worker was healthy and busy
/// the entire time.
///
/// `slot_free_since_ms` is the epoch-ms instant at which the worker's slot
/// last became free to pick up this attempt — the moment its previous stage
/// finished executing, or [`SLOT_NEVER_OCCUPIED`] when the worker has not yet
/// held a live slot (fresh boot / idle after draining). The reaper exempts the
/// attempt only when the deadline elapsed *at or before* the slot became
/// free: in that window a live slot-holder occupied the worker, so the queue
/// delay is legitimate backpressure and the slot picks the attempt up now.
///
/// A worker that had a free slot *before* the deadline yet still never started
/// the attempt (`deadline_ms > slot_free_since_ms`) is genuinely
/// unresponsive — it had capacity and time and did nothing — so the deadline
/// still trips. With [`SLOT_NEVER_OCCUPIED`] this collapses to an
/// unconditional time-in-queue reap.
pub(crate) fn expired_start_deadline_reason_at(
    start_deadline_ms: Option<u64>,
    slot_free_since_ms: u64,
) -> Option<String> {
    let deadline_ms = start_deadline_ms?;
    // The same clock the main stamps `start_deadline_ms` with and the worker loop
    // stamps `slot_free_since_ms` with, so the three are comparable.
    let now_ms = kata_types::time::now_ms();
    if now_ms <= deadline_ms {
        return None;
    }
    // A live slot-holder occupied the worker through the deadline: the queue
    // delay is backpressure, not death. Exempt — the slot runs it now.
    if deadline_ms <= slot_free_since_ms {
        return None;
    }
    Some(format!(
        "attempt start deadline elapsed before worker execution: start_deadline_ms={deadline_ms} now_ms={now_ms} overdue_ms={} slot_free_since_ms={slot_free_since_ms}",
        now_ms.saturating_sub(deadline_ms)
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// No false negative (the branch the head-of-line exemption must NOT
    /// swallow): a worker that HAS held a live slot — `slot_free_since_ms > 0` —
    /// then gets a genuinely-late NEW attempt whose deadline elapsed strictly
    /// AFTER the slot became free (`deadline_ms > slot_free_since_ms`). The slot
    /// was available and the work still never started: unresponsiveness, so it
    /// must still trip.
    #[test]
    fn held_slot_then_late_new_attempt_still_trips() {
        let now = kata_types::time::now_ms();
        let deadline_ms = now - 1_000; // already overdue
        let slot_free_since_ms = deadline_ms - 1; // slot freed BEFORE the deadline
        let reason = expired_start_deadline_reason_at(Some(deadline_ms), slot_free_since_ms);
        assert!(
            reason.is_some(),
            "a slot freed before the deadline yet no start = unresponsive; must trip"
        );
    }

    /// The backpressure exemption: a live slot-holder occupied the worker THROUGH
    /// the deadline (`slot_free_since_ms >= deadline_ms`), so the queue delay is
    /// legitimate and the overdue attempt is exempt.
    #[test]
    fn slot_held_through_deadline_is_exempt() {
        let now = kata_types::time::now_ms();
        let deadline_ms = now - 1_000; // already overdue in wall-clock terms
        let slot_free_since_ms = deadline_ms + 500; // holder freed the slot AFTER the deadline
        assert!(
            expired_start_deadline_reason_at(Some(deadline_ms), slot_free_since_ms).is_none(),
            "a holder occupying the worker through the deadline is backpressure, not death"
        );
    }

    /// An idle / dead-on-arrival worker (`SLOT_NEVER_OCCUPIED`) collapses to the
    /// pure time-in-queue reap: an already-expired deadline trips.
    #[test]
    fn idle_worker_collapses_to_time_in_queue_trip() {
        let deadline_ms = kata_types::time::now_ms() - 1_000;
        assert!(
            expired_start_deadline_reason_at(Some(deadline_ms), SLOT_NEVER_OCCUPIED).is_some(),
            "idle worker must still trip an expired deadline"
        );
    }

    /// A deadline still in the future never trips, regardless of slot state.
    #[test]
    fn future_deadline_never_trips() {
        let deadline_ms = kata_types::time::now_ms() + 60_000;
        assert!(expired_start_deadline_reason_at(Some(deadline_ms), SLOT_NEVER_OCCUPIED).is_none());
        assert!(expired_start_deadline_reason_at(Some(deadline_ms), deadline_ms - 1).is_none());
    }

    /// No configured deadline is always exempt.
    #[test]
    fn no_deadline_is_exempt() {
        assert!(expired_start_deadline_reason_at(None, SLOT_NEVER_OCCUPIED).is_none());
    }
}
