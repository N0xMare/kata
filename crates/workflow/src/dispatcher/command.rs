//! Command-handling methods for [`Dispatcher`]: execution-program
//! registration, checked-command validation, and command bookkeeping.

use smol_str::SmolStr;

use super::{
    AssignmentStatus, AssignmentTiming, CheckedProgramAuthority, Dispatcher, ExecutionProgram,
    INFLIGHT_DEPTH_GAUGE, InflightSeries, Instant, KataResult, LedgerEvent, Ordering, Ulid, debug,
};

impl Dispatcher {
    pub(crate) fn retain_execution_program(
        self: &std::sync::Arc<Self>,
        execution_id: Ulid,
        program: &ExecutionProgram,
    ) -> KataResult<super::ExecutionProgramLease> {
        self.checked_program_authority
            .register(execution_id, Self::program_authority(program))?;
        Ok(super::ExecutionProgramLease {
            dispatcher: std::sync::Arc::clone(self),
            execution_id,
        })
    }

    fn program_authority(program: &ExecutionProgram) -> CheckedProgramAuthority {
        let input_timeouts = kata_program::execution_program::blocking_input_requests(program)
            .enumerate()
            .filter_map(|(index, request)| {
                kata_program::execution_program::lower_blocking_request(program, index)
                    .ok()
                    .map(|lowered| {
                        (
                            lowered.path.program_operation_stage_id(),
                            kata_program::execution_program::input_wait::InputWaitRecord::timeout_default(
                                request,
                            )
                            .to_output(),
                        )
                    })
            })
            .collect();
        CheckedProgramAuthority {
            program_hash: program.program_hash,
            input_timeouts,
        }
    }

    /// Publish the current main-side queue depth as the
    /// `kata_worker_queue_depth` gauge.
    #[allow(clippy::cast_precision_loss)] // queue depth is tiny; matches the crate's other gauge casts (cache.rs, budget.rs)
    fn emit_queue_depth(depth: i64) {
        metrics::gauge!("kata_worker_queue_depth").set(depth as f64);
    }

    /// Charge this assignment to one `kata_worker_inflight_depth`
    /// series, releasing whichever series it held before.
    ///
    /// Idempotent on a repeat of the SAME (worker, status) pair — a redispatch
    /// to the worker that already holds the assignment is still one assignment
    /// in flight, and the ledger does replay a `Dispatched` onto the same
    /// worker on the send-failure fallback leg.
    fn charge_inflight(timing: &mut AssignmentTiming, worker_id: &SmolStr, status: &'static str) {
        if let Some(held) = &timing.inflight
            && held.worker_id == *worker_id
            && held.status == status
        {
            return;
        }
        Self::release_inflight(timing);
        metrics::gauge!(
            INFLIGHT_DEPTH_GAUGE,
            "worker_id" => worker_id.to_string(),
            "status" => status,
        )
        .increment(1.0);
        timing.inflight = Some(InflightSeries {
            worker_id: worker_id.clone(),
            status,
        });
    }

    /// Release whatever `kata_worker_inflight_depth` series this
    /// assignment was charged to. A no-op for an assignment that is not on a
    /// worker, so every release site can call it unconditionally.
    fn release_inflight(timing: &mut AssignmentTiming) {
        if let Some(series) = timing.inflight.take() {
            metrics::gauge!(
                INFLIGHT_DEPTH_GAUGE,
                "worker_id" => series.worker_id.to_string(),
                "status" => series.status,
            )
            .decrement(1.0);
        }
    }

    /// Fold one accepted ledger transition into the worker /
    /// dispatch-plane metrics:
    ///
    /// - `kata_worker_queue_depth` (gauge) — count of `Pending`,
    ///   not-yet-dispatched assignments.
    /// - `kata_worker_inflight_depth` (gauge, `worker_id` + `status`) —
    ///   count of assignments HANDED to a worker and not yet
    ///   finished, split by whether that worker has acknowledged them.
    /// - `kata_worker_submit_to_dispatch_seconds` (histogram) — queue wait, from
    ///   the assignment entering `Pending` to its first `Dispatched`.
    /// - `kata_worker_dispatch_to_start_seconds` (histogram) — from `Dispatched`
    ///   to the worker's `Running` start-checkpoint (dispatch → actual start).
    ///
    /// Event timing is folded by the bookkeeper; direct terminal cleanup also
    /// consumes timing. Both serialize through assignment lifecycle ownership.
    ///
    /// # Why the two gauges are one accounting and not two metrics
    ///
    /// `kata_worker_queue_depth` decrements on `Dispatched` — hand-off to the
    /// transport, not completion — and *"a cap nobody can see in the gauge is a
    /// cap nobody can tune"*: without the in-flight gauge, the backlog a
    /// per-worker cap would bound accumulates precisely in the window the queue
    /// gauge stops counting, so it reads `0` while the backlog grows.
    ///
    /// The `Dispatched` arm below does both halves of that hand-off in one
    /// place: it releases the queue slot AND charges the worker. So an
    /// assignment the main is responsible for is counted in exactly one of the
    /// two gauges — [`AssignmentTiming::counted_in_queue`] and
    /// [`AssignmentTiming::inflight`] are mutually exclusive by construction —
    /// and a backlog can no longer vanish between them. The parked state
    /// (`AwaitingChildCompletion`) holds neither, which is the truth: it is on no
    /// queue and no worker.
    fn record_queue_plane_metrics(&self, event: &LedgerEvent) {
        let id = event.assignment_id;
        // Serialize the authority check with local retirement and placement.
        // A delayed Pending must not recreate timing after terminal cleanup, and
        // a delayed terminal must not consume a live retry successor's gauges.
        let _ownership = self.placement_ownership.section(id);
        match self.settled_attempt_pre_image(id) {
            Ok(Some(state)) if state.is_terminal() || event.new_status.is_terminal() => {
                return;
            }
            Err(error) => {
                tracing::warn!(%error, assignment_id = %id, "timing update deferred because lifecycle authority is unreadable");
                return;
            }
            _ => {}
        }
        match &event.new_status {
            // Queue entry (fresh submit) or re-entry (requeue back to Pending).
            AssignmentStatus::Pending => {
                let now = Instant::now();
                let counted = if let Some(mut timing) = self.assignments.timing_mut(id) {
                    // Requeue: reset the submit clock and the dispatch anchor
                    // so the next dispatch measures a fresh queue wait. Only
                    // re-count into the queue if it had already left it.
                    timing.submitted_at = now;
                    timing.dispatched_at = None;
                    // A requeue un-dispatches: the worker that held this
                    // assignment no longer does, so its in-flight charge is
                    // released as the queue slot is re-taken.
                    Self::release_inflight(&mut timing);
                    if timing.counted_in_queue {
                        false
                    } else {
                        timing.counted_in_queue = true;
                        true
                    }
                } else {
                    self.assignments.insert_timing(
                        id,
                        AssignmentTiming {
                            submitted_at: now,
                            dispatched_at: None,
                            counted_in_queue: true,
                            inflight: None,
                        },
                    );
                    true
                };
                if counted {
                    let depth = self.queued_depth.fetch_add(1, Ordering::Relaxed) + 1;
                    Self::emit_queue_depth(depth);
                }
            }
            // Left the queue onto a worker.
            AssignmentStatus::Dispatched { worker_id } => {
                let now = Instant::now();
                if let Some(mut timing) = self.assignments.timing_mut(id) {
                    // Measure submit→dispatch only on the FIRST dispatch; a
                    // redispatch keeps the original queue-wait sample and just
                    // re-anchors the dispatch→start clock below.
                    if timing.dispatched_at.is_none() {
                        metrics::histogram!("kata_worker_submit_to_dispatch_seconds").record(
                            now.saturating_duration_since(timing.submitted_at)
                                .as_secs_f64(),
                        );
                    }
                    timing.dispatched_at = Some(now);
                    // The hand-off the queue gauge stops counting at: the
                    // assignment becomes this worker's unacknowledged backlog.
                    Self::charge_inflight(&mut timing, worker_id, event.new_status.tag());
                    if timing.counted_in_queue {
                        timing.counted_in_queue = false;
                        drop(timing);
                        let depth = self.queued_depth.fetch_sub(1, Ordering::Relaxed) - 1;
                        Self::emit_queue_depth(depth);
                    }
                }
            }
            // Worker acknowledged and started the stage.
            AssignmentStatus::Running { worker_id } => {
                let now = Instant::now();
                if let Some(mut timing) = self.assignments.timing_mut(id) {
                    if let Some(dispatched_at) = timing.dispatched_at {
                        metrics::histogram!("kata_worker_dispatch_to_start_seconds")
                            .record(now.saturating_duration_since(dispatched_at).as_secs_f64());
                    }
                    // Same assignment, same worker, different answer to "has
                    // this worker started it?" — the move from `dispatched` to
                    // `running` is what separates a saturated worker from one
                    // that took work and started nothing.
                    Self::charge_inflight(&mut timing, worker_id, event.new_status.tag());
                }
            }
            // Parked off both planes: a subworkflow parent is freed so its
            // child can run on the same pool. It holds no queue slot, so it may
            // not keep an in-flight charge either.
            AssignmentStatus::AwaitingChildCompletion { .. } => {
                if let Some(mut timing) = self.assignments.timing_mut(id) {
                    Self::release_inflight(&mut timing);
                }
            }
            // Terminal: drop the anchor, release the worker's in-flight charge,
            // and, if it never left the queue (e.g. an orphan before any worker
            // accepted it), release its queue slot.
            status if status.is_terminal() => {
                if let Some(timing) = self.assignments.take_timing(id) {
                    self.release_assignment_timing(timing);
                }
            }
            // `Stalled` deliberately changes NOTHING here. It does not change
            // the assignment's stored status, and a worker that has gone quiet
            // is still holding the work it was handed — a stall that silently
            // released the charge would erase the very backlog an operator is
            // reading the gauge to find.
            _ => {}
        }
    }

    pub(super) fn release_assignment_timing(&self, mut timing: AssignmentTiming) {
        Self::release_inflight(&mut timing);
        if timing.counted_in_queue {
            let depth = self.queued_depth.fetch_sub(1, Ordering::Relaxed) - 1;
            Self::emit_queue_depth(depth);
        }
    }

    /// Reconcile the consume-once load charge from authoritative state when an
    /// event is terminal.
    /// Also clears any stall-dedup entries for the assignment so ghost
    /// entries don't persist after the assignment is done.
    /// Non-terminal events and events without a worker attribution
    /// are ignored.
    pub(crate) fn on_event(&self, event: &LedgerEvent) {
        // Main-side dispatch-plane latency + queue-depth metrics,
        // driven off the same accepted-transition stream this bookkeeper already
        // consumes.
        self.record_queue_plane_metrics(event);

        // kata_worker_assignments_total{status,transport}. Counted off accepted
        // ledger transitions — the same event source the bookkeeper
        // already consumes — so each real transition counts exactly once:
        // the ledger latches terminal states and only broadcasts accepted
        // transitions. `transport` falls back to `"unknown"` for a
        // pre-dispatch failure/orphan that never reached a worker (so the
        // count is not silently dropped) — see `AssignmentStatus::worker_id`.
        //
        // THE CENSUS IS THE ENUM'S, NOT THIS SITE'S. A `matches!` list here
        // would not widen when a variant is added: an operator cancel would
        // increment `dispatched` and then emit NO terminal counterpart, so an ops
        // dashboard watching `dispatched - (completed+failed+orphaned+cancelled)`
        // as an in-flight estimate would drift up by one per cancel. A `matches!`
        // is total by DEFAULT rather than by checking, so nothing would see it.
        // `AssignmentStatus::counts_in_the_worker_lifecycle_census` answers with
        // one exhaustive `match`, which a new variant cannot be added past.
        if event.new_status.counts_in_the_worker_lifecycle_census() {
            let transport: &'static str = match event.new_status.worker_id() {
                Some(worker_id) => self
                    .supervisor
                    .get_worker(worker_id)
                    .map_or("unknown", |info| info.value().transport_kind()),
                None => "unknown",
            };
            metrics::counter!(
                "kata_worker_assignments_total",
                "status" => event.new_status.tag(),
                "transport" => transport,
            )
            .increment(1);
        }

        if !event.new_status.is_terminal() {
            return;
        }
        // Clear stall dedup entries for this assignment.
        // Prevents ghost entries from accumulating for assignments that
        // were stalled then Orphaned (the terminal transition fires here
        // before the entry would be naturally evicted by a new stall cycle).
        self.retire_terminal_assignment(event.assignment_id);
        let worker_id = event.new_status.worker_id();
        self.reconcile_dispatch_charge(event.assignment_id);
        if let Some(worker_id) = worker_id {
            debug!(
                %worker_id,
                assignment_id = %event.assignment_id,
                status = event.new_status.tag(),
                "dispatcher: reconciled dispatch charge on terminal"
            );
        }
    }
}
