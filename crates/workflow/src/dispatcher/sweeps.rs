//! Sweep/timeout logic for [`Dispatcher`]: the boot orphan pass, the
//! deadline, due-wait and heartbeat sweeps, and periodic charge bookkeeping.

use super::{
    Arc, AssignmentStatus, Dispatcher, Duration, KataError, KataResult, Ulid, broadcast, debug,
    dispatcher_now_ms, emit_heartbeat_lag, info, warn,
};
use std::collections::BTreeSet;

impl Dispatcher {
    fn reconcile_after_bookkeeper_lag(&self, lagged: u64) {
        warn!(
            lagged,
            "dispatcher: bookkeeper lagged on ledger events; reconciling load charges"
        );
        self.reconcile_dispatch_charges();
    }

    /// THE BOOT PASS. Resolve every non-terminal ledger assignment that no
    /// durable recovery plan owns as `Orphaned { reason }`.
    ///
    /// Called once, at installed-main boot, from
    /// `BootRig::resume_or_orphan_in_flight_runs` and AFTER
    /// `WorkflowExecutor::recover_in_flight_runs` has prepared every
    /// lifecycle-owned execution. `protected_executions` is that recovery's
    /// `protected_execution_ids`: anything the resume path owns is SPARED here,
    /// and everything else — in-flight attempts whose execution was never
    /// recovered, executions whose lifecycle has already settled, rows the resume
    /// scan never claimed — falls through for fail-fast cleanup.
    ///
    /// Rationale: after an installed-main restart, the correlation between a
    /// previously-dispatched assignment and the worker process it was running
    /// on is gone. The worker process may still be alive, but its transport has
    /// been torn down and re-establishing it would be indistinguishable from a
    /// fresh worker connecting, so the previous assignment cannot be resumed in
    /// place. Checked-program resume re-spawns the runner and reconciles the
    /// ledger; anything outside that authority boundary is orphaned.
    ///
    /// # It is FAIL-CLOSED, and that is boot's polarity rather than a sweep's
    ///
    /// A background sweep may log a failed transition and retry on the next
    /// tick. This one has no next tick: it runs once, before readiness, and an
    /// assignment it could not durably orphan is an assignment the ledger still
    /// reports as live to every reader that comes after. So a failure aborts
    /// startup naming the assignment rather than counting the survivors — the
    /// posture `BootRig` already had, kept when the pass moved through this
    /// door.
    ///
    /// # Discovery and write are both on the authority chain
    ///
    /// The candidate population is [`Self::live_work_registry`] — every
    /// non-terminal attempt the chain holds — less `protected_executions`, and
    /// each candidate is orphaned through [`Self::mark_orphaned_and_fold_attempt`],
    /// so the discovery and the decision consult one plane. `recoverable_ids`
    /// selects `admitting` / `running` / `terminalizing`, so an execution whose
    /// lifecycle has SETTLED is never protected and its live attempts are orphaned
    /// here.
    ///
    /// Returns the number of assignments that were transitioned to `Orphaned`.
    /// Zero is the common case once the resume path has handled every in-flight
    /// execution.
    ///
    /// Synchronous: every write is a durable chain write, none of which is
    /// async. Declared on
    /// `&self` (not `self: Arc<Self>`) so the cli can call it on a
    /// bare `Dispatcher` reference during boot without juggling Arcs.
    pub fn orphan_in_flight_runs(
        &self,
        reason: impl Into<String>,
        protected_executions: &BTreeSet<Ulid>,
    ) -> KataResult<usize> {
        let reason = reason.into();
        // The per-candidate re-read comes from the same plane as the discovery,
        // and it is what carries the `execution_id` the protection test needs.
        let victims: Vec<Ulid> = self
            .live_work_registry()?
            .into_iter()
            .filter(|work| !protected_executions.contains(&work.execution_id))
            .map(|work| work.assignment_id)
            .collect();
        if victims.is_empty() {
            return Ok(0);
        }
        info!(
            count = victims.len(),
            %reason,
            "dispatcher: orphaning non-terminal assignments from previous boot"
        );
        let mut orphaned = 0usize;
        for id in victims {
            self.mark_orphaned_and_fold_attempt(id, reason.clone())
                .map_err(|error| {
                    KataError::Storage(format!(
                        "required recovery could not durably orphan assignment {id}: {error}"
                    ))
                })?;
            orphaned += 1;
        }
        Ok(orphaned)
    }

    /// Background task that keeps consume-once dispatch charges synchronized
    /// with ledger transitions, including startup, periodic, and lag recovery.
    ///
    /// Spawn this once per dispatcher, typically at the start of
    /// `run_installed_main`/`run_local_main`:
    ///
    /// ```ignore
    /// let dispatcher = Arc::new(Dispatcher::new(...));
    /// let bg = Arc::clone(&dispatcher);
    /// tokio::spawn(async move { bg.run_bookkeeper().await });
    /// ```
    ///
    /// The task exits cleanly when the ledger's broadcast channel is
    /// closed (i.e. the ledger is dropped).
    pub async fn run_bookkeeper(self: Arc<Self>) {
        let mut rx = self.ledger.subscribe();
        let mut reconciliation = tokio::time::interval(Duration::from_secs(1));
        reconciliation.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        self.reconcile_dispatch_charges();
        loop {
            tokio::select! {
                event = rx.recv() => match event {
                    Ok(event) => self.on_event(&event),
                    Err(broadcast::error::RecvError::Lagged(n)) => {
                        self.reconcile_after_bookkeeper_lag(n);
                    }
                    Err(broadcast::error::RecvError::Closed) => {
                        debug!("dispatcher: bookkeeper exiting — ledger channel closed");
                        return;
                    }
                },
                _ = reconciliation.tick() => {
                    self.reconcile_dispatch_charges();
                }
            }
        }
    }

    /// Deterministic receiver-lag witness: subscribe, reconcile startup, pause
    /// behind semaphores while the producer overruns the buffer, then execute the
    /// same lag handler as production. No wall-clock sleeps.
    #[cfg(test)]
    async fn run_bookkeeper_lag_witness(
        self: Arc<Self>,
        mut rx: broadcast::Receiver<()>,
        ready: Arc<tokio::sync::Semaphore>,
        resume: Arc<tokio::sync::Semaphore>,
        reconciled: Arc<tokio::sync::Semaphore>,
    ) {
        self.reconcile_dispatch_charges();
        ready.add_permits(1);
        resume.acquire().await.unwrap().forget();
        let Err(broadcast::error::RecvError::Lagged(n)) = rx.recv().await else {
            panic!("capacity-one receiver must report lag after the controlled overrun");
        };
        self.reconcile_after_bookkeeper_lag(n);
        reconciled.add_permits(1);
    }

    /// Deterministic witness for the production periodic reconciliation arm.
    #[cfg(test)]
    async fn run_bookkeeper_periodic_witness(
        self: Arc<Self>,
        ready: Arc<tokio::sync::Semaphore>,
        reconciled: Arc<tokio::sync::Semaphore>,
    ) {
        let mut interval = tokio::time::interval(Duration::from_secs(1));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        interval.tick().await;
        self.reconcile_dispatch_charges();
        ready.add_permits(1);
        interval.tick().await;
        self.reconcile_dispatch_charges();
        reconciled.add_permits(1);
    }

    /// Background task that periodically sweeps the heartbeat
    /// monitor for dead workers and feeds each dead worker
    /// id into [`Dispatcher::handle_worker_death`].
    ///
    /// Without this sweep nothing in production would mark a worker dead
    /// while its connection stays open, so a worker process that stopped
    /// running (frozen, wedged, descheduled for good) would silently orphan
    /// its in-flight stages. It catches the PROCESS, not a hung turn: the
    /// heartbeat is the worker loop's own task and keeps beating while a turn
    /// hangs, which the capsule's wall-time leg bounds instead. A worker whose
    /// connection closes is settled by its reactor at once, without waiting
    /// for this sweep. With it, a worker past `interval + grace` of OBSERVED
    /// silence (`HeartbeatMonitor::sweep`, which charges a stall of the sweep
    /// itself at most one interval) is marked dead, and its in-flight capsule
    /// attempts are settled proven not performed or proven ambiguous — never
    /// redispatched. A dead worker that is the main's supervised node is killed
    /// with everything it started before anything settles, and never heartbeats
    /// again (`handle_worker_death`). A dead worker is settled again at every
    /// sweep until it heartbeats: an attempt whose placement read the worker alive just before
    /// its verdict and committed just after is settled at the next sweep, not
    /// left to the start deadline or wall time, and a settlement that failed is
    /// retried there. Once its connection is gone and a sweep's settlement leaves
    /// nothing on it, the worker is forgotten (`forget_settled_dead_worker`).
    ///
    /// Spawn once per dispatcher, typically next to `run_bookkeeper`:
    ///
    /// ```ignore
    /// let bg = Arc::clone(&dispatcher);
    /// let hb = Arc::clone(&heartbeat);
    /// let interval = Duration::from_millis(cfg.workers.heartbeat_interval_ms);
    /// tokio::spawn(async move {
    ///     bg.run_heartbeat_sweep(hb, interval).await;
    /// });
    /// ```
    ///
    /// Exits only when the dispatcher is dropped (tokio::spawn keeps
    /// the task alive as long as one `Arc<Dispatcher>` lives and the
    /// runtime is up).
    pub async fn run_heartbeat_sweep(
        self: Arc<Self>,
        heartbeat: Arc<kata_transport::heartbeat::HeartbeatMonitor>,
        interval: Duration,
    ) {
        let mut ticker = tokio::time::interval(interval);
        // Skip the immediate-fire tick — we don't want to flag
        // workers as dead the moment we start the loop.
        ticker.tick().await;
        loop {
            ticker.tick().await;

            if !self.startup_recovery_dispatch_is_open() {
                continue;
            }

            // Refresh kata_worker_heartbeat_lag_seconds{worker_id} every
            // sweep tick so operators can alert as a worker's silence
            // approaches the heartbeat timeout. Read-only; runs before the
            // stale/dead checks so the gauge reflects the same instant.
            emit_heartbeat_lag(&heartbeat);

            // Refresh kata_dispatch_permits_available on the same tick. Without
            // this the gauge would latch at its last acquisition-time reading and
            // a quiesced dispatcher would look permanently saturated; with it, an
            // idle dispatcher reports the full configured cap. Read-only.
            self.emit_dispatch_permits_available();

            // ONE judgement per tick, every verdict read at the tick's instant
            // (`HeartbeatMonitor::sweep` charges each worker at most one interval
            // of the main's own stall). Taken before the stall notifications
            // below, whose durable writes would otherwise widen the silence the
            // dead verdict then reads.
            let verdict = heartbeat.sweep();
            for (worker_id, last_heartbeat_at_ms, stalled_for_secs) in verdict.stale {
                self.broadcast_worker_stalls(&worker_id, last_heartbeat_at_ms, stalled_for_secs);
            }
            for silent in &verdict.dead {
                info!(
                    worker_id = %silent.worker_id,
                    observed_silence_ms = silent.observed_silence.as_millis(),
                    last_heartbeat_age_ms = silent.last_heartbeat_age.as_millis(),
                    "heartbeat sweep: worker missed heartbeats; triggering death handling"
                );
            }
            for silent in verdict.dead.into_iter().chain(verdict.still_dead) {
                let worker_id = silent.worker_id.clone();
                let loss = super::WorkerLoss::HeartbeatSilence(silent);
                match self.handle_worker_death(&worker_id, &loss).await {
                    Ok(_) => self.forget_settled_dead_worker(&heartbeat, &worker_id),
                    Err(e) => warn!(
                        %worker_id,
                        error = %e,
                        "heartbeat sweep: handle_worker_death failed"
                    ),
                }
            }
        }
    }

    /// Stop judging a dead worker once nothing can still be settled on it: the
    /// supervisor no longer holds its connection, so no frame can be delivered to it
    /// (a placement that commits after the drop is settled undelivered at the send),
    /// and the death leg that just ran left no non-terminal attempt attributed to it.
    /// Until both hold the worker stays dead in the monitor and is settled again at
    /// every sweep — an attempt placed on it after its verdict, or a settlement that
    /// failed, is caught there. Local capacity mints a fresh worker id per connection,
    /// so without this every closed connection would be re-settled at every sweep for
    /// the main's whole uptime.
    fn forget_settled_dead_worker(
        &self,
        heartbeat: &kata_transport::heartbeat::HeartbeatMonitor,
        worker_id: &str,
    ) {
        if self.supervisor.get_worker(worker_id).is_some() {
            return;
        }
        match self.non_terminal_assignments_on_worker(worker_id) {
            Ok(held) if held.is_empty() => {
                if heartbeat.forget_dead(worker_id) {
                    info!(%worker_id, "heartbeat sweep: forgot a dead worker whose connection is gone and that holds nothing");
                }
            }
            Ok(_) => {}
            Err(e) => warn!(
                %worker_id,
                error = %e,
                "heartbeat sweep: could not read a dead worker's attempts; it stays judged"
            ),
        }
    }

    /// Emit the one-time informational `Stalled` frame for every
    /// non-terminal assignment of a worker that has missed a heartbeat interval
    /// but is still inside the grace window. Returns how many NEW stalls this
    /// call observed (the dedup admissions), which is what makes it testable.
    ///
    /// # This is a POPULATION read, and the liveness classification alone does not
    /// license reading it off the ledger
    ///
    /// The read is LIVENESS by product — a `broadcast_stalled` frame, a counter
    /// and a `warn!`, none of which mutates durable state, gates a dispatch or
    /// settles an assignment — but *"both planes go dark together"* does not
    /// apply here: the DISCOVERY is `HeartbeatMonitor::sweep`'s stale verdict, not a plane.
    /// So a ledger read would let the sweep find every stale worker and then read
    /// an empty population for each, and stall detection would stop entirely for
    /// every worker — a capability loss with nothing to notice it. That is the
    /// same shape as `handle_worker_death`'s discovery: the leg does not degrade,
    /// it goes DARK.
    ///
    /// It therefore uses [`Dispatcher::non_terminal_assignments_on_worker`], the
    /// POPULATION form of `settled_attempt_pre_image` and the *same question* the
    /// worker-death leg already asks of the same worker id — one construction, not
    /// a second union spelled here.
    ///
    /// # The `Err` polarity is DECIDED rather than propagated, and here is the
    /// reason
    ///
    /// The host (`run_heartbeat_sweep`) is a `-> ()` background loop, so `?` is
    /// unavailable and the choice is real. It is decided as **SKIP THIS WORKER
    /// THIS TICK**, spelled once in [`Self::stall_candidates_or_skip`]:
    ///
    /// * **Not abort.** The stale-worker pass runs AHEAD of the dead-worker pass
    ///   in the same tick, and that one settles a dead worker's durable work. An
    ///   unreadable plane must not take crash recovery down to spare an advisory
    ///   notification.
    /// * **Not "treat as empty".** Empty and unreadable are distinguished by the
    ///   `Result` and never by the length — the rule `live_work_registry` states
    ///   on itself. Collapsing them here would make a plane that cannot be read
    ///   indistinguishable from a worker that holds no work — the ambiguity behind
    ///   a data-loss class. The polarity is
    ///   carried in the TYPE (`Option<Vec<_>>`) rather than in a comment, so the
    ///   two answers cannot be conflated by a later edit.
    /// * **Self-healing, by construction.** A stall's dedup key is claimed only
    ///   for a stall this call actually observed, so a skipped tick leaves the
    ///   `(assignment_id, last_heartbeat_at_ms)` key unclaimed and the next tick
    ///   re-observes the same stall. The cost of a skip is bounded by one
    ///   heartbeat interval, and nothing durable is lost.
    ///
    /// Each observation is captured transactionally on the authority chain as
    /// record-only history. The global delivery projector publishes it without
    /// changing lifecycle state. A failed capture releases the dedup key so the
    /// next tick can retry; a missing or no-longer-matching attempt is skipped.
    pub(super) fn broadcast_worker_stalls(
        &self,
        worker_id: &smol_str::SmolStr,
        last_heartbeat_at_ms: u64,
        stalled_for_secs: u64,
    ) -> usize {
        let discovered = self.non_terminal_assignments_on_worker(worker_id.as_str());
        let Some(candidates) = Self::stall_candidates_or_skip(discovered, worker_id) else {
            return 0;
        };
        let mut observed = 0usize;
        for assignment_id in candidates {
            // The same placement section guards retirement, so a discovered
            // candidate cannot recreate dedup state after local cleanup.
            let _ownership = self.placement_ownership.section(assignment_id);
            match self.settled_attempt_pre_image(assignment_id) {
                Ok(Some(state)) if !state.is_terminal() => {}
                Ok(_) => continue,
                Err(error) => {
                    warn!(%error, %assignment_id, "stall observation deferred because lifecycle authority is unreadable");
                    continue;
                }
            }
            if self
                .assignments
                .claim_stall(assignment_id, last_heartbeat_at_ms)
            {
                let observation = i64::try_from(last_heartbeat_at_ms).and_then(|heartbeat| {
                    i64::try_from(stalled_for_secs).map(|duration| (heartbeat, duration))
                });
                let recorded = match observation {
                    Ok((heartbeat, duration)) => self
                        .execution_lifecycle()
                        .db()
                        .record_attempt_stalled(assignment_id, worker_id, heartbeat, duration),
                    Err(error) => Err(kata_types::KataError::Validation(error.to_string())),
                };
                match recorded {
                    Ok(Some(_)) => {}
                    Ok(None) => {
                        self.assignments
                            .release_stall(assignment_id, last_heartbeat_at_ms);
                        continue;
                    }
                    Err(error) => {
                        self.assignments
                            .release_stall(assignment_id, last_heartbeat_at_ms);
                        warn!(%error, %assignment_id, "failed to record stalled observation");
                        continue;
                    }
                }
                metrics::counter!(
                    "kata_workflow_stages_stalled_total",
                    "worker" => worker_id.to_string(),
                )
                .increment(1);
                warn!(
                    %worker_id,
                    %assignment_id,
                    stalled_for_secs,
                    "stage.stalled"
                );
                observed += 1;
            }
        }
        observed
    }

    /// The stall sweep's `Err` polarity, spelled ONCE and in the TYPE.
    ///
    /// `None` is UNREADABLE — skip this worker this tick, retried on the next one
    /// because nothing was deduped. `Some(vec![])` is READABLE AND EMPTY — this
    /// worker genuinely holds no non-terminal work, and there is nothing to
    /// retry. The two are deliberately not the same value; see
    /// [`Self::broadcast_worker_stalls`] for why the decision is a skip and not a
    /// propagation, an abort, or a collapse to empty.
    ///
    /// Associated rather than inline so both directions are unit-testable without
    /// having to make a live database fail.
    fn stall_candidates_or_skip(
        discovered: KataResult<Vec<Ulid>>,
        worker_id: &smol_str::SmolStr,
    ) -> Option<Vec<Ulid>> {
        match discovered {
            Ok(candidates) => Some(candidates),
            Err(error) => {
                warn!(
                    %worker_id,
                    %error,
                    "heartbeat sweep: the deciding plane could not be read for this stalled \
                     worker; skipping its stall notification this tick (retried next tick — \
                     nothing was deduped). NOT an empty population: no durable state is \
                     changed here either way, and the dead-worker pass below is unaffected"
                );
                None
            }
        }
    }

    /// Background task for the deadline sweeps: capsule wall-time and
    /// start-deadline, abandoned claims/invocations/waits, and due main waits.
    ///
    /// Spawn once per dispatcher next to `run_heartbeat_sweep` — `BootRig`
    /// does this for installed and explicit scratch mains. The first interval tick is
    /// consumed so the task does not immediately fail (or re-dispatch)
    /// restored assignments before resume/orphan boot policy has rehydrated
    /// checked dispatch authority.
    ///
    /// # The due-wait leg runs ONCE as soon as startup recovery opens
    ///
    /// Skipping the first tick would make a main-resolved timer whose deadline passed
    /// while the main was down fire a FULL heartbeat interval after the restart
    /// (measured at 10.0–10.6 s after the gate opened). So the task waits for the gate and
    /// runs [`Self::sweep_due_waits`] at once — after recovery activated the runners,
    /// whose folds then observe the acceptance — and only then settles into the ticker.
    pub async fn run_assignment_deadline_sweep(self: Arc<Self>, interval: Duration) {
        let mut ticker = tokio::time::interval(interval);
        ticker.tick().await;
        self.wait_for_startup_recovery_dispatch().await;
        self.run_due_wait_leg(dispatcher_now_ms());
        loop {
            ticker.tick().await;
            self.run_deadline_sweep_tick(dispatcher_now_ms()).await;
        }
    }

    /// One deadline/wait sweep pass over the durable chain.
    ///
    /// Extracted from the loop so a test can drive one deterministic tick.
    /// Best-effort per leg: an error is logged and the pass continues.
    pub(crate) async fn run_deadline_sweep_tick(&self, now_ms: u64) {
        if !self.startup_recovery_dispatch_is_open() {
            return;
        }
        // The legs that DO NOT read the live-work registry run FIRST and regardless of it:
        // each discovers from its own read, so an unreadable registry (one undecodable
        // live attempt row) must not stall them, or every due timer would be skipped.
        //
        // An `Invoke` a latched parent abandoned, FIRST: the child it latches
        // is `terminalizing` from here, so the legs below settle its claims and waits in
        // this same tick.
        if let Err(error) = self.settle_abandoned_invocations() {
            warn!(%error, "abandoned invocation sweep failed");
        }
        // A capsule attempt's own promised wall clock, which the
        // due-wait leg below cannot read (its population is main-resolved waits).
        if let Err(error) = self.sweep_capsule_wall_time(now_ms).await {
            warn!(%error, "capsule wall-time sweep failed");
        }
        if let Err(error) = self.sweep_capsule_start_deadline(now_ms).await {
            warn!(%error, "capsule start-deadline sweep failed");
        }
        // ...and a capsule CLAIM no dispatch reached whose execution has latched its
        // outcome, which no runner will resume and so no other leg reaches.
        if let Err(error) = self.settle_abandoned_capsule_claims() {
            warn!(%error, "abandoned capsule-claim sweep failed");
        }
        // The MAIN-RESOLVED waits, which the registry excludes by
        // name: first a wait whose execution latched its outcome, so a latched execution's
        // timer is cancelled rather than accepted; then every due timer.
        if let Err(error) = self.settle_abandoned_main_attempts() {
            warn!(%error, "abandoned main-wait sweep failed");
        }
        self.run_due_wait_leg(now_ms);
    }

    /// The due-wait leg, best-effort like every leg of the tick: a failure is logged.
    fn run_due_wait_leg(&self, now_ms: u64) {
        match self.sweep_due_waits(i64::try_from(now_ms).unwrap_or(i64::MAX)) {
            Ok(woken) if !woken.is_empty() => {
                info!(
                    count = woken.len(),
                    "due-wait sweep accepted durable timers"
                );
            }
            Ok(_) => {}
            Err(error) => warn!(%error, "due-wait sweep failed"),
        }
    }

    /// Background task that logs every terminal ledger transition
    /// with an `elapsed_ms` field computed from the assignment's
    /// dispatched_at_ms / finished_at_ms timestamps.
    ///
    /// Completed stages log at INFO; Failed / Orphaned at WARN.
    /// `elapsed_ms` is 0 if either timestamp is missing (edge case
    /// for pre-dispatch failures).
    ///
    /// Spawn once per dispatcher:
    ///
    /// ```ignore
    /// let bg = Arc::clone(&dispatcher);
    /// tokio::spawn(async move { bg.run_timing_logger().await });
    /// ```
    ///
    /// Exits cleanly when the ledger broadcast channel closes.
    ///
    /// # It stays on the LEDGER plane, and it is provably unable to DECIDE
    ///
    /// Classified LIVENESS: every arm below is an `info!`/`warn!`, and both the
    /// discovery (`self.ledger.subscribe()`) and the per-event read are the same
    /// plane, so the two go dark together rather than disagreeing. Repointing the
    /// per-event read alone would be strictly WORSE — a chain read behind a
    /// ledger broadcast consults two planes inside one decision, bought for an ops
    /// log line.
    ///
    /// "Liveness" is not enough on its own: an absent row must not `continue` and
    /// suppress the whole terminal log line. [`Self::terminal_elapsed_ms`] is
    /// TOTAL over the absence, so the only fact crossing out of the ledger plane is
    /// a `u64` duration
    /// carrying no identity, no status and no plane fact — and there is no arm left
    /// for a caller to take on `None`. Every other field logged below comes off the
    /// EVENT.
    pub async fn run_timing_logger(self: Arc<Self>) {
        let mut rx = self.ledger.subscribe();
        loop {
            match rx.recv().await {
                Ok(event) => {
                    if !event.new_status.is_terminal() {
                        continue;
                    }
                    let elapsed_ms = self.terminal_elapsed_ms(event.assignment_id);
                    match &event.new_status {
                        AssignmentStatus::Completed { worker_id } => {
                            info!(
                                assignment_id = %event.assignment_id,
                                stage = %event.stage_name,
                                worker = worker_id.as_deref(),
                                elapsed_ms,
                                "stage completed"
                            );
                        }
                        AssignmentStatus::Failed { worker_id, reason } => {
                            // Flatten `Option<SmolStr>` into a plain
                            // string field so ops dashboards that
                            // parse `worker=<name>` don't choke on
                            // `Some("w1")`: the field is always
                            // `worker=<name>`.
                            let worker = worker_id.as_deref().unwrap_or("none");
                            warn!(
                                assignment_id = %event.assignment_id,
                                stage = %event.stage_name,
                                worker,
                                elapsed_ms,
                                reason = %reason,
                                "stage failed"
                            );
                        }
                        // THE OPS LINE AN OPERATOR CANCEL PRODUCES. `is_terminal()`
                        // above includes `Cancelled`, so the cancel reaches this
                        // match; without its own arm it would fall into the
                        // catch-all below, silently dropping the single terminal
                        // line that carries `elapsed_ms` and the suppressed-retry
                        // reason.
                        AssignmentStatus::Cancelled { worker_id, reason } => {
                            let worker = worker_id.as_deref().unwrap_or("none");
                            warn!(
                                assignment_id = %event.assignment_id,
                                stage = %event.stage_name,
                                worker,
                                elapsed_ms,
                                reason = %reason,
                                "stage cancelled"
                            );
                        }
                        AssignmentStatus::Orphaned {
                            prev_worker,
                            reason,
                        } => {
                            let worker = prev_worker.as_deref().unwrap_or("none");
                            warn!(
                                assignment_id = %event.assignment_id,
                                stage = %event.stage_name,
                                worker,
                                elapsed_ms,
                                reason = %reason,
                                "stage orphaned"
                            );
                        }
                        // THE NON-TERMINALS ARE SPELLED OUT, AND THE `_ => {}`
                        // THAT STOOD HERE IS WHY THE CANCEL WENT UNLOGGED. Its
                        // comment claimed "is_terminal() above already filtered
                        // every non-terminal variant, so this arm is
                        // unreachable" — true when written, and made false by a
                        // new terminal that the wildcard then swallowed in
                        // silence. Listing them makes the compiler, rather than
                        // a comment, hold the claim: a new variant lands here as
                        // a build error and has to be classified.
                        AssignmentStatus::Pending
                        | AssignmentStatus::AwaitingApproval { .. }
                        | AssignmentStatus::AwaitingChildCompletion { .. }
                        | AssignmentStatus::Dispatched { .. }
                        | AssignmentStatus::Running { .. }
                        | AssignmentStatus::Stalled { .. } => {}
                    }
                }
                Err(broadcast::error::RecvError::Lagged(n)) => {
                    warn!(lagged = n, "timing logger lagged on ledger events");
                }
                Err(broadcast::error::RecvError::Closed) => {
                    debug!("timing logger exiting — ledger channel closed");
                    return;
                }
            }
        }
    }

    /// How long one terminal transition took, for a LOG FIELD and nothing else.
    ///
    /// # TOTAL over the absence, and that is the whole point
    ///
    /// The `-> u64` is the enforcement, not a convenience. An `Option` here would
    /// hand [`Self::run_timing_logger`] an arm to take on "the plane holds no row"
    /// — an absent-row gate: a `continue` there would make a terminal transition
    /// produce NO ops line at all. The line is always emitted and the duration is
    /// `0` — the same value this logger reports for a pre-dispatch failure whose
    /// anchors are missing.
    ///
    /// `0` therefore means "no measurable interval on the plane that carries the
    /// anchors", never "this assignment does not exist"; the assignment's existence
    /// is asserted by the EVENT that arrived, which no absence here can retract.
    fn terminal_elapsed_ms(&self, assignment_id: Ulid) -> u64 {
        self.execution_lifecycle()
            .db()
            .attempt(assignment_id)
            .ok()
            .flatten()
            .map_or(0, |row| match (row.dispatched_at_ms, row.finished_at_ms) {
                (Some(dispatched), Some(finished)) => {
                    finished.saturating_sub(dispatched).try_into().unwrap_or(0)
                }
                _ => 0,
            })
    }
}

#[cfg(test)]
mod bookkeeper_tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU32, Ordering};

    use kata_core::InFlightLedger;
    use kata_core::operational::{AttemptClaimSpec, CommandSpec, OccurrenceBinding};
    use kata_test_utils::sample_capsule_assignment;
    use kata_transport::heartbeat::HeartbeatMonitor;
    use kata_transport::supervisor::WorkerPoolSupervisor;
    use kata_transport::types::DispatchFrame;
    use smol_str::SmolStr;
    use tokio::sync::Semaphore;
    use ulid::Ulid;

    use super::super::Dispatcher;

    /// Claim a capsule attempt on the chain and PLACE it on `worker_id` — the
    /// seed every charge-reconcile witness needs: an attempt whose durable row
    /// says `dispatched` on the worker the charge is acquired against.
    fn seed_dispatched_capsule(
        dispatcher: &Dispatcher,
        execution_id: Ulid,
        attempt_id: Ulid,
        stage: &str,
        worker_id: &str,
    ) {
        dispatcher
            .ensure_rig_nucleus_admission(execution_id)
            .unwrap();
        let capsule = {
            let mut c = sample_capsule_assignment();
            c.execution_id = execution_id;
            c.attempt_id = attempt_id;
            c
        };
        let face = dispatcher.execution_lifecycle();
        let db = face.db();
        db.claim_attempt(
            execution_id,
            attempt_id,
            &AttemptClaimSpec {
                stage_id: stage.to_string(),
                assignment_json: serde_json::to_vec(&DispatchFrame::Capsule(Box::new(capsule)))
                    .unwrap(),
                initial_state: "pending".to_string(),
                run_ordinal: 0,
                worker_id: None,
                occurrence: OccurrenceBinding::for_test(execution_id, stage),
            },
        )
        .unwrap();
        db.dispatch_claimed_attempt(
            attempt_id,
            worker_id,
            Ulid::new(),
            &CommandSpec {
                command_json: b"{\"cmd\":1}".to_vec(),
            },
        )
        .unwrap();
    }

    #[kata_test_utils::kata_timeout]
    #[tokio::test]
    async fn startup_and_actual_receiver_lag_reconcile_the_owned_charge() {
        let ledger = InFlightLedger::in_memory_with_capacity(1);
        let dispatcher = Arc::new(Dispatcher::new(
            Arc::new(WorkerPoolSupervisor::new()),
            Arc::new(HeartbeatMonitor::new(
                std::time::Duration::from_millis(50),
                std::time::Duration::from_millis(50),
            )),
            Arc::clone(&ledger),
        ));
        let execution_id = Ulid::new();
        let assignment_id = Ulid::new();
        let domain = dispatcher
            .enroll_worker_membrane(
                "bookkeeper-lag-fixture",
                kata_types::identity::WorkerMembraneId(ulid::Ulid::new()),
            )
            .unwrap();
        let (home, _worker) = kata_transport::InProcessTransport::pair(4);
        dispatcher.supervisor.register_worker_with_effect_domain(
            SmolStr::new("w1"),
            Arc::new(home),
            Vec::new(),
            crate::test_harness::rig_worker_containment(),
            *crate::test_harness::oci_rig_executor_term().digest(),
            domain,
        );
        seed_dispatched_capsule(
            &dispatcher,
            execution_id,
            assignment_id,
            "lagged-charge",
            "w1",
        );
        let dispatch_token = dispatcher.mint_dispatch_token();
        {
            let mut ownership = dispatcher.placement_ownership.section(assignment_id);
            ownership.claim(dispatch_token);
        }
        let counter = Arc::new(AtomicU32::new(0));
        dispatcher.dispatch_charges.acquire(
            assignment_id,
            dispatch_token,
            SmolStr::new("w1"),
            Arc::clone(&counter),
        );

        let ready = Arc::new(Semaphore::new(0));
        let resume = Arc::new(Semaphore::new(0));
        let reconciled = Arc::new(Semaphore::new(0));
        // Wakeup lag is independent of authoritative lifecycle history. Mirror
        // inserts publish no lifecycle events, so overrun the actual broadcast
        // protocol directly.
        let (wakeups, receiver) = tokio::sync::broadcast::channel(1);
        let task = tokio::spawn(Arc::clone(&dispatcher).run_bookkeeper_lag_witness(
            receiver,
            Arc::clone(&ready),
            Arc::clone(&resume),
            Arc::clone(&reconciled),
        ));
        ready.acquire().await.unwrap().forget();
        assert_eq!(
            counter.load(Ordering::Relaxed),
            1,
            "startup reconciliation retains the authoritative live placement"
        );

        dispatcher
            .mark_completed_and_fold_attempt(assignment_id, serde_json::json!({"ok": true}))
            .unwrap();
        wakeups.send(()).unwrap();
        wakeups.send(()).unwrap();
        resume.add_permits(1);
        reconciled.acquire().await.unwrap().forget();
        task.await.unwrap();
        assert_eq!(
            counter.load(Ordering::Relaxed),
            0,
            "the lag handler reconstructs terminal ownership instead of dropping events"
        );
    }

    #[kata_test_utils::kata_timeout]
    #[tokio::test]
    async fn periodic_reconciliation_converges_without_consuming_the_terminal_event() {
        let ledger = InFlightLedger::in_memory();
        let dispatcher = Arc::new(Dispatcher::new(
            Arc::new(WorkerPoolSupervisor::new()),
            Arc::new(HeartbeatMonitor::new(
                std::time::Duration::from_millis(50),
                std::time::Duration::from_millis(50),
            )),
            Arc::clone(&ledger),
        ));
        let execution_id = Ulid::new();
        let assignment_id = Ulid::new();
        seed_dispatched_capsule(
            &dispatcher,
            execution_id,
            assignment_id,
            "periodic-charge",
            "w1",
        );
        let dispatch_token = dispatcher.mint_dispatch_token();
        {
            let mut ownership = dispatcher.placement_ownership.section(assignment_id);
            ownership.claim(dispatch_token);
        }
        let counter = Arc::new(AtomicU32::new(0));
        dispatcher.dispatch_charges.acquire(
            assignment_id,
            dispatch_token,
            SmolStr::new("w1"),
            Arc::clone(&counter),
        );

        let ready = Arc::new(Semaphore::new(0));
        let reconciled = Arc::new(Semaphore::new(0));
        let task = tokio::spawn(
            Arc::clone(&dispatcher)
                .run_bookkeeper_periodic_witness(Arc::clone(&ready), Arc::clone(&reconciled)),
        );
        ready.acquire().await.unwrap().forget();
        dispatcher
            .mark_completed_and_fold_attempt(assignment_id, serde_json::json!({"ok": true}))
            .unwrap();
        reconciled.acquire().await.unwrap().forget();
        task.await.unwrap();
        assert_eq!(
            counter.load(Ordering::Relaxed),
            0,
            "the periodic pass converges even though this witness never reads the broadcast"
        );
    }
}
