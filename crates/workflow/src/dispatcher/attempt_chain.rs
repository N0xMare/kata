//! Operational authority for dispatcher admissions, mutations and placements.
//!
//! Every adjudicated mutation reads its pre-image from the operational chain
//! and commits the same transaction that records it — the chain is the only
//! plane an attempt lifecycle lives on.
//!
//! Capsule placement commits its attempt generation, command and membrane
//! binding inside `OperationalDb::dispatch_claimed_attempt` before a transport
//! frame may be sent. Process-local `DispatchToken` ownership serializes
//! competing deliveries; durable terminal and effect fences remain on the
//! operational transactions and the authorized send funnel.
//!
//! Workerless admissions have stage scope and cannot acquire worker placement.
//! Assignment amendments and audit facts retain their named chain records. This module does not make separate database commits atomic.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{self, AtomicU64};

use kata_core::operational::{
    ATTEMPT_TERMINAL_STATES, AttemptRecordKind, ChainStageState, MainSideTransition, OperationalDb,
    UndispatchedStageOutcome,
};
use kata_transport::types::DispatchFrame;
use kata_types::error::{KataError, KataResult};
use kata_types::idempotency::canonicalize_args;
use smol_str::SmolStr;
use tracing::{debug, warn};
use ulid::Ulid;

use super::Dispatcher;

/// A bare stage-scope outcome carrying no durable facts beyond the state —
/// [`UndispatchedStageOutcome`] has no `bare` of its own, so the doors build
/// one spelling here rather than naming nine fields at each site.
fn stage_outcome(state: &str) -> UndispatchedStageOutcome<'_> {
    UndispatchedStageOutcome {
        state,
        reason: None,
        child_execution_id: None,
        output: None,
        finished_at_ms: None,
        awaiting_approval_at_ms: None,
        terminal_charge: None,
    }
}

impl Dispatcher {
    /// The operational nucleus this dispatcher writes attempt facts into, or a
    /// typed refusal naming the execution it could not attribute one to.
    ///
    /// # Invariant
    ///
    /// FAILS CLOSED ON AN ABSENT ROW, matching every other dispatch/promotion gate
    /// and matching the inbox seam's own refusal. An ATTACHED nucleus is authority:
    /// an execution missing from it was never submitted, and dispatching an
    /// assignment whose attempt no plane can record is an unjustified state
    /// advance. Production always admits before dispatch
    /// (`WorkflowExecutor::require_running_lifecycle_for_dispatch`), so this
    /// refusal is production-inert.
    ///
    /// An UNATTACHED nucleus is a test rig's private scratchpad, and
    /// [`Dispatcher::ensure_rig_nucleus_admission`] gives it a coherent row through
    /// the real checked-admission seam instead: repairing the ONE constructor that
    /// mints the empty nucleus
    /// covers every rig, and editing rigs one by one leaves the next one broken.
    fn attempt_chain_nucleus(&self, execution_id: Ulid) -> KataResult<Arc<OperationalDb>> {
        let face = self.execution_lifecycle();
        if face.db().execution_lifecycle(execution_id)?.is_none() {
            return Err(KataError::Validation(format!(
                "dispatcher: refusing to dispatch assignment whose execution {execution_id} the \
                 operational nucleus does not hold"
            )));
        }
        Ok(Arc::clone(face.db()))
    }

    /// The operational nucleus for an execution the chain may or may not know.
    ///
    /// [`Self::attempt_chain_nucleus`]'s fail-CLOSED sibling for the additive
    /// main-side path. `None` means "this execution is not in the nucleus", which
    /// is a reason to record nothing and never a reason to fail a transition the
    /// caller has already committed.
    fn attempt_chain_nucleus_if_known(
        &self,
        execution_id: Ulid,
    ) -> KataResult<Option<Arc<OperationalDb>>> {
        let face = self.execution_lifecycle();
        Ok(face
            .db()
            .execution_lifecycle(execution_id)?
            .map(|_| Arc::clone(face.db())))
    }

    /// ADMIT one stage that will NEVER reach a worker, at STAGE scope on the
    /// authority chain.
    ///
    /// The single expression of "this stage is admitted and undispatchable"
    /// inside the dispatcher and the runner. Every member of the raw-insert
    /// class routes through it: the cache hit, the review-loop escalation gate,
    /// the synthetic branch-failure / branch-skip / budget-halt / bound-halt /
    /// metering-halt metadata rows, and the subworkflow parent park.
    ///
    /// # Why the class is represented at STAGE scope
    ///
    /// A cache hit is NOT an attempt, and the discriminator generalizes: every
    /// stage admitted through
    /// this door is structurally undispatchable and completes without a worker.
    /// Claiming an attempt would leave only two outcomes at settlement time,
    /// both wrong: forge a worker, or strand the attempt non-terminal in the
    /// bounded live registry forever. What IS true — the stage was satisfied
    /// without dispatch — is a stage-scope fact.
    ///
    /// # Why the chain must carry it
    ///
    /// `WorkflowRunner::run` is `Box::pin(self.run_replay())` UNCONDITIONALLY
    /// (`runner/drive.rs`), so the fold is the sole live engine and the deciding
    /// reader is TOTAL over an execution's history. A state the chain does not
    /// carry is therefore not a LAGGING state, it is an ABSENT
    /// one — and the polarity turns an absent terminal into work being redone: a
    /// cache-hit stage would replay as never-run, so the fold would re-dispatch a
    /// stage whose output is already durable, on ORDINARY runs and not merely on
    /// resumes.
    ///
    /// # Failure
    ///
    /// An execution the attached nucleus does not know is a typed refusal (see
    /// [`Self::attempt_chain_nucleus`]) — the same fail-CLOSED polarity the
    /// claiming door uses, and for the same reason: production always admits the
    /// execution before any of these rows can be produced, so the refusal is
    /// production-inert, while recording a durable terminal no plane can replay is
    /// an unjustified advance. A re-presented admission is
    /// an idempotent no-op, which the runner's synthetic-metadata emitters rely on
    /// under the pure-fold resume boot.
    pub fn admit_undispatched_stage(
        &self,
        execution_id: Ulid,
        assignment_id: Ulid,
        stage_id: &str,
        stage_name: &str,
    ) -> KataResult<()> {
        let db = self.attempt_chain_nucleus(execution_id)?;
        db.admit_undispatched_stage(execution_id, assignment_id, stage_id, stage_name)?;
        debug!(
            %assignment_id,
            %execution_id,
            stage = %stage_name,
            "dispatcher: admitted an undispatchable stage; the chain records it at stage scope \
             and claims no attempt for it"
        );
        Ok(())
    }

    /// [`Self::admit_undispatched_stage`] then [`Self::mark_failed_and_fold_attempt`],
    /// committed as ONE transaction
    /// (`OperationalDb::admit_failed_undispatched_stage`): a crash leaves no row or the
    /// failed one, never a `pending` admission. The assignment is fresh and never
    /// placed, so it holds no load charge or placement for the two-step door's
    /// hot-state retirement to release.
    pub(crate) fn admit_failed_undispatched_stage(
        &self,
        execution_id: Ulid,
        assignment_id: Ulid,
        stage_name: &str,
        reason: &str,
    ) -> KataResult<()> {
        let db = self.attempt_chain_nucleus(execution_id)?;
        db.admit_failed_undispatched_stage(
            execution_id,
            assignment_id,
            stage_name,
            stage_name,
            reason,
        )?;
        Ok(())
    }

    /// Mint this dispatch's identity. See [`DispatchToken`].
    ///
    /// Called ONCE per delivery, at the entry of the capsule send door, and
    /// never inside it: the token identifies the delivery that owns the
    /// placement, so a second delivery for one attempt declines as superseded
    /// rather than sends twice.
    ///
    /// `Relaxed` is the whole ordering this needs. The comparison that uses the
    /// value happens under [`Dispatcher::placement_ownership`]'s lock, which is
    /// what publishes it; the counter itself only has to be unique and increasing,
    /// and `fetch_add` is both under any ordering.
    pub(crate) fn mint_dispatch_token(&self) -> DispatchToken {
        self.placement_ownership.mint()
    }

    /// THE CAPSULE ARM'S CHARGE — the consume-once load charge against the AUTHORITY
    /// CHAIN's pre-image.
    ///
    /// The capsule attempt's durable placement is its ROW —
    /// `dispatch_claimed_attempt` wrote `dispatched` and `attempts.worker_id`
    /// atomically at authorization — and a capsule placement never moves (there
    /// is no capsule redelivery), so the refusals the row answers are "the
    /// attempt settled terminal under this send" and "the recorded placement is
    /// not this delivery's"; the supersede is the ownership token the delivery
    /// claimed a statement earlier.
    ///
    /// The charge still counts on the WORKER INSTANCE's own
    /// `active_assignments` — the exact Arc `dispatch_to_current_instance`
    /// compares — so a same-id replacement is `RegistrationReplaced`, proven
    /// not sent. Lock order is placement ownership -> authority read -> charge
    /// map.
    pub(super) fn acquire_capsule_dispatch_charge(
        &self,
        attempt_id: Ulid,
        worker_id: &SmolStr,
        dispatch: DispatchToken,
    ) -> KataResult<Result<super::charge::AcquiredCharge, DeclinedPlacement>> {
        let ownership = self.placement_ownership.section(attempt_id);
        if ownership.owner() != Some(dispatch) {
            return Ok(Err(DeclinedPlacement::SupersededByALaterDispatch {
                status: "dispatched",
            }));
        }
        let face = self.execution_lifecycle();
        let Some(state) = face.db().recovered_attempt(attempt_id)? else {
            return Ok(Err(DeclinedPlacement::Untracked));
        };
        if state.is_terminal() {
            return Ok(Err(DeclinedPlacement::LatchedTerminal {
                status: "terminal",
            }));
        }
        if state.row.worker_id.as_deref() != Some(worker_id.as_str()) {
            return Ok(Err(DeclinedPlacement::MovedOn {
                status: "dispatched",
            }));
        }
        let counter = self
            .supervisor
            .get_worker(worker_id)
            .map(|info| Arc::clone(&info.value().active_assignments))
            .ok_or_else(|| KataError::Network(format!("worker {worker_id} not registered")))?;
        let charge =
            self.dispatch_charges
                .acquire(attempt_id, dispatch, worker_id.clone(), counter);
        Ok(Ok(charge))
    }

    /// Reconcile one charge from current placement authority. This is safe for
    /// delayed events: worker id alone is insufficient; a newer token on the
    /// same id also makes the old charge stale.
    pub(super) fn reconcile_dispatch_charge(&self, assignment_id: Ulid) {
        let Some(snapshot) = self.dispatch_charges.owner(assignment_id) else {
            return;
        };
        self.reconcile_dispatch_charge_snapshot(snapshot);
    }

    fn reconcile_dispatch_charge_snapshot(&self, snapshot: super::charge::ChargeSnapshot) {
        let assignment_id = snapshot.assignment_id;
        let ownership = self.placement_ownership.section(assignment_id);
        let must_release = match self
            .execution_lifecycle()
            .db()
            .recovered_attempt(assignment_id)
        {
            // A live row keeps its charge exactly as long as the charge's own
            // facts still hold: terminal releases, a placement that differs
            // releases, a row that is gone releases, a read fault retains —
            // the fail-closed direction, since a charge nobody counted is a
            // second delivery the worker is not credited with refusing.
            Ok(Some(recovered)) => {
                recovered.is_terminal()
                    || recovered.row.worker_id.as_deref() != Some(snapshot.worker_id.as_str())
                    || ownership
                        .owner()
                        .is_some_and(|owner| owner != snapshot.dispatch)
            }
            Ok(None) => true,
            Err(error) => {
                warn!(
                    %assignment_id,
                    dispatch = %snapshot.dispatch,
                    error = %error,
                    "dispatcher: retaining load charge because the attempt-row reconciliation failed"
                );
                false
            }
        };
        drop(ownership);
        if must_release {
            self.dispatch_charges
                .release_if_owned(assignment_id, snapshot.token);
        }
    }

    /// Reconcile every process-local charge after broadcast loss or on the
    /// periodic missed-subscription safety pass.
    pub(super) fn reconcile_dispatch_charges(&self) {
        self.reconcile_execution_hot_state();
        for snapshot in self.dispatch_charges.snapshot() {
            self.reconcile_dispatch_charge_snapshot(snapshot);
        }
        for assignment_id in self.assignments.ids() {
            if let Err(error) = self.reconcile_assignment_hot_state(assignment_id, true) {
                warn!(%error, %assignment_id, "assignment hot-state reconciliation deferred");
            }
        }
    }

    /// Deterministic load-charge witness for integration tests. Production invokes the
    /// same reconciliation at bookkeeper startup, periodically, and after lag.
    #[cfg(any(test, feature = "test-support"))]
    pub fn reconcile_dispatch_charges_for_test(&self) {
        self.reconcile_dispatch_charges();
    }

    /// Retire assignment hot state only after an authoritative terminal. Called
    /// after successful terminal writes and by terminal event handling. Periodic
    /// reconciliation also covers missed events and failed cleanup reads.
    ///
    /// # The polarity is deliberate
    ///
    /// Forgetting LATE costs memory — one `Ulid` and one `u64` for an assignment
    /// that can never be placed again. Forgetting EARLY costs a second delivery
    /// frame, which is the defect. So a terminalizer that failed to call this
    /// would leak and stay correct, and no caller can make the map answer "nobody
    /// owns this" for a live placement.
    pub(super) fn retire_terminal_assignment(&self, assignment_id: Ulid) {
        if let Err(error) = self.reconcile_assignment_hot_state(assignment_id, false) {
            warn!(%error, %assignment_id, "assignment hot-state cleanup deferred; authority remains unchanged");
        }
    }

    /// Drop only a currently terminal placement, while excluding a newer
    /// dispatch claim. A delayed result must preserve a live retry successor.
    pub(super) fn reconcile_terminal_placement_ownership(
        &self,
        assignment_id: Ulid,
    ) -> KataResult<()> {
        self.reconcile_assignment_hot_state(assignment_id, false)
    }

    /// One terminal retirement boundary. The placement lock also serializes
    /// command admission, telemetry insertion, and stall claims; lock order is
    /// placement -> durable authority -> registry/charges. No registry operation
    /// calls back into placement or the database while its mutex is held.
    pub(super) fn reconcile_assignment_hot_state(
        &self,
        assignment_id: Ulid,
        retire_absent: bool,
    ) -> KataResult<()> {
        let mut ownership = self.placement_ownership.section(assignment_id);
        let terminal = match self
            .execution_lifecycle()
            .db()
            .recovered_attempt(assignment_id)?
        {
            Some(recovered) => recovered.is_terminal(),
            None => retire_absent,
        };
        if !terminal {
            return Ok(());
        }
        if let Some(timing) = self.assignments.retire(assignment_id) {
            self.release_assignment_timing(timing);
        }
        ownership.owners.remove(&assignment_id);
        if let Some(charge) = self.dispatch_charges.owner(assignment_id) {
            self.dispatch_charges
                .release_if_owned(assignment_id, charge.token);
        }
        Ok(())
    }

    /// The DURABLE half of the ingress fence: which worker this attempt is
    /// placed on, and which generation is live.
    ///
    /// Both coordinates come off the `attempts` row, which is the same row the
    /// capsule authorization's `dispatch_claimed_attempt` wrote and stamped with
    /// the OUTBOUND epoch. That identity is the point: the two directions of the
    /// fence must not be able to disagree about which generation is live, and they
    /// cannot when they read one column.
    ///
    /// `Ok(None)` means no plane holds an attempt row for this assignment — an
    /// unknown attempt, which the fence's caller treats as unattributable rather
    /// than as a placement mismatch.
    pub(crate) fn attempt_durable_placement(
        &self,
        assignment_id: Ulid,
    ) -> KataResult<Option<DurableAttemptPlacement>> {
        let Some(row) = self.execution_lifecycle().db().attempt(assignment_id)? else {
            return Ok(None);
        };
        Ok(Some(DurableAttemptPlacement {
            lease_epoch: row.lease_epoch,
            worker_id: row.worker_id,
        }))
    }

    /// The durable dispatch COMMAND minted for the attempt's given
    /// generation, so an outbound re-delivery can reproduce the command the row
    /// authorized rather than minting a second one.
    pub(crate) fn attempt_dispatch_command_id(
        &self,
        assignment_id: Ulid,
        lease_epoch: i64,
    ) -> KataResult<Option<Ulid>> {
        self.execution_lifecycle()
            .db()
            .attempt_command_at_epoch(assignment_id, lease_epoch)
    }

    /// EVERY stage of `execution_id` and the state each has REACHED on the
    /// authority chain, from the two chain representations an execution's work
    /// lives in.
    ///
    /// `undispatched_stage_states` serves the stage-scope class and
    /// `attempts_for_execution` the attempt-scope class; a reader that
    /// consulted only one would be blind to the other, so this returns both in one
    /// list.
    /// An `attempts` row is either a worker's or a MAIN-RESOLVED attempt's (schema 24:
    /// a wait, a join, an invocation), and both are here, the main one named by its
    /// `stage_id` and carrying its folded `awaiting_*` or terminal state.
    ///
    /// # Invariant
    ///
    /// FAILS CLOSED ON AN ABSENT NUCLEUS, via [`Self::attempt_chain_nucleus`]. This
    /// is the polarity that separates it from
    /// [`Self::attempt_chain_nucleus_if_known`]: an additive WRITE may decline to
    /// record, but a DECIDING READ that answered "no stages" for an execution the
    /// chain cannot see would hand every one of the five predicates the exact
    /// empty-plane answer they misread. A refusal names the execution instead.
    pub fn execution_stage_states(&self, execution_id: Ulid) -> KataResult<Vec<ChainStageState>> {
        let db = self.attempt_chain_nucleus(execution_id)?;
        let mut states = db.undispatched_stage_states(execution_id)?;
        for recovered in db.attempts_for_execution(execution_id)? {
            // A MAIN-RESOLVED attempt (schema 24) is INCLUDED, named by its canonical
            // `stage_id` exactly as the capsule arm is: neither surviving arm carries
            // a stage name of its own, and the row's `stage_id` is the canonical
            // coordinate both classify under. Skipping a main attempt would make a
            // parked wait invisible to every consumer that decides from
            // non-terminality — the closeout witness would answer "all terminal" or "no
            // history" beside a live wait, hot state would retire under it, and the
            // `max_concurrency` cap would not count it.
            let stage_name = recovered.row.stage_id.clone();
            states.push(ChainStageState {
                assignment_id: recovered.row.attempt_id,
                execution_id: recovered.row.execution_id,
                stage_name,
                state: recovered.state.clone(),
                child_execution_id: recovered.row.child_execution_id,
                seq: recovered
                    .state_source_seq
                    .unwrap_or(recovered.row.source_seq),
            });
        }
        Ok(states)
    }

    /// The fence the MAIN mints to command a worker about this attempt,
    /// plus the worker it is currently placed on.
    ///
    /// # Why the main reads the durable row rather than remembering an epoch
    ///
    /// The worker obeys a stop only at the epoch its dispatch was fenced at, and a
    /// stop minted from an epoch the caller happens to be holding names whatever
    /// that caller last saw rather than what the row holds. So the
    /// coordinates come off the `attempts` row at the instant the decision is
    /// made — the SAME column [`Self::attempt_durable_placement`] reads and the
    /// same one the outbound drain compares against, which is what makes the two
    /// directions of the fence unable to disagree.
    ///
    /// `Ok(None)` means no plane holds a row for this assignment, or it holds no
    /// placement — in both cases there is no worker to command, which a caller
    /// must treat as "nothing to stop" rather than as a failure.
    pub fn attempt_command_target(
        &self,
        assignment_id: Ulid,
    ) -> KataResult<Option<(SmolStr, kata_transport::types::AttemptFence)>> {
        let Some(placement) = self.attempt_durable_placement(assignment_id)? else {
            return Ok(None);
        };
        let Some(worker_id) = placement.worker_id else {
            return Ok(None);
        };
        let worker_id = SmolStr::new(worker_id);
        Ok(Some((
            worker_id.clone(),
            kata_transport::types::AttemptFence::commanding(placement.lease_epoch, worker_id),
        )))
    }

    /// Record durably that the main has decided to stop this generation,
    /// BEFORE the control frame is handed to any transport.
    ///
    /// The ordering is the whole point and is stated on
    /// [`OperationalDb::record_stop_request`](kata_core::operational::OperationalDb::record_stop_request)
    /// too, because getting it backwards is silent: a stop that was SENT and
    /// recorded nowhere leaves the worker acting on an ask the main has forgotten,
    /// and parking would then be authorized by a lifecycle that no longer
    /// describes anything.
    ///
    /// Takes the fence rather than an epoch so the durable row is keyed by exactly
    /// the coordinates the frame carries — [`Self::attempt_command_target`] mints
    /// both from one read, and a caller that could pass a different epoch here
    /// than it sent could record a stop against a generation it never commanded.
    pub fn record_attempt_stop_request(
        &self,
        assignment_id: Ulid,
        fence: &kata_transport::types::AttemptFence,
        reason: &str,
    ) -> KataResult<kata_core::operational::stop_ack::StopRequestOutcome> {
        self.execution_lifecycle().db().record_stop_request(
            assignment_id,
            fence.lease_epoch,
            fence.worker_id.as_str(),
            reason,
        )
    }

    /// A transport accepted the stop frame for this generation.
    ///
    /// Bookkeeping, not safety: no SAFETY decision reads it. It separates "the
    /// stop never left the main" from "the stop left and the worker has not
    /// answered", which is what an operator asking why parking is still refused
    /// actually needs.
    ///
    /// `WorkflowExecutor::require_terminal_lifecycle_for_parking` branches on
    /// `delivered_at_ms` to word its refusal "delivered, unanswered" versus "never
    /// delivered". The distinction matters — that is the operator's difference
    /// between a wedged worker and a transport that never carried the frame — and
    /// the caller that treats the write as non-fatal
    /// (`WorkflowExecutor::cancel`) is trading a DIAGNOSTIC, not a guarantee. See
    /// `kata_core::operational::stop_ack::OperationalDb::mark_stop_delivered` for
    /// the crash window this write cannot close.
    pub fn mark_attempt_stop_delivered(
        &self,
        assignment_id: Ulid,
        fence: &kata_transport::types::AttemptFence,
    ) -> KataResult<()> {
        self.execution_lifecycle()
            .db()
            .mark_stop_delivered(assignment_id, fence.lease_epoch)
    }

    /// Every stop of this execution the worker has not answered.
    ///
    /// Empty is what authorizes reclaiming the execution's workspace. The rows,
    /// rather than a count, because the refusal has to NAME the attempt that is
    /// still holding it.
    pub fn unacknowledged_attempt_stops(
        &self,
        execution_id: Ulid,
    ) -> KataResult<Vec<kata_core::operational::stop_ack::StopRequestRow>> {
        self.execution_lifecycle()
            .db()
            .unacknowledged_stops(execution_id)
    }

    /// Every stop ever asked of THIS ATTEMPT, acknowledged or not.
    ///
    /// Deliberately not [`Self::unacknowledged_attempt_stops`] narrowed to one
    /// attempt: that reader is empty by the time the retry decision runs. The
    /// reactor acknowledges a stop from the worker's own terminal frame BEFORE
    /// dispatching that frame to `handle_stage_failure`, so a cancelled stage
    /// that failed reaches the retry decision with its stop already discharged,
    /// so reading only unacknowledged stops would record the failure `failed`
    /// rather than `cancelled`, and the runner would re-run the stage as a new
    /// attempt while the operator's surface said the cancel landed.
    ///
    /// The stop is a STANDING INSTRUCTION about the attempt; the acknowledgement
    /// answers a different question (no worker is running generation E). See
    /// `OperationalDb::stops_standing_against_attempt`.
    pub fn stops_standing_against_attempt(
        &self,
        execution_id: Ulid,
        assignment_id: Ulid,
    ) -> KataResult<Vec<kata_core::operational::stop_ack::StopRequestRow>> {
        self.execution_lifecycle()
            .db()
            .stops_standing_against_attempt(execution_id, assignment_id)
    }

    /// Discharge an outstanding stop on an attributed operator assertion.
    ///
    /// The exit from the outstanding-stop latch. See
    /// `OperationalDb::discharge_stop` for why it is mandatory and why a
    /// probe-backed discharge is unrepresentable.
    pub fn discharge_attempt_stop(
        &self,
        execution_id: Ulid,
        assignment_id: Ulid,
        lease_epoch: i64,
        discharge: &kata_types::execution::StopDischarge,
    ) -> KataResult<kata_core::operational::stop_ack::StopDischargeOutcome> {
        self.execution_lifecycle().db().discharge_stop(
            execution_id,
            assignment_id,
            lease_epoch,
            discharge,
        )
    }

    /// EVERY stop of this execution, for the record an operator reads.
    ///
    /// The settled ones are the point, not noise: "your cancel was acknowledged"
    /// is the answer an operator came for, and a projection carrying only the
    /// outstanding stops would empty out at the exact moment the cancel succeeded
    /// and be indistinguishable from a cancel that never happened.
    pub fn execution_attempt_stops(
        &self,
        execution_id: Ulid,
    ) -> KataResult<Vec<kata_core::operational::stop_ack::StopRequestRow>> {
        self.execution_lifecycle()
            .db()
            .execution_stop_requests(execution_id)
    }

    /// The state EVERY assignment of one execution has REACHED on the authority
    /// chain, in the ROW shape.
    ///
    /// # Why this exists beside [`Self::execution_stage_states`]
    ///
    /// They scan the same history and answer different questions. The stage-scope
    /// reader carries a bare STATE, which is everything the runner's fold-path
    /// predicates need and nothing kata-api's observation and closeout surfaces
    /// do: those read a completion's OUTPUT, discriminate a cancellation on the
    /// FAILURE REASON's prefix, and order competing completions. Widening
    /// [`ChainStageState`] to carry all of that would have put payload facts on
    /// the type the RUNNER decides from, where no consumer reads them and every
    /// future consumer could — so the two shapes stay two shapes, over one fold.
    ///
    /// # Invariant
    ///
    /// FAILS CLOSED ON AN ABSENT NUCLEUS, through the SAME
    /// [`Self::attempt_chain_nucleus`] predicate every chain writer and the
    /// deciding reader use. Not a parallel gate that could drift: one predicate,
    /// and this calls it.
    ///
    /// The polarity matters as much here as it does for the fold. Its consumers
    /// — the execution record's lifecycle fold (status, outputs, failure
    /// messages, walk-away warnings), the runner's in-flight rehydration, and
    /// [`Self::settled_attempt_pre_image`] — would each read an empty answer as
    /// "nothing happened yet": a failed execution as pending, an in-flight
    /// capsule as unsubmitted. An execution the nucleus cannot speak for is named
    /// in a refusal instead.
    ///
    /// Production reaches these paths only for executions admitted through the
    /// checked submit door, which is what puts them IN the nucleus, so the refusal
    /// is production-inert — the same reasoning kata-api's
    /// `execution_chain_stage_states` records for the predicate half.
    pub fn execution_assignment_states(
        &self,
        execution_id: Ulid,
    ) -> KataResult<Vec<crate::attempt_delivery::ChainAssignmentState>> {
        crate::attempt_delivery::AttemptDeliveryMapper::new(
            self.attempt_chain_nucleus(execution_id)?,
        )
        .execution_assignment_states(execution_id)
    }

    /// The outcome the authority chain folds for one assignment — `None` when
    /// the chain holds no record of it.
    ///
    /// Covers both admission classes: an attempt-scope row locates its
    /// execution through `attempts`, a stage-scope one through the
    /// undispatched-stage admission. The fold reads the same captured prefix
    /// [`Self::execution_assignment_states`] does, so a reader cannot observe a
    /// settlement here that the population read would contradict.
    pub fn settled_attempt_pre_image(
        &self,
        assignment_id: Ulid,
    ) -> KataResult<Option<crate::attempt_delivery::FoldOutcome>> {
        let db = self.live_work_nucleus();
        let execution_id =
            if let Some(execution_id) = self.workerless_stage_execution_id(assignment_id)? {
                execution_id
            } else {
                let Some(row) = db.attempt(assignment_id)? else {
                    return Ok(None);
                };
                row.execution_id
            };
        Ok(self
            .execution_assignment_states(execution_id)?
            .into_iter()
            .find(|state| state.assignment_id == assignment_id)
            .map(|state| state.outcome))
    }

    /// The execution a stage-scope admission answers on, `None` when the chain
    /// holds no undispatched-stage admission for this assignment.
    pub fn workerless_stage_execution_id(&self, assignment_id: Ulid) -> KataResult<Option<Ulid>> {
        Ok(self
            .live_work_nucleus()
            .undispatched_stage_admission(assignment_id)?
            .map(|admission| admission.execution_id))
    }

    /// The AUTHORITY CHAIN one DECIDING READER folds, mapped onto what the fold
    /// consumes.
    ///
    /// # The gate
    ///
    /// Every chain WRITER routes through [`Self::attempt_chain_nucleus`]
    /// and refuses an execution the nucleus does not hold, *"refusing to dispatch
    /// work no plane records"*. The DECIDING READER, `WorkflowRunner::fold_to_head`,
    /// reads through this gate too. Ungated, and composed with the main-side
    /// writer's deliberate fail-SAFE
    /// ([`Self::attempt_chain_nucleus_if_known`] records NOTHING for an execution
    /// the nucleus does not hold), a reader would turn "this plane has no record of
    /// the execution" into "this execution ran nothing": completed work replayed as
    /// never-run, and a re-dispatch of a stage whose output is already durable.
    ///
    /// The two halves are the SAME gate, which is the point: a reader cannot
    /// come to disagree with a writer about which executions this plane can speak
    /// for, because there is one predicate and both call it.
    ///
    /// # Invariant
    ///
    /// FAILS CLOSED, naming the execution. The polarity is deliberately opposite
    /// to the additive main-side writer's: a WRITE that records nothing leaves the
    /// attempt where it stood, whereas a deciding READ that answered "no history"
    /// would advance work on the strength of an absence.
    pub fn deciding_chain_reader(
        &self,
        execution_id: Ulid,
    ) -> KataResult<crate::attempt_delivery::AttemptDeliveryMapper> {
        Ok(crate::attempt_delivery::AttemptDeliveryMapper::new(
            self.attempt_chain_nucleus(execution_id)?,
        ))
    }

    /// The highest AUTHORITY sequence this execution's chain holds.
    ///
    /// # It moves WITH the fold, or neither moves
    ///
    /// This is the `H` in `WorkflowRunner::run_replay`'s blocked-check. `A` is the
    /// fold's watermark, a chain sequence, so comparing it
    /// against a second sequence space would reintroduce the live-lock the code's
    /// own comment above that check already describes.
    ///
    /// Gated exactly as [`Self::deciding_chain_reader`] is, and for the same
    /// reason: `0` from a plane that cannot see the execution reads as "every
    /// durable event is folded", which is the premise the stuck verdict rests on.
    pub fn execution_chain_head(&self, execution_id: Ulid) -> KataResult<i64> {
        self.attempt_chain_nucleus(execution_id)?
            .execution_transition_head(execution_id)
    }

    /// A LIVENESS handle on the plane the deciding reader folds.
    ///
    /// # NOT gated, and that is not an omission
    ///
    /// [`Wake`](kata_core::operational::liveness::Wake) carries no payload and
    /// answers no question about any execution, so there is nothing here for an
    /// absent nucleus to answer WRONGLY — the failure a gate would prevent does
    /// not exist. Gating it would instead couple a liveness handle to an
    /// execution's admission state — a second authority wearing a safety costume.
    ///
    /// It is taken from the same face [`Self::attempt_chain_nucleus`] returns, so
    /// the plane that publishes is the plane the fold reads.
    #[must_use]
    pub fn chain_liveness(&self) -> kata_core::operational::liveness::PlaneLiveness {
        self.execution_lifecycle().db().liveness()
    }

    /// Record a worker's mid-stage SAFE POINT.
    ///
    /// `WorkflowRunner::fold_to_head` recovers the safe point off the frames it
    /// folds, and `boot_pure_fold` re-asserts it forward.
    ///
    /// # Invariant
    ///
    /// MONOTONE, ENFORCED BY THE WRITER RATHER THAN BY THIS CALLER.
    /// `record_attempt_safe_point` applies `MAX(COALESCE(last_checkpoint, -1), ?)`
    /// in SQL, so a resumed worker's regressive `sequence 0` start marker cannot
    /// rewind the safe point.
    ///
    /// # Failure: ADDITIVE, matching the main-side writer's polarity
    ///
    /// An assignment the chain holds no attempt for records nothing and is not an
    /// error. No current writer dispatches work off the chain, so this arm records
    /// nothing; a checkpoint is an observability frame, and refusing it would fail
    /// the frame's reader for no state the chain could lose.
    pub fn record_checkpoint_and_fold_attempt(
        &self,
        assignment_id: Ulid,
        sequence: u64,
    ) -> KataResult<()> {
        // The identity resolution IS the chain's own attempt row, so the execution
        // this belongs to is read off the plane that holds it.
        let face = self.execution_lifecycle();
        let Some(attempt) = face.db().attempt(assignment_id)? else {
            return Ok(());
        };
        if face.view().lifecycle(attempt.execution_id)?.is_none() {
            return Ok(());
        }
        face.db()
            .record_attempt_safe_point(assignment_id, i64::try_from(sequence).unwrap_or(i64::MAX))
            .map(|_| ())
    }

    /// EVERY unit of live work the AUTHORITY chain holds, across ALL executions.
    ///
    /// # Who reads it
    ///
    /// The dispatcher's four deadline/retry sweeps. Those sweeps decide
    /// ACROSS executions — a tick has no execution to scope by — so
    /// [`Self::execution_stage_states`], which the runner's fold-path predicates
    /// use, structurally cannot serve them.
    ///
    /// # BOTH classes, and why `live_attempts` alone was not enough
    ///
    /// `OperationalDb::live_attempts` reads the `attempts` table, so it sees the
    /// DISPATCHABLE class and nothing else. The stage-scope class is admitted
    /// through [`Self::admit_undispatched_stage`] precisely because it never
    /// reaches a worker, so it has no `attempts` row at all, and a registry built
    /// from `live_attempts` alone would answer EMPTY for it forever.
    ///
    /// So the registry is the union of the two chain representations an execution's
    /// work lives in, exactly as [`Self::execution_stage_states`] unions them one
    /// scope down: `live_attempts` for the dispatchable class,
    /// [`OperationalDb::live_undispatched_stages`] for the stage-scope class.
    ///
    /// # Invariant
    ///
    /// EMPTY AND UNREADABLE ARE DISTINGUISHED BY THE `Result`, NEVER BY THE LENGTH.
    /// This is the polarity `OperationalDb::attempts_for_execution` states for the
    /// per-execution reader and it is the one that matters here, because EVERY
    /// consumer of this registry treats an empty answer as "nothing to do" and the
    /// deadline sweeps' version of that is silent — a stage that has overrun is
    /// simply never failed. `Ok(vec![])` is a plane that genuinely holds no live
    /// work, which is an ordinary state (a fresh data dir, every execution
    /// settled); a plane that cannot be read is an `Err` that reaches the caller.
    ///
    /// # Failure
    ///
    /// An attempt whose assignment blob carries no readable stage name is a typed
    /// refusal rather than a skipped row — the same rule
    /// [`Self::execution_stage_states`] applies, because a silently dropped
    /// candidate is a stage that never trips its deadline.
    pub fn live_work_registry(&self) -> KataResult<Vec<LiveWork>> {
        let db = self.live_work_nucleus();
        let mut live = Vec::new();
        for recovered in db.live_attempts()? {
            // BY NAME: a MAIN-RESOLVED attempt is live, and it is nobody's live WORK —
            // no deadline, retry, death, stall or orphan leg this registry feeds can be
            // true of an attempt no worker ever holds. Refusing it instead would fail
            // the whole registry, and with it every sweep of the tick.
            if recovered.row.executor == kata_core::operational::AttemptExecutor::Main {
                continue;
            }
            live.push(LiveWork::from_recovered(&recovered)?);
        }
        for stage in db.live_undispatched_stages()? {
            live.push(LiveWork::from_stage(&stage));
        }
        Ok(live)
    }

    /// Enumerate authoritative approval parks across admitted executions.
    ///
    /// The enumeration is `approval_gated_attempts` — every `awaiting_approval`
    /// attempt of an admitting/running execution, of ANY executor — and NOT
    /// `live_work_registry`: the registry sheds `executor = 'main'` rows by
    /// name because its deadline/retry consumers have no worker legs for them,
    /// but a parked `workspace_effect` gate IS a main-executor `awaiting_
    /// approval` attempt. Reading it off the registry made the operator's
    /// whole gate list blind to exactly the gates it exists for (measured: a
    /// parked effect park listed nothing; the decide door answered only a
    /// caller who already knew the attempt id). Worker rows keep going through
    /// `LiveWork`; main rows go through `workspace_effect_gate_view` and never
    /// reach `LiveWork::from_recovered`, which refuses them.
    ///
    /// The parked transition payload supplies the current park reason, and the
    /// FIRST park's frame the anchor — including workerless gates.
    pub fn parked_approval_gates(&self) -> KataResult<Vec<ParkedApprovalGate>> {
        let mut gates: Vec<ParkedApprovalGate> = Vec::new();
        for recovered in self.live_work_nucleus().approval_gated_attempts()? {
            // THE `oci` MAIN-GATE ARM. A main-resolved gate — a
            // `workspace_effect` gate or a bounded-expansion's parked
            // `on_max = "escalate"` gate — is `awaiting_approval` like a
            // capsule's but is no capsule: read its scope off the parked
            // transition's payload.
            if recovered.row.executor == kata_core::operational::AttemptExecutor::Main {
                if let Some((reason, awaiting_since_ms, scope)) =
                    self.workspace_effect_gate_view(recovered.row.attempt_id)?
                {
                    let stage_name = SmolStr::new(&recovered.row.stage_id);
                    gates.push(ParkedApprovalGate {
                        assignment_id: recovered.row.attempt_id,
                        execution_id: recovered.row.execution_id,
                        stage_name,
                        reason,
                        awaiting_since_ms,
                        capsule: None,
                        workspace_effect: Some(scope),
                        expansion: None,
                    });
                    continue;
                }
                if let Some((reason, awaiting_since_ms, gate)) =
                    self.expansion_gate_view(recovered.row.attempt_id)?
                {
                    gates.push(ParkedApprovalGate {
                        assignment_id: recovered.row.attempt_id,
                        execution_id: recovered.row.execution_id,
                        stage_name: SmolStr::new(&gate.stage),
                        reason,
                        awaiting_since_ms,
                        capsule: None,
                        workspace_effect: None,
                        expansion: Some(gate),
                    });
                }
                continue;
            }
            let work = LiveWork::from_recovered(&recovered)?;
            // THE CAPSULE ARM. A capsule attempt's park is read off the
            // parking claim and its capsule off the capsule's own bytes.
            if let Some((reason, awaiting_since_ms, capsule)) =
                self.capsule_gate_view(work.assignment_id)?
            {
                gates.push(ParkedApprovalGate {
                    assignment_id: work.assignment_id,
                    execution_id: work.execution_id,
                    stage_name: work.stage_name,
                    reason,
                    awaiting_since_ms,
                    capsule: Some(capsule),
                    workspace_effect: None,
                    expansion: None,
                });
                continue;
            }
            // A WORKER-ATTEMPT park that is not a capsule gate: an approval park
            // with no capsule, workspace-effect, or expansion gate view. Its
            // reason and anchor come off the
            // FIRST approval park transition, which is the authoritative
            // record the parked payload left — and the only home either fact
            // has, since no `attempts` column carries either.
            let db = self.live_work_nucleus();
            let Some(park) =
                db.first_approval_park_transition(work.execution_id, work.assignment_id)?
            else {
                continue;
            };
            let payload: serde_json::Value =
                serde_json::from_slice(&park.payload_json).map_err(|error| {
                    KataError::Storage(format!(
                        "dispatcher: the first approval-park frame of attempt {} of execution \
                         {} carries an undecodable payload: {error}",
                        work.assignment_id, work.execution_id
                    ))
                })?;
            let reason = payload
                .get("reason")
                .and_then(serde_json::Value::as_str)
                .map(str::to_owned)
                .ok_or_else(|| {
                    KataError::Storage(format!(
                        "dispatcher: the first approval-park frame of attempt {} of execution \
                         {} carries no reason",
                        work.assignment_id, work.execution_id
                    ))
                })?;
            gates.push(ParkedApprovalGate {
                assignment_id: work.assignment_id,
                execution_id: work.execution_id,
                stage_name: work.stage_name,
                reason,
                // Preserve absence; the frame's recorded instant is the park's
                // own, and a missing one stays `None` rather than fabricate.
                awaiting_since_ms: u64::try_from(park.recorded_at_ms).ok(),
                capsule: None,
                workspace_effect: None,
                expansion: None,
            });
        }
        Ok(gates)
    }

    /// The operational nucleus a GLOBAL chain read runs against.
    ///
    /// [`Self::attempt_chain_nucleus`]'s execution-free sibling, and deliberately
    /// WITHOUT its gate. That sibling refuses an execution the nucleus does not
    /// hold; a registry spanning every execution has no single execution to check,
    /// so there is no equivalent question to ask.
    ///
    /// # Why an UNATTACHED nucleus is read rather than refused
    ///
    /// Refusing it would make a production-unreachable condition into a test-only
    /// failure. `Dispatcher::new`'s private nucleus is a RIG's
    /// scratchpad — `attempt_chain_nucleus` says so and treats it the same way,
    /// auto-admitting into it rather than refusing — and every production
    /// construction attaches a real face before a sweep can run. Refusing would
    /// therefore never fire in production and would break every rig that drives a
    /// sweep through a shared test helper, which is the "editing the rigs one by
    /// one" failure the auto-admission seam exists to avoid.
    ///
    /// INFALLIBLE, and it returns no `Result` "for symmetry":
    /// a wrapper that cannot fail but says it might invites a caller to treat its
    /// `Err` arm as the unreadable-plane case, which lives one level down on the
    /// `OperationalDb` query itself.
    fn live_work_nucleus(&self) -> Arc<OperationalDb> {
        Arc::clone(self.execution_lifecycle().db())
    }

    /// Run ONE main-side transition against the authority chain — the single
    /// expression of "a main-side decision moved this assignment" inside the
    /// dispatcher and the runner.
    ///
    /// Its callers are the settling doors — [`Self::mark_failed_and_report`],
    /// [`Self::mark_orphaned_and_fold_attempt`] and the test-support
    /// `mark_completed_and_fold_attempt` — so a settled chain state always
    /// declines. The class is read from the chain rather than inferred:
    ///
    /// 1. an ATTEMPT — recorded at attempt scope through
    ///    [`OperationalDb::record_main_side_transition`];
    /// 2. an UNDISPATCHED-STAGE admission — recorded at stage scope through
    ///    [`OperationalDb::record_undispatched_stage_transition`];
    /// 3. NEITHER — no current writer leaves an assignment off the chain; this
    ///    arm records nothing and is not an error.
    ///
    /// # The settled branch
    ///
    /// A transition arriving behind a TERMINAL chain state is declined — the
    /// generation is settled — and reported as
    /// [`MainSideOutcome::ChainAlreadySettled`]. Nothing folded here opens a
    /// new generation of a settled attempt.
    ///
    /// # Failure: ADDITIVE
    ///
    /// An assignment the chain does not hold decides NOTHING, records NOTHING,
    /// and is not an error — the verdict is
    /// [`MainSideOutcome::NotOnTheChain`]. Real storage and validation faults
    /// from the chain write itself still propagate.
    fn fold_main_side(
        &self,
        assignment_id: Ulid,
        transition: &mut MainSideTransition<'_>,
        stage: &UndispatchedStageOutcome<'_>,
    ) -> KataResult<MainSideOutcome> {
        let db = self.live_work_nucleus();
        if db.attempt(assignment_id)?.is_none() {
            // The stage-scope class settles on its admission. No current writer
            // leaves an assignment with neither row.
            if db.undispatched_stage_admission(assignment_id)?.is_some() {
                let admission = db
                    .undispatched_stage_admission(assignment_id)?
                    .expect("admission checked above");
                if let Some(held) =
                    db.last_undispatched_stage_transition(admission.execution_id, assignment_id)?
                    && ATTEMPT_TERMINAL_STATES.contains(&held.resulting_state.as_str())
                {
                    return Ok(MainSideOutcome::ChainAlreadySettled {
                        agreed: held.resulting_state == transition.state,
                    });
                }
                db.record_undispatched_stage_transition(assignment_id, stage)?;
                return Ok(MainSideOutcome::RecordedAtStageScope);
            }
            debug!(
                %assignment_id,
                state = transition.state,
                "dispatcher: the chain holds neither an attempt nor an undispatched-stage \
                 admission for this assignment; recording nothing rather than minting an \
                 attempt for work no dispatch placed"
            );
            return Ok(MainSideOutcome::NotOnTheChain);
        }
        // THE DECISION. The chain's own latch classification, consulted as a
        // VALUE so an ordinary post-terminal advance declines instead of
        // erroring.
        if let Some(settled) = db
            .attempt_state(assignment_id)?
            .filter(|state| ATTEMPT_TERMINAL_STATES.contains(&state.as_str()))
        {
            debug!(
                %assignment_id,
                chain_state = %settled,
                projected = transition.state,
                "dispatcher: the chain has already settled this attempt; recording nothing"
            );
            return Ok(MainSideOutcome::ChainAlreadySettled {
                agreed: settled == transition.state,
            });
        }
        // A DISPATCHED capsule attempt ended main-side (the boot orphan sweep, a
        // failure decided off the chain) carries the charge the main holds no report
        // for — the same one a capsule settlement records — because the writer refuses
        // a dispatched attempt's failure-class terminal without one
        // (`TERMINAL_CHARGE_REQUIRED`).
        let unreported = match (
            transition.terminal_charge,
            db.recovered_attempt(assignment_id)?,
        ) {
            (None, Some(recovered))
                if recovered.row.dispatched_at_ms.is_some()
                    && kata_core::operational::CHARGE_BEARING_ATTEMPT_STATES
                        .contains(&transition.state) =>
            {
                match recovered.arm()? {
                    kata_core::operational::AttemptArm::Capsule(occurrence) => {
                        Some(self.settlement_charge(
                            occurrence,
                            super::capsule_settlement::SettlementVerdict::ProvenAmbiguous,
                            super::capsule_settlement::SettlementReport::Unreported,
                        ))
                    }
                    kata_core::operational::AttemptArm::Main(_) => None,
                }
            }
            _ => None,
        };
        let charged = MainSideTransition {
            terminal_charge: unreported.as_ref().or(transition.terminal_charge),
            ..*transition
        };
        db.record_main_side_transition(assignment_id, &charged)?;
        Ok(MainSideOutcome::Recorded)
    }

    /// Transition to `Failed` on the authority chain.
    ///
    /// `pub` alongside [`Self::admit_undispatched_stage`] because those two
    /// together ARE the door `kata-api`'s workflow-level failure sentinel goes
    /// through.
    pub fn mark_failed_and_fold_attempt(
        &self,
        assignment_id: Ulid,
        reason: impl Into<String>,
    ) -> KataResult<()> {
        self.mark_failed_and_report(assignment_id, reason)
            .map(|_| ())
    }

    /// [`Self::mark_failed_and_fold_attempt`], handing back the VERDICT.
    ///
    /// # Why the deadline sweeps needed this rather than a re-read
    ///
    /// The sweeps ask *"did MY failure land, or did a racing terminal beat me to
    /// it?"* and the chain's own answer for THIS transition is strictly more
    /// precise than a re-read that compares a `reason` string.
    pub(crate) fn mark_failed_and_report(
        &self,
        assignment_id: Ulid,
        reason: impl Into<String>,
    ) -> KataResult<MainSideOutcome> {
        let reason = reason.into();
        let mut transition = MainSideTransition {
            reason: Some(reason.as_str()),
            ..MainSideTransition::bare("failed")
        };
        let stage = UndispatchedStageOutcome {
            reason: Some(reason.as_str()),
            ..stage_outcome("failed")
        };
        let outcome = self.fold_main_side(assignment_id, &mut transition, &stage)?;
        self.reconcile_dispatch_charge(assignment_id);
        self.retire_terminal_assignment(assignment_id);
        Ok(outcome)
    }

    /// Transition to `Orphaned`.
    pub(crate) fn mark_orphaned_and_fold_attempt(
        &self,
        assignment_id: Ulid,
        reason: impl Into<String>,
    ) -> KataResult<()> {
        let reason = reason.into();
        let mut transition = MainSideTransition {
            reason: Some(reason.as_str()),
            ..MainSideTransition::bare("orphaned")
        };
        let stage = UndispatchedStageOutcome {
            reason: Some(reason.as_str()),
            ..stage_outcome("orphaned")
        };
        let _outcome = self.fold_main_side(assignment_id, &mut transition, &stage)?;
        self.reconcile_dispatch_charge(assignment_id);
        self.retire_terminal_assignment(assignment_id);
        Ok(())
    }

    /// Transition to `Completed`.
    ///
    /// A completion the MAIN side decides has no worker frame behind it. When the
    /// assignment never held a worker its completion carries `None`.
    ///
    /// When it DOES reach an attempt, the committed output rides the
    /// transition payload. `WorkflowRunner::apply_event` returns `Err` outright on
    /// a `Completed` frame with no output, so a completion recorded without one is
    /// unfoldable rather than merely lossy — and the operational plane refuses to
    /// write that pair at all.
    ///
    /// Test scaffolding only: no production path completes an attempt main-side
    /// (a capsule completes through the result reactor, a main-resolved attempt
    /// through its own resolve verb), so this exists to settle a seeded attempt.
    #[cfg(any(test, feature = "test-support"))]
    pub fn mark_completed_and_fold_attempt(
        &self,
        assignment_id: Ulid,
        output: serde_json::Value,
    ) -> KataResult<()> {
        let mut transition = MainSideTransition {
            output: Some(&output),
            ..MainSideTransition::bare("completed")
        };
        let stage = UndispatchedStageOutcome {
            output: Some(&output),
            ..stage_outcome("completed")
        };
        let _outcome = self.fold_main_side(assignment_id, &mut transition, &stage)?;
        self.reconcile_dispatch_charge(assignment_id);
        self.retire_terminal_assignment(assignment_id);
        Ok(())
    }

    /// AMEND a settled attempt's recorded output — the capsule arm and the
    /// stage-scope class.
    ///
    /// The chain append is the amendment's only home: a capsule attempt has no
    /// other plane to project onto, and an `outcome_amended` frame is the
    /// record every repointed reader folds through the delivery mapping's
    /// overlay.
    ///
    /// `false` — nothing written — for an assignment the chain holds neither an
    /// attempt nor a stage-scope admission for. It is IDEMPOTENT: an append
    /// whose bytes the chain already holds is skipped, so a caller that
    /// re-offers an amendment cannot leave one frame per offer behind it.
    pub fn amend_output_and_fold_attempt(
        &self,
        assignment_id: Ulid,
        envelope: serde_json::Value,
    ) -> KataResult<bool> {
        let db = self.live_work_nucleus();
        let Some(recovered) = db.recovered_attempt(assignment_id)? else {
            if db.undispatched_stage_admission(assignment_id)?.is_some() {
                // The stage-scope record is last-wins, and the writer refuses
                // a stage it cannot prove settled, so appending is the whole
                // amendment — there is no second plane to lag or lead.
                db.record_undispatched_stage_metadata(
                    assignment_id,
                    kata_core::operational::UndispatchedStageRecord::OutcomeAmended(envelope),
                )?;
                return Ok(true);
            }
            return Ok(false);
        };
        let Some(_) = self.attempt_chain_nucleus_if_known(recovered.row.execution_id)? else {
            return Ok(false);
        };
        let outcome = canonicalize_args(&envelope);
        if Self::chain_already_holds_this_amendment(&db, &recovered, &outcome)? {
            return Ok(true);
        }
        db.amend_attempt_outcome(assignment_id, &outcome)?;
        Ok(true)
    }

    /// AMEND a CAPSULE attempt's accepted output.
    ///
    /// The amendment door above writes an attempt-scope append, which every
    /// attempt row can carry; the capsule arm's settlement is its occurrence's
    /// acceptance, which is what this door asks. A capsule attempt has no other
    /// plane to project: its one home is the chain.
    ///
    /// `false` — nothing written — for an execution the nucleus does not hold or an
    /// attempt no occurrence accepted.
    pub fn amend_accepted_capsule_output(
        &self,
        execution_id: Ulid,
        attempt_id: Ulid,
        envelope: &serde_json::Value,
    ) -> KataResult<bool> {
        let Some(db) = self.attempt_chain_nucleus_if_known(execution_id)? else {
            return Ok(false);
        };
        db.amend_accepted_capsule_output(attempt_id, envelope)
    }

    /// Does the chain ALREADY hold these amended bytes as the EFFECTIVE amendment
    /// of this attempt's current settlement?
    ///
    /// # Why this exists
    ///
    /// `amend_attempt_outcome` is a record-only APPEND, so it is not idempotent:
    /// every call leaves another `outcome_amended` frame.
    ///
    /// # The test is the OVERLAY'S OWN RULE, not a second one
    ///
    /// The population fold (`attempt_delivery::population`) applies an amendment
    /// only AFTER the settlement it amends in chain order, which is what keeps a
    /// previous generation's amendment off a re-run generation's completion. So
    /// "already held" has to mean held UNDER THE CURRENT SETTLEMENT: an append that
    /// predates it is invisible to every reader and skipping on it would suppress a
    /// real write. Asked once, here, in the same terms.
    ///
    /// # Bounding
    ///
    /// Compared against the payload as STORED. `OperationalDb::amend_attempt_outcome`
    /// replaces an over-bound outcome with a truncation marker, so the two agree
    /// for every value either door can produce; an outcome that somehow straddled
    /// the bound would compare unequal and re-append, which is the safe direction.
    fn chain_already_holds_this_amendment(
        db: &OperationalDb,
        recovered: &kata_core::operational::RecoveredAttempt,
        outcome: &[u8],
    ) -> KataResult<bool> {
        let settled_seq = recovered
            .state_source_seq
            .unwrap_or(recovered.row.source_seq);
        Ok(db
            .attempt_record_appends(
                kata_core::operational::AttemptRecordScope::Attempt(recovered.row.attempt_id),
                AttemptRecordKind::OutcomeAmended,
            )?
            .last()
            .is_some_and(|held| held.seq > settled_seq && held.payload_json == outcome))
    }
}

/// WHAT ONE MAIN-SIDE TRANSITION DID on the authority chain.
///
/// # Why this is a value and not a `()`
///
/// The chain decides, and there are still two questions a caller cannot answer
/// by re-reading: did MY transition commit, and did it land on a settled
/// generation that declined it. A verdict a caller can silently drop is a
/// verdict nobody acts on, which is why it is `#[must_use]` and why the one
/// named consumption point reports.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[must_use = "a main-side transition may have been REFUSED by the chain; \
              discarding this verdict makes a decision go unrecorded with \
              nobody noticing"]
pub(crate) enum MainSideOutcome {
    /// The chain committed the transition at ATTEMPT scope — the assignment is
    /// a dispatched unit of work.
    Recorded,
    /// The chain committed the transition at STAGE scope — the assignment is a
    /// structurally undispatchable stage admission.
    RecordedAtStageScope,
    /// The chain had already settled this attempt, so its latch stood and it
    /// recorded nothing.
    ChainAlreadySettled {
        /// Whether the settled chain state is the one the main side projected.
        ///
        /// `true` is convergence — a second `failed` landing on a chain the
        /// seam already folded to `failed`. `false` is a re-decision of a
        /// settled generation — a real divergence, reported loudly rather than
        /// swallowed.
        agreed: bool,
    },
    /// The chain holds NEITHER an attempt nor a stage admission for this
    /// assignment, or does not know its execution at all. No current writer
    /// leaves an assignment off the chain. Nothing was recorded, by the additive
    /// polarity this door is bound to.
    NotOnTheChain,
}

/// WHY a capsule delivery was declined — the discriminator a caller needs to
/// choose between "the attempt is settled, stop" and "someone else owns it".
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DeclinedPlacement {
    /// The attempt latched TERMINAL under the delivery. The terminal latch is
    /// ONE-WAY, so no later send can succeed either: the whole delivery is
    /// over, and the attempt already carries the durable outcome whichever
    /// terminalizer decided it.
    LatchedTerminal { status: &'static str },
    /// The attempt is still live but no longer holds this placement — another
    /// main-side actor moved it (a requeue, a park). It is not this delivery's
    /// to advance; the deadline and stall sweeps own a row that then stops
    /// moving.
    MovedOn { status: &'static str },
    /// A LATER delivery already owns the live placement.
    ///
    /// What moved is the OWNERSHIP: a delivery minted after this one claimed the
    /// attempt and sent it, and this send would hand a SECOND delivery frame to
    /// a second worker. See [`DispatchToken`].
    SupersededByALaterDispatch { status: &'static str },
    /// NO attempt row names this assignment at all.
    Untracked,
}

impl DeclinedPlacement {
    /// The attempt's status tag at the moment of refusal, for logs.
    pub(crate) const fn status(self) -> &'static str {
        match self {
            Self::LatchedTerminal { status }
            | Self::MovedOn { status }
            | Self::SupersededByALaterDispatch { status } => status,
            Self::Untracked => "untracked",
        }
    }
}

impl std::fmt::Display for DeclinedPlacement {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::LatchedTerminal { status } => {
                write!(f, "latched terminal at `{status}` under this dispatch")
            }
            Self::MovedOn { status } => {
                write!(f, "moved to `{status}` under this dispatch")
            }
            Self::SupersededByALaterDispatch { status } => write!(
                f,
                "is held at `{status}` by a LATER dispatch's placement, which this \
                 dispatch would overwrite"
            ),
            Self::Untracked => f.write_str("is no longer tracked by the chain"),
        }
    }
}

/// ONE unit of live work as the AUTHORITY chain holds it.
///
/// # Why one type over two chain representations
///
/// An execution's work lives on the chain in two shapes: a DISPATCHABLE stage is
/// an `attempts` row, and a stage satisfied (or parked) without dispatch is a
/// stage-scope transition chain. The dispatcher's sweeps do not make that
/// distinction. Handing the sweeps two types would push the union into five call
/// sites and make "did I remember the other class?" a per-sweep question.
///
/// # The stage-scope half is DELIBERATELY sparse
///
/// A stage-scope row has no placement, no dispatch anchor and no start anchor,
/// because the class is defined by never reaching a worker. Those fields are
/// therefore `None` rather than defaulted to zero — a zero `started_at_ms` would
/// read to the deadline sweep as "started at the epoch", i.e. infinitely overdue,
/// and it would fail every parked stage-scope row on the first tick.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LiveWork {
    /// The assignment identity, aliased to the chain's `attempt_id`.
    pub assignment_id: Ulid,
    /// The execution this work belongs to.
    pub execution_id: Ulid,
    /// The stage name, which every sweep logs and two of them return.
    pub stage_name: SmolStr,
    /// The lifecycle state the chain folds to, in the stamped v4 vocabulary —
    /// equal by construction to `AssignmentStatus::tag()`.
    ///
    /// `None` is CORRUPTION rather than a state, exactly as
    /// [`RecoveredAttempt::state`](kata_core::operational::RecoveredAttempt::state)
    /// documents. Every consumer here routes through [`Self::is`] or
    /// [`Self::is_terminal`], both of which answer an absent state in the
    /// conservative direction.
    pub state: Option<String>,
    /// The worker this work is currently placed on, if any.
    pub worker_id: Option<SmolStr>,
    /// The child execution a parked subworkflow parent waits on.
    pub child_execution_id: Option<Ulid>,
    /// The instant the current generation was placed on a worker.
    pub dispatched_at_ms: Option<u64>,
    /// The instant the worker reported it started — the execution deadline's
    /// anchor, and the durable receipt that a frame reached a worker process.
    pub started_at_ms: Option<u64>,
}

impl LiveWork {
    /// Whether the folded state is exactly `state`.
    ///
    /// Spelled as a method for the reason [`ChainStageState::is`] gives: an absent
    /// state must answer `false` to every such question, and a call site writing
    /// `work.state == Some("dispatched")` would get that right only by accident.
    #[must_use]
    pub fn is(&self, state: &str) -> bool {
        self.state.as_deref() == Some(state)
    }

    /// Whether the folded state is terminal.
    ///
    /// ONE classification, shared with the chain's terminal latch, the registry
    /// filters and both `is_terminal` siblings — see
    /// [`ATTEMPT_TERMINAL_STATES`]. An absent state is NOT terminal, which is the
    /// conservative direction for every sweep: the work stays a candidate and the
    /// per-decision re-read gets another chance to classify it, rather than being
    /// silently shed.
    #[must_use]
    pub fn is_terminal(&self) -> bool {
        self.state
            .as_deref()
            .is_some_and(|state| ATTEMPT_TERMINAL_STATES.contains(&state))
    }

    /// Build from a durable attempt row joined to its folded state.
    ///
    /// Everything this value carries is a row field: neither surviving
    /// assignment-blob arm names a stage, so `attempts.stage_id` is the stage
    /// coordinate the sweeps route on — read off the row rather than decoded.
    fn from_recovered(recovered: &kata_core::operational::RecoveredAttempt) -> KataResult<Self> {
        // BY NAME, before anything else: a MAIN-RESOLVED attempt is no worker's live
        // work, and every sweep this value feeds is a worker leg. The registry
        // excludes it; a point re-read that reaches one is refused as what it is.
        if recovered.row.executor == kata_core::operational::AttemptExecutor::Main {
            return Err(KataError::Validation(format!(
                "dispatcher: attempt {} of execution {} is MAIN-RESOLVED; it is no worker's \
                 live work and no worker leg decides anything about it",
                recovered.row.attempt_id, recovered.row.execution_id
            )));
        }
        Ok(Self {
            assignment_id: recovered.row.attempt_id,
            execution_id: recovered.row.execution_id,
            stage_name: SmolStr::new(recovered.row.stage_id.as_str()),
            state: recovered.state.clone(),
            worker_id: recovered.row.worker_id.as_deref().map(SmolStr::new),
            child_execution_id: recovered.row.child_execution_id,
            dispatched_at_ms: millis(recovered.row.dispatched_at_ms),
            started_at_ms: millis(recovered.row.started_at_ms),
        })
    }

    /// Build from a stage-scope fold — the raw-insert class.
    ///
    /// Infallible, unlike its attempt-scope sibling: the stage name is a REQUIRED
    /// payload key the chain reader already refused without, so there is no blob
    /// left to fail decoding here.
    fn from_stage(stage: &ChainStageState) -> Self {
        Self {
            assignment_id: stage.assignment_id,
            execution_id: stage.execution_id,
            stage_name: SmolStr::new(&stage.stage_name),
            state: stage.state.clone(),
            // See the type doc: absent, never zero.
            worker_id: None,
            child_execution_id: stage.child_execution_id,
            dispatched_at_ms: None,
            started_at_ms: None,
        }
    }
}

/// ONE assignment PARKED on an approval gate, as the deciding plane holds it.
///
/// # Why this type exists at all
///
/// `WorkflowExecutor::pending_approvals` — the operator's entire gate list —
/// reports the park REASON and the park ANCHOR, which `LiveWork` does not carry:
/// it holds `state`, the status TAG only. The fields below are exactly what that
/// consumer reads, with nothing carried for a consumer that does not exist.
///
/// # Not [`LiveWork`], and the reason is a cost rather than taste
///
/// Widening `LiveWork` would put a per-candidate frame probe on the four deadline
/// and retry sweeps, which re-read the registry on every tick and consult neither
/// fact. This reader pays that probe only for the parked population.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParkedApprovalGate {
    /// The assignment an operator will approve or reject.
    pub assignment_id: Ulid,
    /// The execution the gate belongs to.
    pub execution_id: Ulid,
    /// The stage name the gate parks.
    pub stage_name: SmolStr,
    /// The operator-visible reason the park carries.
    pub reason: String,
    /// The first park's authoritative instant, when present.
    ///
    /// # `None` is ABSENT
    ///
    /// The wire type it feeds (`kata_types::approval::PendingApproval`) widened to
    /// `Option<u64>` for this field, because `0` is a fabricated instant
    /// AND is the FIFO sort key of the operator's
    /// panel — every anchorless gate would sort ahead of genuinely older ones.
    ///
    /// A chain-discovered park has a park frame by construction. The reader
    /// preserves an absent anchor as `None`, never a fabricated instant;
    /// malformed authority refuses the read.
    ///
    /// The authoritative pre-image retains the first park's anchor across
    /// re-parking, so a re-parked gate keeps its place in the FIFO panel.
    pub awaiting_since_ms: Option<u64>,
    /// The capsule this gate binds, for a CAPSULE attempt's gate: what approving it
    /// authorizes to run. `None` for a gate of any other class.
    pub capsule: Option<kata_types::approval::PendingCapsuleGate>,
    /// The workspace effect this gate binds, for an `oci` `workspace_effect`
    /// stage's gate: the op, the ref it moves, the candidate it parked
    /// against, and for a `forge_export` the remote and base branch the push
    /// goes to. `None` for every other gate.
    pub workspace_effect: Option<kata_types::approval::PendingWorkspaceEffectGate>,
    /// The expansion this gate binds, for an `oci` bounded-expansion's parked
    /// `on_max = "escalate"` gate: the loop's coordinate and the
    /// bound it spent. `None` for every other gate.
    pub expansion: Option<kata_types::approval::PendingExpansionGate>,
}

/// A durable millisecond column as the sweeps' arithmetic wants it.
///
/// The chain stores `i64` and every sweep compares against a `u64` wall clock. A
/// negative or over-large value is NOT a timestamp, and answering `None` puts it
/// in the same bucket as a column that was never written — which is the bucket
/// every sweep already handles by skipping. Saturating to `0` instead would read
/// as "started at the epoch", i.e. infinitely overdue, and fail live work.
fn millis(stored: Option<i64>) -> Option<u64> {
    stored.and_then(|value| u64::try_from(value).ok())
}

/// The authoritative dispatch-frame blob, encoded the ONE way the chain stores it.
///
/// # One encoder, because there are three writers of one column
///
/// `attempts.assignment_json` is written by the `pending` claim, by the fused
/// claim+dispatch, and by the main-attempt claim.
/// A second spelling of the encoding would make it a convention rather than a
/// rule — and it matters more here than usual because `attempt_payload::frame_arm`
/// is the ONE decoder of this column's arm: a blob encoded differently from the
/// claim's shape is refused there before it is ever a durable row.
///
/// Canonical (recursively key-sorted, compact) so two encodings of one
/// [`DispatchFrame`] are byte-equal, which is what lets a test assert the blob
/// round-trips BYTE-identically rather than merely semantically.
///
/// # The ARM is in the bytes
///
/// The column holds an externally tagged [`DispatchFrame`], so the blob NAMES which
/// shape the attempt was claimed with (`{"capsule": {…}}`) instead of leaving a
/// reader to infer it from which fields happen to be present. This is still the
/// one encoder and `attempt_delivery`'s payload decode is still the one
/// decoder.
///
/// # Failure
///
/// A frame that will not serialize is a typed `Internal` error naming the attempt
/// and the call site, never a silent empty blob — `OperationalDb` refuses an empty
/// one at the writer, but a refusal that reaches the caller with its own coordinates
/// is the one that can be acted on.
pub(crate) fn assignment_blob_for_the_chain(
    frame: &DispatchFrame,
    context: &str,
) -> KataResult<Vec<u8>> {
    Ok(canonicalize_args(
        // THE DISK DOOR: `attempts` rows are PER-ATTEMPT and RETAINED, so a
        // plaintext credential landing in this column is not scrubbed by rotating
        // the credential. `durable_record()` projects one out per arm; it borrows (no
        // clone) for the at-rest frames this build produces, and the capsule arm has
        // no credential carrier to project. See `DispatchFrame::durable_record`.
        &serde_json::to_value(frame.durable_record().as_ref()).map_err(|error| {
            KataError::Internal(format!(
                "dispatcher: serialize dispatch frame for attempt {} for {context}: {error}",
                frame.attempt_id()
            ))
        })?,
    ))
}

/// What the main durably holds about an attempt's placement, for the
/// ingress fence to compare an inbound frame's claims against.
///
/// An OWNED snapshot rather than a borrow of the row: the fence decision and the
/// frame handling that follows it are separated by a `&self` re-entry into the
/// dispatcher, and holding a row borrow across that would force the whole reactor
/// arm to be written around the lifetime instead of around the decision.
#[derive(Debug)]
pub(crate) struct DurableAttemptPlacement {
    /// The fencing lease epoch the attempt's CURRENT generation holds.
    pub(crate) lease_epoch: i64,
    /// The worker the attempt is currently placed on, or `None`.
    pub(crate) worker_id: Option<String>,
}

/// WHICH DISPATCH is asking for a placement — the fact the placement fence
/// needs.
///
/// # The defect it closes
///
/// Two `&Dispatcher` methods in ONE process can race a placement for one
/// attempt, because a capsule delivery and the settlement of an undelivered
/// claim are separated by an `await`. A placement that recorded only WHICH
/// WORKER would leave the send fence unable to distinguish "my own delivery's
/// claim" from "another plane's". This is that missing fact:
/// minted once per delivery, ordered, and compared against the token that owns
/// the live placement.
///
/// # PROCESS-LOCAL, and that is not a gap
///
/// Both planes in the collision are `&Dispatcher` methods in ONE process. A
/// delivery does not survive a crash — the task and its pending send die with
/// the process — so there is no in-flight delivery on the far side of a restart
/// for a token to fence, and nothing here needs a durable home, a migration, a
/// retention rule or a crash-window treatment.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) struct DispatchToken(u64);

#[cfg(test)]
impl DispatchToken {
    pub(super) const fn for_test(value: u64) -> Self {
        Self(value)
    }
}

/// WHICH DELIVERY owns each live placement, and the critical section the
/// delivery decides that under.
///
/// # Why one lock and not a `DashMap`
///
/// The ownership READ and the CLAIM are ONE decision: a competing claim landing
/// between them is exactly what [`DispatchToken`] exists to refuse, so a check
/// the claim is not serialized with would refuse a smaller set than it claims
/// to. A per-key concurrent map gives atomicity per operation, not across two.
/// The section is short, and every write inside it already serializes on
/// `operational.db`'s single writer connection — so a dispatcher-wide lock
/// costs a placement nothing it was not already paying.
#[derive(Debug, Default)]
pub(crate) struct PlacementOwnership {
    /// The token source. Monotonic across the whole process, which is stronger
    /// than the comparison needs and is the cheapest way to be sure of it.
    next: AtomicU64,
    owners: parking_lot::Mutex<HashMap<Ulid, DispatchToken>>,
}

impl PlacementOwnership {
    /// Hand out the next delivery's identity.
    ///
    /// `Relaxed` is the whole ordering this needs: the value is PUBLISHED by
    /// [`Self::section`]'s lock, which is where every comparison happens. The
    /// counter itself only has to be unique and increasing, and `fetch_add` is
    /// both under any ordering.
    fn mint(&self) -> DispatchToken {
        DispatchToken(self.next.fetch_add(1, atomic::Ordering::Relaxed))
    }

    /// Enter the ownership section for one assignment.
    pub(super) fn section(&self, assignment_id: Ulid) -> PlacementOwnershipSection<'_> {
        PlacementOwnershipSection {
            assignment_id,
            owners: self.owners.lock(),
        }
    }
}

/// The held ownership section — see [`PlacementOwnership`]. Dropping it ends the
/// section, so a `drop` is the statement that publishes the claim to the next
/// delivery.
pub(super) struct PlacementOwnershipSection<'a> {
    assignment_id: Ulid,
    owners: parking_lot::MutexGuard<'a, HashMap<Ulid, DispatchToken>>,
}

impl PlacementOwnershipSection<'_> {
    /// Which delivery owns the live placement, if any this process is still
    /// tracking did.
    pub(super) fn owner(&self) -> Option<DispatchToken> {
        self.owners.get(&self.assignment_id).copied()
    }

    /// Record this delivery as the owner of the placement it just claimed.
    pub(super) fn claim(&mut self, dispatch: DispatchToken) {
        self.owners.insert(self.assignment_id, dispatch);
    }
}

impl std::fmt::Display for DispatchToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "#{}", self.0)
    }
}
