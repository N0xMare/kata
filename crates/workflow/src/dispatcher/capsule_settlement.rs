//! SETTLING a capsule attempt the main has lost sight of.
//!
//! # The two legs, and why neither re-delivers
//!
//! A capsule attempt is not deadline-swept, orphaned or re-delivered: the
//! capsule arm is the only arm a worker can hold, and nothing re-sends an
//! attempt — a loss or a stall is adjudicated off the durable chain and
//! settled here. Without this module an attempt whose worker died, or whose
//! container ran forever, would stay `dispatched` for good.
//!
//! [`Dispatcher::settle_lost_capsule_attempt`] is the one door both legs use:
//!
//! * the WORKER-DEATH leg (`handle_worker_death`) settles every capsule attempt placed on
//!   the dead worker;
//! * the WALL-TIME leg ([`Dispatcher::sweep_capsule_wall_time`], every deadline tick)
//!   settles a capsule attempt whose STARTED instant (the worker's capsule-arm start
//!   checkpoint, folded as `running` through the occurrence binding) plus the capsule's
//!   own promised `wall_time_ms` plus [`CAPSULE_WALL_TIME_GRACE_MS`] has passed. An
//!   attempt that has not STARTED is never settled by it: a capsule queued behind a busy
//!   worker is waiting, not late — the start deadline, applied by the worker, is what
//!   bounds the queue.
//!
//! Seven more reach the same recording door
//! ([`Dispatcher::settle_capsule_attempt`], which re-reads liveness under the writer lock
//! so a settlement and an accepting completion are exclusive):
//!
//! * the START-DEADLINE leg ([`Dispatcher::sweep_capsule_start_deadline`]) — a delivered
//!   attempt that never started, past the node's start deadline plus
//!   [`CAPSULE_START_GRACE_MS`], on a worker holding no started attempt;
//! * the RESTART leg ([`Dispatcher::settle_capsule_attempts_after_restart`]) — every
//!   dispatched capsule attempt the previous main left live, before any runner resumes,
//!   once each worker failure the previous main retained undecided has been adjudicated
//!   (which records that attempt's terminal from the worker's report instead), and every
//!   ABANDONED claim (below);
//! * the UNSENT-CLAIM leg ([`Dispatcher::settle_unsent_capsule_claim`]) — a capsule
//!   attempt CLAIMED and never dispatched: from the submit path when its authorization
//!   fails after the claim; from a resumed runner's boot when the dispatch of a claim the
//!   previous main left fails ([`Dispatcher::dispatch_claims_left_undispatched`]); and,
//!   through [`Dispatcher::settle_abandoned_capsule_claims`], from every deadline tick
//!   and the restart leg for a claim whose execution has latched a terminal outcome
//!   (`terminalizing` or terminal) or has no lifecycle row, so no runner will ever boot
//!   and dispatch it;
//! * the SEND-FAILURE leg — a frame the transport refused, or the door could not build,
//!   from the delivery door;
//! * the SEND-DEADLINE leg ([`Dispatcher::settle_stalled_capsule_send`]) — a frame whose
//!   send is still parked at `workers.dispatch_deadline_ms` on a worker that holds no
//!   started attempt, from the delivery door; its write is not cancelled and may still
//!   land (a send queued behind a running attempt is backpressure and is not settled);
//! * the REFUSED-RESULT leg ([`Dispatcher::record_refused_capsule_result`]) — a result the
//!   main's adoption refused, from the reactor;
//! * the COMPLETION-JUDGEMENT leg ([`Dispatcher::judge_capsule_completion`]) — a
//!   completion whose provider reported its capture TRUNCATED, or whose process exited
//!   with a status its stage's checked exit policy fails, from the reactor, before any
//!   byte of the result is read.
//!
//! Each records a MAIN-SIDE terminal (`failed`, or `cancelled` under a standing operator
//! stop) off the attempt's durable OCCURRENCE binding, records its verdict as the typed
//! `verdict` the failure retry reads, and names it again in the recorded reason for the
//! operator: PROVEN AMBIGUOUS when the main cannot see whether the container ran, PROVEN
//! NOT PERFORMED only where no frame can have reached a worker — the send-failure leg,
//! where the frame was never built or the transport answered that it did not arrive whole,
//! and the unsent-claim leg, where no dispatch was ever committed (a frame is sent only
//! after its dispatch commits) — and PERFORMED BUT FAILED only for the completion-judgement
//! leg, whose worker reported the process ran to an exit. A MISSING START is never taken as proof: the start
//! checkpoint is folded asynchronously, so a container can be running while
//! `started_at_ms` is still NULL. The death, deadline and send-deadline legs then send
//! the worker a FENCED `Stop` for that generation, best-effort, so a settled attempt that
//! is still running is killed rather than left to hold the slot the main just released.
//! No durable stop request is written: the attempt is already terminal, and a stop row
//! against a terminal attempt is an ask no worker terminal will ever acknowledge. A late
//! completion is then SUPERSEDED — at the reactor's early check before anything is read,
//! or by the accepting transaction's own fence re-read, which declares nothing. Nothing is
//! re-delivered — there is no capsule re-delivery.
//!
//! # What each settlement is charged
//!
//! Every settlement records a `terminal_charge` ([`Dispatcher::settlement_charge`]), read
//! off what the main HOLDS of the run ([`SettlementReport`]) and the capsule it authorized:
//!
//! * PROVEN NOT PERFORMED — no frame reached a worker, so nothing billed: the authoritative
//!   `0` (`StageUsage::unbilled`).
//! * A `Command` capsule (a shell stage) — its process makes no billable call: the
//!   authoritative `0`, as a shell stage's completion is.
//! * An `Agent` turn whose worker REPORTED a completion (the completion-judgement leg,
//!   the scope judge, the refused-result leg) — the turn's reported usage, priced as the
//!   worker priced it, or `Unavailable` naming the adapter and the model when it reported
//!   none (`kata_types::metering::agent_turn_usage`, the completion's own rule).
//! * An `Agent` capsule with NO report (the death, wall-time, restart, start-deadline and
//!   send-deadline legs) — its turn may have been issued and its usage is unknown:
//!   `Unavailable` naming the capsule's adapter and declared model.
//! * A capsule the main cannot read back — `Unavailable` with no pair to name: a
//!   settlement never stays open over its charge.
//!
//! A charge is never dropped: the main-side writer refuses a failure-class terminal of a
//! dispatched attempt that carries none (`kata_core::operational::TERMINAL_CHARGE_REQUIRED`).

use kata_core::operational::{AttemptArm, MainSideTransition};
use kata_types::error::{KataError, KataResult};
use tracing::{info, warn};
use ulid::Ulid;

use super::Dispatcher;

/// The slack past a capsule's own `wall_time_ms`, measured from its folded start, before
/// the main settles it — `kata_types::capsule_timing::CAPSULE_WALL_TIME_GRACE_MS`.
///
/// DERIVED there rather than chosen here: the worker's prepare budget (start anchor to the
/// provider's assignment, refused past it) plus the provider's frame margin (assignment to
/// the kill) plus a report slack. So the worker's own kill fires before this leg can
/// settle a live attempt; that module states the inequality and the one thing it does not
/// order (a step of this main's wall clock). It is a SWEEP bound — settling late is
/// harmless, settling a live attempt early is the defect.
pub const CAPSULE_WALL_TIME_GRACE_MS: u64 = kata_types::capsule_timing::CAPSULE_WALL_TIME_GRACE_MS;

/// The slack past the node's `assignment_start_deadline` before the main settles a
/// delivered capsule attempt that never started — the worker applies the same deadline
/// and its own report should land first. Errs long for the wall-time grace's reason.
pub const CAPSULE_START_GRACE_MS: u64 = 60_000;

/// The recorded reason's verdict clause when the main cannot see whether the container ran.
const PROVEN_AMBIGUOUS: &str = "PROVEN AMBIGUOUS: the main cannot observe whether this \
     capsule's container ran, so the stage may have done anything it was asked. The attempt \
     is settled terminal and NOT re-delivered (capsule re-delivery is not implemented)";

/// The recorded reason's verdict clause when no dispatch frame for the attempt can have
/// reached a worker — one that was never built, one the transport refused, or one whose
/// dispatch was never committed. The cause before it says which.
const PROVEN_NOT_PERFORMED: &str = "PROVEN NOT PERFORMED: no dispatch frame for this capsule \
     attempt reached a worker, so no container was started for it. The attempt is settled \
     terminal and NOT re-delivered (capsule re-delivery is not implemented)";

/// The recorded reason's verdict clause when the capsule's process RAN AND EXITED and its
/// completion fails the stage — a capture its provider truncated, or an exit status the
/// stage's checked exit policy fails. The cause before it says which.
const PERFORMED_BUT_FAILED: &str = "PERFORMED BUT FAILED: the capsule's process ran and \
     exited, and its completion fails the stage, so its reported /out result is not adopted \
     and the occurrence accepts no outcome. The attempt is settled terminal and NOT \
     re-delivered (capsule re-delivery is not implemented)";

/// The recorded reason `settle_capsule_attempts_after_restart` names.
pub const CAPSULE_MAIN_RESTARTED: &str = "the main restarted";

/// How a settled capsule attempt's effects are classified: its typed `verdict`, and the
/// clause its recorded reason states it in.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SettlementVerdict {
    /// The container never ran.
    ProvenNotPerformed,
    /// The main cannot tell whether it ran.
    ProvenAmbiguous,
    /// It ran, exited, and its completion fails the stage — the
    /// `DeliveryFailureProvenance::PerformedButFailed` shape: nothing about the effect is
    /// unknown, and it did happen.
    PerformedButFailed,
}

impl SettlementVerdict {
    fn clause(self) -> &'static str {
        match self {
            Self::ProvenNotPerformed => PROVEN_NOT_PERFORMED,
            Self::ProvenAmbiguous => PROVEN_AMBIGUOUS,
            Self::PerformedButFailed => PERFORMED_BUT_FAILED,
        }
    }

    /// The typed verdict the terminal transition records.
    fn provenance(self) -> kata_types::effect::DeliveryFailureProvenance {
        use kata_types::effect::DeliveryFailureProvenance as P;
        match self {
            Self::ProvenNotPerformed => P::ProvenNotPerformed,
            Self::ProvenAmbiguous => P::ProvenAmbiguous,
            Self::PerformedButFailed => P::PerformedButFailed,
        }
    }
}

/// What a settlement must still find true UNDER THE WRITER LOCK to be recorded.
#[derive(Clone, Copy, Debug)]
pub(crate) enum SettlementPremise<'a> {
    /// The attempt is not terminal.
    Live,
    /// The start-deadline leg's premise:
    /// [`kata_core::OperationalDb::record_main_side_transition_if_start_overdue`].
    StartOverdue(kata_core::operational::StartOverdue<'a>),
    /// The unsent-claim leg's premise — not terminal, and neither half of a dispatch
    /// recorded: [`kata_core::OperationalDb::record_main_side_transition_if_undispatched`].
    Undispatched,
}

/// Which terminal a settlement records.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SettledAs {
    /// `failed` — or `cancelled` when an operator stop stands against the attempt.
    FailedUnlessStopped,
    /// `cancelled`: the operator cancelled the execution — a cancel reaching a parked
    /// approval gate, or a parked gate whose execution latched a `cancelled` outcome.
    Cancelled,
}

/// What the main HOLDS of a capsule attempt's run when it settles it — the fact its
/// `terminal_charge` is read off ([`Dispatcher::settlement_charge`]).
#[derive(Clone, Copy, Debug)]
pub(crate) enum SettlementReport<'a> {
    /// The worker reported the process's completion: its agent turn's report, or `None`
    /// when the frame carries none (a `Command` capsule's).
    Completion(Option<&'a kata_types::agent::AgentTurnReport>),
    /// No completion reached the main.
    Unreported,
}

/// What one recorded settlement left for the caller to act on: the generation and the
/// placement a fenced stop would name.
pub(crate) struct Settled {
    lease_epoch: i64,
    worker_id: Option<String>,
}

impl Dispatcher {
    /// SETTLE one capsule attempt the main has lost sight of, or report that it is not
    /// one to settle — PROVEN AMBIGUOUS, followed by a best-effort fenced stop.
    ///
    /// `Ok(true)` when a terminal was recorded; `Ok(false)` when the attempt is unknown,
    /// already terminal (including one that turned terminal under the writer lock),
    /// placed on another worker than `on_worker`, or not a capsule attempt.
    ///
    /// # Errors
    ///
    /// A capsule attempt with no occurrence binding (there is no durable authority to
    /// record under), and the main-side writer's own refusals.
    pub(crate) async fn settle_lost_capsule_attempt(
        &self,
        attempt_id: Ulid,
        cause: &str,
        on_worker: Option<&str>,
    ) -> KataResult<bool> {
        let Some(settled) = self.settle_capsule_attempt(
            attempt_id,
            cause,
            on_worker,
            SettlementVerdict::ProvenAmbiguous,
            SettlementReport::Unreported,
            SettlementPremise::Live,
            SettledAs::FailedUnlessStopped,
        )?
        else {
            return Ok(false);
        };
        self.stop_settled_capsule_attempt(attempt_id, cause, &settled)
            .await;
        Ok(true)
    }

    /// The START-DEADLINE leg's settlement of one candidate: recorded only if the
    /// attempt is still unstarted, its worker still holds no started attempt, and it is
    /// still overdue from the later of its dispatch and the worker's last freed slot —
    /// all re-read under the writer lock — then a fenced stop.
    ///
    /// # Errors
    ///
    /// [`Self::settle_lost_capsule_attempt`]'s.
    pub(crate) async fn settle_overdue_capsule_attempt(
        &self,
        attempt_id: Ulid,
        cause: &str,
        overdue: kata_core::operational::StartOverdue<'_>,
    ) -> KataResult<bool> {
        let Some(settled) = self.settle_capsule_attempt(
            attempt_id,
            cause,
            Some(overdue.worker),
            SettlementVerdict::ProvenAmbiguous,
            SettlementReport::Unreported,
            SettlementPremise::StartOverdue(overdue),
            SettledAs::FailedUnlessStopped,
        )?
        else {
            return Ok(false);
        };
        self.stop_settled_capsule_attempt(attempt_id, cause, &settled)
            .await;
        Ok(true)
    }

    /// RECORD one capsule attempt terminal under its occurrence binding, if it is still
    /// live UNDER THE WRITER LOCK — the one recording door every capsule settlement leg
    /// uses. Sends nothing.
    ///
    /// `Ok(None)` for the same set [`Self::settle_lost_capsule_attempt`] answers `false`
    /// for. The liveness re-read is
    /// [`kata_core::OperationalDb::record_main_side_transition_if_live`]'s, which is what
    /// makes a settlement and an accepting completion exclusive: whichever
    /// commits first leaves the other nothing to write.
    ///
    /// # Errors
    ///
    /// An unbound capsule attempt, and the writer's refusals.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn settle_capsule_attempt(
        &self,
        attempt_id: Ulid,
        cause: &str,
        on_worker: Option<&str>,
        verdict: SettlementVerdict,
        report: SettlementReport<'_>,
        premise: SettlementPremise<'_>,
        settled_as: SettledAs,
    ) -> KataResult<Option<Settled>> {
        let face = self.execution_lifecycle();
        let Some(recovered) = face.db().recovered_attempt(attempt_id)? else {
            return Ok(None);
        };
        if recovered.is_terminal() {
            return Ok(None);
        }
        // FENCED on the placement when the caller names one: the death leg's victim scan
        // and this read are not atomic.
        if let Some(worker) = on_worker
            && recovered.row.worker_id.as_deref() != Some(worker)
        {
            return Ok(None);
        }
        // THE OCCURRENCE ROW is the authority this terminal is recorded under — the same
        // binding `plan_worker_failure`'s capsule arm adjudicates off; a capsule arm
        // without one is refused by `arm` itself. A MAIN-RESOLVED attempt is excluded BY
        // NAME: it is never sent, so no capsule settlement — lost, overdue, unsent,
        // undelivered — can be true of it.
        let occurrence = match recovered.arm()? {
            AttemptArm::Capsule(occurrence) => occurrence,
            AttemptArm::Main(_) => return Ok(None),
        };
        let charge = self.settlement_charge(occurrence, verdict, report);
        let stops = self.stops_standing_against_attempt(recovered.row.execution_id, attempt_id)?;
        let verdict_clause = verdict.clause();
        let (state, reason) = match (settled_as, stops.first()) {
            (SettledAs::Cancelled, _) => ("cancelled", format!("{cause}. {verdict_clause}")),
            (SettledAs::FailedUnlessStopped, Some(stop)) => (
                "cancelled",
                format!(
                    "{cause} while an operator stop stood against it (worker {}, reason: {}). \
                     {verdict_clause}",
                    stop.worker_id, stop.reason
                ),
            ),
            (SettledAs::FailedUnlessStopped, None) => {
                ("failed", format!("{cause}. {verdict_clause}"))
            }
        };
        let transition = MainSideTransition {
            reason: Some(&reason),
            terminal_charge: Some(&charge),
            verdict: Some(verdict.provenance()),
            ..MainSideTransition::bare(state)
        };
        let recorded = match premise {
            SettlementPremise::Live => face
                .db()
                .record_main_side_transition_if_live(attempt_id, &transition)?,
            SettlementPremise::StartOverdue(overdue) => face
                .db()
                .record_main_side_transition_if_start_overdue(attempt_id, overdue, &transition)?,
            SettlementPremise::Undispatched => face
                .db()
                .record_main_side_transition_if_undispatched(attempt_id, &transition)?,
        };
        if recorded.is_none() {
            // An accepting completion, another settlement, or (for the start-deadline
            // leg) a folded start committed between the read above and the writer lock:
            // this leg's premise no longer holds, and it has nothing to record.
            return Ok(None);
        }
        warn!(%attempt_id, state, %reason, "dispatcher: settled a capsule attempt main-side");
        self.refresh_worker_result_mirror(attempt_id);
        Ok(Some(Settled {
            lease_epoch: recovered.row.lease_epoch,
            worker_id: recovered.row.worker_id.clone(),
        }))
    }

    /// The `terminal_charge` a settled capsule attempt records — see the module's
    /// "What each settlement is charged".
    ///
    /// Infallible on purpose: a settlement is a liveness door, and a charge it cannot
    /// read the authorized capsule for is UNKNOWN — `Unavailable` with no pair to name,
    /// which a hard cost policy fails closed on — never a reason to leave the attempt
    /// live.
    pub(crate) fn settlement_charge(
        &self,
        occurrence: kata_types::execution_contract::OccurrenceId,
        verdict: SettlementVerdict,
        report: SettlementReport<'_>,
    ) -> kata_types::metering::TerminalCharge {
        use kata_types::metering::{StageUsage, TerminalCharge};
        if verdict == SettlementVerdict::ProvenNotPerformed {
            return TerminalCharge::of_usage(StageUsage::unbilled());
        }
        if let SettlementReport::Completion(Some(agent)) = report {
            return TerminalCharge::of_usage(kata_types::metering::agent_turn_usage(
                agent.usage.as_ref(),
                agent.adapter.as_label(),
                agent
                    .model_reported
                    .as_ref()
                    .map_or("", smol_str::SmolStr::as_str),
            ));
        }
        let usage = match self
            .execution_lifecycle()
            .db()
            .authorized_capsule(occurrence)
        {
            Ok(capsule) => kata_types::metering::unreported_capsule_usage(capsule.process()),
            Err(error) => {
                warn!(
                    occurrence = %occurrence.0,
                    %error,
                    "dispatcher: the settled capsule's authorized capsule is unreadable; its \
                     charge is recorded unknown"
                );
                StageUsage::unmetered("", "")
            }
        };
        TerminalCharge::of_usage(usage)
    }

    /// Send the worker a FENCED `Stop` for a settled generation, best-effort, so a
    /// settled attempt that is still running is killed rather than left holding the slot.
    async fn stop_settled_capsule_attempt(&self, attempt_id: Ulid, cause: &str, settled: &Settled) {
        let Some(worker) = settled.worker_id.as_deref() else {
            return;
        };
        let worker = smol_str::SmolStr::new(worker);
        let stop = kata_transport::types::WorkerControl::Stop {
            assignment_id: attempt_id,
            fence: kata_transport::types::AttemptFence::commanding(
                settled.lease_epoch,
                worker.clone(),
            ),
            reason: format!("the main settled this capsule attempt: {cause}"),
        };
        if let Err(error) = self.supervisor.send_control_to(&worker, stop).await {
            warn!(%attempt_id, %worker, %error, "dispatcher: the settled attempt's stop was not delivered");
        }
    }

    /// RECORD a capsule attempt whose RESULT the main refused (over a bound, the wrong
    /// privacy, an absent member, an unbound attempt) — failed, PROVEN AMBIGUOUS, the
    /// refusal as the reason. The container ran and its effects are unknown; the result
    /// is not adopted. No stop is sent: the worker reported completion. `agent` is the
    /// completion frame's turn report, which the charge is read off.
    ///
    /// `Ok(false)` when the attempt is no longer live under the writer lock.
    ///
    /// # Errors
    ///
    /// [`Self::settle_capsule_attempt`]'s.
    pub(crate) fn record_refused_capsule_result(
        &self,
        attempt_id: Ulid,
        refusal: &str,
        agent: Option<&kata_types::agent::AgentTurnReport>,
    ) -> KataResult<bool> {
        Ok(self
            .settle_capsule_attempt(
                attempt_id,
                &format!("the main refused the capsule's reported result: {refusal}"),
                None,
                SettlementVerdict::ProvenAmbiguous,
                SettlementReport::Completion(agent),
                SettlementPremise::Live,
                SettledAs::FailedUnlessStopped,
            )?
            .is_some())
    }

    /// JUDGE a capsule's reported COMPLETION — its capture, then its exit status — against
    /// its stage, and when it fails, RECORD the attempt `failed` (`cancelled` under a
    /// standing operator stop) instead of adopting its result — PERFORMED BUT FAILED, the
    /// reason carrying the stage's failure error.
    ///
    /// # Why the main judges, and from what
    ///
    /// ADR-0001: the main alone accepts outcomes; a worker returns observations. The exit
    /// code and the `truncated` flag are observations, and whether they are an acceptable
    /// outcome is the stage's to say. The verdict is
    /// [`ShellExitPolicy::judge_provider_completion`](kata_types::workflow::ShellExitPolicy::judge_provider_completion),
    /// the one judgement of a provider-reported shell completion, which asks two
    /// predicates in this order:
    ///
    /// * the CAPTURE first — `judge_provider_capture`: a capture the provider reported
    ///   TRUNCATED (past the assignment's combined `CaptureSpec::limit_bytes`) fails the stage
    ///   whatever its exit policy and whatever it exited;
    /// * then the EXIT STATUS — `ShellExitPolicy::judge_exit`, over the exit code the
    ///   provider reported or `SIGNALLED_EXIT_CODE` when it reported none, against the
    ///   stage's checked `exit_policy`, which the capsule does not carry (its identity folds the
    ///   stage's `contract_hash` through its action, but not the policy's value). So the policy is
    ///   read here off the execution's DURABLE checked program — the program whose hash the
    ///   occurrence was authorized under, cross-checked — never off a process-local registration a
    ///   runner might already have dropped.
    ///
    /// # What is recorded, and what is not
    ///
    /// A failed shell stage's stdout goes nowhere: the /out result is NOT adopted (no
    /// `artifacts` row is declared and the occurrence is not accepted), and the reason
    /// carries the error — the truncation's, or the exit code and a bounded stderr tail.
    /// No retry follows — every capsule-arm failure is terminal: no authoring surface
    /// gives a shell stage a failure-retry policy, and neither failure consumes
    /// `validate_retries`, because each is decided before any output is validated.
    ///
    /// `Ok(true)` when the completion failed the stage (whether or not this call won the
    /// writer lock — a lost race means another terminal already settled the attempt, and
    /// either way the result must not be adopted); `Ok(false)` when the stage accepts it
    /// and the caller adopts the result.
    ///
    /// # Errors
    ///
    /// A storage fault — the execution's program absent, undecodable or carrying stage
    /// classes this binary cannot honour (the decode door's gate,
    /// `validate_carried_stage_execution_classes`), a program that is not the one the
    /// occurrence was authorized under, a stage the program does not hold,
    /// an occurrence with no row — which is not a verdict on the completion, so nothing is
    /// recorded and the attempt stays live; and the recording door's own refusals.
    pub(crate) fn judge_capsule_completion(
        &self,
        recovered: &kata_core::operational::RecoveredAttempt,
        occurrence: kata_types::execution_contract::OccurrenceId,
        exit_code: Option<i32>,
        stderr: &kata_types::execution_contract::ArtifactRef,
        capture_exceeded: bool,
        agent: Option<&kata_types::agent::AgentTurnReport>,
    ) -> KataResult<bool> {
        let policy = self.capsule_stage_exit_policy(recovered, occurrence)?;
        // The judgement's stderr is a bounded TAIL read off the artifact the frame
        // names — the same verified read the adoption performs, never the frame's
        // own bytes (it carries none since the capture moved off the wire).
        let stderr_tail = self
            .execution_lifecycle()
            .db()
            .read_capture_tail(stderr, u64::MAX)?;
        let Err(failure) = policy.judge_provider_completion(
            kata_types::workflow::CAPSULE_CAPTURE_PROVIDER,
            exit_code,
            &stderr_tail,
            capture_exceeded,
        ) else {
            return Ok(false);
        };
        self.settle_capsule_attempt(
            recovered.row.attempt_id,
            &format!("the capsule's process exited and failed its stage: {failure}"),
            None,
            SettlementVerdict::PerformedButFailed,
            SettlementReport::Completion(agent),
            SettlementPremise::Live,
            SettledAs::FailedUnlessStopped,
        )?;
        Ok(true)
    }

    /// The checked `exit_policy` of a capsule attempt's stage, off the execution's durable
    /// program — see [`Self::judge_capsule_completion`].
    fn capsule_stage_exit_policy(
        &self,
        recovered: &kata_core::operational::RecoveredAttempt,
        occurrence: kata_types::execution_contract::OccurrenceId,
    ) -> KataResult<kata_types::workflow::ShellExitPolicy> {
        Ok(self
            .capsule_checked_stage(recovered, occurrence)?
            .policies
            .exit_policy)
    }

    /// The capsule attempt's CHECKED stage, off the execution's durable program
    /// — the one read the exit-policy and output-scope judgements share, so
    /// the closure and the policy are judged against the same program the
    /// occurrence was authorized under.
    fn capsule_checked_stage(
        &self,
        recovered: &kata_core::operational::RecoveredAttempt,
        occurrence: kata_types::execution_contract::OccurrenceId,
    ) -> KataResult<kata_program::execution_program::ExecutionProgramStage> {
        let authorized_under = self
            .execution_lifecycle()
            .db()
            .occurrence(occurrence.0.0)?
            .ok_or_else(|| {
                KataError::Storage(format!(
                    "capsule attempt {}'s occurrence {} has no row",
                    recovered.row.attempt_id, occurrence.0
                ))
            })?
            .program_hash;
        self.checked_program_stage(
            recovered.row.execution_id,
            &recovered.row.stage_id,
            authorized_under,
            &recovered.row.attempt_id.to_string(),
        )
    }

    /// The capsule attempt's CHECKED PROGRAM, off the execution's durable
    /// record — the read the FsPolicy resolution needs beside the stage, so a
    /// `sandbox = "name"` stage is judged against the same program the
    /// occurrence was authorized under.
    fn capsule_checked_program(
        &self,
        recovered: &kata_core::operational::RecoveredAttempt,
        occurrence: kata_types::execution_contract::OccurrenceId,
    ) -> KataResult<kata_program::execution_program::ExecutionProgram> {
        let authorized_under = self
            .execution_lifecycle()
            .db()
            .occurrence(occurrence.0.0)?
            .ok_or_else(|| {
                KataError::Storage(format!(
                    "capsule attempt {}'s occurrence {} has no row",
                    recovered.row.attempt_id, occurrence.0
                ))
            })?
            .program_hash;
        self.checked_program(
            recovered.row.execution_id,
            authorized_under,
            &recovered.row.attempt_id.to_string(),
        )
    }

    /// An execution's durable checked program — the program-decode door's
    /// class validation included — compared against the hash the occurrence
    /// was authorized under, so the read is the authorization's own record,
    /// not just loaded; `subject` decorates the refusal with who was being
    /// judged.
    pub(super) fn checked_program(
        &self,
        execution_id: ulid::Ulid,
        authorized_under: [u8; 32],
        subject: &str,
    ) -> KataResult<kata_program::execution_program::ExecutionProgram> {
        let face = self.execution_lifecycle();
        let bytes = face.program_json(execution_id)?.ok_or_else(|| {
            KataError::Storage(format!(
                "execution {execution_id} holds no checked program for {subject}"
            ))
        })?;
        let program: kata_program::execution_program::ExecutionProgram =
            serde_json::from_slice(&bytes).map_err(|error| {
                KataError::Storage(format!(
                    "execution {execution_id}'s checked program does not decode: {error}"
                ))
            })?;
        // "Invalid combinations fail before a run is created", READ side — a
        // DURABLE PROGRAM DECODE DOOR, declared in
        // `durable_execution_class_revalidation.rs`: a decoded program this binary
        // cannot honour is not one whose stage facts may be applied.
        program
            .validate_carried_stage_execution_classes()
            .map_err(|invalid| {
                KataError::Storage(format!(
                    "execution {execution_id}'s checked program carries stage classes this binary cannot honour, so {subject} is not judged against it: {invalid}",
                ))
            })?;
        if program.program_hash.0 != authorized_under {
            return Err(KataError::Storage(format!(
                "the occurrence {subject} judges was authorized under program {} and execution {execution_id} holds program {}",
                kata_types::primitives::ContentHash::new(authorized_under),
                program.program_hash
            )));
        }
        Ok(program)
    }

    /// A stage of a checked program — the lookup every program-holding caller
    /// shares. A capsule attempt's stage may be a SYNTHETIC expansion member —
    /// `<base>#child-<role>` minted at dispatch off the base stage's
    /// invocation envelope (`parse_child_invocation_stage_name`). The
    /// program holds only the base; the member's judged facts — exit
    /// policy, produces closure — are the base stage's, the very checked
    /// stage `preflight_derived_dispatch` handed the member's dispatch.
    /// The refused set is unchanged: a base the program does not hold, or
    /// a role the base's envelope does not declare, still names no checked
    /// stage.
    pub(super) fn program_stage(
        program: &kata_program::execution_program::ExecutionProgram,
        execution_id: ulid::Ulid,
        stage_id: &str,
        subject: &str,
    ) -> KataResult<kata_program::execution_program::ExecutionProgramStage> {
        if let Some((base, role)) =
            kata_types::execution_contract::parse_child_invocation_stage_name(stage_id)
        {
            let base_stage = program
                .stages
                .get(&kata_types::workflow::StageId(base.clone()))
                .cloned()
                .ok_or_else(|| {
                    KataError::Storage(format!(
                        "{subject} names stage {stage_id:?}, which execution {execution_id}'s checked program does not hold"
                    ))
                })?;
            // A DYNAMIC fanout's child is spelled
            // `<base>#child-<role>-<label>` (`dynamic_child_invocation_stage_name`):
            // its segment is a declared role, a `-`, and a non-empty label.
            let envelope = &base_stage.invocation_envelope;
            let declared = envelope.children.iter().any(|child| {
                child.role == role
                    || (envelope.dynamic_fanout
                        && role
                            .strip_prefix(child.role.as_str())
                            .and_then(|rest| rest.strip_prefix('-'))
                            .is_some_and(|label| !label.is_empty()))
            });
            if !declared {
                return Err(KataError::Storage(format!(
                    "{subject} names stage {stage_id:?} carrying child role {role:?}, which the checked program's stage {base:?} does not declare"
                )));
            }
            return Ok(base_stage);
        }
        program
            .stages
            .get(&kata_types::workflow::StageId(smol_str::SmolStr::new(stage_id)))
            .cloned()
            .ok_or_else(|| {
                KataError::Storage(format!(
                    "{subject} names stage {stage_id:?}, which execution {execution_id}'s checked program does not hold"
                ))
            })
    }

    /// A stage of an execution's durable checked program — the program-decode
    /// door's class validation included — for a caller holding coordinates
    /// rather than a recovered attempt (the approval gate's view) or one
    /// (the scope judge's resolution). `authorized_under` is the program hash
    /// the occurrence was authorized under, so the program read is compared
    /// against the authorization's own record, not just loaded; `subject`
    /// decorates the refusal with who was being judged.
    pub(crate) fn checked_program_stage(
        &self,
        execution_id: ulid::Ulid,
        stage_id: &str,
        authorized_under: [u8; 32],
        subject: &str,
    ) -> KataResult<kata_program::execution_program::ExecutionProgramStage> {
        let program = self.checked_program(execution_id, authorized_under, subject)?;
        Self::program_stage(&program, execution_id, stage_id, subject)
    }

    /// JUDGE the reported `/work` delta's SCOPE before
    /// adoption. Two refusals, both PERFORMED BUT FAILED (the container ran,
    /// the attempt is charged) with the whole delta never applied:
    ///
    /// 1. `work_delta_unsupported_repository` — a `.gitattributes` WRITE
    ///    carrying a checkout conversion (`filter`, `ident`,
    ///    `working-tree-encoding`, `eol=crlf`), judged on the delta's OWN
    ///    content through the admission census's one attribute parser
    ///    ([`kata_vcs::jj::checkout_conversion_findings`]). This check is
    ///    unconditional — it runs under whole-tree scope too, because scope is
    ///    not the question a conversion smuggles past.
    /// 2. `work_delta_out_of_scope` — every changed path must be covered by
    ///    the stage's `produces_files`. An EMPTY
    ///    closure is whole-tree scope — `check_output_closure`
    ///    would call every path undeclared if consulted with it, so the judge
    ///    gates on emptiness itself. A `workspace = "ro"` stage's closure is
    ///    the EMPTY set BY POSTURE, not by declaration — the capsule mounts
    ///    `/work` read-write (`oci_bundle` refuses a ReadOnly `/work`), so
    ///    this door is where the posture is enforced and ANY non-empty delta
    ///    is refused by that name.
    ///
    /// `agent` is the completion frame's turn report: a refused delta's attempt is
    /// charged what its turn reported, never dropped.
    ///
    /// `Ok(true)` when the completion failed a check and this call settled the
    /// attempt (nothing is adopted); `Ok(false)` proceeds to adoption.
    ///
    /// # Errors
    ///
    /// A storage fault — the program, the evidence, the artifact row or the
    /// CAS read — is not a verdict on the completion and propagates
    /// unrecorded.
    pub fn judge_work_delta_scope(
        &self,
        recovered: &kata_core::operational::RecoveredAttempt,
        occurrence: kata_types::execution_contract::OccurrenceId,
        work_delta: Option<&kata_types::execution_contract::ArtifactRef>,
        agent: Option<&kata_types::agent::AgentTurnReport>,
    ) -> KataResult<bool> {
        let Some(reference) = work_delta else {
            // No delta reported: adoption refuses a missing delta on a mapped
            // capsule itself; there is nothing here to judge.
            return Ok(false);
        };
        let db = std::sync::Arc::clone(self.execution_lifecycle().db());
        let delta = read_recorded_work_delta(&db, reference)?;
        let cas = db.output_cas().ok_or_else(|| {
            KataError::Storage(
                "a capsule's /work delta exists only where the node binds a content store"
                    .to_owned(),
            )
        })?;
        // A `.git`/`.jj` component at any depth: a checkout's own bookkeeping —
        // jj's checkout refuses it as a reserved path component, so the tree could
        // publish and then wedge every later materialization. Refused whole at
        // adoption, before anything else judges the delta.
        if let Some(change) = delta
            .changes()
            .iter()
            .find(|change| change.path.reserved_vcs_component().is_some())
        {
            let component = change.path.reserved_vcs_component().unwrap_or("<unknown>");
            return Ok(self
                .settle_capsule_attempt(
                    recovered.row.attempt_id,
                    &format!(
                        "the capsule's /work delta writes `{path}` whose component `{component}` \
                         is VCS-internal ({token}). The whole delta is refused \
                         — nothing of it is applied — and the stage is performed but failed",
                        path = change.path.as_str(),
                        token = kata_types::tree_artifact::WORK_DELTA_RESERVED_PATH,
                    ),
                    None,
                    SettlementVerdict::PerformedButFailed,
                    SettlementReport::Completion(agent),
                    SettlementPremise::Live,
                    SettledAs::FailedUnlessStopped,
                )?
                .is_some());
        }
        for change in delta.changes() {
            let path = change.path.as_str();
            if !path.ends_with(".gitattributes") {
                continue;
            }
            let kata_types::tree_delta::TreeChangeKind::Write { node } = &change.change else {
                continue;
            };
            let Some(object) = node.object() else {
                continue;
            };
            let bytes = cas.get_verified(
                &object,
                node.size_bytes(),
                kata_types::tree_artifact::MAX_MEMBER_BYTES,
            )?;
            let findings = kata_vcs::jj::checkout_conversion_findings(path, &bytes);
            if !findings.is_empty() {
                let rendered = findings
                    .iter()
                    .map(|finding| format!("{finding:?}"))
                    .collect::<Vec<_>>()
                    .join(", ");
                // `Ok(None)` from the settle is the premise lapsed: another
                // writer (the accepting completion, another settlement)
                // committed first — the attempt is no longer this judge's to
                // settle, and the caller falls through to adoption, whose own
                // arbitration reads the recorded outcome.
                return Ok(self
                    .settle_capsule_attempt(
                        recovered.row.attempt_id,
                        &format!(
                            "the capsule's /work delta writes `{path}` declaring a checkout \
                             conversion the `oci` profile does not serve \
                             (work_delta_unsupported_repository): {rendered}. The whole delta is \
                             refused — nothing of it is applied"
                        ),
                        None,
                        SettlementVerdict::PerformedButFailed,
                        SettlementReport::Completion(agent),
                        SettlementPremise::Live,
                        SettledAs::FailedUnlessStopped,
                    )?
                    .is_some());
            }
        }
        // THE SCOPE CHECK — the effective closure is the stage's authored
        // `produces_files`. (A `mutation_policy = "owned_paths"` fanout's
        // per-child scope is judged by the runner over each member's recorded
        // delta, `MutationScopeCheck`.)
        let program = self.capsule_checked_program(recovered, occurrence)?;
        let stage = Self::program_stage(
            &program,
            recovered.row.execution_id,
            &recovered.row.stage_id,
            &recovered.row.attempt_id.to_string(),
        )?;
        // THE `workspace = "ro"` ARM — the authored filesystem posture is part
        // of the scope question the delta answers. `assemble_capsule` binds
        // `/work` ReadWrite for every workspace profile — `oci_bundle`
        // refuses a ReadOnly `/work` by design, so containment cannot stop a
        // capsule from writing under `ro`; the posture's enforcement is this
        // door, at adoption: ANY non-empty delta is out of scope. A `Named`
        // profile the program's own `sandbox_profiles` map cannot answer is
        // the record contradicting its own map — Storage, not a judgement.
        let fs = match stage.policies.sandbox.as_ref() {
            Some(kata_types::sandbox::SandboxRef::Named(name)) => {
                let profile = program.sandbox_profiles.get(name).ok_or_else(|| {
                    KataError::Storage(format!(
                        "stage {}'s sandbox profile \"{name}\" is absent from execution {}'s \
                         checked `sandbox_profiles` — a reference the CHECK resolved at admission",
                        stage.stage_id.0, recovered.row.execution_id,
                    ))
                })?;
                Some(&profile.fs)
            }
            Some(kata_types::sandbox::SandboxRef::Inline(profile)) => Some(&profile.fs),
            None => None,
        };
        if matches!(fs, Some(kata_types::sandbox::FsPolicy::WorkspaceRo))
            && !delta.changes().is_empty()
        {
            let names = delta
                .changes()
                .iter()
                .map(|change| change.path.as_str())
                .collect::<Vec<_>>()
                .join(", ");
            return Ok(self
                .settle_capsule_attempt(
                    recovered.row.attempt_id,
                    &format!(
                        "the capsule's /work delta writes under a `workspace = \"ro\"` sandbox, \
                         whose stage may write nothing (work_delta_out_of_scope): {names}. The \
                         whole delta is refused — nothing of it is applied — and the stage is \
                         performed but failed"
                    ),
                    None,
                    SettlementVerdict::PerformedButFailed,
                    SettlementReport::Completion(agent),
                    SettlementPremise::Live,
                    SettledAs::FailedUnlessStopped,
                )?
                .is_some());
        }
        let declared = &stage.produces_files;
        if declared.is_empty() {
            return Ok(false);
        }
        let changed: Vec<String> = delta
            .changes()
            .iter()
            .map(|change| change.path.as_str().to_owned())
            .collect();
        let report = kata_program::execution_program::check_output_closure(declared, &changed);
        if !report.undeclared.is_empty() {
            let names = report
                .undeclared
                .iter()
                .map(smol_str::SmolStr::as_str)
                .collect::<Vec<_>>()
                .join(", ");
            return Ok(self
                .settle_capsule_attempt(
                    recovered.row.attempt_id,
                    &format!(
                        "the capsule's /work delta wrote outside the stage's declared \
                         `produces_files` scope (work_delta_out_of_scope): {names}. The \
                         whole delta is refused — nothing of it is applied — and the stage is \
                         performed but failed"
                    ),
                    None,
                    SettlementVerdict::PerformedButFailed,
                    SettlementReport::Completion(agent),
                    SettlementPremise::Live,
                    SettledAs::FailedUnlessStopped,
                )?
                .is_some());
        }
        Ok(false)
    }

    /// The derived mirror refresh an ACCEPTED capsule completion owes, for the reactor.
    pub(crate) fn refresh_capsule_result_mirror(&self, attempt_id: Ulid) {
        self.refresh_worker_result_mirror(attempt_id);
    }

    /// SETTLE every live capsule attempt at MAIN START, before any runner resumes.
    ///
    /// # Why restart is a settlement leg of its own
    ///
    /// No other leg reaches these attempts after a restart. The previous main's
    /// reactors died with it, so the death leg never fires for its workers' attempts
    /// (a worker that reconnects is a new registration); the wall-time leg skips an attempt that never started; and the
    /// runner's resume population excludes capsule rows, so it re-submits the stage as
    /// a SECOND generation while the first stays `dispatched` — and the closeout
    /// witness, which reads every attempt, then holds the execution in `terminalizing`
    /// for good. There is no capsule re-delivery, so the only honest answer is to settle.
    ///
    /// PROVEN AMBIGUOUS, ALWAYS — including an attempt with no recorded start. The
    /// placement commits `dispatched_at_ms` BEFORE the send, so the plane cannot say
    /// whether the frame left before the main died; and the worker's start checkpoint is
    /// folded asynchronously, so a container can have been running while `started_at_ms`
    /// was still NULL. Neither absence proves the container never ran. The terminal is
    /// `failed`, or `cancelled` when an operator stop stands against the attempt
    /// (`SettledAs::FailedUnlessStopped`).
    ///
    /// # A failure the previous main retained
    ///
    /// The one report the previous main can have HELD without deciding is a worker
    /// failure: the reactor retains it in the inbox (`buffer_worker_failure`, its own
    /// commit) before it adjudicates it, so a main that died between the two leaves an
    /// `accepted = 0` row whose attempt is still live. Before anything is settled, every
    /// such failure of an execution holding a dispatched capsule attempt is adjudicated
    /// through the reactor's own door ([`Self::adjudicate_worker_failure_input`]), so its
    /// attempt records the WORKER'S verdict, reason and provider failure, and the
    /// settlement below then finds it terminal and writes nothing. An adjudication that
    /// cannot be made (an unreadable inbox, a refused input, or the pass's
    /// `RETAINED_FAILURE_BUDGET` elapsed) is logged and leaves the attempt to this
    /// settlement — PROVEN AMBIGUOUS, the verdict without the report.
    /// A worker COMPLETION is never retained undecided: the reactor accepts one in the
    /// single transaction that adopts its result (`adopt_and_accept_capsule_completion`).
    ///
    /// No stop is sent: nothing is connected yet. A worker that outlived the main does not
    /// keep the container: on a transport that carries control frames the worker loop
    /// races every capsule against its control channel, and a channel that closes ends the
    /// attempt and cancels the container (`kata_worker::worker_loop`'s
    /// `on_control_while_running`); on one that does not, the worker's own provider budget
    /// (`wall_time_ms` plus `PROVIDER_FRAME_MARGIN`) ends it. Either way its late frames are
    /// refused by the fence against a terminal attempt.
    ///
    /// # Claimed attempts
    ///
    /// A claim no dispatch reached is settled here only when it is ABANDONED
    /// ([`Self::settle_abandoned_capsule_claims`]'s predicate: its execution has latched
    /// a terminal outcome or has no lifecycle row). A claim of an execution that will
    /// resume is left for that execution's runner, whose boot dispatches it off its
    /// durable row ([`Self::dispatch_claims_left_undispatched`]); settling it would
    /// force a second generation for work that was never sent anywhere.
    ///
    /// # Errors
    ///
    /// Only an unreadable attempt registry; a per-attempt failure is logged and the pass
    /// continues, so one bad row cannot hold every other execution's recovery.
    pub fn settle_capsule_attempts_after_restart(&self) -> KataResult<Vec<Ulid>> {
        let face = self.execution_lifecycle();
        let live = face.db().live_attempts()?;
        self.adjudicate_failures_retained_before_restart(&live);
        let mut settled = Vec::new();
        for recovered in live {
            let attempt_id = recovered.row.attempt_id;
            match recovered.arm() {
                Ok(AttemptArm::Capsule(_)) => {}
                // BY NAME: a main-resolved attempt is never sent, so a restart settles
                // nothing about it — it waits on in its durable state.
                Ok(AttemptArm::Main(_)) => continue,
                Err(error) => {
                    warn!(%attempt_id, %error, "capsule restart settlement: cannot classify the attempt");
                    continue;
                }
            }
            // A CLAIM no dispatch reached: settled only when abandoned — see the doc.
            if recovered.row.dispatched_at_ms.is_none() {
                match self.settle_capsule_claim_if_abandoned(&recovered) {
                    Ok(true) => settled.push(attempt_id),
                    Ok(false) => {}
                    Err(error) => {
                        warn!(%attempt_id, %error, "restart settlement of an abandoned capsule claim failed");
                    }
                }
                continue;
            }
            match self.settle_capsule_attempt(
                attempt_id,
                CAPSULE_MAIN_RESTARTED,
                None,
                SettlementVerdict::ProvenAmbiguous,
                SettlementReport::Unreported,
                SettlementPremise::Live,
                SettledAs::FailedUnlessStopped,
            ) {
                Ok(Some(_)) => settled.push(attempt_id),
                Ok(None) => {}
                Err(error) => {
                    warn!(%attempt_id, %error, "restart settlement of a capsule attempt failed");
                }
            }
        }
        if !settled.is_empty() {
            info!(
                count = settled.len(),
                "settled capsule attempts left live by the previous main"
            );
        }
        Ok(settled)
    }

    /// Adjudicate every worker failure the previous main retained undecided, for each
    /// execution in `live` holding a dispatched capsule attempt — the first step of
    /// [`Self::settle_capsule_attempts_after_restart`], which says why. Infallible by
    /// design: a failure here is logged, and the restart settlement still settles the
    /// attempt.
    fn adjudicate_failures_retained_before_restart(
        &self,
        live: &[kata_core::operational::RecoveredAttempt],
    ) {
        const RETAINED_FAILURE_BUDGET: std::time::Duration = std::time::Duration::from_secs(30);
        let executions: std::collections::BTreeSet<Ulid> = live
            .iter()
            .filter(|recovered| {
                recovered.row.dispatched_at_ms.is_some()
                    && matches!(recovered.arm(), Ok(AttemptArm::Capsule(_)))
            })
            .map(|recovered| recovered.row.execution_id)
            .collect();
        let deadline = std::time::Instant::now() + RETAINED_FAILURE_BUDGET;
        let face = self.execution_lifecycle();
        for execution_id in executions {
            let inputs = match face.db().buffered_worker_failures(execution_id, deadline) {
                Ok(inputs) => inputs,
                Err(error) => {
                    warn!(%execution_id, %error, "restart: the retained worker failures cannot be read; their attempts settle without them");
                    continue;
                }
            };
            for input in inputs {
                if let Err(error) = self.adjudicate_worker_failure_input(&input) {
                    let attempt_id = input.attempt_id;
                    warn!(%attempt_id, %error, "restart: a retained worker failure was not adjudicated; its attempt settles without it");
                }
            }
        }
    }

    /// SETTLE a capsule attempt CLAIMED and never dispatched — PROVEN NOT PERFORMED, under
    /// the [`SettlementPremise::Undispatched`] premise re-read under the writer lock.
    ///
    /// Honest because a capsule frame is only ever sent AFTER `dispatch_claimed_attempt`
    /// commits the placement and its command (`authorize_attempt`, then
    /// [`Self::deliver_capsule_frame`], which reads the committed placement back): an
    /// attempt with neither has reached no worker, and once this records it terminal the
    /// attempt-scope latch refuses the dispatch that could have sent it.
    ///
    /// `Ok(false)` when the attempt is unknown, terminal, not a capsule attempt, or
    /// dispatched by the time the lock is held.
    ///
    /// # Errors
    ///
    /// [`Self::settle_capsule_attempt`]'s.
    pub(crate) fn settle_unsent_capsule_claim(
        &self,
        attempt_id: Ulid,
        cause: &str,
    ) -> KataResult<bool> {
        self.settle_unsent_capsule_claim_as(attempt_id, cause, SettledAs::FailedUnlessStopped)
    }

    /// [`Self::settle_unsent_capsule_claim`], recording `settled_as`'s terminal.
    fn settle_unsent_capsule_claim_as(
        &self,
        attempt_id: Ulid,
        cause: &str,
        settled_as: SettledAs,
    ) -> KataResult<bool> {
        Ok(self
            .settle_capsule_attempt(
                attempt_id,
                cause,
                None,
                SettlementVerdict::ProvenNotPerformed,
                SettlementReport::Unreported,
                SettlementPremise::Undispatched,
                settled_as,
            )?
            .is_some())
    }

    /// SETTLE every ABANDONED capsule claim — a capsule attempt claimed, never dispatched,
    /// whose execution has latched a terminal outcome (`terminalizing` or terminal) or has
    /// no lifecycle row — PROVEN NOT PERFORMED. Run by every deadline tick and by the
    /// restart leg.
    ///
    /// # Why an abandoned claim needs a leg
    ///
    /// Only its execution's resumed runner ever dispatches a claim the previous main
    /// left ([`Self::dispatch_claims_left_undispatched`], at boot), and an execution
    /// that has latched its outcome is never resumed. Left alone the claim is live
    /// forever: it pins its
    /// Nix environment (`release_environment` refuses `environment_bound_to_live_attempt`)
    /// and, while the execution is `terminalizing`, the closeout witness refuses to finish
    /// it — on every boot. No other leg reaches it: the wall-time and start-deadline legs
    /// read a start or a dispatch it does not have, and the death leg a placement.
    ///
    /// # Errors
    ///
    /// Only an unreadable attempt registry; a per-attempt failure is logged and the pass
    /// continues.
    pub fn settle_abandoned_capsule_claims(&self) -> KataResult<Vec<Ulid>> {
        let mut settled = Vec::new();
        for recovered in self.execution_lifecycle().db().live_attempts()? {
            let attempt_id = recovered.row.attempt_id;
            if recovered.row.dispatched_at_ms.is_some() {
                continue;
            }
            match recovered.arm() {
                Ok(AttemptArm::Capsule(_)) => {}
                // BY NAME: a waiting main attempt is undispatched by construction and is
                // no abandoned CAPSULE claim.
                Ok(AttemptArm::Main(_)) => continue,
                Err(error) => {
                    warn!(%attempt_id, %error, "abandoned-claim sweep: cannot classify the attempt");
                    continue;
                }
            }
            match self.settle_capsule_claim_if_abandoned(&recovered) {
                Ok(true) => settled.push(attempt_id),
                Ok(false) => {}
                Err(error) => {
                    warn!(%attempt_id, %error, "abandoned-claim sweep: settlement failed");
                }
            }
        }
        if !settled.is_empty() {
            info!(
                count = settled.len(),
                "settled capsule claims their executions abandoned"
            );
        }
        Ok(settled)
    }

    /// The abandonment predicate and the settlement, for one capsule claim.
    ///
    /// # A parked approval gate is a claim like any other here
    ///
    /// A gate parked `awaiting_approval` is a live, undispatched claim, so it is settled on
    /// the same predicate: NEVER while its execution is `admitting` or `running` (the
    /// gate is waiting for an operator, not abandoned — a gate has no expiry), and
    /// PROVEN NOT PERFORMED once the execution has latched an outcome or has no lifecycle
    /// row. The recorded reason names the approval park, and for a parked gate a latched
    /// `cancelled` outcome records `cancelled` rather than `failed`.
    fn settle_capsule_claim_if_abandoned(
        &self,
        recovered: &kata_core::operational::RecoveredAttempt,
    ) -> KataResult<bool> {
        use crate::execution_program_store::ExecutionLifecycleState as State;
        let attempt_id = recovered.row.attempt_id;
        let execution_id = recovered.row.execution_id;
        let lifecycle = self.execution_lifecycle().lifecycle(execution_id)?;
        // The resume scan enumerates `execution_lifecycle` alone, so an execution with no
        // row there is never resumed — abandoned for the same reason a latched one is, and
        // named for what it is rather than as an outcome it never latched.
        let parked =
            recovered.state.as_deref() == Some(kata_core::operational::AWAITING_APPROVAL_STATE);
        let (why, cancelled) = match lifecycle.as_ref() {
            Some(record) if matches!(record.state, State::Admitting | State::Running) => {
                return Ok(false);
            }
            Some(record) => (
                format!("has latched its outcome ({})", record.state.as_str()),
                record.terminal_outcome.unwrap_or(record.state) == State::Cancelled,
            ),
            None => (
                "has no lifecycle row, so nothing resumes it".to_owned(),
                false,
            ),
        };
        // A PARKED GATE of a cancelled execution is recorded `cancelled`: the operator's
        // cancel is what ended the wait. An un-parked claim keeps `failed` (the stop-aware
        // default), which is what it recorded before approval gates existed.
        let settled_as = if parked && cancelled {
            SettledAs::Cancelled
        } else {
            SettledAs::FailedUnlessStopped
        };
        let cause = if parked {
            format!(
                "the capsule attempt was PARKED AWAITING APPROVAL and never approved or \
                 dispatched, and its execution {execution_id} {why}, so no operator decision \
                 will ever dispatch it"
            )
        } else {
            format!(
                "the capsule attempt was claimed and never dispatched, and its execution \
                 {execution_id} {why}, so no runner will resume and dispatch it"
            )
        };
        self.settle_unsent_capsule_claim_as(attempt_id, &cause, settled_as)
    }

    /// SETTLE a capsule attempt whose dispatch frame the transport did NOT deliver —
    /// PROVEN NOT PERFORMED, since no worker holds it. Called from the delivery door.
    ///
    /// # What an `Err` from `dispatch_to` proves, per transport
    ///
    /// A frame the door could not BUILD (a stored blob that does not decode,
    /// `frame_for_dispatch`'s stamp read, the checked frame's validation) never reached the
    /// transport at all. The supervisor's own
    /// refusals (no such worker, a dead transport) precede any byte.
    /// `InProcessTransport` refuses only on a closed channel, which delivers nothing.
    /// `LocalSocketTransport` refuses when a write of the length-prefixed frame fails; a
    /// frame whose last byte never reached the socket is a truncated frame, which the
    /// worker's reader refuses and drops the connection on, never decoding it. There is no
    /// other worker transport.
    pub(crate) fn settle_undelivered_capsule_attempt(
        &self,
        attempt_id: Ulid,
        worker_id: &str,
        error: &KataError,
    ) {
        let cause = format!("the dispatch frame was not delivered to worker {worker_id}: {error}");
        if let Err(settle_error) = self.settle_capsule_attempt(
            attempt_id,
            &cause,
            None,
            SettlementVerdict::ProvenNotPerformed,
            SettlementReport::Unreported,
            SettlementPremise::Live,
            SettledAs::FailedUnlessStopped,
        ) {
            warn!(%attempt_id, %settle_error, "settling an undelivered capsule attempt failed");
        }
    }

    /// SETTLE a capsule attempt whose dispatch send is still parked at
    /// `workers.dispatch_deadline_ms` on a worker that is not draining its connection —
    /// PROVEN AMBIGUOUS, then a fenced stop. Called from the delivery door. `true` when a
    /// terminal was recorded.
    ///
    /// "Not draining" is the start-deadline leg's premise, re-read under the writer lock
    /// with the dispatch deadline as its window: the attempt is unstarted, the worker
    /// holds no started attempt, and neither the dispatch nor the worker's last freed slot
    /// is within the deadline. A worker running an attempt takes its next frame only when
    /// that attempt ends, so a send queued behind it is backpressure and is not settled
    /// here (`false`).
    pub(crate) fn settle_stalled_capsule_send(
        &self,
        attempt_id: Ulid,
        worker_id: &str,
        error: &KataError,
    ) -> bool {
        let deadline_ms = i64::try_from(self.send_timeout.as_millis()).unwrap_or(i64::MAX);
        let overdue = kata_core::operational::StartOverdue {
            worker: worker_id,
            now_ms: i64::try_from(super::dispatcher_now_ms()).unwrap_or(i64::MAX),
            // The guard asks for MORE than the window; the send was parked for at least
            // the whole deadline, and both instants are whole milliseconds.
            window_ms: deadline_ms.saturating_sub(1),
        };
        self.settle_unconfirmed_send_under(
            attempt_id,
            worker_id,
            error,
            SettlementPremise::StartOverdue(overdue),
        )
    }

    /// SETTLE a capsule attempt whose dispatch send task did not run to an answer, so part
    /// of the frame may have been written — PROVEN AMBIGUOUS, then a fenced stop. Called
    /// from the delivery door.
    pub(crate) fn settle_unconfirmed_capsule_send(
        &self,
        attempt_id: Ulid,
        worker_id: &str,
        error: &KataError,
    ) {
        self.settle_unconfirmed_send_under(attempt_id, worker_id, error, SettlementPremise::Live);
    }

    /// The SEND-DEADLINE leg's recording: the write runs in its own task and is NOT
    /// cancelled (a half-written frame desyncs the connection), so it may still land: the
    /// main cannot see whether the container will run, which is the ambiguous verdict,
    /// never PROVEN NOT PERFORMED. The stop is sent from a task of its own: on a connection
    /// that is not draining it queues behind the parked write.
    fn settle_unconfirmed_send_under(
        &self,
        attempt_id: Ulid,
        worker_id: &str,
        error: &KataError,
        premise: SettlementPremise<'_>,
    ) -> bool {
        let cause = format!(
            "the dispatch frame was not confirmed delivered to worker {worker_id}: {error}"
        );
        match self.settle_capsule_attempt(
            attempt_id,
            &cause,
            Some(worker_id),
            SettlementVerdict::ProvenAmbiguous,
            SettlementReport::Unreported,
            premise,
            SettledAs::FailedUnlessStopped,
        ) {
            Ok(Some(settled)) => {
                let dispatcher = self.clone();
                tokio::spawn(async move {
                    dispatcher
                        .stop_settled_capsule_attempt(attempt_id, &cause, &settled)
                        .await;
                });
                true
            }
            Ok(None) => false,
            Err(settle_error) => {
                warn!(%attempt_id, %settle_error, "settling an unconfirmed capsule send failed");
                false
            }
        }
    }

    /// FOLD a capsule attempt's START: the worker's capsule-arm start checkpoint moves a
    /// `dispatched` capsule attempt to `running` with `started_at_ms`, through its
    /// occurrence binding — the anchor [`Self::sweep_capsule_wall_time`] measures from.
    ///
    /// `Ok(false)` when the attempt is unknown, terminal, not a capsule attempt, or not
    /// `dispatched` (a duplicate checkpoint is a no-op).
    ///
    /// # Errors
    ///
    /// A capsule attempt with no occurrence binding, and the writer's own refusals.
    pub(crate) fn fold_capsule_start(
        &self,
        attempt_id: Ulid,
        started_at_ms: i64,
    ) -> KataResult<bool> {
        let face = self.execution_lifecycle();
        let Some(recovered) = face.db().recovered_attempt(attempt_id)? else {
            return Ok(false);
        };
        if recovered.is_terminal() || recovered.state.as_deref() != Some("dispatched") {
            return Ok(false);
        }
        match recovered.arm()? {
            AttemptArm::Capsule(_) => {}
            AttemptArm::Main(_) => return Ok(false),
        }
        face.db().record_main_side_transition(
            attempt_id,
            &MainSideTransition {
                started_at_ms: Some(started_at_ms),
                ..MainSideTransition::bare("running")
            },
        )?;
        Ok(true)
    }

    /// PROJECT one capsule-progress frame: the worker's `CapsuleProgress`
    /// arm names an ATTEMPT, which lives in the operational registry, not
    /// the ledger's `entries` — so this method resolves `execution_id` and
    /// `stage_id` off the attempt's own durable row and emits the shared
    /// [`kata_types::ledger::ProgressEvent`] the SSE/API surface already
    /// carries.
    ///
    /// Informational only: the frame persists nothing, mutates no authority,
    /// and an attempt no plane holds drops the frame with a `debug!`, the
    /// ordinary late-arrival treatment of a forgotten assignment. `dropped` rides through untouched
    /// — the count is the emitter's own bound accounting, published as it arrived.
    ///
    /// # Errors
    ///
    /// Only an unreadable attempt registry.
    pub(crate) fn broadcast_capsule_progress(
        &self,
        attempt_id: Ulid,
        byte_offset: u64,
        preview: String,
        dropped: u64,
    ) -> KataResult<()> {
        let face = self.execution_lifecycle();
        let Some(row) = face.db().attempt(attempt_id)? else {
            tracing::debug!(
                %attempt_id,
                byte_offset,
                "capsule progress for an unknown attempt dropped"
            );
            return Ok(());
        };
        self.ledger
            .emit_progress(kata_types::ledger::ProgressEvent {
                execution_id: row.execution_id,
                assignment_id: attempt_id,
                stage_name: row.stage_id.into(),
                byte_offset,
                preview,
                dropped,
                at_ms: kata_types::time::now_ms(),
            });
        Ok(())
    }

    /// Settle every live capsule attempt whose promised wall clock, plus
    /// [`CAPSULE_WALL_TIME_GRACE_MS`], elapsed since it STARTED (`started_at_ms`, folded
    /// from the worker's capsule-arm start checkpoint). An unstarted attempt is skipped.
    ///
    /// # Errors
    ///
    /// Only an unreadable attempt registry. A per-attempt failure is logged and the sweep
    /// continues, like every other deadline sweep.
    pub(crate) async fn sweep_capsule_wall_time(&self, now_ms: u64) -> KataResult<Vec<Ulid>> {
        let face = self.execution_lifecycle();
        let mut settled = Vec::new();
        for recovered in face.db().live_attempts()? {
            let attempt_id = recovered.row.attempt_id;
            let occurrence = match recovered.arm() {
                Ok(AttemptArm::Capsule(occurrence)) => occurrence,
                // BY NAME: a main-resolved attempt has no wall clock — nothing runs.
                Ok(AttemptArm::Main(_)) => continue,
                Err(error) => {
                    warn!(%attempt_id, %error, "capsule wall-time sweep: cannot classify the attempt");
                    continue;
                }
            };
            let Some(started_at) = recovered
                .row
                .started_at_ms
                .and_then(|at| u64::try_from(at).ok())
            else {
                continue;
            };
            let budgets = match face.db().promised_capsule_budgets(occurrence) {
                Ok(budgets) => budgets,
                Err(error) => {
                    warn!(%attempt_id, %error, "capsule wall-time sweep: cannot read the promised budget");
                    continue;
                }
            };
            let deadline = started_at
                .saturating_add(budgets.wall_time_ms)
                .saturating_add(CAPSULE_WALL_TIME_GRACE_MS);
            if now_ms <= deadline {
                continue;
            }
            let cause = format!(
                "capsule wall time elapsed: started at {started_at}, promised \
                 wall_time_ms {}, grace {CAPSULE_WALL_TIME_GRACE_MS} ms, now {now_ms}",
                budgets.wall_time_ms
            );
            match self
                .settle_lost_capsule_attempt(attempt_id, &cause, None)
                .await
            {
                Ok(true) => settled.push(attempt_id),
                Ok(false) => {}
                Err(error) => {
                    warn!(%attempt_id, %error, "capsule wall-time sweep: settlement failed");
                }
            }
        }
        if !settled.is_empty() {
            info!(
                count = settled.len(),
                "capsule wall-time sweep settled attempts"
            );
        }
        Ok(settled)
    }

    /// Settle every capsule attempt DELIVERED and never STARTED past the node's
    /// `assignment_start_deadline` plus [`CAPSULE_START_GRACE_MS`], measured from the
    /// later of its dispatch and its worker's last freed slot, on a worker that holds no
    /// started attempt — PROVEN AMBIGUOUS, with a fenced stop. The snapshot below only
    /// chooses candidates; each settlement re-reads the whole premise under the writer
    /// lock ([`Self::settle_overdue_capsule_attempt`]).
    ///
    /// # Why the main needs this leg when the worker applies the deadline
    ///
    /// The worker refuses an overdue frame when a slot frees, and reports it; this leg is
    /// for the report that never comes — a frame lost after the transport accepted it, a
    /// worker wedged before its start checkpoint. The grace lets the worker's own verdict
    /// land first. A worker holding a STARTED attempt is exempt: its queue delay is backpressure,
    /// and a wedged holder trips the wall-time leg, after which the queued attempt is no longer
    /// exempt. AMBIGUOUS rather than not performed: the worker is alive and may yet start the
    /// container. The fenced stop covers both cases: a worker still holding the frame QUEUED
    /// remembers the stop and refuses the launch (`kata_worker::worker_loop`'s `PendingStops`,
    /// bounded, capsule arm only), and one that has started it kills the container.
    ///
    /// # Errors
    ///
    /// Only an unreadable attempt registry; per-attempt failures are logged.
    pub(crate) async fn sweep_capsule_start_deadline(&self, now_ms: u64) -> KataResult<Vec<Ulid>> {
        let Some(deadline) = self.assignment_start_deadline else {
            return Ok(Vec::new());
        };
        let deadline_ms = u64::try_from(deadline.as_millis()).unwrap_or(u64::MAX);
        if deadline_ms == 0 {
            return Ok(Vec::new());
        }
        let face = self.execution_lifecycle();
        let live = face.db().live_attempts()?;
        let busy: std::collections::HashSet<&str> = live
            .iter()
            .filter(|recovered| recovered.row.started_at_ms.is_some())
            .filter_map(|recovered| recovered.row.worker_id.as_deref())
            .collect();
        let mut settled = Vec::new();
        for recovered in &live {
            let attempt_id = recovered.row.attempt_id;
            match recovered.arm() {
                Ok(AttemptArm::Capsule(_)) => {}
                // BY NAME: a main-resolved attempt is never delivered, so it has no start.
                Ok(AttemptArm::Main(_)) => continue,
                Err(error) => {
                    warn!(%attempt_id, %error, "capsule start-deadline sweep: cannot classify the attempt");
                    continue;
                }
            }
            if recovered.row.started_at_ms.is_some()
                || recovered.state.as_deref() != Some("dispatched")
            {
                continue;
            }
            let (Some(worker), Some(dispatched_at)) = (
                recovered.row.worker_id.as_deref(),
                recovered
                    .row
                    .dispatched_at_ms
                    .and_then(|at| u64::try_from(at).ok()),
            ) else {
                continue;
            };
            // A cheap PRE-FILTER over the snapshot; the premise itself — unstarted, an
            // idle worker, overdue from the later of the dispatch and the worker's last
            // freed slot — is re-read under the writer lock by the settlement, because
            // each settlement below awaits a network send and the snapshot goes stale.
            let window_ms = deadline_ms.saturating_add(CAPSULE_START_GRACE_MS);
            let elapsed = now_ms.saturating_sub(dispatched_at);
            if elapsed <= window_ms || busy.contains(worker) {
                continue;
            }
            let cause = format!(
                "capsule attempt did not start within assignment_start_deadline_ms={deadline_ms} \
                 (grace {CAPSULE_START_GRACE_MS} ms) of its dispatch or its worker's last freed \
                 slot, on worker {worker}"
            );
            let overdue = kata_core::operational::StartOverdue {
                worker,
                now_ms: i64::try_from(now_ms).unwrap_or(i64::MAX),
                window_ms: i64::try_from(window_ms).unwrap_or(i64::MAX),
            };
            match self
                .settle_overdue_capsule_attempt(attempt_id, &cause, overdue)
                .await
            {
                Ok(true) => settled.push(attempt_id),
                Ok(false) => {}
                Err(error) => {
                    warn!(%attempt_id, %error, "capsule start-deadline sweep: settlement failed");
                }
            }
        }
        if !settled.is_empty() {
            info!(
                count = settled.len(),
                "capsule start-deadline sweep settled attempts"
            );
        }
        Ok(settled)
    }
}

#[cfg(any(test, feature = "test-support"))]
impl Dispatcher {
    /// Test door for [`Self::settle_lost_capsule_attempt`], so the placement fence the
    /// death leg's victim scan normally hides can be driven directly.
    ///
    /// # Errors
    ///
    /// [`Self::settle_lost_capsule_attempt`]'s.
    #[doc(hidden)]
    pub async fn settle_lost_capsule_attempt_for_test(
        &self,
        attempt_id: Ulid,
        cause: &str,
        on_worker: Option<&str>,
    ) -> KataResult<bool> {
        self.settle_lost_capsule_attempt(attempt_id, cause, on_worker)
            .await
    }

    /// Test door for [`Self::settle_overdue_capsule_attempt`] — the start-deadline leg's
    /// settlement of ONE candidate, as the sweep calls it with a candidate its snapshot
    /// chose (which may be stale by then).
    ///
    /// # Errors
    ///
    /// [`Self::settle_overdue_capsule_attempt`]'s.
    #[doc(hidden)]
    pub async fn settle_overdue_capsule_attempt_for_test(
        &self,
        attempt_id: Ulid,
        worker: &str,
        now_ms: i64,
    ) -> KataResult<bool> {
        let deadline_ms = self.assignment_start_deadline.map_or(0, |deadline| {
            i64::try_from(deadline.as_millis()).unwrap_or(i64::MAX)
        });
        self.settle_overdue_capsule_attempt(
            attempt_id,
            "a stale start-deadline candidate (test door)",
            kata_core::operational::StartOverdue {
                worker,
                now_ms,
                window_ms: deadline_ms
                    .saturating_add(i64::try_from(CAPSULE_START_GRACE_MS).unwrap_or(i64::MAX)),
            },
        )
        .await
    }

    /// Test door: ONE whole deadline-sweep tick at a chosen instant — the production
    /// tick, so a cell covers the capsule leg's WIRING into it and not only the leg.
    #[doc(hidden)]
    pub async fn run_deadline_sweep_tick_for_test(&self, now_ms: u64) {
        self.run_deadline_sweep_tick(now_ms).await;
    }
}
/// READ the recorded `/work` delta artifact's bytes and decode them — the
/// scope judge's copy of the verified read adoption repeats: the artifact row
/// bounds the object and the CAS verifies the bytes at that address.
fn read_recorded_work_delta(
    db: &std::sync::Arc<kata_core::OperationalDb>,
    reference: &kata_types::execution_contract::ArtifactRef,
) -> KataResult<kata_types::tree_delta::TreeDelta> {
    // The delta's OWN artifact row is written by ADOPTION, which runs after
    // this read — so the judge reads the OBJECT the reference names
    // (content-verified, bound-checked), not the row. A forged reference
    // resolves to the wrong bytes or misses the store entirely, which is the
    // same refusal either way.
    let cas = db.output_cas().ok_or_else(|| {
        KataError::Storage(
            "a capsule's /work delta exists only where the node binds a content store".to_owned(),
        )
    })?;
    let bytes = cas.get_verified(
        &reference.object_id(),
        reference.size_bytes(),
        kata_types::tree_delta::TreeDelta::MAXIMUM_ENCODED_BYTES,
    )?;
    serde_json::from_slice(&bytes).map_err(|error| {
        KataError::Storage(format!(
            "the reported /work delta artifact {} does not decode: {error}",
            reference.id().0,
        ))
    })
}
