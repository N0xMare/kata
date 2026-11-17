//! Recovery for [`Dispatcher`]: worker-death settlement, and the dispatch of a claim
//! the previous main never dispatched.
//!
//! A capsule attempt is never re-delivered: the send funnel is
//! [`Dispatcher::deliver_capsule_frame`](super::Dispatcher::deliver_capsule_frame),
//! which runs once per attempt — at its authorization, at its approval, or, for a
//! claim whose main died before dispatching it, at its runner's boot (below) — and a
//! worker that dies holding `dispatched`/`running` attempts leaves outcomes no re-send
//! can recover. Every victim is settled PROVEN NOT PERFORMED or NOT PROVEN through
//! [`Dispatcher::settle_lost_capsule_attempt`](super::Dispatcher::settle_lost_capsule_attempt),
//! which is where the ambiguity policy lives.
//!
//! # A claim the previous main never dispatched
//!
//! `authorize_attempt` claims an attempt in one transaction and dispatches it in the
//! next. A main that dies between the two — the window `operational.after_claim_commit`
//! and `operational.after_occurrence_authorized_before_dispatch` both name — leaves a
//! capsule attempt `pending` with no dispatch instant and no command, and the resumed
//! run never presents its occurrence again: the runner's boot marks a stage with a live
//! attempt in flight, an expansion's derive waits on a live member, and a retry seat
//! that minted its occurrence is not queued a second time. So the execution's runner,
//! at boot, dispatches that attempt itself, off its durable row —
//! [`Dispatcher::dispatch_claims_left_undispatched`]. A claim of an execution that
//! does not resume is the abandoned-claim legs'
//! ([`Dispatcher::settle_abandoned_capsule_claims`](super::Dispatcher::settle_abandoned_capsule_claims)).
//!
//! # A node its heartbeat judged dead is killed before anything settles
//!
//! A worker that stops heartbeating while its connection stays open may still be
//! running, stopped, or hung: a settlement taken on its silence alone would leave
//! its containers running beside whatever the main does next, and its next
//! heartbeat would make it live again on the same connection. When the main
//! supervises its node, the heartbeat leg therefore kills that node first, through
//! the [`NodeFence`] the supervision installed: the node is gone before an attempt
//! it held is settled, with every process it started, its containers included,
//! when the main's cgroup is delegated (otherwise the node's own process alone),
//! and the supervision starts a new node, which enrolls like any other. A worker
//! the main does not supervise (an operator's `kata-worker` daemon) is settled on
//! its silence as before.

use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use kata_core::operational::RecoveredAttempt;

use super::{DispatchFrame, Dispatcher, KataError, KataResult, Ulid, info, warn};

/// How long the heartbeat leg waits for a [`NodeFence`]'s answer. It waits holding
/// `worker_deaths`, so every other worker's death waits too; an answer that has
/// not arrived by then counts as a failed kill.
const FENCE_BUDGET: Duration = Duration::from_secs(30);

/// How the main kills the node it supervises: the supervision of `kata serve`'s
/// node, which alone holds that node's process and its cgroup subtree.
pub trait NodeFence: Send + Sync {
    /// Kill the node whose process is `pid`, with every process it started when
    /// the fence holds its cgroup subtree, and resolve once the node is reaped and
    /// that subtree is empty. `Ok(Some(what))` names what was killed, for the
    /// settlement's record; `Ok(None)` when `pid` is no node this fence
    /// supervises, which kills nothing; `Err` when the kill could not be
    /// completed, which leaves the attempts unsettled for the next sweep, as does
    /// an answer that has not arrived within [`FENCE_BUDGET`].
    fn fence(
        &self,
        pid: u32,
    ) -> Pin<Box<dyn Future<Output = Result<Option<String>, String>> + Send + '_>>;
}

/// Why the main declared a worker dead. Every attempt the death settles records
/// it, beside what `/proc` said of the worker's process at that moment, so a
/// settlement names its leg and the evidence it was taken on.
#[derive(Clone, Debug)]
pub enum WorkerLoss {
    /// The worker's connection closed: its transport's own reason.
    ConnectionClosed(String),
    /// The worker passed the heartbeat deadline of observed silence.
    HeartbeatSilence(kata_transport::heartbeat::SilentWorker),
}

impl std::fmt::Display for WorkerLoss {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ConnectionClosed(reason) => write!(f, "its connection closed ({reason})"),
            Self::HeartbeatSilence(silent) => write!(
                f,
                "no heartbeat for {:.1} s of observed silence, past its {:.1} s deadline (the \
                 last one {:.1} s ago)",
                silent.observed_silence.as_secs_f64(),
                silent.deadline.as_secs_f64(),
                silent.last_heartbeat_age.as_secs_f64(),
            ),
        }
    }
}

/// What `/proc` says of the process `pid` names, read at settlement. A pid the
/// kernel has reused for another process would read as that process.
fn process_state(pid: Option<u32>) -> String {
    let Some(pid) = pid else {
        return "its process id is unknown".to_owned();
    };
    match std::fs::read_to_string(format!("/proc/{pid}/stat")) {
        Ok(stat) => match stat
            .rsplit_once(") ")
            .and_then(|(_, rest)| rest.chars().next())
        {
            Some(state) => format!("its process {pid} exists in state {state}"),
            None => format!("its process {pid} exists"),
        },
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            format!("its process {pid} is gone")
        }
        Err(error) => format!("its process {pid} could not be read ({error})"),
    }
}

impl Dispatcher {
    /// Install the supervised node's fence. One main supervises at most one node,
    /// so a second fence is refused.
    pub fn install_node_fence(&self, fence: Arc<dyn NodeFence>) -> KataResult<()> {
        self.node_fence.set(fence).map_err(|_| {
            KataError::Internal("the dispatcher already holds a node fence".to_owned())
        })
    }

    /// React to a worker-level failure (transport closed, heartbeat
    /// expired): settle every non-terminal capsule attempt attributed to
    /// `worker_id`, each recording `loss` and the state of the worker's process.
    ///
    /// Under [`WorkerLoss::HeartbeatSilence`] a worker that is the main's
    /// supervised node is killed first, through the installed [`NodeFence`],
    /// whether or not it holds an attempt (see the module docs); the settlement
    /// records what was killed. A fence that fails leaves every attempt unsettled
    /// and returns the error: the next sweep reports the worker again.
    ///
    /// Returns the attempts the settlement committed. Capsule work is never
    /// redispatched — there is no second delivery of an attempt the chain
    /// already placed — so a dead worker's outcome is decided, not retried.
    ///
    /// # ONE DEATH AT A TIME
    ///
    /// The whole call holds `worker_deaths`. A fence's kill closes the node's
    /// connection, and its result reactor then reports the same death as a closed
    /// connection; holding the lock across the kill and the settlement makes that
    /// report find the attempts already settled under the heartbeat leg's reason,
    /// which names the silence, the stopped process and the kill. A fence holds
    /// the lock [`FENCE_BUDGET`] at most, so one that never answers delays the
    /// deaths queued behind it by that long at most, and blocks none.
    ///
    /// # BOTH ENDS OF THIS LEG COME FROM THE DECIDING PLANE
    ///
    /// Discovery is
    /// [`Dispatcher::non_terminal_assignments_on_worker`](super::Dispatcher::non_terminal_assignments_on_worker),
    /// which reads the authority chain's fold rather than the ledger mirror, so
    /// the leg cannot go dark when the mirror is empty; settlement is the
    /// operational chain's own adjudication in `capsule_settlement`.
    pub async fn handle_worker_death(
        &self,
        worker_id: &str,
        loss: &WorkerLoss,
    ) -> KataResult<Vec<Ulid>> {
        if !self.startup_recovery_dispatch_is_open() {
            return Ok(Vec::new());
        }
        let _one_death_at_a_time = self.worker_deaths.lock().await;
        let pid = self
            .supervisor
            .get_worker(worker_id)
            .and_then(|worker| worker.peer_pid());
        // Read before any kill: the state the verdict was taken on.
        let process = process_state(pid);
        let killed = match loss {
            WorkerLoss::HeartbeatSilence(_) => self.fence_node(worker_id, pid).await?,
            WorkerLoss::ConnectionClosed(_) => None,
        };
        let victims = self.non_terminal_assignments_on_worker(worker_id)?;
        if victims.is_empty() {
            return Ok(Vec::new());
        }
        let reason = match killed {
            Some(killed) => format!("worker {worker_id} died: {loss}; {process}; {killed}"),
            None => format!("worker {worker_id} died: {loss}; {process}"),
        };
        info!(
            %worker_id,
            affected = victims.len(),
            %reason,
            "dispatcher: handling worker death"
        );
        let mut settled = Vec::new();
        for id in victims {
            match self
                .settle_lost_capsule_attempt(id, &reason, Some(worker_id))
                .await
            {
                Ok(true) => settled.push(id),
                Ok(false) => {}
                Err(error) => {
                    warn!(assignment_id = %id, %worker_id, %error, "dispatcher: could not settle a capsule attempt on a dead worker");
                }
            }
        }
        Ok(settled)
    }

    /// DISPATCH every capsule claim of `execution_id` that was committed and never
    /// dispatched, and deliver each frame: the second half of an authorization whose
    /// main died between its claim and its dispatch (the module docs name the window).
    /// Returns the attempts dispatched.
    ///
    /// Called once per execution, by its runner's boot (`WorkflowRunner::run`), before
    /// the drive loop submits anything. Mid-run the same rows are a submission between
    /// its own two transactions, which this door must not finish for it.
    ///
    /// # Which attempts
    ///
    /// Exactly those `OperationalDb::undispatched_attempt_at_occurrence` names for their
    /// own occurrence: worker-executed, not terminal, not parked awaiting approval (a
    /// parked gate is dispatched by its approval and by nothing else), with no dispatch
    /// instant and no command.
    ///
    /// # What is dispatched
    ///
    /// The frame the claim stored, on a worker chosen now — the approval door's shape
    /// ([`Dispatcher::approve_capsule_gate`]). The capsule's bytes, its declaration and
    /// its occurrence were durable before the claim committed, so nothing is assembled
    /// again and none of `authorize_attempt`'s refusals is evaluated a second time. The
    /// dispatch writer still refuses, under the writer lock, a terminal attempt and an
    /// execution that latched a terminal outcome.
    ///
    /// # One dispatch, and what holds it
    ///
    /// The attempt dispatched is the one the crash left: this door claims none. That no
    /// other writer dispatches it between this door's read and its write is the caller's
    /// position, not a premise re-read under the writer lock: the execution's one
    /// runner is at boot, and the only other dispatcher of an undispatched claim is that
    /// runner's own later submission. A walk-away the chain recorded after the claim
    /// does not stop the dispatch, as it would not have stopped the one the crash
    /// interrupted.
    ///
    /// # Errors
    ///
    /// A claim that cannot be dispatched — no eligible worker
    /// (`no_oci_worker_available`), a stored frame that does not decode, the dispatch
    /// writer's refusals — is settled PROVEN NOT PERFORMED
    /// ([`Dispatcher::settle_unsent_capsule_claim`]) and its error returned, which
    /// fails the run: the submit path's rule for the claim a failed authorization
    /// left. The delivery door's errors are returned after that door settled the
    /// attempt. A claim behind the failing one is left to the abandoned-claim sweep,
    /// which reaches it once the run latches its outcome.
    pub(crate) async fn dispatch_claims_left_undispatched(
        &self,
        execution_id: Ulid,
    ) -> KataResult<Vec<Ulid>> {
        let db = Arc::clone(self.execution_lifecycle().db());
        let mut dispatched = Vec::new();
        for claim in db.attempts_for_execution(execution_id)? {
            let attempt_id = claim.row.attempt_id;
            // The adoption reader decides; a recorded dispatch instant only spares it
            // the read.
            if claim.row.dispatched_at_ms.is_some()
                || db.undispatched_attempt_at_occurrence(claim.occurrence_id.0.0)?
                    != Some(attempt_id)
            {
                continue;
            }
            if let Err(error) = self.dispatch_stored_claim(&claim) {
                if let Err(settle_error) = self.settle_unsent_capsule_claim(
                    attempt_id,
                    &format!(
                        "the main restarted with this capsule attempt claimed and never \
                         dispatched, and its dispatch failed: {error}"
                    ),
                ) {
                    warn!(%attempt_id, %settle_error, "dispatcher: settling a claim the restart could not dispatch failed");
                }
                return Err(error);
            }
            info!(
                %execution_id,
                %attempt_id,
                "dispatcher: dispatched a capsule claim the previous main committed and never \
                 dispatched; delivering its frame"
            );
            self.deliver_capsule_frame(attempt_id).await?;
            dispatched.push(attempt_id);
        }
        Ok(dispatched)
    }

    /// The dispatch transaction of [`Self::dispatch_claims_left_undispatched`] for one
    /// claim: its stored frame, on a worker chosen now.
    fn dispatch_stored_claim(&self, claim: &RecoveredAttempt) -> KataResult<()> {
        let attempt_id = claim.row.attempt_id;
        let DispatchFrame::Capsule(frame) = serde_json::from_slice(&claim.assignment_json)
            .map_err(|error| {
                KataError::Storage(format!(
                    "capsule attempt {attempt_id}'s stored frame does not decode: {error}"
                ))
            })?;
        let worker = self.select_capsule_worker()?;
        self.execution_lifecycle().db().dispatch_claimed_attempt(
            attempt_id,
            worker.as_str(),
            Ulid::new(),
            &crate::authorization::capsule_dispatch_command(&frame, worker.as_str())?,
        )?;
        Ok(())
    }

    /// Kill `worker_id` through the node fence when its connection's process,
    /// `pid`, is the supervised node; `None` when no fence is installed, the pid is
    /// unknown, or the fence supervises no such process.
    async fn fence_node(&self, worker_id: &str, pid: Option<u32>) -> KataResult<Option<String>> {
        let (Some(fence), Some(pid)) = (self.node_fence.get(), pid) else {
            return Ok(None);
        };
        let error = match tokio::time::timeout(FENCE_BUDGET, fence.fence(pid)).await {
            Ok(Ok(killed)) => {
                if let Some(killed) = &killed {
                    warn!(%worker_id, pid, %killed, "dispatcher: killed a node its heartbeat judged dead");
                }
                return Ok(killed);
            }
            Ok(Err(error)) => error,
            Err(_) => format!("no answer within {} s", FENCE_BUDGET.as_secs()),
        };
        Err(KataError::Internal(format!(
            "worker {worker_id}'s node (process {pid}) could not be killed before its attempts \
             settle: {error}"
        )))
    }

    /// Test fixtures may present a failure using the retained current placement.
    /// Production ingress supplies the authenticated envelope directly.
    #[cfg(any(test, feature = "test-support"))]
    pub fn handle_stage_failure(
        &self,
        assignment_id: Ulid,
        reason: impl Into<String>,
        verdict: kata_types::effect::DeliveryFailureProvenance,
    ) -> KataResult<()> {
        let recovered = self
            .execution_lifecycle()
            .db()
            .recovered_attempt(assignment_id)?
            .ok_or_else(|| {
                super::KataError::Validation(format!(
                    "failure fixture has no authoritative attempt {assignment_id}"
                ))
            })?;
        let worker_id = recovered.row.worker_id.clone().ok_or_else(|| {
            super::KataError::Validation(format!(
                "failure fixture has no retained worker placement {assignment_id}"
            ))
        })?;
        self.adjudicate_worker_failure_input(&kata_core::operational::WorkerFailureInput {
            execution_id: recovered.row.execution_id,
            attempt_id: assignment_id,
            attempt_ordinal: recovered.row.attempt_ordinal,
            lease_epoch: recovered.row.lease_epoch,
            worker_id,
            reason: reason.into(),
            verdict,
            // A recovery-fixture failure is a synthetic fault, not a provider
            // call — no usage exists to carry.
            usage: None,
            provider_failure: None,
        })
    }
}
