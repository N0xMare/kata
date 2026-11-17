//! The dispatcher's legs over PARKED MAIN-RESOLVED WAITS: the wake
//! of a due timer, the settlement of a wait its execution abandoned, and the cancel of an
//! execution's parked waits.
//!
//! # Who resolves a parked main wait, and on what premise
//!
//! A main wait is never dispatched, so no worker frame ever ends it. Exactly four
//! resolvers do, each re-reading its own premise under the writer lock (the answer inside
//! its own verb, the three dispatcher legs through `OperationalDb::resolve_main_attempt`),
//! which is what makes them mutually exclusive:
//!
//! | resolver | premise | resolution |
//! |---|---|---|
//! | `OperationalDb::resolve_input_wait` (an operator's answer, through the API) | `ParkedIn(awaiting_input)` | an input wait: `completed` with the answer |
//! | [`Dispatcher::sweep_due_waits`] (every deadline tick) | `DueWait { now_ms }` | a timer: `completed`, `{"deadline_ms": …}`; an input wait: `completed` with its request's `default_assumption` (`source: "timeout_default"`) |
//! | [`Dispatcher::cancel_parked_main_waits`] (an operator's execution cancel) | `ParkedIn(state)` | `cancelled` |
//! | [`Dispatcher::settle_abandoned_main_attempts`] (every deadline tick, and the restart leg) | `ParkedIn(state)` | `cancelled` |
//!
//! and the terminal publication itself cancels whatever is still parked, in its own
//! transaction (`OperationalDb::finish_terminalization`).
//!
//! `awaiting_child_completion` is none of theirs. An `Invoke`'s wait ends with its child's
//! terminal publication, with its parent's, or — for a parent that latched its outcome and
//! will not publish it with the wait parked (a main that died mid-closeout) — by
//! [`Dispatcher::settle_abandoned_invocations`]; the last two LATCH the child's cancel in
//! the same commit that ends the wait (`kata_core::operational`'s `child_invocation`).

use kata_core::operational::{
    AttemptLifecycle, MainResolution, MainResolvePremise, ParkedMainWait, ParkedMainWaitScope,
};
use kata_types::error::KataResult;
use tracing::{info, warn};
use ulid::Ulid;

use super::Dispatcher;

/// What one due wait's wake came to.
enum DueWake {
    /// The pass cannot name its resolution (an input wait whose default is not retained);
    /// left parked, and not counted against the pass.
    Unresolvable,
    /// Accepted by this pass.
    Accepted,
    /// Tried: lapsed under the writer lock, or failed and logged.
    NotAccepted,
}

/// How many due waits one sweep pass tries to resolve, and the page it reads them in. A
/// pass that fills it leaves the rest for the next tick, earliest deadline first, so a
/// burst of due timers cannot hold one tick (and the writer lock) for an unbounded run.
/// A wait the pass cannot resolve (an input wait whose default is not retained yet) does
/// not count against it: the pass pages past it, so no number of those can crowd a later
/// deadline out of every pass.
const DUE_WAITS_PER_PASS: usize = 256;

impl Dispatcher {
    /// WAKE every due wait: accept each main-resolved wait whose durable deadline is at or
    /// before `now_ms`, in a running execution, earliest first, at most
    /// [`DUE_WAITS_PER_PASS`] per pass — a TIMER with `{"deadline_ms": <its deadline>}`, an
    /// INPUT wait (a blocking human request whose `timeout_ms` elapsed unanswered) with its
    /// request's timeout resolution, the authored
    /// `default_assumption` (`InputWaitRecord::timeout_default`).
    ///
    /// Idempotent across back-to-back passes — the deadline tick BURSTS its missed
    /// ticks after a pause — because each resolution re-reads
    /// `DueWait { now_ms }` under the writer lock: the first pass accepts, every later one
    /// answers a lapse and writes nothing; an operator answer that committed first makes
    /// the timeout lapse the same way.
    ///
    /// An input wait's default is read off its execution's retained checked-program
    /// authority, which the execution's runner holds while it runs. A due input wait whose
    /// execution holds none (its runner not yet resumed) is left parked for a later pass,
    /// with a warning — never resolved with an answer this pass cannot name — and the pass
    /// reads on past it (`OperationalDb::due_main_waits` pages by `(deadline, attempt)`), so
    /// the left-parked waits never use up the pass's [`DUE_WAITS_PER_PASS`].
    ///
    /// Answers the attempts THIS pass accepted.
    ///
    /// # Errors
    ///
    /// Only an unreadable due set; a per-wait failure is logged and the pass continues.
    pub fn sweep_due_waits(&self, now_ms: i64) -> KataResult<Vec<Ulid>> {
        let lifecycle = self.execution_lifecycle();
        let db = lifecycle.db();
        let mut woken = Vec::new();
        let mut tried = 0_usize;
        let mut after = None;
        loop {
            let page = db.due_main_waits(now_ms, after, DUE_WAITS_PER_PASS)?;
            let last_page = page.len() < DUE_WAITS_PER_PASS;
            for wait in page {
                let Some(deadline_ms) = wait.wait_deadline_ms else {
                    continue;
                };
                after = Some((deadline_ms, wait.attempt_id));
                match self.wake_due_wait(&wait, deadline_ms, now_ms) {
                    DueWake::Unresolvable => continue,
                    DueWake::Accepted => woken.push(wait.attempt_id),
                    DueWake::NotAccepted => {}
                }
                tried += 1;
                if tried == DUE_WAITS_PER_PASS {
                    return Ok(woken);
                }
            }
            if last_page {
                return Ok(woken);
            }
        }
    }

    /// Resolve one due wait on its `DueWait` premise, logging a failure.
    fn wake_due_wait(&self, wait: &ParkedMainWait, deadline_ms: i64, now_ms: i64) -> DueWake {
        let output = match wait.state {
            AttemptLifecycle::AwaitingTimer => serde_json::json!({ "deadline_ms": deadline_ms }),
            AttemptLifecycle::AwaitingInput => {
                let default = self
                    .checked_program_authority
                    .get(&wait.execution_id)
                    .and_then(|authority| authority.input_timeouts.get(&wait.stage_id).cloned());
                let Some(default) = default else {
                    warn!(
                        attempt_id = %wait.attempt_id,
                        execution_id = %wait.execution_id,
                        stage = %wait.stage_id,
                        "due-wait sweep: an input wait is due and its execution retains no \
                         checked program naming its default; left parked for a later pass"
                    );
                    return DueWake::Unresolvable;
                };
                default
            }
            _ => return DueWake::Unresolvable,
        };
        match self.execution_lifecycle().db().resolve_main_attempt(
            wait.attempt_id,
            MainResolvePremise::DueWait { now_ms },
            &MainResolution::Complete { output: &output },
        ) {
            Ok(Some(seq)) => {
                info!(
                    attempt_id = %wait.attempt_id,
                    execution_id = %wait.execution_id,
                    stage = %wait.stage_id,
                    deadline_ms,
                    now_ms,
                    seq,
                    wait = wait.state.as_str(),
                    "dispatcher: a main-resolved wait reached its deadline and was accepted"
                );
                DueWake::Accepted
            }
            Ok(None) => DueWake::NotAccepted,
            Err(error) => {
                warn!(
                    attempt_id = %wait.attempt_id,
                    %error,
                    "due-wait sweep: the wait could not be resolved"
                );
                DueWake::NotAccepted
            }
        }
    }

    /// CANCEL every parked timer and input wait of `execution_id` — an operator's execution
    /// cancel reaching work no worker holds. Each is resolved `cancelled` on its own premise
    /// (`ParkedIn(state)`), so a wait the due sweep accepted first is left accepted and not
    /// counted. Answers how many THIS call cancelled.
    ///
    /// # Errors
    ///
    /// An unreadable wait set, and the first resolution that fails; waits cancelled before
    /// it stay cancelled.
    pub fn cancel_parked_main_waits(&self, execution_id: Ulid, reason: &str) -> KataResult<usize> {
        let waits = self
            .execution_lifecycle()
            .db()
            .parked_main_waits(ParkedMainWaitScope::Execution(execution_id))?;
        let mut cancelled = 0;
        for wait in waits {
            if self.cancel_parked_main_wait(&wait, reason)? {
                cancelled += 1;
            }
        }
        Ok(cancelled)
    }

    /// SETTLE every ABANDONED main wait — a timer or input wait parked in an execution that
    /// is `terminalizing` — `cancelled`. Run by every deadline tick and by the restart leg,
    /// before any runner resumes.
    ///
    /// # Why an abandoned wait needs a leg
    ///
    /// A `terminalizing` execution's runner has returned, so nothing will ever wake its
    /// wait, and the closeout witness refuses to finish an execution while one of its
    /// attempts is non-terminal — on every boot. The terminal publication cancels a parked
    /// wait itself, but a closeout that has not reached the publication (a deferred
    /// cleanup; a restart's repair, which reads the witness FIRST) needs this leg.
    ///
    /// # Errors
    ///
    /// Only an unreadable wait set; a per-wait failure is logged and the pass continues.
    pub fn settle_abandoned_main_attempts(&self) -> KataResult<Vec<Ulid>> {
        let waits = self
            .execution_lifecycle()
            .db()
            .parked_main_waits(ParkedMainWaitScope::TerminalizingExecutions)?;
        let mut settled = Vec::new();
        for wait in waits {
            let reason = format!(
                "execution {} latched its outcome while this wait was parked, so no runner will \
                 wake it",
                wait.execution_id
            );
            match self.cancel_parked_main_wait(&wait, &reason) {
                Ok(true) => settled.push(wait.attempt_id),
                Ok(false) => {}
                Err(error) => warn!(
                    attempt_id = %wait.attempt_id,
                    %error,
                    "abandoned main-wait sweep: the wait could not be settled"
                ),
            }
        }
        if !settled.is_empty() {
            info!(
                count = settled.len(),
                "settled main waits their executions abandoned"
            );
        }
        Ok(settled)
    }

    /// SETTLE every `Invoke` a `terminalizing` execution still has parked on a child —
    /// `cancelled`, with the child's cancel LATCHED in the same commit, down the whole
    /// tree (`OperationalDb::settle_abandoned_child_waits`). Run by every deadline tick and
    /// by the restart leg, before the other settlement legs, so a child it latches has its
    /// own waits and claims settled by them in the same pass.
    ///
    /// # Why an abandoned `Invoke` needs a leg
    ///
    /// A main that died after latching a parent's outcome and before publishing it left
    /// the parent's `Invoke` parked: the closeout witness then refused the parent on every
    /// boot, which aborted the whole recovery batch, so the child was never resumed either
    /// and nothing ever ended the wait.
    ///
    /// # Errors
    ///
    /// The plane's read of the abandoned parents. A parent whose own settlement fails is
    /// logged and skipped by the plane, and the others are settled
    /// (`OperationalDb::settle_abandoned_child_waits`).
    pub fn settle_abandoned_invocations(&self) -> KataResult<Vec<Ulid>> {
        let settled = self
            .execution_lifecycle()
            .db()
            .settle_abandoned_child_waits()?;
        if !settled.is_empty() {
            info!(
                count = settled.len(),
                "settled subworkflow invocations their executions abandoned, and latched each \
                 child's cancel"
            );
        }
        Ok(settled)
    }

    fn cancel_parked_main_wait(&self, wait: &ParkedMainWait, reason: &str) -> KataResult<bool> {
        Ok(self
            .execution_lifecycle()
            .db()
            .resolve_main_attempt(
                wait.attempt_id,
                MainResolvePremise::ParkedIn(wait.state),
                &MainResolution::Cancel {
                    reason,
                    terminal_charge: None,
                },
            )?
            .is_some())
    }
}
