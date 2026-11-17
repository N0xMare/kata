//! Engine-level durable schedules: a DURABLE deadline that survives an engine
//! restart and fires from a sweep, never a process-local timer. (The other
//! primitive of that shape, the durable sleep a `sleep(..)` stage lowers to, is
//! [`DurableSleep`](kata_types::wait::DurableSleep), parked by the runner and
//! completed by [`crate::dispatcher::Dispatcher::sweep_due_waits`].)
//!
//! * **Engine schedule / cron** — [`ScheduleSpec`](kata_program::schedule::ScheduleSpec) is what a
//!   `schedule(id=..,submit=..,every_ms=..|cron=..)` DSL builtin lowers to
//!   (`kata_program::schedule`, validated at authoring time).
//!   [`ScheduleFace`] is its durable authority over `operational.db`'s schedule tables,
//!   and [`ScheduleEngine::sweep_due`] fires a schedule when its durable cursor
//!   comes due. This makes "nightly, bump deps and open a candidate" expressible:
//!   `schedule(id="deps", submit="deps-bump", cron="0 2 * * *")`.
//!
//! ## Where a schedule LIVES
//!
//! `operational.db` is the schedule authority. Two properties follow from that and
//! neither is incidental:
//!
//! * **A fire is ONE transaction.** The due claim, the cursor advance, and the
//!   submitted execution commit together or not at all; a cursor kept anywhere
//!   outside that transaction could not be made exactly-once.
//! * **A schedule binds an IMMUTABLE program.** The `submit=` target is resolved,
//!   compiled, and pinned at install; the fire submits those pinned bytes and never
//!   consults the pack name again. The pin binds its own BODY: the admission
//!   chokepoint re-derives the whole-program hash from the decoded program and refuses
//!   a body that does not produce the hash it carries, and [`ScheduleFace::fire`]
//!   applies that guard before the substrate commits anything.
//!
//! ## NAMED HAZARD — the exactly-once claim's lifetime is the execution's retention
//!
//! `schedule_firings.execution_id` is an FK to `programs` `ON DELETE CASCADE`, and the
//! firing row is the ONLY durable statement that an occurrence was claimed. Deleting
//! the execution therefore silently deletes the idempotency proof, and the occurrence
//! becomes claimable again.
//!
//! Latent today — no production path deletes a `programs` row; boot WARNs that
//! retention is unavailable when `ledger_ttl_secs > 0`. And the CASCADE is also what
//! BOUNDS growth, so removing it is not the fix. The precondition retention must
//! satisfy is therefore: **any path that can place the cursor at or below a pruned
//! instant is a duplicate-fire path.** The self-healing cursor advance is the only
//! thing between the two today, and it is not a durable claim.
//! `pruning_an_execution_deletes_the_only_proof_its_occurrence_was_claimed`
//! (`crates/workflow/tests/schedule_engine_tests.rs`) pins the hazard so retention
//! cannot land without confronting it.
//!
//! ## Missed-while-down policy
//!
//! A schedule that comes due while the engine is DOWN is handled per its
//! [`MissedPolicy`], chosen at authoring time:
//!
//! * [`MissedPolicy::FireOnceOnBoot`] (the default) — on the first sweep after
//!   boot, a record whose `next_fire_ms` already elapsed fires EXACTLY ONCE
//!   (missed occurrences are coalesced into a single catch-up run) and then
//!   re-anchors from the current instant. This is the "don't silently skip the
//!   nightly job because the box was rebooting at 02:00" posture.
//! * [`MissedPolicy::Skip`] — a missed occurrence is dropped; the record
//!   re-anchors to the next future occurrence without firing. The posture for
//!   jobs where a stale run is worse than a skipped one.

use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use kata_program::schedule::MissedPolicy;
use kata_types::error::{KataError, KataResult};
use tracing::{info, warn};

mod face;
pub use face::{
    DurableSchedule, IncompatiblePinnedProgram, ScheduleFace,
    inspect_incompatible_pinned_programs_immutable, inspect_schedule_targets_immutable,
};

/// Wall-clock now in Unix milliseconds (UTC). Schedules and sleeps evaluate in
/// UTC so a `cron` expression fires at the same instant regardless of the host
/// timezone.
pub fn schedule_now_ms() -> u64 {
    u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_millis()),
    )
    .unwrap_or(u64::MAX)
}

/// One due occurrence, handed to the [`SubmitFn`] as a complete firing intent.
///
/// The submit callback does NOT compute any of this. `fire_instant` is the DURABLE
/// CURSOR as the sweep read it — never `now` — because it is the firing claim's
/// identity, and a wall-clock claim key changes on every retry and makes the firing
/// primary key non-idempotent. `next_cursor_ms` is strictly greater than
/// `fire_instant` by arithmetic: the record is only due when `cursor <= now`, and
/// `next_after(now)` is strictly after `now`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScheduleFire {
    /// The due schedule, as the durable table reports it.
    pub record: DurableSchedule,
    /// The DUE instant being claimed (the durable cursor).
    pub fire_instant: u64,
    /// The cursor the firing transaction advances to.
    pub next_cursor_ms: u64,
}

/// What ONE submit attempt actually did, as distinct from whether it errored.
///
/// # Failure mode
///
/// The two Ok cases must not collapse into `Ok(())`. An already-fired claim becomes a
/// spent-claim acceptance, which returns `Ok(None)` from the executor; collapsed, it
/// would make [`ScheduleEngine::sweep_due`] log "schedule fired: submitted the pinned
/// workflow" at INFO and push the id into the list documented as "the ids that
/// actually submitted this pass". On the REDELIVERY path (the one the in-transaction
/// cursor advance makes exactly-once) both the log and the API would assert a fire
/// that did not happen.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FireReport {
    /// The pinned workflow was submitted: a NEW execution is durable.
    Submitted,
    /// The claim for this occurrence was already spent — a redelivery. The cursor is
    /// still advanced (the idempotent path is self-healing), but nothing was
    /// submitted and this is NOT a fire.
    AlreadyClaimed,
    /// The fire was REFUSED before any execution existed — its execution target
    /// did not resolve, or did not pass the structural target check — and the
    /// refusal is recorded durably as the occurrence's firing
    /// ([`ScheduleFace::refuse_fire`]); the cursor advanced past it. Not a fire,
    /// and never a silent retry.
    Refused,
}

/// The callback the [`ScheduleEngine`] invokes to submit a due schedule's
/// workflow. Injected so the engine stays decoupled from the concrete submit
/// path (the executor's pinned-schedule acceptance seam in production; a recording
/// sink in tests).
///
/// # Invariant
///
/// The callback owns the FIRING TRANSACTION: claim + cursor + execution commit
/// together (through [`ScheduleFace::fire`], which the executor's acceptance closure
/// calls), or none of them do. That is why the engine advances no cursor itself: a
/// submit and a cursor kept in two places can half-commit.
///
/// It returns a [`FireReport`] rather than `()` because "committed without error" and
/// "submitted an execution" are different facts, and only the caller inside the
/// transaction can tell them apart.
pub type SubmitFn = Arc<dyn Fn(&ScheduleFire) -> KataResult<FireReport> + Send + Sync>;

/// The durable schedule engine: a [`ScheduleFace`] over `operational.db`
/// plus a submit callback, driven by [`Self::sweep_due`] (or the background
/// [`Self::run_schedule_sweep`] loop).
pub struct ScheduleEngine {
    face: ScheduleFace,
    submit: SubmitFn,
}

impl ScheduleEngine {
    /// Build an engine over `face`, submitting due workflows through `submit`.
    #[must_use]
    pub fn new(face: ScheduleFace, submit: SubmitFn) -> Self {
        Self { face, submit }
    }

    /// The durable schedule authority this engine drives.
    #[must_use]
    pub fn face(&self) -> &ScheduleFace {
        &self.face
    }

    /// Fire every schedule whose durable cursor is `<= now_ms`, per its
    /// [`MissedPolicy`].
    ///
    /// * A record due at-or-before `now_ms` submits its workflow (once — missed
    ///   occurrences coalesce) under [`MissedPolicy::FireOnceOnBoot`], and the
    ///   firing transaction re-anchors its cursor to the next occurrence STRICTLY
    ///   after `now_ms`.
    /// * Under [`MissedPolicy::Skip`] a past-due BACKLOG re-anchors WITHOUT
    ///   submitting.
    ///
    /// Returns the ids that actually SUBMITTED an execution this pass — never an id
    /// whose claim was already spent, which commits without submitting anything.
    ///
    /// # Failure mode
    ///
    /// A FAILED submit does not consume the occurrence. The cursor lives inside
    /// the firing transaction, so a submit that did not commit leaves the cursor
    /// exactly where it was and the next sweep retries the same instant. Advancing
    /// the cursor on a generic error would silently drop one occurrence per sweep,
    /// forever, whenever the target pack was renamed or transiently broken. A
    /// tight retry loop is prevented by the 30s sweep interval plus the idempotent claim: a
    /// persistently failing schedule retries at most twice a minute, and each retry
    /// is a no-op after the first successful claim.
    pub fn sweep_due(&self, now_ms: u64) -> Vec<String> {
        let mut fired = Vec::new();
        let records = match self.face.all() {
            Ok(records) => records,
            Err(e) => {
                // Fail closed: an unreadable schedule table disables firing for this
                // tick rather than guessing that nothing is due.
                warn!(error = %e, "schedule sweep: cannot read durable schedules; firing nothing this tick");
                return fired;
            }
        };
        for record in records {
            if record.next_fire_ms > now_ms {
                continue;
            }
            // Advance to the first occurrence strictly after `now_ms` so a
            // whole backlog of missed slots collapses to a single catch-up.
            let next = match record.trigger.next_after(now_ms) {
                Ok(next) => next,
                Err(e) => {
                    warn!(
                        schedule = %record.id,
                        error = %e,
                        "schedule sweep: cannot compute next fire; leaving record parked"
                    );
                    continue;
                }
            };
            // Is this a genuine backlog (≥2 occurrences already in the past —
            // i.e. at least one WHOLE occurrence elapsed unfired while the
            // engine was down), or just the single slot that arrived since the
            // last sweep (normal operation)? The occurrence strictly after the
            // recorded cursor is a second missed slot iff it, too, is already
            // past. This is the "missed WHILE DOWN" signal the MissedPolicy
            // governs. A last-fired instant is not: it would never fire a
            // never-fired Skip schedule's first due slot, and would let an
            // already-fired one catch-up-fire a backlog (both Skip-contract
            // violations; see the regression tests).
            let missed_backlog = record
                .trigger
                .next_after(record.next_fire_ms)
                .is_ok_and(|second| second <= now_ms);
            match record.on_missed {
                // Skip: a MISSED-while-down backlog is dropped and the cursor
                // re-anchors to the next future occurrence WITHOUT firing (the
                // documented contract). A single just-due slot still fires.
                MissedPolicy::Skip if missed_backlog => {
                    if let Err(e) = self.face.skip_to(&record.id, next) {
                        warn!(schedule = %record.id, error = %e, "schedule sweep: skip failed");
                    }
                }
                _ => {
                    let fire = ScheduleFire {
                        fire_instant: record.next_fire_ms,
                        next_cursor_ms: next,
                        record,
                    };
                    match (self.submit)(&fire) {
                        Ok(FireReport::Submitted) => {
                            info!(
                                schedule = %fire.record.id,
                                submit = %fire.record.submit_pack,
                                fire_instant = fire.fire_instant,
                                "schedule fired: submitted the pinned workflow"
                            );
                            fired.push(fire.record.id.clone());
                        }
                        // NOT a fire, and deliberately not counted as one: the claim
                        // for this occurrence was already spent, so no execution was
                        // submitted. The cursor still advanced inside the acceptance
                        // commit, which is what makes the redelivery path self-healing.
                        Ok(FireReport::AlreadyClaimed) => {
                            info!(
                                schedule = %fire.record.id,
                                submit = %fire.record.submit_pack,
                                fire_instant = fire.fire_instant,
                                "schedule sweep: the occurrence was already claimed; nothing was \
                                 submitted (idempotent redelivery)"
                            );
                        }
                        Ok(FireReport::Refused) => {
                            warn!(
                                schedule = %fire.record.id,
                                submit = %fire.record.submit_pack,
                                fire_instant = fire.fire_instant,
                                "schedule sweep: the occurrence's execution target was refused; \
                                 the refusal is recorded as its firing and the next occurrence \
                                 fires on schedule"
                            );
                        }
                        Err(KataError::AdmissionClosed(reason)) => {
                            info!(
                                schedule = %fire.record.id,
                                %reason,
                                "schedule sweep: runtime is stopping; leaving due cursor parked"
                            );
                        }
                        Err(e) => {
                            warn!(
                                schedule = %fire.record.id,
                                error = %e,
                                fire_instant = fire.fire_instant,
                                "schedule sweep: submit failed; the occurrence is NOT consumed and \
                                 the next sweep retries the same instant"
                            );
                        }
                    }
                }
            }
        }
        fired
    }

    /// Background task: sweep due schedules every `interval`. Spawn once at
    /// boot (analogous to [`crate::dispatcher::Dispatcher::run_assignment_deadline_sweep`]):
    ///
    /// ```ignore
    /// let engine = Arc::new(ScheduleEngine::new(face, submit));
    /// tokio::spawn(engine.run_schedule_sweep(Duration::from_secs(30)));
    /// ```
    ///
    /// The first interval tick is consumed so the loop does not immediately
    /// fire on spawn before the boot has settled; from then on each tick sweeps
    /// against the current wall clock.
    pub async fn run_schedule_sweep(self: Arc<Self>, interval: Duration) {
        let mut ticker = tokio::time::interval(interval);
        ticker.tick().await;
        loop {
            ticker.tick().await;
            let _fired = self.sweep_due(schedule_now_ms());
        }
    }
}

#[cfg(test)]
mod tests {
    use kata_program::schedule::{ScheduleSpec, ScheduleTrigger};

    use super::*;

    /// The shutdown fence leaves the due cursor PARKED, so the occurrence is retried
    /// on the next boot's first sweep rather than consumed by a shutdown.
    ///
    /// There is a second, structural reason this holds: the cursor
    /// advance lives inside the firing transaction, and `AdmissionClosed` is raised
    /// by the executor's shutdown fence BEFORE the acceptance commit — so there is
    /// nothing to roll back and nothing to park by hand.
    #[test]
    fn shutdown_admission_leaves_due_schedule_cursor_parked() {
        let face = ScheduleFace::new(Arc::new(
            kata_core::operational::OperationalDb::open_in_memory().unwrap(),
        ));
        let program = kata_program::execution_program::compile_starlark_execution_program(
            "only = stage(id = \"only\", prompt = \"go\", agent = \"shell\")\n\
             workflow(\"pack\", root = only)\n",
            "pack.star",
            &[],
        )
        .unwrap();
        face.install(
            &ScheduleSpec {
                id: "during-shutdown".into(),
                submit_pack: "pack".into(),
                trigger: ScheduleTrigger::Interval { every_ms: 100 },
                on_missed: MissedPolicy::FireOnceOnBoot,
                params: serde_json::Map::new(),
            },
            &program,
            0,
        )
        .unwrap();
        let submit: SubmitFn = Arc::new(|_| {
            Err(KataError::AdmissionClosed(
                "test shutdown fence".to_string(),
            ))
        });
        let engine = ScheduleEngine::new(face.clone(), submit);

        assert!(engine.sweep_due(100).is_empty());
        let record = face.get("during-shutdown").unwrap().unwrap();
        assert_eq!(record.next_fire_ms, 100);
        assert!(face.firings("during-shutdown").unwrap().is_empty());
    }
}
