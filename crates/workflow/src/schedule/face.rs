//! [`ScheduleFace`] — the typed durable-schedule authority over `operational.db`,
//! and the fire-time admission chokepoint.
//!
//! # Invariant
//!
//! A schedule BINDS an immutable checked program plus its invocation schema at
//! INSTALL, and a fire submits exactly those pinned bytes. Nothing on the fire path
//! resolves a pack name, opens the workflow library, or invokes a compiler — the
//! fire path has no argument through which a newly compiled program could enter
//! (`OperationalDb::fire_schedule` takes no program at all), which makes
//! "runtime code does not consult … a newly compiled replacement to decide an
//! existing run" structural rather than asserted.
//!
//! This face owns the two things `kata-core` cannot: the typed decodes
//! ([`ExecutionProgram`], [`ExecutionInvocation`], [`ScheduleTrigger`],
//! [`MissedPolicy`]) and the admission chokepoint those types imply.
//! Everything durable DELEGATES to [`OperationalDb`], so `operational.db` stays
//! the single writer.
//!
//! # Failure mode
//!
//! `ParamProvenance::Schedule` is documented as "re-validated at fire time", and
//! that property SURVIVES pinning — it gets stronger. [`ScheduleFace::fire`] decodes
//! the pinned bytes and re-runs the pin chokepoint ([`checked_schedule_pin`]) on
//! EVERY fire, then asserts the derived program hash, admission digest, and
//! canonical invocation bytes equal the pin. Because the input is fixed, the
//! re-validation is a genuine fixed point: it can only confirm or REFUSE, never
//! silently resolve to something different. Schedule digest stability therefore
//! holds by construction for the PINNED part — every fire of a program that forks no
//! isolated workspace submits byte-identical `invocation_json`. A
//! `worktree_isolated` program's fire submits the pin plus the execution target
//! THAT fire resolved (a schedule's target is resolved per fire, never pinned), so
//! its digest differs exactly where its fork base does.
//!
//! # Enforcement
//!
//! A pack edit between install and fire changes NOTHING at fire time. It takes
//! effect at the next boot reconciliation, through [`ScheduleFace::rebind`] — an
//! operator act, logged and restart-scoped — never silent. A timer is not an operator act, and the
//! sweep cannot reach `rebind`.

use std::sync::Arc;

use kata_core::operational::{
    FireOutcome, InstallOutcome, MissedFirePolicy, OperationalDb, RebindOutcome,
    RefusedFireOutcome, ScheduleFiringRow, ScheduleInstall,
};
use kata_types::idempotency::canonicalize_args;
use kata_types::target::ExecutionTarget;
use kata_types::{KataError, KataResult};
use ulid::Ulid;

use crate::admission::{CheckedAdmission, checked_admission, checked_schedule_pin};
use crate::execution_program_store::ExecutionInvocation;
use kata_program::execution_program::{DURABLE_EXECUTION_CLASS_REFUSAL_RECOURSE, ExecutionProgram};
use kata_program::schedule::{MissedPolicy, ScheduleSpec, ScheduleTrigger};

/// One installed durable schedule: its declaration, decoded, plus the durable
/// cursor.
///
/// Deliberately carries NO program and NO pinned bytes. The sweep decides
/// *whether* a schedule is due from this record; only the firing transaction loads
/// what actually runs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DurableSchedule {
    /// The durable schedule key.
    pub id: String,
    /// The authored submit target. PROVENANCE ONLY — never recompiled by the fire.
    pub submit_pack: String,
    /// What makes the schedule come due.
    pub trigger: ScheduleTrigger,
    /// The missed-while-down policy.
    pub on_missed: MissedPolicy,
    /// The durable next-fire cursor (Unix ms).
    pub next_fire_ms: u64,
}

/// One installed schedule whose PINNED program this binary cannot admit.
///
/// # Invariant
///
/// The schedule half of the compatibility membrane. `IncompatibleExecutionProgram` is
/// keyed by execution id and so structurally cannot describe a schedule pin, which is
/// why this is a distinct type rather than a reuse.
///
/// # Failure mode
///
/// The two halves refuse at DIFFERENT MOMENTS, and the operator's response differs
/// accordingly. An incompatible EXECUTION program is refused at the next `kata serve`
/// — `refuse_incompatible_execution_programs_at_boot` will not let the node start, so
/// it is an upgrade BLOCKER the operator meets immediately and deliberately. An
/// incompatible PINNED program blocks nothing: the node starts, the sweep runs, and
/// the refusal lands unattended at [`Self::next_fire_ms`] — a DEADLINE, and the 3am
/// lost occurrence this preview exists to prevent. So this carries the cursor: "which
/// schedule is broken" without "and it was due at 03:00" is half the finding.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IncompatiblePinnedProgram {
    /// The schedule whose pin cannot be admitted.
    pub schedule_id: String,
    /// Its authored submit target — provenance, and what the operator has to fix.
    pub submit_pack: String,
    /// The pinned program's declared schema version, when it carries one.
    pub schema_version: Option<u64>,
    /// The durable next-fire cursor (Unix ms) — WHEN this refusal becomes a lost
    /// occurrence. `None` only for a cursor outside the `u64` range, which no
    /// writer produces (`decode_row` refuses one on the sweep path); reporting the
    /// finding without a deadline beats dropping the finding.
    pub next_fire_ms: Option<u64>,
    /// Why this binary refuses it, in the same vocabulary the execution-side
    /// membrane reports.
    pub reason: String,
}

/// The typed durable-schedule authority. Clone-cheap; every clone sees the SAME
/// `operational.db` writer.
#[derive(Clone, Debug)]
pub struct ScheduleFace {
    db: Arc<OperationalDb>,
}

impl ScheduleFace {
    /// Wrap an operational database.
    #[must_use]
    pub fn new(db: Arc<OperationalDb>) -> Self {
        Self { db }
    }

    /// The operational writer behind this face.
    #[must_use]
    pub fn db(&self) -> &Arc<OperationalDb> {
        &self.db
    }

    /// Every installed schedule, in stable id order.
    pub fn all(&self) -> KataResult<Vec<DurableSchedule>> {
        self.db
            .installed_schedules()?
            .into_iter()
            .map(decode_row)
            .collect()
    }

    /// One installed schedule by id.
    pub fn get(&self, id: &str) -> KataResult<Option<DurableSchedule>> {
        self.db.installed_schedule(id)?.map(decode_row).transpose()
    }

    /// Every claimed firing of a schedule, oldest first; the newest `fired_at_ms`
    /// is the schedule's last fire.
    pub fn firings(&self, id: &str) -> KataResult<Vec<ScheduleFiringRow>> {
        self.db.schedule_firings(id)
    }

    /// Every installed schedule whose PINNED program this binary cannot admit.
    ///
    /// # Invariant
    ///
    /// `schedules.program_json` is a SECOND durable home for checked programs, and it
    /// had no compatibility surface at all: `ExecutionLifecycleFace::incompatible_programs`
    /// and both immutable `kata upgrade` probes iterate the `programs` table, and
    /// `inspect_schedule_targets_immutable` returns only `(schedule_id, submit_pack)`.
    ///
    /// # Failure mode
    ///
    /// So on a program- or invocation-schema bump, the equivalent condition on the two
    /// halves diverged completely: an incompatible EXECUTION program is a loud
    /// fail-closed boot refusal, while an incompatible PINNED program made
    /// `checked_admission` refuse, `revalidated_pin` error, the sweep park the cursor,
    /// and the schedule fire nothing FOREVER behind one WARN per 30s. Boot self-heals it
    /// only if the target still compiles; if it does not, boot deliberately keeps the
    /// stale unfireable pin.
    ///
    /// # Enforcement
    ///
    /// The set reported here is exactly the set [`Self::revalidated_pin`] refuses, on
    /// the properties both can see: `classify_program_bytes` runs the SAME
    /// `ExecutionProgram::validate_carried_stage_execution_classes` the fire path runs.
    /// A schema bump is not the only way a pin becomes unfireable: a reader that
    /// answered on the schema alone would preview a pin this binary refuses to fire
    /// as COMPATIBLE — including at `kata upgrade` — and the operator would meet the
    /// refusal as a lost occurrence instead of a preview line.
    ///
    /// Reported rather than refused: at boot there IS a pin, and the reconciliation may
    /// be about to replace it. Boot logs each finding that SURVIVES reconciliation at
    /// ERROR, and `kata upgrade` previews the same set immutably before the operator
    /// commits to the new binary. Each finding
    /// carries [`IncompatiblePinnedProgram::next_fire_ms`], because this half of the
    /// membrane states a deadline rather than a blocker.
    pub fn incompatible_pinned_programs(&self) -> KataResult<Vec<IncompatiblePinnedProgram>> {
        let mut found = Vec::new();
        for row in self.db.installed_schedules()? {
            let Some((program, _)) = self.db.pinned_schedule_admission(&row.schedule_id)? else {
                continue;
            };
            let (metadata, incompatibility) =
                crate::execution_program_store::classify_program_bytes(
                    &program.program_json,
                    None,
                )?;
            if let Some(incompatibility) = incompatibility {
                found.push(IncompatiblePinnedProgram {
                    schedule_id: row.schedule_id,
                    submit_pack: row.submit_pack,
                    schema_version: metadata.schema_version,
                    next_fire_ms: u64::try_from(row.cursor_ms).ok(),
                    reason: incompatibility.reason(),
                });
            }
        }
        found.sort_by(|left, right| left.schedule_id.cmp(&right.schedule_id));
        Ok(found)
    }

    /// Install a schedule, PINNING the checked target program and the resolved
    /// invocation it will submit.
    ///
    /// `program` is the compiled target of `spec.submit_pack`, resolved by the
    /// caller (boot's library reconciliation). The invocation is built from
    /// `spec.params` through the ONE admission chokepoint, so what is pinned is a
    /// validated admission, not a caller assertion.
    ///
    /// An identical re-install is [`InstallOutcome::AlreadyInstalled`] and PRESERVES
    /// the durable cursor; a divergent one REFUSES — see [`Self::rebind`].
    pub fn install(
        &self,
        spec: &ScheduleSpec,
        program: &ExecutionProgram,
        now_ms: u64,
    ) -> KataResult<InstallOutcome> {
        let checked = Self::checked_target(spec, program)?;
        let install = install_record(spec, next_after(spec, now_ms)?)?;
        self.db
            .install_schedule(&install, checked.program(), checked.invocation())
    }

    /// Replace an installed schedule's pin — the boot reconciliation's response to
    /// an edited pack, and the ONLY path on which a binding changes.
    ///
    /// The cursor is preserved when the trigger is unchanged and re-anchored when it
    /// changed.
    pub fn rebind(
        &self,
        spec: &ScheduleSpec,
        program: &ExecutionProgram,
        now_ms: u64,
    ) -> KataResult<RebindOutcome> {
        let checked = Self::checked_target(spec, program)?;
        let install = install_record(spec, next_after(spec, now_ms)?)?;
        self.db
            .rebind_schedule(&install, checked.program(), checked.invocation())
    }

    /// Remove a schedule the library no longer declares.
    pub fn remove(&self, id: &str) -> KataResult<bool> {
        self.db.remove_schedule(id)
    }

    /// Advance a schedule's cursor without firing — the `Skip` missed-policy path.
    /// Monotone.
    pub fn skip_to(&self, id: &str, next_fire_ms: u64) -> KataResult<()> {
        self.db.skip_schedule_to(id, cursor_i64(next_fire_ms)?)
    }

    /// The PINNED typed program + invocation a schedule binds, re-validated through
    /// the admission chokepoint and asserted equal to the pin.
    ///
    /// This is validate-at-fire. It runs on EVERY fire, over the pinned bytes:
    /// `checked_admission` RE-DERIVES the whole-program hash from the decoded body,
    /// re-runs the param resolver's fixed point and every envelope bound, and the
    /// three assertions below refuse a forged or drifted pin BEFORE any execution is
    /// admitted.
    ///
    /// # Failure
    ///
    /// The program assertion below is only meaningful BECAUSE `checked_admission`
    /// re-derives: `CheckedAdmission::program().program_hash` is a hash of the
    /// decoded body, so comparing it to `bound_program_hash` proves the pinned BYTES
    /// produce the pinned hash. A chokepoint that COPIED the header field would
    /// reduce this assertion to comparing the header's own `program_hash` field
    /// with `bound_program_hash` — which `pinned_admission` already checked — and a
    /// tampered program body carrying an untouched `program_hash` string would pass all three
    /// assertions and commit. `a_tampered_program_body_under_an_untouched_header_hash_refuses`
    /// (`crates/workflow/tests/program_body_hash.rs`) is the regression.
    pub fn revalidated_pin(
        &self,
        id: &str,
    ) -> KataResult<Option<(ExecutionProgram, ExecutionInvocation)>> {
        let Some((pinned_program, pinned_invocation)) = self.db.pinned_schedule_admission(id)?
        else {
            return Ok(None);
        };
        let program: ExecutionProgram = serde_json::from_slice(&pinned_program.program_json)
            .map_err(|error| {
                KataError::Storage(format!(
                    "schedule {id}: pinned checked program does not decode: {error}"
                ))
            })?;
        // "Invalid combinations fail before a run is created", READ side —
        // DECODE DOOR 2 of 2.
        //
        // `checked_admission` below re-derives the whole-program hash, so it proves
        // these bytes are COHERENT; it says nothing about whether the axes they
        // record are a combination this binary can honour. A pin written by an
        // earlier schema-3 binary — same schema, different closed-world matrix — is
        // self-consistent and passes every existing assertion. Refuse it HERE,
        // before the admission chokepoint and before any occurrence is claimed.
        program
            .validate_carried_stage_execution_classes()
            .map_err(|invalid| {
                KataError::Validation(format!(
                    "schedule {id}: refusing to fire a pinned checked program this binary cannot \
                     honour — {invalid} {DURABLE_EXECUTION_CLASS_REFUSAL_RECOURSE}"
                ))
            })?;
        let invocation: ExecutionInvocation =
            serde_json::from_slice(&pinned_invocation.invocation_json).map_err(|error| {
                KataError::Storage(format!(
                    "schedule {id}: pinned invocation envelope does not decode: {error}"
                ))
            })?;
        let checked = checked_schedule_pin(&program, &invocation).map_err(|error| {
            KataError::Validation(format!(
                "schedule {id}: the pinned admission no longer validates: {error}"
            ))
        })?;
        if checked.program().program_hash != pinned_program.program_hash {
            return Err(KataError::Validation(format!(
                "schedule {id}: the hash RE-DERIVED over the pinned program body does not \
                 equal bound_program_hash; refusing to fire a forged pin"
            )));
        }
        if checked.admission_digest() != pinned_invocation.admission_digest {
            return Err(KataError::Validation(format!(
                "schedule {id}: the re-derived admission digest does not equal \
                 bound_admission_digest; refusing to fire a forged pin"
            )));
        }
        if checked.invocation_json() != pinned_invocation.invocation_json.as_slice() {
            return Err(KataError::Validation(format!(
                "schedule {id}: re-validating the pinned invocation produced DIFFERENT canonical \
                 bytes; refusing to fire a pin that is not a fixed point"
            )));
        }
        Ok(Some((program, invocation)))
    }

    /// Commit ONE firing: claim the due instant, advance the cursor, and submit the
    /// pinned execution — all in a single `operational.db` transaction.
    ///
    /// # Invariant
    ///
    /// This is the whole of the eliminated half-commit. Either the claim, the
    /// cursor, and the execution all commit, or none of them do; there is no
    /// interleaving in which an execution is durable and the cursor is not, and no
    /// interleaving in which the cursor advanced past an occurrence that never ran.
    ///
    /// # Failure
    ///
    /// A redelivered claim for the same DUE instant is
    /// [`FireOutcome::AlreadyFired`] — which still advances the cursor, so the
    /// idempotent path is self-healing. The program is NOT a parameter: the writer
    /// reads the pinned bytes itself.
    ///
    /// # Enforcement
    ///
    /// [`Self::revalidated_pin`] runs FIRST, here, rather than only in the caller.
    /// `OperationalDb::fire_schedule` reads the pinned bytes and inserts them into
    /// `programs` itself, and `kata-core` cannot see the typed [`ExecutionProgram`]
    /// — so its own pin check is limited to `header == bound_program_hash`. Leaving
    /// the typed re-validation to the boot submit closure made the property
    /// depend on that closure's call ORDER: `ScheduleFace::fire` on its own would
    /// commit a body-tampered pin into the durable `programs` row that boot recovery
    /// reloads. This makes the guard structural for every caller of the typed face,
    /// which is every production caller (`fire_schedule` has no other one).
    ///
    /// Not an atomicity claim: the read and the fire are separate transactions, so
    /// this is the same defense-in-depth the substrate's own header check is. The
    /// only writers of a pin are install/rebind, both boot-scoped and both holding
    /// the data-dir authority.
    ///
    /// # The fire's target
    ///
    /// `target` is the execution target THIS fire resolved for a
    /// `worktree_isolated` program (`None` for any other): a schedule's target is
    /// resolved at every fire, never pinned. The pin plus that target is run
    /// through the admission chokepoint here — [`checked_admission`], the
    /// structural target check included — before the writer splices the same
    /// target into the pinned envelope and commits it. A target on a program that
    /// forks no isolated workspace, or none on one that does, is refused here.
    pub fn fire(
        &self,
        id: &str,
        fire_instant: u64,
        execution_id: Ulid,
        next_cursor_ms: u64,
        target: Option<&ExecutionTarget>,
    ) -> KataResult<FireOutcome> {
        let Some((program, pinned)) = self.revalidated_pin(id)? else {
            return Err(KataError::Validation(format!(
                "schedule {id}: refusing to fire a schedule that is not installed"
            )));
        };
        checked_admission(&program, &pinned.with_target(target.cloned())).map_err(|error| {
            KataError::Validation(format!(
                "schedule {id}: the pinned admission with this fire's target does not validate: \
                 {error}"
            ))
        })?;
        self.db.fire_schedule(
            id,
            cursor_i64(fire_instant)?,
            execution_id,
            cursor_i64(next_cursor_ms)?,
            target,
        )
    }

    /// Record the DUE occurrence at `fire_instant` as REFUSED — its execution
    /// target did not resolve, or did not pass the structural target check, so
    /// no execution exists — and advance the cursor past it, in one
    /// transaction. The refusal is the instant's durable firing record; the
    /// occurrence is never retried silently, and the next one fires on schedule.
    pub fn refuse_fire(
        &self,
        id: &str,
        fire_instant: u64,
        refusal: &str,
        next_cursor_ms: u64,
    ) -> KataResult<RefusedFireOutcome> {
        self.db.refuse_schedule_fire(
            id,
            cursor_i64(fire_instant)?,
            refusal,
            cursor_i64(next_cursor_ms)?,
        )
    }

    /// Validate the authored spec against its compiled target and produce the
    /// checked admission to pin. The ONE place a schedule's invocation is built, so
    /// install and rebind cannot disagree about what a declaration means.
    ///
    /// Associated rather than a method: it touches no durable state, and keeping it
    /// off `&self` makes that visible — building the admission to pin is pure, and
    /// only [`ScheduleFace::install`] / [`ScheduleFace::rebind`] commit it.
    pub fn checked_target(
        spec: &ScheduleSpec,
        program: &ExecutionProgram,
    ) -> KataResult<CheckedAdmission> {
        spec.validate()?;
        let resolved =
            kata_types::params::resolve_and_validate_params(&program.params, &spec.params)
                .map_err(|error| {
                    KataError::Validation(format!(
                        "schedule {}: params do not satisfy the declared contract of {:?}: {error}",
                        spec.id, spec.submit_pack
                    ))
                })?;
        let invocation = ExecutionInvocation::workflow_with_params(Vec::new(), resolved);
        checked_schedule_pin(program, &invocation).map_err(|error| {
            KataError::Validation(format!(
                "schedule {}: target {:?} does not admit: {error}",
                spec.id, spec.submit_pack
            ))
        })
    }
}

/// The authored declaration in the operational plane's shape.
///
/// `trigger` is CANONICAL JSON, not `serde_json::to_string`:
/// `converge_existing_schedule` compares the column by string equality, so a
/// non-canonical encoding would make an identical re-install look like a rebind and
/// re-anchor the cursor on every boot.
fn install_record(spec: &ScheduleSpec, cursor_ms: u64) -> KataResult<ScheduleInstall> {
    Ok(ScheduleInstall {
        schedule_id: spec.id.clone(),
        submit_pack: spec.submit_pack.clone(),
        trigger: canonical_trigger(&spec.trigger)?,
        on_missed: core_policy(spec.on_missed),
        cursor_ms: cursor_i64(cursor_ms)?,
    })
}

/// The `(schedule_id, submit_pack)` of every installed schedule, read WITHOUT
/// creating SQLite sidecars, taking locks, or recovering ambient journal state.
///
/// # Invariant
///
/// `kata upgrade --dry-run` must be observationally READ-ONLY — the preview's own
/// regression asserts the data dir's bytes are unchanged and that no `-wal`/`-shm`
/// appeared. `OperationalDb::open` cannot serve that: it applies WAL pragmas, creates
/// the schema idempotently, and stamps `user_version`, so merely opening the nucleus
/// to list schedule targets would materialize sidecars and fail the preview's
/// byte-identity bar. This uses the same shared immutable probe
/// `inspect_blocking_incompatible_programs_immutable` uses, behind the same
/// plain-file-I/O forward-version gate.
///
/// A data dir with no nucleus, or one without a schedules table, is empty rather
/// than an error.
pub fn inspect_schedule_targets_immutable(
    path: impl AsRef<std::path::Path>,
) -> KataResult<Vec<(String, String)>> {
    let path = path.as_ref().to_path_buf();
    // The SAME forward-version gate the production open path applies, before reading a
    // row: plain file I/O, no handle, no sidecar, no page rewrite.
    kata_core::refuse_newer_operational_schema(&path)?;
    kata_core::inspect_optional_immutable_sqlite(&path, "operational nucleus", |connection| {
        let schedules_exist: bool = connection
            .query_row(
                "SELECT EXISTS (
                    SELECT 1 FROM sqlite_schema WHERE type = 'table' AND name = 'schedules'
                )",
                [],
                |row| row.get(0),
            )
            .map_err(|error| {
                KataError::Storage(format!("operational nucleus validate schedules: {error}"))
            })?;
        if !schedules_exist {
            return Ok(Vec::new());
        }
        let mut stmt = connection
            .prepare("SELECT schedule_id, submit_pack FROM schedules ORDER BY schedule_id")
            .map_err(|error| {
                KataError::Storage(format!(
                    "operational nucleus prepare schedule scan: {error}"
                ))
            })?;
        let rows = stmt
            .query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })
            .map_err(|error| {
                KataError::Storage(format!("operational nucleus schedule scan: {error}"))
            })?;
        rows.collect::<Result<Vec<_>, _>>().map_err(|error| {
            KataError::Storage(format!("operational nucleus schedule scan row: {error}"))
        })
    })
    .map(Option::unwrap_or_default)
}

/// [`ScheduleFace::incompatible_pinned_programs`] without opening the nucleus — the
/// upgrade preview's read of the schedule half of the compatibility membrane.
///
/// # Invariant
///
/// Same posture and same shared probe as [`inspect_schedule_targets_immutable`]:
/// `kata upgrade --dry-run` must be observationally READ-ONLY, so this cannot use
/// `OperationalDb::open` (which applies WAL pragmas, creates the schema, and stamps
/// `user_version`, materializing sidecars). A data dir with no nucleus, or one
/// without a schedules table, is empty rather than an error.
///
/// # Failure mode
///
/// This is the finding an operator MUST be able to see before upgrading: a pinned
/// program the new binary cannot admit fires nothing, forever, and boot only self-heals
/// it if the target still compiles. It reads `cursor_ms` so the
/// preview can state WHEN — the next fire is the moment the refusal costs something.
pub fn inspect_incompatible_pinned_programs_immutable(
    path: impl AsRef<std::path::Path>,
) -> KataResult<Vec<IncompatiblePinnedProgram>> {
    let path = path.as_ref().to_path_buf();
    kata_core::refuse_newer_operational_schema(&path)?;
    kata_core::inspect_optional_immutable_sqlite(&path, "operational nucleus", |connection| {
        let schedules_exist: bool = connection
            .query_row(
                "SELECT EXISTS (
                    SELECT 1 FROM sqlite_schema WHERE type = 'table' AND name = 'schedules'
                )",
                [],
                |row| row.get(0),
            )
            .map_err(|error| {
                KataError::Storage(format!("operational nucleus validate schedules: {error}"))
            })?;
        if !schedules_exist {
            return Ok(Vec::new());
        }
        let mut stmt = connection
            .prepare(
                "SELECT schedule_id, submit_pack, program_json, cursor_ms
                   FROM schedules ORDER BY schedule_id",
            )
            .map_err(|error| {
                KataError::Storage(format!("operational nucleus prepare pin scan: {error}"))
            })?;
        let rows = stmt
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                    row.get::<_, i64>(3)?,
                ))
            })
            .map_err(|error| {
                KataError::Storage(format!("operational nucleus pin scan: {error}"))
            })?;
        let mut found = Vec::new();
        for row in rows {
            let (schedule_id, submit_pack, program_json, cursor_ms) = row.map_err(|error| {
                KataError::Storage(format!("operational nucleus pin scan row: {error}"))
            })?;
            let (metadata, incompatibility) =
                crate::execution_program_store::classify_program_bytes(&program_json, None)?;
            if let Some(incompatibility) = incompatibility {
                found.push(IncompatiblePinnedProgram {
                    schedule_id,
                    submit_pack,
                    schema_version: metadata.schema_version,
                    next_fire_ms: u64::try_from(cursor_ms).ok(),
                    reason: incompatibility.reason(),
                });
            }
        }
        Ok(found)
    })
    .map(Option::unwrap_or_default)
}

/// The canonical serialization of a trigger declaration — the durable column
/// value, and the comparison key for converge-or-refuse.
fn canonical_trigger(trigger: &ScheduleTrigger) -> KataResult<String> {
    let value = serde_json::to_value(trigger).map_err(|error| {
        KataError::Serialization(format!("serialize schedule trigger: {error}"))
    })?;
    String::from_utf8(canonicalize_args(&value)).map_err(|error| {
        KataError::Serialization(format!("canonical schedule trigger is not UTF-8: {error}"))
    })
}

/// Decode one durable row into the typed sweep record, VALIDATING on read.
///
/// # Failure mode
///
/// This decoder fails closed like the rest of its family. Deserializing `trigger`
/// without calling [`ScheduleTrigger::validate`], or coercing an out-of-range
/// `cursor_ms` to `0` with `unwrap_or(0)`, would each produce exactly the spin the strict-advance refusal exists to prevent —
///
/// * a durable `{"interval":{"every_ms":0}}` makes `next_after(now) == now`, so the
///   firing transaction's strict `next_cursor_ms > fire_instant` check refuses, the
///   cursor stays on the due instant, and the sweep re-presents it every 30s forever
///   behind one WARN;
/// * a NEGATIVE `cursor_ms` decoded to `0` is `<= now` forever, and its fire
///   would claim instant `0` rather than the stored one.
///
/// `every_ms: 0` is unreachable through today's writers — `ScheduleSpec::validate`
/// refuses it at authoring, install, and rebind, and `next_after` arithmetic cannot
/// produce a non-advancing cursor — but "no writer produces it" is a property of the
/// writers, not of the representation, and the value is trivially REPRESENTABLE on
/// disk. Validating here makes an out-of-vocabulary row a loud refusal (the sweep's
/// `face.all()` arm already fails closed for the tick) instead of a permanent silent
/// wedge.
fn decode_row(row: kata_core::operational::ScheduleRow) -> KataResult<DurableSchedule> {
    let trigger: ScheduleTrigger = serde_json::from_str(&row.trigger).map_err(|error| {
        KataError::Storage(format!(
            "schedule {}: stored trigger {:?} does not decode: {error}",
            row.schedule_id, row.trigger
        ))
    })?;
    trigger.validate().map_err(|error| {
        KataError::Storage(format!(
            "schedule {}: stored trigger {:?} decodes but is not a valid trigger ({error}); \
             refusing to sweep a row no writer could have produced — a non-advancing trigger \
             wedges the cursor on one instant forever",
            row.schedule_id, row.trigger
        ))
    })?;
    let next_fire_ms = u64::try_from(row.cursor_ms).map_err(|_| {
        KataError::Storage(format!(
            "schedule {}: stored cursor_ms {} is negative; refusing to sweep it. Coercing it to \
             0 would make the schedule permanently due AND make its fire claim instant 0 rather \
             than the stored one",
            row.schedule_id, row.cursor_ms
        ))
    })?;
    Ok(DurableSchedule {
        id: row.schedule_id,
        submit_pack: row.submit_pack,
        trigger,
        on_missed: typed_policy(row.on_missed),
        next_fire_ms,
    })
}

fn next_after(spec: &ScheduleSpec, now_ms: u64) -> KataResult<u64> {
    spec.trigger.next_after(now_ms)
}

/// Unix-ms cursors are `u64` in the authoring/sweep types and `INTEGER` on disk.
/// A value beyond `i64::MAX` is ~292 million years out; refuse rather than wrap
/// into the past.
fn cursor_i64(value: u64) -> KataResult<i64> {
    i64::try_from(value).map_err(|_| {
        KataError::Validation(format!(
            "schedule cursor {value} exceeds the durable INTEGER range"
        ))
    })
}

/// Map the authored policy onto the operational vocabulary. The two enums carry
/// identical on-disk spellings by construction;
/// `missed_policy_spellings_match_the_operational_vocabulary` pins it.
pub(crate) fn core_policy(policy: MissedPolicy) -> MissedFirePolicy {
    match policy {
        MissedPolicy::FireOnceOnBoot => MissedFirePolicy::FireOnceOnBoot,
        MissedPolicy::Skip => MissedFirePolicy::Skip,
    }
}

pub(crate) fn typed_policy(policy: MissedFirePolicy) -> MissedPolicy {
    match policy {
        MissedFirePolicy::FireOnceOnBoot => MissedPolicy::FireOnceOnBoot,
        MissedFirePolicy::Skip => MissedPolicy::Skip,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The two enums are mapped positionally by [`core_policy`] / [`typed_policy`],
    /// and BOTH are written to `schedules.on_missed`, whose CHECK constraint only
    /// accepts the operational spellings. A divergence would not be a compile error
    /// — it would be a runtime CHECK violation on the first install.
    #[test]
    fn missed_policy_spellings_match_the_operational_vocabulary() {
        for policy in [MissedPolicy::FireOnceOnBoot, MissedPolicy::Skip] {
            let core = core_policy(policy);
            assert_eq!(
                MissedPolicy::parse(core.as_str()),
                Some(policy),
                "the operational label {:?} must parse back to the authored policy",
                core.as_str()
            );
            assert_eq!(typed_policy(core), policy, "the mapping round-trips");
        }
    }

    /// The trigger column is the converge-or-refuse comparison key, so its encoding
    /// has to be canonical AND has to be the spelling the substrate's own CHECK
    /// vocabulary and fixtures already use.
    #[test]
    fn canonical_trigger_is_stable_and_round_trips() {
        let interval = ScheduleTrigger::Interval { every_ms: 1000 };
        assert_eq!(
            canonical_trigger(&interval).unwrap(),
            "{\"interval\":{\"every_ms\":1000}}"
        );
        let cron = ScheduleTrigger::Cron {
            expr: "0 2 * * *".to_string(),
        };
        assert_eq!(
            canonical_trigger(&cron).unwrap(),
            "{\"cron\":{\"expr\":\"0 2 * * *\"}}"
        );
        for trigger in [interval, cron] {
            let encoded = canonical_trigger(&trigger).unwrap();
            let decoded: ScheduleTrigger = serde_json::from_str(&encoded).unwrap();
            assert_eq!(decoded, trigger);
            assert_eq!(
                canonical_trigger(&decoded).unwrap(),
                encoded,
                "re-encoding a decoded trigger must be byte-identical, or an unchanged \
                 re-install looks like a rebind"
            );
        }
    }
}
