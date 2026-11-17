//! [`ExecutionLifecycleFace`] — the typed execution-lifecycle authority over
//! `operational.db`.
//!
//! # Invariant
//!
//! This is the WHOLE production surface for execution-nucleus facts (checked
//! program, immutable invocation, coarse lifecycle). It owns
//! exactly two things `kata-core` cannot: the typed decodes
//! (`ExecutionInvocation`, `ExecutionTerminalReason`, `ExecutionLifecycleRecord`)
//! and the canonical-bytes validation those types imply. Everything else — every
//! read, every mutation — DELEGATES to [`ExecutionLifecycleView`] /
//! [`OperationalDb`], so `operational.db` stays the single writer and the single
//! authority.
//!
//! # Failure mode
//!
//! This face is NOT a compatibility reader. It reads exactly one schema — the
//! current `operational.db` — and there is no second store to dual-write and no
//! reader reconciliation rule to get wrong.
//!
//! # Enforcement
//!
//! Admission goes through [`crate::admission::checked_admission`] — the ONE
//! admission chokepoint — so the `(invocation_json, admission_digest)` pair the
//! operational writer persists is always derived from validated bytes.
//! [`Self::invocation`] re-verifies the stored envelope on every read (canonical
//! JSON + digest binding via the core view, then the typed column cross-check
//! here), and [`Self::lifecycle`] re-verifies that a stored terminal reason is
//! canonical JSON.

use std::sync::Arc;

use kata_core::operational::{
    ExecutionLifecycleView, LifecycleRow, LifecycleState, OperationalDb, SubmitOutcome,
};
use kata_effects_contract::TargetPinClaim;
use kata_types::idempotency::canonicalize_args;
use kata_types::{KataError, KataResult};
use ulid::Ulid;

/// Durable workspace disposition owned by execution cleanup.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CleanupDisposition {
    PreserveSuccessfulCandidate,
    RemoveSubmitSetupWorkspace,
    ParkFailedOrCancelledCandidate,
    ConvergeAbsent,
}

impl CleanupDisposition {
    /// The disposition a terminal intent of `outcome` commits.
    const fn for_outcome(outcome: ExecutionLifecycleState) -> Self {
        match outcome {
            ExecutionLifecycleState::Completed => Self::PreserveSuccessfulCandidate,
            ExecutionLifecycleState::Failed
            | ExecutionLifecycleState::Cancelled
            | ExecutionLifecycleState::TimedOut => Self::ParkFailedOrCancelledCandidate,
            ExecutionLifecycleState::Admitting
            | ExecutionLifecycleState::Running
            | ExecutionLifecycleState::Terminalizing => Self::ConvergeAbsent,
        }
    }

    const fn as_str(self) -> &'static str {
        match self {
            Self::PreserveSuccessfulCandidate => "preserve_success",
            Self::RemoveSubmitSetupWorkspace => "remove_submit_setup",
            Self::ParkFailedOrCancelledCandidate => "park_failed",
            Self::ConvergeAbsent => "converge_absent",
        }
    }

    fn from_str(value: &str) -> KataResult<Self> {
        match value {
            "preserve_success" => Ok(Self::PreserveSuccessfulCandidate),
            "remove_submit_setup" => Ok(Self::RemoveSubmitSetupWorkspace),
            "park_failed" => Ok(Self::ParkFailedOrCancelledCandidate),
            "converge_absent" => Ok(Self::ConvergeAbsent),
            other => Err(KataError::Storage(format!(
                "unknown execution cleanup disposition {other:?}"
            ))),
        }
    }
}

use crate::execution_program_store::{
    ExecutionInvocation, ExecutionInvocationKind, ExecutionInvocationRecord,
    ExecutionLifecycleRecord, ExecutionLifecycleState, ExecutionProgramMetadata,
    ExecutionTerminalReason, IncompatibleExecutionProgram, MAX_EXECUTION_INVOCATION_BYTES,
    blocking_incompatible_programs, execution_program_metadata, validated_terminal_reason_bytes,
};
use kata_program::execution_program::ExecutionProgram;

/// The typed execution-lifecycle authority. Clone-cheap; every clone sees the
/// SAME `operational.db` writer.
#[derive(Clone, Debug)]
pub struct ExecutionLifecycleFace {
    view: ExecutionLifecycleView,
}

impl ExecutionLifecycleFace {
    /// Wrap an operational database.
    #[must_use]
    pub fn new(db: Arc<OperationalDb>) -> Self {
        Self {
            view: ExecutionLifecycleView::new(db),
        }
    }

    /// A face over the operational database at `path`, opening (or creating) it.
    ///
    /// Boot owns ONE `OperationalDb` for the whole process and builds the face from
    /// it with [`Self::new`]; this convenience exists for tests and one-shot tools
    /// that need a face over a specific file without external output storage.
    /// Offloaded outputs require [`Self::open_with_cas`]; this constructor does
    /// not infer or create a CAS from the database path.
    pub fn open(path: impl AsRef<std::path::Path>) -> KataResult<Self> {
        Ok(Self::new(Arc::new(OperationalDb::open(path)?)))
    }

    /// Open authority with its explicitly selected durable output store.
    pub fn open_with_cas(
        path: impl AsRef<std::path::Path>,
        cas: Arc<kata_core::store::cas::CasStore>,
    ) -> KataResult<Self> {
        Ok(Self::new(Arc::new(OperationalDb::open_with_cas(
            path, cas,
        )?)))
    }

    /// A face over a fresh in-memory operational database (tests, and the
    /// in-memory ledger mode).
    pub fn in_memory() -> KataResult<Self> {
        Ok(Self::new(Arc::new(OperationalDb::open_in_memory()?)))
    }

    /// The narrow core read facade this face decodes.
    #[must_use]
    pub fn view(&self) -> &ExecutionLifecycleView {
        &self.view
    }

    /// The operational writer. Held so every caller reaches the typed transaction
    /// API without a second handle.
    #[must_use]
    pub fn db(&self) -> &Arc<OperationalDb> {
        self.view.db()
    }

    // -- admission -------------------------------------------------------

    /// Admit a checked program + immutable invocation into the `admitting` phase.
    ///
    /// Program + invocation + `admitting` lifecycle + the `submitted` transition +
    /// the execution projection commit in ONE `synchronous=FULL` transaction. No
    /// attempt may be dispatched until [`Self::mark_running_after_admission`].
    ///
    /// # Failure
    ///
    /// Validation runs at [`crate::admission::checked_admission`] BEFORE any
    /// durable write. A re-admission with byte-identical facts converges
    /// idempotently; a different program or invocation for the same execution id
    /// is a typed refusal.
    pub fn admit_current_execution(
        &self,
        execution_id: Ulid,
        program: &ExecutionProgram,
        invocation: &ExecutionInvocation,
    ) -> KataResult<()> {
        let checked = crate::admission::checked_admission(program, invocation)?;
        match checked.persist(self.db(), execution_id)? {
            SubmitOutcome::Submitted { .. } | SubmitOutcome::AlreadySubmitted => Ok(()),
        }
    }

    /// INVOKE a subworkflow child under the `oci` profile: claim
    /// the parent's `Invoke` main attempt parked `awaiting_child_completion` on
    /// `child_execution_id` AND admit that child, in ONE operational transaction
    /// (`OperationalDb::invoke_child_execution`). The child's records are minted by
    /// [`crate::admission::checked_admission`], the same chokepoint every admission uses.
    ///
    /// # Errors
    ///
    /// The admission's validation (before any write), and the operational verb's.
    pub fn invoke_child_execution(
        &self,
        attempt_id: Ulid,
        spec: &kata_core::operational::MainAttemptSpec,
        child_execution_id: Ulid,
        program: &ExecutionProgram,
        invocation: &ExecutionInvocation,
    ) -> KataResult<kata_core::operational::InvokeChildOutcome> {
        let checked = crate::admission::checked_admission(program, invocation)?;
        self.db().invoke_child_execution(
            attempt_id,
            spec,
            child_execution_id,
            checked.program(),
            checked.invocation(),
        )
    }

    // -- the lifecycle edges --------------------------------------------

    /// Admission evidence and workspace setup are complete. The sole transition
    /// that authorizes dispatch.
    pub fn mark_running_after_admission(&self, execution_id: Ulid) -> KataResult<()> {
        self.db().mark_running(execution_id).map(drop)
    }

    /// Durably latch ONE terminal decision before failure evidence, candidate
    /// parking, or any other destructive closeout. Equal retries are idempotent; a
    /// different outcome or reason is refused.
    pub fn begin_terminalization(
        &self,
        execution_id: Ulid,
        outcome: ExecutionLifecycleState,
        reason: &ExecutionTerminalReason,
    ) -> KataResult<()> {
        let disposition = CleanupDisposition::for_outcome(outcome);
        self.begin_terminalization_with_cleanup(execution_id, outcome, reason, disposition)
    }

    /// Latch terminal intent and an explicitly typed cleanup disposition atomically.
    pub fn begin_terminalization_with_cleanup(
        &self,
        execution_id: Ulid,
        outcome: ExecutionLifecycleState,
        reason: &ExecutionTerminalReason,
        disposition: CleanupDisposition,
    ) -> KataResult<()> {
        if !outcome.is_terminal() {
            return Err(KataError::Validation(
                "execution lifecycle terminal intent requires a terminal outcome".into(),
            ));
        }
        let reason_json = validated_terminal_reason_bytes(reason)?;
        self.db()
            .begin_terminalization_with_cleanup(
                execution_id,
                core_state(outcome),
                &reason_json,
                disposition.as_str(),
            )
            .map(drop)
    }

    /// [`Self::begin_terminalization`], unless a CANCEL was latched on the execution
    /// first by another party (a parent ending the `Invoke` that waits on it, or an
    /// operator cancel of the execution or of an ancestor —
    /// `OperationalDb::latch_execution_cancel`):
    /// that intent is ADOPTED and nothing is written. Answers the intent that stands —
    /// the caller's, or the adopted `cancelled` one with its latched reason.
    ///
    /// A runner's task latches its own outcome only after its run returned, so a cancel
    /// latched while it ran is the one intent it can meet here; any OTHER differing
    /// intent is refused exactly as [`Self::begin_terminalization`] refuses it.
    ///
    /// # Errors
    ///
    /// [`Self::begin_terminalization`]'s, and a latched reason that does not decode.
    pub fn begin_terminalization_adopting_cancel(
        &self,
        execution_id: Ulid,
        outcome: ExecutionLifecycleState,
        reason: &ExecutionTerminalReason,
    ) -> KataResult<(ExecutionLifecycleState, ExecutionTerminalReason)> {
        let reason_json = validated_terminal_reason_bytes(reason)?;
        let disposition = CleanupDisposition::for_outcome(outcome);
        match self.db().begin_terminalization_adopting_cancel(
            execution_id,
            core_state(outcome),
            &reason_json,
            disposition.as_str(),
        )? {
            kata_core::operational::TerminalIntent::Latched => Ok((outcome, reason.clone())),
            kata_core::operational::TerminalIntent::AdoptedCancel {
                terminal_reason_json,
            } => {
                let adopted: ExecutionTerminalReason =
                    serde_json::from_slice(&terminal_reason_json).map_err(|error| {
                        KataError::Storage(format!(
                            "decode the cancel latched on execution {execution_id}: {error}"
                        ))
                    })?;
                Ok((ExecutionLifecycleState::Cancelled, adopted))
            }
        }
    }

    /// Publish the already-latched terminal outcome after required closeout.
    pub fn finish_terminalization(&self, execution_id: Ulid) -> KataResult<()> {
        self.db().finish_terminalization(execution_id).map(drop)
    }

    /// Discharge the durable execution cleanup gate before terminal publication.
    pub fn complete_cleanup(&self, execution_id: Ulid) -> KataResult<()> {
        self.db().complete_execution_cleanup(execution_id).map(drop)
    }

    /// Read the durable cleanup action selected in the terminal-intent transaction.
    pub fn cleanup_disposition(
        &self,
        execution_id: Ulid,
    ) -> KataResult<Option<CleanupDisposition>> {
        self.db()
            .execution_cleanup_disposition(execution_id)?
            .as_deref()
            .map(CleanupDisposition::from_str)
            .transpose()
    }

    /// Preserve bounded cleanup failure evidence for immediate restart retry.
    pub fn defer_cleanup(&self, execution_id: Ulid, error: &str) -> KataResult<()> {
        self.db().defer_execution_cleanup(execution_id, error, 0)
    }

    // -- reads -----------------------------------------------------------

    /// The authoritative lifecycle for one execution.
    pub fn lifecycle(&self, execution_id: Ulid) -> KataResult<Option<ExecutionLifecycleRecord>> {
        self.view
            .lifecycle(execution_id)?
            .map(|row| typed_lifecycle(&row))
            .transpose()
    }

    /// Checked execution-program JSON for an execution.
    pub fn program_json(&self, execution_id: Ulid) -> KataResult<Option<Vec<u8>>> {
        self.view.program_json(execution_id)
    }

    /// The boot target-pin sweep's claim for `execution_id`
    /// ([`TargetPinClaim`]).
    ///
    /// OWNED exactly when the execution has a non-terminal lifecycle, or has
    /// checked-program authority whose lifecycle is not yet classified, or when
    /// the store cannot be read (a read error is not evidence a pin is free).
    /// An owned claim carries the execution's recorded target — the one its
    /// stored invocation froze — when that record reads, so a pin a power loss
    /// tore can be re-derived from it; `None` otherwise, and the pins are kept
    /// as they stand. Every other execution — one whose resolution was refused
    /// or crashed before acceptance (no `programs` row), or a terminal one whose
    /// release left pins behind — is UNOWNED.
    #[must_use]
    pub fn target_pin_claim(&self, execution_id: Ulid) -> TargetPinClaim {
        let owned = match self.lifecycle(execution_id) {
            Ok(Some(lifecycle)) => !lifecycle.state.is_terminal(),
            Ok(None) => !matches!(self.program_json(execution_id), Ok(None)),
            Err(_) => true,
        };
        if !owned {
            return TargetPinClaim::Unowned;
        }
        TargetPinClaim::Owned(
            self.invocation(execution_id)
                .ok()
                .flatten()
                .and_then(|record| record.invocation.target)
                .map(Box::new),
        )
    }

    /// Decode only the stable evidence header of a stored program. Never upgrades
    /// or dispatches the payload.
    pub fn metadata(&self, execution_id: Ulid) -> KataResult<Option<ExecutionProgramMetadata>> {
        self.program_json(execution_id)?
            .map(|json| execution_program_metadata(&json, Some(execution_id)))
            .transpose()
    }

    /// Load and verify the immutable normalized invocation envelope.
    ///
    /// The BYTE-level checks (canonical JSON, `blake3(bytes) == admission_digest`)
    /// happen in the core view; this adds the typed decode and the column
    /// cross-check the typed envelope makes possible.
    pub fn invocation(&self, execution_id: Ulid) -> KataResult<Option<ExecutionInvocationRecord>> {
        let Some(stored) = self.view.invocation(execution_id)? else {
            return Ok(None);
        };
        if stored.invocation_json.len() > MAX_EXECUTION_INVOCATION_BYTES {
            return Err(KataError::Storage(format!(
                "execution {execution_id} invocation exceeds the {MAX_EXECUTION_INVOCATION_BYTES}-byte bound"
            )));
        }
        let invocation: ExecutionInvocation = serde_json::from_slice(&stored.invocation_json)
            .map_err(|error| {
                KataError::Storage(format!(
                    "decode invocation for execution {execution_id}: {error}"
                ))
            })?;
        if i64::from(invocation.schema_version) != stored.schema_version
            || invocation.kind != typed_kind(stored.kind)
        {
            return Err(KataError::Storage(format!(
                "execution {execution_id} invocation columns disagree with its typed envelope"
            )));
        }
        Ok(Some(ExecutionInvocationRecord {
            execution_id,
            invocation,
            admission_hash: stored.admission_digest.0.into_array(),
            created_at_ms: stored.created_at_ms,
        }))
    }

    /// Every non-terminal phase recovery must reconcile before readiness.
    pub fn recoverable_execution_ids(&self) -> KataResult<Vec<Ulid>> {
        self.view.recoverable_ids()
    }

    /// Every lifecycle-owned execution, for durable query discovery.
    pub fn lifecycle_execution_ids(&self) -> KataResult<Vec<Ulid>> {
        self.view.known_ids()
    }

    /// The retained programs that keep this binary off the directory — the
    /// compatibility membrane boot consults before any current deserialization,
    /// and the same set `kata upgrade` previews
    /// ([`blocking_incompatible_programs`]).
    pub fn incompatible_programs(&self) -> KataResult<Vec<IncompatibleExecutionProgram>> {
        blocking_incompatible_programs(self.view.active_program_json()?)
    }

    // -- test-support compatibility helpers ------------------------------

    /// Admit + authorize in one call, for tests written before admission became an
    /// explicit phase. Production callers must publish admission evidence between
    /// the two.
    #[cfg(any(test, feature = "test-support"))]
    #[doc(hidden)]
    pub fn put_current_program(
        &self,
        execution_id: Ulid,
        program: &ExecutionProgram,
    ) -> KataResult<()> {
        self.admit_current_execution(
            execution_id,
            program,
            &ExecutionInvocation::workflow(Vec::new()),
        )?;
        self.mark_running_after_admission(execution_id)
    }

    /// [`Self::put_current_program`] for an ISOLATED program: its invocation
    /// carries `target`, the frozen target every `worktree_isolated` admission
    /// must carry.
    #[cfg(any(test, feature = "test-support"))]
    #[doc(hidden)]
    pub fn put_current_program_with_target(
        &self,
        execution_id: Ulid,
        program: &ExecutionProgram,
        target: kata_types::target::ExecutionTarget,
    ) -> KataResult<()> {
        self.admit_current_execution(
            execution_id,
            program,
            &ExecutionInvocation::workflow(Vec::new()).with_target(Some(target)),
        )?;
        self.mark_running_after_admission(execution_id)
    }

    /// Persist opaque checked-program evidence of any schema with NO invocation and
    /// NO lifecycle. Fixture seam only (see
    /// [`OperationalDb::debug_put_raw_program`]).
    #[cfg(any(test, feature = "test-support"))]
    #[doc(hidden)]
    pub fn put_raw_legacy_evidence_json(
        &self,
        execution_id: Ulid,
        program_json: &[u8],
    ) -> KataResult<()> {
        self.db().debug_put_raw_program(execution_id, program_json)
    }

    /// Submit opaque program bytes as active authority. Fixture seam only.
    #[cfg(any(test, feature = "test-support"))]
    #[doc(hidden)]
    pub fn put_raw_active_program_json(
        &self,
        execution_id: Ulid,
        program_json: &[u8],
    ) -> KataResult<()> {
        crate::admission::unchecked_active_fixture_admission(program_json)
            .persist(self.db(), execution_id)?;
        Ok(())
    }

    /// Make lifecycle UPDATEs fail while reads keep working. Test seam only.
    #[cfg(any(test, feature = "test-support"))]
    #[doc(hidden)]
    pub fn reject_lifecycle_writes_for_test(&self) -> KataResult<()> {
        self.db().debug_reject_lifecycle_updates()
    }

    /// Make program INSERTs fail, so admission cannot persist. Test seam only.
    #[cfg(any(test, feature = "test-support"))]
    #[doc(hidden)]
    pub fn reject_program_writes_for_test(&self) -> KataResult<()> {
        self.db().debug_reject_program_inserts()
    }

    /// Delete an execution's nucleus rows. Test seam only.
    #[cfg(any(test, feature = "test-support"))]
    #[doc(hidden)]
    pub fn delete(&self, execution_id: Ulid) -> KataResult<()> {
        self.db().debug_delete_execution(execution_id)
    }

    /// Make lifecycle discovery UNREADABLE, proving every gate fails closed rather
    /// than treating an error as an absent row.
    #[cfg(any(test, feature = "test-support"))]
    #[doc(hidden)]
    pub fn drop_lifecycle_table_for_test(&self) -> KataResult<()> {
        self.db().debug_drop_lifecycle_table()
    }

    /// Latch and publish a terminal outcome in one call, for tests that do not
    /// exercise closeout ordering.
    #[cfg(any(test, feature = "test-support"))]
    #[doc(hidden)]
    pub fn mark_terminal(
        &self,
        execution_id: Ulid,
        outcome: ExecutionLifecycleState,
    ) -> KataResult<()> {
        self.begin_terminalization(
            execution_id,
            outcome,
            &ExecutionTerminalReason::new(
                "test_compat_terminal",
                "test compatibility terminal transition",
            ),
        )?;
        self.complete_cleanup(execution_id)?;
        self.finish_terminalization(execution_id)
    }
}

/// Map the typed workflow lifecycle state onto the operational vocabulary. The two
/// enums carry identical on-disk spellings by construction (the operational
/// `LifecycleState` docs pin that), so this is a total mapping, never a lossy one.
fn core_state(state: ExecutionLifecycleState) -> LifecycleState {
    match state {
        ExecutionLifecycleState::Admitting => LifecycleState::Admitting,
        ExecutionLifecycleState::Running => LifecycleState::Running,
        ExecutionLifecycleState::Terminalizing => LifecycleState::Terminalizing,
        ExecutionLifecycleState::Completed => LifecycleState::Completed,
        ExecutionLifecycleState::Failed => LifecycleState::Failed,
        ExecutionLifecycleState::Cancelled => LifecycleState::Cancelled,
        ExecutionLifecycleState::TimedOut => LifecycleState::TimedOut,
    }
}

fn typed_state(state: LifecycleState) -> ExecutionLifecycleState {
    match state {
        LifecycleState::Admitting => ExecutionLifecycleState::Admitting,
        LifecycleState::Running => ExecutionLifecycleState::Running,
        LifecycleState::Terminalizing => ExecutionLifecycleState::Terminalizing,
        LifecycleState::Completed => ExecutionLifecycleState::Completed,
        LifecycleState::Failed => ExecutionLifecycleState::Failed,
        LifecycleState::Cancelled => ExecutionLifecycleState::Cancelled,
        LifecycleState::TimedOut => ExecutionLifecycleState::TimedOut,
    }
}

fn typed_kind(kind: kata_core::operational::InvocationKind) -> ExecutionInvocationKind {
    match kind {
        kata_core::operational::InvocationKind::Workflow => ExecutionInvocationKind::Workflow,
        kata_core::operational::InvocationKind::DirectAgent => ExecutionInvocationKind::DirectAgent,
    }
}

/// Decode a durable lifecycle row into its typed form, re-verifying that a stored
/// terminal reason is CANONICAL JSON.
///
/// A reason that decodes but is not canonical means something wrote it around the typed
/// boundary, and a terminal reason is a recovery contract (the migration-replay
/// codes discriminate a checked-replay terminal), so it is refused rather than
/// accepted.
fn typed_lifecycle(row: &LifecycleRow) -> KataResult<ExecutionLifecycleRecord> {
    let execution_id = row.execution_id;
    let terminal_outcome = row.terminal_outcome.map(typed_state);
    if terminal_outcome.is_some_and(|outcome| !outcome.is_terminal()) {
        return Err(KataError::Storage(format!(
            "execution {execution_id} has non-terminal terminal_outcome"
        )));
    }
    let terminal_reason = row
        .terminal_reason_json
        .as_deref()
        .map(|bytes| {
            let reason: ExecutionTerminalReason =
                serde_json::from_slice(bytes).map_err(|error| {
                    KataError::Storage(format!(
                        "decode terminal reason for execution {execution_id}: {error}"
                    ))
                })?;
            let value = serde_json::to_value(&reason).map_err(|error| {
                KataError::Storage(format!(
                    "re-encode terminal reason for execution {execution_id}: {error}"
                ))
            })?;
            if canonicalize_args(&value) != bytes {
                return Err(KataError::Storage(format!(
                    "execution {execution_id} terminal reason is not canonical JSON"
                )));
            }
            Ok(reason)
        })
        .transpose()?;
    Ok(ExecutionLifecycleRecord {
        execution_id,
        state: typed_state(row.state),
        created_at_ms: row.created_at_ms,
        terminal_outcome,
        terminal_reason,
        terminal_started_at_ms: row.terminal_started_at_ms,
        finished_at_ms: row.finished_at_ms,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The two enums are mapped positionally by [`core_state`] / [`typed_state`],
    /// and BOTH are written to `execution_lifecycle.state`, whose CHECK constraint
    /// only accepts the operational spellings. A divergence would not be a compile
    /// error — it would be a runtime CHECK violation on the first terminalization.
    #[test]
    fn lifecycle_state_spellings_match_the_operational_vocabulary() {
        for state in [
            ExecutionLifecycleState::Admitting,
            ExecutionLifecycleState::Running,
            ExecutionLifecycleState::Terminalizing,
            ExecutionLifecycleState::Completed,
            ExecutionLifecycleState::Failed,
            ExecutionLifecycleState::Cancelled,
            ExecutionLifecycleState::TimedOut,
        ] {
            assert_eq!(
                state.as_str(),
                core_state(state).as_str(),
                "the typed and operational lifecycle vocabularies must agree"
            );
            assert_eq!(
                typed_state(core_state(state)),
                state,
                "the mapping round-trips"
            );
            assert_eq!(state.is_terminal(), core_state(state).is_terminal());
        }
    }

    #[test]
    fn invocation_kind_spellings_match_the_operational_vocabulary() {
        for (typed, core) in [
            (
                ExecutionInvocationKind::Workflow,
                kata_core::operational::InvocationKind::Workflow,
            ),
            (
                ExecutionInvocationKind::DirectAgent,
                kata_core::operational::InvocationKind::DirectAgent,
            ),
        ] {
            assert_eq!(typed.as_str(), core.as_str());
            assert_eq!(typed_kind(core), typed);
        }
    }
}
