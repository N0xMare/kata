//! Durable clone quarantine. Identity or fresh execution IDs cannot release it.
use super::OperationalDb;
use kata_types::error::{KataError, KataResult};
use rusqlite::{Connection, params};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use ulid::Ulid;

#[path = "imports_checkpoints.rs"]
mod checkpoints;
pub use checkpoints::{RecoverySleepPopulation, inspect_recovery_sleep_population};

fn storage(error: rusqlite::Error) -> KataError {
    KataError::Storage(format!("recovery import authority: {error}"))
}

pub(super) fn require_imports_reconciled(conn: &Connection) -> KataResult<()> {
    let pending: bool = conn
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM recovery_imports WHERE released_at_ms IS NULL)",
            [],
            |row| row.get(0),
        )
        .map_err(storage)?;
    if pending {
        return Err(KataError::Validation("clone/import quarantine blocks all execution claims, execution resume and schedule firing until explicit reconciliation and rebinding release every imported obligation".into()));
    }
    Ok(())
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ImportAuthority {
    pub artifact_id: Ulid,
    pub source_directory_id: String,
    pub target_directory_id: String,
    pub catalog_digest: String,
}

/// One non-terminal execution a clone import carried over, and whether an operator
/// decision has reconciled it. `key` is the execution id as lower-case hex.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ImportSubject {
    pub artifact_id: Ulid,
    pub key: String,
    pub reconciled: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ImportDecision {
    ExecutionResumeApproved,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImportSubjectDecision {
    pub subject_key: String,
    pub decision: ImportDecision,
    pub operator: String,
    pub reason: String,
}
/// A subject-bound operator authorization, not a machine proof that an external
/// side effect did or did not happen. Effect settlement remains independent.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImportDecisionPacket {
    pub artifact_id: Ulid,
    pub decisions: Vec<ImportSubjectDecision>,
}

impl ImportDecisionPacket {
    /// Preflight the complete selected continuation population before extraction.
    /// Attribution authorizes resume; it never proves checkpoint or effect safety.
    pub fn validate_execution_resume_set(
        &self,
        artifact_id: Ulid,
        executions: &[Ulid],
    ) -> KataResult<()> {
        use std::collections::BTreeSet;
        let refusal = || {
            KataError::Validation(
            "recovery decisions must authorize exactly the artifact's supported executions with bounded operator attribution".into(),
        )
        };
        if self.artifact_id != artifact_id || self.decisions.len() > 4096 {
            return Err(refusal());
        }
        let expected: BTreeSet<_> = executions
            .iter()
            .map(|id| format!("{:032x}", u128::from(*id)))
            .collect();
        if expected.len() != executions.len() || self.decisions.len() != expected.len() {
            return Err(refusal());
        }
        let mut actual = BTreeSet::new();
        for decision in &self.decisions {
            if decision.decision != ImportDecision::ExecutionResumeApproved
                || decision.operator.trim().is_empty()
                || decision.operator.len() > 256
                || decision.reason.trim().is_empty()
                || decision.reason.len() > 4096
                || !actual.insert(decision.subject_key.clone())
            {
                return Err(refusal());
            }
        }
        if actual != expected {
            return Err(refusal());
        }
        Ok(())
    }
}

/// Actual typed authority population, independently checked against its chain.
#[derive(Debug)]
pub struct RecoveryPopulation {
    pub nonterminal_executions: Vec<Ulid>,
    pub unsettled_attempts: Vec<Ulid>,
    /// Whether any schedule is installed. Recovery capture and clone import both refuse
    /// such a population.
    pub has_installed_schedules: bool,
}

/// Read-only, reusable for a WAL-aware live connection or an immutable capture.
/// Directory absence and an empty/nonterminal count alone are not integrity.
pub fn inspect_recovery_population(
    conn: &Connection,
    deadline: Instant,
) -> KataResult<RecoveryPopulation> {
    let _deadline = RecoveryReadDeadline::new(conn, deadline)?;
    super::projection::verify_watermark(conn)?;
    let mut foreign_keys = conn.prepare("PRAGMA foreign_key_check").map_err(storage)?;
    if foreign_keys
        .query([])
        .map_err(storage)?
        .next()
        .map_err(storage)?
        .is_some()
    {
        return Err(KataError::Validation(
            "recovery population has dangling authority rows".into(),
        ));
    }
    let mut population = RecoveryPopulation {
        nonterminal_executions: Vec::new(),
        unsettled_attempts: Vec::new(),
        has_installed_schedules: conn
            .query_row("SELECT EXISTS(SELECT 1 FROM schedules)", [], |row| {
                row.get(0)
            })
            .map_err(storage)?,
    };
    let mut query = conn.prepare("SELECT p.execution_id,l.state,i.execution_id FROM programs p LEFT JOIN execution_lifecycle l ON l.execution_id=p.execution_id LEFT JOIN invocations i ON i.execution_id=p.execution_id ORDER BY p.execution_id").map_err(storage)?;
    let mut rows = query.query([]).map_err(storage)?;
    while let Some(row) = rows.next().map_err(storage)? {
        recovery_deadline(deadline)?;
        let id = super::ulid_from_bytes(&row.get::<_, Vec<u8>>(0).map_err(storage)?)?;
        let state = row
            .get::<_, Option<String>>(1)
            .map_err(storage)?
            .ok_or_else(|| {
                KataError::Validation("recovery program lacks lifecycle authority".into())
            })?;
        if row.get::<_, Option<Vec<u8>>>(2).map_err(storage)?.is_none() {
            return Err(KataError::Validation(
                "recovery program lacks invocation authority".into(),
            ));
        }
        if let Some(mismatch) = super::projection::classify_nucleus_mismatch_at(conn, id)? {
            return Err(KataError::Validation(mismatch.detail));
        }
        if !super::LifecycleState::parse(&state)?.is_terminal() {
            population.nonterminal_executions.push(id);
        }
    }
    let mut query = conn.prepare("SELECT a.attempt_id,p.state FROM attempts a LEFT JOIN attempt_projection p ON p.execution_id=a.execution_id AND p.stage_id=a.stage_id AND p.attempt_ordinal=a.attempt_ordinal ORDER BY a.attempt_id").map_err(storage)?;
    let mut rows = query.query([]).map_err(storage)?;
    while let Some(row) = rows.next().map_err(storage)? {
        recovery_deadline(deadline)?;
        let id = super::ulid_from_bytes(&row.get::<_, Vec<u8>>(0).map_err(storage)?)?;
        let state = row
            .get::<_, Option<String>>(1)
            .map_err(storage)?
            .ok_or_else(|| {
                KataError::Validation("recovery attempt lacks lifecycle projection".into())
            })?;
        let state = super::AttemptLifecycle::from_state(&state)
            .ok_or_else(|| KataError::Validation("unknown recovery attempt state".into()))?;
        if state.custody() != super::AttemptCustody::Settled {
            population.unsettled_attempts.push(id);
        }
    }
    recovery_deadline(deadline)?;
    Ok(population)
}

fn recovery_deadline(deadline: Instant) -> KataResult<()> {
    if Instant::now() >= deadline {
        return Err(KataError::Validation(
            "recovery SQL deadline elapsed".into(),
        ));
    }
    Ok(())
}

/// Scoped interrupt ownership for recovery's private or mutex-exclusive reader.
/// Cancellation joins before that connection can service another caller. Like
/// replay-store export's watchdog, this uses SQLite's safe interrupt handle.
pub struct RecoveryReadDeadline<'a> {
    _connection: &'a Connection,
    cancel: std::sync::mpsc::Sender<()>,
    watchdog: Option<std::thread::JoinHandle<()>>,
}
impl<'a> RecoveryReadDeadline<'a> {
    pub fn new(connection: &'a Connection, deadline: Instant) -> KataResult<Self> {
        recovery_deadline(deadline)?;
        let interrupt = connection.get_interrupt_handle();
        let (cancel, done) = std::sync::mpsc::channel();
        let watchdog = std::thread::spawn(move || {
            if !matches!(
                done.recv_timeout(deadline.saturating_duration_since(Instant::now())),
                Err(std::sync::mpsc::RecvTimeoutError::Timeout)
            ) {
                return;
            }
            loop {
                // A one-shot interrupt delivered between statements would miss
                // a later VM. Once expired, interrupt until this scope cancels.
                interrupt.interrupt();
                if !matches!(
                    done.recv_timeout(Duration::from_millis(5)),
                    Err(std::sync::mpsc::RecvTimeoutError::Timeout)
                ) {
                    return;
                }
            }
        });
        Ok(Self {
            _connection: connection,
            cancel,
            watchdog: Some(watchdog),
        })
    }
}
impl Drop for RecoveryReadDeadline<'_> {
    fn drop(&mut self) {
        let _ = self.cancel.send(());
        if let Some(watchdog) = self.watchdog.take() {
            let _ = watchdog.join();
        }
    }
}

/// Trusted runtime seam, like backup's RecoveryVerifier. Implementations must
/// retain offline lifecycle/discovery/data-directory ownership for the entire
/// verification/release scope and inspect actual target config, repository,
/// workspace/checkpoint and identity bindings. An operator packet is not proof.
pub trait ImportTargetVerifier {
    fn verify_current_target(
        &self,
        data_dir: &Path,
        current_target_id: &str,
        authority: &ImportAuthority,
        subjects: &[ImportSubject],
    ) -> KataResult<()>;
}

/// An ephemeral, non-serializable proof. Only actual verification constructs it;
/// borrowing the verifier keeps its caller-owned fencing scope alive.
pub struct VerifiedImportReadiness<'a> {
    db: &'a OperationalDb,
    verifier: &'a dyn ImportTargetVerifier,
    data_dir: PathBuf,
    current_target_id: String,
    authority: ImportAuthority,
    deadline: Instant,
}

impl OperationalDb {
    #[cfg(any(test, feature = "test-support"))]
    pub fn pending_import_subjects(&self) -> KataResult<Vec<ImportSubject>> {
        Ok(self
            .current_import_subjects()?
            .into_iter()
            .filter(|subject| !subject.reconciled)
            .collect())
    }

    fn current_import_subjects(&self) -> KataResult<Vec<ImportSubject>> {
        let conn = self.writer.lock();
        let mut query = conn.prepare("SELECT i.artifact_id,lower(hex(l.execution_id)),s.decision_json IS NOT NULL FROM recovery_imports i CROSS JOIN execution_lifecycle l LEFT JOIN recovery_import_subjects s ON s.artifact_id=i.artifact_id AND s.subject_key=lower(hex(l.execution_id)) WHERE i.released_at_ms IS NULL AND l.state IN ('admitting','running','terminalizing') ORDER BY 1,2").map_err(storage)?;
        query
            .query_map([], |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, bool>(2)?,
                ))
            })
            .map_err(storage)?
            .map(|row| {
                let (id, key, reconciled) = row.map_err(storage)?;
                let bytes: [u8; 16] = id
                    .try_into()
                    .map_err(|_| KataError::Storage("invalid import artifact ID".into()))?;
                Ok(ImportSubject {
                    artifact_id: Ulid::from_bytes(bytes),
                    key,
                    reconciled,
                })
            })
            .collect()
    }

    pub fn apply_import_decisions(&self, packet: &ImportDecisionPacket) -> KataResult<()> {
        if packet.decisions.is_empty() || packet.decisions.len() > 4096 {
            return Err(KataError::Validation(
                "import decision packet must contain 1..=4096 decisions".into(),
            ));
        }
        if packet.decisions.iter().any(|item| {
            item.subject_key.is_empty()
                || item.subject_key.len() > 1024
                || item.operator.trim().is_empty()
                || item.operator.len() > 256
                || item.reason.trim().is_empty()
                || item.reason.len() > 4096
        }) {
            return Err(KataError::Validation(
                "import decisions require bounded subject, operator attribution and reason".into(),
            ));
        }
        self.in_writer_txn(|tx| {
            for decision in &packet.decisions {
                // This is an attributed operator assertion, not a probe of the
                // external world. Exact subject matching and the final effect
                // settlement guard remain separate obligations.
                let encoded = serde_json::to_string(decision).map_err(|error| KataError::Serialization(error.to_string()))?;
                if tx.execute("UPDATE recovery_import_subjects SET decision_json=?3 WHERE artifact_id=?1 AND subject_key=?2 AND decision_json IS NULL", params![packet.artifact_id.to_bytes().as_slice(), decision.subject_key, encoded]).map_err(storage)? != 1 { return Err(KataError::Validation("import subject absent, duplicated or already reconciled".into())); }
            }
            Ok(())
        })
    }
    /// The deliberately global refused set includes fresh execution IDs.
    pub fn require_imports_reconciled(&self) -> KataResult<()> {
        require_imports_reconciled(&self.writer.lock())
    }

    /// Called only by verified clone activation before publishing target identity.
    /// Subjects are enumerated from the copied authority, not supplied by caller.
    ///
    /// Refuses a population with an installed schedule: a cloned schedule would fire on
    /// the target as well as on the source, and no import decision reconciles one. The
    /// recovery capture refuses such a source first; this is the same refusal at the
    /// door that writes the quarantine.
    pub(crate) fn quarantine_verified_import(
        &self,
        authority: &ImportAuthority,
        deadline: Instant,
    ) -> KataResult<()> {
        if authority.artifact_id == Ulid::nil()
            || authority.source_directory_id.is_empty()
            || authority.target_directory_id.is_empty()
            || authority.source_directory_id == authority.target_directory_id
            || authority.catalog_digest.len() != 64
        {
            return Err(KataError::Validation(
                "invalid verified import identity binding".into(),
            ));
        }
        let population =
            self.with_read(|connection| inspect_recovery_population(connection, deadline))?;
        if population.has_installed_schedules {
            return Err(KataError::Validation(
                "clone import refuses a population with an installed schedule: a cloned schedule \
                 would fire on the target as well as on the source"
                    .into(),
            ));
        }
        self.in_writer_txn(|tx| {
            tx.execute("INSERT INTO recovery_imports(artifact_id,source_directory_id,target_directory_id,catalog_digest,released_at_ms) VALUES(?1,?2,?3,?4,NULL)",
                params![authority.artifact_id.to_bytes().as_slice(), authority.source_directory_id, authority.target_directory_id, authority.catalog_digest]).map_err(storage)?;
            tx.execute("INSERT INTO recovery_import_subjects(artifact_id,subject_key,decision_json) SELECT ?1,lower(hex(execution_id)),NULL FROM execution_lifecycle WHERE state IN ('admitting','running','terminalizing')",
                params![authority.artifact_id.to_bytes().as_slice()]).map_err(storage)?;
            Ok(())
        })
    }

    pub fn import_authorities(&self) -> KataResult<Vec<ImportAuthority>> {
        self.import_authorities_matching(false)
    }

    pub fn pending_import_authorities(&self) -> KataResult<Vec<ImportAuthority>> {
        self.import_authorities_matching(true)
    }

    fn import_authorities_matching(&self, pending_only: bool) -> KataResult<Vec<ImportAuthority>> {
        let conn = self.writer.lock();
        let mut query = conn.prepare("SELECT artifact_id,source_directory_id,target_directory_id,catalog_digest FROM recovery_imports WHERE (?1=0 OR released_at_ms IS NULL) ORDER BY artifact_id").map_err(storage)?;
        query
            .query_map([pending_only], |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                ))
            })
            .map_err(storage)?
            .map(|row| {
                let (id, source_directory_id, target_directory_id, catalog_digest) =
                    row.map_err(storage)?;
                let bytes: [u8; 16] = id
                    .try_into()
                    .map_err(|_| KataError::Storage("invalid import artifact ID".into()))?;
                Ok(ImportAuthority {
                    artifact_id: Ulid::from_bytes(bytes),
                    source_directory_id,
                    target_directory_id,
                    catalog_digest,
                })
            })
            .collect()
    }

    pub fn verify_import_readiness<'a>(
        &'a self,
        data_dir: &Path,
        current_target_id: &str,
        artifact_id: Ulid,
        deadline: Instant,
        verifier: &'a dyn ImportTargetVerifier,
    ) -> KataResult<VerifiedImportReadiness<'a>> {
        let canonical = data_dir
            .canonicalize()
            .map_err(|_| KataError::Validation("target directory unavailable".into()))?;
        let actual = self
            .path()
            .ok_or_else(|| {
                KataError::Validation("import readiness requires a file-backed authority".into())
            })?
            .canonicalize()
            .map_err(|_| KataError::Validation("target authority unavailable".into()))?;
        if actual != canonical.join("operational.db") {
            return Err(KataError::Validation(
                "target readiness names a different operational authority".into(),
            ));
        }
        self.with_read(|connection| inspect_recovery_population(connection, deadline))?;
        crate::store::backup::verify_import_evidence_before(
            &canonical,
            current_target_id,
            self,
            deadline,
        )?;
        let authority = self
            .import_authorities()?
            .into_iter()
            .find(|authority| authority.artifact_id == artifact_id)
            .ok_or_else(|| KataError::Validation("import authority not found".into()))?;
        let subjects: Vec<_> = self
            .current_import_subjects()?
            .into_iter()
            .filter(|subject| subject.artifact_id == artifact_id)
            .collect();
        verifier.verify_current_target(&canonical, current_target_id, &authority, &subjects)?;
        recovery_deadline(deadline)?;
        Ok(VerifiedImportReadiness {
            db: self,
            verifier,
            data_dir: canonical,
            current_target_id: current_target_id.into(),
            authority,
            deadline,
        })
    }

    /// Consume a fresh machine proof, then recheck actual obligations atomically.
    /// Earlier-target approvals never discharge this new target's verification.
    pub fn release_reconciled_import(&self, proof: VerifiedImportReadiness<'_>) -> KataResult<()> {
        if !std::ptr::eq(self, proof.db) {
            return Err(KataError::Validation(
                "import readiness belongs to another authority owner".into(),
            ));
        }
        let checked = self.verify_import_readiness(
            &proof.data_dir,
            &proof.current_target_id,
            proof.authority.artifact_id,
            proof.deadline,
            proof.verifier,
        )?;
        if checked.authority != proof.authority {
            return Err(KataError::Validation(
                "import authority changed after verification".into(),
            ));
        }
        let artifact_id = proof.authority.artifact_id;
        self.in_writer_txn(|tx| {
            recovery_deadline(proof.deadline)?;
            let incomplete: bool = tx.query_row("SELECT EXISTS(SELECT 1 FROM execution_lifecycle l WHERE l.state IN ('admitting','running','terminalizing') AND NOT EXISTS(SELECT 1 FROM recovery_import_subjects s WHERE s.artifact_id=?1 AND s.subject_key=lower(hex(l.execution_id)) AND s.decision_json IS NOT NULL))", params![artifact_id.to_bytes().as_slice()], |row| row.get(0)).map_err(storage)?;
            if incomplete { return Err(KataError::Validation("import release requires every subject decision".into())); }
            if tx.execute("UPDATE recovery_imports SET released_at_ms=?2 WHERE artifact_id=?1 AND released_at_ms IS NULL AND source_directory_id=?3 AND target_directory_id=?4 AND catalog_digest=?5", params![artifact_id.to_bytes().as_slice(), super::now_ms(), proof.authority.source_directory_id, proof.authority.target_directory_id, proof.authority.catalog_digest]).map_err(storage)? != 1 {
                return Err(KataError::Validation("unreleased import not found".into()));
            }
            Ok(())
        })
    }
}

#[cfg(test)]
#[path = "imports_tests.rs"]
mod tests;
