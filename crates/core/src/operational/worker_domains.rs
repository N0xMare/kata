//! Retained worker membrane enrollments and immutable physical-dispatch bindings.

use kata_types::error::{KataError, KataResult};
use kata_types::identity::{WorkerEffectDomain, WorkerMembraneId};
use rusqlite::{OptionalExtension, params};
use ulid::Ulid;

use super::OperationalDb;

fn storage(error: rusqlite::Error) -> KataError {
    KataError::Storage(format!("worker effect domain: {error}"))
}

fn decode_id(bytes: Vec<u8>) -> KataResult<Ulid> {
    let bytes: [u8; 16] = bytes
        .try_into()
        .map_err(|_| KataError::Storage("worker domain identity must be 16 bytes".into()))?;
    if bytes == [0; 16] {
        return Err(KataError::Storage("worker domain identity is nil".into()));
    }
    Ok(Ulid::from_bytes(bytes))
}

impl OperationalDb {
    /// The recovery worker census: every enrolled worker effect domain.
    ///
    /// Includes disconnected enrollments, even when no claim currently names
    /// them: only an authenticated worker inventory can prove their store empty.
    /// Worker-reported retained entries are a separate authenticated operand,
    /// never inferred here.
    pub fn worker_recovery_domains(&self) -> KataResult<Vec<WorkerEffectDomain>> {
        let conn = self.writer.lock();
        let mut query = conn
            .prepare(
                "SELECT source_main, membrane_id, enrollment_id
                 FROM worker_effect_domains
                 ORDER BY source_main, membrane_id LIMIT 4097",
            )
            .map_err(storage)?;
        let rows = query
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                ))
            })
            .map_err(storage)?;
        let domains = rows
            .map(|row| {
                let (source_main, membrane, enrollment) = row.map_err(storage)?;
                Ok(WorkerEffectDomain {
                    source_main,
                    membrane: WorkerMembraneId(decode_id(membrane)?),
                    enrollment: decode_id(enrollment)?,
                })
            })
            .collect::<KataResult<Vec<_>>>()?;
        if domains.len() > 4096 {
            return Err(KataError::Validation(
                "worker recovery census exceeds the 4096-instance bound".into(),
            ));
        }
        Ok(domains)
    }

    /// Enroll a verified membrane before making its connection dispatchable.
    /// Reconnects converge. Disconnection never deletes the retained census.
    pub fn enroll_worker_domain(
        &self,
        source_main: &str,
        membrane: WorkerMembraneId,
    ) -> KataResult<WorkerEffectDomain> {
        if source_main.is_empty() || source_main.len() > 128 || membrane.0 == Ulid::nil() {
            return Err(KataError::Validation(
                "invalid source main or worker membrane identity".into(),
            ));
        }
        self.in_writer_txn(|tx| {
            let existing: Option<Vec<u8>> = tx.query_row(
                "SELECT enrollment_id FROM worker_effect_domains WHERE source_main = ?1 AND membrane_id = ?2",
                params![source_main, membrane.0.to_bytes().as_slice()], |row| row.get(0))
                .optional().map_err(storage)?;
            let enrollment = if let Some(bytes) = existing {
                decode_id(bytes)?
            } else {
                let enrollment = Ulid::new();
                tx.execute("INSERT INTO worker_effect_domains(source_main, membrane_id, enrollment_id) VALUES(?1, ?2, ?3)",
                    params![source_main, membrane.0.to_bytes().as_slice(), enrollment.to_bytes().as_slice()]).map_err(storage)?;
                enrollment
            };
            Ok(WorkerEffectDomain { source_main: source_main.to_owned(), membrane, enrollment })
        })
    }

    /// Complete durable census, including disconnected and replaced membranes.
    pub fn worker_effect_domains(&self) -> KataResult<Vec<WorkerEffectDomain>> {
        let conn = self.writer.lock();
        let mut query = conn.prepare("SELECT source_main, membrane_id, enrollment_id FROM worker_effect_domains ORDER BY source_main, membrane_id LIMIT 4097").map_err(storage)?;
        let domains = query
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                ))
            })
            .map_err(storage)?
            .map(|row| {
                let (source_main, membrane, enrollment) = row.map_err(storage)?;
                Ok(WorkerEffectDomain {
                    source_main,
                    membrane: WorkerMembraneId(decode_id(membrane)?),
                    enrollment: decode_id(enrollment)?,
                })
            })
            .collect::<KataResult<Vec<_>>>()?;
        if domains.len() > 4096 {
            return Err(KataError::Validation(
                "worker domain census exceeds the 4096-instance capture bound".into(),
            ));
        }
        Ok(domains)
    }

    /// Read the immutable receiver binding for a dispatch generation.
    #[cfg(any(test, feature = "test-support"))]
    pub fn worker_dispatch_domain(
        &self,
        attempt: Ulid,
        epoch: i64,
    ) -> KataResult<Option<WorkerEffectDomain>> {
        let conn = self.writer.lock();
        let row: Option<(String, Vec<u8>, Vec<u8>)> = conn.query_row(
            "SELECT d.source_main, d.membrane_id, d.enrollment_id FROM worker_dispatch_domains b JOIN worker_effect_domains d ON d.enrollment_id = b.enrollment_id WHERE b.attempt_id = ?1 AND b.lease_epoch = ?2",
            params![attempt.to_bytes().as_slice(), epoch], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))
            .optional().map_err(storage)?;
        row.map(|(source_main, membrane, enrollment)| {
            Ok(WorkerEffectDomain {
                source_main,
                membrane: WorkerMembraneId(decode_id(membrane)?),
                enrollment: decode_id(enrollment)?,
            })
        })
        .transpose()
    }
}

/// Runs inside the transaction allocating the physical dispatch generation.
pub(super) fn bind_dispatch(
    tx: &rusqlite::Transaction<'_>,
    attempt: Ulid,
    epoch: i64,
    worker_label: &str,
    domain: &WorkerEffectDomain,
) -> KataResult<()> {
    let registered: bool = tx.query_row("SELECT EXISTS(SELECT 1 FROM worker_effect_domains WHERE source_main = ?1 AND membrane_id = ?2 AND enrollment_id = ?3)",
                params![domain.source_main, domain.membrane.0.to_bytes().as_slice(), domain.enrollment.to_bytes().as_slice()], |row| row.get(0)).map_err(storage)?;
    let placed: bool = tx.query_row("SELECT EXISTS(SELECT 1 FROM attempts WHERE attempt_id = ?1 AND lease_epoch = ?2 AND worker_id = ?3)",
                params![attempt.to_bytes().as_slice(), epoch, worker_label], |row| row.get(0)).map_err(storage)?;
    if !registered || !placed {
        return Err(KataError::Validation(
            "worker dispatch domain does not match enrolled membrane and durable placement".into(),
        ));
    }
    tx.execute("INSERT OR IGNORE INTO worker_dispatch_domains(attempt_id, lease_epoch, enrollment_id, worker_label) VALUES(?1, ?2, ?3, ?4)",
                params![attempt.to_bytes().as_slice(), epoch, domain.enrollment.to_bytes().as_slice(), worker_label]).map_err(storage)?;
    let agrees: bool = tx.query_row("SELECT EXISTS(SELECT 1 FROM worker_dispatch_domains WHERE attempt_id = ?1 AND lease_epoch = ?2 AND enrollment_id = ?3 AND worker_label = ?4)",
                params![attempt.to_bytes().as_slice(), epoch, domain.enrollment.to_bytes().as_slice(), worker_label], |row| row.get(0)).map_err(storage)?;
    if !agrees {
        return Err(KataError::Validation(
            "worker dispatch domain is already bound to another membrane".into(),
        ));
    }
    Ok(())
}
