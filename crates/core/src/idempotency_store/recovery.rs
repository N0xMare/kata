//! An expiring recovery hold: at most one live capture generation per store.
use super::{IdempotencyStore, KataError, KataResult, Ulid};
use kata_types::recovery::{
    MAX_RECOVERY_DATABASE_BYTES, MAX_RECOVERY_HOLD_MS, RecoveryRequest, WorkerRecoveryReceipt,
};
use parking_lot::Mutex;
use std::{
    io::Read,
    path::Path,
    sync::Arc,
    time::{Duration, Instant},
};

#[derive(Default)]
pub(super) struct RecoveryGate {
    held: Mutex<Option<(Ulid, Instant)>>,
}

pub struct IdempotencyRecoveryHold {
    store: Arc<IdempotencyStore>,
    receipt: WorkerRecoveryReceipt,
}
impl IdempotencyRecoveryHold {
    pub fn receipt(&self) -> &WorkerRecoveryReceipt {
        &self.receipt
    }
    pub fn is_live(&self) -> bool {
        self.store
            .recovery_gate
            .held
            .lock()
            .is_some_and(|(id, until)| id == self.receipt.generation_id && Instant::now() < until)
    }
    pub fn renew(&self, hold_ms: u64) -> KataResult<()> {
        validate_hold(hold_ms)?;
        let mut held = self.store.recovery_gate.held.lock();
        match *held {
            Some((id, until)) if id == self.receipt.generation_id && Instant::now() < until => {
                *held = Some((id, Instant::now() + Duration::from_millis(hold_ms)));
                Ok(())
            }
            _ => Err(refusal("recovery hold expired")),
        }
    }
}
impl Drop for IdempotencyRecoveryHold {
    fn drop(&mut self) {
        let mut held = self.store.recovery_gate.held.lock();
        if held.is_some_and(|(id, _)| id == self.receipt.generation_id) {
            *held = None;
        }
    }
}
fn refusal(message: &str) -> KataError {
    KataError::Storage(message.into())
}
fn validate_hold(ms: u64) -> KataResult<()> {
    if ms == 0 || ms > MAX_RECOVERY_HOLD_MS {
        return Err(refusal("invalid recovery hold duration"));
    }
    Ok(())
}
impl IdempotencyStore {
    /// Caller owns an empty regular file in a private export directory. This
    /// never changes the live store's identity or installs exported authority.
    pub fn begin_recovery_capture(
        self: &Arc<Self>,
        request: &RecoveryRequest,
        destination: &Path,
        hold_ms: u64,
        max_bytes: u64,
    ) -> KataResult<IdempotencyRecoveryHold> {
        validate_hold(hold_ms)?;
        if !request.is_valid() {
            return Err(refusal("invalid recovery request identity"));
        }
        if max_bytes == 0 || max_bytes > MAX_RECOVERY_DATABASE_BYTES {
            return Err(refusal("invalid recovery byte bound"));
        }
        let metadata = std::fs::symlink_metadata(destination)
            .map_err(|e| refusal(&format!("recovery destination: {e}")))?;
        if !metadata.is_file() || metadata.len() != 0 {
            return Err(refusal(
                "recovery destination must be an empty private regular file",
            ));
        }
        let mut held = self.recovery_gate.held.lock();
        if held.is_some_and(|(_, until)| Instant::now() < until) {
            return Err(refusal("recovery capture already held"));
        }
        let conn = self.backed.conn.lock();
        if Self::read_membrane_identity(&conn)? != request.domain.membrane {
            return Err(refusal("recovery membrane mismatch"));
        }
        let pages: u64 = conn
            .query_row("PRAGMA page_count", [], |r| r.get(0))
            .map_err(|e| refusal(&e.to_string()))?;
        let page_size: u64 = conn
            .query_row("PRAGMA page_size", [], |r| r.get(0))
            .map_err(|e| refusal(&e.to_string()))?;
        if pages
            .checked_mul(page_size)
            .is_none_or(|bytes| bytes > max_bytes)
        {
            return Err(refusal("recovery database exceeds requested byte bound"));
        }
        let deadline = Instant::now() + Duration::from_millis(hold_ms);
        let interrupt = conn.get_interrupt_handle();
        let (done_tx, done_rx) = std::sync::mpsc::channel::<()>();
        let watchdog = std::thread::spawn(move || {
            if matches!(
                done_rx.recv_timeout(Duration::from_millis(hold_ms)),
                Err(std::sync::mpsc::RecvTimeoutError::Timeout)
            ) {
                interrupt.interrupt();
            }
        });
        let capture = conn.execute(
            "VACUUM INTO ?1",
            [destination
                .to_str()
                .ok_or_else(|| refusal("non-UTF8 recovery destination"))?],
        );
        let _ = done_tx.send(());
        let _ = watchdog.join();
        capture.map_err(|e| refusal(&format!("recovery SQLite capture: {e}")))?;
        let mut file = std::fs::File::open(destination).map_err(|e| refusal(&e.to_string()))?;
        file.sync_all().map_err(|e| refusal(&e.to_string()))?;
        let len = file.metadata().map_err(|e| refusal(&e.to_string()))?.len();
        if len > max_bytes {
            return Err(refusal("recovery export exceeds requested byte bound"));
        }
        let mut hash = blake3::Hasher::new();
        let mut buffer = vec![0; 64 * 1024];
        loop {
            if Instant::now() >= deadline {
                return Err(refusal("recovery capture deadline expired"));
            }
            let n = file
                .read(&mut buffer)
                .map_err(|e| refusal(&e.to_string()))?;
            if n == 0 {
                break;
            }
            hash.update(&buffer[..n]);
        }
        let generation_id = Ulid::new();
        *held = Some((generation_id, deadline));
        Ok(IdempotencyRecoveryHold {
            store: Arc::clone(self),
            receipt: WorkerRecoveryReceipt {
                artifact_id: request.artifact_id,
                request_nonce: request.request_nonce,
                domain: request.domain.clone(),
                generation_id,
                schema_version: super::IDEMPOTENCY_SCHEMA_VERSION,
                database_digest: hash.finalize().to_hex().to_string(),
                database_byte_len: len,
            },
        })
    }
}
