//! One domain-authenticated, expiring export session per worker connection.
use kata_core::{IdempotencyStore, idempotency_store::IdempotencyRecoveryHold};
use kata_types::{
    identity::WorkerEffectDomain,
    recovery::{
        MAX_RECOVERY_CHUNK_BYTES, MAX_RECOVERY_DATABASE_BYTES, MAX_RECOVERY_HOLD_MS,
        RecoveryCommand, RecoveryRefusal, RecoveryReply, RecoveryRequest,
    },
};
use std::{
    io::{Read, Seek, SeekFrom},
    sync::Arc,
};

pub(crate) struct RecoverySession {
    domain: Option<WorkerEffectDomain>,
    store: Option<Arc<IdempotencyStore>>,
    export: Option<Export>,
}
struct Export {
    hold: IdempotencyRecoveryHold,
    file: std::fs::File,
    _directory: tempfile::TempDir,
    request: RecoveryRequest,
    offset: u64,
}
impl RecoverySession {
    pub(crate) fn new(
        binding: (Option<WorkerEffectDomain>, Option<Arc<IdempotencyStore>>),
    ) -> Self {
        Self {
            domain: binding.0,
            store: binding.1,
            export: None,
        }
    }
    pub(crate) fn held(&mut self) -> bool {
        if self
            .export
            .as_ref()
            .is_some_and(|export| !export.hold.is_live())
        {
            self.export = None;
        }
        self.export.is_some()
    }
    pub(crate) async fn handle(&mut self, command: RecoveryCommand, busy: bool) -> RecoveryReply {
        let request = command.request().clone();
        let outcome = self.apply(command, busy).await;
        outcome.unwrap_or_else(|reason| RecoveryReply::Refused { request, reason })
    }
    async fn apply(
        &mut self,
        command: RecoveryCommand,
        busy: bool,
    ) -> Result<RecoveryReply, RecoveryRefusal> {
        if !command.request().is_valid() {
            return Err(RecoveryRefusal::InvalidBounds);
        }
        let domain = self.domain.as_ref().ok_or(RecoveryRefusal::Unbound)?;
        if command.request().domain != *domain {
            return Err(RecoveryRefusal::WrongDomain);
        }
        let store = self.store.as_ref().ok_or(RecoveryRefusal::Unbound)?;
        if store
            .membrane_id()
            .map_err(|_| RecoveryRefusal::CaptureFailed)?
            != domain.membrane
        {
            return Err(RecoveryRefusal::WrongDomain);
        }
        let store = Arc::clone(store);
        self.held();
        match command {
            RecoveryCommand::Begin {
                request,
                hold_ms,
                max_bytes,
            } => {
                if busy || self.export.is_some() {
                    return Err(RecoveryRefusal::Busy);
                }
                if hold_ms == 0
                    || hold_ms > MAX_RECOVERY_HOLD_MS
                    || max_bytes == 0
                    || max_bytes > MAX_RECOVERY_DATABASE_BYTES
                {
                    return Err(RecoveryRefusal::InvalidBounds);
                }
                let capture_request = request.clone();
                let export = tokio::task::spawn_blocking(move || {
                    let directory =
                        tempfile::tempdir().map_err(|_| RecoveryRefusal::CaptureFailed)?;
                    let path = directory.path().join("idempotency.db");
                    std::fs::OpenOptions::new()
                        .write(true)
                        .create_new(true)
                        .open(&path)
                        .map_err(|_| RecoveryRefusal::CaptureFailed)?;
                    let hold = store
                        .begin_recovery_capture(&capture_request, &path, hold_ms, max_bytes)
                        .map_err(|_| RecoveryRefusal::CaptureFailed)?;
                    let file =
                        std::fs::File::open(&path).map_err(|_| RecoveryRefusal::CaptureFailed)?;
                    let mut permissions = file
                        .metadata()
                        .map_err(|_| RecoveryRefusal::CaptureFailed)?
                        .permissions();
                    permissions.set_readonly(true);
                    file.set_permissions(permissions)
                        .map_err(|_| RecoveryRefusal::CaptureFailed)?;
                    Ok(Export {
                        hold,
                        file,
                        _directory: directory,
                        request: capture_request,
                        offset: 0,
                    })
                })
                .await
                .map_err(|_| RecoveryRefusal::CaptureFailed)??;
                let reply = RecoveryReply::Ready {
                    receipt: export.hold.receipt().clone(),
                };
                self.export = Some(export);
                Ok(reply)
            }
            other => {
                let (request, generation_id) = match &other {
                    RecoveryCommand::Read {
                        request,
                        generation_id,
                        ..
                    }
                    | RecoveryCommand::Renew {
                        request,
                        generation_id,
                        ..
                    }
                    | RecoveryCommand::Release {
                        request,
                        generation_id,
                    } => (request.clone(), *generation_id),
                    RecoveryCommand::Begin { .. } => unreachable!(),
                };
                let export = self.export.as_mut().ok_or(RecoveryRefusal::Expired)?;
                if export.request != request || export.hold.receipt().generation_id != generation_id
                {
                    return Err(RecoveryRefusal::StaleGeneration);
                }
                match other {
                    RecoveryCommand::Read {
                        offset, max_bytes, ..
                    } => {
                        if max_bytes == 0 || max_bytes > MAX_RECOVERY_CHUNK_BYTES {
                            return Err(RecoveryRefusal::InvalidBounds);
                        }
                        let len = export.hold.receipt().database_byte_len;
                        if offset != export.offset || offset >= len {
                            return Err(RecoveryRefusal::InvalidOffset);
                        }
                        let count = usize::try_from(u64::from(max_bytes).min(len - offset))
                            .map_err(|_| RecoveryRefusal::InvalidBounds)?;
                        let mut bytes = vec![0; count];
                        export
                            .file
                            .seek(SeekFrom::Start(offset))
                            .map_err(|_| RecoveryRefusal::CaptureFailed)?;
                        export
                            .file
                            .read_exact(&mut bytes)
                            .map_err(|_| RecoveryRefusal::CaptureFailed)?;
                        export.offset += count as u64;
                        Ok(RecoveryReply::Chunk {
                            request,
                            generation_id,
                            offset,
                            bytes,
                        })
                    }
                    RecoveryCommand::Renew { hold_ms, .. } => {
                        if hold_ms == 0 || hold_ms > MAX_RECOVERY_HOLD_MS {
                            return Err(RecoveryRefusal::InvalidBounds);
                        }
                        export
                            .hold
                            .renew(hold_ms)
                            .map_err(|_| RecoveryRefusal::Expired)?;
                        Ok(RecoveryReply::Renewed {
                            request,
                            generation_id,
                        })
                    }
                    RecoveryCommand::Release { .. } => {
                        self.export = None;
                        Ok(RecoveryReply::Released {
                            request,
                            generation_id,
                        })
                    }
                    RecoveryCommand::Begin { .. } => unreachable!(),
                }
            }
        }
    }
}
