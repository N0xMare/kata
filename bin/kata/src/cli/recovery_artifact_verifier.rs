//! Shared source/restore verification: captured authority, retained reference
//! evidence, and a fresh remote object closure must agree independently.
use std::sync::Mutex;
use std::time::{Duration, Instant};

use kata_core::store::backup::{
    BackupManifest, CapturedRecoveryReferences, RecoveryVerifier, RemoteRecoveryProof,
};
use kata_types::recovery::RecoveryReferenceSnapshot;
use kata_types::{KataError, KataResult};
use kata_vcs::recovery_remote::{
    RecoveryRemoteLimits, RecoveryRemoteRequest, VerifiedRecoveryRepository,
    reacquire_recovery_repository,
};
use ulid::Ulid;

pub(super) struct ArtifactVerifier {
    remote_id: String,
    remote_url: String,
    deadline: Instant,
    repository: Mutex<Option<VerifiedRecoveryRepository>>,
}

fn refusal(message: impl std::fmt::Display) -> KataError {
    KataError::Storage(format!("runtime recovery verification: {message}"))
}

impl ArtifactVerifier {
    pub(super) fn new(remote_id: String, remote_url: String, deadline: Instant) -> Self {
        Self {
            remote_id,
            remote_url,
            deadline,
            repository: Mutex::new(None),
        }
    }

    fn acquire(
        &self,
        snapshot: &RecoveryReferenceSnapshot,
        artifact_id: Ulid,
    ) -> KataResult<VerifiedRecoveryRepository> {
        kata_vcs::jj::recovery_references::validate_recovery_reference_snapshot(snapshot)
            .map_err(refusal)?;
        let remaining = self
            .deadline
            .checked_duration_since(Instant::now())
            .filter(|time| !time.is_zero())
            .ok_or_else(|| refusal("capture deadline elapsed"))?;
        reacquire_recovery_repository(
            &RecoveryRemoteRequest {
                artifact_id,
                remote_id: self.remote_id.clone(),
                url: self.remote_url.clone(),
                required_commits: snapshot.required_commits.clone(),
                reference_set_digest: snapshot.reference_set_digest.clone(),
            },
            RecoveryRemoteLimits {
                timeout: remaining.min(Duration::from_secs(600)),
                max_storage_bytes: 16 * 1024 * 1024 * 1024,
                max_objects: 1_000_000,
                max_uncompressed_bytes: 64 * 1024 * 1024 * 1024,
                max_output_bytes: 128 * 1024 * 1024,
            },
        )
        .map_err(refusal)
    }

    pub(super) fn build_proof(
        &self,
        snapshot: &RecoveryReferenceSnapshot,
        artifact_id: Ulid,
    ) -> KataResult<RemoteRecoveryProof> {
        let repository = self.acquire(snapshot, artifact_id)?;
        let closure = repository.proof();
        let proof = RemoteRecoveryProof {
            artifact_id,
            remote_id: closure.remote_id.clone(),
            required_commits: closure.required_commits.clone(),
            reference_set_digest: closure.reference_set_digest.clone(),
            closure_digest: closure.closure_digest.clone(),
            reference_snapshot: snapshot.clone(),
        };
        *self
            .repository
            .lock()
            .map_err(|_| refusal("verified repository owner poisoned"))? = Some(repository);
        Ok(proof)
    }

    pub(super) fn take_repository(&self) -> KataResult<VerifiedRecoveryRepository> {
        self.repository
            .lock()
            .map_err(|_| refusal("verified repository owner poisoned"))?
            .take()
            .ok_or_else(|| refusal("no verified object repository is retained"))
    }
}

impl RecoveryVerifier for ArtifactVerifier {
    fn deadline(&self) -> Instant {
        self.deadline
    }

    fn verify_captured_references(
        &self,
        artifact: &std::path::Path,
        manifest: &BackupManifest,
    ) -> KataResult<CapturedRecoveryReferences> {
        let proof = kata_core::store::backup::read_remote_recovery_proof(artifact, manifest)?;
        if proof.remote_id != self.remote_id || manifest.artifact_id != Some(proof.artifact_id) {
            return Err(refusal(
                "configured remote or artifact identity differs from proof",
            ));
        }
        let census =
            super::recovery_references::census_captured(artifact, manifest, self.deadline)?;
        census.validate_snapshot(&proof.reference_snapshot)?;
        let cohort = super::recovery_references::recovery_cohort_captured(
            artifact,
            manifest,
            self.deadline,
        )?;
        cohort.verify_checkpoints(kata_core::store::backup::recovery_workspace_checkpoints(
            manifest,
        )?)?;
        // Fetch again from the configured remote. A previous capture-time proof
        // or the source's local object cache cannot authorize target activation.
        let repository = self.acquire(&proof.reference_snapshot, proof.artifact_id)?;
        let closure = repository.proof();
        let references = CapturedRecoveryReferences {
            remote_id: closure.remote_id.clone(),
            required_commits: closure.required_commits.clone(),
            reference_set_digest: closure.reference_set_digest.clone(),
            closure_digest: closure.closure_digest.clone(),
        };
        if references.required_commits != proof.required_commits
            || references.reference_set_digest != proof.reference_set_digest
            || references.closure_digest != proof.closure_digest
        {
            return Err(refusal(
                "captured references or remote closure differ from proof",
            ));
        }
        *self
            .repository
            .lock()
            .map_err(|_| refusal("verified repository owner poisoned"))? = Some(repository);
        Ok(references)
    }
}
