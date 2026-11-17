//! Domain-scoped recovery exchange over an already authenticated worker link.
use crate::identity::WorkerEffectDomain;
use serde::{Deserialize, Serialize};
use ulid::Ulid;

/// Every commit-bearing field of a pinned repository view has a distinct kind.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryReferenceKind {
    Head,
    Bookmark,
    Tag,
    RemoteBookmark,
    RemoteTag,
    GitRef,
    GitHead,
    Workspace,
    DurableCommit,
    DurableChange,
    DurableBookmark,
}

/// Conflict sides retain absent terms and multiplicity; neither side is dropped.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryReference {
    pub kind: RecoveryReferenceKind,
    /// Hash of the reference name, keeping source paths and secrets out of proofs.
    pub name_digest: String,
    pub remote_name_digest: Option<String>,
    pub tracked: Option<bool>,
    pub removes: Vec<Option<String>>,
    pub adds: Vec<Option<String>>,
}

/// Source reference evidence retained in a recovery proof. The sorted concrete
/// root set excludes jj's synthetic root; remote proof covers ancestry closure.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryReferenceSnapshot {
    pub operation_id: String,
    pub references: Vec<RecoveryReference>,
    pub required_commits: Vec<String>,
    pub resolved_changes: std::collections::BTreeMap<String, String>,
    pub reference_set_digest: String,
}

impl RecoveryReferenceSnapshot {
    /// Stable length-framed digest of all evidence fields except the digest itself.
    /// Shape and bound validation belong to the consuming recovery boundary.
    pub fn computed_digest(&self) -> String {
        fn field(hash: &mut blake3::Hasher, bytes: &[u8]) {
            hash.update(&(bytes.len() as u64).to_le_bytes());
            hash.update(bytes);
        }
        let mut hash = blake3::Hasher::new();
        hash.update(b"kata-recovery-reference-set-v1\0");
        field(&mut hash, self.operation_id.as_bytes());
        hash.update(&(self.references.len() as u64).to_le_bytes());
        for reference in &self.references {
            let kind = match reference.kind {
                RecoveryReferenceKind::Head => 0,
                RecoveryReferenceKind::Bookmark => 1,
                RecoveryReferenceKind::Tag => 2,
                RecoveryReferenceKind::RemoteBookmark => 3,
                RecoveryReferenceKind::RemoteTag => 4,
                RecoveryReferenceKind::GitRef => 5,
                RecoveryReferenceKind::GitHead => 6,
                RecoveryReferenceKind::Workspace => 7,
                RecoveryReferenceKind::DurableCommit => 8,
                RecoveryReferenceKind::DurableChange => 9,
                RecoveryReferenceKind::DurableBookmark => 10,
            };
            hash.update(&[kind]);
            field(&mut hash, reference.name_digest.as_bytes());
            field(
                &mut hash,
                reference
                    .remote_name_digest
                    .as_deref()
                    .unwrap_or("")
                    .as_bytes(),
            );
            hash.update(&[match reference.tracked {
                None => 0,
                Some(false) => 1,
                Some(true) => 2,
            }]);
            for side in [&reference.removes, &reference.adds] {
                hash.update(&(side.len() as u64).to_le_bytes());
                for term in side {
                    field(&mut hash, term.as_deref().unwrap_or("").as_bytes());
                }
            }
        }
        hash.update(&(self.required_commits.len() as u64).to_le_bytes());
        for commit in &self.required_commits {
            field(&mut hash, commit.as_bytes());
        }
        hash.update(&(self.resolved_changes.len() as u64).to_le_bytes());
        for (change, commit) in &self.resolved_changes {
            field(&mut hash, change.as_bytes());
            field(&mut hash, commit.as_bytes());
        }
        hash.finalize().to_hex().to_string()
    }
}

pub const MAX_RECOVERY_HOLD_MS: u64 = 60_000;
pub const MAX_RECOVERY_DATABASE_BYTES: u64 = 1024 * 1024 * 1024 * 1024;
pub const MAX_RECOVERY_CHUNK_BYTES: u32 = 256 * 1024;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryRequest {
    pub artifact_id: Ulid,
    pub request_nonce: Ulid,
    pub domain: WorkerEffectDomain,
}
impl RecoveryRequest {
    pub fn is_valid(&self) -> bool {
        !self.domain.source_main.is_empty()
            && self.domain.source_main.len() <= 255
            && self.artifact_id != Ulid::nil()
            && self.request_nonce != Ulid::nil()
            && self.domain.enrollment != Ulid::nil()
            && self.domain.membrane.0 != Ulid::nil()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
pub enum RecoveryCommand {
    Begin {
        request: RecoveryRequest,
        hold_ms: u64,
        max_bytes: u64,
    },
    Read {
        request: RecoveryRequest,
        generation_id: Ulid,
        offset: u64,
        max_bytes: u32,
    },
    Renew {
        request: RecoveryRequest,
        generation_id: Ulid,
        hold_ms: u64,
    },
    Release {
        request: RecoveryRequest,
        generation_id: Ulid,
    },
}
impl RecoveryCommand {
    pub fn request(&self) -> &RecoveryRequest {
        match self {
            Self::Begin { request, .. }
            | Self::Read { request, .. }
            | Self::Renew { request, .. }
            | Self::Release { request, .. } => request,
        }
    }
}

/// Main accepts this only after peer enrollment and request correlation checks.
/// The artifact's trust boundary carries that authenticated exchange to restore.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkerRecoveryReceipt {
    pub artifact_id: Ulid,
    pub request_nonce: Ulid,
    pub domain: WorkerEffectDomain,
    pub generation_id: Ulid,
    pub schema_version: u32,
    pub database_digest: String,
    pub database_byte_len: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryRefusal {
    Unbound,
    WrongDomain,
    Busy,
    InvalidBounds,
    StaleGeneration,
    Expired,
    InvalidOffset,
    CaptureFailed,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "snake_case", deny_unknown_fields)]
pub enum RecoveryReply {
    Ready {
        receipt: WorkerRecoveryReceipt,
    },
    Chunk {
        request: RecoveryRequest,
        generation_id: Ulid,
        offset: u64,
        bytes: Vec<u8>,
    },
    Renewed {
        request: RecoveryRequest,
        generation_id: Ulid,
    },
    Released {
        request: RecoveryRequest,
        generation_id: Ulid,
    },
    Refused {
        request: RecoveryRequest,
        reason: RecoveryRefusal,
    },
}
