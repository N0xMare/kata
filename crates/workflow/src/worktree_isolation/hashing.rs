//! Content-addressing / hashing concern for the validation candidate binding:
//! its content hash and fingerprint, the per-path hashes they compose from, and
//! the low-level blake3 field helpers.
//!
//! Concern-split out of `worktree_isolation.rs` (behavior-preserving move).

use super::{ContentHash, Ulid};

#[derive(Debug, Clone)]
pub(super) struct CandidatePathHash {
    pub(super) path: String,
    pub(super) kind: &'static str,
    pub(super) digest: Option<ContentHash>,
}

pub(super) fn validation_candidate_content_hash(
    head_commit: Option<&str>,
    path_hashes: &[CandidatePathHash],
) -> ContentHash {
    let mut hasher = blake3::Hasher::new();
    hash_str(
        &mut hasher,
        "domain",
        "kata.validation_candidate.content.v1",
    );
    hash_opt_str(&mut hasher, "head_commit", head_commit);
    hash_usize(&mut hasher, "path_count", path_hashes.len());
    for path_hash in path_hashes {
        hash_str(&mut hasher, "path", &path_hash.path);
        hash_str(&mut hasher, "kind", path_hash.kind);
        hash_opt_hash(&mut hasher, "digest", path_hash.digest.as_ref());
    }
    ContentHash::new(*hasher.finalize().as_bytes())
}

pub(super) fn validation_candidate_fingerprint(
    execution_id: Ulid,
    backend: Option<&str>,
    head_commit: Option<&str>,
    content_hash: &ContentHash,
    changed_paths: &[String],
) -> ContentHash {
    let mut hasher = blake3::Hasher::new();
    hash_str(
        &mut hasher,
        "domain",
        "kata.validation_candidate.fingerprint.v1",
    );
    hash_str(&mut hasher, "execution_id", &execution_id.to_string());
    hash_opt_str(&mut hasher, "workspace_backend", backend);
    hash_opt_str(&mut hasher, "head_commit", head_commit);
    hash_hash(&mut hasher, "content_hash", content_hash);
    hash_usize(&mut hasher, "changed_path_count", changed_paths.len());
    for path in changed_paths {
        hash_str(&mut hasher, "changed_path", path);
    }
    ContentHash::new(*hasher.finalize().as_bytes())
}

fn hash_str(hasher: &mut blake3::Hasher, name: &str, value: &str) {
    hasher.update(name.as_bytes());
    hasher.update(&(value.len() as u64).to_le_bytes());
    hasher.update(value.as_bytes());
}

fn hash_opt_str(hasher: &mut blake3::Hasher, name: &str, value: Option<&str>) {
    if let Some(value) = value {
        hasher.update(name.as_bytes());
        hasher.update(&[1]);
        hash_str(hasher, "value", value);
    } else {
        hasher.update(name.as_bytes());
        hasher.update(&[0]);
    }
}

fn hash_hash(hasher: &mut blake3::Hasher, name: &str, value: &ContentHash) {
    hasher.update(name.as_bytes());
    hasher.update(value.as_bytes());
}

fn hash_opt_hash(hasher: &mut blake3::Hasher, name: &str, value: Option<&ContentHash>) {
    if let Some(value) = value {
        hasher.update(name.as_bytes());
        hasher.update(&[1]);
        hasher.update(value.as_bytes());
    } else {
        hasher.update(name.as_bytes());
        hasher.update(&[0]);
    }
}

fn hash_usize(hasher: &mut blake3::Hasher, name: &str, value: usize) {
    hasher.update(name.as_bytes());
    hasher.update(&(value as u64).to_le_bytes());
}
