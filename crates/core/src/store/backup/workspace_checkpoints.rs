//! Artifact-bound reconstruction evidence, never new runtime authority.
use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use ulid::Ulid;

use super::{BackupManifest, KataError, KataResult, RecoveryTreatment};

pub const MAX_CHECKPOINT_ENTRIES: usize = 100_000;
pub const MAX_CHECKPOINT_BYTES: u64 = 16 * 1024 * 1024 * 1024;
const MAX_CHECKPOINT_SLEEPS: usize = 4096;
// File entries also have a CapturedAsset record. The allowance includes
// JSON escaping of quotes in the bounded path and duplicated member name.
pub(super) const MAX_CHECKPOINT_MANIFEST_BYTES: u64 =
    (MAX_CHECKPOINT_ENTRIES as u64) * 8192 + (MAX_CHECKPOINT_SLEEPS as u64) * 4096;

/// One durable sleep the captured execution is parked in: a MAIN-resolved attempt
/// in `awaiting_timer`, due at `wait_deadline_ms` (the attempt row's own column). The
/// restored data dir carries the authority; this entry is the evidence the restore
/// cross-checks it against.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoverySleepCheckpoint {
    pub attempt_id: Ulid,
    pub stage_id: String,
    pub attempt_ordinal: u32,
    pub lease_epoch: u64,
    pub wait_deadline_ms: i64,
    pub transition_seq: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryWorkspaceCheckpoint {
    pub execution_id: Ulid,
    pub program_hash: String,
    pub authority_head: u64,
    pub sleeps: Vec<RecoverySleepCheckpoint>,
    /// The actual registered working-copy commit; its parents are Git evidence.
    pub workspace_commit_id: String,
    pub candidate: RecoveryCheckpointTree,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryCheckpointTree {
    pub root_mode: u32,
    pub entries: Vec<RecoveryCheckpointEntry>,
    pub digest: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum RecoveryCheckpointEntry {
    Directory {
        path: String,
        mode: u32,
    },
    File {
        path: String,
        member: String,
        mode: u32,
    },
}

impl RecoveryCheckpointEntry {
    pub fn path(&self) -> &str {
        match self {
            Self::Directory { path, .. } | Self::File { path, .. } => path,
        }
    }
    pub fn mode(&self) -> u32 {
        match self {
            Self::Directory { mode, .. } | Self::File { mode, .. } => *mode,
        }
    }
}

pub(super) fn refused(reason: &str) -> KataError {
    KataError::Validation(format!("workspace checkpoint refused: {reason}"))
}

fn hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

pub(super) fn valid_path(path: &str) -> bool {
    !path.is_empty()
        && path.len() <= 1024
        && path.split('/').count() <= 64
        && !path
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte == b'\\')
        && path
            .split('/')
            .all(|part| !part.is_empty() && part != "." && part != "..")
}

pub(super) fn validate_checkpoint_tree_shape(tree: &RecoveryCheckpointTree) -> KataResult<()> {
    if tree.entries.len() > MAX_CHECKPOINT_ENTRIES
        || tree.root_mode & !0o777 != 0
        || tree.root_mode & 0o500 != 0o500
        || !hex(&tree.digest, 64)
    {
        return Err(refused("invalid tree bounds, root permissions or digest"));
    }
    let mut directories = BTreeSet::new();
    let mut previous: Option<&str> = None;
    for entry in &tree.entries {
        let path = entry.path();
        if !valid_path(path)
            || entry.mode() & !0o777 != 0
            || previous.is_some_and(|held| held >= path)
        {
            return Err(refused("invalid or unsorted tree entry"));
        }
        if let Some((parent, _)) = path.rsplit_once('/')
            && !directories.contains(parent)
        {
            return Err(refused("tree entry lacks its explicit directory parent"));
        }
        match entry {
            RecoveryCheckpointEntry::Directory { mode, .. } => {
                if mode & 0o500 != 0o500 {
                    return Err(refused("directory is not owner-readable and searchable"));
                }
                directories.insert(path);
            }
            RecoveryCheckpointEntry::File { member, mode, .. } => {
                if !valid_path(member) || mode & 0o400 == 0 {
                    return Err(refused("invalid file member or unreadable permissions"));
                }
            }
        }
        previous = Some(path);
    }
    Ok(())
}

pub(super) fn validate_checkpoint_catalog(
    checkpoints: &[RecoveryWorkspaceCheckpoint],
    commits: &[String],
) -> KataResult<BTreeSet<String>> {
    if checkpoints.len() > 4096 {
        return Err(refused("checkpoint population exceeds 4096"));
    }
    let mut previous = None;
    let mut members = BTreeSet::new();
    let mut entries = 0usize;
    let mut sleep_count = 0usize;
    for checkpoint in checkpoints {
        if checkpoint.execution_id == Ulid::nil()
            || previous.is_some_and(|held| held >= checkpoint.execution_id)
            || !hex(&checkpoint.program_hash, 64)
            || checkpoint.authority_head == 0
            || !hex(&checkpoint.workspace_commit_id, 40)
            || commits
                .binary_search(&checkpoint.workspace_commit_id)
                .is_err()
            || checkpoint.sleeps.is_empty()
            || checkpoint.sleeps.len() > 4096
        {
            return Err(refused("invalid checkpoint identity or authority binding"));
        }
        previous = Some(checkpoint.execution_id);
        sleep_count = sleep_count
            .checked_add(checkpoint.sleeps.len())
            .ok_or_else(|| refused("sleep population overflow"))?;
        if sleep_count > MAX_CHECKPOINT_SLEEPS {
            return Err(refused("checkpoint sleep population exceeds 4096"));
        }
        let mut attempts = BTreeSet::new();
        for sleep in &checkpoint.sleeps {
            if sleep.attempt_id == Ulid::nil()
                || sleep.stage_id.is_empty()
                || sleep.stage_id.len() > 1024
                || sleep.stage_id.bytes().any(|b| b.is_ascii_control())
                || sleep.wait_deadline_ms <= 0
                || sleep.transition_seq == 0
                || sleep.transition_seq > checkpoint.authority_head
                || !attempts.insert(sleep.attempt_id)
            {
                return Err(refused("invalid sleep checkpoint binding"));
            }
        }
        let tree = &checkpoint.candidate;
        validate_checkpoint_tree_shape(tree)?;
        entries = entries
            .checked_add(tree.entries.len())
            .ok_or_else(|| refused("entry overflow"))?;
        if entries > MAX_CHECKPOINT_ENTRIES {
            return Err(refused("checkpoint catalog exceeds 100000 entries"));
        }
        for entry in &tree.entries {
            if matches!(entry.path().split('/').next(), Some(".jj" | ".git")) {
                return Err(refused(
                    "candidate metadata cannot be imported as file content",
                ));
            }
            if let RecoveryCheckpointEntry::File { path, member, .. } = entry {
                let expected = format!(
                    "recovery/jj/checkpoints/{}/candidate/{path}",
                    checkpoint.execution_id
                );
                if member != &expected || !members.insert(member.clone()) {
                    return Err(refused(
                        "checkpoint member is outside its exact logical namespace",
                    ));
                }
            }
        }
    }
    Ok(members)
}

pub fn recovery_workspace_checkpoints(
    manifest: &BackupManifest,
) -> KataResult<&[RecoveryWorkspaceCheckpoint]> {
    manifest
        .recovery_assets
        .iter()
        .flatten()
        .find_map(|asset| {
            if asset.location == "vcs.jj_repo"
                && let RecoveryTreatment::ReacquireVerified { checkpoints, .. } = &asset.treatment
            {
                Some(checkpoints.as_slice())
            } else {
                None
            }
        })
        .ok_or_else(|| refused("missing checkpoint treatment"))
}

/// Membership in a Git closure is not evidence of which workspace owned a head.
/// Bind the selected commit to the original pinned workspace reference itself.
pub(super) fn validate_checkpoint_references(
    checkpoints: &[RecoveryWorkspaceCheckpoint],
    snapshot: &kata_types::recovery::RecoveryReferenceSnapshot,
) -> KataResult<()> {
    use kata_types::recovery::RecoveryReferenceKind;
    let mut workspaces = BTreeMap::new();
    for reference in &snapshot.references {
        if reference.kind == RecoveryReferenceKind::Workspace
            && workspaces
                .insert(reference.name_digest.as_str(), reference)
                .is_some()
        {
            return Err(refused("duplicate pinned workspace reference"));
        }
    }
    for checkpoint in checkpoints {
        let name = format!("agent-{}", checkpoint.execution_id);
        let name_digest = blake3::hash(name.as_bytes()).to_hex();
        let reference = workspaces
            .get(name_digest.as_str())
            .ok_or_else(|| refused("checkpoint lacks its pinned execution workspace reference"))?;
        if !reference.removes.is_empty()
            || reference.adds.len() != 1
            || reference.adds[0].as_deref() != Some(checkpoint.workspace_commit_id.as_str())
        {
            return Err(refused(
                "checkpoint commit differs from its pinned execution workspace head",
            ));
        }
    }
    Ok(())
}

pub(super) fn tree_digest_with_records(
    tree: &RecoveryCheckpointTree,
    records: &BTreeMap<String, (u64, String)>,
) -> KataResult<String> {
    let mut hash = blake3::Hasher::new();
    hash.update(b"kata-workspace-checkpoint-v1\0");
    hash.update(&tree.root_mode.to_le_bytes());
    for entry in &tree.entries {
        let encoded =
            serde_json::to_vec(entry).map_err(|_| refused("checkpoint encoding failed"))?;
        hash.update(&(encoded.len() as u64).to_le_bytes());
        hash.update(&encoded);
        if let RecoveryCheckpointEntry::File { member, .. } = entry {
            let (length, digest) = records
                .get(member)
                .ok_or_else(|| refused("checkpoint member lacks digest evidence"))?;
            if !hex(digest, 64) {
                return Err(refused("invalid member digest"));
            }
            hash.update(&length.to_le_bytes());
            hash.update(digest.as_bytes());
        }
    }
    Ok(hash.finalize().to_hex().to_string())
}

pub(super) fn checkpoint_tree_digest(
    members: &super::recovery_assets::MemberIndex<'_>,
    tree: &RecoveryCheckpointTree,
) -> KataResult<String> {
    let mut records = BTreeMap::new();
    let mut bytes = 0u64;
    for entry in &tree.entries {
        if let RecoveryCheckpointEntry::File { member, .. } = entry {
            let record = members.require(member)?;
            bytes = bytes
                .checked_add(record.byte_len)
                .ok_or_else(|| refused("byte overflow"))?;
            if bytes > MAX_CHECKPOINT_BYTES {
                return Err(refused("checkpoint exceeds 16 GiB"));
            }
            records.insert(
                member.clone(),
                (
                    record.byte_len,
                    record
                        .digest
                        .clone()
                        .ok_or_else(|| refused("missing digest"))?,
                ),
            );
        }
    }
    tree_digest_with_records(tree, &records)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn checkpoint() -> RecoveryWorkspaceCheckpoint {
        RecoveryWorkspaceCheckpoint {
            execution_id: Ulid::from(1u128),
            program_hash: "a".repeat(64),
            authority_head: 7,
            sleeps: vec![RecoverySleepCheckpoint {
                attempt_id: Ulid::from(2u128),
                stage_id: "pause".into(),
                attempt_ordinal: 0,
                lease_epoch: 0,
                wait_deadline_ms: 1234,
                transition_seq: 7,
            }],
            workspace_commit_id: "b".repeat(40),
            candidate: RecoveryCheckpointTree {
                root_mode: 0o755,
                entries: vec![],
                digest: "c".repeat(64),
            },
        }
    }

    #[test]
    fn checkpoint_catalog_requires_exact_commit_authority_and_unique_population() {
        let held = checkpoint();
        let commits = vec![held.workspace_commit_id.clone()];
        assert!(validate_checkpoint_catalog(std::slice::from_ref(&held), &commits).is_ok());
        assert!(validate_checkpoint_catalog(std::slice::from_ref(&held), &[]).is_err());
        assert!(validate_checkpoint_catalog(&[held.clone(), held.clone()], &commits).is_err());
        let mut ahead = held.clone();
        ahead.sleeps[0].transition_seq += 1;
        assert!(validate_checkpoint_catalog(&[ahead], &commits).is_err());
        let mut empty = held;
        empty.sleeps.clear();
        assert!(validate_checkpoint_catalog(&[empty], &commits).is_err());
    }

    #[test]
    fn checkpoint_head_binding_refuses_missing_duplicate_conflicted_and_wrong_references() {
        use kata_types::recovery::{
            RecoveryReference, RecoveryReferenceKind, RecoveryReferenceSnapshot,
        };
        let held = checkpoint();
        let reference = RecoveryReference {
            kind: RecoveryReferenceKind::Workspace,
            name_digest: blake3::hash(format!("agent-{}", held.execution_id).as_bytes())
                .to_hex()
                .to_string(),
            remote_name_digest: None,
            tracked: None,
            removes: vec![],
            adds: vec![Some(held.workspace_commit_id.clone())],
        };
        let mut snapshot = RecoveryReferenceSnapshot {
            operation_id: "fixture".into(),
            references: vec![reference.clone()],
            required_commits: vec![held.workspace_commit_id.clone()],
            resolved_changes: BTreeMap::new(),
            reference_set_digest: String::new(),
        };
        assert!(validate_checkpoint_references(std::slice::from_ref(&held), &snapshot).is_ok());
        snapshot.references.clear();
        assert!(validate_checkpoint_references(std::slice::from_ref(&held), &snapshot).is_err());
        snapshot.references = vec![reference.clone(), reference.clone()];
        assert!(validate_checkpoint_references(std::slice::from_ref(&held), &snapshot).is_err());
        snapshot.references = vec![reference];
        snapshot.references[0].removes.push(Some("d".repeat(40)));
        assert!(validate_checkpoint_references(std::slice::from_ref(&held), &snapshot).is_err());
        snapshot.references[0].removes.clear();
        snapshot.references[0].adds[0] = Some("d".repeat(40));
        assert!(validate_checkpoint_references(std::slice::from_ref(&held), &snapshot).is_err());
        snapshot.references[0].adds[0] = None;
        assert!(validate_checkpoint_references(std::slice::from_ref(&held), &snapshot).is_err());
    }

    #[test]
    fn checkpoint_catalog_refuses_provider_metadata_and_foreign_member_namespaces() {
        let mut held = checkpoint();
        let commits = vec![held.workspace_commit_id.clone()];
        for path in ["output.txt", ".jj", ".git", "../escape", "/absolute"] {
            held.candidate.entries = vec![RecoveryCheckpointEntry::File {
                path: path.into(),
                member: "recovery/jj/proof.json".into(),
                mode: 0o644,
            }];
            assert!(validate_checkpoint_catalog(std::slice::from_ref(&held), &commits).is_err());
        }
        held.candidate.entries = vec![RecoveryCheckpointEntry::File {
            path: "output.txt".into(),
            member: format!(
                "recovery/jj/checkpoints/{}/candidate/output.txt",
                held.execution_id
            ),
            mode: 0o644,
        }];
        assert_eq!(
            validate_checkpoint_catalog(&[held], &commits)
                .unwrap()
                .len(),
            1
        );
    }

    #[test]
    fn checkpoint_tree_requires_explicit_sorted_parents_and_supported_permissions() {
        let mut tree = checkpoint().candidate;
        tree.entries = vec![RecoveryCheckpointEntry::Directory {
            path: "a/b".into(),
            mode: 0o755,
        }];
        assert!(validate_checkpoint_tree_shape(&tree).is_err());
        tree.entries.insert(
            0,
            RecoveryCheckpointEntry::Directory {
                path: "a".into(),
                mode: 0o755,
            },
        );
        assert!(validate_checkpoint_tree_shape(&tree).is_ok());
        tree.entries.reverse();
        assert!(validate_checkpoint_tree_shape(&tree).is_err());
        tree.entries.clear();
        tree.root_mode = 0o4755;
        assert!(validate_checkpoint_tree_shape(&tree).is_err());
    }

    #[test]
    fn checkpoint_tree_seal_covers_empty_directories_modes_members_and_bytes() {
        let mut tree = checkpoint().candidate;
        let empty = tree_digest_with_records(&tree, &BTreeMap::new()).unwrap();
        tree.entries.push(RecoveryCheckpointEntry::Directory {
            path: "empty".into(),
            mode: 0o755,
        });
        let directory = tree_digest_with_records(&tree, &BTreeMap::new()).unwrap();
        assert_ne!(empty, directory);
        tree.root_mode = 0o700;
        assert_ne!(
            directory,
            tree_digest_with_records(&tree, &BTreeMap::new()).unwrap()
        );
        tree.entries.push(RecoveryCheckpointEntry::File {
            path: "file".into(),
            member: "member".into(),
            mode: 0o644,
        });
        assert!(tree_digest_with_records(&tree, &BTreeMap::new()).is_err());
        let mut records = BTreeMap::from([("member".into(), (3, "d".repeat(64)))]);
        let file = tree_digest_with_records(&tree, &records).unwrap();
        records.insert("member".into(), (4, "d".repeat(64)));
        assert_ne!(file, tree_digest_with_records(&tree, &records).unwrap());
        records.insert("member".into(), (3, "e".repeat(64)));
        assert_ne!(file, tree_digest_with_records(&tree, &records).unwrap());
    }

    #[test]
    fn checkpoint_manifest_allowance_covers_escaped_entry_and_asset_records() {
        let path = "\"".repeat(1024);
        let entry = RecoveryCheckpointEntry::File {
            path: path.clone(),
            member: path.clone(),
            mode: 0o777,
        };
        let record = super::super::CapturedAsset {
            name: path,
            tier: super::super::DurabilityTier::Durable,
            byte_len: MAX_CHECKPOINT_BYTES,
            digest: Some("f".repeat(64)),
        };
        let bytes = serde_json::to_vec_pretty(&(entry, record)).unwrap();
        assert!(bytes.len() < 8192, "{}", bytes.len());
        assert!(
            MAX_CHECKPOINT_MANIFEST_BYTES >= (MAX_CHECKPOINT_ENTRIES as u64) * (bytes.len() as u64)
        );
    }
}
