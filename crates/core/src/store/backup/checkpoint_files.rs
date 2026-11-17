//! Bounded file evidence for an offline, caller-owned workspace generation.
//! Directory descriptors bind every traversal. This is not a filesystem snapshot:
//! the caller must exclude writers throughout capture and artifact publication.
use std::collections::BTreeMap;
use std::ffi::OsStr;
use std::io::{Read, Write};
use std::path::Path;
use std::time::Instant;

use super::workspace_checkpoints::{
    MAX_CHECKPOINT_BYTES, MAX_CHECKPOINT_ENTRIES, checkpoint_tree_digest, refused,
    tree_digest_with_records, valid_path, validate_checkpoint_tree_shape,
};
use super::{
    BackupManifest, KataResult, ProvenDir, RecoveryCheckpointEntry, RecoveryCheckpointTree,
    RecoveryMemberSource,
};

fn check(deadline: Instant) -> KataResult<()> {
    if Instant::now() >= deadline {
        return Err(refused("filesystem deadline expired"));
    }
    Ok(())
}

fn io_error(error: impl std::fmt::Display) -> super::KataError {
    refused(&format!("filesystem operation failed: {error}"))
}

#[cfg(unix)]
fn mode(dir: &ProvenDir) -> KataResult<u32> {
    no_attributes(&dir.fd)?;
    Ok(rustix::fs::fstat(&dir.fd).map_err(io_error)?.st_mode & 0o7777)
}

#[cfg(unix)]
fn no_attributes(fd: impl std::os::fd::AsFd) -> KataResult<()> {
    let mut buffer = [0u8; 1];
    match rustix::fs::flistxattr(fd, &mut buffer[..]) {
        Ok(0) => Ok(()),
        Ok(_) | Err(rustix::io::Errno::RANGE) => {
            Err(refused("extended attributes are unsupported"))
        }
        Err(error) => Err(io_error(error)),
    }
}

#[cfg(unix)]
fn names(dir: &ProvenDir, deadline: Instant) -> KataResult<Vec<String>> {
    let mut names = Vec::new();
    for entry in rustix::fs::Dir::read_from(&dir.fd).map_err(io_error)? {
        check(deadline)?;
        let entry = entry.map_err(io_error)?;
        let name = entry.file_name().to_str().map_err(io_error)?;
        if matches!(name, "." | "..") {
            continue;
        }
        if !valid_path(name) || name.contains('/') {
            return Err(refused("unsupported filename"));
        }
        names.push(name.to_owned());
        if names.len() > MAX_CHECKPOINT_ENTRIES {
            return Err(refused("directory entry bound exceeded"));
        }
    }
    names.sort();
    Ok(names)
}

fn hash_file(
    file: &mut std::fs::File,
    maximum: u64,
    deadline: Instant,
) -> KataResult<(u64, String)> {
    let mut hash = blake3::Hasher::new();
    let mut total = 0u64;
    let mut buffer = vec![0u8; 64 * 1024].into_boxed_slice();
    loop {
        check(deadline)?;
        let count = file.read(&mut buffer).map_err(io_error)?;
        if count == 0 {
            break;
        }
        total = total
            .checked_add(count as u64)
            .ok_or_else(|| refused("file size overflow"))?;
        if total > maximum {
            return Err(refused("checkpoint byte bound exceeded"));
        }
        hash.update(&buffer[..count]);
    }
    Ok((total, hash.finalize().to_hex().to_string()))
}

#[cfg(unix)]
struct Capture<'a> {
    prefix: &'a str,
    entries: Vec<RecoveryCheckpointEntry>,
    sources: Vec<RecoveryMemberSource>,
    records: BTreeMap<String, (u64, String)>,
    bytes: u64,
    deadline: Instant,
}

#[cfg(unix)]
impl Capture<'_> {
    fn walk(
        &mut self,
        dir: &ProvenDir,
        relative: &str,
        metadata: bool,
        depth: usize,
    ) -> KataResult<()> {
        use rustix::fs::{AtFlags, FileType};
        if depth > 64 {
            return Err(refused("checkpoint depth exceeds 64"));
        }
        for name in names(dir, self.deadline)? {
            if metadata && name == ".jj" {
                dir.open_child(OsStr::new(&name), "checkpoint", "target-owned jj metadata")?;
                continue;
            }
            if metadata && name == ".git" {
                return Err(refused("candidate contains unsupported Git metadata"));
            }
            let path = if relative.is_empty() {
                name.clone()
            } else {
                format!("{relative}/{name}")
            };
            if !valid_path(&path) || self.entries.len() >= MAX_CHECKPOINT_ENTRIES {
                return Err(refused("checkpoint path or entry bound exceeded"));
            }
            let stat = rustix::fs::statat(&dir.fd, name.as_str(), AtFlags::SYMLINK_NOFOLLOW)
                .map_err(io_error)?;
            match FileType::from_raw_mode(stat.st_mode) {
                FileType::Directory => {
                    let child =
                        dir.open_child(OsStr::new(&name), "checkpoint", "real directory")?;
                    self.entries.push(RecoveryCheckpointEntry::Directory {
                        path: path.clone(),
                        mode: mode(&child)?,
                    });
                    self.walk(&child, &path, false, depth + 1)?;
                }
                FileType::RegularFile => {
                    let (mut file, length) = dir.open_source_file(
                        OsStr::new(&name),
                        MAX_CHECKPOINT_BYTES - self.bytes,
                        "checkpoint",
                        "regular file",
                    )?;
                    let opened = rustix::fs::fstat(&file).map_err(io_error)?;
                    if opened.st_nlink != 1 {
                        return Err(refused("hard-linked files are unsupported"));
                    }
                    no_attributes(&file)?;
                    let record =
                        hash_file(&mut file, MAX_CHECKPOINT_BYTES - self.bytes, self.deadline)?;
                    let after = rustix::fs::fstat(&file).map_err(io_error)?;
                    if record.0 != length
                        || opened.st_size != after.st_size
                        || opened.st_mtime != after.st_mtime
                        || opened.st_mtime_nsec != after.st_mtime_nsec
                        || opened.st_ctime != after.st_ctime
                        || opened.st_ctime_nsec != after.st_ctime_nsec
                    {
                        return Err(refused("source changed while hashing"));
                    }
                    self.bytes += record.0;
                    let member = format!("{}/{path}", self.prefix);
                    self.entries.push(RecoveryCheckpointEntry::File {
                        path,
                        member: member.clone(),
                        mode: opened.st_mode & 0o7777,
                    });
                    self.sources.push(RecoveryMemberSource {
                        name: member.clone(),
                        source_path: dir.child_path(OsStr::new(&name)),
                    });
                    self.records.insert(member, record);
                }
                _ => return Err(refused("symlink or special file is not checkpointable")),
            }
        }
        Ok(())
    }
}

/// Capture file identities without writing or snapshotting the source workspace.
#[cfg(unix)]
pub fn capture_checkpoint_tree(
    root: &Path,
    member_prefix: &str,
    candidate_metadata: bool,
    deadline: Instant,
) -> KataResult<(RecoveryCheckpointTree, Vec<RecoveryMemberSource>)> {
    check(deadline)?;
    if !valid_path(member_prefix) {
        return Err(refused("invalid member prefix"));
    }
    let dir = ProvenDir::open(root, "checkpoint", "owned real root")?;
    let mut capture = Capture {
        prefix: member_prefix,
        entries: Vec::new(),
        sources: Vec::new(),
        records: BTreeMap::new(),
        bytes: 0,
        deadline,
    };
    capture.walk(&dir, "", candidate_metadata, 0)?;
    capture
        .entries
        .sort_by(|left, right| left.path().cmp(right.path()));
    let mut tree = RecoveryCheckpointTree {
        root_mode: mode(&dir)?,
        entries: capture.entries,
        digest: "0".repeat(64),
    };
    validate_checkpoint_tree_shape(&tree)?;
    tree.digest = tree_digest_with_records(&tree, &capture.records)?;
    Ok((tree, capture.sources))
}

/// Verify the declared tree against actual immutable artifact member bytes.
pub fn verify_checkpoint_tree(
    artifact: &Path,
    manifest: &BackupManifest,
    tree: &RecoveryCheckpointTree,
    deadline: Instant,
) -> KataResult<()> {
    check(deadline)?;
    validate_checkpoint_tree_shape(tree)?;
    let indexed = super::recovery_assets::MemberIndex::new(manifest)?;
    if checkpoint_tree_digest(&indexed, tree)? != tree.digest {
        return Err(refused("tree digest mismatch"));
    }
    for entry in &tree.entries {
        check(deadline)?;
        if entry.path().split('/').count() > 64 {
            return Err(refused("checkpoint depth exceeds 64"));
        }
        if let RecoveryCheckpointEntry::File { member, .. } = entry {
            let record = indexed.require(member)?;
            let (mut file, length) =
                super::recovery_assets::open_member(artifact, member, MAX_CHECKPOINT_BYTES)?;
            let (actual, digest) = hash_file(&mut file, record.byte_len, deadline)?;
            if length != record.byte_len
                || actual != record.byte_len
                || record.digest.as_deref() != Some(&digest)
            {
                return Err(refused("artifact file digest mismatch"));
            }
        }
    }
    Ok(())
}

#[cfg(unix)]
fn clear(
    dir: &ProvenDir,
    metadata: bool,
    deadline: Instant,
    count: &mut usize,
    depth: usize,
) -> KataResult<()> {
    use rustix::fs::{AtFlags, FileType};
    if depth > 64 {
        return Err(refused("target depth exceeds 64"));
    }
    for name in names(dir, deadline)? {
        if metadata && name == ".jj" {
            dir.open_child(OsStr::new(&name), "checkpoint", "target-owned jj metadata")?;
            continue;
        }
        if metadata && name == ".git" {
            return Err(refused("target contains Git metadata"));
        }
        *count += 1;
        if *count > MAX_CHECKPOINT_ENTRIES {
            return Err(refused("target entry bound exceeded"));
        }
        let stat = rustix::fs::statat(&dir.fd, name.as_str(), AtFlags::SYMLINK_NOFOLLOW)
            .map_err(io_error)?;
        let flags = match FileType::from_raw_mode(stat.st_mode) {
            FileType::Directory => {
                let child =
                    dir.open_child(OsStr::new(&name), "checkpoint", "real target directory")?;
                rustix::fs::fchmod(&child.fd, rustix::fs::Mode::from_raw_mode(0o700))
                    .map_err(io_error)?;
                clear(&child, false, deadline, count, depth + 1)?;
                AtFlags::REMOVEDIR
            }
            // A verified base commit may contain links that the checkpoint
            // deleted or replaced. Remove the link itself, never its referent.
            FileType::RegularFile | FileType::Symlink => AtFlags::empty(),
            _ => return Err(refused("target contains special file")),
        };
        rustix::fs::unlinkat(&dir.fd, name.as_str(), flags).map_err(io_error)?;
    }
    Ok(())
}

#[cfg(unix)]
fn parent(root: &ProvenDir, path: &str) -> KataResult<(ProvenDir, String)> {
    let mut dir = ProvenDir {
        display: root.display.clone(),
        fd: rustix::io::dup(&root.fd).map_err(io_error)?,
    };
    let mut parts = path.split('/').peekable();
    while let Some(part) = parts.next() {
        if parts.peek().is_none() {
            return Ok((dir, part.to_owned()));
        }
        dir = dir.open_child(OsStr::new(part), "checkpoint", "explicit parent directory")?;
    }
    Err(refused("empty path"))
}

/// Replace content only in a caller-owned, unpublished target; never remove its root.
#[cfg(unix)]
pub fn restore_checkpoint_tree(
    artifact: &Path,
    manifest: &BackupManifest,
    tree: &RecoveryCheckpointTree,
    target: &Path,
    candidate_metadata: bool,
    deadline: Instant,
) -> KataResult<()> {
    verify_checkpoint_tree(artifact, manifest, tree, deadline)?;
    let indexed = super::recovery_assets::MemberIndex::new(manifest)?;
    if candidate_metadata
        && tree
            .entries
            .iter()
            .any(|entry| matches!(entry.path().split('/').next(), Some(".jj" | ".git")))
    {
        return Err(refused("checkpoint contains candidate metadata"));
    }
    let root = ProvenDir::open(target, "checkpoint", "owned unpublished target")?;
    rustix::fs::fchmod(&root.fd, rustix::fs::Mode::from_raw_mode(0o700)).map_err(io_error)?;
    clear(&root, candidate_metadata, deadline, &mut 0, 0)?;
    for entry in &tree.entries {
        check(deadline)?;
        let (dir, name) = parent(&root, entry.path())?;
        match entry {
            RecoveryCheckpointEntry::Directory { .. } => {
                let child = dir.child(OsStr::new(&name), "checkpoint", "owned target directory")?;
                rustix::fs::fchmod(&child.fd, rustix::fs::Mode::from_raw_mode(0o700))
                    .map_err(io_error)?;
            }
            RecoveryCheckpointEntry::File { member, mode, .. } => {
                let (mut input, _) =
                    super::recovery_assets::open_member(artifact, member, MAX_CHECKPOINT_BYTES)?;
                let maximum = indexed.require(member)?.byte_len;
                let mut output =
                    dir.create_owned_file(OsStr::new(&name), "checkpoint", "owned target file")?;
                let mut buffer = vec![0u8; 64 * 1024].into_boxed_slice();
                let mut total = 0u64;
                loop {
                    check(deadline)?;
                    let count = input.read(&mut buffer).map_err(io_error)?;
                    if count == 0 {
                        break;
                    }
                    total += count as u64;
                    if total > maximum {
                        return Err(refused("copy byte bound exceeded"));
                    }
                    output.write_all(&buffer[..count]).map_err(io_error)?;
                }
                rustix::fs::fchmod(&output, rustix::fs::Mode::from_raw_mode(*mode))
                    .map_err(io_error)?;
                output.sync_all().map_err(io_error)?;
            }
        }
    }
    for entry in tree.entries.iter().rev() {
        check(deadline)?;
        if let RecoveryCheckpointEntry::Directory { path, mode } = entry {
            let (dir, name) = parent(&root, path)?;
            let child = dir.open_child(OsStr::new(&name), "checkpoint", "target directory")?;
            rustix::fs::fchmod(&child.fd, rustix::fs::Mode::from_raw_mode(*mode))
                .map_err(io_error)?;
            child.sync("checkpoint")?;
        }
    }
    rustix::fs::fchmod(&root.fd, rustix::fs::Mode::from_raw_mode(tree.root_mode))
        .map_err(io_error)?;
    root.sync("checkpoint")?;
    verify_materialized_checkpoint_tree(target, tree, manifest, candidate_metadata, deadline)
}

/// Independent disk recensus detects omissions, extras, changed modes and changed bytes.
#[cfg(unix)]
pub fn verify_materialized_checkpoint_tree(
    target: &Path,
    tree: &RecoveryCheckpointTree,
    manifest: &BackupManifest,
    candidate_metadata: bool,
    deadline: Instant,
) -> KataResult<()> {
    validate_checkpoint_tree_shape(tree)?;
    let indexed = super::recovery_assets::MemberIndex::new(manifest)?;
    let expected: BTreeMap<_, _> = tree
        .entries
        .iter()
        .map(|entry| (entry.path(), entry))
        .collect();
    let (mut actual, _) =
        capture_checkpoint_tree(target, "verification", candidate_metadata, deadline)?;
    for entry in &mut actual.entries {
        if let RecoveryCheckpointEntry::File { path, member, .. } = entry
            && let Some(RecoveryCheckpointEntry::File { member: wanted, .. }) =
                expected.get(path.as_str())
        {
            member.clone_from(wanted);
        }
    }
    if actual.root_mode != tree.root_mode || actual.entries != tree.entries {
        return Err(refused("materialized tree shape or permissions mismatch"));
    }
    let dir = ProvenDir::open(target, "checkpoint", "owned target")?;
    let mut records = BTreeMap::new();
    for entry in &tree.entries {
        if let RecoveryCheckpointEntry::File { path, member, .. } = entry {
            let (parent, name) = parent(&dir, path)?;
            let (mut file, _) = parent.open_source_file(
                OsStr::new(&name),
                MAX_CHECKPOINT_BYTES,
                "checkpoint",
                "materialized file",
            )?;
            records.insert(
                member.clone(),
                hash_file(&mut file, MAX_CHECKPOINT_BYTES, deadline)?,
            );
        }
    }
    if tree_digest_with_records(tree, &records)? != tree.digest
        || checkpoint_tree_digest(&indexed, tree)? != tree.digest
    {
        return Err(refused("materialized tree bytes mismatch"));
    }
    Ok(())
}

#[cfg(all(test, unix))]
#[path = "checkpoint_files_tests.rs"]
mod tests;
