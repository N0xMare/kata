//! Read-only recovery census of the current jj view, under its publication lock.
//!
//! The caller also holds Kata's main-data-directory ownership fence. This lock
//! excludes jj operation publication; it does not exclude manual Git writes or
//! working-file edits. Those need a complementary caller-owned source fence.
//! No workspace adoption, index building, working-copy snapshot or import runs.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::io::Read as _;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use jj_lib::backend::{Backend as _, CommitId};
use jj_lib::config::StackedConfig;
use jj_lib::git_backend::GitBackend;
use jj_lib::object_id::ObjectId as _;
use jj_lib::op_store::{RefTarget, RemoteRefState};
use jj_lib::repo::StoreFactories;
use jj_lib::settings::UserSettings;
use jj_lib::stacked_table::{TableSegment as _, TableStore};
use jj_lib::workspace::{Workspace, default_working_copy_factories};
use kata_types::recovery::{RecoveryReference, RecoveryReferenceKind, RecoveryReferenceSnapshot};
use serde::{Deserialize, Serialize};

const MAX_COMMITS: usize = 100_000;
const MAX_METADATA_BYTES: usize = 1024 * 1024;

/// A census refusal never includes source paths, credentials or backend errors.
#[derive(Debug, thiserror::Error)]
pub enum RecoveryReferenceError {
    #[error("recovery reference deadline elapsed")]
    Deadline,
    #[error("recovery reference census refused: {0}")]
    Refused(&'static str),
    #[error("recovery reference I/O failed")]
    Io(#[from] std::io::Error),
}

/// A durable runtime reference whose exact target must exist in the pinned view.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryNamedReference {
    LocalBookmark(String),
}

/// Source-only eligibility facts from the exact pinned view, not proof metadata.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecoveryWorkspaceCensus {
    pub retained_execution_workspaces: bool,
    execution_workspaces:
        Result<Vec<super::recovery_workspaces::RecoveryExecutionWorkspace>, &'static str>,
}

impl RecoveryWorkspaceCensus {
    /// Exact local execution roots from the pinned view. Unsupported or missing
    /// workspace metadata refuses checkpoint export; no source paths serialize.
    pub fn execution_workspaces(
        &self,
    ) -> Result<&[super::recovery_workspaces::RecoveryExecutionWorkspace], RecoveryReferenceError>
    {
        self.execution_workspaces
            .as_deref()
            .map_err(|reason| refusal(reason))
    }
}

fn is_execution_workspace(name: &str) -> bool {
    if let Some(id) = name.strip_prefix("agent-") {
        return id.parse::<ulid::Ulid>().is_ok();
    }
    name.strip_prefix("fork-").is_some_and(|rest| {
        rest.get(..26)
            .is_some_and(|id| id.parse::<ulid::Ulid>().is_ok())
            && rest.get(26..27) == Some("-")
            && rest.len() > 27
    })
}

fn check_deadline(deadline: Instant) -> Result<(), RecoveryReferenceError> {
    if Instant::now() >= deadline {
        return Err(RecoveryReferenceError::Deadline);
    }
    Ok(())
}

fn refusal(reason: &'static str) -> RecoveryReferenceError {
    RecoveryReferenceError::Refused(reason)
}

/// Validate retained proof evidence independently of the source jj loader.
pub fn validate_recovery_reference_snapshot(
    snapshot: &RecoveryReferenceSnapshot,
) -> Result<(), RecoveryReferenceError> {
    validate_hex(&snapshot.operation_id, 128)?;
    validate_hex(&snapshot.reference_set_digest, 64)?;
    if snapshot.references.is_empty()
        || !snapshot.references.windows(2).all(|pair| pair[0] < pair[1])
        || snapshot.required_commits.len() > MAX_COMMITS
    {
        return Err(refusal("invalid reference ordering or population"));
    }
    let mut roots = BTreeSet::new();
    let mut changes = BTreeMap::new();
    let mut identities = BTreeSet::new();
    let mut bytes = 0usize;
    for reference in &snapshot.references {
        validate_hex(&reference.name_digest, 64)?;
        if reference.kind != RecoveryReferenceKind::Head
            && !identities.insert((
                reference.kind.clone(),
                &reference.name_digest,
                &reference.remote_name_digest,
            ))
        {
            return Err(refusal("duplicate named reference identity"));
        }
        if matches!(
            reference.kind,
            RecoveryReferenceKind::Head | RecoveryReferenceKind::GitHead
        ) && reference.name_digest != blake3::hash(b"").to_hex().as_str()
        {
            return Err(refusal("invalid unnamed reference identity"));
        }
        let remote = matches!(
            reference.kind,
            RecoveryReferenceKind::RemoteBookmark | RecoveryReferenceKind::RemoteTag
        );
        if remote != reference.remote_name_digest.is_some() || remote != reference.tracked.is_some()
        {
            return Err(refusal("invalid remote reference shape"));
        }
        if let Some(name) = &reference.remote_name_digest {
            validate_hex(name, 64)?;
        }
        bytes = bytes.saturating_add(1024).saturating_add(
            reference
                .removes
                .len()
                .saturating_add(reference.adds.len())
                .saturating_mul(96),
        );
        if bytes > MAX_METADATA_BYTES
            || reference.adds.len() != reference.removes.len().saturating_add(1)
            || !reference.adds.windows(2).all(|pair| pair[0] <= pair[1])
            || !reference.removes.windows(2).all(|pair| pair[0] <= pair[1])
        {
            return Err(refusal("invalid or oversized conflict shape"));
        }
        for commit in reference.adds.iter().chain(&reference.removes).flatten() {
            validate_hex(commit, 40)?;
            if !commit.bytes().all(|byte| byte == b'0') {
                roots.insert(commit.clone());
            }
        }
        if matches!(
            reference.kind,
            RecoveryReferenceKind::Head
                | RecoveryReferenceKind::Workspace
                | RecoveryReferenceKind::DurableCommit
                | RecoveryReferenceKind::DurableChange
        ) && (!reference.removes.is_empty() || reference.adds[0].is_none())
        {
            return Err(refusal("invalid concrete reference shape"));
        }
        if reference.kind == RecoveryReferenceKind::DurableCommit {
            let commit = reference.adds[0]
                .as_ref()
                .ok_or_else(|| refusal("missing durable commit"))?;
            if reference.name_digest != blake3::hash(commit.as_bytes()).to_hex().as_str() {
                return Err(refusal("durable commit name mismatch"));
            }
        }
        if reference.kind == RecoveryReferenceKind::DurableChange {
            changes.insert(reference.name_digest.clone(), reference.adds[0].clone());
        }
        if reference.kind == RecoveryReferenceKind::DurableBookmark
            && !snapshot.references.iter().any(|other| {
                other.kind == RecoveryReferenceKind::Bookmark
                    && other.name_digest == reference.name_digest
                    && other.adds == reference.adds
                    && other.removes == reference.removes
            })
        {
            return Err(refusal("durable bookmark missing from view"));
        }
    }
    if !snapshot
        .references
        .iter()
        .any(|reference| reference.kind == RecoveryReferenceKind::Head)
        || roots.into_iter().collect::<Vec<_>>() != snapshot.required_commits
        || changes.len() != snapshot.resolved_changes.len()
    {
        return Err(refusal("reference root population mismatch"));
    }
    for (change, commit) in &snapshot.resolved_changes {
        validate_hex(change, 32)?;
        validate_hex(commit, 40)?;
        if changes.get(blake3::hash(change.as_bytes()).to_hex().as_str())
            != Some(&Some(commit.clone()))
        {
            return Err(refusal("resolved change population mismatch"));
        }
    }
    if snapshot.computed_digest() != snapshot.reference_set_digest {
        return Err(refusal("reference digest mismatch"));
    }
    Ok(())
}

/// Linux jj-lib 0.39 uses flock + unlink-before-unlock, retrying unlinked inodes.
/// Reproduce that protocol with nonblocking acquisition to enforce a deadline.
#[cfg(unix)]
struct HeadsFence {
    path: PathBuf,
    _file: nix::fcntl::Flock<File>,
}

#[cfg(unix)]
impl HeadsFence {
    fn acquire(path: PathBuf, deadline: Instant) -> Result<Self, RecoveryReferenceError> {
        use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};
        loop {
            check_deadline(deadline)?;
            let file = OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .truncate(false)
                .custom_flags(nix::libc::O_NOFOLLOW)
                .open(&path)?;
            match nix::fcntl::Flock::lock(file, nix::fcntl::FlockArg::LockExclusiveNonblock) {
                Ok(file) if file.metadata()?.nlink() != 0 => {
                    return Ok(Self { path, _file: file });
                }
                Ok(_) => {}
                Err((_, nix::errno::Errno::EWOULDBLOCK)) => {
                    std::thread::sleep(Duration::from_millis(5));
                }
                Err((_, error)) => return Err(std::io::Error::from(error).into()),
            }
        }
    }
}

#[cfg(unix)]
impl Drop for HeadsFence {
    fn drop(&mut self) {
        // jj's waiting publishers re-open after acquiring an unlinked inode.
        let _ = fs::remove_file(&self.path);
    }
}

/// Run a bounded caller operation while the source's jj publication fence holds.
///
/// Supply full lowercase hexadecimal durable change and commit identities. The
/// callback must honor `deadline` (including remote verification and capture).
/// A callback result arriving after the deadline is discarded. This function
/// cannot interrupt arbitrary callback code or a blocked filesystem syscall.
/// Metadata copied to private scratch is capped at 1 MiB; large sources refuse.
#[cfg(unix)]
pub fn with_recovery_references<T>(
    repo_path: &Path,
    change_ids: &[String],
    commit_ids: &[String],
    named_refs: &[RecoveryNamedReference],
    deadline: Instant,
    callback: impl FnOnce(&RecoveryReferenceSnapshot, RecoveryWorkspaceCensus) -> T,
) -> Result<T, RecoveryReferenceError> {
    check_deadline(deadline)?;
    if change_ids
        .len()
        .saturating_add(commit_ids.len())
        .saturating_add(named_refs.len())
        > MAX_COMMITS
    {
        return Err(refusal("durable reference census exceeds bound"));
    }
    for change in change_ids {
        validate_hex(change, 32)?;
    }
    for commit in commit_ids {
        validate_hex(commit, 40)?;
    }
    let settings = UserSettings::from_config(StackedConfig::with_defaults())
        .map_err(|_| refusal("settings unavailable"))?;
    let workspace = Workspace::load(
        &settings,
        repo_path,
        &StoreFactories::default(),
        &default_working_copy_factories(),
    )
    .map_err(|_| refusal("existing jj workspace unavailable"))?;
    let loader = workspace.repo_loader();
    let source_backend = loader
        .store()
        .backend_impl::<GitBackend>()
        .ok_or_else(|| refusal("unsupported non-Git backend"))?;
    if loader.op_heads_store().name() != "simple_op_heads_store"
        || loader.op_store().name() != "simple_op_store"
    {
        return Err(refusal("unsupported operation store"));
    }
    let _fence = HeadsFence::acquire(workspace.repo_path().join("op_heads/heads/lock"), deadline)?;
    let mut head_count = 0;
    for entry in fs::read_dir(workspace.repo_path().join("op_heads/heads"))? {
        check_deadline(deadline)?;
        let entry = entry?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| refusal("invalid operation head name"))?;
        if name == "lock" {
            continue;
        }
        head_count += 1;
        if head_count > 1 {
            return Err(refusal("operation head is missing or ambiguous"));
        }
        validate_hex(&name, 128)?;
        if !entry.file_type()?.is_file() {
            return Err(refusal("unsupported operation head shape"));
        }
    }
    let heads = futures::executor::block_on(loader.op_heads_store().get_op_heads())
        .map_err(|_| refusal("operation heads unavailable"))?;
    let [head] = heads.as_slice() else {
        return Err(refusal("operation head is missing or ambiguous"));
    };
    bounded_store_file(
        &workspace.repo_path().join("op_store/operations"),
        &head.hex(),
    )?;
    let operation = futures::executor::block_on(loader.load_operation(head))
        .map_err(|_| refusal("operation unavailable"))?;
    bounded_store_file(
        &workspace.repo_path().join("op_store/views"),
        &operation.view_id().hex(),
    )?;
    let view = futures::executor::block_on(operation.view())
        .map_err(|_| refusal("operation view unavailable"))?;
    let mut census = Census::new(head.hex());
    census.view(view.store_view())?;
    let mut workspaces = RecoveryWorkspaceCensus {
        retained_execution_workspaces: view
            .store_view()
            .wc_commit_ids
            .keys()
            .any(|name| is_execution_workspace(name.as_str())),
        execution_workspaces: super::recovery_workspaces::census_execution_workspaces(
            repo_path,
            workspace.repo_path(),
            &settings,
            &view.store_view().wc_commit_ids,
            deadline,
        ),
    };
    for reference in named_refs.iter().collect::<BTreeSet<_>>() {
        let RecoveryNamedReference::LocalBookmark(name) = reference;
        if name.is_empty() || name.len() > MAX_METADATA_BYTES {
            return Err(refusal("malformed durable bookmark name"));
        }
        let name_key = jj_lib::ref_name::RefNameBuf::from(name.as_str());
        let target = view
            .store_view()
            .local_bookmarks
            .get(&name_key)
            .filter(|target| target.is_present())
            .ok_or_else(|| refusal("durable bookmark is unresolved"))?;
        census.add(
            RecoveryReferenceKind::DurableBookmark,
            name,
            None,
            None,
            target,
        )?;
    }
    for id in commit_ids.iter().collect::<BTreeSet<_>>() {
        validate_hex(id, 40)?;
        census.add(
            RecoveryReferenceKind::DurableCommit,
            id,
            None,
            None,
            &RefTarget::normal(parse_commit(id)?),
        )?;
    }

    // GitBackend::read_commit imports commits whose extras are absent. Copy only
    // extras metadata and insist every read has an entry before calling it. Its
    // get_head repair/merge then has write access to scratch, never source extras.
    let scratch = tempfile::tempdir()?;
    let mut copied = 0;
    copy_metadata(
        &workspace.repo_path().join("store/extra"),
        &scratch.path().join("extra"),
        &mut copied,
        deadline,
        0,
    )?;
    validate_table_framing(&scratch.path().join("extra"))?;
    fs::write(
        scratch.path().join("git_target"),
        source_backend
            .git_repo_path()
            .as_os_str()
            .as_encoded_bytes(),
    )?;
    let backend = GitBackend::load(&settings, scratch.path())
        .map_err(|_| refusal("copied Git backend unavailable"))?;
    let table = TableStore::load(scratch.path().join("extra"), 20)
        .get_head()
        .map_err(|_| refusal("copied change metadata unavailable"))?;
    let requested: BTreeSet<_> = change_ids.iter().cloned().collect();
    for id in &requested {
        validate_hex(id, 32)?;
    }
    let mut matches: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let mut workspace_trees: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    if let Ok(entries) = &workspaces.execution_workspaces {
        for entry in entries {
            workspace_trees
                .entry(entry.commit_id.clone())
                .or_default()
                .insert(entry.stored_tree_id.clone());
        }
    }
    let mut pending = census.commits.clone();
    let mut visited = BTreeSet::new();
    while let Some(id) = pending.pop_first() {
        check_deadline(deadline)?;
        if id == "0".repeat(40) || !visited.insert(id.clone()) {
            continue;
        }
        if visited.len() > MAX_COMMITS {
            return Err(refusal("commit census exceeds bound"));
        }
        let commit_id = parse_commit(&id)?;
        if table.get_value(commit_id.as_bytes()).is_none() {
            return Err(refusal("commit has no retained jj change metadata"));
        }
        let commit = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            futures::executor::block_on(backend.read_commit(&commit_id))
        }))
        .map_err(|_| refusal("malformed retained change metadata"))?
        .map_err(|_| refusal("retained commit unavailable"))?;
        validate_hex(&commit.change_id.hex(), 32)?;
        if let Some(trees) = workspace_trees.get(&id)
            && (trees.len() != 1
                || !trees.contains(&super::JjBackend::merged_tree_id_hex(&commit.root_tree)))
        {
            workspaces.execution_workspaces =
                Err("execution workspace checkout disagrees with pinned registration");
        }
        let change = commit.change_id.hex();
        if requested.contains(&change) {
            matches.entry(change).or_default().insert(id);
        }
        pending.extend(commit.parents.iter().map(jj_lib::object_id::ObjectId::hex));
    }
    for change in requested {
        let candidates = matches.remove(&change).unwrap_or_default();
        let mut candidates = candidates.into_iter();
        let commit = candidates
            .next()
            .ok_or_else(|| refusal("durable change is unresolved"))?;
        if candidates.next().is_some() {
            return Err(refusal("durable change is ambiguous"));
        }
        census.add(
            RecoveryReferenceKind::DurableChange,
            &change,
            None,
            None,
            &RefTarget::normal(parse_commit(&commit)?),
        )?;
        census.snapshot.resolved_changes.insert(change, commit);
    }
    census.snapshot.references.sort();
    census.snapshot.required_commits = census
        .commits
        .into_iter()
        .filter(|id| id != &"0".repeat(40))
        .collect();
    census.snapshot.reference_set_digest = census.snapshot.computed_digest();
    check_deadline(deadline)?;
    let result = callback(&census.snapshot, workspaces);
    check_deadline(deadline)?;
    Ok(result)
}

fn validate_hex(id: &str, len: usize) -> Result<(), RecoveryReferenceError> {
    if id.len() != len
        || !id
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(refusal("malformed durable identity"));
    }
    Ok(())
}

fn bounded_store_file(dir: &Path, id: &str) -> Result<(), RecoveryReferenceError> {
    validate_hex(id, 128)?;
    if id.bytes().all(|b| b == b'0') {
        return Ok(());
    }
    let metadata = fs::symlink_metadata(dir.join(id))?;
    if !metadata.is_file() || metadata.len() > MAX_METADATA_BYTES as u64 {
        return Err(refusal("unsupported or oversized operation metadata"));
    }
    Ok(())
}

pub(super) fn parse_commit(id: &str) -> Result<CommitId, RecoveryReferenceError> {
    validate_hex(id, 40)?;
    let bytes: Result<Vec<_>, _> = (0..40)
        .step_by(2)
        .map(|i| u8::from_str_radix(&id[i..i + 2], 16))
        .collect();
    Ok(CommitId::from_bytes(
        &bytes.map_err(|_| refusal("malformed commit identity"))?,
    ))
}

fn copy_metadata(
    source: &Path,
    target: &Path,
    copied: &mut usize,
    deadline: Instant,
    depth: usize,
) -> Result<(), RecoveryReferenceError> {
    check_deadline(deadline)?;
    *copied = copied
        .checked_add(128)
        .ok_or_else(|| refusal("metadata exceeds bound"))?;
    if *copied > MAX_METADATA_BYTES {
        return Err(refusal("metadata exceeds bound"));
    }
    let metadata = fs::symlink_metadata(source)?;
    if metadata.is_dir() {
        if depth > 1 || (depth == 1 && source.file_name().is_none_or(|name| name != "heads")) {
            return Err(refusal("unsupported metadata directory shape"));
        }
        fs::create_dir(target)?;
        for entry in fs::read_dir(source)? {
            let entry = entry?;
            copy_metadata(
                &entry.path(),
                &target.join(entry.file_name()),
                copied,
                deadline,
                depth + 1,
            )?;
        }
    } else if metadata.is_file() {
        let size =
            usize::try_from(metadata.len()).map_err(|_| refusal("metadata exceeds bound"))?;
        *copied = copied
            .checked_add(size.max(1))
            .ok_or_else(|| refusal("metadata exceeds bound"))?;
        if *copied > MAX_METADATA_BYTES {
            return Err(refusal("metadata exceeds bound"));
        }
        let mut bytes = Vec::new();
        File::open(source)?
            .take(size as u64 + 1)
            .read_to_end(&mut bytes)?;
        if bytes.len() != size {
            return Err(refusal("metadata changed while copying"));
        }
        fs::write(target, bytes)?;
    } else {
        return Err(refusal("unsupported metadata file shape"));
    }
    Ok(())
}

/// Only framing validation for jj-lib 0.39's 20-byte-key stacked table. The
/// upstream reader trusts lengths, offsets and parent filenames before decoding
/// extras. Validate these on private bounded bytes; semantics stay in jj-lib.
fn validate_table_framing(path: &Path) -> Result<(), RecoveryReferenceError> {
    fn u32_at(bytes: &[u8], offset: usize) -> Result<usize, RecoveryReferenceError> {
        let word = bytes
            .get(offset..offset + 4)
            .ok_or_else(|| refusal("truncated metadata frame"))?;
        Ok(u32::from_le_bytes(
            word.try_into()
                .map_err(|_| refusal("truncated metadata frame"))?,
        ) as usize)
    }
    let mut parents = BTreeMap::new();
    for entry in fs::read_dir(path)? {
        let entry = entry?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| refusal("invalid metadata segment name"))?;
        if name == "heads" {
            continue;
        }
        validate_hex(&name, 128)?;
        let bytes = fs::read(entry.path())?;
        let parent_len = u32_at(&bytes, 0)?;
        if parent_len != 0 && parent_len != 128 {
            return Err(refusal("unsupported metadata parent frame"));
        }
        let parent = if parent_len == 0 {
            None
        } else {
            let parent = std::str::from_utf8(
                bytes
                    .get(4..132)
                    .ok_or_else(|| refusal("truncated metadata parent"))?,
            )
            .map_err(|_| refusal("invalid metadata parent name"))?
            .to_owned();
            validate_hex(&parent, 128)?;
            Some(parent)
        };
        let entries = u32_at(&bytes, 4 + parent_len)?;
        let index_start = 8 + parent_len;
        let index_bytes = entries
            .checked_mul(24)
            .ok_or_else(|| refusal("metadata index exceeds bound"))?;
        let values_start = index_start + index_bytes;
        if values_start > bytes.len() {
            return Err(refusal("truncated metadata index"));
        }
        let values_len = bytes.len() - values_start;
        let mut previous_offset = 0;
        let mut previous_key: Option<&[u8]> = None;
        for index in 0..entries {
            let start = index_start + index * 24;
            let key = &bytes[start..start + 20];
            let offset = u32_at(&bytes, start + 20)?;
            if offset < previous_offset
                || offset > values_len
                || previous_key.is_some_and(|old| old >= key)
            {
                return Err(refusal("invalid metadata index framing"));
            }
            previous_offset = offset;
            previous_key = Some(key);
        }
        parents.insert(name, parent);
    }
    let mut head_count = 0;
    for entry in fs::read_dir(path.join("heads"))? {
        head_count += 1;
        let name = entry?
            .file_name()
            .into_string()
            .map_err(|_| refusal("invalid metadata head"))?;
        validate_hex(&name, 128)?;
        if !parents.contains_key(&name) {
            return Err(refusal("missing metadata head segment"));
        }
    }
    if head_count == 0 {
        return Err(refusal("missing change metadata head"));
    }
    for name in parents.keys() {
        let mut seen = BTreeSet::new();
        let mut next = Some(name);
        while let Some(name) = next {
            // Legitimate jj stacked tables have logarithmic depth. This bound
            // prevents upstream recursive loading from exhausting the stack.
            if !seen.insert(name) || seen.len() > 64 {
                return Err(refusal("cyclic or excessive metadata depth"));
            }
            next = parents
                .get(name)
                .ok_or_else(|| refusal("missing metadata parent"))?
                .as_ref();
        }
    }
    Ok(())
}

struct Census {
    snapshot: RecoveryReferenceSnapshot,
    commits: BTreeSet<String>,
    bytes: usize,
}

impl Census {
    fn new(operation_id: String) -> Self {
        Self {
            snapshot: RecoveryReferenceSnapshot {
                operation_id,
                references: Vec::new(),
                required_commits: Vec::new(),
                resolved_changes: BTreeMap::new(),
                reference_set_digest: String::new(),
            },
            commits: BTreeSet::new(),
            bytes: 0,
        }
    }

    fn add(
        &mut self,
        kind: RecoveryReferenceKind,
        name: &str,
        remote: Option<&str>,
        tracked: Option<bool>,
        target: &RefTarget,
    ) -> Result<(), RecoveryReferenceError> {
        let mut removes: Vec<_> = target
            .as_merge()
            .removes()
            .map(|id| id.as_ref().map(jj_lib::object_id::ObjectId::hex))
            .collect();
        let mut adds: Vec<_> = target
            .as_merge()
            .adds()
            .map(|id| id.as_ref().map(jj_lib::object_id::ObjectId::hex))
            .collect();
        removes.sort();
        adds.sort();
        self.bytes += 1024 + (removes.len() + adds.len()) * 96;
        if self.bytes > MAX_METADATA_BYTES {
            return Err(refusal("reference metadata exceeds bound"));
        }
        self.commits
            .extend(removes.iter().chain(&adds).flatten().cloned());
        if self.commits.len() > MAX_COMMITS {
            return Err(refusal("commit census exceeds bound"));
        }
        self.snapshot.references.push(RecoveryReference {
            kind,
            name_digest: blake3::hash(name.as_bytes()).to_hex().to_string(),
            remote_name_digest: remote.map(|r| blake3::hash(r.as_bytes()).to_hex().to_string()),
            tracked,
            removes,
            adds,
        });
        Ok(())
    }

    fn view(&mut self, view: &jj_lib::op_store::View) -> Result<(), RecoveryReferenceError> {
        // An upstream addition must break compilation until its recovery roots
        // are classified. No `..` silently excludes future commit-bearing fields.
        let jj_lib::op_store::View {
            head_ids: _,
            local_bookmarks: _,
            local_tags: _,
            remote_views: _,
            git_refs: _,
            git_head: _,
            wc_commit_ids: _,
        } = view;
        for id in &view.head_ids {
            self.add(
                RecoveryReferenceKind::Head,
                "",
                None,
                None,
                &RefTarget::normal(id.clone()),
            )?;
        }
        for (name, target) in &view.local_bookmarks {
            self.add(
                RecoveryReferenceKind::Bookmark,
                name.as_str(),
                None,
                None,
                target,
            )?;
        }
        for (name, target) in &view.local_tags {
            self.add(
                RecoveryReferenceKind::Tag,
                name.as_str(),
                None,
                None,
                target,
            )?;
        }
        for (name, target) in &view.git_refs {
            self.add(
                RecoveryReferenceKind::GitRef,
                name.as_str(),
                None,
                None,
                target,
            )?;
        }
        self.add(
            RecoveryReferenceKind::GitHead,
            "",
            None,
            None,
            &view.git_head,
        )?;
        for (name, id) in &view.wc_commit_ids {
            self.add(
                RecoveryReferenceKind::Workspace,
                name.as_str(),
                None,
                None,
                &RefTarget::normal(id.clone()),
            )?;
        }
        for (remote, refs) in &view.remote_views {
            let jj_lib::op_store::RemoteView {
                bookmarks: _,
                tags: _,
            } = refs;
            for (name, reference) in &refs.bookmarks {
                self.add(
                    RecoveryReferenceKind::RemoteBookmark,
                    name.as_str(),
                    Some(remote.as_str()),
                    Some(match reference.state {
                        RemoteRefState::Tracked => true,
                        RemoteRefState::New => false,
                    }),
                    &reference.target,
                )?;
            }
            for (name, reference) in &refs.tags {
                self.add(
                    RecoveryReferenceKind::RemoteTag,
                    name.as_str(),
                    Some(remote.as_str()),
                    Some(match reference.state {
                        RemoteRefState::Tracked => true,
                        RemoteRefState::New => false,
                    }),
                    &reference.target,
                )?;
            }
        }
        Ok(())
    }
}
