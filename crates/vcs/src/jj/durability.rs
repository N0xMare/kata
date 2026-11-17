//! The repository's DURABILITY BARRIER, and kata's answers for a repository a
//! power loss TORE.
//!
//! # Why a barrier
//!
//! jj-lib writes git objects and refs through gix, and gix 0.80 never syncs one:
//! a loose object or a loose ref is a temp file renamed into place. jj's OWN
//! files (operations, views, index segments, the working-copy state) are
//! `sync_data`'d before their rename. So after a power loss jj's operation log
//! can name a commit whose loose object came back EMPTY, and a ref kata wrote
//! can come back unparseable. Measured on a guest power loss (E3 P1-host, F7):
//! `refs/kata/targets/<exec>/head`, `refs/jj/keep/*` and the workspace's commit
//! objects came back zero-length, though the admission and the capsule's
//! dispatch that depended on them had committed `synchronous=FULL`, and the
//! restarted main exited on them.
//!
//! The barrier is `syncfs(2)` on every filesystem holding the repository — its
//! root (which holds `.jj/` and the execution workspaces under `agents/`) and
//! its git store. On return, every write made to those filesystems before the
//! call is on stable storage (ext4 commits its journal and flushes the device's
//! cache). It is the repository's half of ADR 0001's "bytes are preserved
//! before durable references", and it runs at these points:
//!
//! * **before a jj transaction kata publishes** ([`commit_transaction`], and the
//!   `/work` apply's and the commit effect's own publications): the objects and
//!   refs the transaction wrote are durable before the operation that names
//!   them, so jj's operation log never names a torn object — a teardown's
//!   removal transaction among them, so whatever its call wrote first is
//!   durable before a workspace file is removed;
//! * **before a provider call that wrote the repository returns**
//!   ([`JjBackend::durably`]): what it wrote — the operation files, the
//!   working-copy checkout, a target pin, a pin's deletion — is durable before
//!   the caller commits the transition that depends on it;
//! * **after jj-lib's workspace initialization** (`create_workspace_based`), over
//!   the workspace's own filesystem; and **between the op-log GC's new head and
//!   its first deletion** (`compact_op_log`).
//!
//! Each of them is pinned at the syscall boundary by
//! `repository_durability`'s barrier cell (`just repository-barrier-live`).
//!
//! jj-lib's own operations inside one call escape them: its workspace
//! initialization (`Workspace::init_workspace_with_existing_repo`) writes the new
//! workspace's `.jj/repo` pointer and publishes an `add workspace` operation, and
//! an adoption (`Workspace::init_external_git`) publishes two `init` operations;
//! kata syncs before the call answers, so a power loss can tear a registered
//! workspace only inside it. The recovered `Admitting` execution's census then
//! refuses its admission, and a read of its `@` refuses [`REPOSITORY_TORN`].
//!
//! Every barrier's descriptors are opened BEFORE the writes it covers: Linux
//! samples a filesystem's writeback-error sequence when a descriptor opens, so
//! `syncfs` reports a writeback failure of any of those writes as
//! `repository_not_durable` ([`REPOSITORY_NOT_DURABLE`]), and nothing that
//! depends on them is recorded. A teardown publishes behind the barrier its
//! calling provider call opened ([`JjBackend::durably`] hands it over), so a
//! writeback failure of the park or landing that preceded it refuses the
//! teardown with the workspace standing.
//!
//! The cost is one `syncfs` per barrier: it waits for every dirty page of the
//! filesystem, not only the repository's. Measured on this project's NVMe
//! (ext4): 0.15 ms with nothing dirty, 2.8 ms (p50) after a small jj-sized write,
//! 66 ms with 256 MiB of one other writer's dirty data, and 0.4 s for the first
//! sync on the shared build box at load 15 with 0.8 GB dirty (0.4 ms for the next).
//! A barrier runs per repository write a durable transition depends on — per
//! submit, per `/work` apply, per workspace effect, per closeout park, per pin
//! release, per boot sweep and repair — never per read.
//!
//! # What a power loss can still tear, and kata's answer
//!
//! A write after the last barrier was depended on by nothing durable, so a power
//! loss can tear it. [`JjBackend::repair_torn_repository`] runs at boot, before
//! anything else touches the repository, and answers each kind (its doc states
//! the refused set): an EMPTY loose object is removed (git and gix skip writing
//! an object whose file exists, so a later write of the same content would name
//! the empty file forever); a torn ref jj keeps (`refs/jj/keep/<id>`) is
//! re-derived from its own name, a torn branch jj's export evidently wrote last
//! from jj's record, and any other torn ref — one the operator's git may have
//! written since jj recorded it — is left and named. A torn target pin is the
//! boot sweep's (`jj::target`): an unowned one is deleted, an owned one rewritten
//! at the recorded target. A commit the repository's view names but the store
//! cannot read — what a disk that lost a barriered write leaves — is refused
//! [`REPOSITORY_TORN`] by name ([`JjBackend::named_commit`]), and so is a
//! candidate whose tree or files the store lost under an intact commit, before a
//! park, a landing or a workspace effect publishes it or tears its workspace
//! down ([`require_intact_content`]).

use std::collections::BTreeSet;
use std::fs::File;
use std::os::fd::AsRawFd as _;
use std::os::unix::fs::MetadataExt as _;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use gix::refs::transaction::{Change, LogChange, PreviousValue, RefEdit, RefLog};
use jj_lib::backend::{BackendError, CommitId};
use jj_lib::object_id::ObjectId as _;
use jj_lib::op_store::RefTarget;
use jj_lib::ref_name::GitRefName;
use jj_lib::repo::ReadonlyRepo;
use jj_lib::transaction::Transaction;
use kata_types::{KataError, KataResult};

use super::JjBackend;
use super::census::common_git_dir;
use crate::trunk::is_kata_owned_ref;

/// A repository write kata could not make durable: a `syncfs` of a filesystem
/// holding the repository failed (a writeback error since the barrier opened,
/// or the call itself). Nothing that depends on those writes is recorded.
pub const REPOSITORY_NOT_DURABLE: &str = "repository_not_durable";

/// The repository's view (or kata's own record) names a commit its store does
/// not hold, or holds as bytes it cannot read: a write the disk lost after its
/// barrier. Refused by name wherever kata reads such a commit; never repaired.
pub const REPOSITORY_TORN: &str = "repository_torn";

/// `syncfs(2)` over every filesystem holding a repository.
pub(crate) struct RepositoryBarrier {
    /// One open directory per distinct filesystem (by device), opened before
    /// the writes this barrier covers.
    filesystems: Vec<(PathBuf, File)>,
}

impl RepositoryBarrier {
    /// Open a barrier over the filesystems holding `dirs`, one descriptor per
    /// distinct device. A directory that does not exist is skipped (a git store
    /// not created yet holds no write to cover).
    ///
    /// # Errors
    ///
    /// `repository_not_durable` when an existing directory cannot be opened or
    /// stat'ed.
    pub(crate) fn open<'a>(dirs: impl IntoIterator<Item = &'a Path>) -> KataResult<Self> {
        let mut devices = BTreeSet::new();
        let mut filesystems = Vec::new();
        for dir in dirs {
            let file = match File::open(dir) {
                Ok(file) => file,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                Err(error) => return Err(not_durable("open", dir, &error)),
            };
            let device = file
                .metadata()
                .map_err(|error| not_durable("stat", dir, &error))?
                .dev();
            if devices.insert(device) {
                filesystems.push((dir.to_path_buf(), file));
            }
        }
        Ok(Self { filesystems })
    }

    /// The barrier a jj transaction is published behind: over the filesystem
    /// of `store`'s git store, where gix writes the transaction's objects and
    /// refs with no sync — jj syncs the content of its own operation, view,
    /// index, extra-metadata and working-copy-state files before renaming them
    /// into place. A store with no git backend holds no unsynced object, and its
    /// barrier covers nothing.
    pub(crate) fn for_git_store(store: &jj_lib::store::Store) -> KataResult<Self> {
        let git = jj_lib::git::get_git_backend(store)
            .ok()
            .map(|backend| common_git_dir(backend.git_repo_path()));
        Self::open(git.as_deref())
    }

    /// `syncfs` every filesystem: on `Ok`, every write made to them before this
    /// call is on stable storage.
    ///
    /// # Errors
    ///
    /// `repository_not_durable`, naming `what` and the filesystem whose sync
    /// failed.
    pub(crate) fn sync(&self, what: &str) -> KataResult<()> {
        for (dir, file) in &self.filesystems {
            nix::unistd::syncfs(file.as_raw_fd()).map_err(|errno| {
                KataError::Storage(format!(
                    "{REPOSITORY_NOT_DURABLE}: {what}: syncfs of the filesystem holding {} \
                     failed ({errno}); nothing that depends on this repository write is recorded",
                    dir.display()
                ))
            })?;
        }
        Ok(())
    }
}

fn not_durable(step: &str, dir: &Path, error: &std::io::Error) -> KataError {
    KataError::Storage(format!(
        "{REPOSITORY_NOT_DURABLE}: cannot {step} {} to open its durability barrier: {error}",
        dir.display()
    ))
}

/// Publish `tx` once everything it wrote is durable: `barrier` (opened before
/// the transaction wrote anything) syncs, then the operation that names those
/// writes is committed. `context` prefixes a commit failure.
///
/// # Errors
///
/// `repository_not_durable` from the barrier, nothing published; jj's commit
/// failure as `Internal`.
pub(crate) fn commit_transaction(
    barrier: &RepositoryBarrier,
    tx: Transaction,
    description: String,
    context: &str,
) -> KataResult<Arc<ReadonlyRepo>> {
    barrier.sync(context)?;
    JjBackend::block_on(tx.commit(description))
        .map_err(|err| KataError::Internal(format!("{context}: {err}")))
}

/// What a ref's LOOSE file holds, read from the file itself — never through a
/// ref store, which refuses to instantiate a torn one.
#[derive(Debug, PartialEq, Eq)]
enum LooseRef {
    /// No loose file (the ref is absent, or only packed).
    Absent,
    /// A direct ref: `<hex>` and a newline.
    Direct(gix::ObjectId),
    /// A symbolic ref: `ref: <name>`.
    Symbolic,
    /// Anything else — the empty file a power loss leaves among it.
    Torn,
}

fn read_loose_ref(path: &Path) -> KataResult<LooseRef> {
    let bytes = match std::fs::read(path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(LooseRef::Absent),
        Err(error) => {
            return Err(KataError::Internal(format!(
                "read the loose ref {}: {error}",
                path.display()
            )));
        }
    };
    if bytes.starts_with(b"ref: ") {
        return Ok(LooseRef::Symbolic);
    }
    let text = bytes.strip_suffix(b"\n").unwrap_or(&bytes);
    let hex = text.len() == 40 || text.len() == 64;
    if hex
        && text.iter().all(u8::is_ascii_hexdigit)
        && let Ok(id) = gix::ObjectId::from_hex(text)
    {
        return Ok(LooseRef::Direct(id));
    }
    Ok(LooseRef::Torn)
}

/// Whether the store holds `id` and can read it. A loose object kata can read
/// the bytes of and gix cannot decode is torn (`false`), as is an absent one; a
/// failure to read the loose file at all is an error, never an answer.
pub(crate) fn object_intact(repo: &gix::Repository, id: gix::ObjectId) -> KataResult<bool> {
    Ok(read_intact(repo, id)?.is_some())
}

/// `id` read from the store: `Some` when it reads, `None` when it is TORN —
/// absent, or a loose file kata can read the bytes of and gix cannot decode. A
/// failure to read the loose file at all (a permission, an I/O error) is an
/// error, never an answer.
fn read_intact(repo: &gix::Repository, id: gix::ObjectId) -> KataResult<Option<gix::Object<'_>>> {
    match repo.try_find_object(id) {
        Ok(found) => Ok(found),
        Err(error) => torn_unless_unreadable(repo, id, &error).map(|()| None),
    }
}

/// [`object_intact`] for a blob, reading only its header — what a candidate's
/// file needs to be readable, without inflating its content.
fn blob_intact(repo: &gix::Repository, id: gix::ObjectId) -> KataResult<bool> {
    match repo.try_find_header(id) {
        Ok(found) => Ok(found.is_some()),
        Err(error) => torn_unless_unreadable(repo, id, &error).map(|()| false),
    }
}

/// A store read of `id` failed with `error`: torn (`Ok`) when its loose file
/// reads, else the error that kept kata from reading it.
fn torn_unless_unreadable(
    repo: &gix::Repository,
    id: gix::ObjectId,
    error: &dyn std::fmt::Display,
) -> KataResult<()> {
    let loose = loose_object_path(repo, id);
    match std::fs::read(&loose) {
        Ok(_) => Ok(()),
        Err(read) => Err(KataError::Internal(format!(
            "read object {id} ({error}); its loose file {}: {read}",
            loose.display()
        ))),
    }
}

/// Refuse [`REPOSITORY_TORN`] unless the store can read everything a park, a
/// landing or a workspace effect would publish `commit` with: each parent commit,
/// and every tree and blob under `commit`'s tree (a blob by its header). Without
/// it, a tree the store lost answered `Internal` from jj's working-copy read — the
/// closeout stayed `Terminalizing` — and a lost blob whose file still matched the
/// working copy's recorded state was never read at all: the park published a
/// commit the store could not serve and tore down the one copy that held its
/// bytes. A submodule's commit is not the store's to hold, and is not read; nor is
/// anything older than `commit`'s parents (their trees, and their own
/// ancestors). A store with no git backend holds no object gix wrote unsynced,
/// and is not walked.
///
/// The walk reads every tree of the candidate once and every blob's header once —
/// proportional to the candidate's tree, run once per call that would publish or
/// tear down the candidate, never per read. Measured: 5–14 ms over this project's
/// own 2,017-file tree in a debug build, beside the 57–61 ms the same call's
/// working-copy status takes.
///
/// # Errors
///
/// `repository_torn` (`Validation`) naming the first object the store lost and
/// its path, or the store's other failures (`Internal`).
pub(crate) fn require_intact_content(
    repo: &dyn jj_lib::repo::Repo,
    commit: &jj_lib::commit::Commit,
    what: &str,
) -> KataResult<()> {
    let Ok(backend) = jj_lib::git::get_git_backend(repo.store()) else {
        return Ok(());
    };
    for parent in commit.parent_ids() {
        if parent != repo.store().root_commit_id() {
            JjBackend::named_commit(repo, parent, &format!("parent of the {what}"))?;
        }
    }
    let git = backend.git_repo();
    let id = gix::ObjectId::try_from(commit.id().as_bytes())
        .map_err(|err| KataError::Internal(format!("{what} {}: {err}", commit.id().hex())))?;
    let tree_of = |err: &dyn std::fmt::Display| {
        KataError::Internal(format!(
            "read the tree of {what} {}: {err}",
            commit.id().hex()
        ))
    };
    let root = git
        .find_commit(id)
        .map_err(|err| tree_of(&err))?
        .tree_id()
        .map_err(|err| tree_of(&err))?
        .detach();
    let torn = |kind: &str, id: gix::ObjectId, path: &str| {
        KataError::Validation(format!(
            "{REPOSITORY_TORN}: the {kind} {id} at `/{path}` under {what} {} is not readable \
             from the repository's store: the store lost a write a durable record depends on \
             — nothing is re-derived, and the workspace and its files stand for inspection",
            commit.id().hex()
        ))
    };
    let mut pending = vec![(root, String::new())];
    while let Some((tree_id, path)) = pending.pop() {
        let Some(object) = read_intact(&git, tree_id)? else {
            return Err(torn("tree", tree_id, &path));
        };
        let Ok(tree) = object.try_into_tree() else {
            return Err(torn("tree", tree_id, &path));
        };
        let Ok(decoded) = tree.decode() else {
            return Err(torn("tree", tree_id, &path));
        };
        for entry in &decoded.entries {
            let child = if path.is_empty() {
                entry.filename.to_string()
            } else {
                format!("{path}/{}", entry.filename)
            };
            let oid = entry.oid.to_owned();
            if entry.mode.is_tree() {
                pending.push((oid, child));
            } else if !entry.mode.is_commit() && !blob_intact(&git, oid)? {
                return Err(torn("blob", oid, &child));
            }
        }
    }
    Ok(())
}

fn loose_object_path(repo: &gix::Repository, id: gix::ObjectId) -> PathBuf {
    let hex = id.to_hex().to_string();
    repo.common_dir()
        .join("objects")
        .join(&hex[..2])
        .join(&hex[2..])
}

/// Point the ref `name` at `id` (`Some`) or delete it (`None`), whatever its
/// loose file holds now — a torn file included: gix's `PreviousValue::Any`
/// never reads the old value.
pub(crate) fn rewrite_ref(
    repo: &gix::Repository,
    name: &str,
    id: Option<gix::ObjectId>,
    message: &str,
) -> KataResult<()> {
    let change = match id {
        Some(id) => Change::Update {
            log: LogChange {
                mode: RefLog::AndReference,
                force_create_reflog: false,
                message: message.into(),
            },
            expected: PreviousValue::Any,
            new: gix::refs::Target::Object(id),
        },
        None => Change::Delete {
            expected: PreviousValue::Any,
            log: RefLog::AndReference,
        },
    };
    let edit = RefEdit {
        change,
        name: name
            .try_into()
            .map_err(|err| KataError::Internal(format!("ref name `{name}`: {err}")))?,
        deref: false,
    };
    repo.edit_references([edit])
        .map_err(|err| KataError::Internal(format!("rewrite the ref `{name}`: {err}")))?;
    Ok(())
}

/// What [`JjBackend::repair_torn_repository`] found and did.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct TornRepair {
    /// Empty loose objects removed, by object id.
    pub removed_objects: Vec<String>,
    /// Torn refs rewritten at the target kata re-derived for them.
    pub rederived_refs: Vec<String>,
    /// Torn refs deleted: nothing records a target for them.
    pub deleted_refs: Vec<String>,
    /// Torn refs left as they stand — no record of kata's or jj's names a
    /// target for them, and kata does not own them. Each is named at boot as
    /// `repository_torn`; jj's next import of git's refs refuses on it until
    /// the operator repairs or deletes it.
    pub unrepaired_refs: Vec<String>,
}

impl TornRepair {
    /// Whether the repair changed nothing and left nothing torn.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.removed_objects.is_empty()
            && self.rederived_refs.is_empty()
            && self.deleted_refs.is_empty()
            && self.unrepaired_refs.is_empty()
    }
}

/// Every loose file under `<git>/<namespace>`, as its full ref name.
pub(crate) fn loose_refs_under(git: &Path, namespace: &str) -> KataResult<Vec<String>> {
    let mut names = Vec::new();
    let mut pending = vec![git.join(namespace)];
    while let Some(dir) = pending.pop() {
        let entries = match std::fs::read_dir(&dir) {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => {
                return Err(KataError::Internal(format!(
                    "list the loose refs under {}: {error}",
                    dir.display()
                )));
            }
        };
        for entry in entries {
            let entry = entry.map_err(|error| {
                KataError::Internal(format!(
                    "list the loose refs under {}: {error}",
                    dir.display()
                ))
            })?;
            let path = entry.path();
            let kind = entry.file_type().map_err(|error| {
                KataError::Internal(format!("stat {}: {error}", path.display()))
            })?;
            if kind.is_dir() {
                pending.push(path);
            } else if kind.is_file() && path.extension().is_none_or(|extension| extension != "lock")
            {
                let relative = path.strip_prefix(git).map_err(|err| {
                    KataError::Internal(format!("ref path {}: {err}", path.display()))
                })?;
                names.push(relative.to_string_lossy().into_owned());
            }
        }
    }
    names.sort();
    Ok(names)
}

/// Remove every EMPTY loose object file under `objects`: `<2 hex>/<38 or 62
/// hex>`, zero bytes long. A zero-length file is never a loose object (one is a
/// zlib stream), git and gix both write an object through a temp file renamed
/// into place (so no write in flight is ever an empty file at its final path),
/// and both SKIP a write whose object file exists — so an empty one left by a
/// power loss would otherwise stand in for its object forever. Nothing else is
/// touched: an object file that is non-empty and still undecodable is left as
/// it stands (a residual: a later write of that object is skipped, and a read
/// of it refuses `repository_torn`).
fn remove_empty_loose_objects(objects: &Path) -> KataResult<Vec<String>> {
    let mut removed = Vec::new();
    let fanout = match std::fs::read_dir(objects) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(removed),
        Err(error) => {
            return Err(KataError::Internal(format!(
                "list {}: {error}",
                objects.display()
            )));
        }
    };
    for dir in fanout {
        let dir = dir.map_err(|error| KataError::Internal(format!("list objects: {error}")))?;
        let prefix = dir.file_name().to_string_lossy().into_owned();
        if prefix.len() != 2 || !prefix.bytes().all(|b| b.is_ascii_hexdigit()) {
            continue;
        }
        let entries = std::fs::read_dir(dir.path()).map_err(|error| {
            KataError::Internal(format!("list {}: {error}", dir.path().display()))
        })?;
        for entry in entries {
            let entry = entry.map_err(|error| KataError::Internal(format!("list: {error}")))?;
            let rest = entry.file_name().to_string_lossy().into_owned();
            let named = (rest.len() == 38 || rest.len() == 62)
                && rest.bytes().all(|b| b.is_ascii_hexdigit());
            if !named {
                continue;
            }
            let meta = entry.metadata().map_err(|error| {
                KataError::Internal(format!("stat {}: {error}", entry.path().display()))
            })?;
            if meta.is_file() && meta.len() == 0 {
                std::fs::remove_file(entry.path()).map_err(|error| {
                    KataError::Internal(format!(
                        "remove the empty loose object {}: {error}",
                        entry.path().display()
                    ))
                })?;
                removed.push(format!("{prefix}{rest}"));
            }
        }
    }
    removed.sort();
    Ok(removed)
}

impl JjBackend {
    /// The git store behind this backend's repository, read the way jj's git
    /// backend loads it (`<repo>/.jj/repo/store/git_target`, relative to the
    /// store), or `None` for a store with no git backend.
    fn git_store_dir(&self) -> KataResult<Option<PathBuf>> {
        let store = self
            .repo_path
            .join(super::JJ_METADATA_DIR_NAME)
            .join("repo")
            .join("store");
        let target = match std::fs::read(store.join("git_target")) {
            Ok(target) => target,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => {
                return Err(KataError::Internal(format!(
                    "read jj's git_target under {}: {error}",
                    store.display()
                )));
            }
        };
        let target = jj_lib::file_util::path_from_bytes(&target).map_err(|err| {
            KataError::Internal(format!("jj's git_target under {}: {err}", store.display()))
        })?;
        Ok(Some(common_git_dir(&store.join(target))))
    }

    /// The barrier over this backend's repository: its root (`.jj/`, the
    /// execution workspaces) and its git store.
    pub(crate) fn barrier(&self) -> KataResult<RepositoryBarrier> {
        let git = self.git_store_dir()?;
        RepositoryBarrier::open(std::iter::once(self.repo_path.as_path()).chain(git.as_deref()))
    }

    /// Run `op`, a provider call that writes the repository, and answer only
    /// once what it wrote is durable: the barrier opens before `op` and syncs
    /// after it, on its `Ok` and its `Err` alike — a refusal can name what the
    /// call wrote before it refused (a landing that parked its candidate), and
    /// the caller records that answer. `op` is handed the barrier, so a step that
    /// must order the call's earlier writes before it (a teardown) syncs the
    /// descriptor opened before them, and a writeback error of any of them is
    /// reported there.
    ///
    /// # Errors
    ///
    /// `repository_not_durable` when the sync fails (whatever `op` answered:
    /// nothing it wrote can be relied on), else `op`'s own error.
    pub(crate) fn durably<T>(
        &self,
        what: &str,
        op: impl FnOnce(&RepositoryBarrier) -> KataResult<T>,
    ) -> KataResult<T> {
        let barrier = self.barrier()?;
        let answer = op(&barrier);
        barrier.sync(what)?;
        answer
    }

    /// Refuse [`REPOSITORY_TORN`] unless `agent`'s workspace `@` — the candidate
    /// a park, a landing or a workspace effect is about to read through the
    /// working copy, publish and tear down — reads whole from the store
    /// ([`require_intact_content`]). Runs BEFORE the working copy is read: jj-lib
    /// answers a tree it cannot read from inside its snapshot. A workspace the
    /// view names no `@` for is not this check's: the caller's own lookup
    /// answers it.
    ///
    /// # Errors
    ///
    /// `repository_torn` (`Validation`), or the store's other failures.
    pub(crate) fn require_intact_workspace_candidate(
        &self,
        agent: &kata_types::AgentId,
    ) -> KataResult<()> {
        let settings = self.user_settings()?;
        let workspace = self.load_root_workspace(&settings)?;
        let repo = Self::block_on(workspace.repo_loader().load_at_head())
            .map_err(|err| KataError::Internal(format!("failed to load jj repo head: {err}")))?;
        let name = Self::workspace_name(agent);
        if repo.view().get_wc_commit_id(&name).is_none() {
            return Ok(());
        }
        let candidate = Self::workspace_commit(repo.as_ref(), &name)?;
        require_intact_content(repo.as_ref(), &candidate, "the workspace's @")
    }

    /// The commit `id`, which the repository's view or kata's own record names
    /// (`what` says which), read from the store. A store that does not hold it,
    /// or holds bytes for it that cannot be read, is refused
    /// [`REPOSITORY_TORN`]: the view or the record outlived a write the disk
    /// lost. Any other store failure stays `Internal`.
    ///
    /// # Errors
    ///
    /// `repository_torn` (`Validation`), or the store's other failures.
    pub(crate) fn named_commit(
        repo: &dyn jj_lib::repo::Repo,
        id: &CommitId,
        what: &str,
    ) -> KataResult<jj_lib::commit::Commit> {
        let error = match repo.store().get_commit(id) {
            Ok(commit) => return Ok(commit),
            Err(error) => error,
        };
        let torn = match &error {
            BackendError::ObjectNotFound { .. } => true,
            BackendError::ReadObject { .. } => jj_lib::git::get_git_backend(repo.store())
                .ok()
                .and_then(|backend| {
                    let git = backend.git_repo();
                    let id = gix::ObjectId::try_from(id.as_bytes()).ok()?;
                    object_intact(&git, id).ok().map(|intact| !intact)
                })
                .unwrap_or(false),
            _ => false,
        };
        if torn {
            return Err(KataError::Validation(format!(
                "{REPOSITORY_TORN}: {what} {} is not readable from the repository's store \
                 ({error}): the store lost a write a durable record depends on — the commit \
                 is not re-derived, and the workspace and its files stand for inspection",
                id.hex()
            )));
        }
        Err(KataError::Internal(format!(
            "failed to load jj {what}: {error}"
        )))
    }

    /// Repair what a power loss TORE in this repository, before anything else
    /// reads or writes it — boot runs it first. Exactly:
    ///
    /// * every EMPTY loose object file is removed (see
    ///   `remove_empty_loose_objects` for why, and its residual);
    /// * a loose `refs/jj/keep/<id>` that does not parse, or names an object the
    ///   store cannot read, is rewritten at `<id>` (its own name) when the store
    ///   holds `<id>` intact, and deleted otherwise — it keeps nothing alive;
    /// * a loose branch under `refs/heads/` that does not parse is rewritten at
    ///   the one commit jj's view records for it, when the store holds that
    ///   commit intact and jj's export is the branch's evidenced last writer: it
    ///   is one of kata's own branches (`parked/`, `exec-`, `kata/`, which only
    ///   kata's export writes), or the newest entry of its reflog is jj's export
    ///   (`export from jj`) of that very commit — trunk after a kata landing. A
    ///   kata branch jj holds no record of is deleted (an export a crash cut off
    ///   before its transaction);
    /// * every other torn branch — one the operator's git wrote after jj's
    ///   record, or whose reflog names no such export — and every torn
    ///   remote-tracking ref or tag (the operator's git writes those; kata's
    ///   export never does) is LEFT and named in [`TornRepair::unrepaired_refs`]:
    ///   jj's record can be older than the operator's last write, and rewriting
    ///   the ref there would roll their work back by guess. The reflog is a file
    ///   the same power loss can tear: when it lost the operator's newest entry
    ///   along with their ref, and the entry before it is jj's export of jj's
    ///   recorded commit, the branch is rewritten at that commit — the residual
    ///   the operator guide states;
    /// * `refs/kata/targets/` is left to the target-pin sweep, which owns the
    ///   ownership rule; every other namespace is not read.
    ///
    /// What it writes is synced before it returns (`durably`): a ref's deletion
    /// rewrites the repository-wide `packed-refs` when the ref is also packed,
    /// and an unsynced rewrite a power loss empties would take every packed ref
    /// with it. A power loss inside the repair is answered by the next boot's.
    ///
    /// # Errors
    ///
    /// A failure to list, read, remove or rewrite (`Internal`),
    /// `repository_not_durable` when the sync fails; a backend with no git store
    /// has nothing to repair.
    pub fn repair_torn_repository(&self) -> KataResult<TornRepair> {
        super::record_vcs_op("repair_torn", || {
            self.durably("repair_torn", |_| self.repair_torn_repository_inner())
        })
    }

    fn repair_torn_repository_inner(&self) -> KataResult<TornRepair> {
        let Some(git_dir) = self.git_store_dir()? else {
            return Ok(TornRepair::default());
        };
        let mut repair = TornRepair {
            removed_objects: remove_empty_loose_objects(&git_dir.join("objects"))?,
            ..TornRepair::default()
        };
        let git = gix::open(&git_dir).map_err(|err| {
            KataError::Internal(format!(
                "open the git store {} to repair it: {err}",
                git_dir.display()
            ))
        })?;
        for name in loose_refs_under(&git_dir, "refs/jj/keep")? {
            let named = name
                .rsplit('/')
                .next()
                .and_then(|hex| gix::ObjectId::from_hex(hex.as_bytes()).ok());
            let standing = match read_loose_ref(&git_dir.join(&name))? {
                LooseRef::Direct(id) if Some(id) == named && object_intact(&git, id)? => continue,
                LooseRef::Absent => continue,
                _ => named,
            };
            match standing {
                Some(id) if object_intact(&git, id)? => {
                    rewrite_ref(&git, &name, Some(id), "kata: re-derive a torn keep ref")?;
                    repair.rederived_refs.push(name);
                }
                _ => {
                    rewrite_ref(&git, &name, None, "kata: delete a torn keep ref")?;
                    repair.deleted_refs.push(name);
                }
            }
        }
        let mut torn_imported = Vec::new();
        for namespace in ["refs/heads", "refs/remotes", "refs/tags"] {
            for name in loose_refs_under(&git_dir, namespace)? {
                if read_loose_ref(&git_dir.join(&name))? == LooseRef::Torn {
                    torn_imported.push(name);
                }
            }
        }
        if torn_imported.is_empty() {
            return Ok(repair);
        }
        let settings = self.user_settings()?;
        let workspace = self.load_root_workspace(&settings)?;
        let repo = Self::block_on(workspace.repo_loader().load_at_head())
            .map_err(|err| KataError::Internal(format!("failed to load jj repo head: {err}")))?;
        for name in torn_imported {
            let Some(branch) = name.strip_prefix("refs/heads/") else {
                repair.unrepaired_refs.push(name);
                continue;
            };
            let kata_owned = is_kata_owned_ref(branch);
            let recorded = GitRefName::new(&name);
            let recorded = repo.view().get_git_ref(recorded);
            let rederived = recorded_single_commit(recorded)
                .and_then(|id| gix::ObjectId::try_from(id.as_bytes()).ok());
            match rederived {
                Some(id)
                    if (kata_owned || newest_reflog_entry_is_jj_export(&git_dir, &name, id)?)
                        && object_intact(&git, id)? =>
                {
                    rewrite_ref(&git, &name, Some(id), "kata: re-derive a torn ref from jj")?;
                    repair.rederived_refs.push(name);
                }
                None if kata_owned => {
                    rewrite_ref(&git, &name, None, "kata: delete a torn kata branch")?;
                    repair.deleted_refs.push(name);
                }
                _ => repair.unrepaired_refs.push(name),
            }
        }
        Ok(repair)
    }
}

fn recorded_single_commit(target: &RefTarget) -> Option<&CommitId> {
    target.as_normal()
}

/// The message jj's export writes into a ref's reflog (`jj_lib::git`).
const JJ_EXPORT_REFLOG_MESSAGE: &str = "export from jj";

/// Whether the newest entry of `name`'s reflog (`<git>/logs/<name>`) is jj's
/// export of `id`: the line parses, its new value is `id`, and its message is
/// jj's export message. An absent, empty or torn reflog is no evidence (`false`).
fn newest_reflog_entry_is_jj_export(
    git_dir: &Path,
    name: &str,
    id: gix::ObjectId,
) -> KataResult<bool> {
    let path = git_dir.join("logs").join(name);
    let bytes = match std::fs::read(&path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => {
            return Err(KataError::Internal(format!(
                "read the reflog {}: {error}",
                path.display()
            )));
        }
    };
    let Some(newest) = bytes
        .split(|byte| *byte == b'\n')
        .rev()
        .find(|line| !line.is_empty())
    else {
        return Ok(false);
    };
    let Some((header, message)) = std::str::from_utf8(newest)
        .ok()
        .and_then(|line| line.split_once('\t'))
    else {
        return Ok(false);
    };
    let new = header.split(' ').nth(1);
    Ok(message == JJ_EXPORT_REFLOG_MESSAGE
        && new.is_some_and(|new| gix::ObjectId::from_hex(new.as_bytes()).ok() == Some(id)))
}
