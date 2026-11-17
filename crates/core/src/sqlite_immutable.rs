//! Fail-closed, observationally read-only SQLite inspection.
//!
//! Maintenance compatibility probes can run before Kata owns the data
//! directory. They must not create SQLite sidecars or silently ignore journal
//! state. This helper centralizes that immutable-open contract. Normal runtime
//! boot uses a separate authority-held, recovery-capable open path so a
//! legitimate crash WAL is not mistaken for hostile ambient state.
//!
//! SQLite's VFS canonicalizes descriptor pseudo-paths such as `/proc/self/fd`
//! and may reopen the resulting pathname, so those paths are not an inode
//! binding. Maintenance inspection instead copies an adopted source descriptor
//! into an unguessable, mode-checked private snapshot and opens that ordinary
//! file before unlinking it for the callback lifetime.
//!
//! A stable effective-owner-only coordinator under the validated temporary
//! root holds a nonblocking advisory lock for the complete inspection. The
//! next owner descriptor-validates and boundedly reaps strict stale attempts
//! before creating its one active attempt, so repeated hard kills cannot
//! accumulate snapshots. In a root-owned sticky shared temporary root, another
//! local user can precreate Kata's predictable per-uid coordinator name;
//! owner/mode checks make that a fail-closed local denial of service, never
//! adopted authority.
//!
//! Snapshot size and fallback capacity are hard-bounded. The fallback copy's
//! progress timeout is cooperative: Kata checks it between each read and
//! partial-write syscall, but a blocked kernel/filesystem call can exceed it.
//! This probe therefore requires a responsive local regular filesystem; it does
//! not claim a hard wall-clock bound for FUSE, network, or failing storage.

use std::fs::{File, OpenOptions};
use std::io::{Read as _, Seek as _, Write as _};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

#[cfg(test)]
use std::sync::Arc;

#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt as _;

use kata_types::{KataError, KataResult};
use rusqlite::{Connection, OpenFlags};

const PRIVATE_SNAPSHOT_NAME: &str = "snapshot.db";
const MAX_PRIVATE_SNAPSHOT_BYTES: u64 = 1024 * 1024 * 1024 * 1024;
const PRIVATE_SNAPSHOT_MIN_COPY_PROGRESS_TIMEOUT: Duration = Duration::from_mins(5);
const PRIVATE_SNAPSHOT_MAX_COPY_PROGRESS_TIMEOUT: Duration = Duration::from_hours(24);
const PRIVATE_SNAPSHOT_MIN_COPY_RATE_BYTES_PER_SECOND: u64 = 16 * 1024 * 1024;
const PRIVATE_SNAPSHOT_COPY_CHUNK_BYTES: usize = 1024 * 1024;
const PRIVATE_SNAPSHOT_MIN_HEADROOM_BYTES: u64 = 64 * 1024 * 1024;
const PRIVATE_SNAPSHOT_MAX_HEADROOM_BYTES: u64 = 1024 * 1024 * 1024;
#[cfg(unix)]
const PRIVATE_SNAPSHOT_COORDINATOR_LOCK: &str = "coordinator.lock";
#[cfg(unix)]
const PRIVATE_SNAPSHOT_ATTEMPT_PREFIX: &str = "attempt-";
#[cfg(unix)]
const PRIVATE_SNAPSHOT_MAX_COORDINATOR_ENTRIES: usize = 64;
#[cfg(unix)]
const PRIVATE_SNAPSHOT_MAX_ATTEMPT_ENTRIES: usize = 4;

// Restore staging and authority-held upgrade paths currently enter through the
// same generic API. They do not transfer a held directory/file descriptor that
// could prove their pathname is still the staged inode, so skipping this
// snapshot there would weaken the contract. A future no-copy trusted-private
// mode must accept such an unforgeable authority object, not a boolean claim.

#[derive(Clone, Default)]
struct SnapshotMaterializationPolicy {
    temporary_root: Option<PathBuf>,
    force_copy: bool,
    available_bytes: Option<u64>,
    copy_progress_timeout: Option<Duration>,
    #[cfg(test)]
    materialization_hook: Option<Arc<dyn Fn(MaterializationCheckpoint)>>,
    #[cfg(test)]
    clone_outcome: TestCloneOutcome,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum MaterializationCheckpoint {
    DirectoryCreatedBeforeFirstRevalidate,
    PrivateDirectoryOpened,
    MidCopy,
    FinalVerify,
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
enum TestCloneOutcome {
    #[default]
    System,
    Success,
    Error {
        errno: i32,
        leave_partial_destination: bool,
    },
}

/// Inspect an optional SQLite database without recovery, locking, or writes,
/// treating orphan sidecars as ambiguous authority rather than as a fresh store.
/// `Ok(None)` when no database exists at `path`.
///
/// Kata adopts the source inode, copies its exact validated bytes into a
/// private snapshot, and opens SQLite only on that snapshot. The snapshot
/// pathname is unlinked before the callback, but its private directory and the
/// SQLite connection remain alive until the callback returns. Callbacks must
/// therefore treat the borrowed connection as a side-effect-free,
/// callback-lifetime view; they must not retain or reopen SQLite's reported
/// filename.
///
/// The helper rejects ambient rollback/WAL state and verifies the source
/// pathname, file identity, and sidecar absence after materialization and
/// again after the callback. This bounds a pre-coordination probe; an applied
/// operation must still repeat the probe while it owns the relevant Kata
/// authority locks.
///
/// Source bytes and fallback capacity are hard-bounded. Copy progress time is
/// checked between each read and partial-write syscall under the
/// responsive-local-filesystem assumption;
/// a blocked kernel/filesystem operation is outside that cooperative bound.
pub fn inspect_optional_immutable_sqlite<T>(
    path: &Path,
    store_name: &str,
    inspect: impl FnOnce(&Connection) -> KataResult<T>,
) -> KataResult<Option<T>> {
    inspect_optional_immutable_sqlite_with_hooks(path, store_name, || {}, |_| {}, inspect)
}

fn inspect_optional_immutable_sqlite_with_hooks<T>(
    path: &Path,
    store_name: &str,
    after_source_adoption: impl FnOnce(),
    after_snapshot_materialization: impl FnOnce(&Path),
    inspect: impl FnOnce(&Connection) -> KataResult<T>,
) -> KataResult<Option<T>> {
    inspect_optional_immutable_sqlite_with_hooks_and_policy(
        path,
        store_name,
        after_source_adoption,
        after_snapshot_materialization,
        &SnapshotMaterializationPolicy::default(),
        inspect,
    )
}

fn inspect_optional_immutable_sqlite_with_hooks_and_policy<T>(
    path: &Path,
    store_name: &str,
    after_source_adoption: impl FnOnce(),
    after_snapshot_materialization: impl FnOnce(&Path),
    policy: &SnapshotMaterializationPolicy,
    inspect: impl FnOnce(&Connection) -> KataResult<T>,
) -> KataResult<Option<T>> {
    let original = path.to_path_buf();
    reject_sqlite_sidecars(&original, store_name)?;
    let original_metadata = match std::fs::symlink_metadata(&original) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            reject_sqlite_sidecars(&original, store_name)?;
            return match std::fs::symlink_metadata(&original) {
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
                Ok(_) => Err(KataError::Storage(format!(
                    "{store_name} immutable SQLite source appeared during inspection: {}",
                    original.display()
                ))),
                Err(error) => Err(KataError::Storage(format!(
                    "{store_name} immutable SQLite inspection cannot restat {}: {error}",
                    original.display()
                ))),
            };
        }
        Err(error) => {
            return Err(KataError::Storage(format!(
                "{store_name} immutable SQLite inspection cannot stat {}: {error}",
                original.display()
            )));
        }
    };
    if original_metadata.file_type().is_symlink() || !original_metadata.is_file() {
        return Err(KataError::Storage(format!(
            "{store_name} immutable SQLite inspection requires a regular non-symlink file at {}",
            original.display()
        )));
    }

    let canonical = original.canonicalize().map_err(|error| {
        KataError::Storage(format!(
            "{store_name} immutable SQLite inspection cannot canonicalize {}: {error}",
            original.display()
        ))
    })?;
    let before = sqlite_file_snapshot(&canonical, store_name)?;
    reject_sqlite_sidecars(&canonical, store_name)?;

    let mut opened = open_immutable_sqlite_source(&canonical, &before, store_name)?;
    // Deterministic test seam for the dangerous interval after Kata has
    // adopted the inode but before it materializes the private snapshot.
    after_source_adoption();

    let private = materialize_private_sqlite_snapshot(&mut opened, &before, store_name, policy)?;
    after_snapshot_materialization(&private.path);

    let operation = inspect_private_sqlite_snapshot(
        &original, &canonical, &before, &opened, &private, store_name, inspect,
    );
    let cleanup = cleanup_private_sqlite_snapshot(private, store_name);
    finish_private_snapshot_operation(operation, cleanup, store_name)
}

fn finish_private_snapshot_operation<T>(
    operation: KataResult<T>,
    cleanup: KataResult<()>,
    store_name: &str,
) -> KataResult<T> {
    match (operation, cleanup) {
        (Ok(value), Ok(())) => Ok(value),
        (Err(error), Ok(())) => Err(error),
        (Ok(_), Err(cleanup_error)) => Err(cleanup_error),
        (Err(operation_error), Err(cleanup_error)) => Err(KataError::Storage(format!(
            "{store_name} immutable SQLite inspection failed: {operation_error}; additionally, private-snapshot cleanup failed: {cleanup_error}"
        ))),
    }
}

fn finish_private_snapshot_postcondition<T>(
    operation: KataResult<T>,
    postcondition: KataResult<()>,
    store_name: &str,
) -> KataResult<T> {
    match (operation, postcondition) {
        (Ok(value), Ok(())) => Ok(value),
        (Err(error), Ok(())) => Err(error),
        (Ok(_), Err(postcondition_error)) => Err(postcondition_error),
        (Err(operation_error), Err(postcondition_error)) => Err(KataError::Storage(format!(
            "{store_name} immutable SQLite callback failed: {operation_error}; additionally, post-inspection authority validation failed: {postcondition_error}"
        ))),
    }
}

fn immutable_open_flags() -> OpenFlags {
    OpenFlags::SQLITE_OPEN_READ_ONLY
        | OpenFlags::SQLITE_OPEN_URI
        | OpenFlags::SQLITE_OPEN_NO_MUTEX
        | OpenFlags::SQLITE_OPEN_NOFOLLOW
}

#[cfg(unix)]
fn open_immutable_sqlite_source(
    path: &Path,
    expected: &SqliteFileSnapshot,
    store_name: &str,
) -> KataResult<File> {
    let mut options = OpenOptions::new();
    options
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK);
    let file = options.open(path).map_err(|error| {
        KataError::Storage(format!(
            "{store_name} immutable SQLite inspection cannot adopt {}: {error}",
            path.display()
        ))
    })?;
    let opened = sqlite_file_snapshot_from_file(&file, store_name, path)?;
    if &opened != expected {
        return Err(KataError::Storage(format!(
            "{store_name} immutable SQLite source changed before descriptor adoption: {}",
            path.display()
        )));
    }
    Ok(file)
}

#[cfg(not(unix))]
fn open_immutable_sqlite_source(
    _path: &Path,
    _expected: &SqliteFileSnapshot,
    store_name: &str,
) -> KataResult<File> {
    Err(KataError::Storage(format!(
        "{store_name} immutable SQLite inspection is supported only on Kata's Unix hosts"
    )))
}

struct PrivateSqliteSnapshot {
    directory: DescriptorOwnedPrivateDirectory,
    path: PathBuf,
    file: File,
    file_identity: FileIdentity,
    len: u64,
}

struct DescriptorOwnedPrivateDirectory {
    coordinator: InspectionCoordinator,
    basename: String,
    path: PathBuf,
    handle: File,
    identity: FileIdentity,
    cleanup_armed: bool,
}

#[cfg(unix)]
struct InspectionCoordinator {
    temporary_root: TemporaryRootAuthority,
    path: PathBuf,
    handle: File,
    identity: FileIdentity,
    lock: File,
    lock_identity: FileIdentity,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct FileIdentity {
    #[cfg(unix)]
    dev: u64,
    #[cfg(unix)]
    ino: u64,
}

impl FileIdentity {
    fn from_snapshot(snapshot: &SqliteFileSnapshot) -> Self {
        Self {
            #[cfg(unix)]
            dev: snapshot.dev,
            #[cfg(unix)]
            ino: snapshot.ino,
        }
    }
}

#[cfg(unix)]
struct TemporaryRootAuthority {
    path: PathBuf,
    handle: File,
    identity: TemporaryRootIdentity,
    ancestors: Vec<BoundAncestorDirectory>,
}

#[cfg(unix)]
struct BoundAncestorDirectory {
    path: PathBuf,
    handle: File,
    identity: TemporaryRootIdentity,
}

#[cfg(not(unix))]
struct TemporaryRootAuthority;

#[cfg(not(unix))]
impl TemporaryRootAuthority {
    fn revalidate(&self, store_name: &str) -> KataResult<()> {
        Err(KataError::Storage(format!(
            "{store_name} immutable SQLite inspection is supported only on Kata's Unix hosts"
        )))
    }
}

fn run_materialization_hook(
    policy: &SnapshotMaterializationPolicy,
    checkpoint: MaterializationCheckpoint,
) {
    #[cfg(test)]
    if let Some(hook) = &policy.materialization_hook {
        hook(checkpoint);
    }

    #[cfg(not(test))]
    let _ = (policy, checkpoint);
}

#[cfg(unix)]
fn private_snapshot_coordinator_basename() -> String {
    format!(
        "kata-sqlite-inspection-uid-{}",
        rustix::process::geteuid().as_raw()
    )
}

/// Same-user inspections are legal and brief; a concurrent holder means
/// "serialize behind me", not "conflict". The bounded wait below turns
/// transient overlap (parallel tests, a CLI probe racing the main) into a
/// short wait; a holder still alive at the deadline yields the same
/// fail-closed refusal. Proof:
/// `concurrent_inspection_waits_for_coordinator_release`.
const COORDINATOR_CONTENTION_DEADLINE: std::time::Duration = std::time::Duration::from_secs(3);
const COORDINATOR_CONTENTION_POLL: std::time::Duration = std::time::Duration::from_millis(25);

#[cfg(unix)]
impl InspectionCoordinator {
    fn acquire(temporary_root: TemporaryRootAuthority, store_name: &str) -> KataResult<Self> {
        Self::acquire_with_contention_deadline(
            temporary_root,
            store_name,
            COORDINATOR_CONTENTION_DEADLINE,
        )
    }

    fn acquire_with_contention_deadline(
        temporary_root: TemporaryRootAuthority,
        store_name: &str,
        contention_deadline: std::time::Duration,
    ) -> KataResult<Self> {
        use std::os::unix::fs::PermissionsExt as _;

        temporary_root.revalidate(store_name)?;
        let basename = private_snapshot_coordinator_basename();
        let created = match rustix::fs::mkdirat(
            &temporary_root.handle,
            basename.as_str(),
            rustix::fs::Mode::RWXU,
        ) {
            Ok(()) => true,
            Err(error) if error == rustix::io::Errno::EXIST => false,
            Err(error) => {
                return Err(KataError::Storage(format!(
                    "{store_name} immutable SQLite inspection cannot create its owner-private coordinator: {error}"
                )));
            }
        };
        let path = temporary_root.path.join(&basename);
        let handle = rustix::fs::openat(
            &temporary_root.handle,
            basename.as_str(),
            rustix::fs::OFlags::RDONLY
                | rustix::fs::OFlags::DIRECTORY
                | rustix::fs::OFlags::NOFOLLOW
                | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        )
        .map(File::from)
        .map_err(|error| {
            KataError::Storage(format!(
                "{store_name} immutable SQLite inspection cannot bind owner-private coordinator {}: {error}",
                path.display()
            ))
        })?;
        if created {
            handle
                .set_permissions(std::fs::Permissions::from_mode(0o700))
                .map_err(|error| {
                    KataError::Storage(format!(
                        "{store_name} immutable SQLite inspection cannot secure coordinator {}: {error}",
                        path.display()
                    ))
                })?;
        }
        let identity = verify_private_directory(&path, None, store_name)?;
        if file_identity_from_file(&handle, store_name)? != identity {
            return Err(KataError::Storage(format!(
                "{store_name} immutable SQLite coordinator pathname and descriptor identities differ"
            )));
        }

        let lock_created = match rustix::fs::openat(
            &handle,
            PRIVATE_SNAPSHOT_COORDINATOR_LOCK,
            rustix::fs::OFlags::RDWR
                | rustix::fs::OFlags::CREATE
                | rustix::fs::OFlags::EXCL
                | rustix::fs::OFlags::NOFOLLOW
                | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR,
        ) {
            Ok(lock) => (File::from(lock), true),
            Err(error) if error == rustix::io::Errno::EXIST => {
                let lock = rustix::fs::openat(
                    &handle,
                    PRIVATE_SNAPSHOT_COORDINATOR_LOCK,
                    rustix::fs::OFlags::RDWR
                        | rustix::fs::OFlags::NOFOLLOW
                        | rustix::fs::OFlags::CLOEXEC,
                    rustix::fs::Mode::empty(),
                )
                .map(File::from)
                .map_err(|error| {
                    KataError::Storage(format!(
                        "{store_name} immutable SQLite inspection cannot bind its coordinator lock: {error}"
                    ))
                })?;
                (lock, false)
            }
            Err(error) => {
                return Err(KataError::Storage(format!(
                    "{store_name} immutable SQLite inspection cannot create its coordinator lock: {error}"
                )));
            }
        };
        let (lock, lock_created) = lock_created;
        if lock_created {
            lock.set_permissions(std::fs::Permissions::from_mode(0o600))
                .map_err(|error| {
                    KataError::Storage(format!(
                        "{store_name} immutable SQLite inspection cannot secure its coordinator lock: {error}"
                    ))
                })?;
        }
        let lock_identity = validate_coordinator_lock(&handle, &lock, store_name)?;
        let contention_deadline_at = std::time::Instant::now() + contention_deadline;
        loop {
            match rustix::fs::flock(&lock, rustix::fs::FlockOperation::NonBlockingLockExclusive) {
                Ok(()) => break,
                Err(error)
                    if error == rustix::io::Errno::WOULDBLOCK
                        && std::time::Instant::now() < contention_deadline_at =>
                {
                    std::thread::sleep(COORDINATOR_CONTENTION_POLL);
                }
                Err(error) => {
                    return Err(KataError::Storage(format!(
                        "{store_name} immutable SQLite inspection is already in progress for this operating-system user; nonblocking coordinator lock refused acquisition: {error}"
                    )));
                }
            }
        }

        let coordinator = Self {
            temporary_root,
            path,
            handle,
            identity,
            lock,
            lock_identity,
        };
        coordinator.revalidate(store_name)?;
        coordinator.sweep_stale_attempts(store_name)?;
        coordinator.revalidate(store_name)?;
        Ok(coordinator)
    }

    fn revalidate(&self, store_name: &str) -> KataResult<()> {
        self.temporary_root.revalidate(store_name)?;
        let observed = verify_private_directory(&self.path, Some(&self.identity), store_name)?;
        if observed != file_identity_from_file(&self.handle, store_name)? {
            return Err(KataError::Storage(format!(
                "{store_name} immutable SQLite coordinator descriptor identity changed"
            )));
        }
        let lock_identity = validate_coordinator_lock(&self.handle, &self.lock, store_name)?;
        if lock_identity != self.lock_identity {
            return Err(KataError::Storage(format!(
                "{store_name} immutable SQLite coordinator lock identity changed"
            )));
        }
        Ok(())
    }

    fn sweep_stale_attempts(&self, store_name: &str) -> KataResult<()> {
        let names = bounded_directory_names(
            &self.handle,
            PRIVATE_SNAPSHOT_MAX_COORDINATOR_ENTRIES,
            "coordinator",
            store_name,
        )?;
        for name in &names {
            if name == PRIVATE_SNAPSHOT_COORDINATOR_LOCK {
                continue;
            }
            if !is_strict_private_attempt_name(name) {
                return Err(KataError::Storage(format!(
                    "{store_name} immutable SQLite coordinator contains unknown entry {name:?}; preserving it and refusing inspection"
                )));
            }
        }
        for name in names {
            if name != PRIVATE_SNAPSHOT_COORDINATOR_LOCK {
                reap_stale_private_attempt(&self.handle, &self.path, &name, store_name)?;
            }
        }
        Ok(())
    }
}

#[cfg(unix)]
fn validate_coordinator_lock(
    coordinator: &File,
    lock: &File,
    store_name: &str,
) -> KataResult<FileIdentity> {
    use std::os::unix::fs::MetadataExt as _;

    let held = lock.metadata().map_err(|error| {
        KataError::Storage(format!(
            "{store_name} immutable SQLite inspection cannot inspect coordinator lock: {error}"
        ))
    })?;
    let named = rustix::fs::statat(
        coordinator,
        PRIVATE_SNAPSHOT_COORDINATOR_LOCK,
        rustix::fs::AtFlags::SYMLINK_NOFOLLOW,
    )
    .map_err(|error| {
        KataError::Storage(format!(
            "{store_name} immutable SQLite inspection cannot inspect coordinator-lock name: {error}"
        ))
    })?;
    let effective_uid = rustix::process::geteuid().as_raw();
    #[allow(clippy::useless_conversion)]
    let named_identity = FileIdentity {
        dev: u64::try_from(named.st_dev).map_err(|_| {
            KataError::Storage(format!(
                "{store_name} immutable SQLite coordinator-lock device identity is invalid"
            ))
        })?,
        ino: u64::try_from(named.st_ino).map_err(|_| {
            KataError::Storage(format!(
                "{store_name} immutable SQLite coordinator-lock inode identity is invalid"
            ))
        })?,
    };
    let held_identity = FileIdentity {
        dev: held.dev(),
        ino: held.ino(),
    };
    #[allow(clippy::useless_conversion)]
    let named_uid = u32::try_from(named.st_uid).map_err(|_| {
        KataError::Storage(format!(
            "{store_name} immutable SQLite coordinator-lock owner is invalid"
        ))
    })?;
    #[allow(clippy::useless_conversion)]
    let named_nlink = u64::try_from(named.st_nlink).map_err(|_| {
        KataError::Storage(format!(
            "{store_name} immutable SQLite coordinator-lock link count is invalid"
        ))
    })?;
    if !held.is_file()
        || named.st_mode & libc::S_IFMT != libc::S_IFREG
        || held.mode() & 0o7777 != 0o600
        || named.st_mode & 0o7777 != 0o600
        || held.uid() != effective_uid
        || named_uid != effective_uid
        || held.nlink() != 1
        || named_nlink != 1
        || held_identity != named_identity
    {
        return Err(KataError::Storage(format!(
            "{store_name} immutable SQLite coordinator lock must be the same effective-owner 0600 regular inode with exactly one link"
        )));
    }
    Ok(held_identity)
}

#[cfg(unix)]
fn bounded_directory_names(
    directory: &File,
    maximum: usize,
    label: &str,
    store_name: &str,
) -> KataResult<Vec<String>> {
    let entries = rustix::fs::Dir::read_from(directory).map_err(|error| {
        KataError::Storage(format!(
            "{store_name} immutable SQLite inspection cannot enumerate {label}: {error}"
        ))
    })?;
    let mut names = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|error| {
            KataError::Storage(format!(
                "{store_name} immutable SQLite inspection cannot enumerate {label}: {error}"
            ))
        })?;
        let bytes = entry.file_name().to_bytes();
        if bytes == b"." || bytes == b".." {
            continue;
        }
        if names.len() == maximum {
            return Err(KataError::Storage(format!(
                "{store_name} immutable SQLite {label} exceeds its bounded {maximum}-entry inspection limit; preserving entries"
            )));
        }
        names.push(std::str::from_utf8(bytes).map_err(|_| KataError::Storage(format!(
            "{store_name} immutable SQLite {label} contains a non-UTF-8 entry; preserving it and refusing inspection"
        )))?.to_owned());
    }
    Ok(names)
}

#[cfg(unix)]
fn is_strict_private_attempt_name(name: &str) -> bool {
    let Some(value) = name.strip_prefix(PRIVATE_SNAPSHOT_ATTEMPT_PREFIX) else {
        return false;
    };
    value.len() == 26 && value.bytes().all(|byte| {
        byte.is_ascii_digit()
            || matches!(byte, b'A'..=b'H' | b'J'..=b'K' | b'M'..=b'N' | b'P'..=b'T' | b'V'..=b'Z')
    }) && value.parse::<ulid::Ulid>().is_ok()
}

#[cfg(unix)]
fn reap_stale_private_attempt(
    coordinator: &File,
    coordinator_path: &Path,
    basename: &str,
    store_name: &str,
) -> KataResult<()> {
    let path = coordinator_path.join(basename);
    let handle = rustix::fs::openat(
        coordinator,
        basename,
        rustix::fs::OFlags::RDONLY
            | rustix::fs::OFlags::DIRECTORY
            | rustix::fs::OFlags::NOFOLLOW
            | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )
    .map(File::from)
    .map_err(|error| KataError::Storage(format!(
        "{store_name} immutable SQLite stale attempt {basename:?} is not a descriptor-bindable directory; preserving it: {error}"
    )))?;
    let identity = verify_private_directory(&path, None, store_name)?;
    if file_identity_from_file(&handle, store_name)? != identity {
        return Err(KataError::Storage(format!(
            "{store_name} immutable SQLite stale-attempt pathname and descriptor identities differ; preserving it"
        )));
    }
    let entry_names = bounded_directory_names(
        &handle,
        PRIVATE_SNAPSHOT_MAX_ATTEMPT_ENTRIES,
        "stale attempt",
        store_name,
    )?;
    if entry_names.iter().any(|name| name != PRIVATE_SNAPSHOT_NAME) {
        return Err(KataError::Storage(format!(
            "{store_name} immutable SQLite stale attempt contains an unknown entry; preserving it and refusing inspection"
        )));
    }
    if entry_names.iter().any(|name| name == PRIVATE_SNAPSHOT_NAME) {
        let file = rustix::fs::openat(
            &handle,
            PRIVATE_SNAPSHOT_NAME,
            rustix::fs::OFlags::RDONLY
                | rustix::fs::OFlags::NOFOLLOW
                | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        )
        .map(File::from)
        .map_err(|error| KataError::Storage(format!(
            "{store_name} immutable SQLite cannot bind stale private snapshot; preserving it: {error}"
        )))?;
        let snapshot = private_file_snapshot(&file, &path.join(PRIVATE_SNAPSHOT_NAME), store_name)?;
        validate_private_file_snapshot(
            &snapshot,
            None,
            snapshot.len,
            1,
            store_name,
            &path.join(PRIVATE_SNAPSHOT_NAME),
        )?;
        if snapshot.len > MAX_PRIVATE_SNAPSHOT_BYTES {
            return Err(KataError::Storage(format!(
                "{store_name} immutable SQLite stale snapshot exceeds the hard size bound; preserving it"
            )));
        }
        let named_metadata = rustix::fs::statat(
            &handle,
            PRIVATE_SNAPSHOT_NAME,
            rustix::fs::AtFlags::SYMLINK_NOFOLLOW,
        )
        .map_err(|error| KataError::Storage(format!(
            "{store_name} immutable SQLite cannot restat stale private snapshot; preserving it: {error}"
        )))?;
        #[allow(clippy::useless_conversion)]
        let named_identity = FileIdentity {
            dev: u64::try_from(named_metadata.st_dev).map_err(|_| {
                KataError::Storage(format!(
                    "{store_name} immutable SQLite stale snapshot device identity is invalid"
                ))
            })?,
            ino: u64::try_from(named_metadata.st_ino).map_err(|_| {
                KataError::Storage(format!(
                    "{store_name} immutable SQLite stale snapshot inode identity is invalid"
                ))
            })?,
        };
        if named_identity != FileIdentity::from_snapshot(&snapshot) {
            return Err(KataError::Storage(format!(
                "{store_name} immutable SQLite stale snapshot name was replaced; preserving it"
            )));
        }
        remove_bound_private_snapshot_if_present(&handle, store_name)?;
    }
    verify_bound_private_directory_empty(&handle, store_name)?;
    remove_bound_private_directory_name_if_empty(coordinator, basename, &identity, store_name)
}

#[cfg(unix)]
impl DescriptorOwnedPrivateDirectory {
    fn create(
        temporary_root: TemporaryRootAuthority,
        policy: &SnapshotMaterializationPolicy,
        store_name: &str,
    ) -> KataResult<Self> {
        use std::os::unix::fs::PermissionsExt as _;

        let coordinator = InspectionCoordinator::acquire(temporary_root, store_name)?;
        for _ in 0..32 {
            let basename = format!("{PRIVATE_SNAPSHOT_ATTEMPT_PREFIX}{}", ulid::Ulid::new());
            match rustix::fs::mkdirat(
                &coordinator.handle,
                basename.as_str(),
                rustix::fs::Mode::RWXU,
            ) {
                Ok(()) => {}
                Err(error) if error == rustix::io::Errno::EXIST => continue,
                Err(error) => {
                    return Err(KataError::Storage(format!(
                        "{store_name} immutable SQLite inspection cannot create descriptor-owned private directory: {error}"
                    )));
                }
            }

            let path = coordinator.path.join(&basename);
            let handle = rustix::fs::openat(
                &coordinator.handle,
                basename.as_str(),
                rustix::fs::OFlags::RDONLY
                    | rustix::fs::OFlags::DIRECTORY
                    | rustix::fs::OFlags::NOFOLLOW
                    | rustix::fs::OFlags::CLOEXEC,
                rustix::fs::Mode::empty(),
            )
            .map(File::from)
            .map_err(|error| {
                KataError::Storage(format!(
                    "{store_name} immutable SQLite inspection cannot bind descriptor-owned private directory {}: {error}",
                    path.display()
                ))
            });
            let handle = match handle {
                Ok(handle) => handle,
                Err(operation_error) => {
                    // Without a successfully bound descriptor Kata has no
                    // identity proof for this name. Preserve it for bounded
                    // next-owner inspection rather than unlink by basename.
                    return Err(operation_error);
                }
            };
            let identity = match file_identity_from_file(&handle, store_name) {
                Ok(identity) => identity,
                Err(operation_error) => {
                    return Err(operation_error);
                }
            };
            let directory = Self {
                coordinator,
                basename,
                path,
                handle,
                identity,
                cleanup_armed: true,
            };

            run_materialization_hook(
                policy,
                MaterializationCheckpoint::DirectoryCreatedBeforeFirstRevalidate,
            );
            let validation = (|| {
                directory
                    .handle
                    .set_permissions(std::fs::Permissions::from_mode(0o700))
                    .map_err(|error| {
                        KataError::Storage(format!(
                            "{store_name} immutable SQLite inspection cannot secure private directory {}: {error}",
                            directory.path.display()
                        ))
                    })?;
                directory.coordinator.revalidate(store_name)?;
                verify_private_directory(&directory.path, Some(&directory.identity), store_name)?;
                if file_identity_from_file(&directory.handle, store_name)? != directory.identity {
                    return Err(KataError::Storage(format!(
                        "{store_name} immutable SQLite private-directory descriptor identity changed immediately after creation"
                    )));
                }
                Ok(())
            })();
            if let Err(operation_error) = validation {
                let cleanup = directory.cleanup(store_name);
                return finish_private_snapshot_operation(
                    Err(operation_error),
                    cleanup,
                    store_name,
                );
            }
            return Ok(directory);
        }

        Err(KataError::Storage(format!(
            "{store_name} immutable SQLite inspection exhausted private-directory name attempts"
        )))
    }

    fn cleanup(mut self, store_name: &str) -> KataResult<()> {
        let snapshot_cleanup = remove_bound_private_snapshot_if_present(&self.handle, store_name);
        let empty_check = verify_bound_private_directory_empty(&self.handle, store_name);
        let directory_cleanup = remove_bound_private_directory_name_if_empty(
            &self.coordinator.handle,
            &self.basename,
            &self.identity,
            store_name,
        );
        let root_revalidation = self.coordinator.revalidate(store_name);
        // Explicit cleanup gets exactly one identity-gated basename attempt.
        // On mismatch or error, disarm Drop and preserve the held original;
        // never turn a cleanup failure into removal of an unproven replacement.
        self.cleanup_armed = false;

        let cleanup = finish_private_snapshot_operation(snapshot_cleanup, empty_check, store_name);
        let cleanup = finish_private_snapshot_operation(cleanup, directory_cleanup, store_name);
        finish_private_snapshot_operation(cleanup, root_revalidation, store_name)
    }
}

#[cfg(unix)]
impl Drop for DescriptorOwnedPrivateDirectory {
    fn drop(&mut self) {
        if !self.cleanup_armed {
            return;
        }
        let _ = rustix::fs::unlinkat(
            &self.handle,
            PRIVATE_SNAPSHOT_NAME,
            rustix::fs::AtFlags::empty(),
        );
        let _ = remove_bound_private_directory_name_if_empty(
            &self.coordinator.handle,
            &self.basename,
            &self.identity,
            "SQLite store",
        );
    }
}

#[cfg(unix)]
fn remove_bound_private_directory_name_if_empty(
    temporary_root: &File,
    basename: &str,
    expected_identity: &FileIdentity,
    store_name: &str,
) -> KataResult<()> {
    // `statat` followed by `unlinkat` cannot be one atomic Unix operation.
    // The held parent descriptor, no-follow lookup, expected identity, and
    // coordinator flock exclude accidental/Kata races. A non-cooperating
    // same-owner process can still exchange the name in this final interval;
    // that is an explicit same-owner trust residual, never a cross-owner one.
    let metadata = match rustix::fs::statat(
        temporary_root,
        basename,
        rustix::fs::AtFlags::SYMLINK_NOFOLLOW,
    ) {
        Ok(metadata) => metadata,
        Err(error) if error == rustix::io::Errno::NOENT => return Ok(()),
        Err(error) => {
            return Err(KataError::Storage(format!(
                "{store_name} immutable SQLite inspection cannot inspect descriptor-owned private-directory name: {error}"
            )));
        }
    };
    if metadata.st_mode & libc::S_IFMT != libc::S_IFDIR {
        return Err(KataError::Storage(format!(
            "{store_name} immutable SQLite private-directory name was replaced by a non-directory before cleanup"
        )));
    }
    #[allow(clippy::useless_conversion)]
    let observed = FileIdentity {
        dev: u64::try_from(metadata.st_dev).map_err(|_| {
            KataError::Storage(format!(
                "{store_name} immutable SQLite private-directory device identity is invalid"
            ))
        })?,
        ino: u64::try_from(metadata.st_ino).map_err(|_| {
            KataError::Storage(format!(
                "{store_name} immutable SQLite private-directory inode identity is invalid"
            ))
        })?,
    };
    if expected_identity != &observed {
        return Err(KataError::Storage(format!(
            "{store_name} immutable SQLite private-directory name was replaced before cleanup; refusing removal"
        )));
    }
    rustix::fs::unlinkat(
        temporary_root,
        basename,
        rustix::fs::AtFlags::REMOVEDIR,
    )
    .map_err(|error| {
        KataError::Storage(format!(
            "{store_name} immutable SQLite descriptor-relative private-directory cleanup failed without recursive traversal: {error}"
        ))
    })?;
    match rustix::fs::statat(
        temporary_root,
        basename,
        rustix::fs::AtFlags::SYMLINK_NOFOLLOW,
    ) {
        Err(error) if error == rustix::io::Errno::NOENT => Ok(()),
        Ok(_) => Err(KataError::Storage(format!(
            "{store_name} immutable SQLite private-directory name remained after descriptor-relative cleanup"
        ))),
        Err(error) => Err(KataError::Storage(format!(
            "{store_name} immutable SQLite cannot verify descriptor-relative private-directory cleanup: {error}"
        ))),
    }
}

#[cfg(unix)]
fn verify_bound_private_directory_empty(directory: &File, store_name: &str) -> KataResult<()> {
    let entries = rustix::fs::Dir::read_from(directory).map_err(|error| {
        KataError::Storage(format!(
            "{store_name} immutable SQLite inspection cannot enumerate held private directory: {error}"
        ))
    })?;
    for entry in entries {
        let entry = entry.map_err(|error| {
            KataError::Storage(format!(
                "{store_name} immutable SQLite inspection cannot enumerate held private directory: {error}"
            ))
        })?;
        let name = entry.file_name().to_bytes();
        if name != b"." && name != b".." {
            return Err(KataError::Storage(format!(
                "{store_name} immutable SQLite held private directory contains an unexpected entry after inspection"
            )));
        }
    }
    Ok(())
}

#[cfg(unix)]
#[derive(Debug, Clone, PartialEq, Eq)]
struct TemporaryRootIdentity {
    dev: u64,
    ino: u64,
    uid: u32,
    gid: u32,
    mode: u32,
}

#[cfg(unix)]
impl TemporaryRootAuthority {
    fn open(path: &Path, store_name: &str) -> KataResult<Self> {
        let path = path.canonicalize().map_err(|error| {
            KataError::Storage(format!(
                "{store_name} immutable SQLite inspection cannot resolve temporary root {}: {error}",
                path.display()
            ))
        })?;
        let mut chain = bind_canonical_directory_chain(&path, store_name)?;
        let leaf = chain.pop().expect("absolute directory chain has a root");
        let handle = leaf.handle;
        let identity = leaf.identity;
        validate_temporary_root_posture(&identity, store_name, &path)?;
        let authority = Self {
            path,
            handle,
            identity,
            ancestors: chain,
        };
        authority.revalidate(store_name)?;
        Ok(authority)
    }

    fn revalidate(&self, store_name: &str) -> KataResult<()> {
        for ancestor in &self.ancestors {
            let observed = bound_directory_identity(&ancestor.path, &ancestor.handle, store_name)?;
            validate_temporary_ancestor_posture(&observed, store_name, &ancestor.path)?;
            if observed != ancestor.identity {
                return Err(KataError::Storage(format!(
                    "{store_name} immutable SQLite temporary-root ancestor identity changed at {}",
                    ancestor.path.display()
                )));
            }
        }

        let observed = bound_directory_identity(&self.path, &self.handle, store_name)?;
        validate_temporary_root_posture(&observed, store_name, &self.path)?;
        if observed != self.identity {
            return Err(KataError::Storage(format!(
                "{store_name} immutable SQLite temporary-root identity changed at {}",
                self.path.display()
            )));
        }
        Ok(())
    }
}

#[cfg(unix)]
fn bind_canonical_directory_chain(
    path: &Path,
    store_name: &str,
) -> KataResult<Vec<BoundAncestorDirectory>> {
    use std::path::Component;

    let flags = rustix::fs::OFlags::RDONLY
        | rustix::fs::OFlags::DIRECTORY
        | rustix::fs::OFlags::NOFOLLOW
        | rustix::fs::OFlags::CLOEXEC;
    let root = rustix::fs::open("/", flags, rustix::fs::Mode::empty()).map_err(|error| {
        KataError::Storage(format!(
            "{store_name} immutable SQLite inspection cannot bind filesystem root: {error}"
        ))
    })?;
    let mut chain = Vec::new();
    let mut current_path = PathBuf::from("/");
    let root_file = File::from(root);
    let root_identity = bound_directory_identity(&current_path, &root_file, store_name)?;
    validate_temporary_ancestor_posture(&root_identity, store_name, &current_path)?;
    chain.push(BoundAncestorDirectory {
        path: current_path.clone(),
        handle: root_file,
        identity: root_identity,
    });

    for component in path.components() {
        let Component::Normal(component) = component else {
            continue;
        };
        let parent = &chain.last().expect("root is bound").handle;
        let child = rustix::fs::openat(parent, component, flags, rustix::fs::Mode::empty())
            .map_err(|error| {
                KataError::Storage(format!(
                    "{store_name} immutable SQLite inspection cannot bind temporary-root component {}: {error}",
                    current_path.join(component).display()
                ))
            })?;
        current_path.push(component);
        let child = File::from(child);
        let identity = bound_directory_identity(&current_path, &child, store_name)?;
        chain.push(BoundAncestorDirectory {
            path: current_path.clone(),
            handle: child,
            identity,
        });
    }
    if current_path != path {
        return Err(KataError::Storage(format!(
            "{store_name} immutable SQLite temporary-root binding did not resolve the requested path {}",
            path.display()
        )));
    }
    Ok(chain)
}

#[cfg(unix)]
fn bound_directory_identity(
    path: &Path,
    handle: &File,
    store_name: &str,
) -> KataResult<TemporaryRootIdentity> {
    use std::os::unix::fs::MetadataExt as _;

    let held = handle.metadata().map_err(|error| {
        KataError::Storage(format!(
            "{store_name} immutable SQLite inspection cannot inspect bound directory {}: {error}",
            path.display()
        ))
    })?;
    let pathname = std::fs::symlink_metadata(path).map_err(|error| {
        KataError::Storage(format!(
            "{store_name} immutable SQLite bound-directory pathname changed at {}: {error}",
            path.display()
        ))
    })?;
    if !held.is_dir() || pathname.file_type().is_symlink() || !pathname.is_dir() {
        return Err(KataError::Storage(format!(
            "{store_name} immutable SQLite bound-directory pathname is not a real directory: {}",
            path.display()
        )));
    }
    let snapshot = |metadata: &std::fs::Metadata| TemporaryRootIdentity {
        dev: metadata.dev(),
        ino: metadata.ino(),
        uid: metadata.uid(),
        gid: metadata.gid(),
        mode: metadata.mode(),
    };
    let held = snapshot(&held);
    let pathname = snapshot(&pathname);
    if held != pathname {
        return Err(KataError::Storage(format!(
            "{store_name} immutable SQLite bound-directory identity changed at {}",
            path.display()
        )));
    }
    Ok(held)
}

#[cfg(unix)]
fn validate_temporary_ancestor_posture(
    identity: &TemporaryRootIdentity,
    store_name: &str,
    path: &Path,
) -> KataResult<()> {
    let permissions = identity.mode & 0o7777;
    let effective_uid = rustix::process::geteuid().as_raw();
    if identity.uid != effective_uid && identity.uid != 0 {
        return Err(KataError::Storage(format!(
            "{store_name} immutable SQLite inspection refuses temporary-root ancestor {} owned by untrusted uid {} (effective uid {effective_uid})",
            path.display(),
            identity.uid
        )));
    }
    let non_owner_writable = permissions & 0o022 != 0;
    let root_sticky_shared =
        identity.uid == 0 && permissions & libc::S_ISVTX != 0 && permissions & 0o022 != 0;
    if non_owner_writable && !root_sticky_shared {
        return Err(KataError::Storage(format!(
            "{store_name} immutable SQLite inspection refuses unsafe temporary-root ancestor {} (uid {}, mode {:04o})",
            path.display(),
            identity.uid,
            permissions
        )));
    }
    Ok(())
}

#[cfg(unix)]
fn validate_temporary_root_posture(
    identity: &TemporaryRootIdentity,
    store_name: &str,
    path: &Path,
) -> KataResult<()> {
    let permissions = identity.mode & 0o7777;
    let effective_uid = rustix::process::geteuid().as_raw();
    let owner_only = identity.uid == effective_uid && permissions.trailing_zeros() >= 6;
    let root_sticky_shared =
        identity.uid == 0 && permissions & libc::S_ISVTX != 0 && permissions & 0o022 != 0;
    if !owner_only && !root_sticky_shared {
        return Err(KataError::Storage(format!(
            "{store_name} immutable SQLite inspection refuses unsafe temporary root {} (uid {}, mode {:04o}); require an effective-owner-only directory or a root-owned sticky shared directory",
            path.display(),
            identity.uid,
            permissions
        )));
    }
    Ok(())
}

#[cfg(unix)]
fn materialize_private_sqlite_snapshot(
    source: &mut File,
    expected: &SqliteFileSnapshot,
    store_name: &str,
    policy: &SnapshotMaterializationPolicy,
) -> KataResult<PrivateSqliteSnapshot> {
    use std::os::unix::fs::PermissionsExt as _;

    if expected.len > MAX_PRIVATE_SNAPSHOT_BYTES {
        return Err(KataError::Storage(format!(
            "{store_name} immutable SQLite source size {} exceeds the private-snapshot maximum {MAX_PRIVATE_SNAPSHOT_BYTES}",
            expected.len
        )));
    }
    let temporary_root_path = policy
        .temporary_root
        .clone()
        .unwrap_or_else(std::env::temp_dir);
    let temporary_root = TemporaryRootAuthority::open(&temporary_root_path, store_name)?;
    let directory = DescriptorOwnedPrivateDirectory::create(temporary_root, policy, store_name)?;
    run_materialization_hook(policy, MaterializationCheckpoint::PrivateDirectoryOpened);

    let materialization = (|| {
        directory.coordinator.revalidate(store_name)?;
        let path = directory.path.join(PRIVATE_SNAPSHOT_NAME);
        let (mut file, cloned) =
            create_private_snapshot_file(source, &directory.handle, &path, store_name, policy)?;
        file.set_permissions(std::fs::Permissions::from_mode(0o600))
            .map_err(|error| {
                KataError::Storage(format!(
                    "{store_name} immutable SQLite inspection cannot secure private snapshot {}: {error}",
                    path.display()
                ))
            })?;

        let initial = private_file_snapshot(&file, &path, store_name)?;
        validate_private_file_snapshot(
            &initial,
            None,
            if cloned { expected.len } else { 0 },
            1,
            store_name,
            &path,
        )?;
        let file_identity = FileIdentity::from_snapshot(&initial);

        if !cloned {
            ensure_private_snapshot_capacity(&file, expected.len, policy, store_name)?;
            copy_private_snapshot_bounded(source, &mut file, expected.len, policy, store_name)?;
        }

        file.flush().map_err(|error| {
            KataError::Storage(format!(
                "{store_name} immutable SQLite inspection cannot flush private snapshot {}: {error}",
                path.display()
            ))
        })?;

        run_materialization_hook(policy, MaterializationCheckpoint::FinalVerify);
        verify_private_snapshot_path(&path, &file, &file_identity, expected.len, store_name)?;
        verify_private_directory(&directory.path, Some(&directory.identity), store_name)?;
        if file_identity_from_file(&directory.handle, store_name)? != directory.identity {
            return Err(KataError::Storage(format!(
                "{store_name} immutable SQLite private-directory descriptor identity changed during materialization"
            )));
        }
        directory.coordinator.revalidate(store_name)?;
        Ok((path, file, file_identity))
    })();

    match materialization {
        Ok((path, file, file_identity)) => Ok(PrivateSqliteSnapshot {
            directory,
            path,
            file,
            file_identity,
            len: expected.len,
        }),
        Err(operation_error) => {
            let cleanup = directory.cleanup(store_name);
            finish_private_snapshot_operation(Err(operation_error), cleanup, store_name)
        }
    }
}

#[cfg(unix)]
fn create_empty_private_snapshot(
    directory: &File,
    path: &Path,
    store_name: &str,
) -> KataResult<File> {
    let flags = rustix::fs::OFlags::RDWR
        | rustix::fs::OFlags::CREATE
        | rustix::fs::OFlags::EXCL
        | rustix::fs::OFlags::NOFOLLOW
        | rustix::fs::OFlags::CLOEXEC;
    rustix::fs::openat(
        directory,
        PRIVATE_SNAPSHOT_NAME,
        flags,
        rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR,
    )
    .map(File::from)
    .map_err(|error| {
        KataError::Storage(format!(
            "{store_name} immutable SQLite inspection cannot create private snapshot {}: {error}",
            path.display()
        ))
    })
}

#[cfg(target_os = "linux")]
fn create_private_snapshot_file(
    source: &File,
    directory: &File,
    path: &Path,
    store_name: &str,
    policy: &SnapshotMaterializationPolicy,
) -> KataResult<(File, bool)> {
    let file = create_empty_private_snapshot(directory, path, store_name)?;
    if policy.force_copy {
        return Ok((file, false));
    }
    let error = match attempt_linux_private_snapshot_clone(&file, source, policy) {
        Ok(()) => return Ok((file, true)),
        Err(error) => error,
    };
    if clone_fallback_allowed(&error) {
        file.set_len(0).map_err(|reset_error| {
            KataError::Storage(format!(
                "{store_name} immutable SQLite inspection cannot reset unsupported reflink destination {}: {reset_error}",
                path.display()
            ))
        })?;
        Ok((file, false))
    } else {
        Err(KataError::Storage(format!(
            "{store_name} immutable SQLite descriptor reflink failed for {}: {error}",
            path.display()
        )))
    }
}

#[cfg(target_os = "linux")]
fn attempt_linux_private_snapshot_clone(
    destination: &File,
    source: &File,
    policy: &SnapshotMaterializationPolicy,
) -> std::io::Result<()> {
    #[cfg(test)]
    match policy.clone_outcome {
        TestCloneOutcome::System => {}
        TestCloneOutcome::Success => return simulate_descriptor_clone(source, destination),
        TestCloneOutcome::Error {
            errno,
            leave_partial_destination,
        } => {
            if leave_partial_destination {
                let source_len = source.metadata()?.len();
                destination.set_len(source_len.saturating_add(17))?;
            }
            return Err(std::io::Error::from_raw_os_error(errno));
        }
    }

    #[cfg(not(test))]
    let _ = policy;

    rustix::fs::ioctl_ficlone(destination, source)
        .map_err(|error| std::io::Error::from_raw_os_error(error.raw_os_error()))
}

#[cfg(all(test, unix))]
fn simulate_descriptor_clone(source: &File, destination: &File) -> std::io::Result<()> {
    use std::os::unix::fs::FileExt as _;

    let len = source.metadata()?.len();
    destination.set_len(len)?;
    let mut offset = 0_u64;
    let mut buffer = vec![0_u8; PRIVATE_SNAPSHOT_COPY_CHUNK_BYTES];
    while offset < len {
        let limit = usize::try_from((len - offset).min(buffer.len() as u64))
            .expect("clone test chunk is bounded by usize");
        let read = source.read_at(&mut buffer[..limit], offset)?;
        if read == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "simulated descriptor clone source shortened",
            ));
        }
        destination.write_all_at(&buffer[..read], offset)?;
        offset += read as u64;
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn create_private_snapshot_file(
    source: &File,
    directory: &File,
    path: &Path,
    store_name: &str,
    policy: &SnapshotMaterializationPolicy,
) -> KataResult<(File, bool)> {
    if !policy.force_copy {
        #[cfg(test)]
        if policy.clone_outcome == TestCloneOutcome::Success {
            let file = create_empty_private_snapshot(directory, path, store_name)?;
            simulate_descriptor_clone(source, &file).map_err(|error| {
                KataError::Storage(format!(
                    "{store_name} immutable SQLite simulated descriptor clone failed for {}: {error}",
                    path.display()
                ))
            })?;
            return Ok((file, true));
        }

        #[cfg(test)]
        let clone = match policy.clone_outcome {
            TestCloneOutcome::Error {
                errno,
                leave_partial_destination,
            } => {
                if leave_partial_destination {
                    let partial = create_empty_private_snapshot(directory, path, store_name)?;
                    partial
                        .set_len(source.metadata().map_err(|error| {
                            KataError::Storage(format!(
                                "{store_name} immutable SQLite cannot size simulated partial clone: {error}"
                            ))
                        })?.len().saturating_add(17))
                        .map_err(|error| {
                            KataError::Storage(format!(
                                "{store_name} immutable SQLite cannot create simulated partial clone: {error}"
                            ))
                        })?;
                }
                Err(std::io::Error::from_raw_os_error(errno))
            }
            TestCloneOutcome::System | TestCloneOutcome::Success => rustix::fs::fclonefileat(
                source,
                directory,
                PRIVATE_SNAPSHOT_NAME,
                rustix::fs::CloneFlags::NOFOLLOW | rustix::fs::CloneFlags::NOOWNERCOPY,
            )
            .map_err(std::io::Error::from),
        };
        #[cfg(not(test))]
        let clone = rustix::fs::fclonefileat(
            source,
            directory,
            PRIVATE_SNAPSHOT_NAME,
            rustix::fs::CloneFlags::NOFOLLOW | rustix::fs::CloneFlags::NOOWNERCOPY,
        )
        .map_err(std::io::Error::from);
        if clone.is_ok() {
            let file = rustix::fs::openat(
                directory,
                PRIVATE_SNAPSHOT_NAME,
                rustix::fs::OFlags::RDONLY
                    | rustix::fs::OFlags::NOFOLLOW
                    | rustix::fs::OFlags::CLOEXEC,
                rustix::fs::Mode::empty(),
            )
                .map(File::from)
                .map_err(|error| {
                    KataError::Storage(format!(
                        "{store_name} immutable SQLite inspection cannot open cloned private snapshot {}: {error}",
                        path.display()
                    ))
                })?;
            return Ok((file, true));
        }
        let error = clone.expect_err("checked clone error");
        if !clone_fallback_allowed(&error) {
            return Err(KataError::Storage(format!(
                "{store_name} immutable SQLite descriptor clone failed for {}: {error}",
                path.display()
            )));
        }
        match rustix::fs::unlinkat(
            directory,
            PRIVATE_SNAPSHOT_NAME,
            rustix::fs::AtFlags::empty(),
        ) {
            Ok(()) => {}
            Err(remove_error) if remove_error == rustix::io::Errno::NOENT => {}
            Err(remove_error) => {
                return Err(KataError::Storage(format!(
                    "{store_name} immutable SQLite inspection cannot clear failed clone destination {}: {remove_error}",
                    path.display()
                )));
            }
        }
    }
    create_empty_private_snapshot(directory, path, store_name).map(|file| (file, false))
}

#[cfg(all(unix, not(any(target_os = "linux", target_os = "macos"))))]
fn create_private_snapshot_file(
    _source: &File,
    directory: &File,
    path: &Path,
    store_name: &str,
    _policy: &SnapshotMaterializationPolicy,
) -> KataResult<(File, bool)> {
    create_empty_private_snapshot(directory, path, store_name).map(|file| (file, false))
}

#[cfg(unix)]
fn clone_fallback_allowed(error: &std::io::Error) -> bool {
    matches!(
        error.raw_os_error(),
        Some(libc::EOPNOTSUPP | libc::ENOTTY | libc::EXDEV | libc::EINVAL | libc::ENOSYS)
    )
}

#[cfg(unix)]
fn private_snapshot_copy_progress_timeout(
    len: u64,
    policy: &SnapshotMaterializationPolicy,
) -> Duration {
    if let Some(timeout) = policy.copy_progress_timeout {
        return timeout;
    }
    let seconds = len.saturating_add(PRIVATE_SNAPSHOT_MIN_COPY_RATE_BYTES_PER_SECOND - 1)
        / PRIVATE_SNAPSHOT_MIN_COPY_RATE_BYTES_PER_SECOND;
    Duration::from_secs(seconds)
        .max(PRIVATE_SNAPSHOT_MIN_COPY_PROGRESS_TIMEOUT)
        .min(PRIVATE_SNAPSHOT_MAX_COPY_PROGRESS_TIMEOUT)
}

#[cfg(unix)]
fn ensure_private_snapshot_capacity(
    destination: &File,
    len: u64,
    policy: &SnapshotMaterializationPolicy,
    store_name: &str,
) -> KataResult<()> {
    let available = if let Some(available) = policy.available_bytes {
        available
    } else {
        let stats = rustix::fs::fstatvfs(destination).map_err(|error| {
            KataError::Storage(format!(
                "{store_name} immutable SQLite inspection cannot measure private-snapshot capacity: {error}"
            ))
        })?;
        stats.f_bavail.saturating_mul(stats.f_frsize)
    };
    let proportional = (len / 100).min(PRIVATE_SNAPSHOT_MAX_HEADROOM_BYTES);
    let headroom = PRIVATE_SNAPSHOT_MIN_HEADROOM_BYTES.max(proportional);
    let required = len.checked_add(headroom).ok_or_else(|| {
        KataError::Storage(format!(
            "{store_name} immutable SQLite private-snapshot capacity requirement overflowed"
        ))
    })?;
    if available < required {
        return Err(KataError::Storage(format!(
            "{store_name} immutable SQLite private-snapshot fallback requires {required} available bytes (database {len} plus {headroom} safety headroom), but only {available} are available"
        )));
    }
    Ok(())
}

#[cfg(unix)]
fn copy_private_snapshot_bounded(
    source: &mut File,
    destination: &mut File,
    expected_len: u64,
    policy: &SnapshotMaterializationPolicy,
    store_name: &str,
) -> KataResult<()> {
    source.rewind().map_err(|error| {
        KataError::Storage(format!(
            "{store_name} immutable SQLite inspection cannot rewind the adopted source: {error}"
        ))
    })?;
    destination.rewind().map_err(|error| {
        KataError::Storage(format!(
            "{store_name} immutable SQLite inspection cannot rewind its private snapshot: {error}"
        ))
    })?;
    let progress_deadline = Instant::now()
        .checked_add(private_snapshot_copy_progress_timeout(expected_len, policy))
        .ok_or_else(|| {
            KataError::Storage(format!(
                "{store_name} immutable SQLite private-snapshot progress deadline overflowed"
            ))
        })?;
    let mut remaining = expected_len;
    let mut copied = 0_u64;
    let mut mid_copy_hook_ran = false;
    let mut buffer = vec![0_u8; PRIVATE_SNAPSHOT_COPY_CHUNK_BYTES];
    while remaining > 0 {
        if Instant::now() >= progress_deadline {
            return Err(KataError::Storage(format!(
                "{store_name} immutable SQLite private-snapshot fallback exceeded its cooperative size-derived progress deadline between local-filesystem calls after {copied} of {expected_len} bytes"
            )));
        }
        let limit = usize::try_from(remaining.min(buffer.len() as u64))
            .expect("copy chunk is bounded by usize");
        let read = source.read(&mut buffer[..limit]).map_err(|error| {
            KataError::Storage(format!(
                "{store_name} immutable SQLite inspection cannot read adopted source: {error}"
            ))
        })?;
        if read == 0 {
            return Err(KataError::Storage(format!(
                "{store_name} immutable SQLite source shortened during private snapshot materialization: expected {expected_len} bytes, copied {copied}"
            )));
        }
        write_private_snapshot_chunk_bounded(
            destination,
            &buffer[..read],
            progress_deadline,
            &mut copied,
            &mut remaining,
            expected_len,
            store_name,
        )?;
        if !mid_copy_hook_ran {
            mid_copy_hook_ran = true;
            run_materialization_hook(policy, MaterializationCheckpoint::MidCopy);
        }
    }
    let mut excess = [0_u8; 1];
    if source.read(&mut excess).map_err(|error| {
        KataError::Storage(format!(
            "{store_name} immutable SQLite inspection cannot bound the adopted source length: {error}"
        ))
    })? != 0
    {
        return Err(KataError::Storage(format!(
            "{store_name} immutable SQLite source grew during private snapshot materialization"
        )));
    }
    if Instant::now() >= progress_deadline {
        return Err(KataError::Storage(format!(
            "{store_name} immutable SQLite private-snapshot fallback exceeded its cooperative size-derived progress deadline between local-filesystem calls after {copied} bytes"
        )));
    }
    Ok(())
}

#[cfg(unix)]
fn write_private_snapshot_chunk_bounded(
    destination: &mut impl std::io::Write,
    bytes: &[u8],
    progress_deadline: Instant,
    copied: &mut u64,
    remaining: &mut u64,
    expected_len: u64,
    store_name: &str,
) -> KataResult<()> {
    let mut written = 0;
    while written < bytes.len() {
        if Instant::now() >= progress_deadline {
            return Err(KataError::Storage(format!(
                "{store_name} immutable SQLite private-snapshot fallback exceeded its cooperative size-derived progress deadline between partial-write calls after {copied} of {expected_len} bytes"
            )));
        }
        match destination.write(&bytes[written..]) {
            Ok(0) => {
                return Err(KataError::Storage(format!(
                    "{store_name} immutable SQLite private-snapshot destination made zero write progress after {copied} of {expected_len} bytes"
                )));
            }
            Ok(count) => {
                written += count;
                *copied += count as u64;
                *remaining -= count as u64;
            }
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(error) => {
                return Err(KataError::Storage(format!(
                    "{store_name} immutable SQLite inspection cannot materialize its private snapshot: {error}"
                )));
            }
        }
    }
    Ok(())
}

#[cfg(not(unix))]
fn materialize_private_sqlite_snapshot(
    _source: &mut File,
    _expected: &SqliteFileSnapshot,
    store_name: &str,
    _policy: &SnapshotMaterializationPolicy,
) -> KataResult<PrivateSqliteSnapshot> {
    Err(KataError::Storage(format!(
        "{store_name} immutable SQLite inspection is supported only on Kata's Unix hosts"
    )))
}

fn inspect_private_sqlite_snapshot<T>(
    original: &Path,
    canonical: &Path,
    expected: &SqliteFileSnapshot,
    source: &File,
    private: &PrivateSqliteSnapshot,
    store_name: &str,
    inspect: impl FnOnce(&Connection) -> KataResult<T>,
) -> KataResult<Option<T>> {
    private.directory.coordinator.revalidate(store_name)?;
    revalidate_immutable_source(original, canonical, expected, source, store_name)?;
    verify_private_snapshot_path(
        &private.path,
        &private.file,
        &private.file_identity,
        private.len,
        store_name,
    )?;
    verify_private_directory(
        &private.directory.path,
        Some(&private.directory.identity),
        store_name,
    )?;
    verify_private_directory_handle(private, store_name)?;
    private.directory.coordinator.revalidate(store_name)?;

    let uri = immutable_sqlite_uri(&private.path, store_name)?;
    let connection = Connection::open_with_flags(uri, immutable_open_flags()).map_err(|error| {
        KataError::Storage(format!(
            "{store_name} immutable SQLite private-snapshot open failed for {}: {error}",
            original.display()
        ))
    })?;
    private.directory.coordinator.revalidate(store_name)?;

    // Recheck the held file and pathname after SQLite's pathname-based open,
    // then unlink it. Both SQLite and Kata retain open descriptors, while no
    // pathname remains for a later reopen or replacement.
    verify_private_snapshot_path(
        &private.path,
        &private.file,
        &private.file_identity,
        private.len,
        store_name,
    )?;
    unlink_private_snapshot(private, store_name)?;
    reject_existing_path(&private.path, store_name)?;
    let unlinked = private_file_snapshot(&private.file, &private.path, store_name)?;
    validate_private_file_snapshot(
        &unlinked,
        Some(&private.file_identity),
        private.len,
        0,
        store_name,
        &private.path,
    )?;
    private.directory.coordinator.revalidate(store_name)?;

    let result = inspect(&connection);
    drop(connection);

    // A concurrent writer, link, sidecar, or pathname replacement makes the
    // observation ambiguous even when the callback happened to succeed.
    let postcondition = (|| {
        revalidate_immutable_source(original, canonical, expected, source, store_name)?;
        verify_private_directory_empty(private, store_name)?;
        private.directory.coordinator.revalidate(store_name)
    })();
    finish_private_snapshot_postcondition(result.map(Some), postcondition, store_name)
}

#[cfg(unix)]
fn unlink_private_snapshot(private: &PrivateSqliteSnapshot, store_name: &str) -> KataResult<()> {
    rustix::fs::unlinkat(
        &private.directory.handle,
        PRIVATE_SNAPSHOT_NAME,
        rustix::fs::AtFlags::empty(),
    )
    .map_err(|error| {
        KataError::Storage(format!(
            "{store_name} immutable SQLite inspection cannot unlink private snapshot {}: {error}",
            private.path.display()
        ))
    })?;
    reject_bound_private_snapshot_path(&private.directory.handle, store_name)
}

#[cfg(unix)]
fn reject_bound_private_snapshot_path(directory: &File, store_name: &str) -> KataResult<()> {
    match rustix::fs::statat(
        directory,
        PRIVATE_SNAPSHOT_NAME,
        rustix::fs::AtFlags::SYMLINK_NOFOLLOW,
    ) {
        Err(error) if error == rustix::io::Errno::NOENT => Ok(()),
        Ok(_) => Err(KataError::Storage(format!(
            "{store_name} immutable SQLite private snapshot remained reachable after descriptor-relative unlink"
        ))),
        Err(error) => Err(KataError::Storage(format!(
            "{store_name} immutable SQLite inspection cannot verify descriptor-relative snapshot removal: {error}"
        ))),
    }
}

#[cfg(unix)]
fn remove_bound_private_snapshot_if_present(directory: &File, store_name: &str) -> KataResult<()> {
    match rustix::fs::unlinkat(
        directory,
        PRIVATE_SNAPSHOT_NAME,
        rustix::fs::AtFlags::empty(),
    ) {
        Ok(()) => reject_bound_private_snapshot_path(directory, store_name),
        Err(error) if error == rustix::io::Errno::NOENT => Ok(()),
        Err(error) => Err(KataError::Storage(format!(
            "{store_name} immutable SQLite descriptor-relative private-snapshot cleanup failed: {error}"
        ))),
    }
}

#[cfg(not(unix))]
fn remove_bound_private_snapshot_if_present(_directory: &File, store_name: &str) -> KataResult<()> {
    Err(KataError::Storage(format!(
        "{store_name} immutable SQLite inspection is supported only on Kata's Unix hosts"
    )))
}

#[cfg(not(unix))]
fn unlink_private_snapshot(_private: &PrivateSqliteSnapshot, store_name: &str) -> KataResult<()> {
    Err(KataError::Storage(format!(
        "{store_name} immutable SQLite inspection is supported only on Kata's Unix hosts"
    )))
}

fn cleanup_private_sqlite_snapshot(
    private: PrivateSqliteSnapshot,
    store_name: &str,
) -> KataResult<()> {
    let PrivateSqliteSnapshot {
        directory, file, ..
    } = private;
    drop(file);
    directory.cleanup(store_name)
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SqliteFileSnapshot {
    len: u64,
    modified: Option<std::time::SystemTime>,
    #[cfg(unix)]
    dev: u64,
    #[cfg(unix)]
    ino: u64,
    #[cfg(unix)]
    mode: u32,
    #[cfg(unix)]
    nlink: u64,
    #[cfg(unix)]
    uid: u32,
    #[cfg(unix)]
    gid: u32,
    #[cfg(unix)]
    mtime: i64,
    #[cfg(unix)]
    mtime_nsec: i64,
    #[cfg(unix)]
    ctime: i64,
    #[cfg(unix)]
    ctime_nsec: i64,
}

fn sqlite_file_snapshot(path: &Path, store_name: &str) -> KataResult<SqliteFileSnapshot> {
    let metadata = std::fs::symlink_metadata(path).map_err(|error| {
        KataError::Storage(format!(
            "{store_name} immutable SQLite inspection cannot stat {}: {error}",
            path.display()
        ))
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(KataError::Storage(format!(
            "{store_name} immutable SQLite inspection requires a stable regular file at {}",
            path.display()
        )));
    }

    let snapshot = sqlite_file_snapshot_from_metadata(metadata);
    validate_source_snapshot(&snapshot, store_name, path)?;
    Ok(snapshot)
}

fn sqlite_file_snapshot_from_file(
    file: &File,
    store_name: &str,
    display_path: &Path,
) -> KataResult<SqliteFileSnapshot> {
    let metadata = file.metadata().map_err(|error| {
        KataError::Storage(format!(
            "{store_name} immutable SQLite inspection cannot inspect adopted descriptor for {}: {error}",
            display_path.display()
        ))
    })?;
    if !metadata.is_file() {
        return Err(KataError::Storage(format!(
            "{store_name} immutable SQLite inspection adopted a non-regular source at {}",
            display_path.display()
        )));
    }

    let snapshot = sqlite_file_snapshot_from_metadata(metadata);
    validate_source_snapshot(&snapshot, store_name, display_path)?;
    Ok(snapshot)
}

fn sqlite_file_snapshot_from_metadata(metadata: std::fs::Metadata) -> SqliteFileSnapshot {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;

        SqliteFileSnapshot {
            len: metadata.len(),
            modified: metadata.modified().ok(),
            dev: metadata.dev(),
            ino: metadata.ino(),
            mode: metadata.mode(),
            nlink: metadata.nlink(),
            uid: metadata.uid(),
            gid: metadata.gid(),
            mtime: metadata.mtime(),
            mtime_nsec: metadata.mtime_nsec(),
            ctime: metadata.ctime(),
            ctime_nsec: metadata.ctime_nsec(),
        }
    }

    #[cfg(not(unix))]
    {
        SqliteFileSnapshot {
            len: metadata.len(),
            modified: metadata.modified().ok(),
        }
    }
}

fn validate_source_snapshot(
    snapshot: &SqliteFileSnapshot,
    store_name: &str,
    path: &Path,
) -> KataResult<()> {
    #[cfg(unix)]
    if snapshot.nlink != 1 {
        return Err(KataError::Storage(format!(
            "{store_name} immutable SQLite inspection requires exactly one source link at {}; hard links can hide journal or WAL authority under another filename",
            path.display()
        )));
    }
    Ok(())
}

fn revalidate_immutable_source(
    original: &Path,
    canonical: &Path,
    expected: &SqliteFileSnapshot,
    source: &File,
    store_name: &str,
) -> KataResult<()> {
    reject_sqlite_sidecars(original, store_name)?;
    reject_sqlite_sidecars(canonical, store_name)?;
    let recanonicalized = original.canonicalize().map_err(|error| {
        KataError::Storage(format!(
            "{store_name} immutable SQLite source changed during inspection at {}: {error}",
            original.display()
        ))
    })?;
    if recanonicalized != canonical {
        return Err(KataError::Storage(format!(
            "{store_name} immutable SQLite source path changed during inspection: {}",
            original.display()
        )));
    }
    let path_snapshot = sqlite_file_snapshot(canonical, store_name)?;
    let descriptor_snapshot = sqlite_file_snapshot_from_file(source, store_name, original)?;
    if &path_snapshot != expected || &descriptor_snapshot != expected {
        return Err(KataError::Storage(format!(
            "{store_name} immutable SQLite source changed during inspection: {}",
            original.display()
        )));
    }
    reject_sqlite_sidecars(original, store_name)?;
    reject_sqlite_sidecars(canonical, store_name)?;
    Ok(())
}

fn private_file_snapshot(
    file: &File,
    path: &Path,
    store_name: &str,
) -> KataResult<SqliteFileSnapshot> {
    let metadata = file.metadata().map_err(|error| {
        KataError::Storage(format!(
            "{store_name} immutable SQLite inspection cannot inspect private snapshot {}: {error}",
            path.display()
        ))
    })?;
    if !metadata.is_file() {
        return Err(KataError::Storage(format!(
            "{store_name} immutable SQLite private snapshot is not a regular file: {}",
            path.display()
        )));
    }
    Ok(sqlite_file_snapshot_from_metadata(metadata))
}

fn validate_private_file_snapshot(
    snapshot: &SqliteFileSnapshot,
    expected_identity: Option<&FileIdentity>,
    expected_len: u64,
    expected_links: u64,
    store_name: &str,
    path: &Path,
) -> KataResult<()> {
    #[cfg(unix)]
    {
        let identity = FileIdentity::from_snapshot(snapshot);
        if expected_identity.is_some_and(|expected| expected != &identity)
            || snapshot.len != expected_len
            || snapshot.nlink != expected_links
            || snapshot.mode & 0o7777 != 0o600
            || snapshot.uid != rustix::process::geteuid().as_raw()
        {
            return Err(KataError::Storage(format!(
                "{store_name} immutable SQLite private snapshot identity, length, link count, effective owner, or 0600 mode changed at {}",
                path.display()
            )));
        }
        Ok(())
    }

    #[cfg(not(unix))]
    {
        let _ = (
            snapshot,
            expected_identity,
            expected_len,
            expected_links,
            path,
        );
        Err(KataError::Storage(format!(
            "{store_name} immutable SQLite inspection is supported only on Kata's Unix hosts"
        )))
    }
}

fn verify_private_snapshot_path(
    path: &Path,
    file: &File,
    expected_identity: &FileIdentity,
    expected_len: u64,
    store_name: &str,
) -> KataResult<()> {
    let held = private_file_snapshot(file, path, store_name)?;
    validate_private_file_snapshot(
        &held,
        Some(expected_identity),
        expected_len,
        1,
        store_name,
        path,
    )?;
    let metadata = std::fs::symlink_metadata(path).map_err(|error| {
        KataError::Storage(format!(
            "{store_name} immutable SQLite inspection cannot inspect private snapshot pathname {}: {error}",
            path.display()
        ))
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(KataError::Storage(format!(
            "{store_name} immutable SQLite private snapshot pathname is not a regular non-symlink file: {}",
            path.display()
        )));
    }
    let pathname = sqlite_file_snapshot_from_metadata(metadata);
    validate_private_file_snapshot(
        &pathname,
        Some(expected_identity),
        expected_len,
        1,
        store_name,
        path,
    )
}

#[cfg(unix)]
fn verify_private_directory(
    path: &Path,
    expected_identity: Option<&FileIdentity>,
    store_name: &str,
) -> KataResult<FileIdentity> {
    use std::os::unix::fs::MetadataExt as _;

    let metadata = std::fs::symlink_metadata(path).map_err(|error| {
        KataError::Storage(format!(
            "{store_name} immutable SQLite inspection cannot inspect private directory {}: {error}",
            path.display()
        ))
    })?;
    if metadata.file_type().is_symlink()
        || !metadata.is_dir()
        || metadata.mode() & 0o7777 != 0o700
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.nlink() < 2
    {
        return Err(KataError::Storage(format!(
            "{store_name} immutable SQLite private directory is not an effective-owner 0700 directory with a valid link count: {}",
            path.display()
        )));
    }
    let identity = FileIdentity {
        dev: metadata.dev(),
        ino: metadata.ino(),
    };
    if expected_identity.is_some_and(|expected| expected != &identity) {
        return Err(KataError::Storage(format!(
            "{store_name} immutable SQLite private directory identity changed at {}",
            path.display()
        )));
    }
    Ok(identity)
}

#[cfg(not(unix))]
fn verify_private_directory(
    _path: &Path,
    _expected_identity: Option<&FileIdentity>,
    store_name: &str,
) -> KataResult<FileIdentity> {
    Err(KataError::Storage(format!(
        "{store_name} immutable SQLite inspection is supported only on Kata's Unix hosts"
    )))
}

fn verify_private_directory_empty(
    private: &PrivateSqliteSnapshot,
    store_name: &str,
) -> KataResult<()> {
    let unlinked = private_file_snapshot(&private.file, &private.path, store_name)?;
    validate_private_file_snapshot(
        &unlinked,
        Some(&private.file_identity),
        private.len,
        0,
        store_name,
        &private.path,
    )?;
    verify_private_directory(
        &private.directory.path,
        Some(&private.directory.identity),
        store_name,
    )?;
    verify_private_directory_handle(private, store_name)?;
    reject_existing_path(&private.path, store_name)?;
    verify_bound_private_directory_empty(&private.directory.handle, store_name)
}

#[cfg(unix)]
fn file_identity_from_file(file: &File, store_name: &str) -> KataResult<FileIdentity> {
    use std::os::unix::fs::MetadataExt as _;

    let metadata = file.metadata().map_err(|error| {
        KataError::Storage(format!(
            "{store_name} immutable SQLite inspection cannot inspect held directory: {error}"
        ))
    })?;
    if !metadata.is_dir() {
        return Err(KataError::Storage(format!(
            "{store_name} immutable SQLite held private-directory descriptor is not a directory"
        )));
    }
    Ok(FileIdentity {
        dev: metadata.dev(),
        ino: metadata.ino(),
    })
}

#[cfg(unix)]
fn verify_private_directory_handle(
    private: &PrivateSqliteSnapshot,
    store_name: &str,
) -> KataResult<()> {
    if file_identity_from_file(&private.directory.handle, store_name)? != private.directory.identity
    {
        return Err(KataError::Storage(format!(
            "{store_name} immutable SQLite private-directory descriptor identity changed"
        )));
    }
    Ok(())
}

#[cfg(not(unix))]
fn verify_private_directory_handle(
    _private: &PrivateSqliteSnapshot,
    store_name: &str,
) -> KataResult<()> {
    Err(KataError::Storage(format!(
        "{store_name} immutable SQLite inspection is supported only on Kata's Unix hosts"
    )))
}

fn reject_existing_path(path: &Path, store_name: &str) -> KataResult<()> {
    match std::fs::symlink_metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Ok(_) => Err(KataError::Storage(format!(
            "{store_name} immutable SQLite private snapshot pathname still exists after unlink: {}",
            path.display()
        ))),
        Err(error) => Err(KataError::Storage(format!(
            "{store_name} immutable SQLite inspection cannot verify private snapshot unlink at {}: {error}",
            path.display()
        ))),
    }
}

fn reject_sqlite_sidecars(path: &Path, store_name: &str) -> KataResult<()> {
    for suffix in ["-journal", "-wal", "-shm"] {
        let sidecar = sqlite_sidecar_path(path, suffix);
        match std::fs::symlink_metadata(&sidecar) {
            Ok(_) => {
                return Err(KataError::Storage(format!(
                    "{store_name} immutable SQLite inspection refuses ambient sidecar {}: something still has this database open, or did not close it cleanly. Close every process that has it open (for a live data directory, the Kata node serving it) and checkpoint the database before retrying",
                    sidecar.display()
                )));
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(KataError::Storage(format!(
                    "{store_name} immutable SQLite inspection cannot inspect sidecar {}: {error}",
                    sidecar.display()
                )));
            }
        }
    }
    Ok(())
}

fn sqlite_sidecar_path(path: &Path, suffix: &str) -> PathBuf {
    let mut name = path.as_os_str().to_os_string();
    name.push(suffix);
    PathBuf::from(name)
}

#[cfg(unix)]
fn immutable_sqlite_uri(path: &Path, store_name: &str) -> KataResult<String> {
    use std::fmt::Write as _;
    use std::os::unix::ffi::OsStrExt;

    if !path.is_absolute() {
        return Err(KataError::Storage(format!(
            "{store_name} immutable SQLite inspection requires an absolute canonical path"
        )));
    }
    let mut uri = String::with_capacity(path.as_os_str().as_bytes().len() + 24);
    uri.push_str("file:");
    for byte in path.as_os_str().as_bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' | b'/' => {
                uri.push(char::from(*byte));
            }
            _ => write!(&mut uri, "%{byte:02X}").expect("writing to String cannot fail"),
        }
    }
    uri.push_str("?immutable=1");
    Ok(uri)
}

#[cfg(not(unix))]
fn immutable_sqlite_uri(_path: &Path, store_name: &str) -> KataResult<String> {
    Err(KataError::Storage(format!(
        "{store_name} immutable SQLite inspection is supported only on Kata's Unix hosts"
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// [`inspect_optional_immutable_sqlite`] for a database that must exist.
    fn inspect_immutable_sqlite<T>(
        path: &Path,
        store_name: &str,
        inspect: impl FnOnce(&Connection) -> KataResult<T>,
    ) -> KataResult<T> {
        inspect_optional_immutable_sqlite(path, store_name, inspect)?.ok_or_else(|| {
            KataError::Storage(format!(
                "{store_name} immutable SQLite inspection requires an existing database at {}",
                path.display()
            ))
        })
    }

    #[cfg(unix)]
    fn assert_clean_persistent_coordinator(root: &Path) {
        let entries = std::fs::read_dir(root)
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect::<Vec<_>>();
        assert_eq!(
            entries,
            vec![std::ffi::OsString::from(
                private_snapshot_coordinator_basename()
            )],
            "temporary root must retain only its stable coordinator"
        );
        let coordinator = root.join(private_snapshot_coordinator_basename());
        let coordinator_entries = std::fs::read_dir(coordinator)
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect::<Vec<_>>();
        assert_eq!(
            coordinator_entries,
            vec![std::ffi::OsString::from(PRIVATE_SNAPSHOT_COORDINATOR_LOCK)],
            "coordinator must retain only its stable lock"
        );
    }

    #[cfg(unix)]
    fn create_test_database(path: &Path) {
        let connection = Connection::open(path).unwrap();
        connection
            .execute_batch(
                "CREATE TABLE expected (value INTEGER NOT NULL); INSERT INTO expected VALUES (7);",
            )
            .unwrap();
    }

    /// The per-euid coordinator refuses a concurrent acquisition instead of queueing, so
    /// two tests that reach `inspect_optional_immutable_sqlite` at the same instant fail
    /// rather than wait. INVARIANT: every test that can reach it is serialized into the
    /// nextest `heavy-io` group. FAILURE MODE, if it is not: *"nonblocking coordinator
    /// lock refused acquisition: Resource temporarily unavailable (os error 11)"*, only
    /// under load, and `retries = 0` means the gate dies the first time it happens.
    ///
    /// ENFORCEMENT POINT: this test. Comparing the filter only against a literal it
    /// carries itself would pass when a new caller appears, because the same diff would
    /// change both. PROOF the check has teeth: the loop
    /// below reads the CALL SITES out of the crate source, so a module that starts
    /// calling the coordinator fails this test until a clause names it. The literal
    /// remains, because it is the only thing that catches a silent REDUCTION of the
    /// filter or a duplicated override block.
    ///
    /// What is still enumerated and cannot be derived here: the callers that reach the
    /// coordinator TRANSITIVELY, through `store::backup`, from test binaries in this
    /// crate and in `bin/kata`. No call site names them.
    #[test]
    fn sqlite_immutable_nextest_group_covers_every_current_caller_surface() {
        // Cross-process per-uid serialization: this test drives a product
        // immutable-SQLite inspection, whose coordinator is a per-euid singleton with a
        // NONBLOCKING 3s product deadline. Two suites under one uid made it refuse with a
        // storage-integrity message for a scheduling cause. See
        // kata_test_utils::inspection_lock.
        let _inspection_lock = kata_test_utils::inspection_lock::hold();
        let config = include_str!("../../../.config/nextest.toml");

        // Read the sources at RUNTIME rather than `include_str!`-ing them: these are
        // multi-thousand-line files and embedding them would grow every kata-core test
        // binary to carry a string three `contains` calls consume.
        let crate_src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let direct_callers = [(
            "store/backup.rs",
            "store::backup",
            "test(store::backup::tests::)",
        )];
        for (relative, caller, clause) in direct_callers {
            let source = std::fs::read_to_string(crate_src.join(relative))
                .unwrap_or_else(|error| panic!("read {relative}: {error}"));
            assert!(
                source.contains("inspect_optional_immutable_sqlite"),
                "{caller} no longer reaches the immutable-SQLite coordinator; retire its \
                 heavy-io clause in a deliberate diff rather than leaving this check \
                 asserting a serialization nothing needs"
            );
            assert!(
                config.contains(clause),
                "{caller} reaches the per-euid immutable-SQLite coordinator but no \
                 nextest clause `{clause}` serializes its tests"
            );
        }

        // Every OTHER module in this crate that calls the coordinator must be added to
        // `direct_callers` above; this is the check that notices one appearing.
        let mut found = std::collections::BTreeSet::new();
        let mut stack = vec![crate_src.clone()];
        while let Some(dir) = stack.pop() {
            for entry in std::fs::read_dir(&dir).unwrap() {
                let path = entry.unwrap().path();
                if path.is_dir() {
                    stack.push(path);
                    continue;
                }
                if path.extension().and_then(|extension| extension.to_str()) != Some("rs") {
                    continue;
                }
                let source = std::fs::read_to_string(&path).unwrap();
                if source.contains("inspect_optional_immutable_sqlite") {
                    found.insert(
                        path.strip_prefix(&crate_src)
                            .unwrap()
                            .to_string_lossy()
                            .into_owned(),
                    );
                }
            }
        }
        let mut expected = direct_callers
            .iter()
            .map(|(relative, _, _)| (*relative).to_owned())
            .collect::<std::collections::BTreeSet<_>>();
        // The coordinator's own definition and re-export are not callers.
        expected.insert("sqlite_immutable.rs".to_owned());
        expected.insert("lib.rs".to_owned());
        assert_eq!(
            found, expected,
            "kata-core's immutable-SQLite call sites moved; every caller needs a nextest \
             heavy-io clause and an entry above, or its tests fail under load with \
             \"nonblocking coordinator lock refused acquisition\""
        );

        // Transitive reachers, enumerated because no call site names them: the durable
        // asset map and the backup CLI tests drive `store::backup`
        // into the coordinator.
        for clause in [
            "test(cli::backup::tests::)",
            "test(durable_assets::tests::)",
            "binary(backup_durability_tests)",
            "binary(backup_recovery_v4)",
            "binary(durable_asset_map)",
            "binary(backup_omission_report_tests)",
        ] {
            assert!(
                config.contains(clause),
                "`{clause}` reaches the immutable-SQLite coordinator transitively and \
                 must stay in the heavy-io group"
            );
        }

        let direct_filter = r#"filter = '''
    test(sqlite_immutable)
    | binary(backup_tests)
    | binary(backup_durability_tests)
    | binary(backup_omission_report_tests)
    | binary(durable_asset_map)
    | binary(upgrade_cmd_tests)
    | test(cli::backup::tests::)
    | test(store::backup::tests::)
    | test(durable_assets::tests::)
    | test(restore_stays_bound_to_locked_directory_after_parent_alias_retarget)
    | test(apply_stays_bound_to_the_locked_directory_after_parent_alias_retarget)
    | test(dry_run_stays_on_one_physical_source_after_parent_alias_retarget)
'''
test-group = "heavy-io""#;
        assert_eq!(
            config.matches(direct_filter).count(),
            1,
            "nextest direct SQLite caller filter is missing or duplicated"
        );
        assert_eq!(
            config
                .matches("filter = 'binary(backup_recovery_v4)'\ntest-group = \"heavy-io\"")
                .count(),
            1,
            "current recovery must join immutable inspection scheduling without changing its timeout"
        );
        assert!(
            !config.contains("test(incompatible_scan_is_complete_sandbox_scoped_and_non_mutating)"),
            "the in-memory compatibility scan does not acquire immutable-SQLite coordination"
        );
        assert!(
            !config.contains("test(parent_alias_retarget)"),
            "a broad alias-retarget filter would serialize unrelated data-dir-lock coverage"
        );
    }

    #[cfg(unix)]
    #[test]
    fn immutable_temporary_ancestor_posture_rejects_every_foreign_non_root_owner() {
        let effective_uid = rustix::process::geteuid().as_raw();
        let foreign_uid = if effective_uid == 1 { 2 } else { 1 };
        let identity = |uid, mode| TemporaryRootIdentity {
            dev: 1,
            ino: 1,
            uid,
            gid: 1,
            mode,
        };

        for mode in [0o555, 0o755, 0o1777] {
            let error = validate_temporary_ancestor_posture(
                &identity(foreign_uid, mode),
                "test store",
                Path::new("/foreign-ancestor"),
            )
            .expect_err("a foreign non-root owner must never become path authority");
            assert!(error.to_string().contains("untrusted uid"));
        }

        validate_temporary_ancestor_posture(
            &identity(effective_uid, 0o755),
            "test store",
            Path::new("/owner-ancestor"),
        )
        .expect("an effective-owner ancestor without group/other writes is trusted");
        validate_temporary_ancestor_posture(
            &identity(0, 0o755),
            "test store",
            Path::new("/root-ancestor"),
        )
        .expect("a non-writable root-owned ancestor is trusted");
        validate_temporary_ancestor_posture(
            &identity(0, 0o1777),
            "test store",
            Path::new("/root-sticky-ancestor"),
        )
        .expect("a root-owned sticky shared ancestor is trusted");
    }

    #[cfg(unix)]
    fn replace_active_attempt(snapshot_path: &Path, root: &Path) -> (PathBuf, PathBuf) {
        use std::os::unix::fs::PermissionsExt as _;

        let active = snapshot_path.parent().unwrap().to_path_buf();
        let retired = active.parent().unwrap().join(format!(
            "{PRIVATE_SNAPSHOT_ATTEMPT_PREFIX}{}",
            ulid::Ulid::new()
        ));
        std::fs::rename(&active, &retired).unwrap();
        std::fs::create_dir(&active).unwrap();
        std::fs::set_permissions(&active, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::write(root.join("replacement-sentinel"), b"preserve").unwrap();
        (active, retired)
    }

    #[test]
    fn immutable_inspection_supports_metacharacter_source_path_bytes() {
        // Cross-process per-uid serialization: this test drives a product
        // immutable-SQLite inspection, whose coordinator is a per-euid singleton with a
        // NONBLOCKING 3s product deadline. Two suites under one uid made it refuse with a
        // storage-integrity message for a scheduling cause. See
        // kata_test_utils::inspection_lock.
        let _inspection_lock = kata_test_utils::inspection_lock::hold();
        let temp = tempfile::tempdir().unwrap();
        let parent = temp.path().join("has?query#fragment%percent");
        std::fs::create_dir(&parent).unwrap();
        let path = parent.join("authority.db");
        let connection = Connection::open(&path).unwrap();
        connection
            .execute_batch(
                "CREATE TABLE expected (value INTEGER NOT NULL); INSERT INTO expected VALUES (7);",
            )
            .unwrap();
        drop(connection);

        let value = inspect_immutable_sqlite(&path, "test store", |connection| {
            connection
                .query_row("SELECT value FROM expected", [], |row| row.get::<_, i64>(0))
                .map_err(|error| KataError::Storage(error.to_string()))
        })
        .unwrap();
        assert_eq!(value, 7);
    }

    #[cfg(unix)]
    #[test]
    fn immutable_inspection_supports_non_utf8_source_path_bytes() {
        // Cross-process per-uid serialization: this test drives a product
        // immutable-SQLite inspection, whose coordinator is a per-euid singleton with a
        // NONBLOCKING 3s product deadline. Two suites under one uid made it refuse with a
        // storage-integrity message for a scheduling cause. See
        // kata_test_utils::inspection_lock.
        let _inspection_lock = kata_test_utils::inspection_lock::hold();
        use std::ffi::OsString;
        use std::os::unix::ffi::OsStringExt;

        let temp = tempfile::tempdir().unwrap();
        let parent = temp
            .path()
            .join(OsString::from_vec(vec![b'n', b'o', b'n', 0xFF]));
        std::fs::create_dir(&parent).unwrap();
        let path = parent.join("authority.db");
        let connection = Connection::open(&path).unwrap();
        connection
            .execute_batch("CREATE TABLE expected (value INTEGER);")
            .unwrap();
        drop(connection);

        inspect_immutable_sqlite(&path, "test store", |connection| {
            connection
                .query_row("SELECT count(*) FROM expected", [], |row| {
                    row.get::<_, i64>(0)
                })
                .map(|_| ())
                .map_err(|error| KataError::Storage(error.to_string()))
        })
        .unwrap();
    }

    #[test]
    fn immutable_inspection_refuses_ambient_sidecars() {
        // Cross-process per-uid serialization: this test drives a product
        // immutable-SQLite inspection, whose coordinator is a per-euid singleton with a
        // NONBLOCKING 3s product deadline. Two suites under one uid made it refuse with a
        // storage-integrity message for a scheduling cause. See
        // kata_test_utils::inspection_lock.
        let _inspection_lock = kata_test_utils::inspection_lock::hold();
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("authority.db");
        let connection = Connection::open(&path).unwrap();
        connection
            .execute_batch("CREATE TABLE expected (value INTEGER);")
            .unwrap();
        drop(connection);
        std::fs::write(sqlite_sidecar_path(&path, "-wal"), b"ambient authority").unwrap();

        let error = inspect_immutable_sqlite(&path, "test store", |_| Ok(()))
            .expect_err("ambient WAL must make immutable classification ambiguous");
        assert!(error.to_string().contains("refuses ambient sidecar"));
        // This refusal serves every caller, and not every database it guards belongs
        // to a node: a restore artifact's database has no server. So the recourse
        // names whatever holds the file, and a node only as the live-directory case.
        // It never names an earlier binary, which cannot open a directory this one
        // admits.
        let message = error.to_string();
        assert!(
            message.contains("Close every process that has it open")
                && message.contains("for a live data directory, the Kata node serving it"),
            "{message}"
        );
        assert!(
            !message.contains("; stop the Kata node") && !message.contains("previous Kata binary"),
            "{message}"
        );
    }

    #[test]
    fn immutable_inspection_rejects_source_mutation_during_callback() {
        // Cross-process per-uid serialization: this test drives a product
        // immutable-SQLite inspection, whose coordinator is a per-euid singleton with a
        // NONBLOCKING 3s product deadline. Two suites under one uid made it refuse with a
        // storage-integrity message for a scheduling cause. See
        // kata_test_utils::inspection_lock.
        let _inspection_lock = kata_test_utils::inspection_lock::hold();
        use std::io::Write as _;

        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("authority.db");
        let connection = Connection::open(&path).unwrap();
        connection
            .execute_batch(
                "CREATE TABLE expected (value INTEGER); INSERT INTO expected VALUES (7);",
            )
            .unwrap();
        drop(connection);

        let mutation_path = path.clone();
        let error = inspect_immutable_sqlite(&path, "test store", |connection| {
            let _: i64 = connection
                .query_row("SELECT value FROM expected", [], |row| row.get(0))
                .map_err(|error| KataError::Storage(error.to_string()))?;
            OpenOptions::new()
                .append(true)
                .open(&mutation_path)
                .and_then(|mut file| file.write_all(&[0]))
                .map_err(|error| KataError::Storage(error.to_string()))?;
            Ok(())
        })
        .expect_err("in-place mutation must invalidate the inspection");

        assert!(error.to_string().contains("changed during inspection"));
    }

    #[test]
    fn immutable_callback_error_remains_primary_when_postcondition_also_fails() {
        // Cross-process per-uid serialization: this test drives a product
        // immutable-SQLite inspection, whose coordinator is a per-euid singleton with a
        // NONBLOCKING 3s product deadline. Two suites under one uid made it refuse with a
        // storage-integrity message for a scheduling cause. See
        // kata_test_utils::inspection_lock.
        let _inspection_lock = kata_test_utils::inspection_lock::hold();
        use std::io::Write as _;

        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("authority.db");
        let connection = Connection::open(&path).unwrap();
        connection
            .execute_batch("CREATE TABLE expected (value INTEGER);")
            .unwrap();
        drop(connection);

        let mutation_path = path.clone();
        let error = inspect_immutable_sqlite(&path, "test store", |_| {
            OpenOptions::new()
                .append(true)
                .open(&mutation_path)
                .and_then(|mut file| file.write_all(&[0]))
                .unwrap();
            Err::<(), _>(KataError::Storage("callback-primary".to_string()))
        })
        .expect_err("callback and postcondition failures must both remain visible");

        let message = error.to_string();
        assert!(message.contains("callback-primary"), "{message}");
        assert!(
            message.contains("post-inspection authority validation failed")
                && message.contains("changed during inspection"),
            "{message}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn immutable_materialization_rejects_shortened_and_growing_sources() {
        // Cross-process per-uid serialization: this test drives a product
        // immutable-SQLite inspection, whose coordinator is a per-euid singleton with a
        // NONBLOCKING 3s product deadline. Two suites under one uid made it refuse with a
        // storage-integrity message for a scheduling cause. See
        // kata_test_utils::inspection_lock.
        let _inspection_lock = kata_test_utils::inspection_lock::hold();
        use std::io::Write as _;

        for grow in [false, true] {
            let temp = tempfile::tempdir().unwrap();
            let path = temp.path().join("authority.db");
            let connection = Connection::open(&path).unwrap();
            connection
                .execute_batch(
                    "CREATE TABLE expected (value INTEGER); INSERT INTO expected VALUES (7);",
                )
                .unwrap();
            drop(connection);

            let policy = SnapshotMaterializationPolicy {
                force_copy: true,
                available_bytes: Some(u64::MAX),
                ..SnapshotMaterializationPolicy::default()
            };
            let error = inspect_optional_immutable_sqlite_with_hooks_and_policy(
                &path,
                "test store",
                || {
                    if grow {
                        OpenOptions::new()
                            .append(true)
                            .open(&path)
                            .and_then(|mut file| file.write_all(&[0]))
                            .unwrap();
                    } else {
                        OpenOptions::new()
                            .write(true)
                            .truncate(true)
                            .open(&path)
                            .unwrap();
                    }
                },
                |_| panic!("an invalid source length must not produce a private snapshot"),
                &policy,
                |_| -> KataResult<()> {
                    panic!("an invalid source length must not reach the callback")
                },
            )
            .expect_err("source length drift must fail closed during bounded copy");

            let expected_message = if grow { "grew" } else { "shortened" };
            assert!(error.to_string().contains(expected_message));
        }
    }

    #[cfg(unix)]
    #[test]
    fn immutable_inspection_snapshots_adopted_inode_but_rejects_unlink_and_replacement() {
        // Cross-process per-uid serialization: this test drives a product
        // immutable-SQLite inspection, whose coordinator is a per-euid singleton with a
        // NONBLOCKING 3s product deadline. Two suites under one uid made it refuse with a
        // storage-integrity message for a scheduling cause. See
        // kata_test_utils::inspection_lock.
        let _inspection_lock = kata_test_utils::inspection_lock::hold();
        use std::cell::Cell;

        fn create_database(path: &Path, value: i64) {
            let connection = Connection::open(path).unwrap();
            connection
                .execute_batch(&format!(
                    "CREATE TABLE expected (value INTEGER NOT NULL); \
                     INSERT INTO expected VALUES ({value});"
                ))
                .unwrap();
        }

        let temp = tempfile::tempdir().unwrap();
        let original = temp.path().join("authority.db");
        let replacement = temp.path().join("replacement.db");
        create_database(&original, 7);
        create_database(&replacement, 99);
        let snapshot_observed = Cell::new(None);
        let callback_ran = Cell::new(false);

        let error = inspect_optional_immutable_sqlite_with_hooks(
            &original,
            "test store",
            || {
                std::fs::remove_file(&original).unwrap();
                std::fs::rename(&replacement, &original).unwrap();
            },
            |snapshot| {
                use std::os::unix::fs::MetadataExt as _;

                let metadata = std::fs::symlink_metadata(snapshot).unwrap();
                assert!(metadata.is_file());
                assert_eq!(metadata.mode() & 0o7777, 0o600);
                let uri = immutable_sqlite_uri(snapshot, "test store").unwrap();
                let connection = Connection::open_with_flags(uri, immutable_open_flags()).unwrap();
                snapshot_observed.set(Some(
                    connection
                        .query_row("SELECT value FROM expected", [], |row| row.get::<_, i64>(0))
                        .unwrap(),
                ));
            },
            |_| {
                callback_ran.set(true);
                Ok(())
            },
        )
        .expect_err("unlinking the adopted inode and replacing its path must fail closed");

        assert_eq!(
            snapshot_observed.get(),
            Some(7),
            "materialization must copy the adopted inode, never its pathname replacement",
        );
        assert!(!callback_ran.get());
        assert!(error.to_string().contains("exactly one source link"));
    }

    #[cfg(unix)]
    #[test]
    fn immutable_inspection_refuses_hardlink_with_alternate_wal_authority() {
        // Cross-process per-uid serialization: this test drives a product
        // immutable-SQLite inspection, whose coordinator is a per-euid singleton with a
        // NONBLOCKING 3s product deadline. Two suites under one uid made it refuse with a
        // storage-integrity message for a scheduling cause. See
        // kata_test_utils::inspection_lock.
        let _inspection_lock = kata_test_utils::inspection_lock::hold();
        use std::cell::Cell;

        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("authority.db");
        let alias = temp.path().join("alternate.db");
        let connection = Connection::open(&path).unwrap();
        connection
            .execute_batch("CREATE TABLE expected (value INTEGER);")
            .unwrap();
        drop(connection);
        std::fs::hard_link(&path, &alias).unwrap();
        std::fs::write(sqlite_sidecar_path(&alias, "-wal"), b"alternate authority").unwrap();
        let callback_ran = Cell::new(false);

        let error = inspect_immutable_sqlite(&path, "test store", |_| {
            callback_ran.set(true);
            Ok(())
        })
        .expect_err("a hard link can hide WAL authority under an alternate basename");

        assert!(!callback_ran.get());
        assert!(error.to_string().contains("exactly one source link"));
    }

    #[cfg(unix)]
    #[test]
    fn immutable_callback_uses_unlinked_snapshot_and_private_directory_lifetime() {
        // Cross-process per-uid serialization: this test drives a product
        // immutable-SQLite inspection, whose coordinator is a per-euid singleton with a
        // NONBLOCKING 3s product deadline. Two suites under one uid made it refuse with a
        // storage-integrity message for a scheduling cause. See
        // kata_test_utils::inspection_lock.
        let _inspection_lock = kata_test_utils::inspection_lock::hold();
        use std::cell::RefCell;
        use std::os::unix::fs::MetadataExt as _;

        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("authority.db");
        let connection = Connection::open(&path).unwrap();
        connection
            .execute_batch(
                "CREATE TABLE expected (value INTEGER NOT NULL); INSERT INTO expected VALUES (7);",
            )
            .unwrap();
        drop(connection);
        let private_directory = RefCell::new(None);

        let value = inspect_immutable_sqlite(&path, "test store", |connection| {
            let snapshot_path: String = connection
                .query_row("PRAGMA database_list", [], |row| row.get(2))
                .map_err(|error| KataError::Storage(error.to_string()))?;
            let snapshot_path = PathBuf::from(snapshot_path);
            assert!(
                !snapshot_path.exists(),
                "the private snapshot pathname must be gone before the callback"
            );
            let directory = snapshot_path.parent().unwrap().to_path_buf();
            let metadata = std::fs::symlink_metadata(&directory).unwrap();
            assert!(metadata.is_dir());
            assert_eq!(metadata.mode() & 0o7777, 0o700);
            private_directory.replace(Some(directory));
            connection
                .query_row("SELECT value FROM expected", [], |row| row.get::<_, i64>(0))
                .map_err(|error| KataError::Storage(error.to_string()))
        })
        .unwrap();

        assert_eq!(value, 7);
        let private_directory = private_directory.borrow();
        assert!(
            !private_directory.as_ref().unwrap().exists(),
            "the private directory must be removed after the callback"
        );
    }

    #[cfg(unix)]
    #[test]
    fn immutable_inspection_refuses_unsafe_temporary_root() {
        // Cross-process per-uid serialization: this test drives a product
        // immutable-SQLite inspection, whose coordinator is a per-euid singleton with a
        // NONBLOCKING 3s product deadline. Two suites under one uid made it refuse with a
        // storage-integrity message for a scheduling cause. See
        // kata_test_utils::inspection_lock.
        let _inspection_lock = kata_test_utils::inspection_lock::hold();
        use std::os::unix::fs::PermissionsExt as _;

        let temp = tempfile::tempdir().unwrap();
        std::fs::set_permissions(temp.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let source = temp.path().join("authority.db");
        let connection = Connection::open(&source).unwrap();
        connection
            .execute_batch("CREATE TABLE expected (value INTEGER);")
            .unwrap();
        drop(connection);

        let unsafe_root = temp.path().join("unsafe-root");
        std::fs::create_dir(&unsafe_root).unwrap();
        std::fs::set_permissions(&unsafe_root, std::fs::Permissions::from_mode(0o777)).unwrap();
        let policy = SnapshotMaterializationPolicy {
            temporary_root: Some(unsafe_root),
            ..SnapshotMaterializationPolicy::default()
        };
        let error = inspect_optional_immutable_sqlite_with_hooks_and_policy(
            &source,
            "test store",
            || {},
            |_| {},
            &policy,
            |_| Ok(()),
        )
        .expect_err("non-sticky writable temporary root must be refused");
        assert!(error.to_string().contains("unsafe temporary root"));
    }

    #[cfg(unix)]
    #[test]
    fn immutable_inspection_refuses_safe_leaf_below_unsafe_temporary_ancestor() {
        // Cross-process per-uid serialization: this test drives a product
        // immutable-SQLite inspection, whose coordinator is a per-euid singleton with a
        // NONBLOCKING 3s product deadline. Two suites under one uid made it refuse with a
        // storage-integrity message for a scheduling cause. See
        // kata_test_utils::inspection_lock.
        let _inspection_lock = kata_test_utils::inspection_lock::hold();
        use std::os::unix::fs::PermissionsExt as _;

        let temp = tempfile::tempdir().unwrap();
        std::fs::set_permissions(temp.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let source = temp.path().join("authority.db");
        let connection = Connection::open(&source).unwrap();
        connection
            .execute_batch("CREATE TABLE expected (value INTEGER);")
            .unwrap();
        drop(connection);

        let unsafe_parent = temp.path().join("unsafe-parent");
        let apparently_safe_root = unsafe_parent.join("safe-leaf");
        std::fs::create_dir(&unsafe_parent).unwrap();
        std::fs::set_permissions(&unsafe_parent, std::fs::Permissions::from_mode(0o777)).unwrap();
        std::fs::create_dir(&apparently_safe_root).unwrap();
        std::fs::set_permissions(
            &apparently_safe_root,
            std::fs::Permissions::from_mode(0o700),
        )
        .unwrap();
        let policy = SnapshotMaterializationPolicy {
            temporary_root: Some(apparently_safe_root),
            ..SnapshotMaterializationPolicy::default()
        };
        let error = inspect_optional_immutable_sqlite_with_hooks_and_policy(
            &source,
            "test store",
            || {},
            |_| {},
            &policy,
            |_| Ok(()),
        )
        .expect_err("writable non-sticky ancestor must be refused");
        assert!(error.to_string().contains("unsafe temporary-root ancestor"));
    }

    #[cfg(unix)]
    #[test]
    fn immutable_inspection_detects_temporary_root_retarget_without_deleting_replacement() {
        // Cross-process per-uid serialization: this test drives a product
        // immutable-SQLite inspection, whose coordinator is a per-euid singleton with a
        // NONBLOCKING 3s product deadline. Two suites under one uid made it refuse with a
        // storage-integrity message for a scheduling cause. See
        // kata_test_utils::inspection_lock.
        let _inspection_lock = kata_test_utils::inspection_lock::hold();
        use std::os::unix::fs::PermissionsExt as _;

        let temp = tempfile::tempdir().unwrap();
        std::fs::set_permissions(temp.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let source = temp.path().join("authority.db");
        let connection = Connection::open(&source).unwrap();
        connection
            .execute_batch("CREATE TABLE expected (value INTEGER);")
            .unwrap();
        drop(connection);

        let root = temp.path().join("snapshot-root");
        let retired = temp.path().join("retired-root");
        std::fs::create_dir(&root).unwrap();
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
        let policy = SnapshotMaterializationPolicy {
            temporary_root: Some(root.clone()),
            ..SnapshotMaterializationPolicy::default()
        };
        let error = inspect_optional_immutable_sqlite_with_hooks_and_policy(
            &source,
            "test store",
            || {},
            |_| {
                std::fs::rename(&root, &retired).unwrap();
                std::fs::create_dir(&root).unwrap();
                std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
                std::fs::write(root.join("replacement-sentinel"), b"preserve").unwrap();
            },
            &policy,
            |_| -> KataResult<()> { panic!("retargeted root must not reach callback") },
        )
        .expect_err("temporary-root identity drift must fail closed");

        assert!(
            error.to_string().contains("identity changed"),
            "unexpected retarget refusal: {error}"
        );
        assert_eq!(
            std::fs::read(root.join("replacement-sentinel")).unwrap(),
            b"preserve",
            "cleanup must never traverse a replacement temporary root"
        );
        for entry in std::fs::read_dir(&retired).unwrap() {
            let entry = entry.unwrap();
            if entry.file_type().unwrap().is_dir() {
                assert!(
                    !entry.path().join(PRIVATE_SNAPSHOT_NAME).exists(),
                    "retarget cleanup must unlink private bytes through the held directory descriptor"
                );
            }
        }
    }

    #[cfg(unix)]
    #[test]
    fn immutable_materialization_retarget_seams_remove_private_bytes_without_traversal() {
        // Cross-process per-uid serialization: this test drives a product
        // immutable-SQLite inspection, whose coordinator is a per-euid singleton with a
        // NONBLOCKING 3s product deadline. Two suites under one uid made it refuse with a
        // storage-integrity message for a scheduling cause. See
        // kata_test_utils::inspection_lock.
        let _inspection_lock = kata_test_utils::inspection_lock::hold();
        use std::os::unix::fs::PermissionsExt as _;
        use std::sync::atomic::{AtomicBool, Ordering};

        for checkpoint in [
            MaterializationCheckpoint::DirectoryCreatedBeforeFirstRevalidate,
            MaterializationCheckpoint::PrivateDirectoryOpened,
            MaterializationCheckpoint::MidCopy,
            MaterializationCheckpoint::FinalVerify,
        ] {
            let temp = tempfile::tempdir().unwrap();
            std::fs::set_permissions(temp.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
            let source = temp.path().join("authority.db");
            let connection = Connection::open(&source).unwrap();
            connection
                .execute_batch(
                    "CREATE TABLE expected (value INTEGER NOT NULL); \
                     INSERT INTO expected VALUES (7);",
                )
                .unwrap();
            drop(connection);

            let root = temp.path().join("snapshot-root");
            let retired = temp.path().join("retired-root");
            std::fs::create_dir(&root).unwrap();
            std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
            let triggered = Arc::new(AtomicBool::new(false));
            let hook_root = root.clone();
            let hook_retired = retired.clone();
            let hook_triggered = Arc::clone(&triggered);
            let hook = Arc::new(move |observed| {
                if observed != checkpoint || hook_triggered.swap(true, Ordering::SeqCst) {
                    return;
                }
                std::fs::rename(&hook_root, &hook_retired).unwrap();
                std::fs::create_dir(&hook_root).unwrap();
                std::fs::set_permissions(&hook_root, std::fs::Permissions::from_mode(0o700))
                    .unwrap();
                std::fs::write(hook_root.join("replacement-sentinel"), b"preserve").unwrap();
            });
            let policy = SnapshotMaterializationPolicy {
                temporary_root: Some(root.clone()),
                force_copy: true,
                available_bytes: Some(u64::MAX),
                materialization_hook: Some(hook),
                ..SnapshotMaterializationPolicy::default()
            };

            let error = inspect_optional_immutable_sqlite_with_hooks_and_policy(
                &source,
                "test store",
                || {},
                |_| {},
                &policy,
                |_| -> KataResult<()> { panic!("retargeted materialization must not inspect") },
            )
            .expect_err("every materialization retarget seam must fail closed");

            assert!(triggered.load(Ordering::SeqCst), "missed {checkpoint:?}");
            assert!(
                error.to_string().contains("identity changed")
                    || error.to_string().contains("cannot inspect private"),
                "unexpected {checkpoint:?} refusal: {error}"
            );
            assert_eq!(
                std::fs::read(root.join("replacement-sentinel")).unwrap(),
                b"preserve",
                "{checkpoint:?} cleanup traversed the replacement"
            );
            assert_clean_persistent_coordinator(&retired);
        }
    }

    #[cfg(unix)]
    #[test]
    fn immutable_attempt_replacement_is_preserved_across_success_error_and_panic_drop() {
        // Cross-process per-uid serialization: this test drives a product
        // immutable-SQLite inspection, whose coordinator is a per-euid singleton with a
        // NONBLOCKING 3s product deadline. Two suites under one uid made it refuse with a
        // storage-integrity message for a scheduling cause. See
        // kata_test_utils::inspection_lock.
        let _inspection_lock = kata_test_utils::inspection_lock::hold();
        use std::os::unix::fs::PermissionsExt as _;
        use std::sync::Mutex;

        for outcome in ["success", "error", "panic"] {
            let temp = tempfile::tempdir().unwrap();
            std::fs::set_permissions(temp.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
            let source = temp.path().join("authority.db");
            create_test_database(&source);
            let root = temp.path().join("snapshots");
            std::fs::create_dir(&root).unwrap();
            std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
            let snapshot_path = Arc::new(Mutex::new(None::<PathBuf>));
            let captured = Arc::clone(&snapshot_path);
            let policy = SnapshotMaterializationPolicy {
                temporary_root: Some(root.clone()),
                force_copy: true,
                available_bytes: Some(u64::MAX),
                ..SnapshotMaterializationPolicy::default()
            };

            let run = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                inspect_optional_immutable_sqlite_with_hooks_and_policy(
                    &source,
                    "test store",
                    || {},
                    move |path| *captured.lock().unwrap() = Some(path.to_path_buf()),
                    &policy,
                    |_| {
                        let path = snapshot_path.lock().unwrap().clone().unwrap();
                        let (replacement, retired) = replace_active_attempt(&path, &root);
                        assert!(replacement.exists() && retired.exists());
                        match outcome {
                            "success" => Ok(()),
                            "error" => Err(KataError::Storage("callback failure".to_string())),
                            "panic" => panic!("callback panic"),
                            _ => unreachable!(),
                        }
                    },
                )
            }));
            if outcome == "panic" {
                assert!(run.is_err(), "panic seam must unwind through Drop");
            } else {
                let error = run
                    .unwrap()
                    .expect_err("attempt replacement must fail closed");
                assert!(
                    error.to_string().contains("identity changed")
                        || error.to_string().contains("replaced before cleanup"),
                    "unexpected {outcome} result: {error}"
                );
            }

            assert_eq!(
                std::fs::read(root.join("replacement-sentinel")).unwrap(),
                b"preserve"
            );
            let coordinator = root.join(private_snapshot_coordinator_basename());
            let attempts = std::fs::read_dir(&coordinator)
                .unwrap()
                .filter_map(|entry| {
                    let entry = entry.unwrap();
                    let name = entry.file_name().into_string().unwrap();
                    is_strict_private_attempt_name(&name).then_some(entry.path())
                })
                .collect::<Vec<_>>();
            assert_eq!(attempts.len(), 2, "both unproven names must be preserved");
            assert!(attempts.iter().all(|path| path.is_dir()));

            // The next lock owner validates and descriptor-relatively reaps
            // both bounded stale attempts before creating its one new attempt.
            inspect_optional_immutable_sqlite_with_hooks_and_policy(
                &source,
                "test store",
                || {},
                |_| {},
                &policy,
                |_| Ok(()),
            )
            .unwrap();
            let entries = std::fs::read_dir(&coordinator)
                .unwrap()
                .map(|entry| entry.unwrap().file_name())
                .collect::<Vec<_>>();
            assert_eq!(
                entries,
                vec![std::ffi::OsString::from(PRIVATE_SNAPSHOT_COORDINATOR_LOCK)]
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn concurrent_inspection_waits_for_coordinator_release() {
        // Cross-process per-uid serialization: this test drives a product
        // immutable-SQLite inspection, whose coordinator is a per-euid singleton with a
        // NONBLOCKING 3s product deadline. Two suites under one uid made it refuse with a
        // storage-integrity message for a scheduling cause. See
        // kata_test_utils::inspection_lock.
        let _inspection_lock = kata_test_utils::inspection_lock::hold();
        use std::os::unix::fs::PermissionsExt as _;

        let temp = tempfile::tempdir().unwrap();
        std::fs::set_permissions(temp.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let first = InspectionCoordinator::acquire(
            TemporaryRootAuthority::open(temp.path(), "test store").unwrap(),
            "test store",
        )
        .unwrap();
        let holder = std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_millis(150));
            drop(first);
        });
        // A transient same-user holder must serialize this acquisition, not
        // fail it closed: this is the nextest-parallel / CLI-races-main
        // overlap, and refusing it with "already in progress" would be wrong.
        let second = InspectionCoordinator::acquire(
            TemporaryRootAuthority::open(temp.path(), "test store").unwrap(),
            "test store",
        )
        .expect("bounded contention wait must serialize behind a brief holder");
        drop(second);
        holder.join().unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn immutable_coordinator_reaps_crash_state_and_refuses_live_concurrency() {
        // Cross-process per-uid serialization: this test drives a product
        // immutable-SQLite inspection, whose coordinator is a per-euid singleton with a
        // NONBLOCKING 3s product deadline. Two suites under one uid made it refuse with a
        // storage-integrity message for a scheduling cause. See
        // kata_test_utils::inspection_lock.
        let _inspection_lock = kata_test_utils::inspection_lock::hold();
        use std::os::unix::fs::PermissionsExt as _;

        let temp = tempfile::tempdir().unwrap();
        std::fs::set_permissions(temp.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let first = InspectionCoordinator::acquire(
            TemporaryRootAuthority::open(temp.path(), "test store").unwrap(),
            "test store",
        )
        .unwrap();
        let busy = InspectionCoordinator::acquire_with_contention_deadline(
            TemporaryRootAuthority::open(temp.path(), "test store").unwrap(),
            "test store",
            std::time::Duration::from_millis(100),
        )
        .err()
        .expect("a live holder must make a second inspection fail promptly");
        assert!(busy.to_string().contains("already in progress"));

        let stale = first.path.join(format!(
            "{PRIVATE_SNAPSHOT_ATTEMPT_PREFIX}{}",
            ulid::Ulid::new()
        ));
        std::fs::create_dir(&stale).unwrap();
        std::fs::set_permissions(&stale, std::fs::Permissions::from_mode(0o700)).unwrap();
        let stale_snapshot = stale.join(PRIVATE_SNAPSHOT_NAME);
        std::fs::write(&stale_snapshot, b"crash residue").unwrap();
        std::fs::set_permissions(&stale_snapshot, std::fs::Permissions::from_mode(0o600)).unwrap();
        drop(first); // Equivalent on-disk state to a process killed after creation.

        let recovered = InspectionCoordinator::acquire(
            TemporaryRootAuthority::open(temp.path(), "test store").unwrap(),
            "test store",
        )
        .unwrap();
        assert!(
            !stale.exists(),
            "next lock owner must reap validated crash residue"
        );
        drop(recovered);
        assert_clean_persistent_coordinator(temp.path());
    }

    #[cfg(unix)]
    #[test]
    fn immutable_coordinator_preserves_counterfeit_and_bounds_scans() {
        // Cross-process per-uid serialization: this test drives a product
        // immutable-SQLite inspection, whose coordinator is a per-euid singleton with a
        // NONBLOCKING 3s product deadline. Two suites under one uid made it refuse with a
        // storage-integrity message for a scheduling cause. See
        // kata_test_utils::inspection_lock.
        let _inspection_lock = kata_test_utils::inspection_lock::hold();
        use std::os::unix::fs::PermissionsExt as _;

        let temp = tempfile::tempdir().unwrap();
        std::fs::set_permissions(temp.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let coordinator = temp.path().join(private_snapshot_coordinator_basename());
        std::fs::create_dir(&coordinator).unwrap();
        std::fs::set_permissions(&coordinator, std::fs::Permissions::from_mode(0o700)).unwrap();
        let lock = coordinator.join(PRIVATE_SNAPSHOT_COORDINATOR_LOCK);
        std::fs::write(&lock, b"").unwrap();
        std::fs::set_permissions(&lock, std::fs::Permissions::from_mode(0o600)).unwrap();
        let counterfeit = coordinator.join(format!(
            "{PRIVATE_SNAPSHOT_ATTEMPT_PREFIX}{}",
            ulid::Ulid::new()
        ));
        std::fs::create_dir(&counterfeit).unwrap();
        std::fs::set_permissions(&counterfeit, std::fs::Permissions::from_mode(0o755)).unwrap();
        let error = InspectionCoordinator::acquire(
            TemporaryRootAuthority::open(temp.path(), "test store").unwrap(),
            "test store",
        )
        .err()
        .expect("counterfeit strict-name attempt must fail closed");
        assert!(error.to_string().contains("effective-owner 0700"));
        assert!(counterfeit.exists(), "counterfeit must be preserved");

        std::fs::remove_dir(&counterfeit).unwrap();
        let unknown = coordinator.join("unknown-entry");
        std::fs::write(&unknown, b"preserve").unwrap();
        let error = InspectionCoordinator::acquire(
            TemporaryRootAuthority::open(temp.path(), "test store").unwrap(),
            "test store",
        )
        .err()
        .expect("unknown entry below the scan cap must fail closed");
        assert!(error.to_string().contains("unknown entry"));
        assert_eq!(std::fs::read(&unknown).unwrap(), b"preserve");
        std::fs::remove_file(unknown).unwrap();

        for index in 0..PRIVATE_SNAPSHOT_MAX_COORDINATOR_ENTRIES {
            std::fs::write(coordinator.join(format!("unknown-{index}")), b"preserve").unwrap();
        }
        let error = InspectionCoordinator::acquire(
            TemporaryRootAuthority::open(temp.path(), "test store").unwrap(),
            "test store",
        )
        .err()
        .expect("bounded scan must refuse excess entries");
        assert!(error.to_string().contains("bounded 64-entry"));
        assert!(coordinator.join("unknown-0").exists());
    }

    #[cfg(unix)]
    #[test]
    fn immutable_partial_write_loop_checks_progress_between_actual_writes() {
        struct ShortWriter {
            bytes: Vec<u8>,
            calls: usize,
        }
        impl std::io::Write for ShortWriter {
            fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
                self.calls += 1;
                let count = bytes.len().min(2);
                self.bytes.extend_from_slice(&bytes[..count]);
                Ok(count)
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }

        let expected = b"partial writes are real";
        let mut writer = ShortWriter {
            bytes: Vec::new(),
            calls: 0,
        };
        let mut copied = 0;
        let mut remaining = expected.len() as u64;
        write_private_snapshot_chunk_bounded(
            &mut writer,
            expected,
            Instant::now() + Duration::from_secs(1),
            &mut copied,
            &mut remaining,
            expected.len() as u64,
            "test store",
        )
        .unwrap();
        assert_eq!(writer.bytes, expected);
        assert!(writer.calls > 1);
        assert_eq!((copied, remaining), (expected.len() as u64, 0));

        struct SlowShortWriter {
            calls: usize,
        }
        impl std::io::Write for SlowShortWriter {
            fn write(&mut self, _bytes: &[u8]) -> std::io::Result<usize> {
                self.calls += 1;
                std::thread::sleep(Duration::from_millis(10));
                Ok(1)
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let mut slow = SlowShortWriter { calls: 0 };
        let mut copied = 0;
        let mut remaining = 2;
        let error = write_private_snapshot_chunk_bounded(
            &mut slow,
            b"ab",
            Instant::now() + Duration::from_millis(1),
            &mut copied,
            &mut remaining,
            2,
            "test store",
        )
        .expect_err("deadline must be checked after an actual short write");
        assert!(error.to_string().contains("between partial-write calls"));
        assert_eq!((slow.calls, copied, remaining), (1, 1, 1));
    }

    #[cfg(unix)]
    #[test]
    fn immutable_clone_outcome_seams_cover_success_fallback_and_hard_failure_cleanup() {
        // Cross-process per-uid serialization: this test drives a product
        // immutable-SQLite inspection, whose coordinator is a per-euid singleton with a
        // NONBLOCKING 3s product deadline. Two suites under one uid made it refuse with a
        // storage-integrity message for a scheduling cause. See
        // kata_test_utils::inspection_lock.
        let _inspection_lock = kata_test_utils::inspection_lock::hold();
        use std::os::unix::fs::PermissionsExt as _;

        fn create_database(path: &Path) {
            let connection = Connection::open(path).unwrap();
            connection
                .execute_batch(
                    "CREATE TABLE expected (value INTEGER NOT NULL); \
                     INSERT INTO expected VALUES (7);",
                )
                .unwrap();
        }

        let successful_temp = tempfile::tempdir().unwrap();
        std::fs::set_permissions(
            successful_temp.path(),
            std::fs::Permissions::from_mode(0o700),
        )
        .unwrap();
        let successful_source = successful_temp.path().join("authority.db");
        create_database(&successful_source);
        let successful_root = successful_temp.path().join("snapshots");
        std::fs::create_dir(&successful_root).unwrap();
        std::fs::set_permissions(&successful_root, std::fs::Permissions::from_mode(0o700)).unwrap();
        let success_policy = SnapshotMaterializationPolicy {
            temporary_root: Some(successful_root.clone()),
            clone_outcome: TestCloneOutcome::Success,
            ..SnapshotMaterializationPolicy::default()
        };
        let value = inspect_optional_immutable_sqlite_with_hooks_and_policy(
            &successful_source,
            "test store",
            || {},
            |_| {},
            &success_policy,
            |connection| {
                connection
                    .query_row("SELECT value FROM expected", [], |row| row.get::<_, i64>(0))
                    .map_err(|error| KataError::Storage(error.to_string()))
            },
        )
        .unwrap();
        assert_eq!(value, Some(7));
        assert_clean_persistent_coordinator(&successful_root);

        for errno in [
            libc::EOPNOTSUPP,
            libc::ENOTTY,
            libc::EXDEV,
            libc::EINVAL,
            libc::ENOSYS,
        ] {
            let temp = tempfile::tempdir().unwrap();
            std::fs::set_permissions(temp.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
            let source = temp.path().join("authority.db");
            create_database(&source);
            let root = temp.path().join("snapshots");
            std::fs::create_dir(&root).unwrap();
            std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
            let policy = SnapshotMaterializationPolicy {
                temporary_root: Some(root.clone()),
                available_bytes: Some(u64::MAX),
                copy_progress_timeout: Some(Duration::from_secs(30)),
                clone_outcome: TestCloneOutcome::Error {
                    errno,
                    leave_partial_destination: true,
                },
                ..SnapshotMaterializationPolicy::default()
            };
            let value = inspect_optional_immutable_sqlite_with_hooks_and_policy(
                &source,
                "test store",
                || {},
                |_| {},
                &policy,
                |connection| {
                    connection
                        .query_row("SELECT value FROM expected", [], |row| row.get::<_, i64>(0))
                        .map_err(|error| KataError::Storage(error.to_string()))
                },
            )
            .unwrap();
            assert_eq!(value, Some(7), "fallback errno {errno}");
            assert_clean_persistent_coordinator(&root);
        }

        let failed_temp = tempfile::tempdir().unwrap();
        std::fs::set_permissions(failed_temp.path(), std::fs::Permissions::from_mode(0o700))
            .unwrap();
        let failed_source = failed_temp.path().join("authority.db");
        create_database(&failed_source);
        let failed_root = failed_temp.path().join("snapshots");
        std::fs::create_dir(&failed_root).unwrap();
        std::fs::set_permissions(&failed_root, std::fs::Permissions::from_mode(0o700)).unwrap();
        let failed_policy = SnapshotMaterializationPolicy {
            temporary_root: Some(failed_root.clone()),
            clone_outcome: TestCloneOutcome::Error {
                errno: libc::EPERM,
                leave_partial_destination: true,
            },
            ..SnapshotMaterializationPolicy::default()
        };
        let error = inspect_optional_immutable_sqlite_with_hooks_and_policy(
            &failed_source,
            "test store",
            || {},
            |_| {},
            &failed_policy,
            |_| -> KataResult<()> { panic!("hard clone failure must not inspect") },
        )
        .expect_err("non-fallback clone error must fail closed");
        let message = error.to_string();
        assert!(
            message.contains("descriptor reflink failed")
                || message.contains("descriptor clone failed"),
            "{message}"
        );
        assert_clean_persistent_coordinator(&failed_root);
    }

    #[cfg(unix)]
    #[test]
    fn immutable_forced_copy_fallback_has_hard_capacity_and_cooperative_progress_bounds() {
        // Cross-process per-uid serialization: this test drives a product
        // immutable-SQLite inspection, whose coordinator is a per-euid singleton with a
        // NONBLOCKING 3s product deadline. Two suites under one uid made it refuse with a
        // storage-integrity message for a scheduling cause. See
        // kata_test_utils::inspection_lock.
        let _inspection_lock = kata_test_utils::inspection_lock::hold();
        let temp = tempfile::tempdir().unwrap();
        let source = temp.path().join("authority.db");
        let connection = Connection::open(&source).unwrap();
        connection
            .execute_batch("CREATE TABLE expected (value INTEGER);")
            .unwrap();
        drop(connection);

        let successful = SnapshotMaterializationPolicy {
            force_copy: true,
            available_bytes: Some(u64::MAX),
            copy_progress_timeout: Some(Duration::from_secs(30)),
            ..SnapshotMaterializationPolicy::default()
        };
        inspect_optional_immutable_sqlite_with_hooks_and_policy(
            &source,
            "test store",
            || {},
            |_| {},
            &successful,
            |connection| {
                connection
                    .query_row("SELECT count(*) FROM expected", [], |row| {
                        row.get::<_, i64>(0)
                    })
                    .map(|_| ())
                    .map_err(|error| KataError::Storage(error.to_string()))
            },
        )
        .unwrap();

        let no_capacity = SnapshotMaterializationPolicy {
            available_bytes: Some(0),
            ..successful.clone()
        };
        let error = inspect_optional_immutable_sqlite_with_hooks_and_policy(
            &source,
            "test store",
            || {},
            |_| {},
            &no_capacity,
            |_| Ok(()),
        )
        .expect_err("fallback capacity must be proven before copying");
        assert!(error.to_string().contains("safety headroom"));

        let expired = SnapshotMaterializationPolicy {
            copy_progress_timeout: Some(Duration::ZERO),
            ..successful
        };
        let error = inspect_optional_immutable_sqlite_with_hooks_and_policy(
            &source,
            "test store",
            || {},
            |_| {},
            &expired,
            |_| Ok(()),
        )
        .expect_err("expired fallback progress deadline must fail before callback");
        let message = error.to_string();
        assert!(message.contains("cooperative") && message.contains("progress deadline"));
    }

    #[cfg(unix)]
    #[test]
    fn immutable_materialization_enforces_maximum_before_allocation() {
        let temp = tempfile::tempdir().unwrap();
        let source_path = temp.path().join("authority.db");
        std::fs::write(&source_path, b"small").unwrap();
        let mut source = File::open(&source_path).unwrap();
        let mut snapshot = sqlite_file_snapshot(&source_path, "test store").unwrap();
        snapshot.len = MAX_PRIVATE_SNAPSHOT_BYTES + 1;
        let error = materialize_private_sqlite_snapshot(
            &mut source,
            &snapshot,
            "test store",
            &SnapshotMaterializationPolicy::default(),
        )
        .err()
        .expect("oversized descriptor must fail before creating a snapshot");
        assert!(error.to_string().contains("private-snapshot maximum"));
    }

    #[test]
    fn immutable_cleanup_error_preserves_operation_error_context() {
        let operation = Err(KataError::Storage("primary failure".to_string()));
        let cleanup = Err(KataError::Storage("cleanup failure".to_string()));
        let error = finish_private_snapshot_operation::<()>(operation, cleanup, "test store")
            .expect_err("both failures must remain visible");
        let message = error.to_string();
        assert!(message.contains("primary failure"));
        assert!(message.contains("cleanup failure"));
    }

    #[cfg(unix)]
    #[test]
    fn immutable_open_flags_refuse_symbolic_links() {
        use std::os::unix::fs::symlink;

        let temp = tempfile::tempdir().unwrap();
        let target = temp.path().join("target.db");
        let connection = Connection::open(&target).unwrap();
        connection
            .execute_batch("CREATE TABLE expected (value INTEGER);")
            .unwrap();
        drop(connection);

        let alias = temp.path().join("alias.db");
        symlink(&target, &alias).unwrap();
        let uri = immutable_sqlite_uri(&alias, "test store").unwrap();
        let error = Connection::open_with_flags(uri, immutable_open_flags())
            .expect_err("SQLITE_OPEN_NOFOLLOW must refuse a symbolic-link database path");

        assert!(
            error.to_string().contains("unable to open database file"),
            "unexpected SQLite refusal: {error}",
        );
    }
}
