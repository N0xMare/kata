//! The OCI route's per-attempt directory, `<worker_state>/attempts/<attempt_tag>`, as an
//! OWNED value — and the worker-start sweep that reclaims the ones nobody owns.
//!
//! # Ownership is a `flock`, not a naming convention
//!
//! Several workers on one node share one `worker_state` (every worker uses the MAIN's
//! data directory: the supervised node and each standalone daemon), so "this directory exists"
//! says nothing about whether a live drive is using it. [`OwnedAttemptRoot::acquire`]
//! creates the directory and takes an exclusive `flock` on it that is held for the whole
//! drive AND the caller's publish of `/out`; the kernel drops it when the owning process
//! dies, however it dies. The sweep takes the same lock non-blocking, so a root some
//! live process holds is never touched.
//!
//! # Three ways a root ends, and the one way it does not
//!
//! * **Published** — [`OwnedAttemptRoot::remove`] after `/out` is an artifact: the tree
//!   holds the materialized `/work`, the bundle and the runtime's state, and nothing
//!   reads any of it again. Nothing the guest built under it keeps it: the removal walks
//!   the tree itself ([`remove_tree`]) — descriptor-relative, never through a link,
//!   restoring the owner's access to a directory the guest closed before opening it
//!   (through a descriptor bound to the inode it inspected, never by name), holding at
//!   most [`OPEN_LEVELS`] listings open and a heap stack of one small record per level
//!   whatever depth the guest nested to, costing time linear in the entries however wide
//!   it made a directory, and stopping rather than leaving the root if the tree changes
//!   under it.
//! * **Refused with the teardown CONFIRMED** — the driver removes it the same way.
//! * **`teardown_ambiguous`** — [`OwnedAttemptRoot::retain_ambiguous`] writes
//!   [`TEARDOWN_AMBIGUOUS_MARKER`] and keeps the tree: kata could not confirm the
//!   container's subtree empty, and a recursive delete would race a container it just said
//!   it cannot account for. The marker is what `kata doctor`'s `oci_attempt_roots_retained`
//!   row reads, so the root has an owner an operator can see
//!   ([`retained_attempt_roots`]), and the next worker start reclaims it once no
//!   process is left in the container's cgroup ([`sweep_attempt_roots`]).
//!
//! A removal that FAILS (a mount point beneath the root answers `EBUSY`, an immutable
//! entry `EPERM`) leaves the root on disk, and [`OwnedAttemptRoot::remove`] records the
//! failure in a [`REMOVAL_FAILED_SUFFIX`] file BESIDE the root, in `attempts/` — kata's
//! own directory, so the marker neither depends on the root's own directory accepting a
//! write nor is taken by the walk. The same `oci_attempt_roots_retained` row lists it,
//! every worker start retries the removal, and the removal that succeeds deletes the
//! marker. A marker whose write itself fails (`attempts/` refuses it) is logged and not
//! listed.

use std::fs::File;
use std::path::{Path, PathBuf};

/// The file a `teardown_ambiguous` attempt root carries, holding the unconfirmed
/// teardown's own words. Beside `work/` and `out/`, never inside a directory bound into
/// the container, so a stage cannot forge or erase it.
pub const TEARDOWN_AMBIGUOUS_MARKER: &str = "TEARDOWN_AMBIGUOUS";

/// The suffix of the file `<attempts>/<attempt_tag><suffix>` that records, beside the
/// root, why a removal of `<attempts>/<attempt_tag>` failed. Never inside the root, so the
/// walk does not take it and a root whose own directory refuses writes still gets one.
pub const REMOVAL_FAILED_SUFFIX: &str = ".REMOVAL_FAILED";

/// The subdirectory holding one directory per attempt.
const ATTEMPTS_DIRECTORY: &str = "attempts";

/// The attempt root's `oci/` — one `<container id>/` per container the provider started.
const ATTEMPT_OCI_DIRECTORY: &str = "oci";

/// `<worker_state>/attempts`.
#[must_use]
pub fn attempts_directory(worker_state: &Path) -> PathBuf {
    worker_state.join(ATTEMPTS_DIRECTORY)
}

/// One attempt root, created and exclusively `flock`ed for as long as this value lives.
#[derive(Debug)]
pub struct OwnedAttemptRoot {
    path: PathBuf,
    _lock: nix::fcntl::Flock<File>,
}

impl OwnedAttemptRoot {
    /// Create `path` (and its parents) and take its exclusive lock, without blocking.
    ///
    /// # Errors
    ///
    /// The OS text when the directory cannot be created or opened, and a refusal naming
    /// the root when another live process already holds it — an attempt tag is an attempt
    /// id, so a second holder is a duplicate drive, never something to wait for.
    pub fn acquire(path: &Path) -> Result<Self, String> {
        std::fs::create_dir_all(path)
            .map_err(|e| format!("create attempt root {}: {e}", path.display()))?;
        let directory =
            File::open(path).map_err(|e| format!("open attempt root {}: {e}", path.display()))?;
        let lock = nix::fcntl::Flock::lock(directory, nix::fcntl::FlockArg::LockExclusiveNonblock)
            .map_err(|(_, errno)| {
                format!(
                    "attempt root {} is held by another live drive ({errno}); an attempt runs \
                     once, and a second drive of it must not share or remove the first one's \
                     bytes",
                    path.display()
                )
            })?;
        Ok(Self {
            path: path.to_path_buf(),
            _lock: lock,
        })
    }

    /// The directory.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Remove the whole tree, still holding the lock, and release it. A failure is
    /// LOGGED and never raised: the caller's outcome (a published result, a refusal) is
    /// the operator's fact, and a cleanup error in its place would bury it. A root that
    /// is already gone (`NotFound`) is silent; anything that changes under the walk is a
    /// logged failure.
    ///
    /// The tree is the guest's as much as kata's — see [`remove_tree`] for what the
    /// guest may have left in it and why none of it keeps the root. Every caller removes
    /// a root whose container is gone — a confirmed teardown, or the sweep's empty
    /// cgroup — so nothing changes the tree while it is walked; if something did, the
    /// walk stops rather than leave the root.
    ///
    /// A failed removal writes [`REMOVAL_FAILED_SUFFIX`] beside the root with the error,
    /// so `kata doctor` lists it; a removal that succeeds (or finds the root gone) deletes
    /// that marker.
    pub fn remove(self, attempt_tag: &str, why: &'static str) {
        let marker = removal_failed_marker(&self.path);
        let removed = remove_tree(&self.path);
        match removed {
            Ok(()) => tracing::debug!(
                attempt = attempt_tag,
                attempt_root = %self.path.display(),
                why,
                "attempt root removed"
            ),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                tracing::warn!(
                    attempt = attempt_tag,
                    attempt_root = %self.path.display(),
                    why,
                    %error,
                    "the attempt root could NOT be removed; nothing will read its bytes, \
                     `kata doctor` lists it, and the next worker start's sweep retries it"
                );
                if let Err(write_error) = std::fs::write(&marker, format!("{error}\n")) {
                    tracing::warn!(
                        attempt = attempt_tag,
                        marker = %marker.display(),
                        error = %write_error,
                        "could not record the failed removal beside its attempt root; \
                         `kata doctor` will not list it"
                    );
                }
                return;
            }
        }
        remove_stale_marker(&marker);
    }

    /// Keep the tree, write [`TEARDOWN_AMBIGUOUS_MARKER`] with `outcome` in it, and
    /// release the lock — so the root is reported by `kata doctor` and reclaimed by a
    /// later worker start once its container is provably gone.
    pub fn retain_ambiguous(self, attempt_tag: &str, outcome: &str) {
        let marker = self.path.join(TEARDOWN_AMBIGUOUS_MARKER);
        if let Err(error) = std::fs::write(&marker, format!("{outcome}\n")) {
            tracing::warn!(
                attempt = attempt_tag,
                marker = %marker.display(),
                %error,
                "could not record the ambiguous teardown beside its attempt root; `kata doctor` \
                 will not list it"
            );
        }
        tracing::warn!(
            attempt = attempt_tag,
            attempt_root = %self.path.display(),
            "oci stage driver: attempt root LEFT IN PLACE because the teardown could not be \
             confirmed; removing it would race a container kata cannot account for"
        );
    }
}

/// `<attempts>/<attempt_tag><REMOVAL_FAILED_SUFFIX>` for the root `<attempts>/<attempt_tag>`.
fn removal_failed_marker(root: &Path) -> PathBuf {
    let mut name = root.file_name().unwrap_or_default().to_os_string();
    name.push(REMOVAL_FAILED_SUFFIX);
    root.with_file_name(name)
}

/// Delete a removal-failed marker whose root is gone. Best effort: a marker left behind
/// names no root, so the doctor row does not list it, and the next sweep retries.
fn remove_stale_marker(marker: &Path) {
    if let Err(error) = std::fs::remove_file(marker)
        && error.kind() != std::io::ErrorKind::NotFound
    {
        tracing::debug!(
            marker = %marker.display(),
            %error,
            "a removed attempt root's removal-failed marker could not be deleted"
        );
    }
}

/// Read as the directory it owns, so a caller that only needs the path (`/out` beneath
/// it, a `display()`) does not have to know it holds a lock.
impl std::ops::Deref for OwnedAttemptRoot {
    type Target = Path;

    fn deref(&self) -> &Path {
        &self.path
    }
}

/// Remove `root` and everything beneath it, as the guest may have left it.
///
/// The guest owned every directory under `work/`, `out/` and `git/` through its
/// single-uid mapping, so it may have:
///
/// * dropped a directory's mode — the worker holds no `CAP_DAC_OVERRIDE`, so an unlink
///   beneath a `0500` directory, or any read of a `0000` one, fails `EACCES`: each
///   directory's owner `rwx` is restored BEFORE it is opened;
/// * planted a link — every entry's kind is read with `lstat`, and a link is unlinked as
///   itself, never opened or changed through;
/// * nested directories as deep as the filesystem allows — the walk is a LOOP, not a
///   recursion, over a stack of levels on the heap, and holds at most [`OPEN_LEVELS`]
///   listings open: the deepest ones. A level above them keeps only its identity and the
///   `getdents` cookie of the child the walk is inside, so neither the descriptor table
///   nor the thread's stack grows with the guest's depth (the heap holds one small
///   record per level);
/// * made a directory as wide as the filesystem allows, every child a non-empty
///   directory — a listing is never read again from its start after a child is emptied:
///   an open one goes on where it was, and a closed one is reopened at that child's
///   cookie, so the cost is linear in the entries. (Reading again from the start is
///   quadratic on ext4, which keeps a directory's emptied blocks and walks them again on
///   every read.)
///
/// # What confines the walk
///
/// The walk changes the filesystem in exactly three ways — `unlinkat` of an entry, a
/// `chmod` restoring a directory's owner access, and a last `rmdir` of `root` by its
/// path (kata's own, never the guest's) — and reaches every entry from a descriptor of a
/// directory it holds, each held directory checked by identity, `(st_dev, st_ino)`:
///
/// * `root` is opened `O_NOFOLLOW`; a child is `lstat`ed by name in its parent's
///   descriptor, opened `O_NOFOLLOW`, and kept only if it is the directory the `lstat`
///   returned; a closed parent is reopened through the child's `..` and kept only if it
///   is the directory the walk descended from;
/// * `unlinkat` never follows a link: it removes the entry under that name in a held
///   directory, whatever the entry has become since its `lstat`;
/// * a directory's mode is restored through a descriptor bound to the inode, never by
///   name: the name is opened `O_PATH | O_NOFOLLOW` (which opens a link as itself), the
///   descriptor is kept only if it is a directory with the `lstat`'s `(st_dev, st_ino)`,
///   and the `chmod` goes through `/proc/self/fd/<n>`, which the kernel resolves to the
///   inode that descriptor holds rather than to a name (glibc's
///   `fchmodat(AT_SYMLINK_NOFOLLOW)` does the same).
///
/// So every inode the walk changes is one it found, by those checks, to be an entry of a
/// directory it reached from `root`. A name swapped after its `lstat` — for a link to
/// anything outside, or for another directory — and a directory renamed while the walk is
/// inside it, end the removal with an error, never a step past the root; so does an entry
/// that vanishes from under it: only `root` itself being gone is `NotFound`.
///
/// A filesystem mounted on a directory beneath the root is never entered or emptied: the
/// walk's first change to a directory its listing returns is `unlinkat(REMOVEDIR)`,
/// which a mount point answers `EBUSY`, and the walk stops there with that error. That
/// rmdir-first order is what protects a mounted filesystem — the identity check and the
/// `..` climb would both pass on a mount's root.
///
/// What the checks do NOT refuse, because no guest can bring it about:
///
/// * a held directory moved OUT of the root by a process that can write outside it — the
///   walk goes on emptying it where it now is. The guest never sees outside its tree, and
///   every caller's container is gone before the removal;
/// * an inode freed and its `(st_dev, st_ino)` reused, between a check and the act, by a
///   directory created elsewhere and renamed in — identity is that pair, and only a
///   process writing both inside and outside the tree during the removal could do it;
/// * a `/proc` that is not this host's procfs — the mode restore trusts `/proc/self/fd`.
///
/// A directory that still will not go after a listing from its start found nothing in it
/// is an error, not a loop. Any other directory that will not go is listed again (a
/// filesystem whose cookies did not survive the removal of earlier entries can only leave
/// entries behind, never reach outside the tree).
fn remove_tree(root: &Path) -> std::io::Result<()> {
    remove_tree_observed(root, |_| {})
}

/// What [`remove_tree_observed`] reports as it walks — the seam its cells change the tree
/// at, and read the kernel's state through. A depth counts from `root`, which is 0.
#[cfg_attr(not(test), allow(dead_code))] // read only by the cells
enum Step<'a> {
    /// The listing at `depth - 1` returned `name`, a directory its `lstat` found not
    /// empty — before the walk restores its mode or opens it.
    Found {
        depth: usize,
        name: &'a std::ffi::CStr,
    },
    /// The mode restore for `name` opened it `O_PATH` and found the descriptor to be the
    /// directory `Found` named — before it changes the mode.
    Restoring { name: &'a std::ffi::CStr },
    /// The walk opened the directory at `depth` and has not listed it yet.
    Entered(usize),
    /// The listing at `depth` returned nothing more; its directory is removed next.
    Leaving(usize),
    /// The listing at `depth` was closed and is now open again through `..`, positioned
    /// to return the child just emptied; `listing` is its descriptor.
    Reopened {
        depth: usize,
        listing: std::os::fd::BorrowedFd<'a>,
    },
}

/// [`remove_tree`], reporting each [`Step`] to `observe`.
fn remove_tree_observed(root: &Path, mut observe: impl FnMut(Step<'_>)) -> std::io::Result<()> {
    let directory = rustix::fs::open(root, WALK_FLAGS, rustix::fs::Mode::empty())?;
    walk(directory, &mut observe).map_err(|error| {
        if error.kind() == std::io::ErrorKind::NotFound {
            std::io::Error::other(format!(
                "an entry vanished while the tree was being removed: {error}"
            ))
        } else {
            error
        }
    })?;
    std::fs::remove_dir(root)
}

const WALK_FLAGS: rustix::fs::OFlags = rustix::fs::OFlags::RDONLY
    .union(rustix::fs::OFlags::DIRECTORY)
    .union(rustix::fs::OFlags::NOFOLLOW)
    .union(rustix::fs::OFlags::CLOEXEC);

/// The most listings [`remove_tree`] holds open at once — its whole descriptor budget,
/// whatever depth the guest nested to.
const OPEN_LEVELS: usize = 16;

/// A directory's identity, which a name or `..` does not carry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct DirectoryId {
    dev: u64,
    ino: u64,
}

impl DirectoryId {
    fn of(stat: &rustix::fs::Stat) -> Self {
        Self {
            dev: stat.st_dev,
            ino: stat.st_ino,
        }
    }
}

/// One directory on the walk's stack.
struct Level {
    id: DirectoryId,
    /// The open listing — `None` once the walk is more than [`OPEN_LEVELS`] deeper.
    listing: Option<rustix::fs::Dir>,
    /// The cookie of the next entry the listing returns.
    position: i64,
    /// Whether the listing was opened (or last positioned) at the directory's start, and
    /// whether it has returned an entry since: both together say the directory was
    /// listed empty.
    from_start: bool,
    found: bool,
    /// The child the walk is inside: its cookie, and its name while this level's listing
    /// is open (a closed level is reopened at the cookie, which returns the child again).
    child_at: Option<i64>,
    child_name: Option<std::ffi::CString>,
}

impl Level {
    fn opened(fd: std::os::fd::OwnedFd, id: DirectoryId) -> std::io::Result<Self> {
        Ok(Self {
            id,
            listing: Some(rustix::fs::Dir::new(fd)?),
            position: 0,
            from_start: true,
            found: false,
            child_at: None,
            child_name: None,
        })
    }

    fn open_listing(&self) -> std::io::Result<std::os::fd::BorrowedFd<'_>> {
        match &self.listing {
            Some(listing) => Ok(listing.fd()?),
            None => Err(std::io::Error::other(
                "the walk used a directory it had closed",
            )),
        }
    }

    /// Reposition the open listing at `cookie`, so it returns that entry next.
    fn seek(&mut self, cookie: i64) -> std::io::Result<()> {
        if let Some(listing) = self.listing.as_mut() {
            listing.seek(cookie)?;
        }
        self.position = cookie;
        self.from_start = cookie == 0;
        self.found = false;
        Ok(())
    }
}

/// Empty the tree under `root` (which the caller removes).
fn walk(root: std::os::fd::OwnedFd, observe: &mut impl FnMut(Step<'_>)) -> std::io::Result<()> {
    let root_id = DirectoryId::of(&rustix::fs::fstat(&root)?);
    let mut stack = vec![Level::opened(root, root_id)?];
    // The open levels are always the deepest `open` of the stack.
    let mut open = 1;
    loop {
        let depth = stack.len();
        let Some(level) = stack.last_mut() else {
            return Ok(());
        };
        if let Some((name, stat)) = next_full_directory(level)? {
            observe(Step::Found { depth, name: &name });
            let child = descend(level, &name, &stat, observe)?;
            if open == OPEN_LEVELS {
                let shallowest = stack.len() - open;
                stack[shallowest].listing = None;
                stack[shallowest].child_name = None;
                open -= 1;
            }
            stack.push(child);
            open += 1;
            observe(Step::Entered(depth));
            continue;
        }
        observe(Step::Leaving(depth - 1));
        let Some(left) = stack.pop() else {
            return Ok(());
        };
        open -= 1;
        let listed_empty = left.from_start && !left.found;
        let Some(parent) = stack.last_mut() else {
            return Ok(());
        };
        let Some(cookie) = parent.child_at.take() else {
            return Err(std::io::Error::other(
                "the walk left a directory it never entered",
            ));
        };
        if let Some(name) = parent.child_name.take() {
            let directory = parent.open_listing()?;
            match rustix::fs::unlinkat(directory, &name, rustix::fs::AtFlags::REMOVEDIR) {
                Ok(()) => {}
                Err(rustix::io::Errno::NOTEMPTY | rustix::io::Errno::EXIST) if !listed_empty => {
                    // Entries its listing did not return: list the child again.
                    parent.seek(cookie)?;
                }
                Err(error) => return Err(error.into()),
            }
        } else {
            let up = rustix::fs::openat(
                left.open_listing()?,
                c"..",
                WALK_FLAGS,
                rustix::fs::Mode::empty(),
            )?;
            if DirectoryId::of(&rustix::fs::fstat(&up)?) != parent.id {
                return Err(changed_under_the_walk(c".."));
            }
            parent.listing = Some(rustix::fs::Dir::new(up)?);
            open += 1;
            // The reopened listing returns the emptied child first, and removes it. A child
            // that will not go is entered again from its start, and a listing from its
            // start that finds nothing ends the walk when the child is left.
            parent.seek(cookie)?;
            observe(Step::Reopened {
                depth: depth - 2,
                listing: parent.open_listing()?,
            });
        }
    }
}

/// Restore `name`'s owner access, open it, check it is the directory `stat` named, and
/// record it as `level`'s child.
fn descend(
    level: &mut Level,
    name: &std::ffi::CStr,
    stat: &rustix::fs::Stat,
    observe: &mut impl FnMut(Step<'_>),
) -> std::io::Result<Level> {
    let directory = level.open_listing()?;
    if stat.st_mode & 0o700 != 0o700 {
        restore_owner_access(directory, name, stat, observe)?;
    }
    let child = rustix::fs::openat(directory, name, WALK_FLAGS, rustix::fs::Mode::empty())?;
    let id = DirectoryId::of(&rustix::fs::fstat(&child)?);
    if id != DirectoryId::of(stat) {
        return Err(changed_under_the_walk(name));
    }
    level.child_at = Some(level.position);
    level.child_name = Some(name.to_owned());
    Level::opened(child, id)
}

/// Give the directory `stat` describes, found as `name` in `directory`, its owner `rwx`
/// back — through a descriptor bound to that inode, never by name. A directory with no
/// read bit cannot be opened for an `fchmod`, so the descriptor is `O_PATH`, and the
/// `chmod` goes through its `/proc/self/fd` entry, which resolves to the inode itself.
fn restore_owner_access(
    directory: std::os::fd::BorrowedFd<'_>,
    name: &std::ffi::CStr,
    stat: &rustix::fs::Stat,
    observe: &mut impl FnMut(Step<'_>),
) -> std::io::Result<()> {
    use std::os::fd::AsRawFd;
    let pinned = rustix::fs::openat(
        directory,
        name,
        rustix::fs::OFlags::PATH | rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )?;
    let found = rustix::fs::fstat(&pinned)?;
    if rustix::fs::FileType::from_raw_mode(found.st_mode) != rustix::fs::FileType::Directory
        || DirectoryId::of(&found) != DirectoryId::of(stat)
    {
        return Err(changed_under_the_walk(name));
    }
    observe(Step::Restoring { name });
    let mode = rustix::fs::Mode::from_raw_mode(stat.st_mode & 0o7777) | rustix::fs::Mode::RWXU;
    rustix::fs::chmod(
        format!("/proc/self/fd/{}", pinned.as_raw_fd()).as_str(),
        mode,
    )?;
    Ok(())
}

fn changed_under_the_walk(name: &std::ffi::CStr) -> std::io::Error {
    std::io::Error::other(format!(
        "the tree changed while it was being removed: {name:?} is not the directory the walk \
         found there; the removal stops rather than act outside the root"
    ))
}

/// Read `level`'s listing on, unlinking every entry that goes in one call — every
/// non-directory, and every directory that is already empty — and return the first
/// directory that is NOT empty, with its `lstat`; `None` once the listing ends.
fn next_full_directory(
    level: &mut Level,
) -> std::io::Result<Option<(std::ffi::CString, rustix::fs::Stat)>> {
    let Some(listing) = level.listing.as_mut() else {
        return Err(std::io::Error::other(
            "the walk used a directory it had closed",
        ));
    };
    while let Some(entry) = listing.read() {
        let entry = entry?;
        let name = entry.file_name();
        if name.to_bytes() == b"." || name.to_bytes() == b".." {
            level.position = entry.offset();
            continue;
        }
        level.found = true;
        let directory = listing.fd()?;
        let stat = rustix::fs::statat(directory, name, rustix::fs::AtFlags::SYMLINK_NOFOLLOW)?;
        if rustix::fs::FileType::from_raw_mode(stat.st_mode) == rustix::fs::FileType::Directory {
            match rustix::fs::unlinkat(directory, name, rustix::fs::AtFlags::REMOVEDIR) {
                Ok(()) => {}
                Err(rustix::io::Errno::NOTEMPTY | rustix::io::Errno::EXIST) => {
                    return Ok(Some((name.to_owned(), stat)));
                }
                Err(error) => return Err(error.into()),
            }
        } else {
            rustix::fs::unlinkat(directory, name, rustix::fs::AtFlags::empty())?;
        }
        level.position = entry.offset();
    }
    Ok(None)
}

/// What one [`sweep_attempt_roots`] pass did.
#[derive(Debug, Default)]
pub struct AttemptRootSweep {
    /// Roots no live process held and no live process's cgroup names — removed.
    pub removed: Vec<PathBuf>,
    /// Roots kept because a live process is still in one of their containers' cgroups,
    /// with the container id that proved it.
    pub retained: Vec<(PathBuf, String)>,
}

/// The WORKER-START sweep of `<worker_state>/attempts`.
///
/// A root is removed only when BOTH hold: no live process holds its lock (so no drive or
/// publish is in flight anywhere on this node), and no process on this host is in a
/// cgroup naming any container the attempt started (read off every `/proc/<pid>/cgroup`,
/// which is the kernel's answer and does not depend on which delegated parent the
/// container's owner used). Everything else is left — a root is disk, a live container
/// is a stage — and a kept root with a live container is RETURNED for the boot line.
///
/// Best effort per entry: one unreadable root must not stop the rest, and the caller is a
/// worker that has to come up.
#[must_use]
pub fn sweep_attempt_roots(worker_state: &Path) -> AttemptRootSweep {
    let mut sweep = AttemptRootSweep::default();
    let Ok(entries) = std::fs::read_dir(attempts_directory(worker_state)) else {
        return sweep;
    };
    let mut live_cgroups: Option<String> = None;
    for entry in entries.flatten() {
        if !entry.file_type().is_ok_and(|t| t.is_dir()) {
            // A removal-failed marker whose root a removal took since (or a crash took
            // between the root's removal and the marker's).
            if let Some(root) = marker_root(&entry.path())
                && std::fs::symlink_metadata(&root)
                    .is_err_and(|error| error.kind() == std::io::ErrorKind::NotFound)
            {
                remove_stale_marker(&entry.path());
            }
            continue;
        }
        let path = entry.path();
        // Non-blocking: held means a live drive, which is not residue.
        let Ok(directory) = File::open(&path) else {
            continue;
        };
        let Ok(lock) =
            nix::fcntl::Flock::lock(directory, nix::fcntl::FlockArg::LockExclusiveNonblock)
        else {
            continue;
        };
        let cgroups = live_cgroups.get_or_insert_with(every_process_cgroup);
        if let Some(container) = container_ids(&path)
            .into_iter()
            .find(|id| names_container_cgroup(cgroups, id))
        {
            sweep.retained.push((path, container));
            continue;
        }
        let owned = OwnedAttemptRoot { path, _lock: lock };
        let path = owned.path.clone();
        owned.remove("worker-start", "worker_start_sweep");
        if !path.exists() {
            sweep.removed.push(path);
        }
    }
    sweep
}

/// The root a removal-failed marker names, when `marker` is one.
fn marker_root(marker: &Path) -> Option<PathBuf> {
    let name = marker.file_name()?.to_str()?;
    let tag = name.strip_suffix(REMOVAL_FAILED_SUFFIX)?;
    (!tag.is_empty()).then(|| marker.with_file_name(tag))
}

/// Why an attempt root is still on disk with no drive holding it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Retention {
    /// A removal of it failed; the error's text.
    RemovalFailed(String),
    /// Its container's teardown could not be confirmed; the teardown's own words.
    TeardownAmbiguous(String),
}

/// The attempt roots under `worker_state` that are still a directory and carry a marker —
/// a [`REMOVAL_FAILED_SUFFIX`] file beside them, or [`TEARDOWN_AMBIGUOUS_MARKER`] inside
/// — sorted by path: `kata doctor`'s `oci_attempt_roots_retained` row. A root with both
/// is listed once, as the failed removal: the removal ran, so the teardown was settled.
///
/// # Errors
///
/// The OS text when `<worker_state>/attempts` exists and cannot be read. An absent
/// directory is `Ok(empty)`: a node that never ran a capsule has nothing retained.
pub fn retained_attempt_roots(worker_state: &Path) -> Result<Vec<(PathBuf, Retention)>, String> {
    let attempts = attempts_directory(worker_state);
    let entries = match std::fs::read_dir(&attempts) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(format!("read {}: {error}", attempts.display())),
    };
    let mut retained: Vec<(PathBuf, Retention)> = entries
        .flatten()
        .filter(|entry| entry.file_type().is_ok_and(|t| t.is_dir()))
        .filter_map(|entry| {
            let root = entry.path();
            let read = |path: PathBuf| {
                std::fs::read_to_string(path)
                    .ok()
                    .map(|text| text.trim().to_owned())
            };
            let retention = read(removal_failed_marker(&root))
                .map(Retention::RemovalFailed)
                .or_else(|| {
                    read(root.join(TEARDOWN_AMBIGUOUS_MARKER)).map(Retention::TeardownAmbiguous)
                })?;
            Some((root, retention))
        })
        .collect();
    retained.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(retained)
}

/// The container ids an attempt's provider started: the directory names under `oci/`.
fn container_ids(attempt_root: &Path) -> Vec<String> {
    std::fs::read_dir(attempt_root.join(ATTEMPT_OCI_DIRECTORY))
        .map(|entries| {
            entries
                .flatten()
                .filter(|entry| entry.file_type().is_ok_and(|t| t.is_dir()))
                .filter_map(|entry| entry.file_name().into_string().ok())
                .collect()
        })
        .unwrap_or_default()
}

/// Whether any line of `cgroups` places a process in `kata.oci.<container>` or beneath it.
fn names_container_cgroup(cgroups: &str, container: &str) -> bool {
    let parent = format!("/kata.oci.{container}");
    cgroups
        .lines()
        .any(|line| line.ends_with(&parent) || line.contains(&format!("{parent}/")))
}

/// Every live process's `/proc/<pid>/cgroup` text, concatenated.
fn every_process_cgroup() -> String {
    let mut all = String::new();
    let Ok(entries) = std::fs::read_dir("/proc") else {
        return all;
    };
    for entry in entries.flatten() {
        if entry
            .file_name()
            .to_str()
            .is_some_and(|name| name.bytes().all(|b| b.is_ascii_digit()))
            && let Ok(text) = std::fs::read_to_string(entry.path().join("cgroup"))
        {
            all.push_str(&text);
            all.push('\n');
        }
    }
    all
}

#[cfg(test)]
mod tests {
    use super::{OPEN_LEVELS, Step, remove_tree_observed};
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::PermissionsExt;
    use std::path::Path;

    /// **A directory renamed shallower while the removal is inside it never takes the
    /// removal out of the root.** The root is `<state>/attempts/victim`, beside a sibling
    /// attempt and a file in `attempts/` and in `<state>`; the guest's tree is a chain of
    /// directories under `work/` ending in `big`, which holds files. When the walk enters
    /// `big`, a directory of the chain is moved up to `work/` — two levels shallower. The
    /// walk must stop with an error that is not `NotFound` (which `remove` would swallow)
    /// and touch nothing outside the root. Two cases, one per way back to a parent:
    ///
    /// * `work/a/b/c/big`, `c` moved: every level's listing is still open, and the walk
    ///   finds `c` gone from `b` when it comes back to remove it;
    /// * a chain deeper than [`OPEN_LEVELS`], `d3` moved: `d2`'s listing was closed, so
    ///   the walk climbs from `d3` by `..`, reaches `work`, and must see it is not `d2`.
    ///
    /// The filesystem is read through `std::fs`.
    ///
    /// **Would red if:** the walk climbed back by `..` trusting a depth count instead of
    /// the identity of the directory it descended from.
    #[test]
    fn a_rename_under_the_walk_never_takes_it_out_of_the_root() {
        let deep: Vec<String> = (1..=OPEN_LEVELS + 4).map(|n| format!("d{n}")).collect();
        let deep: Vec<&str> = deep.iter().map(String::as_str).collect();
        let cases: [(&str, Vec<&str>, &str, &str); 2] = [
            (
                "inside the open listings",
                vec!["a", "b", "c"],
                "work/a/b/c",
                "an entry vanished",
            ),
            (
                "beyond the open listings",
                deep.clone(),
                "work/d1/d2/d3",
                "the tree changed",
            ),
        ];
        let mut failures = Vec::new();
        for (case, chain, moved, expected) in cases {
            let scratch = tempfile::tempdir().expect("a scratch directory");
            // One guard level, so even a walk that escaped further stays in the tempdir.
            let state = scratch.path().join("guard/state");
            let attempts = state.join("attempts");
            let victim = attempts.join("victim");
            let mut big = victim.join("work");
            for name in &chain {
                big.push(name);
            }
            big.push("big");
            std::fs::create_dir_all(&big).unwrap();
            for n in 0..64 {
                std::fs::write(big.join(format!("f{n}")), b"guest bytes\n").unwrap();
            }
            std::fs::create_dir_all(attempts.join("sibling")).unwrap();
            let outside = [
                attempts.join("sibling/keep"),
                attempts.join("SENTINEL-ATTEMPTS"),
                state.join("SENTINEL-STATE"),
            ];
            for file in &outside {
                std::fs::write(file, b"not the guest's\n").unwrap();
            }

            // `work` is depth 1, so `big` is the chain's length plus 2.
            let big_depth = chain.len() + 2;
            let mut renamed = false;
            let outcome = remove_tree_observed(&victim, |step| {
                if matches!(step, Step::Entered(depth) if depth == big_depth) && !renamed {
                    renamed = true;
                    std::fs::rename(victim.join(moved), victim.join("work/moved")).unwrap();
                }
            });

            if !renamed {
                failures.push(format!("{case}: the walk never entered `big`"));
            }
            match &outcome {
                Err(error)
                    if error.kind() != std::io::ErrorKind::NotFound
                        && error.to_string().contains(expected) => {}
                other => failures.push(format!(
                    "{case}: the walk did not stop with \"{expected}\": {other:?}"
                )),
            }
            for file in &outside {
                if !file.exists() {
                    failures.push(format!("{case}: {} was removed", file.display()));
                }
            }
        }
        assert!(failures.is_empty(), "{failures:#?}");
    }

    /// The mode of `path` itself, never through a link.
    fn mode(path: &Path) -> u32 {
        std::fs::symlink_metadata(path)
            .unwrap()
            .permissions()
            .mode()
            & 0o7777
    }

    /// **A name swapped between the walk's `lstat` and its act on that directory never
    /// takes the walk outside the root, nor into a directory it did not inspect.** The
    /// root is `<state>/attempts/victim`; `<state>` holds an owner-only file and an
    /// owner-only directory the guest could never reach. Under `work/` are `closed` (a
    /// `0077` directory holding a file, so its owner access must be restored before it is
    /// opened) and `open` (a `0755` directory holding a file). At one of two steps the cell
    /// moves the named directory to `work/moved` and puts something else under its name:
    ///
    /// * at [`Step::Found`] — after its `lstat`, before the walk acts on it — `closed`
    ///   becomes a link to the outside FILE, and then a link to the outside DIRECTORY: a
    ///   mode restored by name follows the link and sets the outside target's mode to
    ///   `0777`; and `open` becomes a new directory holding a file: a walk that did not
    ///   check what it opened by identity would empty a directory it never inspected.
    ///   Each must end in "the tree changed";
    /// * at [`Step::Restoring`] — after the mode restore checked its `O_PATH` descriptor,
    ///   before it changes the mode — `closed` becomes a link to the outside FILE, and
    ///   then to the outside DIRECTORY. The check has already passed, so only acting
    ///   through that descriptor keeps the `chmod` off the link: the moved directory must
    ///   come out `0777`, and the walk must then end in an error.
    ///
    /// No case may end in `NotFound` (which `remove` would swallow) or `Ok`, and every
    /// case must leave the outside targets' modes and bytes as they were. Read through
    /// `std::fs`.
    ///
    /// **Would red if:** the mode restore re-resolved the name (`chmodat`) instead of
    /// acting through a descriptor bound to the inode the `lstat` named — at either
    /// step, even after checking that descriptor — or the walk entered a directory
    /// without comparing it with that `lstat`.
    #[test]
    fn a_name_swapped_after_the_walk_inspected_it_is_refused_never_followed() {
        enum Swap {
            LinkTo(&'static str),
            NewDirectory,
        }
        #[derive(PartialEq)]
        enum At {
            Found,
            Restoring,
        }
        let cases = [
            ("closed", Swap::LinkTo("PRECIOUS"), At::Found),
            ("closed", Swap::LinkTo("PRECIOUS-DIR"), At::Found),
            ("open", Swap::NewDirectory, At::Found),
            ("closed", Swap::LinkTo("PRECIOUS"), At::Restoring),
            ("closed", Swap::LinkTo("PRECIOUS-DIR"), At::Restoring),
        ];
        let mut failures = Vec::new();
        for (name, swap, at) in cases {
            let when = match at {
                At::Found => "at Found",
                At::Restoring => "at Restoring",
            };
            let case = match &swap {
                Swap::LinkTo(target) => format!("`{name}` swapped {when} for a link to {target}"),
                Swap::NewDirectory => format!("`{name}` swapped {when} for a new directory"),
            };
            let scratch = tempfile::tempdir().expect("a scratch directory");
            let state = scratch.path().join("guard/state");
            let victim = state.join("attempts/victim");
            let work = victim.join("work");
            for directory in ["closed", "open"] {
                std::fs::create_dir_all(work.join(directory)).unwrap();
                std::fs::write(work.join(directory).join("f"), b"guest bytes\n").unwrap();
            }
            std::fs::set_permissions(work.join("closed"), PermissionsExt::from_mode(0o077))
                .unwrap();
            let precious = state.join("PRECIOUS");
            let precious_dir = state.join("PRECIOUS-DIR");
            std::fs::write(&precious, b"not the guest's\n").unwrap();
            std::fs::create_dir(&precious_dir).unwrap();
            std::fs::write(precious_dir.join("keep"), b"not the guest's\n").unwrap();
            std::fs::set_permissions(&precious, PermissionsExt::from_mode(0o600)).unwrap();
            std::fs::set_permissions(&precious_dir, PermissionsExt::from_mode(0o700)).unwrap();

            let mut swapped = false;
            let outcome = remove_tree_observed(&victim, |step| {
                let ((At::Found, Step::Found { name: found, .. })
                | (At::Restoring, Step::Restoring { name: found })) = (&at, step)
                else {
                    return;
                };
                if found.to_bytes() == name.as_bytes() && !swapped {
                    swapped = true;
                    std::fs::rename(work.join(name), work.join("moved")).unwrap();
                    match &swap {
                        Swap::LinkTo(target) => {
                            std::os::unix::fs::symlink(state.join(target), work.join(name))
                                .unwrap();
                        }
                        Swap::NewDirectory => {
                            std::fs::create_dir(work.join(name)).unwrap();
                            std::fs::write(work.join(name).join("f"), b"never inspected\n")
                                .unwrap();
                        }
                    }
                }
            });

            if !swapped {
                failures.push(format!("{case}: the walk never found `{name}`"));
            }
            match (&at, &outcome) {
                (At::Found, Err(error))
                    if error.kind() != std::io::ErrorKind::NotFound
                        && error.to_string().contains("the tree changed") => {}
                (At::Restoring, Err(error)) if error.kind() != std::io::ErrorKind::NotFound => {}
                (At::Found, other) => failures.push(format!(
                    "{case}: the walk did not stop with \"the tree changed\": {other:?}"
                )),
                (At::Restoring, other) => failures.push(format!(
                    "{case}: the walk did not stop with an error other than NotFound: {other:?}"
                )),
            }
            if at == At::Restoring && swapped && mode(&work.join("moved")) != 0o777 {
                failures.push(format!(
                    "{case}: the directory the restore inspected came out {:o}, not 777",
                    mode(&work.join("moved"))
                ));
            }
            for (target, want) in [(&precious, 0o600), (&precious_dir, 0o700)] {
                if mode(target) != want {
                    failures.push(format!(
                        "{case}: {} changed mode from {want:o} to {:o}",
                        target.display(),
                        mode(target)
                    ));
                }
            }
            if std::fs::read(&precious).ok().as_deref() != Some(&b"not the guest's\n"[..])
                || !precious_dir.join("keep").exists()
            {
                failures.push(format!("{case}: an outside target's bytes changed"));
            }
            // Let the tempdir go: a `closed` the walk stopped before, moved or not, keeps
            // its guest mode.
            for left in [work.join("moved"), work.join("closed")] {
                if std::fs::symlink_metadata(&left).is_ok_and(|m| m.is_dir()) {
                    std::fs::set_permissions(&left, PermissionsExt::from_mode(0o700)).unwrap();
                }
            }
        }
        assert!(failures.is_empty(), "{failures:#?}");
    }

    /// **A listing the walk closed and reopens through `..` goes on at the child it just
    /// emptied, never at its start** — the half of the linear-time removal that the wide
    /// cell (`a_wide_guest_directory_is_removed_in_time_linear_in_its_entries`, whose tree
    /// is too shallow for any listing to close) cannot see, and that no timing cell can
    /// pin at a practical size. `work/wide` holds eight directories, each above a chain
    /// [`OPEN_LEVELS`] + 4 deep, so the walk closes `wide`'s listing inside every one of
    /// them and reopens it through `..` on the way back. Before the walk, the cell lists
    /// every directory of the tree itself, through its own descriptors, and takes each
    /// child's cookie from that listing: the `d_off` of the entry before it (0 for the
    /// first), the position a listing must be at to return that child next — never the
    /// walk's own record. It follows the walk's path through the [`Step::Found`] names;
    /// at each [`Step::Reopened`] it reads the reopened descriptor's offset from the
    /// KERNEL (`lseek(fd, 0, SEEK_CUR)`), which must be that independently listed cookie
    /// of the child just emptied. It also counts eight reopens of `wide`, at least seven
    /// of them at a cookie that is not 0 (the start; ext4 orders a listing by name hash,
    /// so one child may legitimately be first), so the cell cannot pass on a tree that
    /// never closed `wide`, or whose children all came first; and it requires the root
    /// gone.
    ///
    /// **Would red if:** a reopened listing were positioned at its start (or not
    /// positioned at all), or at a cookie other than the emptied child's — as when the
    /// walk's record of its position stopped advancing past an entry it read — a walk
    /// that is quadratic in a wide directory's entries whenever its children are deep.
    #[test]
    fn a_reopened_listing_goes_on_at_the_emptied_childs_cookie() {
        let scratch = tempfile::tempdir().expect("a scratch directory");
        let victim = scratch.path().join("attempts/victim");
        let wide = victim.join("work/wide");
        let siblings = 8;
        for n in 0..siblings {
            let mut chain = wide.join(format!("s{n}"));
            for level in 0..OPEN_LEVELS + 4 {
                chain.push(format!("c{level}"));
            }
            std::fs::create_dir_all(&chain).unwrap();
            std::fs::write(chain.join("f"), b"guest bytes\n").unwrap();
        }
        // `work` is depth 1 and `wide` depth 2.
        let wide_depth = 2;

        // Each child's cookie, by the path of its parent relative to `victim`, from the
        // cell's own listing of every directory before the walk.
        let mut cookies = std::collections::HashMap::new();
        let mut directories = vec![std::path::PathBuf::new()];
        while let Some(relative) = directories.pop() {
            let fd = rustix::fs::open(
                victim.join(&relative),
                rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::DIRECTORY,
                rustix::fs::Mode::empty(),
            )
            .unwrap();
            let mut listing = rustix::fs::Dir::new(fd).unwrap();
            let mut before = 0;
            while let Some(entry) = listing.read() {
                let entry = entry.unwrap();
                let name = std::ffi::OsStr::from_bytes(entry.file_name().to_bytes());
                if name != "." && name != ".." {
                    cookies.insert((relative.clone(), name.to_owned()), before);
                    if entry.file_type() == rustix::fs::FileType::Directory {
                        directories.push(relative.join(name));
                    }
                }
                before = entry.offset();
            }
        }

        // The walk's path: the name it found at each depth, `work` first.
        let mut path: Vec<std::ffi::OsString> = Vec::new();
        let mut wide_reopens = 0;
        let mut wide_reopens_past_start = 0;
        let mut failures = Vec::new();
        let outcome = remove_tree_observed(&victim, |step| match step {
            Step::Found { depth, name } => {
                path.truncate(depth - 1);
                path.push(std::ffi::OsStr::from_bytes(name.to_bytes()).to_owned());
            }
            Step::Reopened { depth, listing } => {
                let offset = rustix::fs::seek(listing, rustix::fs::SeekFrom::Current(0))
                    .expect("the reopened listing's offset");
                let parent: std::path::PathBuf = path[..depth].iter().collect();
                let child = path[depth].clone();
                let expected = cookies.get(&(parent.clone(), child.clone())).copied();
                if i64::try_from(offset).ok() != expected {
                    failures.push(format!(
                        "depth {depth}: reopened at offset {offset}, not at the cookie the \
                         cell listed for {child:?} in {parent:?}: {expected:?}"
                    ));
                }
                if depth == wide_depth {
                    wide_reopens += 1;
                    if expected != Some(0) {
                        wide_reopens_past_start += 1;
                    }
                }
            }
            Step::Restoring { .. } | Step::Entered(_) | Step::Leaving(_) => {}
        });
        if let Err(error) = outcome {
            failures.push(format!("the removal failed: {error}"));
        }
        // ext4 orders a listing by name hash, so one child may come first, at cookie 0.
        if wide_reopens != siblings || wide_reopens_past_start < siblings - 1 {
            failures.push(format!(
                "`wide` was reopened {wide_reopens} times, {wide_reopens_past_start} of them \
                 past its start, not once per child ({siblings}) and past the start for all \
                 but at most one"
            ));
        }
        if victim.exists() {
            failures.push("the root is still on disk".to_owned());
        }
        assert!(failures.is_empty(), "{failures:#?}");
    }

    /// **A directory that a listing from its start found empty, and that still will not
    /// go, ends the removal with an error instead of being listed again forever.**
    /// `work/x` holds one file. Every time the walk enters `x` ([`Step::Entered`]) the
    /// cell deletes what `x` holds, so the listing from `x`'s start finds nothing; every
    /// time the walk leaves it ([`Step::Leaving`]) the cell adds a new file — an actor
    /// that keeps filling the tree, up to ten times. The walk must stop with an error
    /// after leaving `x` once.
    ///
    /// **Would red if:** the walk listed a directory again after a listing from its
    /// start found nothing in it (it would leave `x` eleven times and then succeed).
    #[test]
    fn a_directory_listed_empty_that_will_not_go_is_an_error_not_a_loop() {
        let scratch = tempfile::tempdir().expect("a scratch directory");
        let victim = scratch.path().join("attempts/victim");
        let x = victim.join("work/x");
        std::fs::create_dir_all(&x).unwrap();
        std::fs::write(x.join("f0"), b"guest bytes\n").unwrap();
        // `work` is depth 1 and `x` depth 2.
        let x_depth = 2;

        let mut left = 0;
        let outcome = remove_tree_observed(&victim, |step| match step {
            Step::Entered(depth) if depth == x_depth => {
                for entry in std::fs::read_dir(&x).unwrap() {
                    std::fs::remove_file(entry.unwrap().path()).unwrap();
                }
            }
            Step::Leaving(depth) if depth == x_depth => {
                left += 1;
                if left <= 10 {
                    std::fs::write(x.join(format!("f{left}")), b"more\n").unwrap();
                }
            }
            _ => {}
        });
        assert!(
            outcome.is_err() && left == 1,
            "the walk left `x` {left} times and ended {outcome:?}"
        );
    }
}
