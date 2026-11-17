//! Installed-main discovery descriptor.
//!
//! The descriptor is a convenience for attached clients, never authority. A
//! stale file after a crash cannot authorize another main. The data-directory
//! lock protects one durable store; the per-owner discovery lease prevents a
//! second installed authority at another store. Clients must still connect to
//! the endpoint and verify the live status handshake as the product protocol
//! evolves.

#[cfg(unix)]
use std::ffi::OsStr;
use std::fs::{File, OpenOptions};
use std::io::Write as _;
#[cfg(unix)]
use std::os::fd::{AsRawFd as _, FromRawFd as _, RawFd};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, Result, bail};
use kata_client::{KataClient, types::SystemStatus};
use nix::errno::Errno;
use nix::fcntl::{Flock, FlockArg};
#[cfg(unix)]
use nix::fcntl::{OFlag, openat};
#[cfg(unix)]
use nix::sys::stat::{Mode, fchmod};
use serde::{Deserialize, Serialize};

use crate::data_dir_lock::{MainLockMetadata, MainMode};
use crate::owner_only_publication::{
    ExistingOwnerOnlyPublication, OwnerOnlyNoReplacePublication, OwnerOnlyPublicationTemp,
    OwnerOnlyPublishedDestination, OwnerOnlyRemoval, chmod_fix, ensure_owner_only_directory,
    foreign_owner_refusal, owner_only_mode_argument, recover_owner_only_publication_artifacts,
};
#[cfg(test)]
use crate::owner_only_publication::{
    capture_owner_only_publication_identity, inject_next_publication_removal_parent_sync_failure,
};
use kata_worker::owner_home::effective_owner_home;

pub const ATTACHMENT_PROTOCOL_VERSION: u32 = 1;
pub const DEFAULT_API_URL: &str = "http://127.0.0.1:8400";
pub(crate) const SERVICE_DISCOVERY_LEASE_FD_ENV: &str = "KATA_SERVICE_DISCOVERY_LEASE_FD";
const MAX_ATTACHMENT_DESCRIPTOR_BYTES: u64 = 64 * 1024;
const MAX_ATTACHMENT_STATUS_BODY_BYTES: usize = 1024 * 1024;
const MAX_ATTACHMENT_PUBLICATION_ARTIFACTS: usize = 64;
const ATTACHMENT_PUBLICATION_ARTIFACT_PREFIX: &str = ".main-attachment-";
const DEFAULT_ATTACHMENT_STATUS_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttachmentDescriptor {
    pub protocol_version: u32,
    pub directory_id: String,
    pub process_generation: String,
    pub endpoint: String,
    pub binary_version: String,
    /// Non-secret description of how an attached client supplies authority.
    pub auth_reference: String,
}

/// RAII publication guard. Drop removes only the generation this guard wrote.
/// Its owned lease reference keeps installed-main discovery authority live
/// through the complete withdrawal attempt.
#[derive(Debug)]
pub(crate) struct InstalledAttachment {
    process_generation: String,
    publication: Option<OwnerOnlyPublishedDestination>,
    _discovery_lease: Arc<InstalledDiscoveryLease>,
}

/// Per-owner discovery lease.  The data-directory lock is the durable-state
/// authority; this second kernel lock serializes the product's single installed
/// main/discovery endpoint across *different* data directories and applied
/// service-definition mutation while that main is stopped. Scratch mains never
/// acquire it. The pathname names a stable coordination inode: dropping
/// the guard releases the kernel lock but deliberately does not unlink the
/// file.  Removing a lock pathname can split authority when another process
/// opened the old inode before the unlink and a later process creates a new one.
#[derive(Debug)]
pub(crate) struct InstalledDiscoveryLease {
    lock: Flock<File>,
}

/// Short-lived per-owner serialization for installed lifecycle mutations.
///
/// The discovery lease cannot serve this purpose: the running main must hold it
/// while `stop` and `restart` ask the native manager to act.  This separate
/// stable inode is held for one applied install/start/stop/restart/uninstall,
/// upgrade, or restore operation. It prevents a manager from snapshotting an
/// old unit or plist during publication and prevents destructive maintenance
/// from overlapping an installed lifecycle transition.
#[derive(Debug)]
pub(crate) struct InstalledLifecycleOperationLease {
    _lock: Flock<File>,
}

impl InstalledDiscoveryLease {
    pub(crate) fn acquire() -> Result<Self> {
        let path = installed_discovery_lease_path();
        Self::acquire_at(&path)
    }

    fn acquire_at(path: &Path) -> Result<Self> {
        let parent = path
            .parent()
            .ok_or_else(|| anyhow::anyhow!("installed-main discovery lease has no parent"))?;
        let parent_created = create_owner_discovery_directory(parent)?;
        let parent_file = open_discovery_parent(parent, parent_created)?;
        let file = open_discovery_lease_file(&parent_file, path)?;
        validate_discovery_lease_file(&file, path)?;
        let lock = match Flock::lock(file, FlockArg::LockExclusiveNonblock) {
            Ok(lock) => lock,
            Err((_file, Errno::EWOULDBLOCK)) => bail!(
                "another installed Kata main already owns per-user discovery at {}; attach to or stop it before starting a different installed main",
                path.display()
            ),
            Err((_file, error)) => bail!(
                "cannot establish per-user installed-main discovery lock {}: {error}",
                path.display()
            ),
        };
        verify_discovery_lock_exclusion(&lock, &parent_file, path)?;
        validate_discovery_lease_path(&lock, &parent_file, path)?;
        Ok(Self { lock })
    }

    #[cfg(any(test, feature = "test-support"))]
    pub(crate) fn acquire_at_for_test(path: &Path) -> Result<Self> {
        Self::acquire_at(path)
    }

    /// Make the already-locked descriptor survive the native-service
    /// trampoline's `exec`. The guard remains owned by the trampoline if exec
    /// fails; a successful exec transfers the descriptor into the new image.
    #[cfg(unix)]
    pub(crate) fn prepare_service_exec_handoff(&self) -> Result<RawFd> {
        let descriptor = self.lock.as_raw_fd();
        if descriptor <= libc::STDERR_FILENO {
            bail!("installed-main discovery lease uses an unsafe stdio descriptor");
        }
        set_descriptor_close_on_exec(descriptor, false)?;
        Ok(descriptor)
    }

    /// Acquire the normal lease or adopt the exact descriptor held across a
    /// native-service trampoline exec. Adoption proves that the inherited
    /// descriptor already owns the stable pathname lock before touching its
    /// lock state, so a forged unlocked descriptor cannot create a hidden
    /// validation-to-start gap.
    pub(crate) fn acquire_or_adopt_service_exec_handoff(
        inherited: Option<&std::ffi::OsStr>,
    ) -> Result<Self> {
        match inherited {
            None => Self::acquire(),
            #[cfg(unix)]
            Some(raw) => {
                Self::adopt_service_exec_handoff_at(&installed_discovery_lease_path(), raw)
            }
            #[cfg(not(unix))]
            Some(_) => bail!("installed-main discovery lease handoff requires Unix"),
        }
    }

    pub(crate) fn probe_available() -> Result<bool> {
        Self::probe_available_at(&installed_discovery_lease_path())
    }

    fn probe_available_at(path: &Path) -> Result<bool> {
        let parent_path = path
            .parent()
            .ok_or_else(|| anyhow::anyhow!("installed-main discovery lease has no parent"))?;
        let state = create_owner_discovery_directory(parent_path)?;
        let parent = open_discovery_parent(parent_path, state)?;
        let file = open_discovery_lease_file(&parent, path)?;
        validate_discovery_lease_file(&file, path)?;
        let lock = match Flock::lock(file, FlockArg::LockExclusiveNonblock) {
            Ok(lock) => lock,
            Err((_file, Errno::EWOULDBLOCK)) => return Ok(false),
            Err((_file, error)) => bail!(
                "cannot probe per-user installed-main discovery lock {}: {error}",
                path.display()
            ),
        };
        verify_discovery_lock_exclusion(&lock, &parent, path)?;
        validate_discovery_lease_path(&lock, &parent, path)?;
        drop(lock);
        Ok(true)
    }

    #[cfg(unix)]
    #[allow(unsafe_code)]
    fn adopt_service_exec_handoff_at(path: &Path, raw: &OsStr) -> Result<Self> {
        let text = raw.to_str().ok_or_else(|| {
            anyhow::anyhow!("installed-main discovery lease descriptor is not Unicode")
        })?;
        let descriptor = text.parse::<RawFd>().with_context(|| {
            format!("invalid installed-main discovery lease descriptor {text:?}")
        })?;
        if descriptor <= libc::STDERR_FILENO {
            bail!("installed-main discovery lease descriptor must be greater than stderr");
        }
        descriptor_flags(descriptor)?;

        // SAFETY: the service trampoline deliberately transfers sole ownership
        // of this inherited descriptor through SERVICE_DISCOVERY_LEASE_FD_ENV.
        // The descriptor was checked live above and is converted exactly once
        // in the new process image.
        let file = unsafe { File::from_raw_fd(descriptor) };
        set_descriptor_close_on_exec(file.as_raw_fd(), true)?;

        let parent_path = path
            .parent()
            .ok_or_else(|| anyhow::anyhow!("installed-main discovery lease has no parent"))?;
        let parent = open_discovery_parent(parent_path, DiscoveryDirectoryState::Existing)?;
        validate_discovery_lease_file(&file, path)?;
        validate_discovery_lease_path(&file, &parent, path)?;
        require_inherited_discovery_lock_is_held(&parent, path)?;

        let lock = match Flock::lock(file, FlockArg::LockExclusiveNonblock) {
            Ok(lock) => lock,
            Err((_file, error)) => bail!(
                "cannot adopt inherited installed-main discovery lock {}: {error}",
                path.display()
            ),
        };
        verify_discovery_lock_exclusion(&lock, &parent, path)?;
        validate_discovery_lease_path(&lock, &parent, path)?;
        Ok(Self { lock })
    }
}

impl InstalledLifecycleOperationLease {
    pub(crate) fn acquire() -> Result<Self> {
        Self::acquire_at(&installed_lifecycle_operation_lease_path())
    }

    fn acquire_at(path: &Path) -> Result<Self> {
        let parent = path
            .parent()
            .ok_or_else(|| anyhow::anyhow!("installed lifecycle operation lease has no parent"))?;
        let parent_created = create_owner_discovery_directory(parent)?;
        let parent_file = open_discovery_parent(parent, parent_created)?;
        let file = open_discovery_lease_file(&parent_file, path)?;
        validate_discovery_lease_file(&file, path)?;
        let lock = match Flock::lock(file, FlockArg::LockExclusiveNonblock) {
            Ok(lock) => lock,
            Err((_file, Errno::EWOULDBLOCK)) => bail!(
                "another Kata installed lifecycle or maintenance operation already owns {}; wait for it to finish before retrying",
                path.display()
            ),
            Err((_file, error)) => bail!(
                "cannot establish installed lifecycle operation lock {}: {error}",
                path.display()
            ),
        };
        verify_discovery_lock_exclusion(&lock, &parent_file, path)?;
        validate_discovery_lease_path(&lock, &parent_file, path)?;
        Ok(Self { _lock: lock })
    }

    #[cfg(any(test, feature = "test-support"))]
    pub(crate) fn acquire_at_for_test(path: &Path) -> Result<Self> {
        Self::acquire_at(path)
    }
}

#[cfg(unix)]
fn require_inherited_discovery_lock_is_held(parent: &File, path: &Path) -> Result<()> {
    let contender = open_existing_discovery_lease_file(parent, path)?;
    let outcome = Flock::lock(contender, FlockArg::LockExclusiveNonblock);
    match outcome {
        Err((_file, Errno::EWOULDBLOCK)) => Ok(()),
        Ok(lock) => {
            drop(lock);
            bail!(
                "inherited installed-main discovery descriptor did not already hold {}",
                path.display()
            )
        }
        Err((_file, error)) => bail!(
            "cannot verify inherited installed-main discovery lock {}: {error}",
            path.display()
        ),
    }
}

#[cfg(unix)]
#[allow(unsafe_code)]
fn descriptor_flags(descriptor: RawFd) -> Result<i32> {
    // SAFETY: F_GETFD reads flags from the validated integer descriptor and
    // does not dereference process memory.
    let flags = unsafe { libc::fcntl(descriptor, libc::F_GETFD) };
    if flags < 0 {
        return Err(std::io::Error::last_os_error())
            .context("inspecting installed-main discovery descriptor flags");
    }
    Ok(flags)
}

#[cfg(unix)]
#[allow(unsafe_code)]
fn set_descriptor_close_on_exec(descriptor: RawFd, enabled: bool) -> Result<()> {
    let flags = descriptor_flags(descriptor)?;
    let updated = if enabled {
        flags | libc::FD_CLOEXEC
    } else {
        flags & !libc::FD_CLOEXEC
    };
    // SAFETY: F_SETFD updates flags on the live descriptor only.
    if unsafe { libc::fcntl(descriptor, libc::F_SETFD, updated) } < 0 {
        return Err(std::io::Error::last_os_error())
            .context("setting installed-main discovery descriptor flags");
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum DiscoveryDirectoryState {
    Created,
    Existing,
}

#[cfg(unix)]
fn open_discovery_parent(path: &Path, state: DiscoveryDirectoryState) -> Result<File> {
    use std::os::unix::fs::OpenOptionsExt as _;

    let mut options = OpenOptions::new();
    options
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_DIRECTORY | libc::O_NOFOLLOW);
    let parent = options.open(path).with_context(|| {
        format!(
            "opening installed-main discovery directory {}",
            path.display()
        )
    })?;
    validate_discovery_parent_owner(&parent, path)?;
    if state == DiscoveryDirectoryState::Created {
        fchmod(parent.as_raw_fd(), Mode::from_bits_truncate(0o700)).with_context(|| {
            format!(
                "setting owner-only permissions on installed-main discovery directory {}",
                path.display()
            )
        })?;
    }
    validate_discovery_parent(&parent, path)?;
    validate_discovery_parent_path(&parent, path)?;
    Ok(parent)
}

#[cfg(not(unix))]
fn open_discovery_parent(path: &Path, _state: DiscoveryDirectoryState) -> Result<File> {
    let parent = File::open(path).with_context(|| {
        format!(
            "opening installed-main discovery directory {}",
            path.display()
        )
    })?;
    Ok(parent)
}

#[cfg(unix)]
fn open_discovery_lease_file(parent: &File, path: &Path) -> Result<File> {
    let leaf = path
        .file_name()
        .ok_or_else(|| anyhow::anyhow!("installed-main discovery lease has no file name"))?;
    let flags = OFlag::O_CLOEXEC | OFlag::O_NOFOLLOW | OFlag::O_NONBLOCK | OFlag::O_RDONLY;
    let (file, created) = match openat(
        Some(parent.as_raw_fd()),
        leaf,
        flags | OFlag::O_CREAT | OFlag::O_EXCL,
        Mode::from_bits_truncate(0o600),
    ) {
        Ok(descriptor) => {
            // SAFETY: `openat` returned a newly owned descriptor and this is
            // its sole conversion into an owning Rust value.
            (file_from_owned_descriptor(descriptor), true)
        }
        Err(Errno::EEXIST) => (open_existing_discovery_lease_file(parent, path)?, false),
        Err(error) => {
            return Err(error).with_context(|| {
                format!("creating installed-main discovery lock {}", path.display())
            });
        }
    };
    if created {
        fchmod(file.as_raw_fd(), Mode::from_bits_truncate(0o600)).with_context(|| {
            format!(
                "setting owner-only permissions on installed-main discovery lock {}",
                path.display()
            )
        })?;
    }
    Ok(file)
}

#[cfg(unix)]
fn open_existing_discovery_lease_file(parent: &File, path: &Path) -> Result<File> {
    let leaf = path
        .file_name()
        .ok_or_else(|| anyhow::anyhow!("installed-main discovery lease has no file name"))?;
    let descriptor = openat(
        Some(parent.as_raw_fd()),
        leaf,
        OFlag::O_CLOEXEC | OFlag::O_NOFOLLOW | OFlag::O_NONBLOCK | OFlag::O_RDONLY,
        Mode::empty(),
    )
    .with_context(|| format!("opening installed-main discovery lock {}", path.display()))?;
    // SAFETY: `openat` returned a newly owned descriptor and this is its sole
    // conversion into an owning Rust value.
    Ok(file_from_owned_descriptor(descriptor))
}

#[cfg(unix)]
#[allow(unsafe_code)]
fn file_from_owned_descriptor(descriptor: RawFd) -> File {
    // SAFETY: callers pass only a successful `openat` result that has not been
    // converted, duplicated, or transferred. `File` becomes its sole owner.
    unsafe { File::from_raw_fd(descriptor) }
}

#[cfg(not(unix))]
fn open_discovery_lease_file(_parent: &File, path: &Path) -> Result<File> {
    let mut options = OpenOptions::new();
    options.create(true).read(true).write(true);
    options
        .open(path)
        .with_context(|| format!("opening installed-main discovery lock {}", path.display()))
}

#[cfg(unix)]
fn validate_discovery_parent_owner(file: &File, path: &Path) -> Result<()> {
    use std::os::unix::fs::MetadataExt as _;

    let metadata = file.metadata().with_context(|| {
        format!(
            "inspecting installed-main discovery directory {}",
            path.display()
        )
    })?;
    if !metadata.is_dir() {
        bail!(
            "installed-main discovery directory {} must be a directory",
            path.display()
        );
    }
    let uid = nix::unistd::geteuid().as_raw();
    if metadata.uid() != uid {
        bail!(
            "installed-main discovery directory {} is owned by uid {}, expected {}; {}",
            path.display(),
            metadata.uid(),
            uid,
            foreign_owner_refusal(metadata.uid(), uid)
        );
    }
    Ok(())
}

#[cfg(not(unix))]
fn validate_discovery_parent_owner(_file: &File, _path: &Path) -> Result<()> {
    Ok(())
}

#[cfg(unix)]
fn validate_discovery_parent(file: &File, path: &Path) -> Result<()> {
    use std::os::unix::fs::MetadataExt as _;

    validate_discovery_parent_owner(file, path)?;
    let metadata = file.metadata().with_context(|| {
        format!(
            "inspecting installed-main discovery directory {}",
            path.display()
        )
    })?;
    let mode = metadata.mode() & 0o7777;
    if mode != 0o700 {
        bail!(
            "installed-main discovery directory {} must have mode 0700; {}",
            path.display(),
            chmod_fix(owner_only_mode_argument(mode), path)
        );
    }
    Ok(())
}

#[cfg(not(unix))]
fn validate_discovery_parent(_file: &File, _path: &Path) -> Result<()> {
    Ok(())
}

#[cfg(unix)]
fn validate_discovery_parent_path(file: &File, path: &Path) -> Result<()> {
    use std::os::unix::fs::MetadataExt as _;

    let opened = file
        .metadata()
        .with_context(|| format!("inspecting opened discovery directory {}", path.display()))?;
    let current = std::fs::symlink_metadata(path)
        .with_context(|| format!("rechecking discovery directory {}", path.display()))?;
    let uid = nix::unistd::geteuid().as_raw();
    if current.file_type().is_symlink()
        || !current.is_dir()
        || current.uid() != uid
        || current.mode() & 0o7777 != 0o700
        || (current.dev(), current.ino()) != (opened.dev(), opened.ino())
    {
        bail!(
            "installed-main discovery directory {} changed or became unsafe while acquiring its lease",
            path.display()
        );
    }
    Ok(())
}

#[cfg(not(unix))]
fn validate_discovery_parent_path(_file: &File, _path: &Path) -> Result<()> {
    Ok(())
}

#[cfg(unix)]
fn validate_discovery_lease_file(file: &File, path: &Path) -> Result<()> {
    use std::os::unix::fs::MetadataExt as _;

    let metadata = file.metadata().with_context(|| {
        format!(
            "inspecting installed-main discovery lock {}",
            path.display()
        )
    })?;
    if !metadata.is_file() {
        bail!(
            "installed-main discovery lock {} must be a regular file",
            path.display()
        );
    }
    let uid = nix::unistd::geteuid().as_raw();
    if metadata.uid() != uid {
        bail!(
            "installed-main discovery lock {} is owned by uid {}, expected {}",
            path.display(),
            metadata.uid(),
            uid
        );
    }
    if metadata.nlink() != 1 {
        bail!(
            "installed-main discovery lock {} must have exactly one link",
            path.display()
        );
    }
    if metadata.mode() & 0o7777 != 0o600 {
        bail!(
            "installed-main discovery lock {} must have mode 0600",
            path.display()
        );
    }
    if metadata.len() != 0 {
        bail!(
            "installed-main discovery lock {} must remain empty",
            path.display()
        );
    }
    Ok(())
}

#[cfg(unix)]
fn validate_discovery_lease_path(file: &File, parent: &File, path: &Path) -> Result<()> {
    use std::os::unix::fs::MetadataExt as _;

    let parent_path = path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("installed-main discovery lease has no parent"))?;
    validate_discovery_parent(parent, parent_path)?;
    validate_discovery_parent_path(parent, parent_path)?;

    validate_discovery_lease_file(file, path)?;
    let opened = file
        .metadata()
        .with_context(|| format!("inspecting opened discovery lock {}", path.display()))?;
    let current = std::fs::symlink_metadata(path).with_context(|| {
        format!(
            "rechecking installed-main discovery lock {}",
            path.display()
        )
    })?;
    if current.file_type().is_symlink()
        || !current.is_file()
        || (current.dev(), current.ino()) != (opened.dev(), opened.ino())
    {
        bail!(
            "installed-main discovery lock {} changed while acquiring its lease",
            path.display()
        );
    }
    Ok(())
}

#[cfg(not(unix))]
fn validate_discovery_lease_path(_file: &File, _parent: &File, _path: &Path) -> Result<()> {
    Ok(())
}

#[cfg(unix)]
fn verify_discovery_lock_exclusion(held: &Flock<File>, parent: &File, path: &Path) -> Result<()> {
    use std::os::unix::fs::MetadataExt as _;

    let contender = open_existing_discovery_lease_file(parent, path)?;
    validate_discovery_lease_file(&contender, path)?;
    let held_metadata = held
        .metadata()
        .with_context(|| format!("inspecting held discovery lock {}", path.display()))?;
    let contender_metadata = contender
        .metadata()
        .with_context(|| format!("inspecting rebound discovery lock {}", path.display()))?;
    if (held_metadata.dev(), held_metadata.ino())
        != (contender_metadata.dev(), contender_metadata.ino())
    {
        bail!(
            "installed-main discovery lock {} changed while binding the held lease",
            path.display()
        );
    }
    let outcome = match Flock::lock(contender, FlockArg::LockExclusiveNonblock) {
        Ok(second_lock) => {
            drop(second_lock);
            Ok(())
        }
        Err((_file, error)) => Err(error),
    };
    require_independent_discovery_lock_contention(outcome, path)?;
    validate_discovery_lease_path(held, parent, path)
}

#[cfg(not(unix))]
fn verify_discovery_lock_exclusion(
    _held: &Flock<File>,
    _parent: &File,
    _path: &Path,
) -> Result<()> {
    Ok(())
}

fn require_independent_discovery_lock_contention(
    outcome: std::result::Result<(), Errno>,
    path: &Path,
) -> Result<()> {
    match outcome {
        Err(error) if error == Errno::EWOULDBLOCK || error == Errno::EAGAIN => Ok(()),
        Ok(()) => bail!(
            "filesystem at {} does not enforce independent exclusive discovery locks",
            path.display()
        ),
        Err(error) => bail!(
            "cannot verify independent discovery-lock exclusion at {}: {error}",
            path.display()
        ),
    }
}

#[cfg(not(unix))]
fn validate_discovery_lease_file(_file: &File, _path: &Path) -> Result<()> {
    Ok(())
}

/// Stable one-per-OS-owner lock path. Neither a descriptor test fixture nor a
/// forged `HOME` may create another installed-main authority for the same uid.
fn installed_discovery_lease_path() -> PathBuf {
    // Test binaries re-exec the installed-main entrypoint while the workspace's
    // parallel suite may be running another main. Keep the production invariant
    // per-uid and provide only cfg(test) harness isolation; a production binary
    // cannot redirect this authority boundary through environment state.
    #[cfg(test)]
    if let Some(path) = std::env::var_os("KATA_TEST_INSTALLED_MAIN_DISCOVERY_LEASE") {
        return PathBuf::from(path);
    }
    discovery_lease_path_for_uid(u64::from(nix::unistd::geteuid().as_raw()))
}

fn installed_lifecycle_operation_lease_path() -> PathBuf {
    #[cfg(test)]
    if let Some(path) = std::env::var_os("KATA_TEST_INSTALLED_MAIN_DISCOVERY_LEASE") {
        let discovery = PathBuf::from(path);
        return discovery
            .parent()
            .expect("test discovery lease path has a parent")
            .join("lifecycle-operation.lock");
    }
    owner_coordination_directory_for_uid(u64::from(nix::unistd::geteuid().as_raw()))
        .join("lifecycle-operation.lock")
}

fn discovery_lease_path_for_uid(uid: u64) -> PathBuf {
    owner_coordination_directory_for_uid(uid).join("discovery.lock")
}

fn owner_coordination_directory_for_uid(uid: u64) -> PathBuf {
    PathBuf::from("/tmp").join(format!("kata-installed-main-{uid}"))
}

fn inspect_owner_discovery_directory(path: &Path) -> Result<std::fs::Metadata> {
    let metadata = std::fs::symlink_metadata(path)
        .with_context(|| format!("inspecting discovery directory {}", path.display()))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        bail!(
            "installed-main discovery directory {} must be an owner directory, not a symlink or non-directory",
            path.display()
        );
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        let uid = nix::unistd::geteuid().as_raw();
        if metadata.uid() != uid {
            bail!(
                "installed-main discovery directory {} is owned by uid {}, expected {}; {}",
                path.display(),
                metadata.uid(),
                uid,
                foreign_owner_refusal(metadata.uid(), uid)
            );
        }
    }
    Ok(metadata)
}

fn create_owner_discovery_directory(path: &Path) -> Result<DiscoveryDirectoryState> {
    match std::fs::symlink_metadata(path) {
        Ok(_) => {
            inspect_owner_discovery_directory(path)?;
            Ok(DiscoveryDirectoryState::Existing)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let mut builder = std::fs::DirBuilder::new();
            #[cfg(unix)]
            {
                use std::os::unix::fs::DirBuilderExt as _;
                builder.mode(0o700);
            }
            match builder.create(path) {
                Ok(()) => {
                    let created = inspect_owner_discovery_directory(path)?;
                    set_owner_only_directory(path)?;
                    let current = inspect_owner_discovery_directory(path)?;
                    #[cfg(unix)]
                    {
                        use std::os::unix::fs::MetadataExt as _;
                        if (created.dev(), created.ino()) != (current.dev(), current.ino()) {
                            bail!(
                                "installed-main discovery directory {} changed while initializing",
                                path.display()
                            );
                        }
                    }
                    Ok(DiscoveryDirectoryState::Created)
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                    inspect_owner_discovery_directory(path)?;
                    Ok(DiscoveryDirectoryState::Existing)
                }
                Err(error) => Err(error).with_context(|| {
                    format!(
                        "creating installed-main discovery directory {}",
                        path.display()
                    )
                }),
            }
        }
        Err(error) => {
            Err(error).with_context(|| format!("inspecting discovery directory {}", path.display()))
        }
    }
}

impl InstalledAttachment {
    pub(crate) fn publish(
        discovery_lease: Arc<InstalledDiscoveryLease>,
        metadata: &MainLockMetadata,
        auth_reference: &str,
    ) -> Result<Self> {
        Self::publish_to_path(
            discovery_lease,
            metadata,
            auth_reference,
            installed_attachment_path()?,
        )
    }

    #[cfg(test)]
    fn publish_at(
        discovery_lease: Arc<InstalledDiscoveryLease>,
        metadata: &MainLockMetadata,
        auth_reference: &str,
        path: PathBuf,
    ) -> Result<Self> {
        Self::publish_to_path(discovery_lease, metadata, auth_reference, path)
    }

    fn publish_to_path(
        discovery_lease: Arc<InstalledDiscoveryLease>,
        metadata: &MainLockMetadata,
        auth_reference: &str,
        path: PathBuf,
    ) -> Result<Self> {
        if metadata.mode != MainMode::Installed {
            bail!("scratch mains never publish the installed-main attachment descriptor");
        }
        let endpoint = metadata
            .control_endpoint
            .clone()
            .ok_or_else(|| anyhow::anyhow!("installed main has no control endpoint to publish"))?;
        let descriptor = AttachmentDescriptor {
            protocol_version: ATTACHMENT_PROTOCOL_VERSION,
            directory_id: metadata.directory_id.clone(),
            process_generation: metadata.process_generation.clone(),
            endpoint,
            binary_version: metadata.binary_version.clone(),
            auth_reference: auth_reference.to_string(),
        };
        let parent = path
            .parent()
            .ok_or_else(|| anyhow::anyhow!("attachment path has no parent: {}", path.display()))?;
        ensure_owner_only_directory(parent, "installed-main attachment")?;
        recover_owner_only_publication_artifacts(
            parent,
            ATTACHMENT_PUBLICATION_ARTIFACT_PREFIX,
            MAX_ATTACHMENT_DESCRIPTOR_BYTES,
            MAX_ATTACHMENT_PUBLICATION_ARTIFACTS,
            "installed-main attachment",
        )?;
        match read_attachment_descriptor_snapshot_at(&path) {
            Ok((_stale, publication)) => {
                match publication.remove(
                    MAX_ATTACHMENT_DESCRIPTOR_BYTES,
                    ATTACHMENT_PUBLICATION_ARTIFACT_PREFIX,
                    "stale installed-main attachment",
                )? {
                    OwnerOnlyRemoval::Removed(_) => {}
                    OwnerOnlyRemoval::RecoveryRequired(error) => {
                        return Err(anyhow::Error::new(error)).context(
                            "stale installed-main attachment removal requires recovery before a new descriptor can be published",
                        );
                    }
                }
            }
            Err(error) if attachment_is_not_found(&error) => {}
            Err(error) => {
                return Err(error).context(
                    "existing installed-main attachment is unsafe or unreadable; refusing replacement",
                );
            }
        }

        let mut bytes = serde_json::to_vec_pretty(&descriptor)
            .context("serializing installed-main attachment descriptor")?;
        bytes.push(b'\n');
        if bytes.len() as u64 > MAX_ATTACHMENT_DESCRIPTOR_BYTES {
            bail!(
                "installed-main attachment descriptor is {} bytes and exceeds the {}-byte safety bound",
                bytes.len(),
                MAX_ATTACHMENT_DESCRIPTOR_BYTES
            );
        }
        let mut temporary = OwnerOnlyPublicationTemp::create(
            parent,
            ATTACHMENT_PUBLICATION_ARTIFACT_PREFIX,
            MAX_ATTACHMENT_DESCRIPTOR_BYTES,
            "installed-main attachment",
        )?;
        let publication = (|| {
            temporary
                .file_mut()
                .write_all(&bytes)
                .context("writing installed-main attachment temporary")?;
            temporary.sync_contents()?;
            match temporary.publish_noreplace(&path)? {
                OwnerOnlyNoReplacePublication::Published(publication) => Ok(publication),
                OwnerOnlyNoReplacePublication::RecoveryRequired { error, .. }
                | OwnerOnlyNoReplacePublication::RenamedRecoveryRequired(error) => {
                    Err(anyhow::Error::new(error)).context(
                        "installed-main attachment publication reached a post-rename recovery state; exact retained publication cleanup is required",
                    )
                }
                OwnerOnlyNoReplacePublication::DestinationExists => {
                    bail!("installed-main attachment destination appeared during publication")
                }
            }
        })();
        let publication = match publication {
            Ok(publication) => publication,
            Err(error) => {
                return match temporary.cleanup() {
                    Ok(()) => Err(error),
                    Err(cleanup) => Err(error).context(format!(
                        "installed-main attachment publication failed and exact temporary cleanup also failed: {cleanup:#}"
                    )),
                };
            }
        };

        // Keep destination ownership armed while validating the fixed
        // pathname. No pathname recapture establishes ownership: the guard
        // already carries the temporary's pre-rename inode identity.
        let validation = read_attachment_descriptor_snapshot_at(publication.path()).and_then(
            |(published, existing)| {
                if published != descriptor {
                    bail!("installed-main attachment changed after publication");
                }
                if existing.identity() != publication.identity() {
                    bail!("installed-main attachment inode changed after publication");
                }
                Ok(())
            },
        );
        if let Err(error) = validation {
            return match publication.withdraw() {
                Ok(()) => Err(error),
                Err(cleanup) => Err(error).context(format!(
                    "installed-main attachment post-publication validation failed and exact destination cleanup also failed: {cleanup:#}"
                )),
            };
        }
        Ok(Self {
            process_generation: descriptor.process_generation,
            publication: Some(publication),
            _discovery_lease: discovery_lease,
        })
    }

    /// Remove this generation's descriptor and durably publish its absence.
    ///
    /// Graceful installed-main shutdown uses this explicit path so attachment
    /// withdrawal can be recorded before the data-directory lock is released.
    /// [`Drop`] remains a best-effort crash/error backstop.
    pub(crate) fn withdraw(mut self) -> Result<()> {
        let publication = self
            .publication
            .take()
            .expect("installed attachment publication ownership is present");
        let (current, current_publication) =
            read_attachment_descriptor_snapshot_at(publication.path())
                .context("reading installed-main attachment before withdrawal")?;
        if current.process_generation != self.process_generation {
            drop(publication);
            bail!(
                "installed-main attachment generation changed before withdrawal (owned {}, current {}); refusing to remove another process generation",
                self.process_generation,
                current.process_generation
            );
        }
        if current_publication.identity() != publication.identity() {
            drop(publication);
            bail!(
                "installed-main attachment inode changed before withdrawal; refusing to remove a replacement"
            );
        }
        publication.withdraw()
    }
}

impl Drop for InstalledAttachment {
    fn drop(&mut self) {
        let Some(publication) = self.publication.take() else {
            return;
        };
        let Ok((current, current_publication)) =
            read_attachment_descriptor_snapshot_at(publication.path())
        else {
            drop(publication);
            return;
        };
        if current.process_generation != self.process_generation
            || current_publication.identity() != publication.identity()
        {
            drop(publication);
            return;
        }
        let _ = publication.withdraw();
    }
}

pub fn read_installed_attachment() -> Result<AttachmentDescriptor> {
    let path = installed_attachment_path()?;
    read_attachment_descriptor_at(&path).with_context(|| {
        format!(
            "installed Kata main is not discoverable at {}; run `kata service status` or start it with `{} kata serve --config <path>`",
            path.display(),
            crate::cli::DELEGATED_SCOPE
        )
    })
}

fn read_attachment_descriptor_at(path: &Path) -> Result<AttachmentDescriptor> {
    read_attachment_descriptor_snapshot_at(path).map(|(descriptor, _identity)| descriptor)
}

fn read_attachment_descriptor_snapshot_at(
    path: &Path,
) -> Result<(AttachmentDescriptor, ExistingOwnerOnlyPublication)> {
    let publication = ExistingOwnerOnlyPublication::open(
        path,
        MAX_ATTACHMENT_DESCRIPTOR_BYTES,
        "installed-main attachment descriptor",
    )?;
    let bytes = publication
        .read_utf8(
            MAX_ATTACHMENT_DESCRIPTOR_BYTES,
            "installed-main attachment descriptor",
        )?
        .into_bytes();
    let descriptor: AttachmentDescriptor = serde_json::from_slice(&bytes).with_context(|| {
        format!(
            "parsing installed-main attachment descriptor {}",
            path.display()
        )
    })?;
    if descriptor.protocol_version != ATTACHMENT_PROTOCOL_VERSION
        || descriptor.directory_id.is_empty()
        || descriptor.process_generation.is_empty()
        || descriptor.endpoint.is_empty()
        || descriptor.auth_reference.is_empty()
    {
        bail!(
            "installed-main attachment descriptor {} is invalid or unsupported; run `kata service status` and restart the main",
            path.display()
        );
    }
    Ok((descriptor, publication))
}

fn attachment_is_not_found(error: &anyhow::Error) -> bool {
    error.chain().any(|cause| {
        cause
            .downcast_ref::<std::io::Error>()
            .is_some_and(|error| error.kind() == std::io::ErrorKind::NotFound)
            || cause.downcast_ref::<nix::errno::Errno>() == Some(&nix::errno::Errno::ENOENT)
    })
}

/// A client connection whose live identity has been checked before use.
pub struct VerifiedAttachedMain {
    pub endpoint: String,
    pub client: KataClient,
    pub status: SystemStatus,
}

/// Discover or explicitly address the installed main, then verify readiness
/// and authority identity before returning a client.
pub async fn connect_verified_attached_main(
    requested_endpoint: Option<&str>,
) -> Result<VerifiedAttachedMain> {
    connect_verified_attached_main_with_timeout(
        requested_endpoint,
        DEFAULT_ATTACHMENT_STATUS_TIMEOUT,
    )
    .await
}

/// Word the refusal for a main that did not answer `/system/status`.
///
/// `descriptor_path` is `Some` exactly when the endpoint was DISCOVERED rather
/// than typed — and that is the case this function exists for. A descriptor left
/// by a main that was killed rather than stopped is readable, well-formed, and
/// points at a port with no process behind it; `read_installed_attachment`
/// succeeds, so the operator never sees the descriptor named anywhere and is
/// simply told an address they have never seen, with no way to know a file on
/// disk chose it. Naming the path is the whole distance between "kata is broken"
/// and one `rm`. An explicitly requested `--api-url` gets no hint, because no
/// descriptor chose it and pointing at one would be a lie.
///
/// Removal is safe by the descriptor's own contract (see this module's header):
/// it is a convenience for attached clients, never authority, so a stale file
/// cannot authorize another main. The condition attached to the `rm` is only
/// that nothing is live — deleting it out from under a RUNNING main would strand
/// other clients.
fn unreachable_main_context(endpoint: &str, descriptor_path: Option<&Path>) -> String {
    let base = format!(
        "could not attach to installed main at {endpoint}; run `kata service status` or start it with `{scope} kata serve --config <path>`",
        scope = crate::cli::DELEGATED_SCOPE
    );
    let Some(path) = descriptor_path else {
        return base;
    };
    let path = path.display();
    format!(
        "{base}. That endpoint was read from the installed-main attachment descriptor at {path} \
         — it is neither a default nor a value you passed. If `kata service status` reports no \
         live main, that descriptor is STALE (a main that was killed rather than stopped leaves \
         one behind). It is never authority, so once nothing is live it is safe to remove: \
         `rm {path}`"
    )
}

async fn connect_verified_attached_main_with_timeout(
    requested_endpoint: Option<&str>,
    status_timeout: std::time::Duration,
) -> Result<VerifiedAttachedMain> {
    let descriptor = if requested_endpoint.is_none() || requested_endpoint == Some(DEFAULT_API_URL)
    {
        Some(read_installed_attachment()?)
    } else {
        None
    };
    let endpoint = descriptor.as_ref().map_or_else(
        || requested_endpoint.unwrap_or(DEFAULT_API_URL).to_string(),
        |descriptor| descriptor.endpoint.clone(),
    );
    let descriptor_path = descriptor
        .as_ref()
        .and_then(|_| installed_attachment_path().ok());
    let client = KataClient::new_with_env_token(&endpoint).with_context(|| {
        format!("building the API client for installed-main endpoint {endpoint:?}")
    })?;
    let status = client
        .system_status_bounded(status_timeout, MAX_ATTACHMENT_STATUS_BODY_BYTES)
        .await
        .with_context(|| unreachable_main_context(&endpoint, descriptor_path.as_deref()))?;
    validate_live_attachment_status(&endpoint, descriptor.as_ref(), &status)?;
    Ok(VerifiedAttachedMain {
        endpoint,
        client,
        status,
    })
}

fn validate_live_attachment_status(
    endpoint: &str,
    descriptor: Option<&AttachmentDescriptor>,
    status: &SystemStatus,
) -> Result<()> {
    if !status.ready || status.process_mode != "installed" {
        bail!(
            "refused API at {endpoint}: expected ready installed main, got ready={} mode={}",
            status.ready,
            status.process_mode
        );
    }
    if status.attachment_protocol_version != Some(ATTACHMENT_PROTOCOL_VERSION) {
        bail!(
            "refused API at {endpoint}: attachment protocol mismatch (client={}, server={:?})",
            ATTACHMENT_PROTOCOL_VERSION,
            status.attachment_protocol_version
        );
    }
    if let Some(expected) = descriptor
        && (status.directory_id.as_deref() != Some(expected.directory_id.as_str())
            || status.process_generation.as_deref() != Some(expected.process_generation.as_str())
            || status.binary_version.as_deref() != Some(expected.binary_version.as_str()))
    {
        bail!(
            "installed-main identity mismatch at {endpoint}: descriptor expected directory_id={} generation={} binary_version={}, live API reported directory_id={:?} generation={:?} binary_version={:?}",
            expected.directory_id,
            expected.process_generation,
            expected.binary_version,
            status.directory_id,
            status.process_generation,
            status.binary_version
        );
    }
    Ok(())
}

/// Synchronous CLI adapter around [`connect_verified_attached_main`].
pub fn resolve_verified_attached_endpoint(requested_endpoint: &str) -> Result<String> {
    connect_verified_attached_main_sync(Some(requested_endpoint)).map(|attached| attached.endpoint)
}

pub fn connect_verified_attached_main_sync(
    requested_endpoint: Option<&str>,
) -> Result<VerifiedAttachedMain> {
    connect_verified_attached_main_sync_with_timeout(
        requested_endpoint,
        DEFAULT_ATTACHMENT_STATUS_TIMEOUT,
    )
}

pub(crate) fn connect_verified_attached_main_sync_with_timeout(
    requested_endpoint: Option<&str>,
    status_timeout: std::time::Duration,
) -> Result<VerifiedAttachedMain> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("building installed-main attachment runtime")?
        .block_on(connect_verified_attached_main_with_timeout(
            requested_endpoint,
            status_timeout,
        ))
}

fn fixed_installed_attachment_path() -> Result<PathBuf> {
    #[cfg(target_os = "macos")]
    {
        let home = effective_owner_home()?;
        return Ok(home
            .join("Library")
            .join("Application Support")
            .join("Kata")
            .join("main-attachment.json"));
    }
    #[cfg(not(target_os = "macos"))]
    {
        // Discovery is durable per-owner state, not session-runtime state.  A
        // service installed outside a login session and a later interactive
        // client must resolve the same path regardless of XDG_RUNTIME_DIR.
        Ok(effective_owner_home()?
            .join(".local")
            .join("state")
            .join("kata")
            .join("main-attachment.json"))
    }
}

/// Resolve the one installed-main descriptor for the effective OS owner.
///
/// Production has no configuration or environment redirection for this path.
#[cfg(not(test))]
pub fn installed_attachment_path() -> Result<PathBuf> {
    fixed_installed_attachment_path()
}

/// Unit-test harness children may isolate descriptor publication without
/// changing any binary target. Cargo features deliberately cannot enable this
/// lookup: default and all-features non-test binaries compile the fixed
/// production definition above.
#[cfg(test)]
pub fn installed_attachment_path() -> Result<PathBuf> {
    if let Some(path) = std::env::var_os("KATA_TEST_MAIN_ATTACHMENT") {
        return Ok(PathBuf::from(path));
    }
    fixed_installed_attachment_path()
}

#[cfg(unix)]
fn set_owner_only_directory(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
        .with_context(|| format!("setting owner-only permissions on {}", path.display()))
}

#[cfg(not(unix))]
fn set_owner_only_directory(_path: &Path) -> Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn discovery_probe_conflicts_with_own_process_lease() {
        let temp = tempfile::TempDir::new().unwrap();
        let path = temp.path().join("authority/discovery.lock");
        let lease = InstalledDiscoveryLease::acquire_at_for_test(&path).unwrap();
        // flock(2) treats a second descriptor opened by this same process as
        // a conflicting holder, so probing a lease this process already owns
        // must read "held". Stopped-state verification therefore must never
        // re-probe a lease its own execution authority holds
        // (service::discovery_quiescent); doing so wedges applied uninstall
        // at the stopped-verification timeout.
        assert!(
            !InstalledDiscoveryLease::probe_available_at(&path).unwrap(),
            "own-process lease must read as held"
        );
        drop(lease);
        assert!(
            InstalledDiscoveryLease::probe_available_at(&path).unwrap(),
            "released lease must read as available"
        );
    }

    fn descriptor(generation: &str) -> AttachmentDescriptor {
        AttachmentDescriptor {
            protocol_version: ATTACHMENT_PROTOCOL_VERSION,
            directory_id: "directory-a".to_string(),
            process_generation: generation.to_string(),
            endpoint: DEFAULT_API_URL.to_string(),
            binary_version: "test".to_string(),
            auth_reference: "none:test".to_string(),
        }
    }

    fn installed_metadata(generation: &str) -> MainLockMetadata {
        MainLockMetadata {
            directory_id: "directory-a".to_string(),
            format_generation: 3,
            mode: MainMode::Installed,
            pid: std::process::id(),
            started_at_unix_ms: 1,
            boot_id: None,
            process_generation: generation.to_string(),
            binary_version: "test".to_string(),
            control_endpoint: Some(DEFAULT_API_URL.to_string()),
        }
    }

    fn write_descriptor(path: &Path, value: &AttachmentDescriptor) {
        std::fs::write(path, serde_json::to_vec(value).expect("serialize")).expect("write");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
                .expect("owner-only descriptor mode");
        }
    }

    fn owner_only_tempdir() -> tempfile::TempDir {
        let root = tempfile::tempdir().expect("owner-only tempdir");
        set_owner_only_directory(root.path()).expect("owner-only tempdir mode");
        root
    }

    fn test_discovery_lease() -> (tempfile::TempDir, Arc<InstalledDiscoveryLease>) {
        let root = owner_only_tempdir();
        let lease = Arc::new(
            InstalledDiscoveryLease::acquire_at(&root.path().join("discovery.lock"))
                .expect("test discovery lease"),
        );
        (root, lease)
    }

    fn attachment_guard(
        discovery_lease: Arc<InstalledDiscoveryLease>,
        path: PathBuf,
        generation: &str,
    ) -> InstalledAttachment {
        set_owner_only_directory(path.parent().expect("attachment parent"))
            .expect("owner-only attachment parent");
        let publication_identity = capture_owner_only_publication_identity(
            &path,
            MAX_ATTACHMENT_DESCRIPTOR_BYTES,
            "test installed-main attachment",
        )
        .expect("capture attachment identity");
        InstalledAttachment {
            process_generation: generation.to_string(),
            publication: Some(OwnerOnlyPublishedDestination::adopt_for_test(
                path,
                publication_identity,
                MAX_ATTACHMENT_DESCRIPTOR_BYTES,
                ATTACHMENT_PUBLICATION_ARTIFACT_PREFIX,
                "test installed-main attachment",
            )),
            _discovery_lease: discovery_lease,
        }
    }

    fn live_status(generation: &str) -> SystemStatus {
        serde_json::from_value(serde_json::json!({
            "node_id": "main",
            "process_mode": "installed",
            "directory_id": "directory-a",
            "process_generation": generation,
            "attachment_protocol_version": ATTACHMENT_PROTOCOL_VERSION,
            "binary_version": "test",
            "recovery_state": "ready",
            "ready": true,
            "uptime_seconds": 1
        }))
        .expect("live status")
    }

    #[test]
    fn verified_handshake_rejects_stale_descriptor_generation() {
        let stale = descriptor("generation-a");
        let live = live_status("generation-b");
        let error = validate_live_attachment_status(DEFAULT_API_URL, Some(&stale), &live)
            .expect_err("a descriptor cannot substitute its generation for live authority");
        let message = format!("{error:#}");
        assert!(message.contains("identity mismatch"), "{message}");
        assert!(message.contains("generation-a"), "{message}");
        assert!(message.contains("generation-b"), "{message}");
    }

    #[test]
    fn discovery_lease_is_uid_stable_and_not_descriptor_relative() {
        assert_eq!(
            discovery_lease_path_for_uid(42),
            PathBuf::from("/tmp/kata-installed-main-42/discovery.lock")
        );
    }

    #[test]
    #[cfg(unix)]
    fn discovery_lease_reuses_one_persistent_inode() {
        use std::os::unix::fs::MetadataExt as _;

        let root = owner_only_tempdir();
        let path = root.path().join("discovery").join("lease.lock");
        let first = InstalledDiscoveryLease::acquire_at(&path).expect("first lease");
        let first_identity = {
            let metadata = path.metadata().expect("first metadata");
            (metadata.dev(), metadata.ino())
        };
        let conflict =
            InstalledDiscoveryLease::acquire_at(&path).expect_err("concurrent lease must fail");
        assert!(
            conflict
                .to_string()
                .contains("already owns per-user discovery")
        );

        drop(first);
        assert!(path.is_file(), "the stable coordination inode must persist");
        let second = InstalledDiscoveryLease::acquire_at(&path).expect("reacquire lease");
        let second_metadata = path.metadata().expect("second metadata");
        assert_eq!(
            first_identity,
            (second_metadata.dev(), second_metadata.ino())
        );
        drop(second);
        assert!(path.is_file());
    }

    #[test]
    #[cfg(unix)]
    fn discovery_availability_probe_observes_the_stable_kernel_lock() {
        let root = owner_only_tempdir();
        let path = root.path().join("discovery").join("lease.lock");
        let lease = InstalledDiscoveryLease::acquire_at(&path).expect("lease");
        assert!(!InstalledDiscoveryLease::probe_available_at(&path).expect("contended probe"));
        drop(lease);
        assert!(InstalledDiscoveryLease::probe_available_at(&path).expect("released probe"));
    }

    #[test]
    #[cfg(unix)]
    fn service_exec_handoff_adopts_the_continuously_held_descriptor() {
        let root = owner_only_tempdir();
        let path = root.path().join("discovery").join("lease.lock");
        let original = std::mem::ManuallyDrop::new(
            InstalledDiscoveryLease::acquire_at(&path).expect("original lease"),
        );
        let descriptor = original
            .prepare_service_exec_handoff()
            .expect("prepare exec handoff");
        assert_eq!(
            descriptor_flags(descriptor).expect("descriptor flags") & libc::FD_CLOEXEC,
            0,
            "the service exec descriptor must survive exec"
        );

        let encoded = descriptor.to_string();
        let adopted =
            InstalledDiscoveryLease::adopt_service_exec_handoff_at(&path, OsStr::new(&encoded))
                .expect("adopt continuously held lease");
        assert_ne!(
            descriptor_flags(descriptor).expect("adopted descriptor flags") & libc::FD_CLOEXEC,
            0,
            "the adopted runtime descriptor must not leak through later execs"
        );
        let error = InstalledDiscoveryLease::acquire_at(&path)
            .expect_err("adopted lease must exclude service mutation");
        assert!(
            error
                .to_string()
                .contains("already owns per-user discovery")
        );

        drop(adopted);
        drop(InstalledDiscoveryLease::acquire_at(&path).expect("lease released after adoption"));
    }

    #[test]
    #[cfg(unix)]
    fn service_exec_handoff_survives_a_real_exec() {
        const CHILD_FD: &str = "KATA_TEST_SERVICE_DISCOVERY_FD";
        const CHILD_PATH: &str = "KATA_TEST_SERVICE_DISCOVERY_PATH";
        const CHILD_STAGE: &str = "KATA_TEST_SERVICE_DISCOVERY_STAGE";

        if std::env::var_os(CHILD_STAGE).as_deref() == Some(OsStr::new("adopt")) {
            let raw_fd = std::env::var_os(CHILD_FD).expect("adopt descriptor");
            let raw_path = std::env::var_os(CHILD_PATH).expect("adopt path");
            let path = PathBuf::from(raw_path);
            let adopted =
                InstalledDiscoveryLease::adopt_service_exec_handoff_at(&path, raw_fd.as_os_str())
                    .expect("child adopts descriptor inherited across exec");
            let error = InstalledDiscoveryLease::acquire_at(&path)
                .expect_err("child handoff remains exclusive");
            assert!(
                error
                    .to_string()
                    .contains("already owns per-user discovery")
            );
            drop(adopted);
            return;
        }

        // The `acquire` stage takes its path from the PARENT's env and then
        // `exec()`s — which REPLACES the process image, so no destructor in it
        // ever runs. A `TempDir` created above this branch is therefore leaked
        // by construction, once per run of this test, and `TempDir`'s cleanup
        // has no other chance: measured, one `just test` under a
        // private `TMPDIR` left exactly one empty `.tmp*` directory and this was
        // it. The stage needs no scratch dir at all, so it creates none.
        if std::env::var_os(CHILD_STAGE).as_deref() == Some(OsStr::new("acquire")) {
            use std::os::unix::process::CommandExt as _;

            let path = PathBuf::from(std::env::var_os(CHILD_PATH).expect("acquire path"));
            let lease = InstalledDiscoveryLease::acquire_at(&path).expect("pre-exec lease");
            let descriptor = lease
                .prepare_service_exec_handoff()
                .expect("prepare real exec handoff");
            let error =
                std::process::Command::new(std::env::current_exe().expect("test executable"))
                    .arg("--exact")
                    .arg("attachment::tests::service_exec_handoff_survives_a_real_exec")
                    .arg("--nocapture")
                    .env(CHILD_STAGE, "adopt")
                    .env(CHILD_FD, descriptor.to_string())
                    .env(CHILD_PATH, &path)
                    .exec();
            panic!("execing adoption child failed: {error}");
        }

        let root = owner_only_tempdir();
        let path = root.path().join("discovery").join("lease.lock");
        let output = std::process::Command::new(std::env::current_exe().expect("test executable"))
            .arg("--exact")
            .arg("attachment::tests::service_exec_handoff_survives_a_real_exec")
            .arg("--nocapture")
            .env(CHILD_STAGE, "acquire")
            .env(CHILD_PATH, &path)
            .output()
            .expect("exec handoff child");
        assert!(
            output.status.success(),
            "exec handoff child failed: stdout={} stderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        drop(InstalledDiscoveryLease::acquire_at(&path).expect("lease released after exec child"));
    }

    #[test]
    #[cfg(unix)]
    fn service_exec_handoff_refuses_an_unlocked_descriptor() {
        use std::os::fd::IntoRawFd as _;

        let root = tempfile::tempdir().expect("tempdir");
        let path = root.path().join("discovery").join("lease.lock");
        drop(InstalledDiscoveryLease::acquire_at(&path).expect("initialize lease"));
        let parent = open_discovery_parent(
            path.parent().expect("parent"),
            DiscoveryDirectoryState::Existing,
        )
        .expect("open parent");
        let descriptor = open_existing_discovery_lease_file(&parent, &path)
            .expect("open unlocked descriptor")
            .into_raw_fd();
        let encoded = descriptor.to_string();
        let error =
            InstalledDiscoveryLease::adopt_service_exec_handoff_at(&path, OsStr::new(&encoded))
                .expect_err("an unlocked descriptor must not become a handoff");
        assert!(
            error.to_string().contains("did not already hold"),
            "unexpected unlocked handoff refusal: {error:#}"
        );
        drop(InstalledDiscoveryLease::acquire_at(&path).expect("lease remains usable"));
    }

    #[test]
    #[cfg(unix)]
    fn discovery_lease_rejects_unsafe_existing_inodes() {
        use std::os::unix::fs::{PermissionsExt as _, symlink};

        let root = tempfile::tempdir().expect("tempdir");
        let create_private_parent = |path: &Path| {
            std::fs::create_dir(path).expect("parent");
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
                .expect("parent permissions");
        };

        for (label, mode) in [
            ("permissive", 0o644),
            ("executable", 0o700),
            ("setid", 0o4600),
            ("read-only", 0o400),
            ("inaccessible", 0o000),
        ] {
            let candidate = root.path().join(label).join("lease.lock");
            create_private_parent(candidate.parent().expect("parent"));
            std::fs::write(&candidate, []).expect("candidate file");
            std::fs::set_permissions(&candidate, std::fs::Permissions::from_mode(mode))
                .expect("permissions");
            let error = InstalledDiscoveryLease::acquire_at(&candidate)
                .expect_err("noncanonical lock mode must fail");
            assert!(
                error.to_string().contains("must have mode 0600")
                    || error
                        .to_string()
                        .contains("opening installed-main discovery lock"),
                "unexpected mode {mode:o} refusal: {error:#}"
            );
            assert_eq!(
                std::fs::symlink_metadata(&candidate)
                    .expect("unchanged candidate")
                    .permissions()
                    .mode()
                    & 0o7777,
                mode,
                "an unsafe existing inode must never be repaired"
            );
        }

        let nonempty = root.path().join("nonempty").join("lease.lock");
        create_private_parent(nonempty.parent().expect("parent"));
        std::fs::write(&nonempty, b"not coordination state").expect("nonempty file");
        std::fs::set_permissions(&nonempty, std::fs::Permissions::from_mode(0o600))
            .expect("permissions");
        let error =
            InstalledDiscoveryLease::acquire_at(&nonempty).expect_err("nonempty lock must fail");
        assert!(error.to_string().contains("must remain empty"));

        let linked = root.path().join("linked").join("lease.lock");
        create_private_parent(linked.parent().expect("parent"));
        std::fs::write(&linked, []).expect("linked file");
        std::fs::hard_link(&linked, root.path().join("second-link")).expect("hard link");
        let error = InstalledDiscoveryLease::acquire_at(&linked)
            .expect_err("multiply linked lock must fail");
        assert!(error.to_string().contains("exactly one link"));

        let target = root.path().join("target");
        std::fs::write(&target, []).expect("target");
        let symlink_path = root.path().join("symlink-parent").join("lease.lock");
        create_private_parent(symlink_path.parent().expect("parent"));
        symlink(&target, &symlink_path).expect("symlink");
        let error =
            InstalledDiscoveryLease::acquire_at(&symlink_path).expect_err("symlink lock must fail");
        assert!(
            error
                .to_string()
                .contains("opening installed-main discovery lock")
        );

        let parent_target = root.path().join("parent-target");
        std::fs::create_dir(&parent_target).expect("parent target");
        let parent_symlink = root.path().join("parent-symlink");
        symlink(&parent_target, &parent_symlink).expect("parent symlink");
        let error = InstalledDiscoveryLease::acquire_at(&parent_symlink.join("lease.lock"))
            .expect_err("symlink parent must fail");
        assert!(
            error
                .to_string()
                .contains("must be an owner directory, not a symlink")
        );
    }

    #[test]
    #[cfg(unix)]
    fn discovery_lease_refuses_path_replacement_after_open() {
        use std::os::unix::fs::PermissionsExt as _;

        let root = tempfile::tempdir().expect("tempdir");
        let parent_path = root.path().join("discovery");
        std::fs::create_dir(&parent_path).expect("parent");
        std::fs::set_permissions(&parent_path, std::fs::Permissions::from_mode(0o700))
            .expect("parent permissions");
        let path = parent_path.join("lease.lock");
        let parent = open_discovery_parent(&parent_path, DiscoveryDirectoryState::Existing)
            .expect("open parent");
        let opened = open_discovery_lease_file(&parent, &path).expect("open lease");
        std::fs::remove_file(&path).expect("replace old pathname in adversarial fixture");
        std::fs::write(&path, []).expect("replacement");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
            .expect("replacement permissions");

        let error = validate_discovery_lease_path(&opened, &parent, &path)
            .expect_err("replacement inode must fail closed");
        assert!(
            error.to_string().contains("changed while acquiring")
                || error.to_string().contains("exactly one link"),
            "unexpected replacement refusal: {error:#}"
        );
    }

    #[test]
    #[cfg(unix)]
    fn discovery_lease_refuses_parent_replacement_after_open() {
        use std::os::unix::fs::PermissionsExt as _;

        let root = tempfile::tempdir().expect("tempdir");
        let parent_path = root.path().join("discovery");
        std::fs::create_dir(&parent_path).expect("parent");
        std::fs::set_permissions(&parent_path, std::fs::Permissions::from_mode(0o700))
            .expect("parent permissions");
        let path = parent_path.join("lease.lock");
        let parent = open_discovery_parent(&parent_path, DiscoveryDirectoryState::Existing)
            .expect("open parent");
        let opened = open_discovery_lease_file(&parent, &path).expect("open lease");

        let retired_parent = root.path().join("retired-discovery");
        std::fs::rename(&parent_path, &retired_parent).expect("retire opened parent");
        std::fs::create_dir(&parent_path).expect("replacement parent");
        std::fs::set_permissions(&parent_path, std::fs::Permissions::from_mode(0o700))
            .expect("replacement parent permissions");
        std::fs::write(&path, []).expect("replacement lease");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
            .expect("replacement lease permissions");

        let error = validate_discovery_lease_path(&opened, &parent, &path)
            .expect_err("replacement parent must fail closed");
        assert!(
            error.to_string().contains("changed or became unsafe"),
            "unexpected parent replacement refusal: {error:#}"
        );
    }

    #[test]
    #[cfg(unix)]
    fn discovery_lease_refuses_fifo_without_blocking() {
        use std::os::unix::fs::PermissionsExt as _;
        use std::process::Stdio;
        use std::time::{Duration, Instant};

        const CHILD_PATH: &str = "KATA_DISCOVERY_FIFO_TEST_PATH";
        if let Some(raw) = std::env::var_os(CHILD_PATH) {
            let path = PathBuf::from(raw);
            let error = InstalledDiscoveryLease::acquire_at(&path)
                .expect_err("FIFO discovery lease must fail closed");
            assert!(
                error.to_string().contains("must be a regular file"),
                "unexpected FIFO refusal: {error:#}"
            );
            return;
        }

        let root = tempfile::tempdir().expect("tempdir");
        let parent = root.path().join("discovery");
        std::fs::create_dir(&parent).expect("parent");
        std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o700))
            .expect("parent permissions");
        let path = parent.join("lease.lock");
        nix::unistd::mkfifo(&path, Mode::from_bits_truncate(0o600)).expect("FIFO fixture");

        let executable = std::env::current_exe().expect("test executable");
        let mut child = std::process::Command::new(executable)
            .arg("--exact")
            .arg("attachment::tests::discovery_lease_refuses_fifo_without_blocking")
            .arg("--nocapture")
            .env(CHILD_PATH, &path)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn FIFO refusal child");
        // Generous on purpose: it wraps a re-exec of the whole kata test binary,
        // which a loaded host starts slowly; a FIFO open that blocks never returns,
        // so any finite bound still catches it.
        let deadline = Instant::now() + Duration::from_secs(30);
        let status = loop {
            if let Some(status) = child.try_wait().expect("poll FIFO refusal child") {
                break status;
            }
            if Instant::now() >= deadline {
                child.kill().expect("terminate blocked FIFO refusal child");
                child.wait().expect("reap blocked FIFO refusal child");
                panic!("opening an existing FIFO discovery lease blocked");
            }
            std::thread::sleep(Duration::from_millis(10));
        };
        assert!(status.success(), "FIFO refusal child failed: {status}");
    }

    #[test]
    fn discovery_lease_requires_independent_lock_contention() {
        let path = Path::new("/tmp/discovery.lock");
        require_independent_discovery_lock_contention(Err(Errno::EWOULDBLOCK), path)
            .expect("contention proves exclusion");
        let error = require_independent_discovery_lock_contention(Ok(()), path)
            .expect_err("independent lock success must fail closed");
        assert!(error.to_string().contains("does not enforce"));
        let error = require_independent_discovery_lock_contention(Err(Errno::EIO), path)
            .expect_err("unexpected lock error must fail closed");
        assert!(error.to_string().contains("cannot verify"));
    }

    #[test]
    #[cfg(unix)]
    fn discovery_lease_refuses_to_repair_an_unsafe_existing_parent() {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

        let root = tempfile::tempdir().expect("tempdir");
        let parent = root.path().join("discovery");
        std::fs::create_dir(&parent).expect("parent");
        std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o755))
            .expect("unsafe parent permissions");
        let path = parent.join("lease.lock");

        let error = InstalledDiscoveryLease::acquire_at(&path)
            .expect_err("unsafe existing parent must fail closed");
        assert!(error.to_string().contains("must have mode 0700"));
        assert_eq!(parent.metadata().expect("metadata").mode() & 0o7777, 0o755);
        assert!(!path.exists(), "refusal must not create the lease inode");
    }

    #[test]
    #[cfg(unix)]
    fn discovery_lease_creation_ignores_restrictive_umask() {
        use std::os::unix::fs::MetadataExt as _;

        const CHILD_PATH: &str = "KATA_DISCOVERY_UMASK_TEST_PATH";
        if let Some(raw) = std::env::var_os(CHILD_PATH) {
            let path = PathBuf::from(raw);
            let lease = InstalledDiscoveryLease::acquire_at(&path).expect("child lease");
            assert_eq!(
                path.parent()
                    .expect("parent")
                    .metadata()
                    .expect("metadata")
                    .mode()
                    & 0o7777,
                0o700
            );
            assert_eq!(path.metadata().expect("metadata").mode() & 0o7777, 0o600);
            drop(lease);
            return;
        }

        let root = tempfile::tempdir().expect("tempdir");
        let path = root.path().join("discovery").join("lease.lock");
        let executable = std::env::current_exe().expect("test executable");
        let output = std::process::Command::new("/bin/sh")
            .arg("-c")
            .arg("umask 0777; exec \"$1\" --exact attachment::tests::discovery_lease_creation_ignores_restrictive_umask --nocapture")
            .arg("kata-discovery-umask")
            .arg(executable)
            .env(CHILD_PATH, &path)
            .output()
            .expect("run restrictive-umask child");
        assert!(
            output.status.success(),
            "restrictive-umask child failed: stdout={} stderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(
            path.parent()
                .expect("parent")
                .metadata()
                .expect("metadata")
                .mode()
                & 0o7777,
            0o700
        );
        assert_eq!(path.metadata().expect("metadata").mode() & 0o7777, 0o600);
    }

    #[test]
    fn explicit_withdraw_removes_only_the_owned_generation() {
        let (_lease_root, lease) = test_discovery_lease();
        let root = tempfile::tempdir().expect("tempdir");
        let path = root.path().join("attachment.json");
        write_descriptor(&path, &descriptor("generation-a"));
        let guard = attachment_guard(Arc::clone(&lease), path.clone(), "generation-a");
        guard.withdraw().expect("withdraw owned descriptor");
        assert!(!path.exists());
    }

    #[test]
    fn attachment_retains_discovery_lease_until_withdrawal_finishes() {
        let root = owner_only_tempdir();
        let lease_path = root.path().join("lease").join("discovery.lock");
        let lease = Arc::new(
            InstalledDiscoveryLease::acquire_at(&lease_path).expect("initial discovery lease"),
        );
        let attachment_parent = root.path().join("attachment");
        std::fs::create_dir(&attachment_parent).expect("attachment parent");
        let attachment_path = attachment_parent.join("attachment.json");
        write_descriptor(&attachment_path, &descriptor("generation-a"));
        let guard = attachment_guard(Arc::clone(&lease), attachment_path.clone(), "generation-a");

        drop(lease);
        let error = InstalledDiscoveryLease::acquire_at(&lease_path)
            .expect_err("attachment publication must retain the discovery lease");
        assert!(format!("{error:#}").contains("another installed Kata main"));

        guard.withdraw().expect("withdraw owned descriptor");
        assert!(!attachment_path.exists());
        drop(
            InstalledDiscoveryLease::acquire_at(&lease_path)
                .expect("discovery lease released only after attachment withdrawal"),
        );
    }

    #[test]
    fn attachment_rename_then_parent_sync_failure_withdraws_exact_publication() {
        let (_lease_root, lease) = test_discovery_lease();
        let root = owner_only_tempdir();
        let path = root.path().join("attachment.json");
        crate::service::inject_next_publication_parent_sync_failure(|| {});

        let error = InstalledAttachment::publish_at(
            Arc::clone(&lease),
            &installed_metadata("generation-a"),
            "none:test",
            path.clone(),
        )
        .expect_err("post-rename directory sync failure must fail publication");

        assert!(format!("{error:#}").contains("injected installed-main attachment"));
        assert!(
            !path.exists(),
            "a failed post-rename sync must not strand a visible attachment"
        );
        assert!(std::fs::read_dir(root.path()).unwrap().all(|entry| {
            !entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with(ATTACHMENT_PUBLICATION_ARTIFACT_PREFIX)
        }));
    }

    /// **The discovery directory's mode refusal prints the `chmod` that fixes
    /// it**, shell-quoted; run by `sh` exactly as printed, it is the whole
    /// fix: the lease is then acquired.
    ///
    /// **Would red if:** the refusal dropped its fix or printed a command that
    /// leaves the directory refused.
    #[test]
    #[cfg(unix)]
    fn a_discovery_directory_mode_refusal_prints_the_chmod_that_fixes_it() {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

        let root = tempfile::tempdir().expect("tempdir");
        let parent = root.path().join("discovery dir");
        std::fs::create_dir(&parent).expect("parent");
        std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o755))
            .expect("unsafe parent permissions");
        let path = parent.join("lease.lock");

        let refusal = format!(
            "{:#}",
            InstalledDiscoveryLease::acquire_at(&path).expect_err("unsafe parent must refuse")
        );
        let (_, command) = refusal
            .rsplit_once("fix: ")
            .unwrap_or_else(|| panic!("the refusal prints no fix: {refusal}"));
        assert_eq!(command, format!("chmod 700 '{}'", parent.display()));
        let status = std::process::Command::new("/bin/sh")
            .arg("-c")
            .arg(command)
            .status()
            .expect("sh");
        assert!(status.success(), "`{command}` failed: {status}");
        assert_eq!(parent.metadata().expect("metadata").mode() & 0o7777, 0o700);
        InstalledDiscoveryLease::acquire_at(&path).expect("the printed fix is the whole fix");
    }

    /// **A discovery directory another account owns is refused with the
    /// reason, never a command.** `/usr` stands in for a squatted
    /// `/tmp/kata-installed-main-<uid>`.
    ///
    /// **Would red if:** the refusal dropped its reason or proposed a command.
    #[test]
    #[cfg(unix)]
    fn a_discovery_directory_another_account_owns_is_refused_with_why() {
        use std::os::unix::fs::MetadataExt as _;

        let euid = nix::unistd::geteuid().as_raw();
        assert_ne!(
            std::fs::metadata("/usr").expect("metadata").uid(),
            euid,
            "precondition: /usr belongs to another account"
        );
        let refusal = format!(
            "{:#}",
            InstalledDiscoveryLease::acquire_at(Path::new("/usr/lease.lock"))
                .expect_err("a foreign directory must refuse")
        );
        assert!(
            refusal.contains(&format!(
                "refused: uid 0 owns it, not you (uid {euid}); kata writes only into directories you own"
            )),
            "{refusal}"
        );
        assert!(!refusal.contains("fix: "), "{refusal}");
        assert!(!refusal.contains("chown"), "{refusal}");
    }

    #[test]
    fn attachment_publish_never_repairs_a_preexisting_parent() {
        use std::os::unix::fs::PermissionsExt as _;

        let (_lease_root, lease) = test_discovery_lease();
        let root = owner_only_tempdir();
        let parent = root.path().join("attachments");
        std::fs::create_dir(&parent).expect("attachment parent");
        std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o755))
            .expect("drift parent posture");
        let path = parent.join("attachment.json");

        let error = InstalledAttachment::publish_at(
            Arc::clone(&lease),
            &installed_metadata("generation-a"),
            "none:test",
            path.clone(),
        )
        .expect_err("preexisting non-private parent must be refused without repair");

        assert!(format!("{error:#}").contains("expected uid"));
        assert_eq!(
            std::fs::symlink_metadata(&parent)
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o755,
            "a preexisting parent is operator state and must not be chmodded"
        );
        assert!(!path.exists());
    }

    #[test]
    fn attachment_publish_never_follows_or_chmods_a_parent_symlink() {
        use std::os::unix::fs::{PermissionsExt as _, symlink};

        let (_lease_root, lease) = test_discovery_lease();
        let root = owner_only_tempdir();
        let target = root.path().join("target");
        let alias = root.path().join("alias");
        std::fs::create_dir(&target).expect("symlink target");
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o755))
            .expect("target posture");
        symlink(&target, &alias).expect("attachment parent symlink");

        let error = InstalledAttachment::publish_at(
            Arc::clone(&lease),
            &installed_metadata("generation-a"),
            "none:test",
            alias.join("attachment.json"),
        )
        .expect_err("attachment parent symlink must fail closed");

        assert!(format!("{error:#}").contains("without following symlinks"));
        assert_eq!(
            std::fs::symlink_metadata(&target)
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o755,
            "refusing a parent symlink must not chmod its target"
        );
        assert!(!target.join("attachment.json").exists());
    }

    #[test]
    fn stale_attachment_removal_recovery_blocks_republication() {
        let (_lease_root, lease) = test_discovery_lease();
        let root = owner_only_tempdir();
        let path = root.path().join("attachment.json");
        write_descriptor(&path, &descriptor("generation-a"));
        inject_next_publication_removal_parent_sync_failure(|| {});

        let error = InstalledAttachment::publish_at(
            Arc::clone(&lease),
            &installed_metadata("generation-b"),
            "none:test",
            path.clone(),
        )
        .expect_err("uncertain stale removal must block a new canonical descriptor");

        let message = format!("{error:#}");
        assert!(message.contains("stale installed-main attachment removal requires recovery"));
        assert!(message.contains("CanonicalRetired"));
        assert!(
            !path.exists(),
            "a new canonical descriptor must not be published"
        );
        assert!(std::fs::read_dir(root.path()).unwrap().any(|entry| {
            entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with(ATTACHMENT_PUBLICATION_ARTIFACT_PREFIX)
        }));
    }

    #[test]
    fn attachment_parent_swap_after_rename_cleans_from_retained_parent() {
        use std::os::unix::fs::PermissionsExt as _;

        let (_lease_root, lease) = test_discovery_lease();
        let root = owner_only_tempdir();
        let canonical_parent = root.path().join("attachments");
        let moved_parent = root.path().join("moved-attachments");
        std::fs::create_dir(&canonical_parent).unwrap();
        std::fs::set_permissions(&canonical_parent, std::fs::Permissions::from_mode(0o700))
            .unwrap();
        let path = canonical_parent.join("attachment.json");
        let hook_parent = canonical_parent.clone();
        let hook_moved = moved_parent.clone();
        crate::service::inject_next_publication_parent_sync_failure(move || {
            std::fs::rename(&hook_parent, &hook_moved).expect("move the opened publication parent");
            std::fs::create_dir(&hook_parent).expect("replace canonical parent");
            std::fs::set_permissions(&hook_parent, std::fs::Permissions::from_mode(0o700)).unwrap();
            std::fs::write(hook_parent.join("sentinel"), b"replacement-parent").unwrap();
        });

        let error = InstalledAttachment::publish_at(
            Arc::clone(&lease),
            &installed_metadata("generation-a"),
            "none:test",
            path,
        )
        .expect_err("parent replacement after rename must fail publication");
        let message = format!("{error:#}");
        assert!(
            message.contains("parent-directory sync failure"),
            "{message}"
        );
        assert_eq!(
            std::fs::read(canonical_parent.join("sentinel")).unwrap(),
            b"replacement-parent"
        );
        assert_eq!(
            std::fs::read_dir(&moved_parent).unwrap().count(),
            0,
            "descriptor and temporary must be removed through the retained parent fd"
        );
    }

    #[test]
    fn attachment_parent_swap_before_no_replace_rename_cleans_from_retained_parent() {
        use std::os::unix::fs::PermissionsExt as _;

        let (_lease_root, lease) = test_discovery_lease();
        let root = owner_only_tempdir();
        let canonical_parent = root.path().join("attachments");
        let moved_parent = root.path().join("moved-attachments");
        std::fs::create_dir(&canonical_parent).unwrap();
        std::fs::set_permissions(&canonical_parent, std::fs::Permissions::from_mode(0o700))
            .unwrap();
        let path = canonical_parent.join("attachment.json");
        let hook_parent = canonical_parent.clone();
        let hook_moved = moved_parent.clone();
        crate::service::inject_pre_no_replace_rename_hook(move || {
            std::fs::rename(&hook_parent, &hook_moved).expect("move the opened publication parent");
            std::fs::create_dir(&hook_parent).expect("replace canonical parent");
            std::fs::set_permissions(&hook_parent, std::fs::Permissions::from_mode(0o700)).unwrap();
            std::fs::write(hook_parent.join("sentinel"), b"replacement-parent").unwrap();
        });

        let error = InstalledAttachment::publish_at(
            Arc::clone(&lease),
            &installed_metadata("generation-a"),
            "none:test",
            path.clone(),
        )
        .expect_err("parent replacement before rename must fail publication");
        let message = format!("{error:#}");
        assert!(message.contains("changed during publication"), "{message}");
        assert_eq!(
            std::fs::read(canonical_parent.join("sentinel")).unwrap(),
            b"replacement-parent"
        );
        assert!(!path.exists(), "the replacement parent remains untouched");
        assert_eq!(
            std::fs::read_dir(&canonical_parent).unwrap().count(),
            1,
            "the replacement parent contains only its sentinel"
        );
        assert_eq!(
            std::fs::read_dir(&moved_parent).unwrap().count(),
            0,
            "the descriptor and every publication artifact are removed through the retained parent fd"
        );
    }

    #[test]
    fn attachment_destination_appearing_at_no_replace_preserves_winner() {
        let (_lease_root, lease) = test_discovery_lease();
        let root = owner_only_tempdir();
        let path = root.path().join("attachment.json");
        let winner = descriptor("generation-b");
        let winner_bytes = serde_json::to_vec(&winner).expect("serialize winner");
        let hook_path = path.clone();
        let hook_winner = winner.clone();
        crate::service::inject_pre_no_replace_rename_hook(move || {
            write_descriptor(&hook_path, &hook_winner);
        });

        let error = InstalledAttachment::publish_at(
            Arc::clone(&lease),
            &installed_metadata("generation-a"),
            "none:test",
            path.clone(),
        )
        .expect_err("a destination appearing before no-replace rename must win");
        let message = format!("{error:#}");
        assert!(
            message.contains("installed-main attachment destination appeared during publication"),
            "{message}"
        );
        assert_eq!(
            read_attachment_descriptor_at(&path).expect("winner preserved"),
            winner
        );
        assert_eq!(
            std::fs::read(&path).unwrap(),
            winner_bytes,
            "the winning publication's exact bytes remain unchanged"
        );
        assert_eq!(
            std::fs::read_dir(root.path()).unwrap().count(),
            1,
            "only the winning destination remains after temporary cleanup"
        );
        assert!(std::fs::read_dir(root.path()).unwrap().all(|entry| {
            !entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with(ATTACHMENT_PUBLICATION_ARTIFACT_PREFIX)
        }));
    }

    #[test]
    fn attachment_post_rename_cleanup_never_unlinks_a_replacement() {
        let (_lease_root, lease) = test_discovery_lease();
        let root = owner_only_tempdir();
        let path = root.path().join("attachment.json");
        let replacement_path = root.path().join("replacement.json");
        write_descriptor(&replacement_path, &descriptor("generation-b"));
        let hook_path = path.clone();
        crate::service::inject_next_publication_parent_sync_failure(move || {
            std::fs::rename(&replacement_path, &hook_path)
                .expect("replace publication before injected sync failure");
        });

        let error = InstalledAttachment::publish_at(
            Arc::clone(&lease),
            &installed_metadata("generation-a"),
            "none:test",
            path.clone(),
        )
        .expect_err("replacement race must fail exact publication cleanup");

        let message = format!("{error:#}");
        assert!(
            message.contains(
                "post-rename recovery state; exact retained publication cleanup is required"
            ),
            "{message}"
        );
        assert!(
            message.contains("injected installed-main attachment parent-directory sync failure"),
            "{message}"
        );
        let preserved = read_attachment_descriptor_at(&path).expect("replacement preserved");
        assert_eq!(preserved.process_generation, "generation-b");
        assert!(std::fs::read_dir(root.path()).unwrap().all(|entry| {
            !entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with(ATTACHMENT_PUBLICATION_ARTIFACT_PREFIX)
        }));
    }

    #[test]
    fn attachment_guard_retains_original_inode_across_replacement() {
        let (_lease_root, lease) = test_discovery_lease();
        let root = owner_only_tempdir();
        let path = root.path().join("attachment.json");
        let mut installed = InstalledAttachment::publish_at(
            Arc::clone(&lease),
            &installed_metadata("generation-a"),
            "none:test",
            path.clone(),
        )
        .unwrap();
        let publication = installed
            .publication
            .take()
            .expect("attachment owns its publication");
        let replacement_path = root.path().join("replacement.json");
        write_descriptor(&replacement_path, &descriptor("generation-b"));
        std::fs::rename(&replacement_path, &path).unwrap();

        let held = publication.open_identity_for_test();
        assert_eq!(
            held.links, 0,
            "the displaced inode remains open, not linked"
        );
        assert_eq!(held.device, publication.identity().device);
        assert_eq!(held.inode, publication.identity().inode);
        let error = publication
            .withdraw()
            .expect_err("withdrawal must refuse the replacement pathname");
        let message = format!("{error:#}");
        assert!(
            message.contains("changed after descriptor adoption"),
            "{message}"
        );
        assert_eq!(
            read_attachment_descriptor_at(&path)
                .unwrap()
                .process_generation,
            "generation-b"
        );
    }

    #[test]
    fn explicit_withdraw_refuses_another_generation() {
        let (_lease_root, lease) = test_discovery_lease();
        let root = tempfile::tempdir().expect("tempdir");
        let path = root.path().join("attachment.json");
        write_descriptor(&path, &descriptor("generation-a"));
        let guard = attachment_guard(Arc::clone(&lease), path.clone(), "generation-a");
        let replacement = root.path().join("replacement.json");
        write_descriptor(&replacement, &descriptor("generation-b"));
        std::fs::rename(&replacement, &path).expect("replace attachment generation");
        let error = guard
            .withdraw()
            .expect_err("must not withdraw another generation");
        assert!(error.to_string().contains("generation changed"));
        assert!(path.exists());
    }

    #[test]
    fn explicit_withdraw_preserves_a_same_generation_replacement_inode() {
        let (_lease_root, lease) = test_discovery_lease();
        let root = tempfile::tempdir().expect("tempdir");
        let path = root.path().join("attachment.json");
        let original = descriptor("generation-a");
        write_descriptor(&path, &original);
        let guard = attachment_guard(Arc::clone(&lease), path.clone(), "generation-a");

        let mut replacement = original;
        replacement.endpoint = "http://127.0.0.1:9999".to_string();
        let replacement_path = root.path().join("replacement.json");
        write_descriptor(&replacement_path, &replacement);
        std::fs::rename(&replacement_path, &path).expect("replace attachment inode");

        let error = guard
            .withdraw()
            .expect_err("withdrawal must not delete a replacement inode");
        assert!(format!("{error:#}").contains("inode changed"));
        let preserved = read_attachment_descriptor_at(&path).expect("replacement preserved");
        assert_eq!(preserved.endpoint, replacement.endpoint);
    }

    #[test]
    fn attachment_recovery_is_bounded_and_rejects_unsafe_known_artifacts() {
        use std::os::unix::fs::PermissionsExt as _;

        let root = tempfile::tempdir().expect("tempdir");
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let safe = root.path().join(".main-attachment-interrupted.tmp");
        std::fs::write(&safe, b"partial").unwrap();
        std::fs::set_permissions(&safe, std::fs::Permissions::from_mode(0o600)).unwrap();
        recover_owner_only_publication_artifacts(
            root.path(),
            ATTACHMENT_PUBLICATION_ARTIFACT_PREFIX,
            MAX_ATTACHMENT_DESCRIPTOR_BYTES,
            MAX_ATTACHMENT_PUBLICATION_ARTIFACTS,
            "test installed-main attachment",
        )
        .unwrap();
        assert!(!safe.exists());

        let unsafe_artifact = root.path().join(".main-attachment-foreign.quarantine");
        std::fs::create_dir(&unsafe_artifact).unwrap();
        let error = recover_owner_only_publication_artifacts(
            root.path(),
            ATTACHMENT_PUBLICATION_ARTIFACT_PREFIX,
            MAX_ATTACHMENT_DESCRIPTOR_BYTES,
            MAX_ATTACHMENT_PUBLICATION_ARTIFACTS,
            "test installed-main attachment",
        )
        .expect_err("unsafe attachment recovery artifacts must fail closed");
        assert!(format!("{error:#}").contains("not safe to recover"));
        assert!(unsafe_artifact.is_dir());
    }

    #[test]
    fn failed_attachment_no_replace_publication_cleans_only_its_temporary() {
        use std::os::unix::fs::PermissionsExt as _;

        let root = tempfile::tempdir().expect("tempdir");
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let destination = root.path().join("attachment.json");
        write_descriptor(&destination, &descriptor("existing"));
        let mut temporary = OwnerOnlyPublicationTemp::create(
            root.path(),
            ATTACHMENT_PUBLICATION_ARTIFACT_PREFIX,
            MAX_ATTACHMENT_DESCRIPTOR_BYTES,
            "test installed-main attachment",
        )
        .unwrap();
        temporary.file_mut().write_all(b"partial").unwrap();
        temporary.sync_contents().unwrap();
        assert!(matches!(
            temporary.publish_noreplace(&destination).unwrap(),
            OwnerOnlyNoReplacePublication::DestinationExists
        ));
        temporary.cleanup().unwrap();

        assert_eq!(
            read_attachment_descriptor_at(&destination)
                .unwrap()
                .process_generation,
            "existing"
        );
        assert!(std::fs::read_dir(root.path()).unwrap().all(|entry| {
            !entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with(ATTACHMENT_PUBLICATION_ARTIFACT_PREFIX)
        }));
    }

    #[test]
    #[cfg(unix)]
    fn attachment_fifo_cannot_block_read_withdraw_or_drop() {
        use std::os::unix::fs::FileTypeExt as _;

        let (_lease_root, lease) = test_discovery_lease();
        let root = tempfile::tempdir().expect("tempdir");
        let path = root.path().join("attachment.json");
        write_descriptor(&path, &descriptor("generation-a"));
        let guard = attachment_guard(Arc::clone(&lease), path.clone(), "generation-a");
        let replacement = root.path().join("replacement.fifo");
        nix::unistd::mkfifo(&replacement, Mode::from_bits_truncate(0o600))
            .expect("FIFO replacement");
        std::fs::rename(&replacement, &path).expect("atomically replace attachment with FIFO");
        let (sender, receiver) = std::sync::mpsc::channel();
        let worker_path = path.clone();
        let worker = std::thread::spawn(move || {
            let read_error = read_attachment_descriptor_at(&worker_path)
                .expect_err("FIFO descriptor must fail closed")
                .to_string();
            let withdraw_error = guard
                .withdraw()
                .expect_err("FIFO withdrawal must fail closed");
            let withdraw_error = format!("{withdraw_error:#}");
            sender.send((read_error, withdraw_error)).expect("result");
        });
        let (read_error, withdraw_error) = receiver
            .recv_timeout(std::time::Duration::from_secs(5))
            .expect("attachment FIFO paths must not block shutdown");
        worker.join().expect("worker");
        assert!(
            read_error.contains("not an exact owner-only bounded regular file publication"),
            "{read_error}"
        );
        assert!(
            withdraw_error.contains("not an exact owner-only bounded regular file publication"),
            "{withdraw_error}"
        );
        assert!(
            std::fs::symlink_metadata(&path)
                .expect("FIFO preserved")
                .file_type()
                .is_fifo(),
            "drop must not remove the unverifiable FIFO replacement"
        );
    }

    #[test]
    #[cfg(unix)]
    fn oversized_attachment_is_bounded_for_read_withdraw_and_drop() {
        use std::os::unix::fs::PermissionsExt as _;

        let (_lease_root, lease) = test_discovery_lease();
        let root = tempfile::tempdir().expect("tempdir");
        let path = root.path().join("attachment.json");
        write_descriptor(&path, &descriptor("generation-a"));
        let guard = attachment_guard(Arc::clone(&lease), path.clone(), "generation-a");
        let replacement = root.path().join("oversized.json");
        std::fs::write(
            &replacement,
            vec![b'x'; usize::try_from(MAX_ATTACHMENT_DESCRIPTOR_BYTES).unwrap() + 1],
        )
        .expect("oversized descriptor");
        std::fs::set_permissions(&replacement, std::fs::Permissions::from_mode(0o600))
            .expect("owner-only descriptor mode");
        std::fs::rename(&replacement, &path)
            .expect("atomically replace attachment with oversized file");
        let read_error = read_attachment_descriptor_at(&path)
            .expect_err("oversized descriptor must fail closed")
            .to_string();
        let expected_bound = format!("bytes<={MAX_ATTACHMENT_DESCRIPTOR_BYTES}");
        assert!(
            read_error.contains("not an exact owner-only bounded regular file publication")
                && read_error.contains(&expected_bound),
            "{read_error}"
        );
        let withdraw_error = guard
            .withdraw()
            .expect_err("oversized withdrawal must fail closed");
        let withdraw_error = format!("{withdraw_error:#}");
        assert!(
            withdraw_error.contains("not an exact owner-only bounded regular file publication")
                && withdraw_error.contains(&expected_bound),
            "{withdraw_error}"
        );
        assert!(
            path.exists(),
            "drop must not remove an unverifiable descriptor"
        );
        assert!(
            path.metadata().expect("oversized replacement").len() > MAX_ATTACHMENT_DESCRIPTOR_BYTES,
            "drop must preserve the oversized replacement exactly"
        );
    }

    #[test]
    fn attached_status_probe_times_out_when_server_accepts_and_stalls() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("listener");
        let address = listener.local_addr().expect("address");
        let (stop_tx, stop_rx) = std::sync::mpsc::channel();
        let server = std::thread::spawn(move || {
            let (_stream, _) = listener.accept().expect("accept probe");
            stop_rx.recv().expect("stop stalled server");
        });
        let endpoint = format!("http://{address}");
        let started = std::time::Instant::now();
        let error = connect_verified_attached_main_sync_with_timeout(
            Some(&endpoint),
            std::time::Duration::from_millis(100),
        )
        .err()
        .expect("accepted connection without a response must time out");
        stop_tx.send(()).expect("stop server");
        server.join().expect("server");
        let message = format!("{error:#}");
        assert!(
            message.contains("deadline") || message.contains("timed out"),
            "{message}"
        );
        assert!(started.elapsed() < std::time::Duration::from_secs(1));
    }

    #[test]
    fn attached_status_probe_rejects_oversized_streaming_body() {
        use std::io::Write as _;

        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("listener");
        let address = listener.local_addr().expect("address");
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept probe");
            let mut request = std::io::BufReader::new(stream.try_clone().expect("clone stream"));
            let mut line = String::new();
            loop {
                use std::io::BufRead as _;
                line.clear();
                request.read_line(&mut line).expect("read request");
                if line == "\r\n" || line.is_empty() {
                    break;
                }
            }
            let body = vec![b'x'; MAX_ATTACHMENT_STATUS_BODY_BYTES + 1];
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            )
            .expect("response header");
            let _ = stream.write_all(&body);
            let _ = stream.flush();
            let _ = stream.shutdown(std::net::Shutdown::Write);
        });
        let endpoint = format!("http://{address}");
        let error = connect_verified_attached_main_sync_with_timeout(
            Some(&endpoint),
            std::time::Duration::from_secs(2),
        )
        .err()
        .expect("oversized status body must fail before allocation is unbounded");
        server.join().expect("server");
        let message = format!("{error:#}");
        assert!(message.contains("body ceiling"), "{message}");
    }

    /// A READABLE-BUT-STALE descriptor must name itself in the refusal.
    ///
    /// A `kata serve` that is `SIGKILL`ed leaves a well-formed descriptor
    /// pointing at an endpoint with no process behind it. A refusal that named
    /// only the endpoint would show the operator an address they never typed,
    /// with no mention that a file chose it and no way to clear it. The descriptor is
    /// documented as a convenience and never authority, so removing a stale one
    /// is safe; the refusal is how the operator learns it exists.
    #[test]
    fn the_unreachable_refusal_names_the_descriptor_that_chose_the_endpoint() {
        let discovered = super::unreachable_main_context(
            "http://127.0.0.1:58393",
            Some(std::path::Path::new(
                "/home/op/.local/state/kata/main-attachment.json",
            )),
        );
        assert!(
            discovered.contains("could not attach to installed main at http://127.0.0.1:58393")
        );
        assert!(
            discovered.contains("/home/op/.local/state/kata/main-attachment.json"),
            "the path that chose the endpoint must appear: {discovered}"
        );
        assert!(
            discovered.contains("STALE"),
            "and the reason it might be wrong: {discovered}"
        );
        assert!(
            discovered.contains("rm /home/op/.local/state/kata/main-attachment.json"),
            "and the command that clears it: {discovered}"
        );
        assert!(
            discovered.contains("kata service status"),
            "gated on the one check that makes removal safe: {discovered}"
        );
    }

    /// The other arm, so the hint is not unconditional prose: an operator who
    /// typed `--api-url` chose the endpoint themselves, and pointing them at a
    /// descriptor that had nothing to do with it would be a fresh false lead.
    #[test]
    fn an_explicitly_requested_endpoint_is_not_blamed_on_a_descriptor() {
        let typed = super::unreachable_main_context("http://10.0.0.7:9999", None);
        assert!(typed.contains("could not attach to installed main at http://10.0.0.7:9999"));
        assert!(
            !typed.contains("descriptor"),
            "no descriptor chose this endpoint: {typed}"
        );
        assert!(!typed.contains("rm "), "{typed}");
    }
}
