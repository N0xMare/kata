//! Descriptor-relative publication of bounded owner-only authority files.
//!
//! Canonical namespace state is committed by rename plus parent-directory
//! sync.  Unlink is only garbage collection: Unix has no atomic
//! unlink-if-this-open-inode-still-matches operation, and Kata deliberately
//! makes no hostile-same-UID claim.  Cooperating Kata writers are serialized
//! by the installed lifecycle/discovery leases owned by their callers.

use std::ffi::{OsStr, OsString};
use std::fs::File;
use std::os::fd::{AsRawFd as _, FromRawFd as _};
use std::os::unix::fs::{FileExt as _, MetadataExt as _};
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context as _, Result, bail};
use nix::errno::Errno;
use nix::fcntl::{OFlag, openat};
use nix::sys::stat::{FchmodatFlags, Mode, fchmod, fchmodat, mkdirat};
use nix::unistd::{UnlinkatFlags, unlinkat};

use crate::authority_file::normalize_new_owner_only_file;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct PublicationFileIdentity {
    pub(crate) device: u64,
    pub(crate) inode: u64,
    pub(crate) bytes: u64,
    pub(crate) modified_seconds: i64,
    pub(crate) modified_nanoseconds: i64,
    pub(crate) changed_seconds: i64,
    pub(crate) changed_nanoseconds: i64,
    pub(crate) uid: u32,
    pub(crate) mode: u32,
    pub(crate) links: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PublicationPostCommitState {
    CanonicalPresent,
    CanonicalRetired,
    PriorCanonicalRetired,
    PriorCanonicalRestored,
    ReplacementPresentWithRollback,
}

#[derive(Debug)]
pub(crate) struct PublicationRecoveryRequired {
    pub(crate) state: PublicationPostCommitState,
    pub(crate) path: PathBuf,
    source: anyhow::Error,
}

impl std::fmt::Display for PublicationRecoveryRequired {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "publication reached post-rename state {:?} at {} and requires reconciliation: {:#}",
            self.state,
            self.path.display(),
            self.source
        )
    }
}

impl std::error::Error for PublicationRecoveryRequired {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(self.source.as_ref())
    }
}

fn post_commit_error(
    state: PublicationPostCommitState,
    path: &Path,
    source: anyhow::Error,
) -> PublicationRecoveryRequired {
    PublicationRecoveryRequired {
        state,
        path: path.to_path_buf(),
        source,
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct DirectoryIdentity {
    device: u64,
    inode: u64,
    uid: u32,
    mode: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum DirectoryPosture {
    OwnerNoGroupWorldWrite,
    OwnerOnly,
    RootNoGroupWorldWrite,
    RootStickyTemporary,
}

#[derive(Clone, Debug)]
struct DirectoryBinding {
    name: OsString,
    identity: DirectoryIdentity,
    posture: Option<DirectoryPosture>,
}

#[derive(Debug)]
struct AuthorityDirectory {
    path: PathBuf,
    file: File,
    root_identity: DirectoryIdentity,
    chain: Vec<DirectoryBinding>,
    posture: DirectoryPosture,
}

impl AuthorityDirectory {
    fn bind_existing(path: &Path, label: &str) -> Result<Self> {
        Self::bind(path, label, false, DirectoryPosture::OwnerNoGroupWorldWrite)
    }

    fn bind_existing_owner_only(path: &Path, label: &str) -> Result<Self> {
        Self::bind(path, label, false, DirectoryPosture::OwnerOnly)
    }

    fn bind_or_create(path: &Path, label: &str, owner_only: bool) -> Result<Self> {
        Self::bind(
            path,
            label,
            true,
            if owner_only {
                DirectoryPosture::OwnerOnly
            } else {
                DirectoryPosture::OwnerNoGroupWorldWrite
            },
        )
    }

    #[allow(unsafe_code)]
    fn bind(
        path: &Path,
        label: &str,
        create_missing: bool,
        posture: DirectoryPosture,
    ) -> Result<Self> {
        let resolved_path = trusted_absolute_path(path);
        let path = resolved_path.as_path();
        if !path.is_absolute() {
            bail!("{label} directory must be absolute: {}", path.display());
        }
        let root_descriptor = openat(None, Path::new("/"), directory_open_flags(), Mode::empty())
            .with_context(|| format!("opening filesystem root for {label}"))?;
        // SAFETY: successful `openat` returns a newly owned descriptor.
        let mut current = unsafe { File::from_raw_fd(root_descriptor) };
        let root_identity = directory_identity(&current, Path::new("/"), label)?;
        let mut current_path = PathBuf::from("/");
        let mut chain = Vec::new();

        for component in path.components() {
            let name = match component {
                Component::RootDir => continue,
                Component::Normal(name) => name,
                _ => bail!(
                    "{label} directory contains a non-normal component: {}",
                    path.display()
                ),
            };
            let opened = openat(
                Some(current.as_raw_fd()),
                name,
                directory_open_flags(),
                Mode::empty(),
            );
            let (child, created) = match opened {
                Ok(descriptor) => {
                    // SAFETY: successful `openat` returns a newly owned descriptor.
                    (unsafe { File::from_raw_fd(descriptor) }, false)
                }
                Err(Errno::ENOENT) if create_missing => {
                    let created = match mkdirat(
                        Some(current.as_raw_fd()),
                        name,
                        Mode::from_bits_truncate(0o700),
                    ) {
                        Ok(()) => true,
                        Err(Errno::EEXIST) => false,
                        Err(error) => {
                            return Err(error).with_context(|| {
                                format!(
                                    "creating {label} directory component {}",
                                    current_path.join(name).display()
                                )
                            });
                        }
                    };
                    if created {
                        fchmodat(
                            Some(current.as_raw_fd()),
                            name,
                            Mode::from_bits_truncate(0o700),
                            FchmodatFlags::FollowSymlink,
                        )
                        .with_context(|| {
                            format!(
                                "normalizing new {label} directory component {} before opening",
                                current_path.join(name).display()
                            )
                        })?;
                    }
                    let descriptor = openat(
                        Some(current.as_raw_fd()),
                        name,
                        directory_open_flags(),
                        Mode::empty(),
                    )
                    .with_context(|| {
                        format!(
                            "binding newly created {label} directory component {}",
                            current_path.join(name).display()
                        )
                    })?;
                    // Only normalize a component this operation definitely
                    // created. An EEXIST winner is validated without mutation.
                    // SAFETY: successful `openat` returns a newly owned descriptor.
                    (unsafe { File::from_raw_fd(descriptor) }, created)
                }
                Err(error) => {
                    return Err(error).with_context(|| {
                        format!(
                            "opening {label} directory component {} without following symlinks",
                            current_path.join(name).display()
                        )
                    });
                }
            };
            current_path.push(name);
            if created {
                fchmod(child.as_raw_fd(), Mode::from_bits_truncate(0o700)).with_context(|| {
                    format!(
                        "normalizing new {label} directory {}",
                        current_path.display()
                    )
                })?;
            }
            let identity = directory_identity(&child, &current_path, label)?;
            // Existing system-owned ancestors are conventional host
            // namespace. Every effective-user-owned component is part of the
            // publication authority chain and must not be writable by another
            // group/world principal. Components created by this operation are
            // held to exact owner-only posture.
            let component_posture = if created {
                Some(DirectoryPosture::OwnerOnly)
            } else if identity.uid == nix::unistd::geteuid().as_raw() {
                Some(DirectoryPosture::OwnerNoGroupWorldWrite)
            } else if identity.uid == 0 && identity.mode & 0o022 == 0 {
                Some(DirectoryPosture::RootNoGroupWorldWrite)
            } else if identity.uid == 0
                && identity.mode == 0o1777
                && is_trusted_root_sticky_temporary(&current_path)
            {
                Some(DirectoryPosture::RootStickyTemporary)
            } else {
                bail!(
                    "{label} directory component {} has unsupported ancestor uid {} mode {:o}; expected root/effective-owner control or a recognized root sticky temporary anchor; {}",
                    current_path.display(),
                    identity.uid,
                    identity.mode,
                    untrusted_ancestor_refusal(identity)
                );
            };
            if let Some(component_posture) = component_posture {
                validate_directory_posture(identity, &current_path, label, component_posture)?;
            }
            chain.push(DirectoryBinding {
                name: name.to_os_string(),
                identity,
                posture: component_posture,
            });
            current = child;
        }
        if current_path != path {
            bail!(
                "{label} directory binding resolved {} instead of {}",
                current_path.display(),
                path.display()
            );
        }
        let final_identity = directory_identity(&current, path, label)?;
        validate_directory_posture(final_identity, path, label, posture)?;
        let directory = Self {
            path: path.to_path_buf(),
            file: current,
            root_identity,
            chain,
            posture,
        };
        directory.revalidate()?;
        Ok(directory)
    }

    #[allow(unsafe_code)]
    fn revalidate(&self) -> Result<()> {
        let root_descriptor = openat(None, Path::new("/"), directory_open_flags(), Mode::empty())
            .context("reopening filesystem root for publication revalidation")?;
        // SAFETY: successful `openat` returns a newly owned descriptor.
        let mut current = unsafe { File::from_raw_fd(root_descriptor) };
        if directory_identity(&current, Path::new("/"), "publication")? != self.root_identity {
            bail!("filesystem root changed during publication");
        }
        let mut path = PathBuf::from("/");
        for binding in &self.chain {
            let descriptor = openat(
                Some(current.as_raw_fd()),
                binding.name.as_os_str(),
                directory_open_flags(),
                Mode::empty(),
            )
            .with_context(|| {
                format!(
                    "rebinding publication directory component {}",
                    path.join(&binding.name).display()
                )
            })?;
            // SAFETY: successful `openat` returns a newly owned descriptor.
            let child = unsafe { File::from_raw_fd(descriptor) };
            path.push(&binding.name);
            let identity = directory_identity(&child, &path, "publication")?;
            if identity.device != binding.identity.device
                || identity.inode != binding.identity.inode
                || identity.uid != binding.identity.uid
                || identity.mode != binding.identity.mode
            {
                bail!(
                    "publication directory component {} changed during publication after descriptor adoption (identity or posture drift)",
                    path.display()
                );
            }
            if let Some(posture) = binding.posture {
                validate_directory_posture(identity, &path, "publication", posture)?;
            }
            current = child;
        }
        let held = directory_identity(&self.file, &self.path, "publication")?;
        let rebound = directory_identity(&current, &self.path, "publication")?;
        if held.device != rebound.device || held.inode != rebound.inode {
            bail!(
                "publication directory {} changed after descriptor adoption",
                self.path.display()
            );
        }
        validate_directory_posture(held, &self.path, "publication", self.posture)
    }

    fn sync(&self, label: &str) -> Result<()> {
        self.file
            .sync_all()
            .with_context(|| format!("syncing {label} directory {}", self.path.display()))
    }
}

fn directory_open_flags() -> OFlag {
    OFlag::O_CLOEXEC | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_RDONLY
}

#[cfg(not(target_os = "macos"))]
fn trusted_absolute_path(path: &Path) -> PathBuf {
    path.to_path_buf()
}

#[cfg(target_os = "macos")]
fn trusted_absolute_path(path: &Path) -> PathBuf {
    // Darwin exposes these fixed root-owned compatibility aliases on every
    // supported host. Resolve only this closed set lexically before the
    // descriptor/no-follow walk; arbitrary intermediate symlinks remain
    // rejected.
    let mut components = path.components();
    if components.next() != Some(Component::RootDir) {
        return path.to_path_buf();
    }
    let Some(Component::Normal(first)) = components.next() else {
        return path.to_path_buf();
    };
    let replacement = match first.to_str() {
        Some("tmp") => Some(PathBuf::from("/private/tmp")),
        Some("var") => Some(PathBuf::from("/private/var")),
        Some("etc") => Some(PathBuf::from("/private/etc")),
        _ => None,
    };
    let Some(mut resolved) = replacement else {
        return path.to_path_buf();
    };
    for component in components {
        resolved.push(component.as_os_str());
    }
    resolved
}

fn directory_identity(file: &File, path: &Path, label: &str) -> Result<DirectoryIdentity> {
    let metadata = file
        .metadata()
        .with_context(|| format!("inspecting {label} directory {}", path.display()))?;
    if !metadata.is_dir() {
        bail!("{label} directory {} is not a directory", path.display());
    }
    Ok(DirectoryIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
        uid: metadata.uid(),
        mode: metadata.mode() & 0o7777,
    })
}

fn validate_directory_posture(
    identity: DirectoryIdentity,
    path: &Path,
    label: &str,
    posture: DirectoryPosture,
) -> Result<()> {
    let uid = nix::unistd::geteuid().as_raw();
    let expected_uid = match posture {
        DirectoryPosture::OwnerNoGroupWorldWrite | DirectoryPosture::OwnerOnly => uid,
        DirectoryPosture::RootNoGroupWorldWrite | DirectoryPosture::RootStickyTemporary => 0,
    };
    let mode_ok = match posture {
        DirectoryPosture::OwnerNoGroupWorldWrite | DirectoryPosture::RootNoGroupWorldWrite => {
            identity.mode & 0o022 == 0
        }
        DirectoryPosture::OwnerOnly => identity.mode == 0o700,
        DirectoryPosture::RootStickyTemporary => {
            identity.mode == 0o1777 && is_trusted_root_sticky_temporary(path)
        }
    };
    if identity.uid != expected_uid || !mode_ok {
        bail!(
            "{label} directory {} has uid {} mode {:o}; expected uid {} with {}; {}",
            path.display(),
            identity.uid,
            identity.mode,
            expected_uid,
            match posture {
                DirectoryPosture::OwnerNoGroupWorldWrite => "not group/world writable",
                DirectoryPosture::OwnerOnly => "mode 0700",
                DirectoryPosture::RootNoGroupWorldWrite => {
                    "root-owned and not group/world writable"
                }
                DirectoryPosture::RootStickyTemporary => {
                    "a recognized root-owned mode 01777 sticky temporary anchor"
                }
            },
            posture_remedy(identity, path, posture, uid)
        );
    }
    Ok(())
}

/// What a refused directory tells its reader: for a directory the effective
/// user owns, `fix: ` and the one `chmod` that brings it to `posture`; for one
/// another account owns, `refused: ` and why. kata never proposes taking a
/// directory over, so no remedy names `chown`.
fn posture_remedy(
    identity: DirectoryIdentity,
    path: &Path,
    posture: DirectoryPosture,
    euid: u32,
) -> String {
    match posture {
        DirectoryPosture::OwnerNoGroupWorldWrite | DirectoryPosture::OwnerOnly
            if identity.uid != euid =>
        {
            foreign_owner_refusal(identity.uid, euid)
        }
        DirectoryPosture::OwnerNoGroupWorldWrite => chmod_fix("go-w", path),
        DirectoryPosture::OwnerOnly => chmod_fix(owner_only_mode_argument(identity.mode), path),
        DirectoryPosture::RootNoGroupWorldWrite | DirectoryPosture::RootStickyTemporary => {
            "refused: kata publishes beneath a directory root owns only while no other account can write it, and never changes one".to_owned()
        }
    }
}

/// Why kata refuses a directory another account owns.
pub(crate) fn foreign_owner_refusal(owner: u32, euid: u32) -> String {
    format!(
        "refused: uid {owner} owns it, not you (uid {euid}); kata writes only into directories you own, because a directory's owner can replace what is written in it"
    )
}

/// Why kata refuses an ancestor that is neither the effective user's nor a
/// root-owned directory it can trust.
fn untrusted_ancestor_refusal(identity: DirectoryIdentity) -> String {
    if identity.uid == 0 {
        "refused: it is root's but others can write it, and it is not /tmp or /var/tmp; another account could replace the path beneath it, so kata will not publish under it".to_owned()
    } else {
        format!(
            "refused: uid {} owns it, neither you nor root; its owner could replace the path beneath it, so kata will not publish under it",
            identity.uid
        )
    }
}

/// The `chmod` mode that makes a directory exactly 0700 from `mode`. GNU
/// `chmod` keeps a directory's set-user-ID and set-group-ID bits under a plain
/// numeric mode (it clears the sticky bit); a leading `00` clears them too.
pub(crate) fn owner_only_mode_argument(mode: u32) -> &'static str {
    if mode & 0o6000 == 0 { "700" } else { "00700" }
}

/// `fix: chmod <mode> <path>`, the path one POSIX shell word, so the printed
/// command is the one to run. A path that is not UTF-8 cannot be printed
/// exactly, so it gets the instruction without a command.
pub(crate) fn chmod_fix(mode: &str, path: &Path) -> String {
    match path.to_str().map(shlex::try_quote) {
        Some(Ok(word)) => format!("fix: chmod {mode} {word}"),
        _ => format!(
            "fix by hand: chmod {mode} on this directory (its path is not UTF-8, so no command is printed)"
        ),
    }
}

fn is_trusted_root_sticky_temporary(path: &Path) -> bool {
    matches!(
        path.to_str(),
        Some("/tmp" | "/var/tmp" | "/private/tmp" | "/private/var/tmp")
    )
}

fn publication_identity(metadata: &std::fs::Metadata) -> PublicationFileIdentity {
    PublicationFileIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
        bytes: metadata.len(),
        modified_seconds: metadata.mtime(),
        modified_nanoseconds: metadata.mtime_nsec(),
        changed_seconds: metadata.ctime(),
        changed_nanoseconds: metadata.ctime_nsec(),
        uid: metadata.uid(),
        mode: metadata.mode() & 0o7777,
        links: metadata.nlink(),
    }
}

fn same_inode_and_posture(left: PublicationFileIdentity, right: PublicationFileIdentity) -> bool {
    left.device == right.device
        && left.inode == right.inode
        && left.bytes == right.bytes
        && left.uid == right.uid
        && left.mode == right.mode
        && left.links == right.links
}

fn same_unlinked_inode_and_posture(
    left: PublicationFileIdentity,
    right: PublicationFileIdentity,
) -> bool {
    left.device == right.device
        && left.inode == right.inode
        && left.bytes == right.bytes
        && left.uid == right.uid
        && left.mode == right.mode
}

fn validate_open_owner_only(
    file: &File,
    path: &Path,
    max_bytes: u64,
    label: &str,
    minimum_links: u64,
    maximum_links: u64,
) -> Result<PublicationFileIdentity> {
    let metadata = file
        .metadata()
        .with_context(|| format!("inspecting open {label} {}", path.display()))?;
    let identity = publication_identity(&metadata);
    let uid = nix::unistd::geteuid().as_raw();
    if !metadata.is_file()
        || identity.uid != uid
        || identity.mode != 0o600
        || !(minimum_links..=maximum_links).contains(&identity.links)
        || identity.bytes > max_bytes
    {
        bail!(
            "open {label} {} is not an exact owner-only bounded regular file publication (uid={} mode {:o} links={} bytes={}, expected uid={} mode 600 links={minimum_links}..={maximum_links} bytes<={max_bytes})",
            path.display(),
            identity.uid,
            identity.mode,
            identity.links,
            identity.bytes,
            uid
        );
    }
    Ok(identity)
}

#[allow(unsafe_code)]
fn open_leaf(
    directory: &AuthorityDirectory,
    name: &OsStr,
    max_bytes: u64,
    label: &str,
    minimum_links: u64,
    maximum_links: u64,
) -> Result<File> {
    let descriptor = openat(
        Some(directory.file.as_raw_fd()),
        name,
        OFlag::O_CLOEXEC | OFlag::O_NOFOLLOW | OFlag::O_NONBLOCK | OFlag::O_RDONLY,
        Mode::empty(),
    )
    .with_context(|| format!("opening {label} {}", directory.path.join(name).display()))?;
    // SAFETY: successful `openat` returns a newly owned descriptor.
    let file = unsafe { File::from_raw_fd(descriptor) };
    validate_open_owner_only(
        &file,
        &directory.path.join(name),
        max_bytes,
        label,
        minimum_links,
        maximum_links,
    )?;
    Ok(file)
}

fn bounded_snapshot(
    file: &File,
    path: &Path,
    max_bytes: u64,
    label: &str,
    minimum_links: u64,
    maximum_links: u64,
) -> Result<(PublicationFileIdentity, Arc<[u8]>)> {
    let before =
        validate_open_owner_only(file, path, max_bytes, label, minimum_links, maximum_links)?;
    let mut bytes = Vec::new();
    let mut buffer = vec![0_u8; 64 * 1024];
    let mut offset = 0_u64;
    loop {
        let remaining = max_bytes
            .saturating_add(1)
            .saturating_sub(offset)
            .min(u64::try_from(buffer.len()).expect("buffer length fits in u64"));
        if remaining == 0 {
            bail!(
                "open {label} {} grew beyond the {max_bytes}-byte safety bound while being read",
                path.display()
            );
        }
        let remaining = usize::try_from(remaining)
            .expect("remaining byte count is bounded by the in-memory buffer");
        let read = file
            .read_at(&mut buffer[..remaining], offset)
            .with_context(|| format!("reading open {label} {}", path.display()))?;
        if read == 0 {
            break;
        }
        bytes.extend_from_slice(&buffer[..read]);
        offset = offset
            .checked_add(read as u64)
            .context("publication snapshot offset overflow")?;
        if offset > max_bytes {
            bail!(
                "open {label} {} grew beyond the {max_bytes}-byte safety bound while being read",
                path.display()
            );
        }
    }
    let after =
        validate_open_owner_only(file, path, max_bytes, label, minimum_links, maximum_links)?;
    if before != after || after.bytes != bytes.len() as u64 {
        bail!("open {label} {} changed while being read", path.display());
    }
    Ok((after, Arc::from(bytes)))
}

#[derive(Debug)]
struct ExistingOwnerOnlyPublicationInner {
    path: PathBuf,
    name: OsString,
    directory: Arc<AuthorityDirectory>,
    file: File,
    identity: PublicationFileIdentity,
    bytes: Arc<[u8]>,
    digest: blake3::Hash,
    max_bytes: u64,
    minimum_links: u64,
    maximum_links: u64,
    label: String,
}

#[derive(Clone, Debug)]
pub(crate) struct ExistingOwnerOnlyPublication(Arc<ExistingOwnerOnlyPublicationInner>);

impl PartialEq for ExistingOwnerOnlyPublication {
    fn eq(&self, other: &Self) -> bool {
        self.0.path == other.0.path
            && self.0.identity == other.0.identity
            && self.0.digest == other.0.digest
            && self.0.bytes == other.0.bytes
    }
}

impl Eq for ExistingOwnerOnlyPublication {}

impl ExistingOwnerOnlyPublication {
    pub(crate) fn open(path: &Path, max_bytes: u64, label: &str) -> Result<Self> {
        let parent = path
            .parent()
            .ok_or_else(|| anyhow::anyhow!("{label} has no parent: {}", path.display()))?;
        let directory = Arc::new(AuthorityDirectory::bind_existing(parent, label)?);
        let name = publication_name(path, label)?;
        Self::open_in(directory, name, max_bytes, label)
    }

    pub(crate) fn open_in_owner_only_directory(
        path: &Path,
        max_bytes: u64,
        label: &str,
    ) -> Result<Self> {
        let parent = path
            .parent()
            .ok_or_else(|| anyhow::anyhow!("{label} has no parent: {}", path.display()))?;
        let directory = Arc::new(AuthorityDirectory::bind_existing_owner_only(parent, label)?);
        let name = publication_name(path, label)?;
        Self::open_in(directory, name, max_bytes, label)
    }

    fn open_in(
        directory: Arc<AuthorityDirectory>,
        name: OsString,
        max_bytes: u64,
        label: &str,
    ) -> Result<Self> {
        Self::open_in_with_links(directory, name, max_bytes, label, 1, 1)
    }

    fn open_in_with_links(
        directory: Arc<AuthorityDirectory>,
        name: OsString,
        max_bytes: u64,
        label: &str,
        minimum_links: u64,
        maximum_links: u64,
    ) -> Result<Self> {
        directory.revalidate()?;
        let path = directory.path.join(&name);
        let file = open_leaf(
            &directory,
            &name,
            max_bytes,
            label,
            minimum_links,
            maximum_links,
        )?;
        let (identity, bytes) =
            bounded_snapshot(&file, &path, max_bytes, label, minimum_links, maximum_links)?;
        let digest = blake3::hash(&bytes);
        let publication = Self(Arc::new(ExistingOwnerOnlyPublicationInner {
            path,
            name,
            directory,
            file,
            identity,
            bytes,
            digest,
            max_bytes,
            minimum_links,
            maximum_links,
            label: label.to_string(),
        }));
        publication.require_current()?;
        Ok(publication)
    }

    pub(crate) fn identity(&self) -> PublicationFileIdentity {
        self.0.identity
    }

    pub(crate) fn read_utf8(&self, max_bytes: u64, label: &str) -> Result<String> {
        if max_bytes < self.0.max_bytes && self.0.identity.bytes > max_bytes {
            bail!(
                "{label} {} exceeds the {max_bytes}-byte safety bound",
                self.0.path.display()
            );
        }
        self.require_current()?;
        String::from_utf8(self.0.bytes.to_vec())
            .with_context(|| format!("{label} {} is not valid UTF-8", self.0.path.display()))
    }

    pub(crate) fn bytes(&self) -> Result<&[u8]> {
        self.require_current()?;
        Ok(&self.0.bytes)
    }

    pub(crate) fn sync_and_revalidate(&self) -> Result<()> {
        self.require_current()?;
        self.0.file.sync_all().with_context(|| {
            format!(
                "syncing existing {} {}",
                self.0.label,
                self.0.path.display()
            )
        })?;
        sync_published_destination_parent(&self.0.directory, &self.0.label)?;
        self.require_current()
    }

    fn require_current(&self) -> Result<()> {
        self.0.directory.revalidate()?;
        let file = open_leaf(
            &self.0.directory,
            &self.0.name,
            self.0.max_bytes,
            &self.0.label,
            self.0.minimum_links,
            self.0.maximum_links,
        )?;
        let (identity, bytes) = bounded_snapshot(
            &file,
            &self.0.path,
            self.0.max_bytes,
            &self.0.label,
            self.0.minimum_links,
            self.0.maximum_links,
        )?;
        let held = bounded_snapshot(
            &self.0.file,
            &self.0.path,
            self.0.max_bytes,
            &self.0.label,
            0,
            self.0.maximum_links,
        )?;
        if identity != self.0.identity
            || held.0.device != self.0.identity.device
            || held.0.inode != self.0.identity.inode
            || bytes != self.0.bytes
            || held.1 != self.0.bytes
        {
            bail!(
                "{} {} changed after descriptor adoption",
                self.0.label,
                self.0.path.display()
            );
        }
        Ok(())
    }

    pub(crate) fn remove(
        &self,
        _max_bytes: u64,
        artifact_prefix: &str,
        label: &str,
    ) -> Result<OwnerOnlyRemoval> {
        self.require_current()?;
        let commit = retire_canonical(self, artifact_prefix, label)?;
        if matches!(
            &commit,
            OwnerOnlyRemoval::Removed(RemovalCommit {
                cleanup: CleanupDisposition::Pending
            })
        ) {
            tracing::warn!(path = %self.0.path.display(), "canonical publication absence committed; retired artifact cleanup remains pending");
        }
        Ok(commit)
    }

    /// Restore this exact adopted artifact to an absent sibling name.
    pub(crate) fn restore_to(
        &self,
        destination: &Path,
        label: &str,
    ) -> Result<OwnerOnlyRestoration> {
        let destination = trusted_absolute_path(destination);
        if destination.parent() != Some(self.0.directory.path.as_path()) {
            bail!("{label} restore destination is not in the retained directory");
        }
        self.require_current()?;
        self.0.directory.revalidate()?;
        let destination_name = publication_name(&destination, label)?;
        rename_noreplace_at(&self.0.directory.file, &self.0.name, &destination_name)
            .with_context(|| format!("restoring {label} to {}", destination.display()))?;
        if let Err(source) = self.0.directory.sync(label) {
            return Ok(OwnerOnlyRestoration::RecoveryRequired(post_commit_error(
                PublicationPostCommitState::CanonicalPresent,
                &destination,
                source,
            )));
        }
        if let Err(source) = self.0.directory.revalidate() {
            return Ok(OwnerOnlyRestoration::RecoveryRequired(post_commit_error(
                PublicationPostCommitState::CanonicalPresent,
                &destination,
                source,
            )));
        }
        let restored = match Self::open_in(
            Arc::clone(&self.0.directory),
            destination_name,
            self.0.max_bytes,
            label,
        ) {
            Ok(restored) => restored,
            Err(source) => {
                return Ok(OwnerOnlyRestoration::RecoveryRequired(post_commit_error(
                    PublicationPostCommitState::CanonicalPresent,
                    &destination,
                    source,
                )));
            }
        };
        if !same_inode_and_posture(restored.0.identity, self.0.identity)
            || restored.0.bytes != self.0.bytes
        {
            return Ok(OwnerOnlyRestoration::RecoveryRequired(post_commit_error(
                PublicationPostCommitState::CanonicalPresent,
                &destination,
                anyhow::anyhow!("{label} restore committed but exact content could not be rebound"),
            )));
        }
        Ok(OwnerOnlyRestoration::Restored)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CleanupDisposition {
    Complete,
    Pending,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct RemovalCommit {
    pub(crate) cleanup: CleanupDisposition,
}

#[derive(Debug)]
pub(crate) enum OwnerOnlyRemoval {
    Removed(RemovalCommit),
    RecoveryRequired(PublicationRecoveryRequired),
}

#[derive(Debug)]
pub(crate) enum OwnerOnlyRestoration {
    Restored,
    RecoveryRequired(PublicationRecoveryRequired),
}

fn retired_name(prefix: &str, identity: PublicationFileIdentity) -> OsString {
    OsString::from(format!(
        "{prefix}delete-{}-{}-{}.quarantine",
        identity.device,
        identity.inode,
        ulid::Ulid::new()
    ))
}

fn quarantine_identity(prefix: &str, name: &str) -> Option<(u64, u64)> {
    let body = name
        .strip_prefix(prefix)?
        .strip_prefix("delete-")?
        .strip_suffix(".quarantine")?;
    let mut parts = body.splitn(3, '-');
    let device = parts.next()?.parse().ok()?;
    let inode = parts.next()?.parse().ok()?;
    let nonce = parts.next()?;
    (!nonce.is_empty()).then_some((device, inode))
}

fn retire_canonical(
    publication: &ExistingOwnerOnlyPublication,
    artifact_prefix: &str,
    label: &str,
) -> Result<OwnerOnlyRemoval> {
    publication.require_current()?;
    let directory = &publication.0.directory;
    let retired = retired_name(artifact_prefix, publication.0.identity);
    run_pre_publication_removal_rename_test_hook();
    rename_noreplace_at(&directory.file, &publication.0.name, &retired)
        .with_context(|| format!("retiring {label} {}", publication.0.path.display()))?;
    run_post_publication_quarantine_test_hook();
    let moved = match ExistingOwnerOnlyPublication::open_in(
        Arc::clone(directory),
        retired.clone(),
        publication.0.max_bytes,
        label,
    ) {
        Ok(moved) => moved,
        Err(source) => {
            return Ok(OwnerOnlyRemoval::RecoveryRequired(post_commit_error(
                PublicationPostCommitState::CanonicalRetired,
                &publication.0.path,
                source.context("adopting retired publication before absence commit"),
            )));
        }
    };
    if !same_inode_and_posture(moved.0.identity, publication.0.identity)
        || moved.0.bytes != publication.0.bytes
    {
        return Ok(OwnerOnlyRemoval::RecoveryRequired(post_commit_error(
            PublicationPostCommitState::CanonicalRetired,
            &publication.0.path,
            anyhow::anyhow!(
                "{label} retired artifact differs from the adopted canonical publication; preserved it for recovery"
            ),
        )));
    }
    if let Err(source) = sync_removed_publication_parent(directory, label) {
        return Ok(OwnerOnlyRemoval::RecoveryRequired(post_commit_error(
            PublicationPostCommitState::CanonicalRetired,
            &publication.0.path,
            source,
        )));
    }
    if let Err(source) = directory.revalidate() {
        return Ok(OwnerOnlyRemoval::RecoveryRequired(post_commit_error(
            PublicationPostCommitState::CanonicalRetired,
            &publication.0.path,
            source,
        )));
    }
    let cleanup = match cleanup_artifact(&moved, label) {
        Ok(()) => CleanupDisposition::Complete,
        Err(error) => {
            tracing::warn!(error = %format!("{error:#}"), "retired publication cleanup deferred after committed absence");
            CleanupDisposition::Pending
        }
    };
    Ok(OwnerOnlyRemoval::Removed(RemovalCommit { cleanup }))
}

fn cleanup_artifact(publication: &ExistingOwnerOnlyPublication, label: &str) -> Result<()> {
    publication.require_current()?;
    unlinkat(
        Some(publication.0.directory.file.as_raw_fd()),
        publication.0.name.as_os_str(),
        UnlinkatFlags::NoRemoveDir,
    )
    .with_context(|| format!("cleaning retired {label} {}", publication.0.path.display()))?;
    publication.0.directory.sync(label)
}

#[derive(Debug)]
pub(crate) struct OwnerOnlyPublicationTemp {
    path: PathBuf,
    directory: Arc<AuthorityDirectory>,
    name: OsString,
    identity: PublicationFileIdentity,
    bytes: Arc<[u8]>,
    file: Option<File>,
    max_bytes: u64,
    artifact_prefix: String,
    label: String,
    active: bool,
}

#[derive(Debug)]
pub(crate) enum OwnerOnlyNoReplacePublication {
    Published(OwnerOnlyPublishedDestination),
    RecoveryRequired {
        publication: OwnerOnlyPublishedDestination,
        error: PublicationRecoveryRequired,
    },
    RenamedRecoveryRequired(PublicationRecoveryRequired),
    DestinationExists,
}

#[derive(Debug)]
pub(crate) enum OwnerOnlyReplacementPublication {
    Published {
        rollback_cleanup: CleanupDisposition,
    },
    RecoveryRequired(PublicationRecoveryRequired),
}

#[derive(Debug)]
pub(crate) struct OwnerOnlyPublishedDestination {
    publication: ExistingOwnerOnlyPublication,
    artifact_prefix: String,
}

impl OwnerOnlyPublishedDestination {
    pub(crate) fn path(&self) -> &Path {
        &self.publication.0.path
    }

    pub(crate) fn identity(&self) -> PublicationFileIdentity {
        self.publication.identity()
    }

    #[cfg(test)]
    pub(crate) fn open_identity_for_test(&self) -> PublicationFileIdentity {
        publication_identity(
            &self
                .publication
                .0
                .file
                .metadata()
                .expect("published file metadata"),
        )
    }

    #[cfg(test)]
    pub(crate) fn adopt_for_test(
        path: PathBuf,
        identity: PublicationFileIdentity,
        max_bytes: u64,
        artifact_prefix: &str,
        label: &str,
    ) -> Self {
        let publication = ExistingOwnerOnlyPublication::open(&path, max_bytes, label)
            .expect("adopt test publication");
        assert_eq!(publication.identity(), identity);
        Self {
            publication,
            artifact_prefix: artifact_prefix.to_string(),
        }
    }

    pub(crate) fn withdraw(self) -> Result<()> {
        match self.publication.remove(
            self.publication.0.max_bytes,
            &self.artifact_prefix,
            &self.publication.0.label,
        )? {
            OwnerOnlyRemoval::Removed(_) => Ok(()),
            OwnerOnlyRemoval::RecoveryRequired(error) => Err(error.into()),
        }
    }
}

// Deliberately no semantic Drop cleanup. A recognizable publication or
// transaction artifact is safer than an unreported namespace mutation.

impl OwnerOnlyPublicationTemp {
    #[allow(unsafe_code)]
    pub(crate) fn create(
        parent: &Path,
        artifact_prefix: &str,
        max_bytes: u64,
        label: &str,
    ) -> Result<Self> {
        let directory = Arc::new(AuthorityDirectory::bind_existing(parent, label)?);
        let name = OsString::from(format!("{artifact_prefix}write-{}.tmp", ulid::Ulid::new()));
        let path = directory.path.join(&name);
        let descriptor = openat(
            Some(directory.file.as_raw_fd()),
            name.as_os_str(),
            OFlag::O_CLOEXEC | OFlag::O_NOFOLLOW | OFlag::O_CREAT | OFlag::O_EXCL | OFlag::O_RDWR,
            Mode::from_bits_truncate(0o600),
        )
        .with_context(|| format!("creating temporary {label} {}", path.display()))?;
        // SAFETY: successful `openat` returns a newly owned descriptor.
        let file = unsafe { File::from_raw_fd(descriptor) };
        normalize_new_owner_only_file(&file, &path, "publication temporary")?;
        let identity = validate_open_owner_only(&file, &path, max_bytes, label, 1, 1)?;
        Ok(Self {
            path,
            directory,
            name,
            identity,
            bytes: Arc::from([]),
            file: Some(file),
            max_bytes,
            artifact_prefix: artifact_prefix.to_string(),
            label: label.to_string(),
            active: true,
        })
    }

    pub(crate) fn file_mut(&mut self) -> &mut File {
        self.file.as_mut().expect("publication temporary is open")
    }

    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    pub(crate) fn retain_for_recovery(&mut self) {
        self.active = false;
        self.file.take();
    }

    pub(crate) fn sync_contents(&mut self) -> Result<()> {
        self.file_mut()
            .sync_all()
            .with_context(|| format!("syncing temporary {} {}", self.label, self.path.display()))?;
        let file = self.file.as_ref().expect("publication temporary is open");
        let (identity, bytes) =
            bounded_snapshot(file, &self.path, self.max_bytes, &self.label, 1, 1)?;
        self.identity = identity;
        self.bytes = bytes;
        Ok(())
    }

    pub(crate) fn cleanup(&mut self) -> Result<()> {
        if !self.active {
            return Ok(());
        }
        let file = self.file.as_ref().expect("active temporary has descriptor");
        let (identity, bytes) =
            bounded_snapshot(file, &self.path, self.max_bytes, &self.label, 0, 1)?;
        if identity.links == 0 {
            if !same_unlinked_inode_and_posture(identity, self.identity) || bytes != self.bytes {
                bail!(
                    "unlinked temporary {} changed before cleanup convergence",
                    self.path.display()
                );
            }
            self.directory.file.sync_all().with_context(|| {
                format!(
                    "syncing retained temporary {} directory {} after exact artifact absence",
                    self.label,
                    self.directory.path.display()
                )
            })?;
            self.active = false;
            self.file.take();
            return Ok(());
        }
        if identity != self.identity || bytes != self.bytes {
            bail!("temporary {} changed before cleanup", self.path.display());
        }

        // Temporary cleanup is non-authoritative garbage collection. Bind the
        // exact name through the retained directory descriptor even when the
        // canonical root-to-leaf path has been replaced; authority commits
        // still require full chain revalidation.
        let rebound = open_leaf(
            &self.directory,
            &self.name,
            self.max_bytes,
            &self.label,
            1,
            1,
        )?;
        let (rebound_identity, rebound_bytes) =
            bounded_snapshot(&rebound, &self.path, self.max_bytes, &self.label, 1, 1)?;
        if rebound_identity != self.identity || rebound_bytes != self.bytes {
            bail!(
                "temporary {} no longer names the exact retained artifact; preserving it",
                self.path.display()
            );
        }
        unlinkat(
            Some(self.directory.file.as_raw_fd()),
            self.name.as_os_str(),
            UnlinkatFlags::NoRemoveDir,
        )
        .with_context(|| format!("cleaning temporary {} {}", self.label, self.path.display()))?;
        self.directory.file.sync_all().with_context(|| {
            format!(
                "syncing retained temporary {} directory {}",
                self.label,
                self.directory.path.display()
            )
        })?;
        self.active = false;
        self.file.take();
        Ok(())
    }
    pub(crate) fn publish_noreplace(
        &mut self,
        destination: &Path,
    ) -> Result<OwnerOnlyNoReplacePublication> {
        let destination = trusted_absolute_path(destination);
        self.require_sibling(&destination)?;
        self.directory.revalidate()?;
        let destination_name = publication_name(&destination, &self.label)?;
        run_pre_no_replace_rename_test_hook();
        if let Err(error) = rename_noreplace_at(&self.directory.file, &self.name, &destination_name)
        {
            if no_replace_destination_exists(&error) {
                return Ok(OwnerOnlyNoReplacePublication::DestinationExists);
            }
            return Err(error)
                .with_context(|| format!("publishing {} {}", self.label, destination.display()));
        }

        // From here onward the namespace has changed. Track the committed name
        // in the retained temporary guard and classify every fallible path as
        // explicit recovery rather than returning an ordinary error.
        self.name.clone_from(&destination_name);
        self.path.clone_from(&destination);
        let held = match bounded_snapshot(
            self.file
                .as_ref()
                .expect("renamed temporary descriptor remains open"),
            &destination,
            self.max_bytes,
            &self.label,
            1,
            1,
        ) {
            Ok(held) => held,
            Err(source) => {
                return Ok(OwnerOnlyNoReplacePublication::RenamedRecoveryRequired(
                    post_commit_error(
                        PublicationPostCommitState::CanonicalPresent,
                        &destination,
                        source,
                    ),
                ));
            }
        };
        if !same_inode_and_posture(held.0, self.identity) || held.1 != self.bytes {
            return Ok(OwnerOnlyNoReplacePublication::RenamedRecoveryRequired(
                post_commit_error(
                    PublicationPostCommitState::CanonicalPresent,
                    &destination,
                    anyhow::anyhow!(
                        "publication rename committed but retained staged inode or bytes changed"
                    ),
                ),
            ));
        }
        self.identity = held.0;

        let publication = match ExistingOwnerOnlyPublication::open_in(
            Arc::clone(&self.directory),
            destination_name,
            self.max_bytes,
            &self.label,
        ) {
            Ok(publication) => publication,
            Err(source) => {
                return Ok(OwnerOnlyNoReplacePublication::RenamedRecoveryRequired(
                    post_commit_error(
                        PublicationPostCommitState::CanonicalPresent,
                        &destination,
                        source.context(
                            "publication rename committed but exact destination adoption failed",
                        ),
                    ),
                ));
            }
        };
        if !same_inode_and_posture(publication.identity(), self.identity)
            || publication.0.bytes != self.bytes
        {
            return Ok(OwnerOnlyNoReplacePublication::RecoveryRequired {
                publication: OwnerOnlyPublishedDestination {
                    publication,
                    artifact_prefix: self.artifact_prefix.clone(),
                },
                error: post_commit_error(
                    PublicationPostCommitState::CanonicalPresent,
                    &destination,
                    anyhow::anyhow!(
                        "publication rename committed but destination content identity changed"
                    ),
                ),
            });
        }

        // Rename legitimately advances ctime. Adopt the post-rename metadata
        // only after the retained descriptor, rebound name, and immutable bytes
        // prove that this is still the staged inode and content.
        self.identity = publication.identity();
        let published = OwnerOnlyPublishedDestination {
            publication,
            artifact_prefix: self.artifact_prefix.clone(),
        };
        if let Err(source) = sync_published_destination_parent(&self.directory, &self.label) {
            return Ok(OwnerOnlyNoReplacePublication::RecoveryRequired {
                publication: published,
                error: post_commit_error(
                    PublicationPostCommitState::CanonicalPresent,
                    &destination,
                    source,
                ),
            });
        }
        if let Err(source) = self.directory.revalidate() {
            return Ok(OwnerOnlyNoReplacePublication::RecoveryRequired {
                publication: published,
                error: post_commit_error(
                    PublicationPostCommitState::CanonicalPresent,
                    &destination,
                    source,
                ),
            });
        }
        self.retain_for_recovery();
        Ok(OwnerOnlyNoReplacePublication::Published(published))
    }
    pub(crate) fn publish_replace(
        &mut self,
        destination: &Path,
        expected: &ExistingOwnerOnlyPublication,
    ) -> Result<OwnerOnlyReplacementPublication> {
        let destination = trusted_absolute_path(destination);
        self.require_sibling(&destination)?;
        if expected.0.path != destination
            || expected.0.directory.path != self.directory.path
            || expected.0.directory.file.metadata()?.dev() != self.directory.file.metadata()?.dev()
            || expected.0.directory.file.metadata()?.ino() != self.directory.file.metadata()?.ino()
        {
            bail!(
                "{} replacement authority is not bound to destination {}",
                self.label,
                destination.display()
            );
        }
        expected.require_current()?;
        self.directory.revalidate()?;
        let destination_name = publication_name(&destination, &self.label)?;
        let rollback_name = OsString::from(format!(
            "{}replace-{}-{}-{}.rollback",
            self.artifact_prefix,
            expected.0.identity.device,
            expected.0.identity.inode,
            ulid::Ulid::new()
        ));
        rename_noreplace_at(&self.directory.file, &destination_name, &rollback_name)
            .context("moving prior publication to replacement rollback")?;

        let prior_recovery = |source: anyhow::Error| {
            OwnerOnlyReplacementPublication::RecoveryRequired(post_commit_error(
                PublicationPostCommitState::PriorCanonicalRetired,
                &destination,
                source,
            ))
        };
        let rollback = match ExistingOwnerOnlyPublication::open_in(
            Arc::clone(&self.directory),
            rollback_name.clone(),
            self.max_bytes,
            &self.label,
        ) {
            Ok(rollback) => rollback,
            Err(source) => {
                return Ok(prior_recovery(source.context(
                    "prior canonical was renamed to rollback but exact adoption failed",
                )));
            }
        };
        if !same_inode_and_posture(rollback.0.identity, expected.0.identity)
            || rollback.0.bytes != expected.0.bytes
        {
            return Ok(prior_recovery(anyhow::anyhow!(
                "replacement rollback differs from the adopted prior publication; preserving it"
            )));
        }
        if let Err(source) = self.directory.sync(&format!("{} rollback", self.label)) {
            return Ok(prior_recovery(source));
        }
        if let Err(source) = self.directory.revalidate() {
            return Ok(prior_recovery(source));
        }

        if let Err(publish_error) =
            rename_noreplace_at(&self.directory.file, &self.name, &destination_name)
        {
            if let Err(source) = rollback.require_current() {
                return Ok(prior_recovery(source));
            }
            if let Err(source) = self.directory.revalidate() {
                return Ok(prior_recovery(source));
            }
            if let Err(source) =
                rename_noreplace_at(&self.directory.file, &rollback_name, &destination_name)
            {
                return Ok(prior_recovery(source.context(
                    "replacement failed and exact prior publication could not be restored",
                )));
            }
            if let Err(source) = self
                .directory
                .sync(&format!("{} rollback restore", self.label))
            {
                return Ok(OwnerOnlyReplacementPublication::RecoveryRequired(
                    post_commit_error(
                        PublicationPostCommitState::PriorCanonicalRestored,
                        &destination,
                        source,
                    ),
                ));
            }
            let restored = match ExistingOwnerOnlyPublication::open_in(
                Arc::clone(&self.directory),
                destination_name,
                self.max_bytes,
                &self.label,
            ) {
                Ok(restored) => restored,
                Err(source) => {
                    return Ok(OwnerOnlyReplacementPublication::RecoveryRequired(
                        post_commit_error(
                            PublicationPostCommitState::PriorCanonicalRestored,
                            &destination,
                            source,
                        ),
                    ));
                }
            };
            if !same_inode_and_posture(restored.0.identity, expected.0.identity)
                || restored.0.bytes != expected.0.bytes
            {
                return Ok(OwnerOnlyReplacementPublication::RecoveryRequired(
                    post_commit_error(
                        PublicationPostCommitState::PriorCanonicalRestored,
                        &destination,
                        anyhow::anyhow!(
                            "replacement failed and restored publication content is not exact"
                        ),
                    ),
                ));
            }
            return Err(publish_error)
                .context("publishing replacement; exact prior publication restored");
        }

        run_post_replacement_rename_test_hook();
        self.name.clone_from(&destination_name);
        self.path.clone_from(&destination);
        let held = match bounded_snapshot(
            self.file
                .as_ref()
                .expect("replacement descriptor remains open"),
            &destination,
            self.max_bytes,
            &self.label,
            1,
            1,
        ) {
            Ok(held) => held,
            Err(source) => {
                return Ok(OwnerOnlyReplacementPublication::RecoveryRequired(
                    post_commit_error(
                        PublicationPostCommitState::ReplacementPresentWithRollback,
                        &destination,
                        source,
                    ),
                ));
            }
        };
        if !same_inode_and_posture(held.0, self.identity) || held.1 != self.bytes {
            return Ok(OwnerOnlyReplacementPublication::RecoveryRequired(
                post_commit_error(
                    PublicationPostCommitState::ReplacementPresentWithRollback,
                    &destination,
                    anyhow::anyhow!(
                        "replacement committed but retained staged inode or bytes changed"
                    ),
                ),
            ));
        }
        self.identity = held.0;
        self.active = false;
        self.file.take();

        let current = match ExistingOwnerOnlyPublication::open_in(
            Arc::clone(&self.directory),
            destination_name,
            self.max_bytes,
            &self.label,
        ) {
            Ok(current) => current,
            Err(source) => {
                return Ok(OwnerOnlyReplacementPublication::RecoveryRequired(
                    post_commit_error(
                        PublicationPostCommitState::ReplacementPresentWithRollback,
                        &destination,
                        source.context(
                            "replacement committed but canonical directory binding changed; preserving the new publication and prior rollback",
                        ),
                    ),
                ));
            }
        };
        if !same_inode_and_posture(current.identity(), self.identity)
            || current.0.bytes != self.bytes
        {
            return Ok(OwnerOnlyReplacementPublication::RecoveryRequired(
                post_commit_error(
                    PublicationPostCommitState::ReplacementPresentWithRollback,
                    &destination,
                    anyhow::anyhow!(
                        "replacement committed but new canonical publication changed; preserving rollback"
                    ),
                ),
            ));
        }
        self.identity = current.identity();
        if let Err(source) = sync_replacement_destination_parent(&self.directory, &self.label) {
            return Ok(OwnerOnlyReplacementPublication::RecoveryRequired(
                post_commit_error(
                    PublicationPostCommitState::ReplacementPresentWithRollback,
                    &destination,
                    source,
                ),
            ));
        }
        if let Err(source) = self.directory.revalidate() {
            return Ok(OwnerOnlyReplacementPublication::RecoveryRequired(
                post_commit_error(
                    PublicationPostCommitState::ReplacementPresentWithRollback,
                    &destination,
                    source,
                ),
            ));
        }
        let rollback_cleanup = match cleanup_artifact(&rollback, &format!("prior {}", self.label)) {
            Ok(()) => CleanupDisposition::Complete,
            Err(error) => {
                tracing::warn!(error = %format!("{error:#}"), "replacement committed; rollback cleanup deferred");
                CleanupDisposition::Pending
            }
        };
        Ok(OwnerOnlyReplacementPublication::Published { rollback_cleanup })
    }
    fn require_sibling(&self, destination: &Path) -> Result<()> {
        if destination.parent() != Some(self.directory.path.as_path()) {
            bail!("{} temporary and destination are not siblings", self.label);
        }
        Ok(())
    }
}

const MAX_SHARED_PUBLICATION_DIRECTORY_SCAN_ENTRIES: usize = 65_536;

fn list_publication_names_where(
    directory_path: &Path,
    max_entries: usize,
    max_scanned_entries: usize,
    label: &str,
    mut include: impl FnMut(&OsStr) -> bool,
) -> Result<Vec<OsString>> {
    use std::os::unix::ffi::OsStrExt as _;

    let directory = AuthorityDirectory::bind_existing(directory_path, label)?;
    let iteration = directory
        .file
        .try_clone()
        .context("cloning publication directory")?;
    let mut entries =
        nix::dir::Dir::from(iteration).context("opening publication directory stream")?;
    let mut names = Vec::new();
    let mut scanned = 0usize;
    for entry in entries.iter() {
        let entry = entry.context("enumerating publication directory")?;
        let name = OsStr::from_bytes(entry.file_name().to_bytes());
        if name == OsStr::new(".") || name == OsStr::new("..") {
            continue;
        }
        if scanned == max_scanned_entries {
            bail!(
                "{label} directory {} exceeds the {max_scanned_entries}-entry bounded scan ceiling",
                directory_path.display()
            );
        }
        scanned += 1;
        if !include(name) {
            continue;
        }
        if names.len() == max_entries {
            bail!(
                "{label} directory {} exceeds the {max_entries}-matching-entry safety ceiling",
                directory_path.display()
            );
        }
        names.push(name.to_os_string());
    }
    drop(entries);
    directory.revalidate()?;
    Ok(names)
}

pub(crate) fn list_publication_names(
    directory_path: &Path,
    max_entries: usize,
    label: &str,
) -> Result<Vec<OsString>> {
    list_publication_names_where(directory_path, max_entries, max_entries, label, |_| true)
}

pub(crate) fn list_publication_names_with_prefix(
    directory_path: &Path,
    prefix: &str,
    max_matches: usize,
    label: &str,
) -> Result<Vec<OsString>> {
    use std::os::unix::ffi::OsStrExt as _;

    let prefix = prefix.as_bytes();
    list_publication_names_where(
        directory_path,
        max_matches,
        MAX_SHARED_PUBLICATION_DIRECTORY_SCAN_ENTRIES,
        label,
        |name| name.as_bytes().starts_with(prefix),
    )
}

fn open_recovery_artifact(
    directory: &Arc<AuthorityDirectory>,
    name: &OsStr,
    artifact_prefix: &str,
    max_bytes: u64,
    maximum_temporary_links: u64,
    label: &str,
) -> Result<ExistingOwnerOnlyPublication> {
    let text = name
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("interrupted {label} artifact name is not UTF-8"))?;
    let is_temporary = Path::new(text).extension() == Some(OsStr::new("tmp"));
    let publication = ExistingOwnerOnlyPublication::open_in_with_links(
        Arc::clone(directory),
        name.to_os_string(),
        max_bytes,
        label,
        1,
        if is_temporary {
            maximum_temporary_links
        } else {
            1
        },
    )?;
    if Path::new(text).extension() == Some(OsStr::new("quarantine")) {
        let encoded = quarantine_identity(artifact_prefix, text).ok_or_else(|| {
            anyhow::anyhow!("interrupted {label} quarantine has no encoded identity; preserving it")
        })?;
        if encoded != (publication.0.identity.device, publication.0.identity.inode) {
            bail!(
                "interrupted {label} quarantine identity conflicts with its name; preserving the conflict"
            );
        }
    }
    Ok(publication)
}

pub(crate) fn recover_owner_only_publication_artifacts(
    directory_path: &Path,
    artifact_prefix: &str,
    max_bytes: u64,
    max_artifacts: usize,
    label: &str,
) -> Result<()> {
    recover_owner_only_publication_artifacts_with_temporary_links(
        directory_path,
        artifact_prefix,
        max_bytes,
        max_artifacts,
        1,
        label,
    )
}

pub(crate) fn recover_owner_only_publication_artifacts_with_temporary_links(
    directory_path: &Path,
    artifact_prefix: &str,
    max_bytes: u64,
    max_artifacts: usize,
    maximum_temporary_links: u64,
    label: &str,
) -> Result<()> {
    // Hold only names across enumeration. Validate every candidate in a
    // no-mutation pass, then reopen and clean one at a time. This keeps the
    // descriptor budget constant while preserving fail-before-mutation
    // behavior under Kata's cooperative publication lease.
    let directory = Arc::new(AuthorityDirectory::bind_existing(directory_path, label)?);
    let names = list_publication_names_with_prefix(
        directory_path,
        artifact_prefix,
        max_artifacts,
        label,
    )
    .with_context(|| {
        format!(
            "enumerating interrupted {label} artifacts within the {max_artifacts}-artifact recovery ceiling"
        )
    })?
    .into_iter()
    .filter(|name| {
        name.to_str().is_some_and(|text| {
            matches!(
                Path::new(text).extension(),
                Some(extension) if extension == "tmp" || extension == "quarantine"
            )
        })
    })
    .collect::<Vec<_>>();

    for name in &names {
        open_recovery_artifact(
            &directory,
            name,
            artifact_prefix,
            max_bytes,
            maximum_temporary_links,
            label,
        )
        .with_context(|| {
            format!(
                "interrupted {label} artifact {} is not safe to recover; preserving it",
                directory.path.join(name).display()
            )
        })?;
    }
    for name in names {
        let artifact = open_recovery_artifact(
            &directory,
            &name,
            artifact_prefix,
            max_bytes,
            maximum_temporary_links,
            label,
        )?;
        cleanup_artifact(&artifact, label)?;
    }
    Ok(())
}

#[cfg(test)]
pub(crate) fn capture_owner_only_publication_identity(
    path: &Path,
    max_bytes: u64,
    label: &str,
) -> Result<PublicationFileIdentity> {
    ExistingOwnerOnlyPublication::open(path, max_bytes, label).map(|value| value.identity())
}

#[cfg(test)]
pub(crate) fn remove_exact_owner_only_publication(
    path: &Path,
    expected: PublicationFileIdentity,
    max_bytes: u64,
    artifact_prefix: &str,
    label: &str,
) -> Result<()> {
    let publication = ExistingOwnerOnlyPublication::open(path, max_bytes, label)?;
    if publication.identity() != expected {
        bail!(
            "{label} {} changed before deletion; refusing deletion of a replacement",
            path.display()
        );
    }
    match publication.remove(max_bytes, artifact_prefix, label)? {
        OwnerOnlyRemoval::Removed(_) => Ok(()),
        OwnerOnlyRemoval::RecoveryRequired(error) => Err(error.into()),
    }
}

fn publication_name(path: &Path, label: &str) -> Result<OsString> {
    path.file_name()
        .map(OsStr::to_os_string)
        .ok_or_else(|| anyhow::anyhow!("{label} has no file name: {}", path.display()))
}

/// `renameat2(RENAME_NOREPLACE)` through rustix's raw syscall, which every Linux libc
/// target reaches — nix 0.28 offers `renameat2` only on glibc, and the factory smoke's
/// in-capsule `kata` is a static musl build of this tree. Its refusal surfaces as an
/// `io::Error`, which `no_replace_destination_exists` reads by kind.
#[cfg(target_os = "linux")]
fn rename_noreplace_at(parent: &File, source: &OsStr, destination: &OsStr) -> Result<()> {
    rustix::fs::renameat_with(
        parent,
        source,
        parent,
        destination,
        rustix::fs::RenameFlags::NOREPLACE,
    )
    .map_err(std::io::Error::from)?;
    Ok(())
}

#[cfg(target_os = "macos")]
#[allow(unsafe_code)]
fn rename_noreplace_at(parent: &File, source: &OsStr, destination: &OsStr) -> Result<()> {
    use std::os::unix::ffi::OsStrExt as _;
    let source = std::ffi::CString::new(source.as_bytes()).context("source contains NUL")?;
    let destination =
        std::ffi::CString::new(destination.as_bytes()).context("destination contains NUL")?;
    // SAFETY: names and directory descriptor remain live for the syscall.
    let result = unsafe {
        libc::renameatx_np(
            parent.as_raw_fd(),
            source.as_ptr(),
            parent.as_raw_fd(),
            destination.as_ptr(),
            libc::RENAME_EXCL,
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error().into())
    }
}

fn no_replace_destination_exists(error: &anyhow::Error) -> bool {
    error
        .downcast_ref::<std::io::Error>()
        .is_some_and(|error| error.kind() == std::io::ErrorKind::AlreadyExists)
}

#[cfg(test)]
thread_local! {
    static PUBLICATION_PARENT_SYNC_FAULT: std::cell::RefCell<Option<Box<dyn FnOnce()>>> = const { std::cell::RefCell::new(None) };
    static REPLACEMENT_PARENT_SYNC_FAULT: std::cell::RefCell<Option<Box<dyn FnOnce()>>> = const { std::cell::RefCell::new(None) };
    static PUBLICATION_REMOVAL_PARENT_SYNC_FAULT: std::cell::RefCell<Option<Box<dyn FnOnce()>>> = const { std::cell::RefCell::new(None) };
    static PUBLICATION_REMOVAL_RENAME_ATTEMPTS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    static PUBLICATION_REMOVAL_SYNC_ATTEMPTS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    static PRE_NO_REPLACE_RENAME_HOOK: std::cell::RefCell<Option<Box<dyn FnOnce()>>> = const { std::cell::RefCell::new(None) };
    static PRE_PUBLICATION_REMOVAL_RENAME_HOOK: std::cell::RefCell<Option<Box<dyn FnOnce()>>> = const { std::cell::RefCell::new(None) };
    static POST_PUBLICATION_QUARANTINE_HOOK: std::cell::RefCell<Option<Box<dyn FnOnce()>>> = const { std::cell::RefCell::new(None) };
    static POST_REPLACEMENT_RENAME_HOOK: std::cell::RefCell<Option<Box<dyn FnOnce()>>> = const { std::cell::RefCell::new(None) };
}

#[cfg(test)]
pub(crate) fn inject_next_publication_parent_sync_failure(hook: impl FnOnce() + 'static) {
    PUBLICATION_PARENT_SYNC_FAULT
        .with(|slot| assert!(slot.borrow_mut().replace(Box::new(hook)).is_none()));
}
#[cfg(test)]
pub(crate) fn inject_next_replacement_parent_sync_failure(hook: impl FnOnce() + 'static) {
    REPLACEMENT_PARENT_SYNC_FAULT
        .with(|slot| assert!(slot.borrow_mut().replace(Box::new(hook)).is_none()));
}
#[cfg(test)]
pub(crate) fn inject_next_publication_removal_parent_sync_failure(hook: impl FnOnce() + 'static) {
    PUBLICATION_REMOVAL_PARENT_SYNC_FAULT
        .with(|slot| assert!(slot.borrow_mut().replace(Box::new(hook)).is_none()));
}
#[cfg(test)]
pub(crate) fn reset_publication_removal_attempt_counts() {
    PUBLICATION_REMOVAL_RENAME_ATTEMPTS.with(|v| v.set(0));
    PUBLICATION_REMOVAL_SYNC_ATTEMPTS.with(|v| v.set(0));
}
#[cfg(test)]
pub(crate) fn publication_removal_attempt_counts() -> (usize, usize) {
    (
        PUBLICATION_REMOVAL_RENAME_ATTEMPTS.with(std::cell::Cell::get),
        PUBLICATION_REMOVAL_SYNC_ATTEMPTS.with(std::cell::Cell::get),
    )
}
#[cfg(test)]
pub(crate) fn inject_pre_no_replace_rename_hook(hook: impl FnOnce() + 'static) {
    PRE_NO_REPLACE_RENAME_HOOK
        .with(|slot| assert!(slot.borrow_mut().replace(Box::new(hook)).is_none()));
}
#[cfg(test)]
pub(crate) fn inject_post_replacement_rename_hook(hook: impl FnOnce() + 'static) {
    POST_REPLACEMENT_RENAME_HOOK
        .with(|slot| assert!(slot.borrow_mut().replace(Box::new(hook)).is_none()));
}
#[cfg(test)]
pub(crate) fn inject_post_publication_quarantine_hook(hook: impl FnOnce() + 'static) {
    POST_PUBLICATION_QUARANTINE_HOOK
        .with(|slot| assert!(slot.borrow_mut().replace(Box::new(hook)).is_none()));
}
#[cfg(test)]
pub(crate) fn inject_pre_publication_removal_rename_hook(hook: impl FnOnce() + 'static) {
    PRE_PUBLICATION_REMOVAL_RENAME_HOOK
        .with(|slot| assert!(slot.borrow_mut().replace(Box::new(hook)).is_none()));
}

#[cfg(test)]
fn run_pre_no_replace_rename_test_hook() {
    if let Some(hook) = PRE_NO_REPLACE_RENAME_HOOK.with(|slot| slot.borrow_mut().take()) {
        hook();
    }
}
#[cfg(not(test))]
fn run_pre_no_replace_rename_test_hook() {}
#[cfg(test)]
fn run_post_replacement_rename_test_hook() {
    if let Some(hook) = POST_REPLACEMENT_RENAME_HOOK.with(|slot| slot.borrow_mut().take()) {
        hook();
    }
}
#[cfg(not(test))]
fn run_post_replacement_rename_test_hook() {}
#[cfg(test)]
fn run_pre_publication_removal_rename_test_hook() {
    PUBLICATION_REMOVAL_RENAME_ATTEMPTS.with(|v| v.set(v.get() + 1));
    if let Some(hook) = PRE_PUBLICATION_REMOVAL_RENAME_HOOK.with(|slot| slot.borrow_mut().take()) {
        hook();
    }
}
#[cfg(not(test))]
fn run_pre_publication_removal_rename_test_hook() {}
#[cfg(test)]
fn run_post_publication_quarantine_test_hook() {
    if let Some(hook) = POST_PUBLICATION_QUARANTINE_HOOK.with(|slot| slot.borrow_mut().take()) {
        hook();
    }
}
#[cfg(not(test))]
fn run_post_publication_quarantine_test_hook() {}

fn sync_published_destination_parent(directory: &AuthorityDirectory, label: &str) -> Result<()> {
    #[cfg(test)]
    if let Some(hook) = PUBLICATION_PARENT_SYNC_FAULT.with(|slot| slot.borrow_mut().take()) {
        hook();
        bail!("injected {label} parent-directory sync failure");
    }
    directory.sync(label)
}

fn sync_replacement_destination_parent(directory: &AuthorityDirectory, label: &str) -> Result<()> {
    #[cfg(test)]
    if let Some(hook) = REPLACEMENT_PARENT_SYNC_FAULT.with(|slot| slot.borrow_mut().take()) {
        hook();
        bail!("injected replacement {label} parent-directory sync failure");
    }
    directory.sync(&format!("replacement {label}"))
}

fn sync_removed_publication_parent(directory: &AuthorityDirectory, label: &str) -> Result<()> {
    #[cfg(test)]
    {
        PUBLICATION_REMOVAL_SYNC_ATTEMPTS.with(|v| v.set(v.get() + 1));
        if let Some(hook) =
            PUBLICATION_REMOVAL_PARENT_SYNC_FAULT.with(|slot| slot.borrow_mut().take())
        {
            hook();
            bail!("injected {label} removal parent-directory sync failure");
        }
    }
    directory.sync(&format!("{label} removal"))
}

pub(crate) fn ensure_owner_only_directory(path: &Path, label: &str) -> Result<()> {
    AuthorityDirectory::bind_or_create(path, label, true).map(|_| ())
}

pub(crate) fn ensure_publication_directory(path: &Path, label: &str) -> Result<()> {
    AuthorityDirectory::bind_or_create(path, label, false).map(|_| ())
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::{PermissionsExt as _, symlink};

    use super::*;

    #[test]
    fn unsafe_effective_owner_intermediate_is_rejected_without_mutation() {
        let root = tempfile::tempdir().unwrap();
        let unsafe_component = root.path().join("unsafe");
        std::fs::create_dir(&unsafe_component).unwrap();
        std::fs::set_permissions(&unsafe_component, std::fs::Permissions::from_mode(0o770))
            .unwrap();
        let target = unsafe_component.join("publication");

        let error = ensure_publication_directory(&target, "test publication")
            .expect_err("writable effective-owner intermediate must fail closed");
        assert!(format!("{error:#}").contains("not group/world writable"));
        assert!(!target.exists());
        assert_eq!(
            std::fs::symlink_metadata(&unsafe_component).unwrap().mode() & 0o7777,
            0o770
        );
    }

    /// The command after a refusal's `fix: `, run by `/bin/sh` exactly as
    /// printed, so the remedy is proven by the shell and the filesystem, not by
    /// kata re-reading its own text.
    fn run_printed_fix(refusal: &str) {
        let (_, command) = refusal
            .rsplit_once("fix: ")
            .unwrap_or_else(|| panic!("the refusal prints no fix: {refusal}"));
        let status = std::process::Command::new("/bin/sh")
            .arg("-c")
            .arg(command)
            .status()
            .unwrap();
        assert!(status.success(), "`{command}` failed: {status}");
    }

    /// A temporary root kata may publish beneath: tempfile creates it under
    /// the process umask, which may leave it group-writable.
    fn owner_only_root() -> tempfile::TempDir {
        let root = tempfile::tempdir().unwrap();
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        root
    }

    fn mode_of(path: &Path) -> u32 {
        std::fs::symlink_metadata(path).unwrap().mode() & 0o7777
    }

    /// **A group-writable directory of yours prints the `chmod` that clears
    /// it.** Ubuntu's umask 002 leaves `~/.local` at 775; the refusal names
    /// `chmod go-w` on the exact directory, shell-quoted (the path here holds
    /// a space), and that command run by `sh` is the whole fix: the bind then
    /// succeeds. The refused set is unchanged: the ancestor is refused first.
    ///
    /// **Would red if:** the refusal dropped its fix, printed it unquoted, or
    /// printed a command that leaves a group/world write bit.
    #[test]
    fn a_group_writable_ancestor_refusal_prints_the_chmod_that_clears_it() {
        let root = owner_only_root();
        let ancestor = root.path().join("dot local");
        std::fs::create_dir(&ancestor).unwrap();
        std::fs::set_permissions(&ancestor, std::fs::Permissions::from_mode(0o775)).unwrap();
        let target = ancestor.join("state");

        let refusal = format!(
            "{:#}",
            ensure_publication_directory(&target, "test publication").unwrap_err()
        );
        assert!(
            refusal.contains(&format!("fix: chmod go-w '{}'", ancestor.display())),
            "{refusal}"
        );
        assert!(!refusal.contains("chown"), "{refusal}");
        assert_eq!(mode_of(&ancestor), 0o775, "the refusal changed nothing");

        run_printed_fix(&refusal);
        assert_eq!(mode_of(&ancestor), 0o755);
        ensure_publication_directory(&target, "test publication")
            .expect("the printed fix is the whole fix");
    }

    /// **An existing owner-only directory prints the `chmod` that makes it
    /// exactly 0700**, including when a set-group-ID bit is set: GNU `chmod
    /// 700` keeps a directory's set-group-ID bit, so that case prints `chmod
    /// 00700`, which clears it.
    ///
    /// **Would red if:** the refusal dropped its fix, or printed `chmod 700`
    /// for a mode with a special bit (the directory would stay refused).
    #[test]
    fn an_owner_only_directory_refusal_prints_the_chmod_that_makes_it_0700() {
        for (mode, command) in [(0o755, "chmod 700"), (0o2750, "chmod 00700")] {
            let root = owner_only_root();
            let directory = root.path().join("owner only");
            std::fs::create_dir(&directory).unwrap();
            std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(mode)).unwrap();
            assert_eq!(mode_of(&directory), mode, "precondition: the mode is set");

            let refusal = format!(
                "{:#}",
                ensure_owner_only_directory(&directory, "test owner-only").unwrap_err()
            );
            assert!(
                refusal.contains(&format!("fix: {command} '{}'", directory.display())),
                "{mode:o}: {refusal}"
            );

            run_printed_fix(&refusal);
            assert_eq!(mode_of(&directory), 0o700, "{mode:o}");
            ensure_owner_only_directory(&directory, "test owner-only")
                .expect("the printed fix is the whole fix");
        }
    }

    /// **A directory another account owns is refused with the reason, never a
    /// `chmod` or `chown`.** `/usr` is root's: kata publishes only into a
    /// directory the effective user owns.
    ///
    /// **Would red if:** the refusal dropped its reason or proposed a command.
    #[test]
    fn a_directory_another_account_owns_is_refused_with_why_and_no_command() {
        let usr = Path::new("/usr");
        let euid = nix::unistd::geteuid().as_raw();
        assert_ne!(
            std::fs::metadata(usr).unwrap().uid(),
            euid,
            "precondition: /usr belongs to another account"
        );
        let refusal = format!(
            "{:#}",
            ensure_publication_directory(usr, "test publication").unwrap_err()
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

    /// **An ancestor kata cannot trust is refused with the reason, never a
    /// command.** `/dev/shm` is root's, mode 1777, and not one of the
    /// recognized sticky temporary anchors.
    ///
    /// **Would red if:** the refusal dropped its reason or proposed a command.
    #[test]
    fn an_untrusted_shared_ancestor_is_refused_with_why_and_no_command() {
        let shm = Path::new("/dev/shm");
        let metadata = std::fs::metadata(shm).unwrap();
        assert_eq!(
            (metadata.uid(), metadata.mode() & 0o7777),
            (0, 0o1777),
            "precondition: /dev/shm is root's shared sticky directory"
        );
        let target = shm.join("kata-publication-refusal-cell");
        let refusal = format!(
            "{:#}",
            ensure_publication_directory(&target, "test publication").unwrap_err()
        );
        assert!(
            refusal.contains(
                "refused: it is root's but others can write it, and it is not /tmp or /var/tmp"
            ),
            "{refusal}"
        );
        assert!(!refusal.contains("fix: "), "{refusal}");
        assert!(!refusal.contains("chown"), "{refusal}");
        assert!(!target.exists());
    }

    /// **Root's sticky `/tmp` and `/var/tmp` are accepted anchors on Linux.**
    /// The installed main's coordination directory is
    /// `/tmp/kata-installed-main-<uid>` (`owner_coordination_directory_for_uid`),
    /// so a Linux installed main exists only while `/tmp` binds. This cell does
    /// not read `TMPDIR`: the suite's `TMPDIR` is a tmpfs under
    /// `$XDG_RUNTIME_DIR`, whose ancestors are root's and not world-writable, so
    /// no other cell of the commit tier walks a sticky anchor. Under each real
    /// anchor it binds a fresh 0700 directory, and creates an owner-only one
    /// beneath it as `ensure_owner_only_directory` creates the coordination
    /// directory; the filesystem, read without kata, shows it at 0700.
    ///
    /// **Would red if:** `is_trusted_root_sticky_temporary` dropped `/tmp` or
    /// `/var/tmp`, or a root 1777 component stopped binding as
    /// `RootStickyTemporary`.
    #[cfg(target_os = "linux")]
    #[test]
    fn root_sticky_tmp_and_var_tmp_bind_as_anchors() {
        for anchor in ["/tmp", "/var/tmp"] {
            let metadata = std::fs::symlink_metadata(anchor).unwrap();
            assert_eq!(
                (
                    metadata.file_type().is_dir(),
                    metadata.uid(),
                    metadata.mode() & 0o7777
                ),
                (true, 0, 0o1777),
                "precondition: {anchor} is root's sticky shared directory"
            );
            let fresh = tempfile::Builder::new()
                .prefix("kata-sticky-anchor-")
                .tempdir_in(anchor)
                .unwrap();
            std::fs::set_permissions(fresh.path(), std::fs::Permissions::from_mode(0o700)).unwrap();

            AuthorityDirectory::bind_existing(fresh.path(), "test anchor").unwrap_or_else(
                |error| panic!("{anchor}: a 0700 directory under it is refused: {error:#}"),
            );
            let created = fresh.path().join("kata-installed-main-cell");
            ensure_owner_only_directory(&created, "test anchor").unwrap_or_else(|error| {
                panic!("{anchor}: an owner-only directory under it is refused: {error:#}")
            });
            assert_eq!(mode_of(&created), 0o700, "{anchor}");
        }
    }

    #[test]
    fn arbitrary_intermediate_symlink_is_rejected() {
        let root = tempfile::tempdir().unwrap();
        let real = root.path().join("real");
        let alias = root.path().join("alias");
        std::fs::create_dir(&real).unwrap();
        symlink(&real, &alias).unwrap();

        let _error = ensure_publication_directory(&alias.join("publication"), "test publication")
            .expect_err("arbitrary intermediate symlink must fail closed");
        assert!(!real.join("publication").exists());
        assert!(
            std::fs::symlink_metadata(&alias)
                .unwrap()
                .file_type()
                .is_symlink()
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn fixed_macos_alias_normalization_is_closed_and_lexical() {
        for (path, expected) in [
            ("/tmp/kata/proof", "/private/tmp/kata/proof"),
            ("/var/kata/proof", "/private/var/kata/proof"),
            ("/etc/kata/proof", "/private/etc/kata/proof"),
            ("/Users/kata/proof", "/Users/kata/proof"),
        ] {
            assert_eq!(
                trusted_absolute_path(Path::new(path)),
                PathBuf::from(expected),
                "unexpected normalization for {path}"
            );
        }
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn fixed_macos_tmp_alias_and_private_path_bind_the_same_directory() {
        let name = format!("kata-publication-alias-{}", ulid::Ulid::new());
        let alias = PathBuf::from("/tmp").join(&name);
        let direct = PathBuf::from("/private/tmp").join(&name);
        std::fs::create_dir(&direct).unwrap();
        std::fs::set_permissions(&direct, std::fs::Permissions::from_mode(0o700)).unwrap();

        let alias_binding = AuthorityDirectory::bind_existing(&alias, "macOS alias").unwrap();
        let direct_binding = AuthorityDirectory::bind_existing(&direct, "macOS direct").unwrap();
        assert_eq!(alias_binding.path, direct);
        assert_eq!(
            (
                alias_binding.file.metadata().unwrap().dev(),
                alias_binding.file.metadata().unwrap().ino()
            ),
            (
                direct_binding.file.metadata().unwrap().dev(),
                direct_binding.file.metadata().unwrap().ino()
            )
        );
        std::fs::remove_dir(&direct).unwrap();
    }

    #[test]
    fn recovery_uses_constant_descriptors_under_low_nofile_limit() {
        const CHILD_ROOT: &str = "KATA_PUBLICATION_LOW_NOFILE_ROOT";
        const ARTIFACT_PREFIX: &str = ".kata-low-nofile.";
        const ARTIFACT_COUNT: usize = 65;
        const CHILD_NOFILE_LIMIT: libc::rlim_t = 32;

        if let Some(root) = std::env::var_os(CHILD_ROOT) {
            let root = PathBuf::from(root);
            lower_child_nofile_limit(CHILD_NOFILE_LIMIT);
            recover_owner_only_publication_artifacts(
                &root,
                ARTIFACT_PREFIX,
                1,
                ARTIFACT_COUNT,
                "low-NOFILE publication",
            )
            .expect("two-pass recovery stays within the child descriptor budget");
            assert_eq!(
                std::fs::read_dir(&root)
                    .expect("read recovered directory")
                    .count(),
                0,
                "recovery must remove every matching artifact"
            );
            return;
        }

        let root = std::env::var_os("XDG_RUNTIME_DIR")
            .and_then(|directory| tempfile::tempdir_in(directory).ok())
            .unwrap_or_else(|| tempfile::tempdir().expect("low-NOFILE recovery root"));
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700))
            .expect("normalize low-NOFILE recovery root");
        for index in 0..ARTIFACT_COUNT {
            let path = root
                .path()
                .join(format!("{ARTIFACT_PREFIX}write-{index}.tmp"));
            std::fs::write(&path, b"x").expect("write recovery artifact");
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
                .expect("normalize recovery artifact");
        }

        let output = std::process::Command::new(std::env::current_exe().expect("test executable"))
            .arg("--exact")
            .arg(
                "owner_only_publication::tests::recovery_uses_constant_descriptors_under_low_nofile_limit",
            )
            .arg("--nocapture")
            .env(CHILD_ROOT, root.path())
            .output()
            .expect("run low-NOFILE recovery child");
        assert!(
            output.status.success(),
            "low-NOFILE recovery child failed: stdout={} stderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(
            std::fs::read_dir(root.path())
                .expect("read recovered directory")
                .count(),
            0,
            "child recovery must remove all {ARTIFACT_COUNT} artifacts"
        );
    }

    #[allow(unsafe_code)]
    fn lower_child_nofile_limit(limit: libc::rlim_t) {
        let mut current = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        // SAFETY: `current` is valid writable storage for `getrlimit`.
        let get_result = unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &raw mut current) };
        assert_eq!(
            get_result,
            0,
            "reading child RLIMIT_NOFILE failed: {}",
            std::io::Error::last_os_error()
        );
        assert!(
            current.rlim_max >= limit,
            "hard RLIMIT_NOFILE {} is below required test limit {limit}",
            current.rlim_max
        );
        let lowered = libc::rlimit {
            rlim_cur: limit,
            rlim_max: current.rlim_max,
        };
        // SAFETY: `lowered` is a valid immutable `rlimit`; this runs only in
        // the disposable exact-test child, so the process-global soft-limit
        // mutation cannot affect another test.
        let set_result = unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &raw const lowered) };
        assert_eq!(
            set_result,
            0,
            "lowering child RLIMIT_NOFILE failed: {}",
            std::io::Error::last_os_error()
        );
    }
}
