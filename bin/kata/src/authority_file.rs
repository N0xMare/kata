//! Bounded descriptor snapshots for installed-main authority inputs.
//!
//! Opening a path with a convenience `read` helper can block forever on a
//! FIFO, follow an unexpected replacement, or allocate from an unbounded
//! regular file.  Service definitions, installed config/environment inputs,
//! executable identity, and immutable data-directory identity all use this
//! module so their failure posture stays identical.

use std::fs::{File, Metadata, OpenOptions};
use std::io::{Read, Seek as _, SeekFrom};
#[cfg(unix)]
use std::os::fd::{AsRawFd as _, RawFd};
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt as _;
use std::path::Path;

use anyhow::{Context as _, Result, bail};

pub(crate) const MAX_SERVICE_ENVIRONMENT_BYTES: u64 = 1024 * 1024;
pub(crate) const MAX_DATA_DIRECTORY_IDENTITY_BYTES: u64 = 64 * 1024;
// The shipped release ceiling is much lower, but a local development install
// can be a debuginfo-heavy binary. Hash it as a stream and retain an explicit upper
// bound large enough for that supported development path.
pub(crate) const MAX_KATA_BINARY_BYTES: u64 = 2 * 1024 * 1024 * 1024;
pub(crate) const SERVICE_CONFIG_SNAPSHOT_FD_ENV: &str = "KATA_SERVICE_CONFIG_SNAPSHOT_FD";

#[derive(Clone, Copy)]
pub(crate) struct AuthorityFilePolicy {
    pub(crate) label: &'static str,
    pub(crate) max_bytes: u64,
    pub(crate) exact_mode: Option<u32>,
    pub(crate) forbidden_mode_bits: u32,
    pub(crate) require_effective_owner: bool,
    pub(crate) require_single_link: bool,
}

impl AuthorityFilePolicy {
    pub(crate) const fn bounded(label: &'static str, max_bytes: u64) -> Self {
        Self {
            label,
            max_bytes,
            exact_mode: None,
            forbidden_mode_bits: 0,
            require_effective_owner: false,
            require_single_link: false,
        }
    }

    pub(crate) const fn owner_only(label: &'static str, max_bytes: u64) -> Self {
        Self {
            label,
            max_bytes,
            exact_mode: Some(0o600),
            forbidden_mode_bits: 0,
            require_effective_owner: true,
            require_single_link: true,
        }
    }
}

pub(crate) fn read_bounded_file(path: &Path, policy: AuthorityFilePolicy) -> Result<Vec<u8>> {
    read_bounded_file_with_post_read(path, policy, || {})
}

fn read_bounded_file_with_post_read(
    path: &Path,
    policy: AuthorityFilePolicy,
    post_read: impl FnOnce(),
) -> Result<Vec<u8>> {
    let (mut file, before) = open_checked(path, policy)?;
    let bytes = read_bounded_from_open_file(&mut file, path, policy)?;
    post_read();
    validate_unchanged_and_bound(&file, path, &before, policy)?;
    Ok(bytes)
}

pub(crate) fn read_bounded_utf8(path: &Path, policy: AuthorityFilePolicy) -> Result<String> {
    let bytes = read_bounded_file(path, policy)?;
    String::from_utf8(bytes)
        .with_context(|| format!("{} {} is not UTF-8", policy.label, path.display()))
}

#[cfg(test)]
pub(crate) fn read_bounded_utf8_with_post_read(
    path: &Path,
    policy: AuthorityFilePolicy,
    post_read: impl FnOnce(),
) -> Result<String> {
    let bytes = read_bounded_file_with_post_read(path, policy, post_read)?;
    String::from_utf8(bytes)
        .with_context(|| format!("{} {} is not UTF-8", policy.label, path.display()))
}

pub(crate) fn digest_bounded_file(path: &Path, policy: AuthorityFilePolicy) -> Result<String> {
    let (mut file, before) = open_checked(path, policy)?;
    let digest = digest_open_file(&mut file, path, policy)?;
    validate_unchanged_and_bound(&file, path, &before, policy)?;
    Ok(digest)
}

/// Normalize a newly created owner-only authority publication independently
/// of the caller's umask, then verify the exact regular-file/owner/link mode
/// before any bytes are written or the temporary inode is renamed.
pub(crate) fn normalize_new_owner_only_file(
    file: &File,
    path: &Path,
    label: &'static str,
) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        file.set_permissions(std::fs::Permissions::from_mode(0o600))
            .with_context(|| format!("setting owner-only mode on {label} {}", path.display()))?;
    }
    let metadata = file
        .metadata()
        .with_context(|| format!("inspecting new {label} {}", path.display()))?;
    validate_metadata(
        &metadata,
        path,
        AuthorityFilePolicy::owner_only(label, u64::MAX),
    )
}

/// Open and hash one stable config snapshot while retaining its descriptor for
/// the native-service exec handoff.
pub(crate) fn open_digest_snapshot(
    path: &Path,
    policy: AuthorityFilePolicy,
) -> Result<(File, String)> {
    let (mut file, before) = open_checked(path, policy)?;
    let digest = digest_open_file(&mut file, path, policy)?;
    validate_unchanged_and_bound(&file, path, &before, policy)?;
    file.seek(SeekFrom::Start(0))
        .with_context(|| format!("rewinding {} {}", policy.label, path.display()))?;
    Ok((file, digest))
}

fn open_checked(path: &Path, policy: AuthorityFilePolicy) -> Result<(File, Metadata)> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC);
    let file = options
        .open(path)
        .with_context(|| format!("opening {} {}", policy.label, path.display()))?;
    let metadata = file
        .metadata()
        .with_context(|| format!("inspecting {} {}", policy.label, path.display()))?;
    validate_metadata(&metadata, path, policy)?;
    Ok((file, metadata))
}

fn validate_metadata(metadata: &Metadata, path: &Path, policy: AuthorityFilePolicy) -> Result<()> {
    if !metadata.is_file() {
        bail!("{} {} must be a regular file", policy.label, path.display());
    }
    if metadata.len() > policy.max_bytes {
        bail!(
            "{} {} exceeds the {}-byte safety bound",
            policy.label,
            path.display(),
            policy.max_bytes
        );
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;

        let mode = metadata.mode() & 0o7777;
        if let Some(expected) = policy.exact_mode
            && mode != expected
        {
            bail!(
                "{} {} has mode {mode:o}, expected {expected:o}",
                policy.label,
                path.display()
            );
        }
        if mode & policy.forbidden_mode_bits != 0 {
            bail!(
                "{} {} has unsafe mode {mode:o}",
                policy.label,
                path.display()
            );
        }
        if policy.require_effective_owner {
            let expected = nix::unistd::geteuid().as_raw();
            if metadata.uid() != expected {
                bail!(
                    "{} {} is owned by uid {}, expected {}",
                    policy.label,
                    path.display(),
                    metadata.uid(),
                    expected
                );
            }
        }
        if policy.require_single_link && metadata.nlink() != 1 {
            bail!(
                "{} {} must have exactly one link, found {}",
                policy.label,
                path.display(),
                metadata.nlink()
            );
        }
    }
    Ok(())
}

fn read_bounded_from_open_file(
    file: &mut File,
    path: &Path,
    policy: AuthorityFilePolicy,
) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    file.take(policy.max_bytes + 1)
        .read_to_end(&mut bytes)
        .with_context(|| format!("reading {} {}", policy.label, path.display()))?;
    if bytes.len() as u64 > policy.max_bytes {
        bail!(
            "{} {} grew beyond the {}-byte safety bound while being read",
            policy.label,
            path.display(),
            policy.max_bytes
        );
    }
    Ok(bytes)
}

fn digest_open_file(file: &mut File, path: &Path, policy: AuthorityFilePolicy) -> Result<String> {
    let mut hasher = blake3::Hasher::new();
    let mut remaining = policy.max_bytes + 1;
    let mut buffer = vec![0_u8; 64 * 1024].into_boxed_slice();
    let mut total = 0_u64;
    while remaining > 0 {
        let limit = usize::try_from(remaining.min(buffer.len() as u64))
            .expect("bounded read chunk fits usize");
        let read = file
            .read(&mut buffer[..limit])
            .with_context(|| format!("hashing {} {}", policy.label, path.display()))?;
        if read == 0 {
            break;
        }
        total += read as u64;
        remaining -= read as u64;
        if total > policy.max_bytes {
            bail!(
                "{} {} grew beyond the {}-byte safety bound while being hashed",
                policy.label,
                path.display(),
                policy.max_bytes
            );
        }
        hasher.update(&buffer[..read]);
    }
    Ok(hasher.finalize().to_hex().to_string())
}

fn validate_unchanged_and_bound(
    file: &File,
    path: &Path,
    before: &Metadata,
    policy: AuthorityFilePolicy,
) -> Result<()> {
    let after = file
        .metadata()
        .with_context(|| format!("rechecking {} {}", policy.label, path.display()))?;
    validate_metadata(&after, path, policy)?;
    if !same_snapshot(before, &after) {
        bail!(
            "{} {} changed while its snapshot was being read",
            policy.label,
            path.display()
        );
    }

    let current = std::fs::symlink_metadata(path)
        .with_context(|| format!("rebinding {} {} to its path", policy.label, path.display()))?;
    validate_metadata(&current, path, policy)?;
    if !same_file(&after, &current) {
        bail!(
            "{} {} was replaced while its snapshot was being read",
            policy.label,
            path.display()
        );
    }
    Ok(())
}

#[cfg(unix)]
fn same_file(left: &Metadata, right: &Metadata) -> bool {
    use std::os::unix::fs::MetadataExt as _;
    (left.dev(), left.ino()) == (right.dev(), right.ino())
}

#[cfg(not(unix))]
fn same_file(left: &Metadata, right: &Metadata) -> bool {
    left.len() == right.len()
}

#[cfg(unix)]
fn same_snapshot(left: &Metadata, right: &Metadata) -> bool {
    use std::os::unix::fs::MetadataExt as _;
    (
        left.dev(),
        left.ino(),
        left.len(),
        left.mtime(),
        left.mtime_nsec(),
        left.ctime(),
        left.ctime_nsec(),
    ) == (
        right.dev(),
        right.ino(),
        right.len(),
        right.mtime(),
        right.mtime_nsec(),
        right.ctime(),
        right.ctime_nsec(),
    )
}

#[cfg(not(unix))]
fn same_snapshot(left: &Metadata, right: &Metadata) -> bool {
    left.len() == right.len() && left.modified().ok() == right.modified().ok()
}

#[cfg(unix)]
#[allow(unsafe_code)]
pub(crate) fn prepare_exec_handoff(file: &File, label: &str) -> Result<RawFd> {
    let descriptor = file.as_raw_fd();
    if descriptor <= libc::STDERR_FILENO {
        bail!("{label} uses an unsafe stdio descriptor");
    }
    // SAFETY: F_GETFD/F_SETFD inspect and update flags on this live descriptor
    // and do not dereference process memory.
    let flags = unsafe { libc::fcntl(descriptor, libc::F_GETFD) };
    if flags < 0 {
        return Err(std::io::Error::last_os_error())
            .with_context(|| format!("inspecting {label} descriptor flags"));
    }
    if unsafe { libc::fcntl(descriptor, libc::F_SETFD, flags & !libc::FD_CLOEXEC) } < 0 {
        return Err(std::io::Error::last_os_error())
            .with_context(|| format!("preparing {label} descriptor for exec"));
    }
    Ok(descriptor)
}

/// Consume the regular config descriptor inherited from `__service-exec`.
/// `/dev/fd` is the common Linux/macOS safe duplication surface; the path is
/// constructed only from a parsed descriptor and opened nonblocking before its
/// regular-file metadata and byte bound are rechecked.
#[cfg(unix)]
pub(crate) fn take_inherited_config_snapshot(raw: &std::ffi::OsStr) -> Result<String> {
    let text = raw
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("installed config descriptor is not Unicode"))?;
    let descriptor = text
        .parse::<RawFd>()
        .with_context(|| format!("invalid installed config descriptor {text:?}"))?;
    if descriptor <= libc::STDERR_FILENO {
        bail!("installed config descriptor must be greater than stderr");
    }

    let path = std::path::PathBuf::from(format!("/dev/fd/{descriptor}"));
    let mut options = OpenOptions::new();
    options
        .read(true)
        .custom_flags(libc::O_NONBLOCK | libc::O_CLOEXEC);
    let result = (|| {
        let mut file = options
            .open(&path)
            .with_context(|| format!("adopting installed config descriptor {descriptor}"))?;
        let policy = config_policy();
        let metadata = file
            .metadata()
            .context("inspecting inherited installed config snapshot")?;
        validate_metadata(&metadata, &path, policy)?;
        file.seek(SeekFrom::Start(0))
            .context("rewinding inherited installed config snapshot")?;
        let bytes = read_bounded_from_open_file(&mut file, &path, policy)?;
        let after = file
            .metadata()
            .context("rechecking inherited installed config snapshot")?;
        validate_metadata(&after, &path, policy)?;
        if !same_snapshot(&metadata, &after) {
            bail!("inherited installed config snapshot changed while being read");
        }
        String::from_utf8(bytes).context("inherited installed config snapshot is not UTF-8")
    })();
    let close = nix::unistd::close(descriptor)
        .with_context(|| format!("closing inherited installed config descriptor {descriptor}"));
    match (result, close) {
        (Ok(snapshot), Ok(())) => Ok(snapshot),
        (Err(error), _) | (Ok(_), Err(error)) => Err(error),
    }
}

pub(crate) const fn config_policy() -> AuthorityFilePolicy {
    // Kata is a one-owner product rather than a hostile multi-user daemon.
    // Config may legitimately be 0664 in an owner-managed project or 0444 in
    // a root-owned package store; regular type, bounded stable bytes, exact
    // digest, and descriptor handoff are the relevant authority properties.
    AuthorityFilePolicy::bounded("installed Kata config", kata_core::MAX_CONFIG_FILE_BYTES)
}

#[cfg(test)]
mod tests {
    use std::os::fd::IntoRawFd as _;
    use std::os::unix::fs::PermissionsExt as _;

    use nix::sys::stat::Mode;
    use tempfile::TempDir;

    use super::*;

    #[test]
    fn bounded_reader_rejects_fifo_without_blocking() {
        let temp = TempDir::new().unwrap();
        let path = temp.path().join("authority.fifo");
        nix::unistd::mkfifo(&path, Mode::from_bits_truncate(0o600)).unwrap();
        let error = read_bounded_file(&path, AuthorityFilePolicy::owner_only("test", 32))
            .expect_err("a FIFO must fail closed");
        assert!(format!("{error:#}").contains("regular file"));
    }

    #[test]
    fn owner_only_reader_rejects_links_modes_and_oversize() {
        let temp = TempDir::new().unwrap();
        let path = temp.path().join("authority");
        std::fs::write(&path, b"ok").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640)).unwrap();
        read_bounded_file(&path, AuthorityFilePolicy::owner_only("test", 32))
            .expect_err("group-readable authority must fail closed");

        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let alias = temp.path().join("alias");
        std::fs::hard_link(&path, alias).unwrap();
        read_bounded_file(&path, AuthorityFilePolicy::owner_only("test", 32))
            .expect_err("multiply-linked authority must fail closed");

        std::fs::remove_file(temp.path().join("alias")).unwrap();
        std::fs::write(&path, [0_u8; 33]).unwrap();
        read_bounded_file(&path, AuthorityFilePolicy::owner_only("test", 32))
            .expect_err("oversized authority must fail closed");
    }

    #[test]
    fn inherited_config_handoff_reads_and_consumes_the_exact_open_snapshot() {
        let temp = TempDir::new().unwrap();
        let path = temp.path().join("kata.toml");
        std::fs::write(&path, b"[node]\nid = \"snapshot\"\n").unwrap();
        let (file, _) = open_digest_snapshot(&path, config_policy()).unwrap();
        let descriptor = prepare_exec_handoff(&file, "test config snapshot").unwrap();
        assert_eq!(file.into_raw_fd(), descriptor);

        std::fs::remove_file(&path).unwrap();
        std::fs::write(&path, b"[node]\nid = \"replacement\"\n").unwrap();
        let snapshot = take_inherited_config_snapshot(descriptor.to_string().as_ref()).unwrap();
        assert_eq!(snapshot, "[node]\nid = \"snapshot\"\n");

        // The inherited descriptor is consumed exactly once.
        let error = take_inherited_config_snapshot(descriptor.to_string().as_ref())
            .expect_err("a consumed inherited descriptor must not be reusable");
        assert!(
            format!("{error:#}").contains("adopting installed config descriptor"),
            "{error:#}"
        );
    }
}
