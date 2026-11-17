//! Unix socket addressing that does not depend on the socket directory's length.
//!
//! See [`kata_types::unix_socket_name`] for the bound this closes and the one it
//! keeps. Every kata site that binds or connects a filesystem unix socket resolves
//! its path through [`UnixSocketAddress`] first and hands the kernel
//! [`UnixSocketAddress::as_path`] — `/proc/self/fd/<fd>/<name>`, where `<fd>` is
//! an `O_PATH | O_DIRECTORY | O_CLOEXEC` descriptor on the socket's parent. The
//! kernel resolves that magic link to the real directory, so the socket inode is
//! created (or found) at the real path; only the address string is short.
//!
//! The descriptor must outlive the `bind`/`connect` call that names it, which is
//! why the address OWNS it: keep the value alive across the call (an `.await`
//! included) and drop it after. Nothing else changes — the socket file still
//! lives at, and is unlinked from, its real path.

use std::os::fd::{AsRawFd, OwnedFd};
use std::path::{Path, PathBuf};

use kata_types::unix_socket_name::{PROC_SELF_FD, SocketNameRefusal, socket_file_name};
use rustix::fs::{Mode, OFlags};

/// Why a socket path could not be turned into a short address.
#[derive(Debug, thiserror::Error)]
pub enum UnixSocketAddressError {
    /// The file name itself is unaddressable — see [`SocketNameRefusal`].
    #[error(transparent)]
    Name(#[from] SocketNameRefusal),
    /// The parent directory could not be opened `O_PATH | O_DIRECTORY`.
    #[error("the unix socket directory {parent} could not be opened: {source}")]
    Parent {
        parent: PathBuf,
        #[source]
        source: std::io::Error,
    },
}

impl From<UnixSocketAddressError> for std::io::Error {
    fn from(error: UnixSocketAddressError) -> Self {
        let kind = match &error {
            UnixSocketAddressError::Name(_) => std::io::ErrorKind::InvalidInput,
            UnixSocketAddressError::Parent { source, .. } => source.kind(),
        };
        Self::new(kind, error)
    }
}

/// A socket path, re-addressed through a held descriptor on its parent.
#[derive(Debug)]
pub struct UnixSocketAddress {
    /// Held so `/proc/self/fd/<fd>` names the directory for as long as `short` is used.
    _parent: OwnedFd,
    short: PathBuf,
}

impl UnixSocketAddress {
    /// Open `path`'s parent and build the short address of its file name.
    ///
    /// A path with an empty parent (a bare relative name) is addressed through `.`.
    ///
    /// # Errors
    /// [`UnixSocketAddressError::Name`] for a name [`socket_file_name`] refuses;
    /// [`UnixSocketAddressError::Parent`] when the parent cannot be opened as a
    /// directory (absent, not a directory, not searchable).
    pub fn resolve(path: &Path) -> Result<Self, UnixSocketAddressError> {
        let name = socket_file_name(path)?;
        let parent = match path.parent() {
            Some(parent) if !parent.as_os_str().is_empty() => parent,
            _ => Path::new("."),
        };
        let fd = rustix::fs::open(
            parent,
            OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|errno| UnixSocketAddressError::Parent {
            parent: parent.to_path_buf(),
            source: std::io::Error::from(errno),
        })?;
        let short = Path::new(&format!("{PROC_SELF_FD}{}", fd.as_raw_fd())).join(name);
        Ok(Self { _parent: fd, short })
    }

    /// The address to hand `bind`/`connect` while `self` is alive.
    #[must_use]
    pub fn as_path(&self) -> &Path {
        &self.short
    }
}

/// `std` bind of `path` through its short address.
///
/// # Errors
/// [`UnixSocketAddress::resolve`]'s refusals as `io::Error`, then `bind`'s own.
pub fn bind_std(path: &Path) -> std::io::Result<std::os::unix::net::UnixListener> {
    let address = UnixSocketAddress::resolve(path)?;
    std::os::unix::net::UnixListener::bind(address.as_path())
}

/// `std` connect to `path` through its short address.
///
/// # Errors
/// [`UnixSocketAddress::resolve`]'s refusals as `io::Error`, then `connect`'s own.
pub fn connect_std(path: &Path) -> std::io::Result<std::os::unix::net::UnixStream> {
    let address = UnixSocketAddress::resolve(path)?;
    std::os::unix::net::UnixStream::connect(address.as_path())
}

/// Tokio bind of `path` through its short address. Synchronous, as
/// `tokio::net::UnixListener::bind` is; must run inside a runtime.
///
/// # Errors
/// As [`bind_std`].
pub fn bind_tokio(path: &Path) -> std::io::Result<tokio::net::UnixListener> {
    let address = UnixSocketAddress::resolve(path)?;
    tokio::net::UnixListener::bind(address.as_path())
}

/// Tokio connect to `path` through its short address; the parent descriptor is
/// held across the await.
///
/// # Errors
/// As [`connect_std`].
pub async fn connect_tokio(path: &Path) -> std::io::Result<tokio::net::UnixStream> {
    let address = UnixSocketAddress::resolve(path)?;
    tokio::net::UnixStream::connect(address.as_path()).await
}
