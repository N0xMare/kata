//! The one length bound a kata unix socket's PATH still has: its file name.
//!
//! The kernel's `sun_path` is 108 bytes (107 plus the NUL `std` requires), and a
//! socket path derived from `node.data_dir` or an attempt root has no such bound —
//! `<data_dir>/oci-worker-state/attempts/<26-char id>/egress/handoff.sock` alone is
//! the data directory plus 73 bytes. So kata never hands the kernel the real path:
//! every socket it binds or connects is addressed as `/proc/self/fd/<fd>/<name>`,
//! where `<fd>` is an `O_PATH` descriptor on the socket's parent directory
//! (`kata_transport::unix_socket::UnixSocketAddress`; `kata-oci-hook` performs the
//! same addressing on its side). That string's length does not depend on the
//! directory at all.
//!
//! What it does depend on is the NAME: `/proc/self/fd/` (14 bytes), a descriptor
//! of at most 10 decimal digits (`c_int`'s maximum), a `/`, then the name — so a
//! name of at most [`MAX_SOCKET_NAME_BYTES`] (82) bytes fits for every descriptor
//! number, and a longer one is refused by [`socket_file_name`] before anything is
//! opened. The refused set is exactly: a path with no final normal component, and
//! a final component longer than 82 bytes.

use std::ffi::OsStr;
use std::path::{Path, PathBuf};

/// `sizeof(sockaddr_un.sun_path)` on Linux.
pub const SUN_PATH_BYTES: usize = 108;

/// The prefix every kata socket address starts with.
pub const PROC_SELF_FD: &str = "/proc/self/fd/";

/// The widest decimal descriptor number: `c_int::MAX` is `2147483647`.
const MAX_FD_DIGITS: usize = 10;

/// The longest socket file NAME kata can address for every descriptor number:
/// `108 - 1 (NUL) - 14 ("/proc/self/fd/") - 10 (fd digits) - 1 ("/")` = 82.
pub const MAX_SOCKET_NAME_BYTES: usize =
    SUN_PATH_BYTES - 1 - PROC_SELF_FD.len() - MAX_FD_DIGITS - 1;

/// Why a socket path cannot be addressed through its parent directory.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum SocketNameRefusal {
    /// The path ends in `..`, `/` or nothing — there is no name to bind.
    #[error("the unix socket path {path} has no file name to bind or connect")]
    NoFileName { path: PathBuf },
    /// The final component is longer than [`MAX_SOCKET_NAME_BYTES`].
    #[error(
        "the unix socket file name {name:?} in {path} is {len} bytes; a kata unix socket is \
         addressed as `{PROC_SELF_FD}<fd>/<name>` within the kernel's {SUN_PATH_BYTES}-byte \
         sun_path, so its file name may be at most {MAX_SOCKET_NAME_BYTES} bytes (the \
         directory's length does not count). Choose a shorter name"
    )]
    NameTooLong {
        path: PathBuf,
        name: String,
        len: usize,
    },
}

/// The file name `path` is bound or connected under, or the refusal.
///
/// # Errors
/// Exactly [`SocketNameRefusal`]'s two arms.
pub fn socket_file_name(path: &Path) -> Result<&OsStr, SocketNameRefusal> {
    let name = path
        .file_name()
        .ok_or_else(|| SocketNameRefusal::NoFileName {
            path: path.to_path_buf(),
        })?;
    let len = name.as_encoded_bytes().len();
    if len > MAX_SOCKET_NAME_BYTES {
        return Err(SocketNameRefusal::NameTooLong {
            path: path.to_path_buf(),
            name: name.to_string_lossy().into_owned(),
            len,
        });
    }
    Ok(name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_name_bound_is_what_fits_beside_the_widest_descriptor() {
        assert_eq!(MAX_SOCKET_NAME_BYTES, 82);
        let widest = format!("{PROC_SELF_FD}{}/{}", i32::MAX, "n".repeat(82));
        assert_eq!(widest.len(), SUN_PATH_BYTES - 1);
    }

    #[test]
    fn a_name_is_refused_above_the_bound_and_accepted_at_it() {
        let dir = PathBuf::from(format!("/{}", "d".repeat(400)));
        let at = dir.join("n".repeat(MAX_SOCKET_NAME_BYTES));
        assert_eq!(
            socket_file_name(&at).map(std::ffi::OsStr::len),
            Ok(MAX_SOCKET_NAME_BYTES),
            "a 400-byte directory does not count against the bound"
        );
        let over = dir.join("n".repeat(MAX_SOCKET_NAME_BYTES + 1));
        assert!(matches!(
            socket_file_name(&over),
            Err(SocketNameRefusal::NameTooLong { len: 83, .. })
        ));
        assert!(matches!(
            socket_file_name(Path::new("/")),
            Err(SocketNameRefusal::NoFileName { .. })
        ));
    }
}
