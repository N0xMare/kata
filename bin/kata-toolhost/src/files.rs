//! The three file verbs: read, write and remove, inside the capsule.
//!
//! Each answers by its request id: `FileBytes` or `Done` on success, otherwise
//! `FileError` carrying the kernel's errno and its text, so the worker maps the
//! failure without a second vocabulary. A read-only bind (`/nix/store`, `/.kata`)
//! answers EROFS because the kernel does, not because this module knows it.
//!
//! They run on the runtime thread, bounded by `MAX_FILE_BYTES`: a read never
//! takes more than one byte past the cap, and opens with `O_NONBLOCK` so a FIFO
//! or a device cannot park the one thread every other session needs (a FIFO,
//! socket or device is refused as not a regular file, EINVAL).

use std::io::{Read as _, Write as _};
use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};

use kata_toolhost_protocol::{FileBody, MAX_FILE_BYTES, RequestId, ToolhostFrame};
use rustix::fs::{Mode, OFlags};

/// The errno of a `FileError` the kernel did not supply: a non-regular file
/// read, or a write path with no file name.
const EINVAL: i32 = 22;
/// A file over [`MAX_FILE_BYTES`].
const EFBIG: i32 = 27;
/// A directory read as a file.
const EISDIR: i32 = 21;
/// An I/O error that carried no errno (none of the calls here produce one).
const EIO: i32 = 5;
/// The mode a NEW file gets; an existing file keeps its own.
const NEW_FILE_MODE: u32 = 0o644;

fn failed(id: RequestId, errno: i32, message: impl Into<String>) -> ToolhostFrame {
    ToolhostFrame::FileError {
        id,
        errno,
        message: message.into(),
    }
}

fn io_failed(id: RequestId, what: &str, error: &std::io::Error) -> ToolhostFrame {
    failed(
        id,
        error.raw_os_error().unwrap_or(EIO),
        format!("{what}: {error}"),
    )
}

/// `ReadFile`: the file's bytes, `None` when it does not exist, EFBIG over the
/// cap, EISDIR for a directory and EINVAL for anything else that is not a
/// regular file.
pub(crate) fn read(id: RequestId, path: &str) -> ToolhostFrame {
    let fd = match rustix::fs::open(
        path,
        OFlags::RDONLY | OFlags::NONBLOCK | OFlags::NOCTTY | OFlags::CLOEXEC,
        Mode::empty(),
    ) {
        Ok(fd) => fd,
        Err(rustix::io::Errno::NOENT) => return ToolhostFrame::FileBytes { id, data_b64: None },
        Err(errno) => return failed(id, errno.raw_os_error(), format!("opening {path}: {errno}")),
    };
    let mut file = std::fs::File::from(fd);
    let meta = match file.metadata() {
        Ok(meta) => meta,
        Err(error) => return io_failed(id, &format!("reading {path}'s metadata"), &error),
    };
    if meta.is_dir() {
        return failed(id, EISDIR, format!("{path} is a directory"));
    }
    if !meta.is_file() {
        return failed(id, EINVAL, format!("{path} is not a regular file"));
    }
    let cap = MAX_FILE_BYTES as u64;
    if meta.len() > cap {
        return too_large(id, path);
    }
    // One byte past the cap and no further: a file that grew after the
    // `metadata` (or a `/proc` file whose size reads 0) is still bounded.
    let mut bytes = Vec::new();
    if let Err(error) = (&mut file).take(cap + 1).read_to_end(&mut bytes) {
        return io_failed(id, &format!("reading {path}"), &error);
    }
    match FileBody::new(bytes) {
        Ok(body) => ToolhostFrame::FileBytes {
            id,
            data_b64: Some(body),
        },
        Err(_) => too_large(id, path),
    }
}

fn too_large(id: RequestId, path: &str) -> ToolhostFrame {
    failed(
        id,
        EFBIG,
        format!("{path} is larger than {MAX_FILE_BYTES} bytes; page through it with exec"),
    )
}

/// `WriteFile`: create the parents, write a temporary file beside the target,
/// rename it over the target. An existing file keeps its permission bits (an
/// edited script stays executable); a new one is `0644`. A target that is a
/// symlink is written through: the link's resolved file is the one replaced.
pub(crate) fn write(id: RequestId, path: &str, body: &FileBody) -> ToolhostFrame {
    let target = match resolve_link(Path::new(path)) {
        Ok(target) => target,
        Err(error) => return io_failed(id, &format!("resolving {path}"), &error),
    };
    let (Some(parent), Some(name)) = (target.parent(), target.file_name()) else {
        return failed(id, EINVAL, format!("{path} names no file"));
    };
    if let Err(error) = std::fs::create_dir_all(parent) {
        return io_failed(id, &format!("creating {}", parent.display()), &error);
    }
    let mode = std::fs::metadata(&target)
        .ok()
        .filter(std::fs::Metadata::is_file)
        .map_or(NEW_FILE_MODE, |meta| meta.permissions().mode() & 0o7777);
    let temporary = parent.join(format!(
        ".{}.kata-toolhost-{}",
        name.to_string_lossy(),
        id.0
    ));
    let written = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&temporary)
        .and_then(|mut file| {
            file.write_all(body.as_bytes())?;
            file.set_permissions(std::fs::Permissions::from_mode(mode))
        })
        .and_then(|()| std::fs::rename(&temporary, &target));
    match written {
        Ok(()) => ToolhostFrame::Done { id },
        Err(error) => {
            let _ = std::fs::remove_file(&temporary);
            io_failed(id, &format!("writing {path}"), &error)
        }
    }
}

/// `path` itself, or the file its final-component symlink resolves to.
fn resolve_link(path: &Path) -> std::io::Result<PathBuf> {
    match path.symlink_metadata() {
        Ok(meta) if meta.file_type().is_symlink() => std::fs::canonicalize(path),
        _ => Ok(path.to_path_buf()),
    }
}

/// `RemoveFile`: unlink the path.
pub(crate) fn remove(id: RequestId, path: &str) -> ToolhostFrame {
    match std::fs::remove_file(path) {
        Ok(()) => ToolhostFrame::Done { id },
        Err(error) => io_failed(id, &format!("removing {path}"), &error),
    }
}
