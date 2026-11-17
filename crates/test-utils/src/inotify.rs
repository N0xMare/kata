//! A kernel-side observer for "did anything open this file" — inotify,
//! watched from the test process, sharing no code with kata.
//!
//! The credential opt-in's cells assert that a path kata must not read was
//! never OPENED. Asking kata ("did you read it?") would be a mirror; the
//! kernel's own `IN_OPEN`/`IN_ACCESS` record is not. Measured before the cells
//! relied on it (python ctypes probe):
//!
//! * a successful `open` + `read` raises `IN_OPEN` and `IN_ACCESS` on the
//!   file's own watch AND on its parent directory's watch;
//! * `stat`/`lstat` raise nothing — so a `symlink_metadata` existence check is
//!   invisible here, which is what lets `kata doctor` report a login's
//!   presence without counting as a read;
//! * an `open` that FAILS (`EACCES` on a mode-000 file) raises NO `IN_OPEN` —
//!   so a cell must keep the watched file readable, or a refused open would
//!   look exactly like no open at all.
//!
//! Events are per-inode-watch and process-agnostic: a cell's own reads of a
//! watched path would count, so a cell arms the watch AFTER writing its
//! fixtures and does not read them back until it has drained.

use std::ffi::OsString;
use std::mem::MaybeUninit;
use std::os::fd::OwnedFd;
use std::path::{Path, PathBuf};

use rustix::fs::inotify;

/// One observed event — the watched path, the entry name for a directory
/// watch, and the raw mask.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Observed {
    /// The path the watch was armed on.
    pub watched: PathBuf,
    /// The directory entry the event names (directory watches only).
    pub name: Option<OsString>,
    /// The kernel's event mask.
    pub flags: inotify::ReadFlags,
}

impl Observed {
    /// Whether this event records an `open` of the watched path (or, on a
    /// directory watch, of an entry in it).
    #[must_use]
    pub fn opened(&self) -> bool {
        self.flags.contains(inotify::ReadFlags::OPEN)
    }

    /// Whether this event records the creation of the entry `name` in a
    /// watched directory.
    #[must_use]
    pub fn created(&self, name: &str) -> bool {
        self.flags.contains(inotify::ReadFlags::CREATE)
            && self.name.as_deref() == Some(std::ffi::OsStr::new(name))
    }
}

/// A non-blocking inotify instance over a fixed set of watched paths.
pub struct Watch {
    fd: OwnedFd,
    watches: Vec<(i32, PathBuf)>,
}

impl Watch {
    /// Watch every path in `paths` (files or directories) for `flags`.
    ///
    /// # Panics
    /// If inotify cannot be initialised or a path cannot be watched — a cell
    /// whose observer did not arm proves nothing, so it fails loudly.
    #[must_use]
    pub fn on(paths: &[&Path], flags: inotify::WatchFlags) -> Self {
        let fd = inotify::init(inotify::CreateFlags::NONBLOCK | inotify::CreateFlags::CLOEXEC)
            .expect("inotify_init1");
        let watches = paths
            .iter()
            .map(|path| {
                let wd = inotify::add_watch(&fd, *path, flags)
                    .unwrap_or_else(|error| panic!("inotify watch on {}: {error}", path.display()));
                (wd, path.to_path_buf())
            })
            .collect();
        Self { fd, watches }
    }

    /// Watch for anything OPENING or READING `paths` — `IN_OPEN | IN_ACCESS`.
    #[must_use]
    pub fn opens_of(paths: &[&Path]) -> Self {
        Self::on(
            paths,
            inotify::WatchFlags::OPEN | inotify::WatchFlags::ACCESS,
        )
    }

    /// Watch `dir` for entries being created in it — `IN_CREATE`.
    #[must_use]
    pub fn creates_in(dir: &Path) -> Self {
        Self::on(&[dir], inotify::WatchFlags::CREATE)
    }

    /// Every event queued since the last drain, in kernel order.
    ///
    /// # Panics
    /// On a read error other than "nothing queued".
    #[must_use]
    pub fn drain(&self) -> Vec<Observed> {
        let mut buf = [MaybeUninit::<u8>::uninit(); 8192];
        let mut reader = inotify::Reader::new(&self.fd, &mut buf);
        let mut out = Vec::new();
        loop {
            match reader.next() {
                Ok(event) => {
                    let watched = self
                        .watches
                        .iter()
                        .find(|(wd, _)| *wd == event.wd())
                        .map_or_else(PathBuf::new, |(_, path)| path.clone());
                    let name = event.file_name().map(|name| {
                        use std::os::unix::ffi::OsStrExt as _;
                        std::ffi::OsStr::from_bytes(name.to_bytes()).to_os_string()
                    });
                    out.push(Observed {
                        watched,
                        name,
                        flags: event.events(),
                    });
                }
                Err(rustix::io::Errno::AGAIN) => return out,
                Err(error) => panic!("inotify read: {error}"),
            }
        }
    }
}
