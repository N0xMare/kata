//! Configuration manager with ArcSwap-based hot-reload.
//!
//! `ConfigManager` loads a `KataConfig` from a TOML file and provides
//! lock-free reads via `ArcSwap`. The `watch` method spawns a background
//! task that uses the `notify` crate to detect file changes, re-parses and
//! validates the file, runs the reload contract ([`apply_reload`]: apply what
//! is hot, report what needs a restart) and swaps the config.

use std::io::Read as _;
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt as _;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use arc_swap::ArcSwap;
use notify::{Event as NotifyEvent, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use tokio::sync::{mpsc, watch};
use tracing::{info, warn};

use kata_types::config::{
    ApiAuthConfig, KataConfig, NormalizePaths, WorkerTransportConfig, parse_kata_config,
};
use kata_types::error::{KataError, KataResult};

use crate::config_reload::apply_reload;

/// Hard ceiling for one node configuration snapshot. Configuration is control
/// data, not a blob transport; a larger file is almost certainly accidental or
/// hostile and must not allocate unbounded startup/reload memory.
pub const MAX_CONFIG_FILE_BYTES: u64 = 4 * 1024 * 1024;

/// A replace-in-place editor may briefly remove the watched pathname before
/// publishing its replacement. Retry that transient gap locally, but keep the
/// watch task bounded so a permanently deleted configuration becomes
/// observable instead of waiting forever for an event that may never arrive.
const WATCH_MISSING_RETRY_ATTEMPTS: usize = 5;
const WATCH_MISSING_RETRY_DELAY: std::time::Duration = std::time::Duration::from_millis(20);

/// Lock-free, hot-reloadable configuration manager.
#[derive(Debug)]
pub struct ConfigManager {
    config: Arc<ArcSwap<KataConfig>>,
    path: PathBuf,
    /// BLAKE3 of the exact on-disk bytes parsed by [`Self::load`]. This is the
    /// boot-snapshot identity exposed by the installed main; it deliberately
    /// does not change when the watcher later observes restart-required edits.
    initial_content_digest: Option<String>,
    /// Exact bytes parsed into the initial validated snapshot. Kept behind a
    /// redacted debug wrapper so startup consumers that read their section out of
    /// the bytes rather than the parsed `KataConfig` (pricing) derive from the same
    /// read without reopening a replaceable path.
    initial_content: Option<InitialConfigContent>,
    /// Content hash of the raw config bytes that produced the config
    /// currently in `config`, or `None` when the manager was built from an
    /// in-memory config (`from_config`) with no on-disk bytes to hash.
    ///
    /// [`watch`](Self::watch) seeds its change-detection gate from this
    /// value rather than re-reading the file, so a change that lands in the
    /// window between [`load`](Self::load) and `watch()` can't be captured
    /// into the seed and then suppressed as a false no-op (the seed race).
    loaded_hash: Arc<Mutex<Option<u64>>>,
}

struct InitialConfigContent(Arc<str>);

impl std::fmt::Debug for InitialConfigContent {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("InitialConfigContent")
            .field("len", &self.0.len())
            .finish_non_exhaustive()
    }
}

impl ConfigManager {
    /// Load a `KataConfig` from the TOML file at `path`. Validates the
    /// config before accepting it.
    pub fn load(path: impl AsRef<Path>) -> KataResult<Self> {
        let supplied_path = path.as_ref();
        let path = supplied_path.canonicalize().map_err(|error| {
            KataError::Config(format!(
                "failed to resolve config {}: {error}",
                supplied_path.display()
            ))
        })?;
        let text = Self::read_text(&path)?;
        Self::from_initial_snapshot(path, text)
    }

    /// Build from the exact descriptor snapshot supplied by the native-service
    /// trampoline. The path remains the authority for relative-path resolution
    /// and future hot reload, but boot parsing never reopens it.
    pub fn load_initial_snapshot(path: impl AsRef<Path>, text: String) -> KataResult<Self> {
        let path = path.as_ref();
        if !path.is_absolute() {
            return Err(KataError::Config(format!(
                "installed config snapshot path must be absolute: {}",
                path.display()
            )));
        }
        Self::from_initial_snapshot(path.to_path_buf(), text)
    }

    fn from_initial_snapshot(path: PathBuf, text: String) -> KataResult<Self> {
        if u64::try_from(text.len()).unwrap_or(u64::MAX) > MAX_CONFIG_FILE_BYTES {
            return Err(KataError::Config(format!(
                "config snapshot exceeds the {MAX_CONFIG_FILE_BYTES}-byte safety bound"
            )));
        }
        // Hash the exact bytes we validate so `loaded_hash` and the stored
        // config are captured from a single read — no seed race with a
        // subsequent re-read.
        let hash = Self::content_hash(&text);
        let initial_content_digest = blake3::hash(text.as_bytes()).to_hex().to_string();
        let config = Self::parse_and_validate(&text, &path)?;
        Ok(Self {
            config: Arc::new(ArcSwap::new(Arc::new(config))),
            path,
            initial_content_digest: Some(initial_content_digest),
            initial_content: Some(InitialConfigContent(Arc::from(text))),
            loaded_hash: Arc::new(Mutex::new(Some(hash))),
        })
    }

    /// Create a `ConfigManager` from an already-loaded config (useful for
    /// tests or programmatic configuration).
    pub fn from_config(config: KataConfig, path: impl AsRef<Path>) -> Self {
        Self {
            config: Arc::new(ArcSwap::new(Arc::new(config))),
            path: path.as_ref().to_path_buf(),
            initial_content_digest: None,
            initial_content: None,
            // No on-disk bytes were read, so there's nothing to seed the
            // watch gate with; the first watch event reconciles against the
            // file (one harmless reload) rather than risk suppressing it.
            loaded_hash: Arc::new(Mutex::new(None)),
        }
    }

    /// Get a snapshot of the current configuration. The returned `Arc` is
    /// valid even if the config is subsequently reloaded.
    pub fn get(&self) -> arc_swap::Guard<Arc<KataConfig>> {
        self.config.load()
    }

    /// Snapshot the current config. Returns a cloned `Arc<KataConfig>`.
    #[must_use]
    pub fn snapshot(&self) -> Arc<KataConfig> {
        self.config.load_full()
    }

    /// Get a cloned `Arc` of the current configuration.
    #[cfg(any(test, feature = "test-support"))]
    pub fn get_arc(&self) -> Arc<KataConfig> {
        Arc::clone(&self.config.load_full())
    }

    /// Reference to the path the config was loaded from.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Digest of the exact bytes that produced the initial validated snapshot.
    /// `None` only for [`Self::from_config`], which has no on-disk source.
    #[must_use]
    pub fn initial_content_digest(&self) -> Option<&str> {
        self.initial_content_digest.as_deref()
    }

    /// Exact UTF-8 content that produced the initial validated snapshot.
    /// `None` only for [`Self::from_config`]. Consumers must use this instead of
    /// reopening [`Self::path`] during startup, because the path may have been
    /// atomically replaced after validation.
    #[must_use]
    pub fn initial_content(&self) -> Option<&str> {
        self.initial_content
            .as_ref()
            .map(|content| content.0.as_ref())
    }

    /// Handle to the underlying `ArcSwap` for consumers that want to
    /// observe future swaps.
    #[must_use]
    pub fn handle(&self) -> Arc<ArcSwap<KataConfig>> {
        Arc::clone(&self.config)
    }

    /// Manually trigger a reload from disk. Returns `Ok(true)` if the
    /// config was successfully reloaded, `Ok(false)` if the file was
    /// unchanged or invalid (logged but not propagated as an error).
    pub fn reload(&self) -> KataResult<bool> {
        let text = match Self::read_text(&self.path) {
            Ok(text) => text,
            Err(e) => {
                warn!(
                    path = %self.path.display(),
                    error = %e,
                    "config reload failed, keeping previous config"
                );
                return Ok(false);
            }
        };
        match Self::parse_and_validate(&text, &self.path) {
            Ok(new_config) => {
                self.config.store(Arc::new(new_config));
                // Keep the watch-gate seed in step with the config a later
                // `watch()` will start from.
                *self.loaded_hash.lock().expect("loaded_hash poisoned") =
                    Some(Self::content_hash(&text));
                info!(path = %self.path.display(), "config reloaded");
                Ok(true)
            }
            Err(e) => {
                warn!(
                    path = %self.path.display(),
                    error = %e,
                    "config reload failed, keeping previous config"
                );
                Ok(false)
            }
        }
    }

    /// Start watching the config file for changes. On every detected
    /// modification, re-reads and validates the config. If valid, runs
    /// [`apply_reload`] against the config it replaces — so every watcher
    /// applies the hot fields and reports the restart-required ones — then
    /// swaps it in.
    ///
    /// Returns a handle that keeps the watcher alive. Drop the handle to
    /// stop watching.
    ///
    /// # Crossing note
    /// Uses `notify` crate's `RecommendedWatcher` with a tokio mpsc
    /// channel bridge. The watcher thread is OS-native (inotify on Linux,
    /// kqueue on macOS, ReadDirectoryChanges on Windows). Events are
    /// forwarded to a tokio task for processing. If `notify` ever becomes
    /// problematic, a polling fallback (re-read on an interval) can
    /// replace the watcher without changing the public API.
    pub fn watch(&self) -> KataResult<WatchHandle> {
        let config = Arc::clone(&self.config);
        let loaded_hash = Arc::clone(&self.loaded_hash);
        let path = self.path.clone();

        // Bridge notify events into the tokio world via an mpsc channel.
        let (tx, mut rx) = mpsc::channel::<()>(4);

        let watch_path = path.clone();
        let event_tx = tx.clone();
        let mut watcher: RecommendedWatcher =
            notify::recommended_watcher(move |res: Result<NotifyEvent, notify::Error>| {
                match res {
                    Ok(event) => {
                        if matches!(
                            event.kind,
                            EventKind::Modify(_) | EventKind::Create(_) | EventKind::Remove(_)
                        ) {
                            // Non-blocking send; if the channel is full we
                            // coalesce (the receiver will re-read anyway).
                            let _ = event_tx.try_send(());
                        }
                    }
                    Err(e) => {
                        warn!(error = %e, "file watcher error");
                    }
                }
            })
            .map_err(|e| {
                KataError::Io(std::io::Error::other(format!("watcher init failed: {e}")))
            })?;

        // Watch the parent directory so we catch renames/recreations.
        let watch_dir = watch_path.parent().unwrap_or(Path::new(".")).to_path_buf();
        watcher
            .watch(&watch_dir, RecursiveMode::NonRecursive)
            .map_err(|e| KataError::Io(std::io::Error::other(format!("watch failed: {e}"))))?;

        // Registration has no retrospective event guarantee. Drive one
        // reconciliation only after the native watch is armed so bytes that
        // changed between `load()` and `watch()` cannot remain stale forever
        // when no later sibling event occurs. A concurrent native event may
        // coalesce with this signal; both mean “re-read current bytes.”
        let _ = tx.try_send(());

        // Content-hash change detection.
        //
        // The watcher fires on *any* event in the config file's parent
        // directory (we watch the dir, not the file, so atomic
        // rename/recreate saves are caught). Without a change gate, every
        // such event re-read/re-parsed/re-swapped/re-logged the config —
        // and because a node's own log stream is written into that same
        // directory, each reload's log lines re-triggered the watcher: a
        // self-sustaining feedback loop that spun at thousands of
        // reloads/sec, filling the disk and burning a core.
        //
        // The gate: hash the config file's raw bytes and only act when the
        // bytes actually changed since the last processed event. An
        // unchanged file (the common case for a sibling-file event) is a
        // cheap read + hash + early-continue — no parse, no swap, no log,
        // hence no new log writes, hence the loop cannot sustain itself.
        // `last_hash` is seeded from `loaded_hash` — the hash of the exact
        // bytes that produced the config currently in the ArcSwap — so the
        // immediate post-registration reconciliation is a no-op for unchanged
        // bytes and applies a change that landed between load() and watch().
        // The hash is advanced
        // for *every* distinct byte content — including content that fails
        // to parse — so a broken edit warns exactly once and a subsequent
        // fix (different bytes) reloads.
        let mut last_hash = *self.loaded_hash.lock().expect("loaded_hash poisoned");

        // Warn at most once per distinct *persistent* read-error kind. A
        // config that becomes permanently unreadable, is replaced by a
        // directory, or is deleted must be observable. The warn itself writes
        // a log line, so an unconditional per-event warn would re-arm the very
        // feedback loop the change-gate above exists to kill. Gating on error
        // kind bounds it to one line per failure mode; a later successful read
        // clears it. A short bounded retry below absorbs the transient
        // NotFound window of replace-in-place editors before it is classified
        // as persistent.
        let mut warned_read_err: Option<std::io::ErrorKind> = None;

        let (progress_tx, progress) = watch::channel(WatchProgress::default());
        let task = tokio::spawn(async move {
            while rx.recv().await.is_some() {
                let drained = 'drain: {
                    let text = match Self::read_text_after_watch_event(&path).await {
                        Ok(text) => {
                            warned_read_err = None;
                            text
                        }
                        // Persistent read failure. Warn once per kind so the
                        // operator can see it, then suppress. This includes a
                        // deletion that survives the bounded transient-miss
                        // retry: there is no promise that another filesystem
                        // event will arrive to make that state observable later.
                        Err(e) => {
                            let kind = e.kind();
                            if warned_read_err != Some(kind) {
                                warn!(
                                    path = %path.display(),
                                    error = %e,
                                    "config unreadable, keeping previous config"
                                );
                                warned_read_err = Some(kind);
                            }
                            break 'drain Drained::Unreadable;
                        }
                    };
                    let hash = Self::content_hash(&text);
                    if last_hash == Some(hash) {
                        // Unchanged bytes — the feedback-loop killer. No-op.
                        break 'drain Drained::Unchanged;
                    }
                    last_hash = Some(hash);

                    match Self::parse_and_validate(&text, &path) {
                        Ok(new_config) => {
                            // `apply_reload` logs each hot application and each
                            // restart-required field itself; this line claims only
                            // that the edit was accepted, never that it took effect.
                            let outcome = apply_reload(&config.load(), &new_config);
                            config.store(Arc::new(new_config));
                            *loaded_hash.lock().expect("loaded_hash poisoned") = Some(hash);
                            info!(
                                path = %path.display(),
                                applied = ?outcome.applied,
                                restart_required = ?outcome.restart_required,
                                failed = ?outcome.failed,
                                "config edit accepted",
                            );
                            Drained::Accepted
                        }
                        Err(e) => {
                            warn!(
                                path = %path.display(),
                                error = %e,
                                "config edit refused, keeping previous config"
                            );
                            Drained::Refused
                        }
                    }
                };
                progress_tx.send_modify(|progress| progress.record(drained));
            }
        });

        Ok(WatchHandle {
            _watcher: watcher,
            _task: task,
            progress,
        })
    }

    /// Read the raw config text from disk.
    fn read_text(path: &Path) -> KataResult<String> {
        Self::read_text_io(path)
            .map_err(|e| KataError::Config(format!("failed to read {}: {e}", path.display())))
    }

    fn read_text_io(path: &Path) -> std::io::Result<String> {
        let mut options = std::fs::OpenOptions::new();
        options.read(true);
        #[cfg(unix)]
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC);
        let mut file = options.open(path)?;
        let before = file.metadata()?;
        if !before.is_file() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "config source must be a regular file",
            ));
        }
        if before.len() > MAX_CONFIG_FILE_BYTES {
            return Err(std::io::Error::new(
                std::io::ErrorKind::FileTooLarge,
                format!("config exceeds the {MAX_CONFIG_FILE_BYTES}-byte safety bound"),
            ));
        }
        let mut bytes = Vec::new();
        (&mut file)
            .take(MAX_CONFIG_FILE_BYTES + 1)
            .read_to_end(&mut bytes)?;
        if bytes.len() as u64 > MAX_CONFIG_FILE_BYTES {
            return Err(std::io::Error::new(
                std::io::ErrorKind::FileTooLarge,
                format!("config grew beyond the {MAX_CONFIG_FILE_BYTES}-byte safety bound"),
            ));
        }
        let after = file.metadata()?;
        if !same_config_snapshot(&before, &after) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "config changed while being read",
            ));
        }
        let current = std::fs::symlink_metadata(path)?;
        if !current.is_file() || !same_config_file(&after, &current) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "config path was replaced while being read",
            ));
        }
        String::from_utf8(bytes).map_err(|error| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("config is not UTF-8: {error}"),
            )
        })
    }

    async fn read_text_after_watch_event(path: &Path) -> std::io::Result<String> {
        for attempt in 0..=WATCH_MISSING_RETRY_ATTEMPTS {
            match Self::read_text_io(path) {
                Err(error)
                    if error.kind() == std::io::ErrorKind::NotFound
                        && attempt < WATCH_MISSING_RETRY_ATTEMPTS =>
                {
                    tokio::time::sleep(WATCH_MISSING_RETRY_DELAY).await;
                }
                result => return result,
            }
        }
        unreachable!("bounded config read loop always returns")
    }

    /// Parse, normalize, and validate an already-read config text.
    ///
    /// Runs `normalize_paths` after deserialization so every
    /// subsequent subsystem sees tilde-free, absolute paths. The
    /// contract is documented on [`NormalizePaths`] itself — downstream
    /// code may assume `<cfg>.node.data_dir`, `vcs.jj_repo`, etc. never
    /// start with `~`.
    fn parse_and_validate(text: &str, path: &Path) -> KataResult<KataConfig> {
        let mut config = parse_kata_config(text, path)?;
        config.normalize_paths();
        resolve_config_relative_paths(&mut config, path)?;
        validate_main_owned_local_socket_paths(&config)?;
        config.validate()?;
        Ok(config)
    }

    /// Stable within-process hash of the config file's raw bytes, used by
    /// [`watch`](Self::watch) for change detection. Only compared against
    /// other hashes computed in the same process, so `DefaultHasher`'s
    /// fixed-key (non-seeded) determinism is sufficient — no cross-run or
    /// cross-host stability is required.
    fn content_hash(text: &str) -> u64 {
        use std::hash::{Hash, Hasher};
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        text.hash(&mut hasher);
        hasher.finish()
    }
}

#[cfg(unix)]
fn same_config_file(left: &std::fs::Metadata, right: &std::fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt as _;
    (left.dev(), left.ino()) == (right.dev(), right.ino())
}

#[cfg(not(unix))]
fn same_config_file(left: &std::fs::Metadata, right: &std::fs::Metadata) -> bool {
    left.len() == right.len()
}

#[cfg(unix)]
fn same_config_snapshot(left: &std::fs::Metadata, right: &std::fs::Metadata) -> bool {
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
fn same_config_snapshot(left: &std::fs::Metadata, right: &std::fs::Metadata) -> bool {
    left.len() == right.len() && left.modified().ok() == right.modified().ok()
}

fn validate_main_owned_local_socket_paths(config: &KataConfig) -> KataResult<()> {
    let mut paths = std::collections::HashSet::new();
    for transport in &config.workers.transports {
        let WorkerTransportConfig::LocalSocket { path } = transport else {
            continue;
        };
        if path.parent() != Some(config.node.data_dir.as_path()) {
            return Err(KataError::Config(format!(
                "local worker socket {} must be a direct child of node.data_dir {}; local capacity is owned by the locked main data directory",
                path.display(),
                config.node.data_dir.display()
            )));
        }
        // The directory's length never matters (the socket is addressed through its
        // parent's descriptor); the NAME's does, and is refused here so `kata serve`
        // and `kata doctor` name it before anything binds.
        kata_types::unix_socket_name::socket_file_name(path)
            .map_err(|refusal| KataError::Config(format!("local worker socket: {refusal}")))?;
        if !paths.insert(path.clone()) {
            return Err(KataError::Config(format!(
                "local worker socket path {} is configured more than once",
                path.display()
            )));
        }
    }
    Ok(())
}

/// Resolve every path-bearing main configuration field from the canonical
/// directory containing `kata.toml`. Process working directory is never an
/// input to installed-main identity, provider selection, credentials, or
/// service behavior.
fn resolve_config_relative_paths(config: &mut KataConfig, config_path: &Path) -> KataResult<()> {
    let base = config_path.parent().ok_or_else(|| {
        KataError::Config(format!(
            "config path has no parent directory: {}",
            config_path.display()
        ))
    })?;
    config.node.data_dir = resolve_relative(base, &config.node.data_dir);
    let data_dir = config.node.data_dir.clone();
    config.vcs.jj_repo = resolve_relative(base, &config.vcs.jj_repo);
    for transport in &mut config.workers.transports {
        match transport {
            WorkerTransportConfig::SupervisedNode {} => {}
            WorkerTransportConfig::LocalSocket { path } => {
                // Local worker listeners are main-owned runtime artifacts.
                // Resolve their relative names inside the locked data
                // directory so stale-socket cleanup can never target an
                // arbitrary path relative to the caller or config checkout.
                *path = resolve_relative(&data_dir, path);
            }
        }
    }
    if let ApiAuthConfig::SignedToken {
        verifying_key_file: Some(path),
        ..
    } = &mut config.api.auth
    {
        *path = resolve_relative(base, path);
    }
    Ok(())
}

fn resolve_relative(base: &Path, path: &Path) -> PathBuf {
    if path.is_absolute() {
        lexical_normalize(path)
    } else {
        lexical_normalize(&base.join(path))
    }
}

fn lexical_normalize(path: &Path) -> PathBuf {
    use std::path::Component;

    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                normalized.pop();
            }
            other => normalized.push(other.as_os_str()),
        }
    }
    normalized
}

/// Handle returned by `ConfigManager::watch`. Dropping this handle stops
/// the file watcher and the reload task.
pub struct WatchHandle {
    _watcher: RecommendedWatcher,
    _task: tokio::task::JoinHandle<()>,
    progress: watch::Receiver<WatchProgress>,
}

impl WatchHandle {
    /// What the reload task has done since it armed, republished after every
    /// change signal it drains — the completion signal a caller waits on instead
    /// of guessing how long the watcher takes.
    #[must_use]
    pub fn progress(&self) -> watch::Receiver<WatchProgress> {
        self.progress.clone()
    }
}

/// Counts of the change signals a [`WatchHandle`]'s task has drained, by what each
/// one found. Signals coalesce (a burst of filesystem events may drain as one), so
/// these count drains, not events; an edit is reflected by the time a drain that
/// read its bytes is counted.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct WatchProgress {
    /// Every drained signal, including the reconciliation `watch` sends on arming.
    pub drained: u64,
    /// Drains that found new bytes, validated them and swapped the config in.
    pub accepted: u64,
    /// Drains that found new bytes the config refused; the previous config stays.
    pub refused: u64,
    /// Drains that could not read the file; the previous config stays.
    pub unreadable: u64,
}

impl WatchProgress {
    fn record(&mut self, drained: Drained) {
        self.drained += 1;
        match drained {
            Drained::Accepted => self.accepted += 1,
            Drained::Refused => self.refused += 1,
            Drained::Unreadable => self.unreadable += 1,
            Drained::Unchanged => {}
        }
    }
}

/// What one drained change signal found.
#[derive(Clone, Copy, Debug)]
enum Drained {
    Accepted,
    Refused,
    Unreadable,
    /// The bytes the current config was loaded from: nothing to do.
    Unchanged,
}
