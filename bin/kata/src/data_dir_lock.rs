//! Crash-safe, process-wide authority lock for a Kata main data directory.
//!
//! A PID file is useful diagnostics but cannot establish exclusive authority:
//! checking a PID and then writing a file is racy, process names can be reused,
//! and stale-file cleanup after a crash is guesswork. [`DataDirLock`] instead
//! holds a kernel advisory lock for the entire main lifetime. The kernel drops
//! it on process death, including `SIGKILL`; metadata in the lock file is only
//! an operator-readable description of the current or most recent holder.

use std::fs::{File, OpenOptions};
use std::io::{Read as _, Seek as _, SeekFrom, Write as _};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use kata_core::store::{CasStore, SqliteNativeMemoryStore, SqliteWorkflowStore};
use kata_core::{DurableEventLog, IdempotencyStore, InFlightLedger, OperationalDb};
use kata_types::KataConfig;
use kata_types::config::WorkerTransportConfig;
use nix::errno::Errno;
use nix::fcntl::{Flock, FlockArg};
use serde::{Deserialize, Serialize};
use ulid::Ulid;

use crate::attachment::InstalledDiscoveryLease;
use crate::authority_file::{
    AuthorityFilePolicy, MAX_DATA_DIRECTORY_IDENTITY_BYTES, normalize_new_owner_only_file,
    read_bounded_file,
};

const IDENTITY_FILE: &str = "main-identity.json";
const LOCK_FILE: &str = "main.lock";
const MAX_MAIN_LOCK_METADATA_BYTES: u64 = 64 * 1024;
/// The data-directory format generation this binary initializes and accepts.
///
/// An identity at any other generation is refused before a lock or store is
/// touched (`validate_identity`), with the new-empty-data-directory recourse: a
/// directory is never upgraded in place.
const FORMAT_GENERATION: u32 = 7;
const INITIALIZED_ENGINE_FILES: &[&str] = &[
    "ledger_events.db",
    "operational.db",
    "idempotency.db",
    "memory.db",
    "stage_cache.db",
    "cas.db",
];
const REQUIRED_AUTHORITY_FILES: &[&str] = &[
    "ledger_events.db",
    "operational.db",
    "idempotency.db",
    "memory.db",
    "cas.db",
];

/// Resolve a configured data directory using the config file, rather than the
/// caller's current working directory, as the base for relative paths.  Service
/// and foreground launch must derive exactly the same authority path.
pub fn resolve_config_data_dir(config_path: &Path, configured: &Path) -> Result<PathBuf> {
    if configured.is_absolute() {
        return Ok(configured.to_path_buf());
    }
    let config = config_path
        .canonicalize()
        .with_context(|| format!("canonicalizing Kata config {}", config_path.display()))?;
    let parent = config
        .parent()
        .ok_or_else(|| anyhow::anyhow!("Kata config has no parent: {}", config.display()))?;
    Ok(lexically_normalize(&parent.join(configured)))
}

/// Product mode holding the data-directory authority lock.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MainMode {
    /// The operator's installed, durable main authority.
    Installed,
    /// A deleted scratch main's identity (`kata mcp --scratch`), read off disk
    /// only: no command creates one, and an installed main refuses the
    /// directory it left by this mode.
    Scratch,
}

/// Immutable identity stored inside every initialized main data directory.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DataDirIdentity {
    pub directory_id: String,
    pub format_generation: u32,
    pub mode: MainMode,
}

/// Non-authoritative diagnostics written after the kernel lock is acquired.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MainLockMetadata {
    pub directory_id: String,
    pub format_generation: u32,
    pub mode: MainMode,
    pub pid: u32,
    pub started_at_unix_ms: u64,
    pub boot_id: Option<String>,
    pub process_generation: String,
    pub binary_version: String,
    pub control_endpoint: Option<String>,
}

/// Exclusive lifetime authority for one canonical data directory.
///
/// The locked file is deliberately the last field so ordinary diagnostic
/// fields are dropped before authority is released.
#[derive(Debug)]
pub struct DataDirLock {
    canonical_data_dir: PathBuf,
    identity: DataDirIdentity,
    metadata: MainLockMetadata,
    _lock: Flock<File>,
}

/// Installed data-directory authority tied to the per-owner discovery lease.
///
/// The lifetime is not decorative: Rust will not permit the discovery lease
/// to be dropped while this guard exists. A running main therefore cannot
/// release the one-per-owner authority while it still holds a durable store,
/// and maintenance commands must establish the same discovery exclusion before
/// taking the data-directory writer lock.
#[derive(Debug)]
pub(crate) struct InstalledDataDirLock<'lease> {
    inner: DataDirLock,
    _discovery_lease: std::marker::PhantomData<&'lease InstalledDiscoveryLease>,
}

/// Exclusive writer authority for extracting an incomplete data snapshot into
/// an identity-less offline directory. It deliberately publishes neither a
/// runtime identity nor clean stores: a data snapshot is not a bootable-node
/// recovery artifact.
#[derive(Debug)]
pub(crate) struct OfflineRestoreLock<'lease> {
    canonical_data_dir: PathBuf,
    _lock: Flock<File>,
    _discovery_lease: std::marker::PhantomData<&'lease InstalledDiscoveryLease>,
}

impl<'lease> OfflineRestoreLock<'lease> {
    pub(crate) fn acquire(
        _discovery_lease: &'lease InstalledDiscoveryLease,
        data_dir: &Path,
    ) -> Result<Self> {
        reject_final_symlink(data_dir)?;
        std::fs::create_dir_all(data_dir)
            .with_context(|| format!("creating offline restore target {}", data_dir.display()))?;
        reject_final_symlink(data_dir)?;
        let canonical_data_dir = data_dir.canonicalize().with_context(|| {
            format!(
                "canonicalizing offline restore target {}",
                data_dir.display()
            )
        })?;
        refuse_identified_restore_target(&canonical_data_dir)?;

        let lock_path = canonical_data_dir.join(LOCK_FILE);
        let file = open_lock_file(&lock_path)
            .with_context(|| format!("opening offline restore lock {}", lock_path.display()))?;
        let lock = match Flock::lock(file, FlockArg::LockExclusiveNonblock) {
            Ok(lock) => lock,
            Err((_file, Errno::EWOULDBLOCK)) => bail!(
                "offline restore target {} is already locked; stop the main or concurrent maintenance operation before restoring",
                canonical_data_dir.display()
            ),
            Err((_file, errno)) => bail!(
                "Kata cannot establish the required exclusive restore lock on {}: {errno}",
                lock_path.display()
            ),
        };
        verify_lock_contention(&lock_path)?;
        // Close the pre-lock check/replacement window without writing identity
        // or lock metadata.
        refuse_identified_restore_target(&canonical_data_dir)?;
        Ok(Self {
            canonical_data_dir,
            _lock: lock,
            _discovery_lease: std::marker::PhantomData,
        })
    }

    pub(crate) fn data_dir(&self) -> &Path {
        &self.canonical_data_dir
    }

    /// The only identity publication door for verified clone extraction.
    /// Ordinary identity-less startup remains a refusal on every crash residue.
    pub(crate) fn activate_verified_import(
        &self,
        verified: &kata_core::store::backup::VerifiedRecoveryArtifact,
        mode: MainMode,
        deadline: std::time::Instant,
        verify_rebindings: impl FnOnce(&Path, &str) -> Result<()>,
    ) -> Result<DataDirIdentity> {
        let data_dir = self.data_dir();
        refuse_identified_restore_target(data_dir)?;
        let identity = DataDirIdentity {
            directory_id: Ulid::new().to_string(),
            format_generation: FORMAT_GENERATION,
            mode,
        };
        verify_rebindings(data_dir, &identity.directory_id)?;
        let prepared = kata_core::store::backup::prepare_clone_import(
            data_dir,
            verified,
            &identity.directory_id,
            deadline,
        )?;
        if prepared.data_dir() != data_dir
            || prepared.target_directory_id() != identity.directory_id
        {
            bail!("verified import preparation belongs to another target");
        }
        preflight_clean_installed_engine(data_dir)?;
        validate_clean_engine_store_set(data_dir)?;
        #[cfg(test)]
        if test_startup_fault("data_dir_lock.import_before_identity") {
            bail!("injected failure after import quarantine before identity publication");
        }
        refuse_identified_restore_target(data_dir)?;
        let temporary = data_dir.join(format!(".main-identity-{}.tmp", Ulid::new()));
        let mut file = open_identity_for_create(&temporary)?;
        normalize_new_owner_only_file(&file, &temporary, "verified clone identity temporary")?;
        let mut bytes = serde_json::to_vec_pretty(&identity)?;
        bytes.push(b'\n');
        file.write_all(&bytes)?;
        file.sync_all()?;
        drop(file);
        std::fs::rename(&temporary, data_dir.join(IDENTITY_FILE))?;
        sync_directory(data_dir)?;
        Ok(identity)
    }
}

fn refuse_identified_restore_target(data_dir: &Path) -> Result<()> {
    let identity = data_dir.join(IDENTITY_FILE);
    match std::fs::symlink_metadata(&identity) {
        Ok(_) => bail!(
            "offline data-snapshot restore refuses identified runtime directory {}; use a separate empty target and preserve both directories offline",
            data_dir.display()
        ),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).with_context(|| format!("inspect {}", identity.display())),
    }
}

impl<'lease> InstalledDataDirLock<'lease> {
    pub(crate) fn acquire(
        _discovery_lease: &'lease InstalledDiscoveryLease,
        data_dir: &Path,
        control_endpoint: Option<String>,
    ) -> Result<Self> {
        DataDirLock::acquire_inner(data_dir, MainMode::Installed, control_endpoint, None)
            .map(Self::from_inner)
    }

    /// Acquire an already-installed data directory only when its immutable
    /// identity still matches the service definition.
    ///
    /// Unlike [`Self::acquire`], this path never creates the directory or its
    /// identity. The comparison is performed while holding the authority lock
    /// and before Kata writes lock metadata or opens any durable store.
    pub(crate) fn acquire_expected(
        _discovery_lease: &'lease InstalledDiscoveryLease,
        data_dir: &Path,
        control_endpoint: Option<String>,
        expected_directory_id: &str,
    ) -> Result<Self> {
        if expected_directory_id.is_empty() {
            bail!("installed service definition has an empty data-directory identity");
        }
        DataDirLock::acquire_inner(
            data_dir,
            MainMode::Installed,
            control_endpoint,
            Some(expected_directory_id),
        )
        .map(Self::from_inner)
    }

    fn from_inner(inner: DataDirLock) -> Self {
        Self {
            inner,
            _discovery_lease: std::marker::PhantomData,
        }
    }
}

impl std::ops::Deref for InstalledDataDirLock<'_> {
    type Target = DataDirLock;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl DataDirLock {
    /// Initialize or open `data_dir`, reject a final-component symlink, and
    /// acquire its exclusive kernel lock without blocking.
    ///
    /// No caller may open a durable Kata store, perform a migration, spawn a
    /// provider child, or bind a control socket before this succeeds.
    #[cfg(test)]
    pub(crate) fn acquire(
        data_dir: &Path,
        mode: MainMode,
        control_endpoint: Option<String>,
    ) -> Result<Self> {
        Self::acquire_inner(data_dir, mode, control_endpoint, None)
    }

    #[cfg(any(test, feature = "test-support"))]
    pub(crate) fn initialize_installed_for_test(data_dir: &Path) -> Result<Self> {
        Self::acquire_inner(data_dir, MainMode::Installed, None, None)
    }

    fn acquire_inner(
        data_dir: &Path,
        mode: MainMode,
        control_endpoint: Option<String>,
        expected_directory_id: Option<&str>,
    ) -> Result<Self> {
        reject_final_symlink(data_dir)?;
        if expected_directory_id.is_some() && !data_dir.exists() {
            bail!(
                "installed service data directory {} no longer exists; refusing to recreate an installed authority",
                data_dir.display()
            );
        }
        if expected_directory_id.is_none() {
            std::fs::create_dir_all(data_dir).with_context(|| {
                format!("creating Kata main data directory {}", data_dir.display())
            })?;
        }
        reject_final_symlink(data_dir)?;

        let canonical_data_dir = data_dir.canonicalize().with_context(|| {
            format!(
                "canonicalizing Kata main data directory {}",
                data_dir.display()
            )
        })?;
        let identity_path = canonical_data_dir.join(IDENTITY_FILE);
        // Refuse a non-current format before even creating/opening the per-directory
        // lock file. Re-read under the acquired lock below for current identities;
        // this early read exists so a clean-break refusal leaves the old directory
        // byte-for-byte untouched.
        if identity_path.exists() {
            inspect_identity(&canonical_data_dir)?
                .expect("identity path exists after successful inspection");
            preflight_clean_installed_engine(&canonical_data_dir)?;
        }
        if !identity_path.exists() {
            refuse_identityless_residue(&canonical_data_dir)?;
        }
        let lock_path = canonical_data_dir.join(LOCK_FILE);
        let file = open_lock_file(&lock_path)
            .with_context(|| format!("opening main authority lock {}", lock_path.display()))?;

        let mut lock = match Flock::lock(file, FlockArg::LockExclusiveNonblock) {
            Ok(lock) => lock,
            Err((mut file, Errno::EWOULDBLOCK)) => {
                let mut current = String::new();
                let _ = std::io::Read::by_ref(&mut file)
                    .take(MAX_MAIN_LOCK_METADATA_BYTES + 1)
                    .read_to_string(&mut current);
                if u64::try_from(current.len()).unwrap_or(u64::MAX) > MAX_MAIN_LOCK_METADATA_BYTES {
                    current.clear();
                    current.push_str("<holder metadata exceeds safety bound>");
                }
                let holder = current.trim();
                bail!(
                    "Kata main data directory {} is already locked by another process{}; attach to that installed main or stop it before retrying",
                    canonical_data_dir.display(),
                    if holder.is_empty() {
                        String::new()
                    } else {
                        format!("; diagnostic holder metadata: {holder}")
                    }
                );
            }
            Err((_file, errno)) => {
                bail!(
                    "Kata cannot establish the required exclusive lock on {}: {errno}; this filesystem/host does not provide usable main-authority lock semantics",
                    lock_path.display()
                );
            }
        };

        // Fail closed if this filesystem does not make a second independent
        // open contend with the lock we just acquired. This catches the most
        // dangerous class of silently ineffective advisory-lock mounts.
        verify_lock_contention(&lock_path)?;
        if !identity_path.exists() {
            refuse_identityless_residue(&canonical_data_dir)?;
        }
        let identity = if let Some(expected) = expected_directory_id {
            let identity = inspect_identity(&canonical_data_dir)?.ok_or_else(|| {
                anyhow::anyhow!(
                    "installed service data directory {} is missing its immutable identity; refusing to initialize or open durable stores",
                    canonical_data_dir.display()
                )
            })?;
            if identity.mode != MainMode::Installed {
                bail!(
                    "installed service data directory {} has {:?} identity; refusing to reinterpret it as installed",
                    canonical_data_dir.display(),
                    identity.mode
                );
            }
            if identity.directory_id != expected {
                bail!(
                    "installed service data-directory identity changed (definition {expected}, locked {}); refusing before writing authority metadata or opening durable stores",
                    identity.directory_id
                );
            }
            preflight_clean_installed_engine(&canonical_data_dir)?;
            identity
        } else {
            load_or_initialize_identity(&canonical_data_dir, mode)?
        };
        // Repeat the immutable probes while holding the directory lock. The
        // pre-lock pass protects retired/current data from lock-metadata
        // mutation; this pass closes replacement races before publication.
        preflight_clean_installed_engine(&canonical_data_dir)?;
        validate_clean_engine_store_set(&canonical_data_dir)?;

        let metadata = MainLockMetadata {
            directory_id: identity.directory_id.clone(),
            format_generation: identity.format_generation,
            mode,
            pid: std::process::id(),
            started_at_unix_ms: kata_types::time::now_ms(),
            boot_id: host_boot_id(),
            process_generation: Ulid::new().to_string(),
            binary_version: env!("CARGO_PKG_VERSION").to_string(),
            control_endpoint,
        };
        let encoded = serde_json::to_vec(&metadata).context("serializing main lock metadata")?;
        lock.set_len(0)
            .with_context(|| format!("truncating main lock metadata {}", lock_path.display()))?;
        lock.seek(SeekFrom::Start(0))
            .with_context(|| format!("seeking main lock metadata {}", lock_path.display()))?;
        #[cfg(test)]
        inject_startup_enospc("data_dir_lock.enospc.lock_metadata")
            .map_err(|error| authority_write_error("writing", &lock_path, error))?;
        lock.write_all(&encoded)
            .map_err(|error| authority_write_error("writing", &lock_path, error))?;
        lock.write_all(b"\n")
            .map_err(|error| authority_write_error("finishing", &lock_path, error))?;
        lock.sync_data()
            .map_err(|error| authority_write_error("syncing", &lock_path, error))?;

        Ok(Self {
            canonical_data_dir,
            identity,
            metadata,
            _lock: lock,
        })
    }

    /// Canonical data-directory path whose `main.lock` this guard owns.
    ///
    /// Callers must derive every durable path used after acquisition from
    /// this value, not from the spelling originally supplied by config or the
    /// CLI. A parent symlink can otherwise be retargeted after the lock is
    /// acquired and make the protected directory differ from the one opened.
    #[must_use]
    pub fn data_dir(&self) -> &Path {
        &self.canonical_data_dir
    }

    /// Bind a validated boot snapshot to the directory this guard actually
    /// locked.
    ///
    /// `node.data_dir` may contain a symlink in an ancestor component. The
    /// directory itself is canonicalized before `main.lock` is acquired, but
    /// continuing to open stores through the original spelling would let that
    /// ancestor be retargeted after acquisition. Local-worker sockets are
    /// main-owned direct children of the same directory, so they must move with
    /// the bound root as one authority unit.
    pub fn bind_config(&self, config: &mut KataConfig) -> Result<()> {
        let configured_data_dir = config.node.data_dir.clone();
        for transport in &mut config.workers.transports {
            let WorkerTransportConfig::LocalSocket { path } = transport else {
                continue;
            };
            if path.parent() != Some(configured_data_dir.as_path()) {
                bail!(
                    "local worker socket {} is not a direct child of configured data directory {}; refusing to rebind an invalid boot snapshot",
                    path.display(),
                    configured_data_dir.display()
                );
            }
            let file_name = path.file_name().ok_or_else(|| {
                anyhow::anyhow!(
                    "local worker socket {} has no filename; refusing to rebind an invalid boot snapshot",
                    path.display()
                )
            })?;
            *path = self.canonical_data_dir.join(file_name);
        }
        config.node.data_dir.clone_from(&self.canonical_data_dir);
        Ok(())
    }

    #[must_use]
    pub fn identity(&self) -> &DataDirIdentity {
        &self.identity
    }

    #[must_use]
    pub fn metadata(&self) -> &MainLockMetadata {
        &self.metadata
    }
}

fn host_boot_id() -> Option<String> {
    #[cfg(target_os = "linux")]
    {
        std::fs::read_to_string("/proc/sys/kernel/random/boot_id")
            .ok()
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty())
    }
    #[cfg(target_os = "macos")]
    {
        macos_boot_id()
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        None
    }
}

#[cfg(target_os = "macos")]
#[allow(unsafe_code)]
fn macos_boot_id() -> Option<String> {
    let mut value = std::mem::MaybeUninit::<libc::timeval>::uninit();
    let mut size = std::mem::size_of::<libc::timeval>();
    // SAFETY: `kern.boottime` returns one fixed `timeval`; the output buffer
    // and size pointer are valid for the call and the value is assumed
    // initialized only after sysctlbyname reports success and the exact size.
    let result = unsafe {
        libc::sysctlbyname(
            c"kern.boottime".as_ptr(),
            value.as_mut_ptr().cast(),
            &mut size,
            std::ptr::null_mut(),
            0,
        )
    };
    if result != 0 || size != std::mem::size_of::<libc::timeval>() {
        return None;
    }
    // SAFETY: the successful exact-size sysctl call initialized `value`.
    let value = unsafe { value.assume_init() };
    Some(format!("{}:{}", value.tv_sec, value.tv_usec))
}

/// Read an existing immutable directory identity without creating or locking
/// the directory. Service preview uses this to reject scratch state.
pub fn inspect_identity(data_dir: &Path) -> Result<Option<DataDirIdentity>> {
    let path = data_dir.join(IDENTITY_FILE);
    match read_identity_bytes(&path) {
        Ok(bytes) => {
            let identity = serde_json::from_slice(&bytes)
                .with_context(|| format!("parsing data-directory identity {}", path.display()))?;
            validate_identity(&identity, &path)?;
            Ok(Some(identity))
        }
        Err(error) if is_not_found(&error) => Ok(None),
        Err(error) => Err(error),
    }
}

/// Read bounded non-authoritative holder diagnostics without creating or
/// acquiring the main lock. The kernel lock remains authority; malformed,
/// unsafe, racing, or oversized metadata is an explicit diagnostic failure.
pub fn inspect_lock_metadata(data_dir: &Path) -> Result<Option<MainLockMetadata>> {
    let path = data_dir.join(LOCK_FILE);
    match read_bounded_file(
        &path,
        AuthorityFilePolicy::owner_only(
            "main authority lock metadata",
            MAX_MAIN_LOCK_METADATA_BYTES,
        ),
    ) {
        Ok(bytes) => serde_json::from_slice(&bytes)
            .with_context(|| format!("parsing main lock metadata {}", path.display()))
            .map(Some),
        Err(error) if is_not_found(&error) => Ok(None),
        Err(error) => Err(error),
    }
}

fn reject_final_symlink(path: &Path) -> Result<()> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => bail!(
            "Kata main data directory {} is a symlink; use the canonical directory itself so one spelling cannot create a second authority",
            path.display()
        ),
        Ok(_) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error)
            .with_context(|| format!("inspecting Kata main data directory {}", path.display())),
    }
}

fn load_or_initialize_identity(data_dir: &Path, mode: MainMode) -> Result<DataDirIdentity> {
    let path = data_dir.join(IDENTITY_FILE);
    match read_identity_bytes(&path) {
        Ok(bytes) => {
            let identity: DataDirIdentity = serde_json::from_slice(&bytes).with_context(|| {
                format!(
                    "parsing immutable data-directory identity {}",
                    path.display()
                )
            })?;
            validate_identity(&identity, &path)?;
            if identity.mode != mode {
                bail!(
                    "Kata data directory {} was initialized for {:?} mode and cannot be opened as {:?}; scratch and installed-main authority never share a data directory",
                    path.display(),
                    identity.mode,
                    mode
                );
            }
            Ok(identity)
        }
        Err(error) if is_not_found(&error) => {
            refuse_identityless_residue(data_dir)?;
            // Generation 2's identity is the readiness commit for this
            // fixed store set. Constructors run under the data-directory
            // lock and perform no workflow/model/effect activity. If any
            // step fails, no identity is published; the partial non-empty
            // directory is deliberately refused on retry and preserved for
            // diagnosis.
            initialize_clean_installed_engine(data_dir)?;
            preflight_clean_installed_engine(data_dir)?;
            #[cfg(test)]
            if test_startup_fault("data_dir_lock.after_store_init_before_identity") {
                bail!(
                    "injected startup failure after clean store initialization and before identity publication"
                );
            }
            let identity = DataDirIdentity {
                directory_id: Ulid::new().to_string(),
                format_generation: FORMAT_GENERATION,
                mode,
            };
            let temporary = data_dir.join(format!(".main-identity-{}.tmp", Ulid::new()));
            let mut file = open_identity_for_create(&temporary).with_context(|| {
                format!(
                    "creating temporary data-directory identity {}",
                    temporary.display()
                )
            })?;
            normalize_new_owner_only_file(
                &file,
                &temporary,
                "immutable data-directory identity temporary",
            )?;
            let mut encoded = serde_json::to_vec_pretty(&identity)
                .context("serializing data-directory identity")?;
            encoded.push(b'\n');
            file.write_all(&encoded).with_context(|| {
                format!("writing data-directory identity {}", temporary.display())
            })?;
            file.sync_all().with_context(|| {
                format!("syncing data-directory identity {}", temporary.display())
            })?;
            drop(file);
            std::fs::rename(&temporary, &path).with_context(|| {
                format!(
                    "publishing immutable data-directory identity {} -> {}",
                    temporary.display(),
                    path.display()
                )
            })?;
            sync_directory(data_dir)?;
            Ok(identity)
        }
        Err(error) => Err(error),
    }
}

fn initialize_clean_installed_engine(data_dir: &Path) -> Result<()> {
    drop(
        InFlightLedger::open_at(&data_dir.join("ledger_events.db"))
            .context("initialize clean ledger_events.db")?,
    );
    drop(
        OperationalDb::open(data_dir.join("operational.db"))
            .context("initialize clean operational.db")?,
    );
    drop(
        IdempotencyStore::open(data_dir.join("idempotency.db"))
            .context("initialize clean idempotency.db")?,
    );
    drop(
        SqliteNativeMemoryStore::open(data_dir.join("memory.db"))
            .context("initialize clean memory.db")?,
    );
    drop(
        SqliteWorkflowStore::open(data_dir.join("stage_cache.db"))
            .context("initialize clean stage-cache/CAS store set")?,
    );
    std::fs::create_dir(data_dir.join("recovery-evidence"))
        .context("initialize authoritative imported recovery evidence root")?;
    validate_clean_engine_store_set(data_dir)
        .context("validate the freshly initialized clean engine store set")?;
    for name in INITIALIZED_ENGINE_FILES {
        kata_core::store::sqlite_backed::checkpoint_and_sync_initialized_file(
            &data_dir.join(name),
            name,
        )
        .with_context(|| format!("durably publish initialized {name}"))?;
    }
    sync_directory(data_dir).context("sync clean engine store-set directory")
}

pub(crate) fn preflight_clean_installed_engine(data_dir: &Path) -> Result<()> {
    // First, ahead of every probe below and every store open: a database this binary
    // does not declare is refused with nothing touched.
    kata_core::durable_assets::refuse_undeclared_databases(data_dir)?;
    let mut missing = Vec::new();
    for name in REQUIRED_AUTHORITY_FILES {
        let path = data_dir.join(name);
        match std::fs::symlink_metadata(&path) {
            Ok(metadata) if metadata.file_type().is_file() => {}
            Ok(_) => bail!(
                "clean engine authority {} is not a regular file; refusing before metadata or store mutation",
                path.display()
            ),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => missing.push(*name),
            Err(error) => return Err(error).with_context(|| format!("inspect {}", path.display())),
        }
    }
    for (name, missing_name) in [("cas", "cas/"), ("recovery-evidence", "recovery-evidence/")] {
        let tree = data_dir.join(name);
        match std::fs::symlink_metadata(&tree) {
            Ok(metadata) if metadata.file_type().is_dir() => {}
            Ok(_) => bail!(
                "clean engine authority {} is not a directory; refusing before metadata or store mutation",
                tree.display()
            ),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                missing.push(missing_name);
            }
            Err(error) => {
                return Err(error).with_context(|| format!("inspect {}", tree.display()));
            }
        }
    }
    if !missing.is_empty() {
        bail!(
            "clean engine restart is missing required authority asset(s): {}; refusing to create empty replacements",
            missing.join(", ")
        );
    }

    OperationalDb::refuse_noncurrent_file_schema(data_dir.join("operational.db"))?;
    DurableEventLog::refuse_noncurrent_file_schema(data_dir.join("ledger_events.db"))?;
    SqliteNativeMemoryStore::refuse_noncurrent_file_schema(data_dir.join("memory.db"))?;
    IdempotencyStore::refuse_noncurrent_file_schema(data_dir.join("idempotency.db"))?;
    CasStore::refuse_noncurrent_file_schema(data_dir.join("cas.db"))?;
    Ok(())
}

fn validate_clean_engine_store_set(data_dir: &Path) -> Result<()> {
    drop(
        InFlightLedger::open_at(&data_dir.join("ledger_events.db"))
            .context("validate clean ledger_events.db")?,
    );
    drop(
        OperationalDb::open(data_dir.join("operational.db"))
            .context("validate clean operational.db")?,
    );
    drop(
        IdempotencyStore::open(data_dir.join("idempotency.db"))
            .context("validate clean idempotency.db")?,
    );
    drop(
        SqliteNativeMemoryStore::open(data_dir.join("memory.db"))
            .context("validate clean memory.db")?,
    );
    drop(
        SqliteWorkflowStore::open(data_dir.join("stage_cache.db"))
            .context("validate clean stage-cache/CAS store set")?,
    );
    Ok(())
}

/// Refuse an identity this binary did not write, with the recourse named: the
/// directory is preserved, never migrated.
fn validate_identity(identity: &DataDirIdentity, path: &Path) -> Result<()> {
    if identity.directory_id.is_empty() || identity.format_generation != FORMAT_GENERATION {
        bail!(
            "invalid Kata data-directory identity {}: expected non-empty directory_id and \
             format_generation={FORMAT_GENERATION}. Use a new empty data directory and \
             preserve this directory offline",
            path.display()
        );
    }
    Ok(())
}
#[cfg(test)]
mod tests;

/// Refuse every identity-less directory entry except the live authority-lock
/// inode. A current-format identity is published last, so any other entry proves
/// this is not a pristine initialization target. The entry stays an `OsString`
/// in the diagnostic so non-UTF-8 names are neither hidden nor normalized.
#[allow(
    clippy::unnecessary_debug_formatting,
    reason = "escape untrusted and non-UTF-8 residue names in the refusal diagnostic"
)]
fn refuse_identityless_residue(data_dir: &Path) -> Result<()> {
    for entry in std::fs::read_dir(data_dir).with_context(|| {
        format!(
            "inspecting identity-less data directory {}",
            data_dir.display()
        )
    })? {
        let entry = entry.with_context(|| {
            format!(
                "reading identity-less data-directory entry in {}",
                data_dir.display()
            )
        })?;
        let name = entry.file_name();
        if name == std::ffi::OsStr::new(LOCK_FILE) {
            continue;
        }
        bail!(
            "Kata data directory {} has no clean-format main identity and contains preserved entry {:?}; refusing to reinterpret retired, interrupted, or foreign state. Use a new empty directory and preserve this one offline.",
            data_dir.display(),
            name
        );
    }
    Ok(())
}

fn lexically_normalize(path: &Path) -> PathBuf {
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

fn sync_directory(path: &Path) -> Result<()> {
    File::open(path)
        .with_context(|| format!("opening data directory {} for sync", path.display()))?
        .sync_all()
        .with_context(|| format!("syncing data directory {}", path.display()))
}

fn open_lock_file(path: &Path) -> Result<File> {
    let mut options = OpenOptions::new();
    options.create_new(true).read(true).write(true);
    owner_only(&mut options);
    no_follow(&mut options);
    nonblocking_cloexec(&mut options);
    let (file, created) = match options.open(path) {
        Ok(file) => (file, true),
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            let mut existing = OpenOptions::new();
            existing.read(true).write(true);
            no_follow(&mut existing);
            nonblocking_cloexec(&mut existing);
            (
                existing.open(path).with_context(|| {
                    format!("opening existing main authority lock {}", path.display())
                })?,
                false,
            )
        }
        Err(error) => {
            return Err(error)
                .with_context(|| format!("creating main authority lock {}", path.display()));
        }
    };
    if created {
        set_owner_only_file(&file, path)?;
    }
    validate_main_lock_file(&file, path)?;
    validate_main_lock_path(&file, path)?;
    Ok(file)
}

fn validate_main_lock_file(file: &File, path: &Path) -> Result<()> {
    let metadata = file
        .metadata()
        .with_context(|| format!("inspecting main authority lock {}", path.display()))?;
    if !metadata.is_file() {
        bail!(
            "main authority lock {} must be a regular file",
            path.display()
        );
    }
    if metadata.len() > MAX_MAIN_LOCK_METADATA_BYTES {
        bail!(
            "main authority lock {} exceeds the {}-byte safety bound",
            path.display(),
            MAX_MAIN_LOCK_METADATA_BYTES
        );
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;

        let expected_uid = nix::unistd::geteuid().as_raw();
        if metadata.uid() != expected_uid {
            bail!(
                "main authority lock {} is owned by uid {}, expected {}",
                path.display(),
                metadata.uid(),
                expected_uid
            );
        }
        if metadata.mode() & 0o7777 != 0o600 {
            bail!("main authority lock {} must have mode 0600", path.display());
        }
        if metadata.nlink() != 1 {
            bail!(
                "main authority lock {} must have exactly one link",
                path.display()
            );
        }
    }
    Ok(())
}

fn validate_main_lock_path(file: &File, path: &Path) -> Result<()> {
    let current = std::fs::symlink_metadata(path)
        .with_context(|| format!("rebinding main authority lock {}", path.display()))?;
    if current.file_type().is_symlink() || !current.is_file() {
        bail!(
            "main authority lock {} changed or is not a regular file",
            path.display()
        );
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;

        let opened = file
            .metadata()
            .with_context(|| format!("inspecting opened main authority lock {}", path.display()))?;
        if (opened.dev(), opened.ino()) != (current.dev(), current.ino()) {
            bail!(
                "main authority lock {} was replaced while being acquired",
                path.display()
            );
        }
    }
    validate_main_lock_file(file, path)
}

#[cfg(unix)]
fn set_owner_only_file(file: &File, path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt as _;

    file.set_permissions(std::fs::Permissions::from_mode(0o600))
        .with_context(|| format!("setting owner-only main authority lock {}", path.display()))
}

#[cfg(not(unix))]
fn set_owner_only_file(_file: &File, _path: &Path) -> Result<()> {
    Ok(())
}

fn read_identity_bytes(path: &Path) -> Result<Vec<u8>> {
    read_bounded_file(
        path,
        AuthorityFilePolicy::owner_only(
            "immutable data-directory identity",
            MAX_DATA_DIRECTORY_IDENTITY_BYTES,
        ),
    )
}

fn is_not_found(error: &anyhow::Error) -> bool {
    error.chain().any(|cause| {
        cause
            .downcast_ref::<std::io::Error>()
            .is_some_and(|io| io.kind() == std::io::ErrorKind::NotFound)
    })
}

fn open_identity_for_create(path: &Path) -> std::io::Result<File> {
    let mut options = OpenOptions::new();
    options.create_new(true).write(true);
    owner_only(&mut options);
    no_follow(&mut options);
    options.open(path)
}

#[cfg(unix)]
fn owner_only(options: &mut OpenOptions) {
    use std::os::unix::fs::OpenOptionsExt as _;
    options.mode(0o600);
}

#[cfg(not(unix))]
fn owner_only(_options: &mut OpenOptions) {}

#[cfg(unix)]
fn no_follow(options: &mut OpenOptions) {
    use std::os::unix::fs::OpenOptionsExt as _;
    options.custom_flags(libc::O_NOFOLLOW);
}

#[cfg(not(unix))]
fn no_follow(_options: &mut OpenOptions) {}

#[cfg(unix)]
fn nonblocking_cloexec(options: &mut OpenOptions) {
    use std::os::unix::fs::OpenOptionsExt as _;

    options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC);
}

#[cfg(not(unix))]
fn nonblocking_cloexec(_options: &mut OpenOptions) {}

fn verify_lock_contention(lock_path: &Path) -> Result<()> {
    let probe = open_lock_file(lock_path)
        .with_context(|| format!("opening lock-semantics probe {}", lock_path.display()))?;
    let outcome = match Flock::lock(probe, FlockArg::LockExclusiveNonblock) {
        Err((_probe, Errno::EWOULDBLOCK)) => LockProbeOutcome::Contended,
        Ok(probe_lock) => {
            drop(probe_lock);
            LockProbeOutcome::IndependentlyAcquired
        }
        Err((_probe, errno)) => LockProbeOutcome::Error(errno),
    };
    // The test-only override models a filesystem that returns success for two
    // independent exclusive locks. It is applied after the real first lock and
    // second-open syscall, so the regression exercises the production startup
    // order without requiring an unsafe network filesystem in CI.
    #[cfg(test)]
    let outcome = if test_startup_fault("data_dir_lock.unsupported_lock_semantics") {
        LockProbeOutcome::IndependentlyAcquired
    } else {
        outcome
    };
    match outcome {
        LockProbeOutcome::Contended => Ok(()),
        LockProbeOutcome::IndependentlyAcquired => bail!(
            "filesystem did not enforce independent contention for {}; refusing to run an authoritative main on unsupported lock semantics; move the Kata data directory to a local filesystem with working flock(2) semantics and retry",
            lock_path.display()
        ),
        LockProbeOutcome::Error(errno) => bail!(
            "could not verify lock semantics for {}: {errno}; move the Kata data directory to a local filesystem with working flock(2) semantics and retry",
            lock_path.display()
        ),
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum LockProbeOutcome {
    Contended,
    IndependentlyAcquired,
    Error(Errno),
}

fn authority_write_error(action: &str, path: &Path, error: std::io::Error) -> anyhow::Error {
    if error.raw_os_error() == Some(libc::ENOSPC) {
        anyhow::anyhow!(
            "{action} main lock metadata {} failed: no space left on device (ENOSPC); free space on the filesystem containing the Kata data directory and retry `{} kata serve`; the installed main did not enter runtime boot or publish readiness",
            path.display(),
            crate::cli::DELEGATED_SCOPE
        )
    } else {
        anyhow::Error::new(error).context(format!("{action} main lock metadata {}", path.display()))
    }
}

/// A startup-only deterministic fault seam. `cfg(test)` means neither the
/// environment check nor the injected behavior exists in a production Kata
/// library or binary. Unit tests re-exec the library test harness so the same
/// installed-main control flow is exercised out of process.
#[cfg(test)]
fn test_startup_fault(point: &str) -> bool {
    std::env::var("KATA_TEST_STARTUP_FAULT").is_ok_and(|target| target == point)
}

#[cfg(test)]
#[path = "data_dir_lock/recovery_tests.rs"]
mod recovery_tests;

#[cfg(test)]
fn inject_startup_enospc(point: &str) -> std::io::Result<()> {
    if test_startup_fault(point) {
        Err(std::io::Error::from_raw_os_error(libc::ENOSPC))
    } else {
        Ok(())
    }
}
