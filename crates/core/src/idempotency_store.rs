//! The worker effect membrane's durable store, `idempotency.db`.
//!
//! It holds one fact: the membrane identity a worker's enrolled effect domain binds
//! to. kata has no per-tool-call mediation, so the store records no tool call.
//!
//! Storage layout mirrors the existing `SqliteWorkflowStore` and
//! `DurableEventLog` patterns: one `parking_lot::Mutex<Connection>`, WAL
//! mode, FULL synchronous (see [`IdempotencyStore::open`]).

use std::path::Path;

use kata_types::error::{KataError, KataResult};
use kata_types::identity::WorkerMembraneId;
use rusqlite::Connection;
use ulid::Ulid;

#[cfg(any(test, feature = "test-support"))]
use crate::store::sqlite_backed::open_sqlite_in_memory;
use crate::store::sqlite_backed::{
    SqliteBacked, apply_wal_pragmas, open_existing_for_schema_validation, open_sqlite,
};

mod recovery;
pub use recovery::IdempotencyRecoveryHold;

/// The `idempotency.db` schema stamp (`PRAGMA user_version`). A worker recovery
/// receipt carries it, and every reader of a captured store compares against it.
pub const IDEMPOTENCY_SCHEMA_VERSION: u32 = 2;

/// The worker effect membrane's SQLite store.
///
/// Thread-safe via `parking_lot::Mutex`. The connection uses WAL mode for
/// concurrent-reader safety, matching the `SqliteWorkflowStore` pattern.
pub struct IdempotencyStore {
    backed: SqliteBacked,
    recovery_gate: recovery::RecoveryGate,
    // Fields drop in declaration order: release ownership only after SQLite closes.
    _owner: Option<std::fs::File>,
}

// All Kata mutable constructors participate. This is not exclusion of raw SQLite
// writers or a guarantee against an external actor replacing a live pathname.
fn acquire_membrane_owner(path: &Path, create: bool) -> KataResult<(std::fs::File, bool)> {
    use rustix::fs::{Mode, OFlags};
    use std::os::unix::fs::MetadataExt;
    let failure =
        |error: String| KataError::Storage(format!("idempotency membrane ownership: {error}"));
    if create && let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        std::fs::create_dir_all(parent).map_err(|e| failure(e.to_string()))?;
    }
    let flags = OFlags::RDWR | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    let (fd, created) = if create {
        match rustix::fs::open(
            path,
            flags | OFlags::CREATE | OFlags::EXCL,
            Mode::RUSR | Mode::WUSR,
        ) {
            Ok(fd) => (fd, true),
            Err(error) if error == rustix::io::Errno::EXIST => (
                rustix::fs::open(path, flags, Mode::empty()).map_err(|e| failure(e.to_string()))?,
                false,
            ),
            Err(error) => return Err(failure(error.to_string())),
        }
    } else {
        (
            rustix::fs::open(path, flags, Mode::empty()).map_err(|e| failure(e.to_string()))?,
            false,
        )
    };
    let file = std::fs::File::from(fd);
    rustix::fs::flock(&file, rustix::fs::FlockOperation::NonBlockingLockExclusive).map_err(
        |e| {
            failure(format!(
                "another mutable owner exists or locking is unavailable: {e}"
            ))
        },
    )?;
    let held = file.metadata().map_err(|e| failure(e.to_string()))?;
    let named = std::fs::symlink_metadata(path).map_err(|e| failure(e.to_string()))?;
    if !held.is_file()
        || !named.is_file()
        || held.nlink() != 1
        || (held.dev(), held.ino()) != (named.dev(), named.ino())
    {
        return Err(failure(
            "database must be a single-linked regular file with stable pathname identity".into(),
        ));
    }
    Ok((file, created))
}

impl std::fmt::Debug for IdempotencyStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IdempotencyStore")
            .field("path", &self.backed.path)
            .finish_non_exhaustive()
    }
}

impl IdempotencyStore {
    /// Validate the existing versioned idempotency authority without opening
    /// the source SQLite file for writes. Missing/reshaped tables are refused;
    /// the product open path has no historical migration contract for them.
    pub fn refuse_noncurrent_file_schema(path: impl AsRef<Path>) -> KataResult<()> {
        let path = path.as_ref();
        let version =
            crate::store::sqlite_backed::stamped_user_version_from_files(path, "idempotency.db")?;
        if path.exists() && version != i64::from(IDEMPOTENCY_SCHEMA_VERSION) {
            return Err(KataError::SchemaMigrationRequired(format!(
                "idempotency.db has unsupported schema stamp {version}; expected \
                 {IDEMPOTENCY_SCHEMA_VERSION}"
            )));
        }
        Ok(())
    }

    /// The store's whole shape: exactly the `membrane_identity` table, whose own
    /// column contract and singleton row [`Self::read_membrane_identity`] checks.
    pub(crate) fn validate_current_schema(conn: &Connection) -> KataResult<()> {
        let tables = conn
            .prepare("SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name")
            .and_then(|mut statement| {
                statement
                    .query_map([], |row| row.get::<_, String>(0))?
                    .collect::<Result<Vec<_>, _>>()
            })
            .map_err(|e| KataError::Storage(format!("idempotency.db inspect tables: {e}")))?;
        if tables != ["membrane_identity"] {
            return Err(KataError::SchemaMigrationRequired(format!(
                "idempotency.db has tables {tables:?}; expected current [\"membrane_identity\"]"
            )));
        }
        Self::read_membrane_identity(conn)?;
        Ok(())
    }

    /// Open (or create) the idempotency store at `path`.
    ///
    /// Initializes the membrane identity for a new store; an existing store must
    /// contain exactly it. Enables WAL mode and
    /// `synchronous=FULL`: the membrane identity is the durable half of the
    /// enrolled worker effect domain, so a power loss must not drop the commit
    /// that created it after the store reported success. It is written once,
    /// so FULL's per-commit fsync costs nothing measurable.
    pub fn open(path: impl AsRef<Path>) -> KataResult<Self> {
        let path = path.as_ref().to_path_buf();
        Self::refuse_noncurrent_file_schema(&path)?;
        let (owner, created) = acquire_membrane_owner(&path, true)?;
        let conn = if created {
            let conn = open_sqlite(&path, "idempotency store")?;
            Self::create_schema(&conn)?;
            conn
        } else {
            Self::refuse_noncurrent_file_schema(&path)?;
            let conn = open_existing_for_schema_validation(&path, "idempotency.db")?;
            Self::validate_current_schema(&conn)?;
            apply_wal_pragmas(&conn, "idempotency store")?;
            conn
        };
        Ok(Self {
            backed: SqliteBacked::from_conn(conn, Some(path)),
            recovery_gate: recovery::RecoveryGate::default(),
            _owner: Some(owner),
        })
    }

    /// Open a provisioned membrane without SQLite's CREATE flag and verify its
    /// configured lifetime before applying runtime pragmas. Loss and replacement
    /// cannot be interpreted as permission to initialize empty authority.
    pub fn open_existing_bound(
        path: impl AsRef<Path>,
        expected: WorkerMembraneId,
    ) -> KataResult<Self> {
        Self::open_existing_inner(path.as_ref(), Some(expected))
    }

    /// Open retained authority without minting a membrane if the file is lost.
    /// Offline maintenance uses this after taking source directory ownership.
    pub fn open_existing(path: impl AsRef<Path>) -> KataResult<Self> {
        Self::open_existing_inner(path.as_ref(), None)
    }

    fn open_existing_inner(path: &Path, expected: Option<WorkerMembraneId>) -> KataResult<Self> {
        let path = path.to_path_buf();
        Self::refuse_noncurrent_file_schema(&path)?;
        let (owner, _) = acquire_membrane_owner(&path, false)?;
        Self::refuse_noncurrent_file_schema(&path)?;
        let conn = open_existing_for_schema_validation(&path, "provisioned worker idempotency.db")?;
        Self::validate_current_schema(&conn)?;
        let actual = Self::read_membrane_identity(&conn)?;
        if expected.is_some_and(|expected| actual != expected) {
            return Err(KataError::Storage(
                "provisioned worker membrane identity does not match existing authority".into(),
            ));
        }
        apply_wal_pragmas(&conn, "idempotency store")?;
        Ok(Self {
            backed: SqliteBacked::from_conn(conn, Some(path)),
            recovery_gate: recovery::RecoveryGate::default(),
            _owner: Some(owner),
        })
    }

    /// Read the live connection's `synchronous` level (2 = FULL). The pragma
    /// is per-connection (not persisted in the file), so it must be read here,
    /// not on a fresh reopen. Never production. Mirrors
    /// `DurableEventLog::debug_synchronous_level`.
    #[cfg(any(test, feature = "test-support"))]
    #[doc(hidden)]
    pub fn debug_synchronous_level(&self) -> KataResult<i64> {
        let conn = self.backed.conn.lock();
        crate::store::sqlite_backed::read_synchronous(&conn)
    }

    /// The persisted lifetime of this membrane, independent of connection and
    /// attempt generations. Missing metadata is lost authority, never a mint.
    pub fn membrane_id(&self) -> KataResult<WorkerMembraneId> {
        Self::read_membrane_identity(&self.backed.conn.lock())
    }

    pub(crate) fn read_membrane_identity(conn: &Connection) -> KataResult<WorkerMembraneId> {
        let mut shape = conn.prepare("SELECT name, type, \"notnull\", pk FROM pragma_table_info('membrane_identity') ORDER BY cid")
            .map_err(|e| KataError::Storage(format!("idempotency membrane schema: {e}")))?;
        let shape = shape
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, i64>(3)?,
                ))
            })
            .map_err(|e| KataError::Storage(format!("idempotency membrane schema: {e}")))?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| KataError::Storage(format!("idempotency membrane schema: {e}")))?;
        if shape
            != [
                ("singleton".to_string(), "INTEGER".to_string(), 1, 1),
                ("membrane_id".to_string(), "BLOB".to_string(), 1, 0),
            ]
        {
            return Err(KataError::Storage(
                "idempotency membrane identity schema is missing or changed".into(),
            ));
        }
        let mut query = conn
            .prepare("SELECT singleton, membrane_id FROM membrane_identity")
            .map_err(|e| KataError::Storage(format!("idempotency membrane identity: {e}")))?;
        let rows = query
            .query_map([], |row| {
                Ok((row.get::<_, i64>(0)?, row.get::<_, Vec<u8>>(1)?))
            })
            .map_err(|e| KataError::Storage(format!("idempotency membrane identity: {e}")))?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| KataError::Storage(format!("idempotency membrane identity: {e}")))?;
        let [(0, bytes)] = rows.as_slice() else {
            return Err(KataError::Storage(
                "idempotency membrane identity must contain exactly one singleton".into(),
            ));
        };
        let bytes: [u8; 16] = bytes.as_slice().try_into().map_err(|_| {
            KataError::Storage("idempotency membrane identity must be 16 bytes".into())
        })?;
        if bytes == [0; 16] {
            return Err(KataError::Storage(
                "idempotency membrane identity is nil".into(),
            ));
        }
        Ok(WorkerMembraneId(Ulid::from_bytes(bytes)))
    }

    /// Open an in-memory idempotency store (useful for tests).
    #[cfg(any(test, feature = "test-support"))]
    pub fn open_in_memory() -> KataResult<Self> {
        let conn = open_sqlite_in_memory("idempotency store")?;
        Self::create_schema(&conn)?;
        Ok(Self {
            backed: SqliteBacked::from_conn(conn, None),
            recovery_gate: recovery::RecoveryGate::default(),
            _owner: None,
        })
    }

    fn create_schema(conn: &Connection) -> KataResult<()> {
        let tx = conn
            .unchecked_transaction()
            .map_err(|e| KataError::Storage(format!("idempotency initialize transaction: {e}")))?;
        tx.execute_batch(&format!(
            "CREATE TABLE membrane_identity (
                singleton INTEGER NOT NULL PRIMARY KEY CHECK(singleton = 0),
                membrane_id BLOB NOT NULL CHECK(length(membrane_id) = 16)
            );
            PRAGMA user_version = {IDEMPOTENCY_SCHEMA_VERSION};",
        ))
        .map_err(|e| KataError::Storage(format!("idempotency store create table failed: {e}")))?;

        tx.execute(
            "INSERT INTO membrane_identity(singleton, membrane_id) VALUES(0, ?1)",
            [Ulid::new().to_bytes().as_slice()],
        )
        .map_err(|e| KataError::Storage(format!("idempotency initialize identity: {e}")))?;
        tx.commit()
            .map_err(|e| KataError::Storage(format!("idempotency initialize commit: {e}")))
    }
}
