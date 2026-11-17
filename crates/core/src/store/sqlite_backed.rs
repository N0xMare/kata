//! Shared SQLite-wrapper primitives for kata-core's several sqlite-backed
//! stores.
//!
//! Durable stores share connection and pre-open primitives, but creation and
//! restart are intentionally different paths. A missing store may be created
//! directly at its current schema; an existing store is opened without CREATE,
//! recovered by SQLite, validated at the exact current stamp/shape, and only
//! then receives runtime WAL pragmas. Product opens run no migration.
//!
//! ## One durability posture
//!
//! Every store opened through these helpers holds authority or a cursor, so
//! [`apply_wal_pragmas`] sets `synchronous=FULL`: SQLite requests
//! synchronization at each commit, subject to filesystem/device honesty; this
//! is not a physical-power-loss test or a cross-file transaction. Two stores
//! open themselves instead: the CAS (`CasStore::open`, `cas.db`) also sets
//! `synchronous=FULL`, and `SqliteWorkflowStore`'s own `stage_cache.db`, whose
//! one table is the `capsule_reuse_v1` reuse hint, sets `synchronous=NORMAL`,
//! because a lost hint row is only a cache miss.
//!
//! The `label` threaded through every helper prefixes any error so the failing
//! store is identifiable from the message alone.
//!
//! ## The exact-version gate (clean-format foundation)
//!
//! Every versioned product store shares a REFUSAL: an existing database must be
//! stamped at exactly the schema this binary understands. The ceiling helpers —
//! [`refuse_newer_schema_from_files`] and [`refuse_newer_schema_on_conn`], both
//! parameterized on `(ceiling, label)` — are shared here because a migration
//! ladder cannot enforce a ceiling for itself. A ladder's skip predicate asks "is
//! this rung already applied?" (`if user_version >= SCHEMA_VERSION { return }`)
//! and a stamp AHEAD of every rung answers yes, so "newer than I understand" and
//! "fully migrated" are the same branch: measured, a store stamped 999 opened
//! silently and the older binary then WROTE, leaving the 999 stamp in place — a
//! durable mutation of a newer release's plane with no record that it happened.
//!
//! The gate is PLAIN FILE I/O and runs BEFORE SQLite is opened at all: the
//! 4-byte big-endian `user_version` at database-header offset 60, folded with
//! the effective stamp in the last checksum-valid committed page-1 frame of a
//! pending `-wal` sidecar. Opening
//! the file with the driver just to read the pragma is NOT refuse-before-touch —
//! on a WAL database the open materializes `-shm` and `journal_mode=WAL` is a
//! persistent header write, which the WAL / hot-WAL byte-identity fixtures in
//! `crates/core/tests/operational_substrate.rs` prove. The on-connection form
//! ([`refuse_newer_schema_on_conn`]) is defence in depth behind it, and the only
//! available gate for an in-memory database or a connection the store did not
//! open from a path.

use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

use kata_types::error::{KataError, KataResult};
use parking_lot::Mutex;
use rusqlite::{Connection, OpenFlags};

/// Milliseconds a blocked writer/reader waits on a held SQLite lock before
/// giving up with `SQLITE_BUSY`. [`apply_wal_pragmas`] and `CasStore::open` set
/// it EXPLICITLY: rusqlite 0.41 arms 5000 ms on every open by itself, so a store
/// that omits the pragma agrees with this value only by coincidence, and would
/// silently stop agreeing the day either side moves.
///
/// WAL admits exactly one writer at a time, and the `cas.db` plane has two
/// independent writer connections in production (the main's shared CAS and a
/// `kata worker`'s own `CasStore::open`), so a writer routinely waits out
/// another's commit. A commit holds the write lock THROUGH its WAL fsync under
/// `synchronous=FULL`, so the critical section a waiter sits behind is one
/// statement plus one device flush: about a millisecond on a quiet NVMe, and
/// unbounded on a stalled one. A QLC NVMe at 88% full stalled that flush past
/// this budget (2026-10-19), and the waiting `cas insert` failed `database is
/// locked`; `just host-check` refuses a gate on a filesystem that full for that
/// reason.
///
/// The bound is deliberate, not a guess to be raised: a frozen writer (a
/// wedged worker process holding the lock) must surface as `SQLITE_BUSY` in the
/// main within this budget rather than hang it.
pub(crate) const BUSY_TIMEOUT_MS: i64 = 5_000;

/// Apply kata's durability pragmas — WAL journal mode, `synchronous=FULL`, and
/// a `busy_timeout` — to `conn`. WAL gives committed-transaction crash
/// consistency; FULL fsyncs the WAL on every commit, the only level that keeps
/// a committed transaction across an OS or power loss; the busy timeout makes a contended
/// connection wait-and-retry rather than hard-erroring with `SQLITE_BUSY`. On
/// an in-memory connection the journal-mode pragma is a benign no-op.
pub(crate) fn apply_wal_pragmas(conn: &Connection, label: &str) -> KataResult<()> {
    conn.pragma_update(None, "journal_mode", "WAL")
        .map_err(|e| KataError::Storage(format!("{label} pragma journal_mode=WAL: {e}")))?;
    conn.pragma_update(None, "synchronous", "FULL")
        .map_err(|e| KataError::Storage(format!("{label} pragma synchronous=FULL: {e}")))?;
    conn.pragma_update(None, "busy_timeout", BUSY_TIMEOUT_MS)
        .map_err(|e| KataError::Storage(format!("{label} pragma busy_timeout: {e}")))?;
    Ok(())
}

/// Read back the connection's live `PRAGMA synchronous` as its integer level
/// (`1` = NORMAL, `2` = FULL). `synchronous` is a per-CONNECTION setting that is
/// NOT persisted in the database file, so this must run on the store's OWN
/// connection — a fresh reopen would report SQLite's default, not the level the
/// store applied. Backs the fence test asserting the authoritative planes
/// opened FULL.
#[cfg(any(test, feature = "test-support"))]
pub(crate) fn read_synchronous(conn: &Connection) -> KataResult<i64> {
    conn.pragma_query_value(None, "synchronous", |row| row.get(0))
        .map_err(|e| KataError::Storage(format!("read synchronous pragma: {e}")))
}

/// Read back the connection's live `PRAGMA busy_timeout` in milliseconds. Backs
/// the test asserting [`apply_wal_pragmas`] armed the wait-and-retry
/// budget instead of leaving the SQLite default of `0` (immediate
/// `SQLITE_BUSY`). In-crate test use only.
#[cfg(test)]
fn read_busy_timeout(conn: &Connection) -> KataResult<i64> {
    conn.pragma_query_value(None, "busy_timeout", |row| row.get(0))
        .map_err(|e| KataError::Storage(format!("read busy_timeout pragma: {e}")))
}

/// Open (or create) a file-backed SQLite connection: create parent directories,
/// open with `READ_WRITE | CREATE | NO_MUTEX`, and apply the WAL + FULL
/// pragmas. The caller runs its own schema on the returned connection.
pub(crate) fn open_sqlite(path: &Path, label: &str) -> KataResult<Connection> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| {
            KataError::Storage(format!(
                "{label} create_dir_all({}) failed: {e}",
                parent.display()
            ))
        })?;
    }
    let conn = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_WRITE
            | OpenFlags::SQLITE_OPEN_CREATE
            | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map_err(|e| KataError::Storage(format!("{label} open({}) failed: {e}", path.display())))?;
    apply_wal_pragmas(&conn, label)?;
    Ok(conn)
}

/// Open an existing SQLite store under caller-held authority, allowing SQLite
/// to recover a hot WAL/rollback journal but never creating the database. The
/// caller must validate the recovered schema before applying pragmas or DDL.
pub(crate) fn open_existing_for_schema_validation(
    path: &Path,
    label: &str,
) -> KataResult<Connection> {
    Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_WRITE
            | OpenFlags::SQLITE_OPEN_NO_MUTEX
            | OpenFlags::SQLITE_OPEN_NOFOLLOW,
    )
    .map_err(|error| KataError::Storage(format!("{label} existing open failed: {error}")))
}

/// SQLite's documented type-affinity classification for a declared column
/// type. Schema validators compare affinity rather than formatting-sensitive
/// `sqlite_master.sql` text.
pub(crate) fn sqlite_affinity(declared_type: &str) -> &'static str {
    let declared_type = declared_type.to_ascii_uppercase();
    if declared_type.contains("INT") {
        "INTEGER"
    } else if declared_type.contains("CHAR")
        || declared_type.contains("CLOB")
        || declared_type.contains("TEXT")
    {
        "TEXT"
    } else if declared_type.contains("BLOB") || declared_type.is_empty() {
        "BLOB"
    } else if declared_type.contains("REAL")
        || declared_type.contains("FLOA")
        || declared_type.contains("DOUB")
    {
        "REAL"
    } else {
        "NUMERIC"
    }
}

/// Open an in-memory SQLite connection with the WAL + FULL pragmas applied
/// (matching the file path's durability posture; the journal-mode pragma is a
/// no-op on an in-memory database).
#[cfg(any(test, feature = "test-support"))]
pub(crate) fn open_sqlite_in_memory(label: &str) -> KataResult<Connection> {
    let conn = Connection::open_in_memory()
        .map_err(|e| KataError::Storage(format!("{label} open_in_memory failed: {e}")))?;
    apply_wal_pragmas(&conn, label)?;
    Ok(conn)
}

/// Checkpoint a freshly initialized SQLite authority file and fsync the main
/// database before an enclosing format identity is published. This is not a
/// general backup primitive; callers must already own exclusive initialization
/// authority and must not race live connections.
pub fn checkpoint_and_sync_initialized_file(path: &Path, label: &str) -> KataResult<()> {
    let conn = open_existing_for_schema_validation(path, label)
        .map_err(|error| KataError::Storage(format!("{label} checkpoint open failed: {error}")))?;
    conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")
        .map_err(|error| KataError::Storage(format!("{label} checkpoint failed: {error}")))?;
    drop(conn);
    std::fs::File::open(path)
        .and_then(|file| file.sync_all())
        .map_err(|error| KataError::Storage(format!("{label} fsync failed: {error}")))
}

/// Byte offset of the 4-byte big-endian `user_version` field inside a SQLite
/// database header (and inside any WAL frame carrying page 1).
const USER_VERSION_OFFSET: u64 = 60;

/// Refuse a database at `path` whose stamped `user_version` exceeds `ceiling`,
/// deciding by PLAIN FILE I/O — no SQLite handle, no sidecar, no page rewrite.
///
/// `label` names the store in the error (`"operational.db"`, `"memory.db"`, …).
/// Safe to call on a missing file: a fresh database reads as version 0.
///
/// # Failure
///
/// [`KataError::SchemaMigrationRequired`], having touched nothing on disk.
pub(crate) fn refuse_newer_schema_from_files(
    path: &Path,
    ceiling: i64,
    label: &str,
) -> KataResult<()> {
    refuse_newer_schema_version(
        stamped_user_version_from_files(path, label)?,
        ceiling,
        label,
    )
}

/// Read `PRAGMA user_version` on an OPEN connection and refuse a value above
/// `ceiling`.
///
/// Defence in depth behind [`refuse_newer_schema_from_files`] — and the ONLY
/// available gate for an in-memory database, or for a connection the caller did
/// not open from a path. Call it before any pragma or DDL: `journal_mode=WAL` is
/// a persistent header write, so a gate placed after it has already mutated the
/// file it was meant to refuse.
pub(crate) fn refuse_newer_schema_on_conn(
    conn: &Connection,
    ceiling: i64,
    label: &str,
) -> KataResult<()> {
    let version: i64 = conn
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .map_err(|error| KataError::Storage(format!("{label} read user_version: {error}")))?;
    refuse_newer_schema_version(version, ceiling, label)
}

/// The refusal itself, for a caller that has ALREADY read the stamp.
///
/// A migration ladder reads `user_version` once and then decides per rung; this
/// lets it spend that one read on the ceiling check too, instead of conflating
/// "ahead of me" with "already applied" the way `>=` / `<=` skip predicates do.
pub(crate) fn refuse_newer_schema_version(
    version: i64,
    ceiling: i64,
    label: &str,
) -> KataResult<()> {
    if version > ceiling {
        return Err(forward_version_error(version, ceiling, label));
    }
    Ok(())
}

/// The one typed forward-version refusal every kata store returns.
///
/// [`KataError::SchemaMigrationRequired`] and never [`KataError::Storage`]: an
/// operator (and the boot path) must be able to MATCH on "this data dir was
/// written by a newer kata" without string-scraping a generic storage error.
pub(crate) fn forward_version_error(version: i64, ceiling: i64, label: &str) -> KataError {
    KataError::SchemaMigrationRequired(format!(
        "{label} is at schema version {version}, but this kata binary only understands \
         version {ceiling}; refusing to open a newer-versioned {label} (upgrade kata or \
         restore a compatible backup)"
    ))
}

/// The stamped `user_version` of the database at `path` WITHOUT opening SQLite.
///
/// Folds two plain reads:
/// 1. the 4-byte big-endian `user_version` at header offset 60 of the main file;
/// 2. the newest `user_version` carried by any valid page-1 frame of a pending
///    `-wal` sidecar (an uncheckpointed stamp the main header does not show yet).
///
/// A committed page-1 frame in the WAL supersedes the main header, including
/// when its version is lower. Taking a numeric maximum would hide a committed
/// behind-version WAL behind a current main header and let SQLite mutate the
/// directory before the exact-version refusal.
pub(crate) fn stamped_user_version_from_files(path: &Path, label: &str) -> KataResult<i64> {
    refuse_orphan_sidecars_for_missing_main(path, label)?;
    let header = header_user_version(path, label)?;
    let wal = wal_user_version(&sidecar_path(path, "-wal"), label)?;
    Ok(wal.unwrap_or(header))
}

/// Refuse crash residue that has no SQLite main database to recover into.
/// Creating a new main beside an orphan journal/WAL would reinterpret evidence
/// as fresh authority.
pub(crate) fn refuse_orphan_sidecars_for_missing_main(path: &Path, label: &str) -> KataResult<()> {
    if !path.exists() {
        for suffix in ["-wal", "-shm", "-journal"] {
            let sidecar = sidecar_path(path, suffix);
            match std::fs::symlink_metadata(&sidecar) {
                Ok(_) => {
                    return Err(KataError::SchemaMigrationRequired(format!(
                        "{label} is missing its main database while sidecar {} remains; refusing to create an empty replacement",
                        sidecar.display()
                    )));
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => {
                    return Err(KataError::Storage(format!(
                        "{label} inspect possible sidecar {}: {error}",
                        sidecar.display()
                    )));
                }
            }
        }
    }
    Ok(())
}

/// The `user_version` in the main database header, or 0 when the file is shorter
/// than the header field (a fresh/zero-length database).
fn header_user_version(path: &Path, label: &str) -> KataResult<i64> {
    let mut file = match std::fs::File::open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(0),
        Err(error) => {
            return Err(KataError::Storage(format!(
                "{label} read header of {}: {error}",
                path.display()
            )));
        }
    };
    let Some(bytes) = read_exact_at(&mut file, USER_VERSION_OFFSET, 4, path, label)? else {
        return Ok(0);
    };
    Ok(i64::from(u32::from_be_bytes([
        bytes[0], bytes[1], bytes[2], bytes[3],
    ])))
}

/// The newest `user_version` any VALID frame of the `-wal` sidecar carries for
/// page 1, or `None` when there is no sidecar / no interpretable WAL.
///
/// WAL layout (SQLite file-format §WAL): a 32-byte header
/// `magic | format | page_size | ckpt_seq | salt1 | salt2 | csum1 | csum2`, then
/// frames of `24-byte header | page_size bytes`. A frame belongs to the current
/// log iff its salts equal the WAL header's salts; the first mismatch ends the
/// log. Every complete frame is checksum-validated; only page 1 contributes a
/// schema stamp because only it carries the database header.
/// An uninterpretable WAL (bad magic, absurd page size) contributes nothing —
/// SQLite would reset such a WAL, and the main-header read still gates.
fn wal_user_version(wal_path: &Path, label: &str) -> KataResult<Option<i64>> {
    let mut file = match std::fs::File::open(wal_path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(KataError::Storage(format!(
                "{label} read wal sidecar {}: {error}",
                wal_path.display()
            )));
        }
    };
    let Some(header) = read_exact_at(&mut file, 0, 32, wal_path, label)? else {
        return Ok(None);
    };
    let magic = u32::from_be_bytes([header[0], header[1], header[2], header[3]]);
    if magic != 0x377f_0682 && magic != 0x377f_0683 {
        return Ok(None);
    }
    let format_version = u32::from_be_bytes([header[4], header[5], header[6], header[7]]);
    if format_version != 3_007_000 {
        return Ok(None);
    }
    let page_size = u32::from_be_bytes([header[8], header[9], header[10], header[11]]);
    if !(512..=65_536).contains(&page_size) || !page_size.is_power_of_two() {
        return Ok(None);
    }
    let page_size = u64::from(page_size);
    let salt = &header[16..24];
    let big_endian_checksum = magic == 0x377f_0683;
    let mut checksum = wal_checksum(&header[..24], big_endian_checksum, [0, 0]);
    let stored_header_checksum = [
        u32::from_be_bytes([header[24], header[25], header[26], header[27]]),
        u32::from_be_bytes([header[28], header[29], header[30], header[31]]),
    ];
    if checksum != stored_header_checksum {
        return Ok(None);
    }

    let mut pending_page_one: Option<i64> = None;
    let mut committed_page_one: Option<i64> = None;
    let mut offset: u64 = 32;
    while let Some(frame) = read_exact_at(&mut file, offset, 24, wal_path, label)? {
        if &frame[8..16] != salt {
            // Not part of the current log: the valid frames end here.
            break;
        }
        let page_number = u32::from_be_bytes([frame[0], frame[1], frame[2], frame[3]]);
        if page_number == 0 {
            break;
        }
        let page_offset = offset + 24;
        let Some(page) = read_exact_at(
            &mut file,
            page_offset,
            usize::try_from(page_size).expect("validated SQLite page size fits usize"),
            wal_path,
            label,
        )?
        else {
            break;
        };
        checksum = wal_checksum(&frame[..8], big_endian_checksum, checksum);
        checksum = wal_checksum(&page, big_endian_checksum, checksum);
        let stored_frame_checksum = [
            u32::from_be_bytes([frame[16], frame[17], frame[18], frame[19]]),
            u32::from_be_bytes([frame[20], frame[21], frame[22], frame[23]]),
        ];
        if checksum != stored_frame_checksum {
            break;
        }
        if page_number == 1 {
            let offset = usize::try_from(USER_VERSION_OFFSET)
                .expect("SQLite header user-version offset fits usize");
            let bytes = &page[offset..offset + 4];
            let candidate = i64::from(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]));
            pending_page_one = Some(candidate);
        }
        let database_size_after_commit =
            u32::from_be_bytes([frame[4], frame[5], frame[6], frame[7]]);
        if database_size_after_commit != 0
            && let Some(candidate) = pending_page_one.take()
        {
            committed_page_one = Some(candidate);
        }
        offset = page_offset + page_size;
    }
    Ok(committed_page_one)
}

fn wal_checksum(bytes: &[u8], big_endian: bool, mut state: [u32; 2]) -> [u32; 2] {
    debug_assert!(bytes.len() >= 8 && bytes.len().is_multiple_of(8));
    for words in bytes.as_chunks::<8>().0 {
        let first = if big_endian {
            u32::from_be_bytes(words[..4].try_into().expect("four-byte word"))
        } else {
            u32::from_le_bytes(words[..4].try_into().expect("four-byte word"))
        };
        let second = if big_endian {
            u32::from_be_bytes(words[4..].try_into().expect("four-byte word"))
        } else {
            u32::from_le_bytes(words[4..].try_into().expect("four-byte word"))
        };
        state[0] = state[0].wrapping_add(first).wrapping_add(state[1]);
        state[1] = state[1].wrapping_add(second).wrapping_add(state[0]);
    }
    state
}

/// Read exactly `len` bytes at `offset`, or `None` when the file is too short.
fn read_exact_at(
    file: &mut std::fs::File,
    offset: u64,
    len: usize,
    path: &Path,
    label: &str,
) -> KataResult<Option<Vec<u8>>> {
    file.seek(SeekFrom::Start(offset)).map_err(|error| {
        KataError::Storage(format!(
            "{label} seek {} in {}: {error}",
            offset,
            path.display()
        ))
    })?;
    let mut buf = vec![0u8; len];
    let mut filled = 0usize;
    while filled < len {
        match file.read(&mut buf[filled..]) {
            Ok(0) => return Ok(None),
            Ok(read) => filled += read,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(error) => {
                return Err(KataError::Storage(format!(
                    "{label} read {}: {error}",
                    path.display()
                )));
            }
        }
    }
    Ok(Some(buf))
}

/// `<path><suffix>` — the SQLite sidecar naming convention.
fn sidecar_path(path: &Path, suffix: &str) -> PathBuf {
    let mut raw = path.to_path_buf().into_os_string();
    raw.push(suffix);
    PathBuf::from(raw)
}

/// A `parking_lot::Mutex<Connection>` plus the originating path (`None` for an
/// in-memory database) — the shared conn+path shape behind kata-core's simplest
/// sqlite-wrapper stores (those with no additional state beyond the connection).
pub(crate) struct SqliteBacked {
    pub(crate) conn: Mutex<Connection>,
    pub(crate) path: Option<PathBuf>,
}

impl std::fmt::Debug for SqliteBacked {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SqliteBacked")
            .field("path", &self.path)
            .finish_non_exhaustive()
    }
}

impl SqliteBacked {
    /// Wrap an already-opened connection (see [`open_sqlite`] /
    /// [`open_sqlite_in_memory`]) and its originating path.
    pub(crate) fn from_conn(conn: Connection, path: Option<PathBuf>) -> Self {
        Self {
            conn: Mutex::new(conn),
            path,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_wal_stamp_fixture(
        main_version: i64,
        wal_version: i64,
    ) -> (tempfile::TempDir, PathBuf, Connection) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("stamp.db");
        let conn = Connection::open(&path).unwrap();
        conn.execute_batch(&format!(
            "CREATE TABLE t(id INTEGER PRIMARY KEY);
             PRAGMA user_version={main_version};
             PRAGMA journal_mode=WAL;
             PRAGMA wal_autocheckpoint=0;
             PRAGMA wal_checkpoint(TRUNCATE);
             PRAGMA user_version={wal_version};"
        ))
        .unwrap();
        assert!(sidecar_path(&path, "-wal").is_file());
        (dir, path, conn)
    }

    #[test]
    fn committed_wal_stamp_supersedes_a_numerically_newer_main_stamp() {
        let (_dir, path, _connection) = build_wal_stamp_fixture(10, 9);
        assert_eq!(
            stamped_user_version_from_files(&path, "fixture").unwrap(),
            9
        );
    }

    #[test]
    fn incomplete_commit_shaped_wal_tail_does_not_override_the_last_valid_commit() {
        let (_dir, path, _connection) = build_wal_stamp_fixture(10, 10);
        let wal_path = sidecar_path(&path, "-wal");
        let mut bytes = std::fs::read(&wal_path).unwrap();
        let page_size =
            usize::try_from(u32::from_be_bytes(bytes[8..12].try_into().unwrap())).unwrap();
        let tail = bytes[32..32 + 24 + 64].to_vec();
        bytes.extend_from_slice(&tail);
        assert!(bytes.len() < 32 + 2 * (24 + page_size));
        std::fs::write(&wal_path, bytes).unwrap();

        assert_eq!(
            stamped_user_version_from_files(&path, "fixture").unwrap(),
            10
        );
    }

    #[test]
    fn invalid_checksum_wal_frame_cannot_hide_a_future_main_stamp() {
        let (_dir, path, _connection) = build_wal_stamp_fixture(11, 10);
        let wal_path = sidecar_path(&path, "-wal");
        let mut bytes = std::fs::read(&wal_path).unwrap();
        bytes[32 + 16] ^= 1;
        std::fs::write(&wal_path, bytes).unwrap();

        assert_eq!(
            stamped_user_version_from_files(&path, "fixture").unwrap(),
            11
        );
    }

    /// `apply_wal_pragmas` must arm [`BUSY_TIMEOUT_MS`] so a contended
    /// connection (e.g. a backup `VACUUM INTO` reader colliding with a
    /// checkpoint) waits-and-retries instead of hard-erroring with
    /// `SQLITE_BUSY`. SQLite's own default is `0`, but rusqlite arms 5000 ms on
    /// open, so this pins the value, not the presence of the pragma call.
    #[test]
    fn apply_wal_pragmas_arms_busy_timeout() {
        // File-backed so WAL journal mode actually engages (the pragma is a
        // no-op on an in-memory DB, but busy_timeout applies regardless).
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("busy.db");
        let conn = open_sqlite(&path, "busy timeout test").unwrap();
        assert_eq!(
            read_busy_timeout(&conn).unwrap(),
            BUSY_TIMEOUT_MS,
            "apply_wal_pragmas must set busy_timeout to BUSY_TIMEOUT_MS",
        );
    }

    /// The busy timeout is armed on the in-memory open path too, so tests and
    /// the memory-mode stores inherit the same wait-and-retry posture.
    #[test]
    fn in_memory_open_arms_busy_timeout() {
        let conn = open_sqlite_in_memory("busy timeout mem test").unwrap();
        assert_eq!(read_busy_timeout(&conn).unwrap(), BUSY_TIMEOUT_MS);
    }

    /// The SQLite this binary links answers `sqlite_version()` at 3.54.0 or
    /// later: CVE-2026-119375 (RUSTSEC-2026-0459, uninitialized page-cache bytes
    /// read through a `-wal` whose page size differs from its database's) is
    /// fixed there. `just deny` refuses the vulnerable `libsqlite3-sys` crate by
    /// version; this refuses the vulnerable LIBRARY, asked through SQL rather
    /// than through the crate's own version constant, so a build that stopped
    /// bundling and linked an older host SQLite is caught too. Refused set: every
    /// linked SQLite older than 3.54.0.
    #[test]
    fn the_linked_sqlite_is_at_or_past_the_release_that_fixes_the_wal_page_size_read() {
        let conn = open_sqlite_in_memory("sqlite version floor test").unwrap();
        let reported: String = conn
            .query_row("SELECT sqlite_version()", [], |row| row.get(0))
            .unwrap();
        let parts: Vec<u32> = reported
            .split('.')
            .map(|part| part.parse().unwrap())
            .collect();
        println!("linked sqlite_version() = {reported}");
        assert!(
            parts.as_slice() >= [3, 54, 0].as_slice(),
            "the linked SQLite {reported} predates 3.54.0 and is exposed to CVE-2026-119375",
        );
    }
}
