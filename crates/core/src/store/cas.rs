//! Content-addressed value store (CAS).
//!
//! Stage outputs land here as blake3 content-addressed objects: equal
//! values (canonicalised — recursive key sort) share ONE object, so two
//! cache entries pointing at the same output cost one copy, not two. Small
//! objects live inline in the `cas.db` metadata row; large objects spill to
//! a git-object-style blob tree under `<parent>/cas/`.
//!
//! # Crash-consistency (git-object-store ordering)
//!
//! TWO independent write planes reference the objects here: this store's
//! `cas.db` (object metadata + inline blobs) and `operational.db`'s `cas_roots`,
//! which holds the AUTHORITATIVE root references. They are separate WAL files, so
//! a crash can commit one and not the other. The invariant that keeps that safe is
//! strict ordering:
//!
//! 1. the blob file is `fsync`'d durable BEFORE its `cas_objects` row, and
//! 2. the `cas_objects` row is committed BEFORE any `operational.db` root
//!    references it — enforced by TYPE, not by convention: an operational root
//!    spec can only be built from a [`DurableObject`] receipt.
//!
//! So a committed reference can never point at absent bytes. The only
//! crash residue is an *orphan* object (written, never referenced), which costs
//! disk and nothing else — the polarity: orphan objects are safe, dangling
//! references are not.
//!
//! # No collection
//!
//! Nothing deletes an object. kata has no CAS garbage collection and no retention
//! pass: a `cas_objects` row and its blob file, once written, stay for the life of
//! the data directory, so the store only grows.

use std::sync::atomic::{self, AtomicU64};

/// Process-global sequence for unique CAS tmp-blob filenames so concurrent
/// writers of the same content don't race a shared `.part`.
static TMP_SEQ: AtomicU64 = AtomicU64::new(0);

/// INVARIANT: this store admits exactly ONE digest function.
///
/// `cas_objects.object_id` is a 32-byte BLOB — the digest half of a
/// [`CasAddress`] — and cannot carry a function label. Every row → path
/// reconstruction below therefore spells `CasAddress::blake3(oid)`, which is
/// sound only while `Blake3` is the sole [`CasDigestFunction`].
///
/// FAILURE MODE: a second variant added without touching the schema would make
/// every one of those reconstructions silently assume the wrong function, and a
/// row written under the new function would resolve to a path holding the old
/// function's object — the silent namespace reuse the self-describing address
/// exists to prevent.
///
/// ENFORCEMENT POINT: here, at compile time. Adding a variant to
/// [`CasDigestFunction::ALL`] FAILS THE BUILD at the place that must then carry
/// the function in the row, rather than leaving a rule someone has to remember.
///
/// PROOF: `cargo check` is the proof; there is no runtime path to falsify.
const _: () = assert!(
    CasDigestFunction::ALL.len() == 1,
    "cas_objects rows store the digest half of a CasAddress only; a second digest function \
     requires the function to be persisted in the row before the row -> path reconstructions in \
     this module can be trusted"
);
use std::io::Write as _;
use std::path::{Path, PathBuf};

use kata_types::cache::{CasAddress, CasDigestFunction, cas_address_for_canonical_bytes};
use kata_types::primitives::ObjectId;
use kata_types::{KataError, KataResult};
use parking_lot::Mutex;
use rusqlite::{Connection, OpenFlags, OptionalExtension, params};

use super::sqlite_backed::sqlite_affinity;

const CURRENT_CAS_TABLE_SQL: &str = "CREATE TABLE cas_objects (
    object_id BLOB NOT NULL PRIMARY KEY,
    size INTEGER NOT NULL,
    storage TEXT NOT NULL CHECK(storage IN ('inline','file')),
    blob BLOB
)";

fn canonical_sql_tokens(sql: &str) -> Option<Vec<String>> {
    let bytes = sql.as_bytes();
    let mut tokens = Vec::new();
    let mut offset = 0;
    while offset < bytes.len() {
        if bytes[offset].is_ascii_whitespace() {
            offset += 1;
        } else if bytes[offset..].starts_with(b"--") {
            offset += 2;
            while offset < bytes.len() && bytes[offset] != b'\n' {
                offset += 1;
            }
        } else if bytes[offset..].starts_with(b"/*") {
            let remainder = &bytes[offset + 2..];
            let end = remainder.windows(2).position(|window| window == b"*/")?;
            offset += 2 + end + 2;
        } else if bytes[offset] == b'\'' {
            let start = offset;
            offset += 1;
            loop {
                if offset >= bytes.len() {
                    return None;
                }
                if bytes[offset] == b'\'' {
                    offset += 1;
                    if offset < bytes.len() && bytes[offset] == b'\'' {
                        offset += 1;
                        continue;
                    }
                    break;
                }
                offset += 1;
            }
            tokens.push(sql[start..offset].to_string());
        } else if bytes[offset].is_ascii_alphanumeric() || bytes[offset] == b'_' {
            let start = offset;
            offset += 1;
            while offset < bytes.len()
                && (bytes[offset].is_ascii_alphanumeric() || bytes[offset] == b'_')
            {
                offset += 1;
            }
            tokens.push(sql[start..offset].to_ascii_lowercase());
        } else {
            tokens.push(char::from(bytes[offset]).to_string());
            offset += 1;
        }
    }
    Some(tokens)
}

/// Canonical byte lengths above this go to the on-disk blob tree; smaller
/// values stay inline in the `cas_objects` row. 100 KiB keeps the sqlite
/// row cache lean while sending only genuinely large payloads to files.
pub const INLINE_THRESHOLD: usize = 100 * 1024;

/// The tree-relative path a CAS member spelled `address` occupies:
/// `<address[0..2]>/<address>`, a 256-way shard.
///
/// THE definition of the blob layout, and the SHARD PRIMITIVE only: it does not
/// know what an address is, it slices the first two bytes off a string. Every
/// production caller reaches it through [`blob_relative_path_of_address`], which
/// does; [`CasStore::blob_path`] joins that onto a store root and
/// [`blob_relative_path_of_handle`] derives it from bytes for the backup capture
/// and restore — two spellings of one layout is how a restore ends up writing an
/// object where the store will not look for it.
///
/// # What it refuses
///
/// NOTHING, deliberately: it is one call away from restore code that handles
/// manifest-supplied strings, and a path helper that panics on one is a denial of
/// service in a preflight. `hex.get(0..2)` covers both a string shorter than two
/// bytes and a string whose byte 2 is not a UTF-8 character boundary, where
/// `&hex[0..2]` would panic and a `len() < 2` guard would not have helped.
/// Totality is not permissiveness downstream: a member path this rule could not
/// have emitted is refused before any target mutation by
/// `kata_core::store::backup`'s shape check.
///
/// Production input is always a [`CasAddress`] rendering — 64 lowercase hex, a
/// `.`, and a function label — so the shard is the address's own first two hex
/// characters and the fallback arm is unreachable from the store.
#[must_use]
pub fn blob_relative_path(hex: &str) -> String {
    match hex.get(0..2) {
        Some(shard) => format!("{shard}/{hex}"),
        None => hex.to_string(),
    }
}

/// The tree-relative path a CAS object with content address `address` occupies.
///
/// # Invariant
///
/// The on-disk layout is DERIVED FROM THE ADDRESS, function included: the file
/// is named by the address's full rendering (`<64 hex>.<function label>`), so a
/// blob on disk — and a member inside a backup artifact, which is the same
/// string — says which digest function verifies it, and an object addressed
/// under a future function can never land on a path this generation would look
/// at. The shard is the digest's first two hex characters, which is why the
/// rendering puts the digest first: the 256-way fan-out does not degenerate to a
/// per-function bucket.
///
/// # Failure mode
///
/// A file named by the bare 64-hex digest, with no function in the address,
/// would let a change of digest scheme reuse the same namespace AND the same
/// paths silently. See [`CasDigestFunction`].
///
/// # Enforcement point
///
/// The single production spelling. [`CasStore::blob_path`] and
/// [`blob_relative_path_of_handle`] both go through it.
#[must_use]
pub fn blob_relative_path_of_address(address: &CasAddress) -> String {
    blob_relative_path(&address.to_string())
}

/// The tree-relative path the bytes behind `file` require in a CAS blob tree.
///
/// # Why the backup asks the store instead of hashing for itself
///
/// A `cas` member's path is not a name, it is a content ADDRESS, and the scheme
/// that produces it belongs to this module — the domain tag, the length prefix,
/// and the shard layout. `crate::store::backup` binds a captured member's
/// CONTENT to its PATH by calling this and comparing; it never spells the scheme,
/// so a change here cannot leave the backup verifying against a layout the store
/// no longer uses.
///
/// # Why it takes a HANDLE and not a `&Path`
///
/// `crate::store::backup` reaches every tree member through an `openat(2)` walk
/// from a proven directory descriptor, precisely so no path is resolved a second
/// time. A sibling that took a `&Path` and opened it undid that at the last step:
/// the address would be derived from whatever the path resolved to on THIS open,
/// which need not be the object the walk proved. There is no path form, and `path`
/// here is rendered in errors and resolved by
/// nothing.
///
/// One streaming pass. The length is read from the OPEN HANDLE rather than from
/// the path, so a rename cannot substitute a different file between the stat and
/// the read, and the count is re-checked against it by
/// [`kata_types::cache::ObjectIdHasher::finish`].
///
/// # Errors
///
/// [`KataError::Storage`] if the file cannot be stat'ed or read, or if the bytes
/// streamed are not the length the handle reported — which means the file changed
/// under the read, and an immutable content-addressed object never legitimately
/// does.
pub fn blob_relative_path_of_handle(mut file: std::fs::File, path: &Path) -> KataResult<String> {
    use std::io::Read as _;

    let declared = file
        .metadata()
        .map_err(|e| {
            KataError::Storage(format!("cas address: stat {} failed: {e}", path.display()))
        })?
        .len();
    let mut hasher = kata_types::cache::ObjectIdHasher::for_canonical_len(declared);
    let mut buffer = vec![0_u8; 128 * 1024];
    loop {
        let read = file.read(&mut buffer).map_err(|e| {
            KataError::Storage(format!("cas address: read {} failed: {e}", path.display()))
        })?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    let address = hasher.finish().ok_or_else(|| {
        KataError::Storage(format!(
            "cas address: {} changed length under the read; a content-addressed object is \
             immutable, so its address cannot be derived from a file that is still moving",
            path.display()
        ))
    })?;
    Ok(blob_relative_path_of_address(&address))
}

fn open_blob_file(path: &Path) -> std::io::Result<std::fs::File> {
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    options.open(path)
}

fn verify_existing_blob(path: &Path, expected: &[u8]) -> KataResult<bool> {
    use std::io::Read as _;
    let refused = |reason: &str| {
        KataError::Storage(format!("cas existing blob {}: {reason}", path.display()))
    };
    let mut file = match open_blob_file(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(refused(&format!("open failed: {error}"))),
    };
    let metadata = file
        .metadata()
        .map_err(|error| refused(&format!("stat failed: {error}")))?;
    if !metadata.is_file() || metadata.len() != expected.len() as u64 {
        return Err(refused(
            "not a regular file with the expected content length",
        ));
    }
    let mut buffer = vec![0u8; 128 * 1024];
    for chunk in expected.chunks(buffer.len()) {
        file.read_exact(&mut buffer[..chunk.len()])
            .map_err(|error| refused(&format!("read failed: {error}")))?;
        if &buffer[..chunk.len()] != chunk {
            return Err(refused(
                "content differs from its expected address; preserve the corrupt file for diagnosis",
            ));
        }
    }
    if file
        .read(&mut buffer[..1])
        .map_err(|error| refused(&format!("read failed: {error}")))?
        != 0
    {
        return Err(refused("content grew during verification"));
    }
    file.sync_all()
        .map_err(|error| refused(&format!("fsync failed: {error}")))?;
    Ok(true)
}

/// PROOF that an object's bytes are durable and content-verified in the CAS.
///
/// Fields are private; [`CasStore::put_durable`] returns it after the verified bytes,
/// directory barriers and FULL SQLite commit. It exists so
/// an operational CAS root cannot name bytes that are not yet on disk:
/// object-before-reference holds across every plane, and the operational plane
/// is the one that could not check it for itself.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DurableObject {
    object_id: ObjectId,
    size: u64,
}

impl DurableObject {
    /// The object's content address.
    #[must_use]
    pub fn object_id(&self) -> ObjectId {
        self.object_id
    }

    /// The object's canonical byte length.
    #[must_use]
    pub fn size(&self) -> u64 {
        self.size
    }

    /// Forge a receipt WITHOUT writing bytes.
    ///
    /// Test-only, and named so a reviewer cannot mistake it for a production
    /// path: every test that needs a root over a synthetic digest would otherwise
    /// have to stand up a real `CasStore`, and the tests that must prove the
    /// ordering (the dangling-root verifier) need to construct the BROKEN state
    /// deliberately.
    #[cfg(any(test, feature = "test-support"))]
    #[doc(hidden)]
    #[must_use]
    pub fn __test_unwritten(object_id: ObjectId) -> Self {
        Self { object_id, size: 0 }
    }
}

/// Handle to the content-addressed value store.
pub struct CasStore {
    conn: Mutex<Connection>,
    db_path: PathBuf,
    blob_dir: PathBuf,
}

impl std::fmt::Debug for CasStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CasStore")
            .field("db_path", &self.db_path)
            .field("blob_dir", &self.blob_dir)
            .finish_non_exhaustive()
    }
}

impl CasStore {
    /// Validate the existing unversioned CAS authority without opening the
    /// source SQLite file for writes.
    pub fn refuse_noncurrent_file_schema(path: impl AsRef<Path>) -> KataResult<()> {
        let path = path.as_ref();
        let version = crate::store::sqlite_backed::stamped_user_version_from_files(path, "cas.db")?;
        if version != 0 {
            return Err(KataError::SchemaMigrationRequired(format!(
                "cas.db has unsupported schema stamp {version}; expected unversioned current shape"
            )));
        }
        Ok(())
    }

    fn validate_current_schema(conn: &Connection) -> KataResult<()> {
        let mut statement = conn
            .prepare("PRAGMA table_info(cas_objects)")
            .map_err(|e| KataError::Storage(format!("cas.db inspect schema: {e}")))?;
        let observed = statement
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(1)?,
                    sqlite_affinity(&row.get::<_, String>(2)?),
                    row.get::<_, i64>(3)?,
                    row.get::<_, i64>(5)?,
                ))
            })
            .map_err(|e| KataError::Storage(format!("cas.db inspect columns: {e}")))?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| KataError::Storage(format!("cas.db read columns: {e}")))?;
        let expected = [
            ("object_id", "BLOB", 1_i64, 1_i64),
            ("size", "INTEGER", 1, 0),
            ("storage", "TEXT", 1, 0),
            ("blob", "BLOB", 0, 0),
        ]
        .map(|(name, affinity, not_null, primary_key)| {
            (name.to_string(), affinity, not_null, primary_key)
        });
        if observed != expected {
            return Err(KataError::SchemaMigrationRequired(format!(
                "cas.db has column contract {observed:?}; expected current contract {expected:?}"
            )));
        }
        let sql: String = conn
            .query_row(
                "SELECT sql FROM sqlite_master WHERE type='table' AND name='cas_objects'",
                [],
                |row| row.get(0),
            )
            .map_err(|e| KataError::Storage(format!("cas.db read table contract: {e}")))?;
        if canonical_sql_tokens(&sql) != canonical_sql_tokens(CURRENT_CAS_TABLE_SQL) {
            return Err(KataError::SchemaMigrationRequired(
                "cas.db table definition is not the canonical current primary-key/storage constraint contract"
                    .to_string(),
            ));
        }
        Ok(())
    }

    /// Open (or create) the CAS at `db_path` with its blob tree at
    /// `blob_dir`. WAL commits use `synchronous=FULL`: a durable receipt may
    /// authorize a root in another database immediately after this commit. A
    /// write blocked by another connection's lock waits the workspace
    /// `BUSY_TIMEOUT_MS`, then fails `database is locked`.
    pub fn open(db_path: impl AsRef<Path>, blob_dir: impl AsRef<Path>) -> KataResult<Self> {
        let db_path = db_path.as_ref().to_path_buf();
        let blob_dir = blob_dir.as_ref().to_path_buf();
        crate::store::sqlite_backed::refuse_orphan_sidecars_for_missing_main(&db_path, "cas.db")?;
        let existing = db_path.exists();
        if existing {
            Self::refuse_noncurrent_file_schema(&db_path)?;
            // Checked before the table: the tree is made only after the table
            // commits, so every interrupted first creation OF THIS STORE lands
            // here. An installed main's never reaches it: its identity is
            // published only after every store is created, boot refuses an
            // identity-less directory first, and with an identity its preflight
            // refuses a missing `cas/` before any store opens.
            if !blob_dir.is_dir() {
                return Err(KataError::SchemaMigrationRequired(format!(
                    "cas.db exists but its required blob tree {} is missing or not a directory: \
                     either the content store's first creation was interrupted before the tree \
                     was made, or the tree was lost; use a new empty data directory and \
                     preserve this directory offline",
                    blob_dir.display()
                )));
            }
        } else if blob_dir.exists() {
            return Err(KataError::SchemaMigrationRequired(format!(
                "CAS blob tree {} exists without cas.db; refusing to create an empty authority",
                blob_dir.display()
            )));
        }
        if let Some(parent) = db_path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| {
                KataError::Storage(format!(
                    "cas create_dir_all({}) failed: {e}",
                    parent.display()
                ))
            })?;
        }
        let conn = if existing {
            let conn = crate::store::sqlite_backed::open_existing_for_schema_validation(
                &db_path, "cas.db",
            )?;
            Self::validate_current_schema(&conn)?;
            conn
        } else {
            Connection::open_with_flags(
                &db_path,
                OpenFlags::SQLITE_OPEN_READ_WRITE
                    | OpenFlags::SQLITE_OPEN_CREATE
                    | OpenFlags::SQLITE_OPEN_NO_MUTEX,
            )
            .map_err(|e| {
                KataError::Storage(format!("cas open({}) failed: {e}", db_path.display()))
            })?
        };
        // Set on both the create and the existing-file path, before any statement
        // that can contend: cas.db has a second writer (a worker's own open) whose
        // FULL commit holds the lock through its fsync.
        conn.pragma_update(
            None,
            "busy_timeout",
            crate::store::sqlite_backed::BUSY_TIMEOUT_MS,
        )
        .map_err(|e| KataError::Storage(format!("cas PRAGMA busy_timeout failed: {e}")))?;
        conn.pragma_update(None, "journal_mode", "WAL")
            .map_err(|e| KataError::Storage(format!("cas PRAGMA journal_mode=WAL failed: {e}")))?;
        conn.pragma_update(None, "synchronous", "FULL")
            .map_err(|e| KataError::Storage(format!("cas PRAGMA synchronous failed: {e}")))?;
        if !existing {
            conn.execute_batch(CURRENT_CAS_TABLE_SQL)
                .map_err(|e| KataError::Storage(format!("cas create table failed: {e}")))?;
        }

        std::fs::create_dir_all(blob_dir.join("tmp")).map_err(|e| {
            KataError::Storage(format!(
                "cas create blob dir({}) failed: {e}",
                blob_dir.display()
            ))
        })?;

        Ok(Self {
            conn: Mutex::new(conn),
            db_path,
            blob_dir,
        })
    }

    /// The blob-tree path for an object: `cas/<aa>/<64 hex>.<function>` where
    /// `<aa>` is the digest's first two hex characters (256-way shard).
    ///
    /// Joins [`blob_relative_path_of_address`] onto this store's root rather than
    /// spelling the layout again — the backup capture has to derive the same path
    /// from bytes alone, and two spellings of one layout is how a restore ends up
    /// writing an object where the store will not look for it.
    fn blob_path(&self, address: &CasAddress) -> PathBuf {
        self.blob_dir.join(blob_relative_path_of_address(address))
    }

    /// Store canonical bytes and return a RECEIPT proving they are durable and
    /// content-verified in this CAS.
    ///
    /// # Invariant
    ///
    /// This produces a [`DurableObject`], the only way to build an operational CAS
    /// root over an object (`CasRootSpec::for_object`). That is what carries the
    /// object-before-reference ordering across the THIRD plane: blob files, CAS
    /// metadata and operational roots cannot share a SQLite transaction, so the
    /// receipt proves the bytes and metadata were committed first.
    pub fn put_durable(&self, canonical_bytes: &[u8]) -> KataResult<DurableObject> {
        let object_id = self.put(canonical_bytes)?;
        // K8 — `operational.after_cas_object_durable_before_root`. The bytes are
        // fsync-durable and their `cas_objects` row is committed, and NO operational
        // root references them: this is the near edge of the
        // "between a CAS object byte becoming durable and its root insertion" window.
        //
        // The seam sits HERE, at the end of the only producer of a `DurableObject`,
        // rather than at some later point in a caller's transaction, for two reasons.
        // It is a chokepoint — a receipt is the sole way to construct an object root
        // (`CasRootSpec::for_object`), so every entry into the window passes through
        // this line and a new caller cannot miss it. And the durable state is
        // IDENTICAL at every point in the window (object present, root absent), so a
        // seam placed later would model the same recovery state while covering fewer
        // callers.
        crate::fault_inject::operational_crash_point("after_cas_object_durable_before_root");
        Ok(DurableObject {
            object_id,
            size: canonical_bytes.len() as u64,
        })
    }

    /// Store canonical bytes, returning their content address.
    ///
    /// `canonical_bytes` MUST already be canonicalised (see
    /// [`kata_types::idempotency::canonicalize_args`]) so equal-but-reordered
    /// values dedup to one object. A repeat object id inserts nothing and keeps
    /// the first-stored row — after checking that row agrees with the presented
    /// bytes: a stored row whose size, storage class or inline content differs is
    /// corruption, refused rather than trusted.
    ///
    /// Ordering (see the module docs): for a file-backed object the blob is
    /// written to `cas/tmp/<oid>.part`, `fsync`'d, atomically renamed into
    /// its shard, and the shard dir `fsync`'d — all BEFORE the `cas_objects`
    /// row is inserted. A failure anywhere in the blob write returns `Err`
    /// with no row written, so no reference can ever be committed against an
    /// absent blob.
    pub fn put(&self, canonical_bytes: &[u8]) -> KataResult<ObjectId> {
        let address = cas_address_for_canonical_bytes(canonical_bytes);
        let oid = address.hash();
        let size = i64::try_from(canonical_bytes.len()).map_err(|_| {
            KataError::Storage(format!(
                "cas object too large: {} bytes",
                canonical_bytes.len()
            ))
        })?;
        if canonical_bytes.len() > INLINE_THRESHOLD {
            self.write_blob_file(&address, canonical_bytes)?;
            let conn = self.conn.lock();
            let inserted = conn
                .execute(
                    "INSERT INTO cas_objects (object_id, size, storage, blob)
                     VALUES (?1, ?2, 'file', NULL) ON CONFLICT(object_id) DO NOTHING",
                    params![oid.as_bytes(), size],
                )
                .map_err(|e| KataError::Storage(format!("cas insert (file) failed: {e}")))?;
            if inserted == 0
                && !stored_row_agrees(
                    &conn,
                    "SELECT EXISTS(SELECT 1 FROM cas_objects WHERE object_id = ?1 AND size = ?2
                       AND storage = 'file' AND blob IS NULL)",
                    params![oid.as_bytes(), size],
                )?
            {
                return Err(KataError::Storage(format!(
                    "cas existing object {oid} has inconsistent file metadata"
                )));
            }
        } else {
            let conn = self.conn.lock();
            let inserted = conn
                .execute(
                    "INSERT INTO cas_objects (object_id, size, storage, blob)
                     VALUES (?1, ?2, 'inline', ?3) ON CONFLICT(object_id) DO NOTHING",
                    params![oid.as_bytes(), size, canonical_bytes],
                )
                .map_err(|e| KataError::Storage(format!("cas insert (inline) failed: {e}")))?;
            if inserted == 0
                && !stored_row_agrees(
                    &conn,
                    "SELECT EXISTS(SELECT 1 FROM cas_objects WHERE object_id = ?1 AND size = ?2
                       AND storage = 'inline' AND blob = ?3)",
                    params![oid.as_bytes(), size, canonical_bytes],
                )?
            {
                return Err(KataError::Storage(format!(
                    "cas existing object {oid} has inconsistent inline content or metadata"
                )));
            }
        }
        Ok(oid)
    }

    /// Durable blob write: tmp file → fsync → atomic rename → fsync shard.
    fn write_blob_file(&self, address: &CasAddress, bytes: &[u8]) -> KataResult<()> {
        let rendered = address.to_string();
        let final_path = self.blob_path(address);
        let shard_dir = final_path
            .parent()
            .expect("blob path always has a shard parent")
            .to_path_buf();
        // The address names the expected content; it cannot prove that an
        // existing file still contains it. Refuse corruption before recording
        // metadata or allowing a durable receipt to authorize a new root.
        if verify_existing_blob(&final_path, bytes)? {
            return self.sync_blob_directories(&shard_dir);
        }
        std::fs::create_dir_all(&shard_dir).map_err(|e| {
            KataError::Storage(format!(
                "cas create shard dir({}) failed: {e}",
                shard_dir.display()
            ))
        })?;
        // Per-writer UNIQUE tmp name (pid + a process-global sequence): a fixed
        // `{hex}.part` shared by concurrent writers of the SAME content races —
        // one `File::create` truncates while another is mid-write, and after the
        // first `rename` consumes the tmp the second `rename` fails NotFound →
        // a spurious put Err.
        let seq = TMP_SEQ.fetch_add(1, atomic::Ordering::Relaxed);
        let tmp_path = self
            .blob_dir
            .join("tmp")
            .join(format!("{rendered}.{}.{seq}.part", std::process::id()));
        {
            let mut f = std::fs::File::create(&tmp_path).map_err(|e| {
                KataError::Storage(format!(
                    "cas create tmp blob({}) failed: {e}",
                    tmp_path.display()
                ))
            })?;
            // Clean up the `.part` on ANY write/fsync failure so a partial write
            // never leaks a tmp file: nothing else ever removes one.
            if let Err(e) = f.write_all(bytes).and_then(|()| f.sync_all()) {
                drop(f);
                let _ = std::fs::remove_file(&tmp_path);
                return Err(KataError::Storage(format!(
                    "cas write/fsync tmp blob failed: {e}"
                )));
            }
        }
        std::fs::rename(&tmp_path, &final_path).map_err(|e| {
            // Best-effort cleanup of the tmp file so a failed rename doesn't
            // leak a `.part`.
            let _ = std::fs::remove_file(&tmp_path);
            KataError::Storage(format!("cas rename blob into shard failed: {e}"))
        })?;
        self.sync_blob_directories(&shard_dir)
    }

    fn sync_blob_directories(&self, shard: &Path) -> KataResult<()> {
        // The file name, its shard, and the blob root must all survive before
        // metadata in another WAL can certify this object as durable.
        let parent = self.blob_dir.parent().map(|path| {
            if path.as_os_str().is_empty() {
                Path::new(".")
            } else {
                path
            }
        });
        for path in [Some(shard), Some(self.blob_dir.as_path()), parent]
            .into_iter()
            .flatten()
        {
            std::fs::File::open(path)
                .and_then(|directory| directory.sync_all())
                .map_err(|error| {
                    KataError::Storage(format!(
                        "cas sync blob directory {} failed: {error}",
                        path.display()
                    ))
                })?;
        }
        Ok(())
    }

    /// Whether the object RESOLVES: its row exists AND, for a file-backed
    /// object, its blob is present on disk.
    ///
    /// Checking the row alone would be the wrong question for the dangling-root
    /// verifier: a missing blob can leave its metadata row intact. Current recovery
    /// artifacts capture the blob tree as well as its database, but a row-only
    /// check would still miss subsequent blob loss. This is a presence check, not
    /// content verification; authoritative operational outputs use bounded verified
    /// reads instead.
    pub fn resolves(&self, oid: &ObjectId) -> KataResult<bool> {
        let conn = self.conn.lock();
        let storage: Option<String> = conn
            .query_row(
                "SELECT storage FROM cas_objects WHERE object_id = ?1",
                params![oid.as_bytes()],
                |r| r.get(0),
            )
            .optional()
            .map_err(|e| KataError::Storage(format!("cas resolves select failed: {e}")))?;
        drop(conn);
        Ok(match storage {
            None => false,
            Some(storage) if storage == "file" => {
                self.blob_path(&CasAddress::blake3(*oid)).is_file()
            }
            Some(_) => true,
        })
    }

    /// The RECORDED LENGTH of a stored object, or `None` when the store holds no row
    /// for it.
    ///
    /// # What it answers and what it deliberately does not
    ///
    /// PRESENCE AND LENGTH, read off `cas_objects`. It does not rehash, does not stat a
    /// file-backed blob, and is therefore NOT an integrity check — integrity is
    /// [`Self::get_verified`]'s, at the moment the bytes are read, which is the only
    /// moment at which it means anything. The distinction is stated because the caller
    /// this exists for (`OperationalDb::adopt_capsule_result`) checks a tree manifest's
    /// members and would otherwise be read as having verified them.
    ///
    /// It is a separate verb from [`Self::resolves`] rather than a widening of it: that
    /// one answers "can these bytes be produced" and consults the FILESYSTEM for a
    /// file-backed object, which is a different question with a different cost.
    ///
    /// # Errors
    ///
    /// Storage failures only.
    pub fn recorded_size(&self, oid: &ObjectId) -> KataResult<Option<u64>> {
        let conn = self.conn.lock();
        let size: Option<i64> = conn
            .query_row(
                "SELECT size FROM cas_objects WHERE object_id = ?1",
                params![oid.as_bytes()],
                |r| r.get(0),
            )
            .optional()
            .map_err(|e| KataError::Storage(format!("cas recorded_size select failed: {e}")))?;
        drop(conn);
        size.map(|size| {
            u64::try_from(size).map_err(|_| {
                KataError::Storage(format!(
                    "cas_objects.size is negative ({size}) for object {oid}"
                ))
            })
        })
        .transpose()
    }

    /// Fetch an object's bytes by content address. `Ok(None)` when no such
    /// object is known; an explicit `Err` when a known file-backed object's
    /// blob is missing on disk. This cache-oriented read does not rehash bytes;
    /// authoritative references use [`Self::get_verified`].
    pub fn get(&self, oid: &ObjectId) -> KataResult<Option<Vec<u8>>> {
        let conn = self.conn.lock();
        let row: Option<(String, Option<Vec<u8>>)> = conn
            .query_row(
                "SELECT storage, blob FROM cas_objects WHERE object_id = ?1",
                params![oid.as_bytes()],
                |r| Ok((r.get::<_, String>(0)?, r.get::<_, Option<Vec<u8>>>(1)?)),
            )
            .optional()
            .map_err(|e| KataError::Storage(format!("cas select failed: {e}")))?;
        drop(conn);

        match row {
            None => Ok(None),
            Some((storage, blob)) if storage == "inline" => blob.map(Some).ok_or_else(|| {
                KataError::Storage(format!("cas inline object {oid} has a NULL blob"))
            }),
            Some(_) => {
                let path = self.blob_path(&CasAddress::blake3(*oid));
                match std::fs::read(&path) {
                    Ok(bytes) => Ok(Some(bytes)),
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                        Err(KataError::Storage(format!(
                            "cas file object {oid} blob missing on disk: {}",
                            path.display()
                        )))
                    }
                    Err(e) => Err(KataError::Storage(format!(
                        "cas read blob({}) failed: {e}",
                        path.display()
                    ))),
                }
            }
        }
    }

    /// Verify an address-only authoritative root using its stored length and a
    /// caller-supplied allocation bound. Missing or inconsistent content refuses.
    pub fn get_verified_bounded(&self, oid: &ObjectId, maximum_size: u64) -> KataResult<Vec<u8>> {
        let size: Option<i64> = self
            .conn
            .lock()
            .query_row(
                "SELECT size FROM cas_objects WHERE object_id = ?1",
                params![oid.as_bytes()],
                |row| row.get(0),
            )
            .optional()
            .map_err(|error| {
                KataError::Storage(format!(
                    "cas verified object {oid}: read length failed: {error}"
                ))
            })?;
        let size = size
            .and_then(|size| u64::try_from(size).ok())
            .ok_or_else(|| {
                KataError::Storage(format!(
                    "cas verified object {oid}: missing or invalid stored length"
                ))
            })?;
        self.get_verified(oid, size, maximum_size)
    }

    /// Resolve a reference carrying its own expected length, checking the bound
    /// before retrieving any payload bytes.
    pub fn get_verified(
        &self,
        oid: &ObjectId,
        expected_size: u64,
        maximum_size: u64,
    ) -> KataResult<Vec<u8>> {
        Self::read_verified(
            &self.conn.lock(),
            &self.blob_dir,
            oid,
            expected_size,
            maximum_size,
        )
    }

    /// Verify against an already opened database and blob root, including an
    /// immutable captured artifact. This performs no writes or lock-file creation.
    pub fn read_verified(
        connection: &Connection,
        blob_dir: &Path,
        oid: &ObjectId,
        expected_size: u64,
        maximum_size: u64,
    ) -> KataResult<Vec<u8>> {
        use std::io::Read as _;
        let refused =
            |reason: &str| KataError::Storage(format!("cas verified object {oid}: {reason}"));
        if expected_size > maximum_size {
            return Err(refused("declared length exceeds the caller's bound"));
        }
        let expected = usize::try_from(expected_size)
            .map_err(|_| refused("declared length exceeds addressable memory"))?;
        let sqlite_size = i64::try_from(expected_size)
            .map_err(|_| refused("declared length exceeds SQLite's length domain"))?;
        // A malformed inline row cannot make SQLite hand us an unbounded blob:
        // its payload is selected only after both lengths and its type match.
        let row: Option<(i64, i64, bool, Option<Vec<u8>>)> = connection
            .query_row(
                "SELECT size, CASE storage WHEN 'inline' THEN 0 WHEN 'file' THEN 1 ELSE 2 END,
                    blob IS NULL,
                    CASE WHEN size = ?2 AND storage = 'inline' AND typeof(blob) = 'blob'
                              AND length(blob) = ?2 THEN blob ELSE NULL END
             FROM cas_objects WHERE object_id = ?1",
                params![oid.as_bytes(), sqlite_size],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .optional()
            .map_err(|error| refused(&format!("read metadata failed: {error}")))?;
        let (size, storage, blob_is_null, inline) =
            row.ok_or_else(|| refused("metadata is missing"))?;
        if size != sqlite_size {
            return Err(refused("stored length disagrees with the reference"));
        }
        let bytes = match storage {
            0 if expected <= INLINE_THRESHOLD => {
                inline.ok_or_else(|| refused("inline content has the wrong type or length"))?
            }
            1 if expected > INLINE_THRESHOLD && blob_is_null => {
                let path = blob_dir.join(blob_relative_path_of_address(&CasAddress::blake3(*oid)));
                let mut file = open_blob_file(&path).map_err(|error| {
                    refused(&format!("open blob {} failed: {error}", path.display()))
                })?;
                let metadata = file
                    .metadata()
                    .map_err(|error| refused(&format!("stat blob failed: {error}")))?;
                if !metadata.is_file() || metadata.len() != expected_size {
                    return Err(refused(
                        "blob is not a regular file with the declared length",
                    ));
                }
                let mut bytes = Vec::new();
                bytes.try_reserve_exact(expected).map_err(|error| {
                    refused(&format!("reserve bounded content failed: {error}"))
                })?;
                bytes.resize(expected, 0);
                file.read_exact(&mut bytes)
                    .map_err(|error| refused(&format!("read blob failed: {error}")))?;
                if file
                    .read(&mut [0u8; 1])
                    .map_err(|error| refused(&format!("read blob end failed: {error}")))?
                    != 0
                {
                    return Err(refused("blob grew during verification"));
                }
                bytes
            }
            _ => {
                return Err(refused(
                    "storage metadata is inconsistent with the declared content",
                ));
            }
        };
        if cas_address_for_canonical_bytes(&bytes).hash() != *oid {
            return Err(refused("content does not match its address"));
        }
        Ok(bytes)
    }

    /// Force a full WAL checkpoint so `cas.db` is crash-consistent and
    /// self-contained (mirrors `SqliteWorkflowStore::checkpoint`).
    pub fn checkpoint(&self) -> KataResult<()> {
        let conn = self.conn.lock();
        conn.query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |row| {
            row.get::<_, i64>(0)
        })
        .map_err(|e| KataError::Storage(format!("cas wal_checkpoint(TRUNCATE) failed: {e}")))?;
        Ok(())
    }
}

impl CasStore {
    /// Test-only: number of rows in `cas_objects` (dedup assertions).
    #[doc(hidden)]
    #[cfg(any(test, feature = "test-support"))]
    pub fn __test_object_count(&self) -> KataResult<u64> {
        let conn = self.conn.lock();
        let n: i64 = conn
            .query_row("SELECT count(*) FROM cas_objects", [], |r| r.get(0))
            .map_err(|e| KataError::Storage(format!("cas count failed: {e}")))?;
        Ok(u64::try_from(n).unwrap_or(0))
    }

    /// Test-only: on-disk blob path for an object (may or may not exist).
    #[doc(hidden)]
    #[must_use]
    #[cfg(any(test, feature = "test-support"))]
    pub fn __test_blob_path(&self, oid: &ObjectId) -> PathBuf {
        self.blob_path(&CasAddress::blake3(*oid))
    }
}

/// Whether the stored row for a re-put object agrees with the presented bytes.
fn stored_row_agrees(
    conn: &Connection,
    sql: &str,
    params: impl rusqlite::Params,
) -> KataResult<bool> {
    conn.query_row(sql, params, |row| row.get(0))
        .map_err(|e| KataError::Storage(format!("cas read existing object failed: {e}")))
}

#[cfg(test)]
mod receipt_durability_tests {
    use super::*;

    #[test]
    fn durable_receipts_require_full_sqlite_commit_sync() {
        let root = tempfile::tempdir().unwrap();
        let cas = CasStore::open(root.path().join("cas.db"), root.path().join("cas")).unwrap();
        let configured: i64 = cas
            .conn
            .lock()
            .query_row("PRAGMA synchronous", [], |row| row.get(0))
            .unwrap();
        assert_eq!(
            configured, 2,
            "an authoritative receipt must not acknowledge an unsynced WAL commit"
        );
    }

    /// Both open paths arm the workspace busy budget on the store's OWN
    /// connection (`busy_timeout` is per connection and not persisted, so a
    /// second handle would report its own). rusqlite arms 5000 ms on open by
    /// itself, so this reads equal to `BUSY_TIMEOUT_MS` without the explicit
    /// pragma only while the two numbers coincide.
    #[test]
    fn cas_open_arms_the_workspace_busy_timeout_on_create_and_reopen() {
        let root = tempfile::tempdir().unwrap();
        let db = root.path().join("cas.db");
        let blobs = root.path().join("cas");
        let read = |cas: &CasStore| -> i64 {
            cas.conn
                .lock()
                .query_row("PRAGMA busy_timeout", [], |row| row.get(0))
                .unwrap()
        };
        let created = CasStore::open(&db, &blobs).unwrap();
        assert_eq!(
            read(&created),
            crate::store::sqlite_backed::BUSY_TIMEOUT_MS,
            "create path"
        );
        drop(created);
        assert!(
            db.exists(),
            "the reopen below must take the existing-file path"
        );
        let reopened = CasStore::open(&db, &blobs).unwrap();
        assert_eq!(
            read(&reopened),
            crate::store::sqlite_backed::BUSY_TIMEOUT_MS,
            "existing-file path"
        );
    }
}

#[cfg(test)]
mod schema_contract_tests {
    use super::*;

    fn create_cas_fixture(path: &Path, table_sql: &str) {
        let conn = Connection::open(path).unwrap();
        conn.execute_batch(table_sql).unwrap();
        conn.pragma_update(None, "user_version", 0).unwrap();
    }

    #[test]
    fn a_storage_check_spelled_only_in_a_comment_is_not_the_current_contract() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("cas.db");
        let blobs = dir.path().join("cas");
        std::fs::create_dir(&blobs).unwrap();
        create_cas_fixture(
            &db,
            "CREATE TABLE cas_objects (
                object_id BLOB NOT NULL PRIMARY KEY,
                size INTEGER NOT NULL,
                storage TEXT NOT NULL /* CHECK(storage IN ('inline','file')) */,
                blob BLOB
            );",
        );
        let conn = Connection::open(&db).unwrap();
        conn.execute(
            "INSERT INTO cas_objects VALUES (x'01', 1, 'not-a-storage-kind', NULL)",
            [],
        )
        .unwrap();
        drop(conn);

        let error = CasStore::open(&db, &blobs)
            .expect_err("a comment must not impersonate the storage-domain constraint");
        assert!(matches!(error, KataError::SchemaMigrationRequired(_)));
    }

    /// A `cas.db` written before the store stopped recording object age — its table
    /// still carries the retired `created_at` column — is refused at open, by the
    /// column contract every open checks, rather than adopted with a column nothing
    /// writes.
    #[test]
    fn a_cas_db_carrying_the_retired_created_at_column_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("cas.db");
        let blobs = dir.path().join("cas");
        std::fs::create_dir(&blobs).unwrap();
        create_cas_fixture(
            &db,
            "CREATE TABLE cas_objects (
                object_id BLOB NOT NULL PRIMARY KEY,
                size INTEGER NOT NULL,
                storage TEXT NOT NULL CHECK(storage IN ('inline','file')),
                blob BLOB,
                created_at INTEGER NOT NULL
            );",
        );

        let error = CasStore::open(&db, &blobs)
            .expect_err("a cas.db of the retired shape must be refused, not adopted");
        assert!(
            matches!(&error, KataError::SchemaMigrationRequired(message)
                if message.contains("column contract")),
            "{error:?}"
        );
    }

    /// An interrupted FIRST creation of the content store leaves `cas.db` without
    /// its blob tree: `open` creates the file, switches it to WAL, commits the
    /// table, and only then makes the tree, so a death anywhere in that sequence
    /// leaves the file — with or without its table — and no tree. That is not an
    /// older shape, so the refusal names the two causes it cannot tell apart and
    /// the new-empty-directory recourse. Both shapes are built by the filesystem
    /// and a raw SQLite handle, and each file is left byte-identical.
    #[test]
    fn an_interrupted_first_creation_is_refused_naming_both_causes() {
        let dir = tempfile::tempdir().unwrap();
        let empty = dir.path().join("empty");
        std::fs::create_dir(&empty).unwrap();
        std::fs::File::create(empty.join("cas.db")).unwrap();
        let tabled = dir.path().join("tabled");
        std::fs::create_dir(&tabled).unwrap();
        {
            let raw = Connection::open(tabled.join("cas.db")).unwrap();
            let mode: String = raw
                .query_row("PRAGMA journal_mode=WAL", [], |row| row.get(0))
                .unwrap();
            assert_eq!(mode, "wal");
            raw.execute_batch("CREATE TABLE cas_objects(object_id BLOB PRIMARY KEY)")
                .unwrap();
        }

        for root in [&empty, &tabled] {
            let db = root.join("cas.db");
            let blobs = root.join("cas");
            let before = std::fs::read(&db).unwrap();
            let error =
                CasStore::open(&db, &blobs).expect_err("a cas.db without its blob tree is refused");
            assert!(
                matches!(error, KataError::SchemaMigrationRequired(_)),
                "{error:?}"
            );
            let message = error.to_string();
            assert!(
                message.contains("first creation was interrupted")
                    && message.contains("the tree was lost")
                    && message.contains(
                        "use a new empty data directory and preserve this directory offline"
                    ),
                "{}: {message}",
                root.display()
            );
            assert!(!blobs.exists(), "the refusal creates no blob tree");
            assert_eq!(
                std::fs::read(&db).unwrap(),
                before,
                "the refusal writes nothing"
            );
        }
    }

    #[test]
    fn harmless_spacing_and_comments_preserve_the_current_cas_contract() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("cas.db");
        let blobs = dir.path().join("cas");
        std::fs::create_dir(&blobs).unwrap();
        create_cas_fixture(
            &db,
            "CREATE /* harmless */ TABLE cas_objects(
                object_id BLOB NOT NULL PRIMARY KEY,
                size INTEGER NOT NULL,
                storage TEXT NOT NULL CHECK ( storage IN ( 'inline' , 'file' ) ),
                blob BLOB
            );",
        );

        CasStore::open(&db, &blobs).expect("equivalent current DDL must reopen");
    }
}

#[cfg(test)]
mod address_layout_tests {
    use super::{blob_relative_path, blob_relative_path_of_address};
    use kata_types::cache::{CasAddress, cas_address_for_canonical_bytes};

    /// The blob layout is DERIVED FROM THE ADDRESS, function included.
    ///
    /// INVARIANT: `<digest[0..2]>/<digest>.<function>`. The digest leads so the
    /// 256-way shard is a fan-out over content, not one bucket per function;
    /// the function trails so a blob file — and the identically-named member
    /// inside a backup artifact — says what verifies it.
    ///
    /// FAILURE MODE: a file named by the bare 64-hex digest would let an
    /// address-scheme change reuse the same paths as well as the same namespace,
    /// and a restore could write a previous generation's object exactly where this
    /// generation looks for a different one.
    ///
    /// ENFORCEMENT POINT: `blob_relative_path_of_address`, the single
    /// production spelling — `CasStore::blob_path` and
    /// `blob_relative_path_of_handle` both go through it.
    #[test]
    fn the_blob_layout_is_derived_from_the_address_and_carries_its_function() {
        let address = cas_address_for_canonical_bytes(b"a canonical payload");
        let digest = address.hash().to_string();
        assert_eq!(digest.len(), 64);

        assert_eq!(
            blob_relative_path_of_address(&address),
            format!("{}/{digest}.blake3", &digest[0..2]),
            "the shard is the DIGEST's first two hex characters and the function trails the name"
        );
        // The path is exactly two components, which is what
        // `kata_core::store::backup`'s member-shape check requires of a CAS
        // member. A layout that put the function in its own directory would be
        // three and would be refused by that check.
        assert_eq!(
            blob_relative_path_of_address(&address).split('/').count(),
            2
        );
        // ROUND TRIP: the file NAME alone is enough to recover the address, so a
        // blob file says what verifies it without its `cas_objects` row.
        let name = blob_relative_path_of_address(&address)
            .rsplit_once('/')
            .expect("two components")
            .1
            .to_string();
        assert_eq!(name.parse::<CasAddress>(), Ok(address));
    }

    /// The shard primitive is TOTAL, and production never reaches its fallback.
    ///
    /// INVARIANT: `blob_relative_path` never panics, for any string.
    ///
    /// FAILURE MODE: it sits one call away from restore code that handles
    /// MANIFEST-SUPPLIED strings; `&hex[0..2]` panics both on a string shorter
    /// than two bytes and on a string whose byte 2 is not a UTF-8 character
    /// boundary, and a panicking path helper is a denial of service in a
    /// preflight. A `len() < 2` guard covers the first class and panics on the
    /// second, which is why the code slices with `get(0..2)`.
    ///
    /// ENFORCEMENT POINT: the `None` arm of `hex.get(0..2)`.
    ///
    /// PROOF: both classes below, plus the statement that a real address cannot
    /// reach either — so totality is a robustness property of the primitive and
    /// not a shape the store can emit.
    #[test]
    fn the_shard_primitive_falls_back_rather_than_panicking_and_production_never_needs_it() {
        assert_eq!(
            blob_relative_path("ab"),
            "ab/ab",
            "two bytes is the boundary"
        );
        // CLASS 1 — shorter than the shard. Not `"/a"`, which would resolve to
        // an ABSOLUTE path once joined onto a store root.
        assert_eq!(blob_relative_path("a"), "a");
        assert_eq!(blob_relative_path(""), "");
        // CLASS 2 — two bytes exist but byte 2 is not a character boundary.
        let euro = "\u{20AC}";
        assert_eq!(euro.len(), 3, "the fixture must be multi-byte");
        assert_eq!(blob_relative_path(euro), euro);

        // And the fallback is unreachable from the store: every production
        // input is a rendered address, which always leads with 64 hex bytes.
        let rendered = cas_address_for_canonical_bytes(b"").to_string();
        assert!(rendered.len() > 2 && rendered.is_char_boundary(2));
        assert_eq!(
            blob_relative_path(&rendered),
            format!("{}/{rendered}", &rendered[0..2])
        );
    }
}
