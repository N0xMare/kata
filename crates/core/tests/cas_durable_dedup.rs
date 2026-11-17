//! A content address is not evidence that existing bytes still match it.
use kata_core::store::{CasStore, INLINE_THRESHOLD};

#[test]
fn durable_blob_dedup_preserves_valid_bytes_and_refuses_corrupt_existing_bytes() {
    for length_delta in [-1isize, 0, 1] {
        let root = tempfile::tempdir().unwrap();
        let database = root.path().join("cas.db");
        let cas = CasStore::open(&database, root.path().join("cas")).unwrap();
        let original = vec![b'a'; INLINE_THRESHOLD + 4096];
        let receipt = cas.put_durable(&original).unwrap();
        let path = cas.__test_blob_path(&receipt.object_id());
        assert_eq!(std::fs::read(&path).unwrap(), original);
        let repeated = cas.put_durable(&original).unwrap();
        assert_eq!(repeated.object_id(), receipt.object_id());
        assert_eq!(repeated.size(), original.len() as u64);
        assert_eq!(std::fs::read(&path).unwrap(), original);

        let sql = rusqlite::Connection::open(&database).unwrap();
        let corrupted = vec![b'b'; original.len().checked_add_signed(length_delta).unwrap()];
        std::fs::write(&path, &corrupted).unwrap();
        let error = cas
            .put_durable(&original)
            .expect_err("a corrupt existing blob must not earn an authoritative durable receipt");
        assert!(error.to_string().contains("existing blob"), "{error}");
        assert_eq!(
            std::fs::read(&path).unwrap(),
            corrupted,
            "preserve corruption evidence"
        );
        let rows: i64 = sql
            .query_row("SELECT count(*) FROM cas_objects", [], |row| row.get(0))
            .unwrap();
        assert_eq!(rows, 1, "failed verification must not add object metadata");
    }
}

#[test]
fn durable_blob_dedup_refuses_corrupt_orphan_without_inserting_metadata() {
    let root = tempfile::tempdir().unwrap();
    let database = root.path().join("cas.db");
    let cas = CasStore::open(&database, root.path().join("cas")).unwrap();
    let original = vec![b'a'; INLINE_THRESHOLD + 4096];
    let receipt = cas.put_durable(&original).unwrap();
    let path = cas.__test_blob_path(&receipt.object_id());
    let sql = rusqlite::Connection::open(&database).unwrap();
    sql.execute("DELETE FROM cas_objects", []).unwrap();
    let corrupted = vec![b'b'; original.len()];
    std::fs::write(&path, &corrupted).unwrap();
    cas.put_durable(&original)
        .expect_err("a corrupt orphan cannot become a durable object");
    assert_eq!(std::fs::read(&path).unwrap(), corrupted);
    let rows: i64 = sql
        .query_row("SELECT count(*) FROM cas_objects", [], |row| row.get(0))
        .unwrap();
    assert_eq!(rows, 0);
}

#[cfg(unix)]
#[test]
fn durable_blob_publication_refuses_a_real_shard_directory_sync_open_failure() {
    use std::os::unix::fs::PermissionsExt as _;
    let root = tempfile::tempdir().unwrap();
    let database = root.path().join("cas.db");
    let cas = CasStore::open(&database, root.path().join("cas")).unwrap();
    let original = vec![b'a'; INLINE_THRESHOLD + 4096];
    let oid = kata_types::cache::cas_address_for_canonical_bytes(&original).hash();
    let path = cas.__test_blob_path(&oid);
    let shard = path.parent().unwrap();
    std::fs::create_dir_all(shard).unwrap();
    // Write+search permits the real rename, but opening the directory for
    // fsync must fail with EACCES. No injected I/O error substitutes for it.
    std::fs::set_permissions(shard, std::fs::Permissions::from_mode(0o300)).unwrap();
    let open_error = std::fs::File::open(shard).unwrap_err();
    assert_eq!(open_error.raw_os_error(), Some(libc::EACCES));
    let result = cas.put_durable(&original);
    std::fs::set_permissions(shard, std::fs::Permissions::from_mode(0o700)).unwrap();
    result.expect_err("a failed directory durability barrier cannot earn a receipt");
    assert_eq!(
        std::fs::read(path).unwrap(),
        original,
        "unclaimed durable bytes remain available for diagnosis/retry"
    );
    let sql = rusqlite::Connection::open(&database).unwrap();
    let rows: i64 = sql
        .query_row("SELECT count(*) FROM cas_objects", [], |row| row.get(0))
        .unwrap();
    assert_eq!(rows, 0);
    cas.put_durable(&original)
        .expect("after restoring directory access, the same orphan is recoverable");
}

#[test]
fn durable_inline_dedup_refuses_corrupt_metadata_without_rewriting_it() {
    for corruption in [
        "blob = X'626164'",
        "size = size + 1",
        "storage = 'file', blob = NULL",
    ] {
        let root = tempfile::tempdir().unwrap();
        let database = root.path().join("cas.db");
        let cas = CasStore::open(&database, root.path().join("cas")).unwrap();
        let original = b"retained inline outcome";
        let receipt = cas.put_durable(original).unwrap();
        assert_eq!(
            cas.put_durable(original).unwrap().object_id(),
            receipt.object_id()
        );
        let sql = rusqlite::Connection::open(&database).unwrap();
        sql.execute(&format!("UPDATE cas_objects SET {corruption}"), [])
            .unwrap();
        let row = |sql: &rusqlite::Connection| -> (i64, String, Option<Vec<u8>>) {
            sql.query_row("SELECT size, storage, blob FROM cas_objects", [], |row| {
                Ok((row.get(0)?, row.get(1)?, row.get(2)?))
            })
            .unwrap()
        };
        let corrupted = row(&sql);
        cas.put_durable(original)
            .expect_err("corrupt retained inline bytes or metadata must not earn a receipt");
        assert_eq!(
            row(&sql),
            corrupted,
            "a refused re-put must leave the corrupt row as evidence, not rewrite it"
        );
    }
}

#[cfg(unix)]
#[test]
fn durable_blob_dedup_refuses_symlinks_and_readerless_fifos() {
    for fifo in [false, true] {
        let root = tempfile::tempdir().unwrap();
        let cas = CasStore::open(root.path().join("cas.db"), root.path().join("cas")).unwrap();
        let original = vec![b'a'; INLINE_THRESHOLD + 4096];
        let receipt = cas.put_durable(&original).unwrap();
        let path = cas.__test_blob_path(&receipt.object_id());
        let retained = root.path().join("retained-valid-blob");
        std::fs::rename(&path, &retained).unwrap();
        if fifo {
            nix::unistd::mkfifo(&path, nix::sys::stat::Mode::from_bits_truncate(0o600)).unwrap();
        } else {
            std::os::unix::fs::symlink(&retained, &path).unwrap();
        }
        cas.put_durable(&original)
            .expect_err("a special entry cannot certify local durable content");
        cas.get_verified(
            &receipt.object_id(),
            original.len() as u64,
            original.len() as u64,
        )
        .expect_err("authoritative reads also refuse special entries");
        assert_eq!(std::fs::read(retained).unwrap(), original);
    }
}

#[test]
fn verified_reads_bind_bounded_inline_and_file_bytes_to_the_requested_address() {
    for size in [32, INLINE_THRESHOLD + 4096] {
        let root = tempfile::tempdir().unwrap();
        let database = root.path().join("cas.db");
        let blob_dir = root.path().join("cas");
        let cas = CasStore::open(&database, &blob_dir).unwrap();
        let original = vec![b'a'; size];
        let receipt = cas.put_durable(&original).unwrap();
        let oid = receipt.object_id();
        assert_eq!(
            cas.get_verified_bounded(&oid, size as u64).unwrap(),
            original
        );
        assert!(cas.get_verified_bounded(&oid, size as u64 - 1).is_err());
        assert_eq!(
            cas.get_verified(&oid, size as u64, size as u64).unwrap(),
            original
        );
        assert!(
            cas.get_verified(&oid, size as u64, size as u64 - 1)
                .is_err()
        );
        assert!(
            cas.get_verified(&oid, size as u64 - 1, size as u64)
                .is_err()
        );
        let read_only = rusqlite::Connection::open_with_flags(
            &database,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
        )
        .unwrap();
        assert_eq!(
            CasStore::read_verified(&read_only, &blob_dir, &oid, size as u64, size as u64).unwrap(),
            original
        );
        let sql = rusqlite::Connection::open(&database).unwrap();
        if size <= INLINE_THRESHOLD {
            sql.execute("UPDATE cas_objects SET blob = ?1", [vec![b'b'; size]])
                .unwrap();
        } else {
            std::fs::write(cas.__test_blob_path(&oid), vec![b'b'; size]).unwrap();
        }
        let error = cas
            .get_verified(&oid, size as u64, size as u64)
            .unwrap_err();
        assert!(error.to_string().contains("address"), "{error}");
        if size <= INLINE_THRESHOLD {
            sql.execute("UPDATE cas_objects SET blob = zeroblob(1048576)", [])
                .unwrap();
        } else {
            let file = std::fs::File::create(cas.__test_blob_path(&oid)).unwrap();
            file.set_len(1 << 32).unwrap();
        }
        assert!(
            cas.get_verified(&oid, size as u64, size as u64).is_err(),
            "oversized physical content must refuse before loading"
        );
        sql.execute("DELETE FROM cas_objects", []).unwrap();
        assert!(
            cas.get_verified(&oid, size as u64, size as u64).is_err(),
            "authoritative absence is an error"
        );
    }
}
