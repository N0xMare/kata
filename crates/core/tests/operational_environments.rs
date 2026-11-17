//! The declared Nix managed-software environments, observed through a SECOND
//! raw rusqlite handle rather than through the API under test.
//!
//! # Invariant
//!
//! EVERY assertion about durable state here reads `operational.db` (or `cas.db`)
//! through a connection this file opens itself. Asking `OperationalDb` whether
//! `OperationalDb` wrote the row is the shape that has let every composition defect in
//! this tree ship green; the typed readers (`active_environments`,
//! `unpromoted_environments`, `environment`) are asserted AGAINST the raw handle, not
//! trusted in place of it.
//!
//! # What it covers
//!
//! The declare/promote/release/delete state machine, its refused sets, the two partial
//! indexes' actual use under `EXPLAIN QUERY PLAN`, and the restart window K15 leaves
//! behind.

use std::path::Path;
use std::sync::Arc;

use kata_core::store::cas::CasStore;
use kata_core::{EnvironmentDeclaration, OperationalDb};
use kata_types::error::KataError;
use rusqlite::params;

const LABEL: &str = "pkgs-static-busybox";
const STAGE_ID: &str = "01JZZZZZZZZZZZZZZZZZZZZZE1";

fn environment_id(seed: u8) -> [u8; 32] {
    [seed; 32]
}

fn closure_digest(seed: u8) -> [u8; 32] {
    [seed ^ 0x5A; 32]
}

fn platform_id() -> [u8; 32] {
    *blake3::hash(b"x86_64-linux").as_bytes()
}

/// A manifest payload deliberately OVER `INLINE_THRESHOLD`, so the object is
/// FILE-backed and the retention assertion can observe a real blob on disk rather
/// than a column inside `cas.db`.
fn manifest_bytes(label: &str) -> Vec<u8> {
    kata_types::idempotency::canonicalize_args(&serde_json::json!({
        "schema_version": 1,
        "label": label,
        "closure": "p".repeat(kata_core::store::INLINE_THRESHOLD + 2_048),
    }))
}

struct Planes {
    dir: tempfile::TempDir,
    op_path: std::path::PathBuf,
    cas_path: std::path::PathBuf,
    blob_dir: std::path::PathBuf,
    db: Arc<OperationalDb>,
    cas: CasStore,
}

fn planes() -> Planes {
    let dir = tempfile::tempdir().unwrap();
    let op_path = dir.path().join("operational.db");
    let cas_path = dir.path().join("cas.db");
    let blob_dir = dir.path().join("cas");
    let db = Arc::new(OperationalDb::open(&op_path).unwrap());
    let cas = CasStore::open(&cas_path, &blob_dir).unwrap();
    Planes {
        dir,
        op_path,
        cas_path,
        blob_dir,
        db,
        cas,
    }
}

/// The SECOND handle. Read-only on purpose: an observer that can write is an observer
/// that can repair what it was meant to catch.
fn raw(path: &Path) -> rusqlite::Connection {
    rusqlite::Connection::open_with_flags(
        path,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .unwrap()
}

fn declare(planes: &Planes, seed: u8, stage: &str) -> EnvironmentDeclaration {
    let object = planes.cas.put_durable(&manifest_bytes(LABEL)).unwrap();
    let declaration = EnvironmentDeclaration::for_staged_root(
        environment_id(seed),
        &object,
        closure_digest(seed),
        LABEL,
        platform_id(),
        stage,
    )
    .unwrap();
    planes.db.declare_environment(&declaration).unwrap();
    declaration
}

/// One `nix_environments` row as the raw handle reads it: `(manifest_object_id,
/// closure_digest, label, platform_id, root_stage_id, root_promoted_at_ms,
/// released_at_ms)`.
type RawEnvironmentRow = (
    Vec<u8>,
    Vec<u8>,
    String,
    Vec<u8>,
    String,
    Option<i64>,
    Option<i64>,
);

/// One `cas_roots` row as the raw handle reads it: `(owner_kind, owner_execution_id,
/// purpose, object_digest, released_at_ms)`.
type RawCasRootRow = (
    String,
    Option<Vec<u8>>,
    String,
    Option<Vec<u8>>,
    Option<i64>,
);

/// An instant AFTER the declaration's `created_at_ms`.
///
/// `nix_environments` CHECKs that a promotion and a release cannot predate the
/// declaration they belong to, and the plane stamps `created_at_ms` from its own clock —
/// so a literal like `10` is not merely unrealistic, it is REFUSED.
fn after_declaration(offset: i64) -> i64 {
    chrono::Utc::now().timestamp_millis() + offset
}

fn index_plan(conn: &rusqlite::Connection, sql: &str) -> String {
    let mut stmt = conn.prepare(sql).unwrap();
    stmt.query_map([], |row| row.get::<_, String>(3))
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap()
        .join(" | ")
}

/// DECLARE commits exactly two rows: the environment, unpromoted, and the node-owned
/// AUTHORITATIVE manifest root that retains its bytes.
///
/// Both counts come off the raw handle in ONE statement, so a torn declare is a value
/// mismatch rather than a missing assertion.
#[test]
fn declare_commits_the_environment_row_and_its_node_owned_manifest_root() {
    let planes = planes();
    let declaration = declare(&planes, 1, STAGE_ID);
    let conn = raw(&planes.op_path);

    let (environments, roots): (i64, i64) = conn
        .query_row(
            "SELECT (SELECT count(*) FROM nix_environments),
                    (SELECT count(*) FROM cas_roots)",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!(
        (environments, roots),
        (1, 1),
        "one declare commits one environment row and one manifest root, never one of the two"
    );

    let (manifest, closure, label, platform, stage, promoted, released): RawEnvironmentRow = conn
        .query_row(
            "SELECT manifest_object_id, closure_digest, label, platform_id, root_stage_id,
                    root_promoted_at_ms, released_at_ms
               FROM nix_environments WHERE environment_id = ?1",
            params![environment_id(1).as_slice()],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                    row.get(6)?,
                ))
            },
        )
        .unwrap();
    assert_eq!(manifest, declaration.manifest_object_id().to_vec());
    assert_eq!(closure, closure_digest(1).to_vec());
    assert_eq!(label, LABEL);
    assert_eq!(platform, platform_id().to_vec());
    assert_eq!(stage, STAGE_ID);
    assert_eq!(
        promoted, None,
        "a fresh declaration is UNPROMOTED: its gc root is still in its staging generation"
    );
    assert_eq!(released, None);

    let (owner_kind, owner_execution, purpose, digest, released_root): RawCasRootRow = conn
        .query_row(
            "SELECT owner_kind, owner_execution_id, purpose, object_digest, released_at_ms
               FROM cas_roots",
            [],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                ))
            },
        )
        .unwrap();
    assert_eq!(
        (owner_kind.as_str(), owner_execution),
        ("node", None),
        "an environment outlives every execution, so its root is NODE-owned"
    );
    assert_eq!(purpose, "nix_environment_manifest");
    assert_eq!(
        digest,
        Some(declaration.manifest_object_id().to_vec()),
        "the root must name the manifest the row names, or one of the two is unverifiable"
    );
    assert_eq!(released_root, None);

    // And the typed readers agree with what the raw handle just showed.
    let active = planes.db.active_environments().unwrap();
    assert_eq!(active.len(), 1);
    assert_eq!(active[0].label, LABEL);
    assert_eq!(planes.db.unpromoted_environments().unwrap().len(), 1);
}

/// PROMOTE stamps the instant, and only once.
#[test]
fn promote_stamps_the_instant_and_is_idempotent() {
    let planes = planes();
    declare(&planes, 2, STAGE_ID);
    let promoted_at = after_declaration(5);
    planes
        .db
        .promote_environment_root(environment_id(2), promoted_at)
        .unwrap();

    let conn = raw(&planes.op_path);
    let promoted: Option<i64> = conn
        .query_row(
            "SELECT root_promoted_at_ms FROM nix_environments WHERE environment_id = ?1",
            params![environment_id(2).as_slice()],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(promoted, Some(promoted_at));
    assert!(
        planes.db.unpromoted_environments().unwrap().is_empty(),
        "a promoted environment leaves the reconciler's work list"
    );

    // A retried reconciliation must not rewrite WHEN the promotion happened.
    planes
        .db
        .promote_environment_root(environment_id(2), promoted_at + 1_000)
        .unwrap();
    let re_read: Option<i64> = conn
        .query_row(
            "SELECT root_promoted_at_ms FROM nix_environments WHERE environment_id = ?1",
            params![environment_id(2).as_slice()],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(
        re_read,
        Some(promoted_at),
        "an idempotent re-promote must not re-stamp the instant"
    );
}

/// RELEASE moves the row AND its manifest root in one transaction; DELETE then removes
/// the row and deliberately LEAVES the released root: nothing deletes a root row.
#[test]
fn release_moves_the_row_and_its_root_together_and_delete_leaves_the_root() {
    let planes = planes();
    declare(&planes, 3, STAGE_ID);
    let promoted = after_declaration(5);
    let released = promoted + 10;
    planes
        .db
        .promote_environment_root(environment_id(3), promoted)
        .unwrap();
    planes
        .db
        .release_environment(environment_id(3), released)
        .unwrap();

    let conn = raw(&planes.op_path);
    let (row_released, root_released): (Option<i64>, Option<i64>) = conn
        .query_row(
            "SELECT (SELECT released_at_ms FROM nix_environments WHERE environment_id = ?1),
                    (SELECT released_at_ms FROM cas_roots)",
            params![environment_id(3).as_slice()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!(
        (row_released, root_released),
        (Some(released), Some(released)),
        "a torn release would leave one of these NULL; they move in ONE transaction"
    );
    assert!(
        planes.db.active_environments().unwrap().is_empty(),
        "a released environment is not active"
    );

    // Releasing again is an idempotent no-op that does not re-stamp the instant.
    planes
        .db
        .release_environment(environment_id(3), released + 500)
        .unwrap();
    let re_read: Option<i64> = conn
        .query_row(
            "SELECT released_at_ms FROM nix_environments WHERE environment_id = ?1",
            params![environment_id(3).as_slice()],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(re_read, Some(released));

    planes
        .db
        .delete_released_environment(environment_id(3))
        .unwrap();
    let (environments, roots): (i64, i64) = conn
        .query_row(
            "SELECT (SELECT count(*) FROM nix_environments),
                    (SELECT count(*) FROM cas_roots)",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!(
        (environments, roots),
        (0, 1),
        "delete removes the row and LEAVES the released root: nothing deletes a root row"
    );
    assert_eq!(planes.db.environment(environment_id(3)).unwrap(), None);
}

/// Re-declaring the SAME id with the SAME declared identity is an idempotent no-op:
/// no second row, no second root, and the original `created_at_ms` survives.
#[test]
fn an_identical_redeclaration_is_an_idempotent_no_op() {
    let planes = planes();
    declare(&planes, 4, STAGE_ID);
    let conn = raw(&planes.op_path);
    let created_before: i64 = conn
        .query_row(
            "SELECT created_at_ms FROM nix_environments WHERE environment_id = ?1",
            params![environment_id(4).as_slice()],
            |row| row.get(0),
        )
        .unwrap();

    declare(&planes, 4, STAGE_ID);
    let (environments, roots, created_after): (i64, i64, i64) = conn
        .query_row(
            "SELECT (SELECT count(*) FROM nix_environments),
                    (SELECT count(*) FROM cas_roots),
                    (SELECT created_at_ms FROM nix_environments WHERE environment_id = ?1)",
            params![environment_id(4).as_slice()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap();
    assert_eq!((environments, roots), (1, 1));
    assert_eq!(
        created_after, created_before,
        "an idempotent re-declare must not rewrite when the environment was declared"
    );
}

/// A re-declaration that DISAGREES is a typed conflict, and the message names the field
/// that diverged rather than merely refusing.
///
/// This is the refusal that matters most: one environment id naming two closures is
/// exactly what an environment id exists to prevent, and a silent overwrite would
/// re-point every future binding at a closure nobody authorized.
#[test]
fn a_divergent_redeclaration_is_a_typed_conflict() {
    let planes = planes();
    declare(&planes, 5, STAGE_ID);
    let conn = raw(&planes.op_path);

    let object = planes.cas.put_durable(&manifest_bytes(LABEL)).unwrap();
    let divergent = EnvironmentDeclaration::for_staged_root(
        environment_id(5),
        &object,
        closure_digest(200),
        LABEL,
        platform_id(),
        STAGE_ID,
    )
    .unwrap();
    let error = planes
        .db
        .declare_environment(&divergent)
        .expect_err("one environment id names one closure");
    assert!(
        matches!(error, KataError::Validation(_)),
        "a conflicting declaration must be a typed refusal, got {error:?}"
    );
    let message = error.to_string();
    assert!(
        message.contains("closure_digest"),
        "the refusal must name the field that diverged: {message}"
    );

    // A differing STAGING GENERATION is refused too, and for its own reason: the stored
    // generation is the one the boot reconciler will promote.
    let stage_divergent = EnvironmentDeclaration::for_staged_root(
        environment_id(5),
        &object,
        closure_digest(5),
        LABEL,
        platform_id(),
        "01JZZZZZZZZZZZZZZZZZZZZZE9",
    )
    .unwrap();
    let error = planes
        .db
        .declare_environment(&stage_divergent)
        .expect_err("the stored staging generation is authoritative");
    assert!(error.to_string().contains("root_stage_id"), "{error}");

    // Nothing was written by either refusal.
    let (environments, roots): (i64, i64) = conn
        .query_row(
            "SELECT (SELECT count(*) FROM nix_environments), (SELECT count(*) FROM cas_roots)",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!(
        (environments, roots),
        (1, 1),
        "a refused declaration must leave the plane exactly as it was"
    );
}

/// The state-machine refusals, each with the observation that it changed nothing.
#[test]
fn the_environment_state_machine_refuses_out_of_order_transitions() {
    let planes = planes();
    declare(&planes, 6, STAGE_ID);
    let promoted_at = after_declaration(40);
    let released_at = promoted_at + 10;
    let conn = raw(&planes.op_path);

    // RELEASE BEFORE PROMOTE: the gc root is still in a staging generation the boot
    // reconciler owns, so releasing it would hand one root to two owners.
    let error = planes
        .db
        .release_environment(environment_id(6), after_declaration(30))
        .expect_err("an unpromoted environment must not be releasable");
    assert!(matches!(error, KataError::Validation(_)), "{error:?}");
    assert!(
        error.to_string().contains(STAGE_ID),
        "the refusal must name the staging generation the reconciler still owns: {error}"
    );
    let released: Option<i64> = conn
        .query_row(
            "SELECT released_at_ms FROM nix_environments WHERE environment_id = ?1",
            params![environment_id(6).as_slice()],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(
        released, None,
        "the refused release must have written nothing"
    );

    // DELETE BEFORE RELEASE.
    let error = planes
        .db
        .delete_released_environment(environment_id(6))
        .expect_err("only a released environment is deletable");
    assert!(matches!(error, KataError::Validation(_)), "{error:?}");
    assert_eq!(
        conn.query_row("SELECT count(*) FROM nix_environments", [], |row| row
            .get::<_, i64>(0))
            .unwrap(),
        1
    );

    // RELEASE / PROMOTE / DELETE of an UNKNOWN environment.
    for error in [
        planes
            .db
            .release_environment(environment_id(99), after_declaration(1))
            .expect_err("release of unknown"),
        planes
            .db
            .promote_environment_root(environment_id(99), after_declaration(1))
            .expect_err("promote of unknown"),
        planes
            .db
            .delete_released_environment(environment_id(99))
            .expect_err("delete of unknown"),
    ] {
        assert!(matches!(error, KataError::Validation(_)), "{error:?}");
        assert!(
            error
                .to_string()
                .contains("no such environment is declared"),
            "{error}"
        );
    }

    // PROMOTE OF RELEASED.
    planes
        .db
        .promote_environment_root(environment_id(6), promoted_at)
        .unwrap();
    planes
        .db
        .release_environment(environment_id(6), released_at)
        .unwrap();
    let error = planes
        .db
        .promote_environment_root(environment_id(6), released_at + 10)
        .expect_err("a released environment's root has been relinquished");
    assert!(matches!(error, KataError::Validation(_)), "{error:?}");

    // RE-DECLARE OF RELEASED: release is a retention decision and must not be undone
    // by a declaration.
    let object = planes.cas.put_durable(&manifest_bytes(LABEL)).unwrap();
    let again = EnvironmentDeclaration::for_staged_root(
        environment_id(6),
        &object,
        closure_digest(6),
        LABEL,
        platform_id(),
        STAGE_ID,
    )
    .unwrap();
    let error = planes
        .db
        .declare_environment(&again)
        .expect_err("a released environment is not re-declarable");
    assert!(error.to_string().contains("released"), "{error}");
    let (promoted, released): (Option<i64>, Option<i64>) = conn
        .query_row(
            "SELECT root_promoted_at_ms, released_at_ms FROM nix_environments
              WHERE environment_id = ?1",
            params![environment_id(6).as_slice()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!((promoted, released), (Some(promoted_at), Some(released_at)));
}

/// An empty label or staging generation is refused at the CONSTRUCTOR, so the schema
/// CHECK stays a backstop for a forged writer rather than the first line of defence.
#[test]
fn a_declaration_without_a_label_or_staging_generation_is_unconstructible() {
    let planes = planes();
    let object = planes.cas.put_durable(&manifest_bytes(LABEL)).unwrap();
    assert!(
        EnvironmentDeclaration::for_staged_root(
            environment_id(7),
            &object,
            closure_digest(7),
            "",
            platform_id(),
            STAGE_ID,
        )
        .is_err()
    );
    assert!(
        EnvironmentDeclaration::for_staged_root(
            environment_id(7),
            &object,
            closure_digest(7),
            LABEL,
            platform_id(),
            "",
        )
        .is_err()
    );
}

/// Both reconciliation scans ride their PARTIAL index, proved by `EXPLAIN QUERY PLAN`
/// on the raw handle against the EXACT statements the readers issue.
///
/// Existence is not use: an index the planner ignores is a table scan wearing an
/// index's name, and these two scans are the ones boot runs before admission opens.
#[test]
fn the_environment_reconciliation_scans_use_their_partial_indexes() {
    let planes = planes();
    // A population where the interesting rows are the MINORITY, so a plan that scanned
    // the table would still return the right answer — which is why the plan, not the
    // answer, is the assertion.
    for seed in 10..30_u8 {
        declare(&planes, seed, STAGE_ID);
        let promoted = after_declaration(5);
        let released = promoted + 10;
        planes
            .db
            .promote_environment_root(environment_id(seed), promoted)
            .unwrap();
        planes
            .db
            .release_environment(environment_id(seed), released)
            .unwrap();
    }
    declare(&planes, 31, STAGE_ID);

    let conn = raw(&planes.op_path);
    // The column list is the PRODUCTION reader's, re-derived from the one const every
    // environment read is built from rather than retyped here: a plan proved over a
    // narrower projection than the reader issues is a plan for a different statement, and
    // a covering-index answer can differ from a table-scan answer on exactly that
    // difference.
    let columns = kata_core::operational::debug_environment_columns()
        .strip_prefix("SELECT ")
        .and_then(|rest| rest.split_once(" FROM nix_environments"))
        .map(|(columns, _)| columns.to_string())
        .expect("the environment read projection is `SELECT <columns> FROM nix_environments`");
    let active_plan = index_plan(
        &conn,
        &format!(
            "EXPLAIN QUERY PLAN SELECT {columns} FROM nix_environments \
             WHERE released_at_ms IS NULL ORDER BY environment_id"
        ),
    );
    assert!(
        active_plan.contains("idx_nix_environments_active"),
        "{active_plan}"
    );
    let unpromoted_plan = index_plan(
        &conn,
        &format!(
            "EXPLAIN QUERY PLAN SELECT {columns} FROM nix_environments \
             WHERE root_promoted_at_ms IS NULL ORDER BY environment_id"
        ),
    );
    assert!(
        unpromoted_plan.contains("idx_nix_environments_unpromoted"),
        "{unpromoted_plan}"
    );

    assert_eq!(planes.db.active_environments().unwrap().len(), 1);
    assert_eq!(planes.db.unpromoted_environments().unwrap().len(), 1);
}

/// A RESTART between declare and promote leaves an unpromoted row, and that row is what
/// the boot reconciler drives.
///
/// This is K15's recovery state reached without a crash: the declaring handle is
/// dropped (closing the writer and checkpointing the WAL) and a fresh product open
/// re-reads the file. The row must come back unpromoted, with its staging generation
/// intact, because the staging directory name is the only thing that lets boot tell the
/// generation it must promote from one it must sweep.
#[test]
fn a_restart_between_declare_and_promote_leaves_the_row_for_the_reconciler() {
    let planes = planes();
    declare(&planes, 8, STAGE_ID);
    let op_path = planes.op_path.clone();
    let cas_path = planes.cas_path.clone();
    let blob_dir = planes.blob_dir.clone();
    let dir = planes.dir;
    drop(planes.db);
    drop(planes.cas);

    let reopened = OperationalDb::open(&op_path).unwrap();
    let unpromoted = reopened.unpromoted_environments().unwrap();
    assert_eq!(
        unpromoted.len(),
        1,
        "the reconciler's work list survives restart"
    );
    assert_eq!(unpromoted[0].environment_id, environment_id(8));
    assert_eq!(unpromoted[0].root_stage_id, STAGE_ID);
    assert_eq!(unpromoted[0].root_promoted_at_ms, None);
    assert_eq!(unpromoted[0].released_at_ms, None);

    // The raw handle agrees, and the manifest root came back with it.
    let conn = raw(&op_path);
    assert_eq!(
        conn.query_row(
            "SELECT count(*) FROM cas_roots WHERE purpose = 'nix_environment_manifest'
               AND owner_kind = 'node' AND released_at_ms IS NULL",
            [],
            |row| row.get::<_, i64>(0)
        )
        .unwrap(),
        1
    );

    // And the reconciler can finish the job it was handed.
    reopened
        .promote_environment_root(environment_id(8), after_declaration(77))
        .unwrap();
    assert!(reopened.unpromoted_environments().unwrap().is_empty());
    drop(CasStore::open(&cas_path, &blob_dir).unwrap());
    drop(dir);
}

/// TWO LIVE ENVIRONMENTS MAY NOT SHARE ONE MANIFEST OBJECT, because they would not
/// share a policy — they would share a ROW.
///
/// # The defect this pins
///
/// A manifest root's id derives from `(node, NULL, nix_environment_manifest,
/// authoritative, Object(manifest_object_id))`, with no environment id in the
/// derivation, so two environments over one manifest object resolve to ONE `cas_roots`
/// row. `release_environment` then releases that shared row on behalf of whichever one
/// was released first, and the OTHER environment is left live with a row whose only
/// manifest root no longer asserts it — which the dangling-root verifier passes over.
///
/// The sharing is asserted here rather than assumed: the second declaration, once the
/// first is gone, reuses the SAME root row (`cas_roots` count stays 1). Without that
/// observation "the refusal is needed" would be a claim about a derivation nobody
/// checked.
#[test]
fn two_live_environments_may_not_share_one_manifest_object() {
    let planes = planes();
    let first = declare(&planes, 40, STAGE_ID);
    let conn = raw(&planes.op_path);

    // A SECOND environment id over the SAME manifest object.
    let second_id = environment_id(41);
    let object = planes
        .cas
        .put_durable(&manifest_bytes(LABEL))
        .expect("the same canonical bytes land on the same object");
    assert_eq!(
        object.object_id().0,
        first.manifest_object_id(),
        "non-vacuity: the two declarations must really name ONE manifest object, or the \
         refusal below is about nothing"
    );
    let colliding = EnvironmentDeclaration::for_staged_root(
        second_id,
        &object,
        closure_digest(41),
        LABEL,
        platform_id(),
        STAGE_ID,
    )
    .unwrap();
    let error = planes
        .db
        .declare_environment(&colliding)
        .expect_err("two live environments over one manifest would share one cas_roots row");
    assert!(
        matches!(error, KataError::Validation(_)),
        "a shared-manifest declaration must be a typed refusal, got {error:?}"
    );
    let message = error.to_string();
    assert!(
        message.contains(&hex::encode(environment_id(40))),
        "the refusal must name the environment that already holds the manifest: {message}"
    );
    assert!(
        message.contains(&hex::encode(second_id)),
        "and the one being refused: {message}"
    );

    // Nothing was written, and the refusal did not disturb the holder.
    let (environments, roots): (i64, i64) = conn
        .query_row(
            "SELECT (SELECT count(*) FROM nix_environments), (SELECT count(*) FROM cas_roots)",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!(
        (environments, roots),
        (1, 1),
        "a refused shared-manifest declaration must leave the plane exactly as it was"
    );
    assert_eq!(planes.db.environment(second_id).unwrap(), None);

    // THE SHARING IS REAL: retire the holder and re-declare the second over the same
    // manifest. It succeeds, and it RE-ACQUIRES the one existing root row rather than
    // inserting a second — which is exactly why two LIVE rows could not be allowed.
    let promoted = after_declaration(5);
    planes
        .db
        .promote_environment_root(environment_id(40), promoted)
        .unwrap();
    planes
        .db
        .release_environment(environment_id(40), promoted + 10)
        .unwrap();
    planes
        .db
        .delete_released_environment(environment_id(40))
        .unwrap();
    planes
        .db
        .declare_environment(&colliding)
        .expect("a released-and-deleted holder has relinquished the manifest");
    let (environments, roots, root_released): (i64, i64, Option<i64>) = conn
        .query_row(
            "SELECT (SELECT count(*) FROM nix_environments),
                    (SELECT count(*) FROM cas_roots),
                    (SELECT released_at_ms FROM cas_roots)",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap();
    assert_eq!(
        (environments, roots),
        (1, 1),
        "the re-declaration reuses the SAME derived root row; that shared identity is the \
         whole reason a second LIVE row is refused"
    );
    assert_eq!(
        root_released, None,
        "and the re-declaration RE-ACQUIRES it, so no live row points at a sweepable root"
    );
}

/// A release whose manifest root is NOT live is an INVARIANT BREAK, reported as
/// `Storage` and rolled back — never swallowed as idempotence.
///
/// # Why the forge is legitimate
///
/// Production cannot reach this state: the declaring transaction commits row and root
/// together, `upsert_cas_root` re-acquires a released root on re-declaration, and
/// `idx_nix_environments_manifest_live` forbids a second live row that could have
/// released it. So the state is forged with a raw WRITABLE handle — the only way to
/// exercise a refusal whose whole purpose is to notice something no code path produces.
/// Treating the `false` as a no-op instead would leave a LIVE row whose bytes a sweep
/// may reclaim, silently.
#[test]
fn a_release_over_an_already_released_manifest_root_is_an_invariant_break() {
    let planes = planes();
    declare(&planes, 42, STAGE_ID);
    let promoted = after_declaration(5);
    planes
        .db
        .promote_environment_root(environment_id(42), promoted)
        .unwrap();

    // FORGE: release the shared manifest root out of band, behind the plane's back.
    {
        let forge = rusqlite::Connection::open(&planes.op_path).unwrap();
        assert_eq!(
            forge
                .execute(
                    "UPDATE cas_roots SET released_at_ms = ?1 WHERE released_at_ms IS NULL",
                    params![promoted],
                )
                .unwrap(),
            1,
            "the forge must really have released the one manifest root"
        );
    }

    let error = planes
        .db
        .release_environment(environment_id(42), promoted + 10)
        .expect_err("a manifest root that is already released is a broken invariant, not a no-op");
    assert!(
        matches!(error, KataError::Storage(_)),
        "an invariant break must not be reported as a caller-fixable validation error, got \
         {error:?}"
    );
    assert!(
        error
            .to_string()
            .contains("one of three invariants is broken")
            || error.to_string().contains("invariants is broken"),
        "{error}"
    );

    // AND THE TRANSACTION ROLLED BACK: the row is still unreleased, so the next reader
    // sees a live environment rather than one whose release half-landed.
    let released: Option<i64> = raw(&planes.op_path)
        .query_row(
            "SELECT released_at_ms FROM nix_environments WHERE environment_id = ?1",
            params![environment_id(42).as_slice()],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(
        released, None,
        "the refused release must not have stamped the row: a half-released environment is \
         the state this refusal exists to prevent"
    );
}
