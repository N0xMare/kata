//! CLI-layer coverage for `kata upgrade` (`cli::upgrade`).
//!
//! These tests pin the operator-facing wrapper: `run_upgrade_cmd` dispatch
//! (dry-run vs apply), `resolve_data_dir` precedence, the checked-program
//! compatibility matrix, and the shared authority lock on `--apply`.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use kata::cli::testing::{
    execution_program_compatibility_plan, initialize_clean_data_dir_for_test, resolve_data_dir,
    run_upgrade_cmd_with_lease_paths,
};
use kata_workflow::execution_lifecycle::ExecutionLifecycleFace;
use kata_workflow::execution_program_store::ExecutionLifecycleState;
use ulid::Ulid;

/// Snapshot every regular file under `dir` as `name -> bytes`, so a dry-run can
/// be asserted byte-for-byte non-mutating.
fn snapshot_dir(dir: &Path) -> BTreeMap<String, Vec<u8>> {
    let mut out = BTreeMap::new();
    for entry in std::fs::read_dir(dir).unwrap() {
        let entry = entry.unwrap();
        if entry.file_type().unwrap().is_file() {
            let name = entry.file_name().to_string_lossy().into_owned();
            out.insert(name, std::fs::read(entry.path()).unwrap());
        }
    }
    out
}

/// A data dir initialized to the CURRENT format through the production
/// initializer. Enough to drive the wrapper's plan/apply dispatch and print paths.
///
/// # The data dir is a CHILD of the temp root, and that is not tidiness
///
/// Anything a command writes BESIDE the data dir (a sibling path) would land
/// OUTSIDE the `TempDir` if the temp root itself were the data dir, where
/// nothing ever removes it. One level down, and a sibling lands inside the root
/// the guard removes.
struct DataDirFixture {
    _tmp: tempfile::TempDir,
    path: PathBuf,
}

impl DataDirFixture {
    /// The data dir itself — NOT the temp root, so a sibling written beside it
    /// stays inside the tree that is cleaned up.
    fn path(&self) -> &Path {
        &self.path
    }
}

fn current_data_dir() -> DataDirFixture {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("data");
    std::fs::create_dir(&path).unwrap();
    initialize_clean_data_dir_for_test(&path).unwrap();
    DataDirFixture { _tmp: tmp, path }
}

/// Run the CLI wrapper with per-test coordination paths. Production has one
/// fixed per-owner authority path; parallel integration tests must not become
/// artificial contenders for that global host resource.
fn run_upgrade_cmd(
    data_dir: Option<PathBuf>,
    config: Option<PathBuf>,
    dry_run: bool,
    apply: bool,
) -> anyhow::Result<()> {
    let coordination = tempfile::tempdir().unwrap();
    let lease_parent = coordination.path().join("coordination");
    run_upgrade_cmd_with_lease_paths(
        data_dir,
        config,
        dry_run,
        apply,
        &lease_parent.join("lifecycle-operation.lock"),
        &lease_parent.join("discovery.lock"),
    )
}

/// Retained program bytes with NO lifecycle row — evidence nothing was admitted to
/// run, which blocks neither boot nor this command.
fn write_raw_program(data_dir: &Path, execution_id: Ulid, json: &[u8]) {
    ExecutionLifecycleFace::open(data_dir.join("operational.db"))
        .unwrap()
        .put_raw_legacy_evidence_json(execution_id, json)
        .unwrap();
}

/// Program bytes under a RUNNING execution — the shape a binary that could
/// dispatch them left behind, and the only shape that blocks.
fn write_active_program(data_dir: &Path, execution_id: Ulid, json: &[u8]) {
    ExecutionLifecycleFace::open(data_dir.join("operational.db"))
        .unwrap()
        .put_raw_active_program_json(execution_id, json)
        .unwrap();
}

/// Program bytes under an execution that ran and FINISHED.
fn write_finished_program(data_dir: &Path, execution_id: Ulid, json: &[u8]) {
    let face = ExecutionLifecycleFace::open(data_dir.join("operational.db")).unwrap();
    face.put_raw_active_program_json(execution_id, json)
        .unwrap();
    face.mark_terminal(execution_id, ExecutionLifecycleState::Completed)
        .unwrap();
}

/// The bytes of a program this binary really compiled — the CURRENT, dispatchable
/// control in the compatibility matrix below.
///
/// A `{"schema_version":4,"workflow_name":"current"}` stub is not a valid stand-in:
/// the membrane does not answer on the header alone. It decodes every
/// current-schema blob and runs the ADR-0001 seven-axis gate, so a stub is correctly
/// reported as undecodable — which would make "a current program is not blocked" a
/// claim about bytes no compiler produced.
fn current_program_json() -> Vec<u8> {
    let program = kata_program::execution_program::compile_starlark_execution_program(
        "one = stage(id = \"one\", prompt = \"ok\", agent = \"shell\")\n\
         workflow(\"current\", root = one)\n",
        "current.star",
        &[],
    )
    .expect("compile the current control program");
    serde_json::to_vec(&program).expect("serialize the current control program")
}

#[test]
fn dry_run_on_current_dir_is_ok_and_byte_identical() {
    let dir = current_data_dir();
    let before = snapshot_dir(dir.path());

    // Explicit --dry-run (dry_run = true), no --apply.
    run_upgrade_cmd(Some(dir.path().to_path_buf()), None, true, false)
        .expect("dry-run on a current dir should succeed");

    let after = snapshot_dir(dir.path());
    assert_eq!(
        before, after,
        "dry-run must not mutate the data dir (byte-identical before/after)"
    );
}

/// The preflight must apply the SAME forward-version gate boot does.
///
/// `kata upgrade` runs its preflight with the NEW binary against a data dir that
/// may have been written by a NEWER one. The operational scan opened the nucleus
/// without any version gate, so a forward-stamped `operational.db` was reported
/// green and the operator was told to proceed — into a boot that refuses before
/// SQLite is opened at all. A preflight that disagrees with boot is worse than no
/// preflight.
#[test]
fn dry_run_refuses_a_forward_stamped_operational_nucleus() {
    let dir = current_data_dir();
    let nucleus = dir.path().join("operational.db");
    // A real current nucleus, then a FORWARD stamp — the shape a newer binary
    // leaves behind.
    {
        let db = kata_core::OperationalDb::open(&nucleus).unwrap();
        db.debug_stamp_user_version(kata_core::OPERATIONAL_SCHEMA_VERSION + 1)
            .unwrap();
    }

    let error = run_upgrade_cmd(Some(dir.path().to_path_buf()), None, true, false)
        .expect_err("the preflight must refuse what boot would refuse");
    let message = format!("{error:#}");
    assert!(
        message.contains("schema version") && message.contains("refusing to open a newer"),
        "the refusal must be the SAME forward-version refusal boot raises: {message}"
    );
}

#[test]
fn bare_upgrade_defaults_to_dry_run_and_is_byte_identical() {
    let dir = current_data_dir();
    let before = snapshot_dir(dir.path());

    // Neither flag: bare `kata upgrade` ⇒ preview (the default).
    run_upgrade_cmd(Some(dir.path().to_path_buf()), None, false, false)
        .expect("bare upgrade should preview, not error");

    let after = snapshot_dir(dir.path());
    assert_eq!(before, after, "the default preview must not mutate the dir");
}

#[test]
fn apply_on_current_dir_is_ok_noop() {
    let dir = current_data_dir();
    // dispatch → classify_durable_format (Current) → the checked-program
    // compatibility scan (empty) → print. Proves the apply wiring end-to-end,
    // including the authority lock, on a directory this binary already writes.
    run_upgrade_cmd(Some(dir.path().to_path_buf()), None, false, true)
        .expect("apply on an already-current dir should be a clean no-op");
}

#[test]
fn first_compatibility_probe_is_byte_identical_and_publishes_no_coordination() {
    let dir = current_data_dir();
    write_active_program(
        dir.path(),
        Ulid::new(),
        br#"{"schema_version":1,"workflow_name":"fresh-probe"}"#,
    );
    let wal = dir.path().join("operational.db-wal");
    let shm = dir.path().join("operational.db-shm");
    assert!(
        !wal.exists() && !shm.exists(),
        "fixture must begin checkpointed"
    );
    let before = snapshot_dir(dir.path());

    run_upgrade_cmd(Some(dir.path().to_path_buf()), None, true, false)
        .expect("first preview must classify through immutable SQLite inspection");
    assert_eq!(
        snapshot_dir(dir.path()),
        before,
        "first preview must not create WAL/SHM or change durable bytes"
    );

    let coordination = tempfile::tempdir().unwrap();
    let lease_parent = coordination.path().join("coordination");
    let error = run_upgrade_cmd_with_lease_paths(
        Some(dir.path().to_path_buf()),
        None,
        false,
        true,
        &lease_parent.join("lifecycle-operation.lock"),
        &lease_parent.join("discovery.lock"),
    )
    .expect_err("incompatible first apply must fail before coordination");
    assert!(format!("{error:#}").contains("unsupported checked-program schema 1"));
    assert_eq!(snapshot_dir(dir.path()), before);
    assert!(
        !lease_parent.exists(),
        "blocked first apply must not publish coordination state"
    );
}

#[test]
fn compatibility_probe_refuses_ambient_sqlite_sidecars_without_mutation() {
    let dir = current_data_dir();
    write_active_program(
        dir.path(),
        Ulid::new(),
        br#"{"schema_version":1,"workflow_name":"sidecar"}"#,
    );
    let wal = dir.path().join("operational.db-wal");
    std::fs::write(&wal, b"unclassified WAL authority").unwrap();
    let before = snapshot_dir(dir.path());
    let error = run_upgrade_cmd(Some(dir.path().to_path_buf()), None, true, false)
        .expect_err("immutable inspection must not ignore an ambient WAL");
    assert!(format!("{error:#}").contains("immutable SQLite inspection refuses ambient sidecar"));
    assert_eq!(snapshot_dir(dir.path()), before);
}

#[test]
fn compatibility_probe_uses_literal_uri_metacharacter_paths() {
    let root = tempfile::tempdir().unwrap();
    let data_dir = root.path().join("has?query#fragment%percent");
    std::fs::create_dir(&data_dir).unwrap();
    let execution_id = Ulid::new();
    write_active_program(
        &data_dir,
        execution_id,
        br#"{"schema_version":1,"workflow_name":"literal-path"}"#,
    );
    let before = snapshot_dir(&data_dir);

    let plan = execution_program_compatibility_plan(&data_dir).unwrap();
    assert_eq!(plan.len(), 1);
    assert_eq!(plan[0].execution_id, execution_id);
    run_upgrade_cmd(Some(data_dir.clone()), None, true, false)
        .expect("preview must inspect the literal database path");
    assert_eq!(snapshot_dir(&data_dir), before);
}

/// An orphan rollback journal beside a MISSING main database is AMBIGUOUS, not
/// empty: the journal may hold the only record of a committed-but-uncheckpointed
/// transaction, so "no main file, therefore a fresh directory" is the wrong
/// reading and `--apply` must refuse before it takes coordination or writes a
/// byte.
#[test]
fn apply_refuses_orphan_operational_journal_before_coordination_or_mutation() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("operational.db-journal"),
        b"orphan operational authority",
    )
    .unwrap();
    let before = snapshot_dir(dir.path());
    let coordination = tempfile::tempdir().unwrap();
    let lease_parent = coordination.path().join("coordination");

    let error = run_upgrade_cmd_with_lease_paths(
        Some(dir.path().to_path_buf()),
        None,
        false,
        true,
        &lease_parent.join("lifecycle-operation.lock"),
        &lease_parent.join("discovery.lock"),
    )
    .expect_err("an orphan operational journal must be ambiguous, not fresh");
    let message = format!("{error:#}");
    // The refusal arrives from `classify_durable_format` ->
    // `OperationalDb::refuse_noncurrent_file_schema`: it names the missing main,
    // names the surviving sidecar by path, and states that no empty replacement
    // will be created.
    assert!(
        message.contains("is missing its main database while sidecar")
            && message.contains("operational.db-journal")
            && message.contains("refusing to create an empty replacement"),
        "{message}"
    );
    assert!(
        message.contains("Initialize a new empty data directory"),
        "the recourse must be the fresh-directory one, not an in-place rewrite: {message}"
    );
    assert_eq!(snapshot_dir(dir.path()), before);
    assert!(!lease_parent.exists());
}

#[test]
fn apply_refuses_ambient_operational_wal_before_coordination_or_mutation() {
    let dir = current_data_dir();
    std::fs::write(
        dir.path().join("operational.db-wal"),
        b"unclassified checked-program authority",
    )
    .unwrap();
    let before = snapshot_dir(dir.path());
    let coordination = tempfile::tempdir().unwrap();
    let lease_parent = coordination.path().join("coordination");

    let error = run_upgrade_cmd_with_lease_paths(
        Some(dir.path().to_path_buf()),
        None,
        false,
        true,
        &lease_parent.join("lifecycle-operation.lock"),
        &lease_parent.join("discovery.lock"),
    )
    .expect_err("an ambient operational WAL must be refused, not read past");
    assert!(format!("{error:#}").contains("refuses ambient sidecar"));
    assert_eq!(snapshot_dir(dir.path()), before);
    assert!(!lease_parent.exists());
}

#[test]
fn resolve_data_dir_prefers_data_dir_over_config() {
    // A bogus config path that would ERROR if it were ever loaded. Because
    // --data-dir wins, the config is never consulted and resolution succeeds.
    let wanted = PathBuf::from("/tmp/kata-upgrade-precedence-xyz");
    let resolved = resolve_data_dir(
        Some(wanted.clone()),
        Some(PathBuf::from("/nonexistent/kata.toml")),
    )
    .expect("--data-dir must win without consulting --config");
    assert_eq!(resolved, wanted);
}

#[test]
fn resolve_data_dir_requires_a_source() {
    assert!(
        resolve_data_dir(None, None).is_err(),
        "with neither --data-dir nor --config there is no data directory to locate"
    );
}

#[test]
fn resolve_data_dir_uses_the_canonical_config_parent_not_process_cwd() {
    let root = tempfile::tempdir().unwrap();
    let config_dir = root.path().join("config");
    std::fs::create_dir(&config_dir).unwrap();
    let config = config_dir.join("kata.toml");
    std::fs::write(
        &config,
        r#"[node]
id = "upgrade-relative-path"
data_dir = "../state"

[runtime]
max_concurrent_dispatches = 64

[workers]
dispatch_deadline_ms = 30000
assignment_start_deadline_ms = 900000
heartbeat_interval_ms = 10000
heartbeat_grace_ms = 30000
max_workers = 4
transports = [{ type = "supervised_node" }]

[api]
bind = "127.0.0.1:0"

[api.auth]
type = "disabled"
"#,
    )
    .unwrap();

    let resolved = resolve_data_dir(None, Some(config)).unwrap();

    assert_eq!(resolved, root.path().join("state"));
    assert!(resolved.is_absolute());
}

#[test]
fn compatibility_matrix_blocks_every_incompatible_program_of_a_non_terminal_execution() {
    let dir = current_data_dir();
    let current_live = Ulid::new();
    let legacy_bwrap_live = Ulid::new();
    let retired_live = Ulid::new();
    let future_live = Ulid::new();
    let missing_live = Ulid::new();
    let noninteger_live = Ulid::new();
    let legacy_terminal = Ulid::new();
    let future_terminal = Ulid::new();
    let legacy_evidence = Ulid::new();

    write_active_program(dir.path(), current_live, &current_program_json());
    write_active_program(
        dir.path(),
        legacy_bwrap_live,
        br#"{"schema_version":1,"workflow_name":"legacy-bwrap","sandbox_profiles":{"p":{"exec":{"kind":"bwrap"},"fs":{"kind":"host"},"net":{"kind":"host"}}}}"#,
    );
    write_active_program(
        dir.path(),
        retired_live,
        br#"{"schema_version":1,"workflow_name":"retired","sandbox_profiles":{"p":{"exec":{"kind":"podman"},"fs":{"kind":"host"},"net":{"kind":"iron_proxy"}}}}"#,
    );
    write_active_program(
        dir.path(),
        future_live,
        br#"{"schema_version":99,"workflow_name":"future"}"#,
    );
    write_active_program(dir.path(), missing_live, br#"{"workflow_name":"missing"}"#);
    write_active_program(
        dir.path(),
        noninteger_live,
        br#"{"schema_version":"2","workflow_name":"noninteger"}"#,
    );
    write_finished_program(
        dir.path(),
        legacy_terminal,
        br#"{"schema_version":1,"workflow_name":"legacy-terminal"}"#,
    );
    write_finished_program(
        dir.path(),
        future_terminal,
        br#"{"schema_version":100,"workflow_name":"future-terminal"}"#,
    );
    write_raw_program(
        dir.path(),
        legacy_evidence,
        br#"{"schema_version":1,"workflow_name":"legacy-evidence"}"#,
    );
    let plan = execution_program_compatibility_plan(dir.path()).unwrap();
    let mut blocked: Vec<Ulid> = plan.iter().map(|program| program.execution_id).collect();
    blocked.sort();
    let mut expected = vec![
        legacy_bwrap_live,
        retired_live,
        future_live,
        missing_live,
        noninteger_live,
    ];
    expected.sort();
    assert_eq!(
        blocked, expected,
        "every incompatible program of a running execution blocks; the current one, the \
         finished ones and the lifecycle-less evidence do not"
    );
    let reason = |id| {
        plan.iter()
            .find(|program| program.execution_id == id)
            .expect("matrix row")
            .incompatibility
            .reason()
    };
    assert!(reason(legacy_bwrap_live).contains("unsupported checked-program schema 1"));
    assert!(reason(retired_live).contains("unsupported checked-program schema 1;"));
    assert!(
        !reason(retired_live).contains("podman"),
        "the schema alone is named"
    );
    assert!(reason(future_live).contains("future checked-program schema 99"));
    assert!(reason(missing_live).contains("missing integer schema_version"));
    assert!(reason(noninteger_live).contains("missing integer schema_version"));

    // Preview succeeds but reports the matrix as blocked without mutating it.
    run_upgrade_cmd(Some(dir.path().to_path_buf()), None, true, false)
        .expect("preview classifies blockers without applying");

    let before_refused_apply = snapshot_dir(dir.path());
    let coordination = tempfile::tempdir().unwrap();
    let lease_parent = coordination.path().join("coordination");
    let lifecycle_path = lease_parent.join("lifecycle-operation.lock");
    let discovery_path = lease_parent.join("discovery.lock");
    let error = run_upgrade_cmd_with_lease_paths(
        Some(dir.path().to_path_buf()),
        None,
        false,
        true,
        &lifecycle_path,
        &discovery_path,
    )
    .expect_err("apply must reject every incompatible row without terminal proof");
    assert_eq!(
        snapshot_dir(dir.path()),
        before_refused_apply,
        "blocked apply must not adopt, back up, or otherwise mutate the data directory"
    );
    assert!(
        !lifecycle_path.exists() && !discovery_path.exists(),
        "blocked apply must refuse before materializing per-owner coordination files"
    );
    let message = format!("{error:#}");
    for (id, reason) in [
        (legacy_bwrap_live, "unsupported checked-program schema 1"),
        (retired_live, "unsupported checked-program schema 1"),
        (future_live, "future checked-program schema 99"),
        (missing_live, "missing integer schema_version"),
        (noninteger_live, "missing integer schema_version"),
    ] {
        assert!(
            message.contains(&id.to_string()),
            "missing id {id}: {message}"
        );
        assert!(
            message.contains(reason),
            "missing reason {reason}: {message}"
        );
    }
    for id in [
        legacy_terminal,
        future_terminal,
        legacy_evidence,
        current_live,
    ] {
        assert!(
            !message.contains(&id.to_string()),
            "{id} does not block, so the refusal must not name it: {message}"
        );
    }
}

#[test]
fn compatibility_probe_does_not_treat_assignment_projection_as_terminal_authority() {
    let dir = current_data_dir();
    write_active_program(dir.path(), Ulid::new(), &current_program_json());
    assert!(
        execution_program_compatibility_plan(dir.path())
            .unwrap()
            .is_empty(),
        "current programs need no legacy liveness classification"
    );
    // A running execution holds no assignment row at all here, and still blocks: the
    // lifecycle row, not assignment state, is what says it is not finished.
    let legacy = Ulid::new();
    write_active_program(
        dir.path(),
        legacy,
        br#"{"schema_version":1,"workflow_name":"legacy"}"#,
    );
    let plan = execution_program_compatibility_plan(dir.path()).unwrap();
    assert_eq!(plan.len(), 1);
    assert_eq!(plan[0].execution_id, legacy);
}

#[test]
fn completed_predecessor_with_undispatched_successor_still_blocks_apply() {
    let dir = current_data_dir();
    let identity_before =
        std::fs::read(dir.path().join("main-identity.json")).expect("clean identity");
    let execution_id = Ulid::new();
    let bytes = br#"{"schema_version":1,"workflow_name":"between-stages","stages":{"predecessor":{},"successor":{}},"edges":[{"from":"predecessor","to":"successor"}]}"#;
    write_active_program(dir.path(), execution_id, bytes);
    // This is the exact transient-terminal counterexample, and it is carried
    // by the PROGRAM alone: the
    // checked workflow declares `predecessor -> successor`, so even a run whose
    // every materialized assignment is terminal still has work to dispatch. No
    // assignment rows are written — see the reduction note above
    // `dry_run_on_current_dir_is_ok_and_byte_identical`; the refusal does not
    // read them and never did.

    let error = run_upgrade_cmd(Some(dir.path().to_path_buf()), None, false, true)
        .expect_err("all-terminal assignment rows are not top-level terminal proof");
    assert!(
        format!("{error:#}").contains("undispatched successor"),
        "error={error:#}"
    );
    assert_eq!(
        std::fs::read(dir.path().join("main-identity.json")).unwrap(),
        identity_before,
        "pre-lock refusal must preserve the established data-directory identity"
    );
    assert!(
        std::fs::read_dir(dir.path()).unwrap().all(|entry| {
            !entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with("pre-upgrade-backup")
        }),
        "pre-lock refusal must not create a migration backup"
    );
    let stored = ExecutionLifecycleFace::open(dir.path().join("operational.db"))
        .unwrap()
        .program_json(execution_id)
        .unwrap()
        .expect("incompatible evidence retained");
    assert_eq!(stored, bytes);
}

/// Boot and `kata upgrade` block
/// on ONE set of retained checked programs — the incompatible programs of executions
/// whose top-level lifecycle is not terminal — so the preview can never refuse a
/// directory boot starts on, or pass one boot refuses.
///
/// The fixture plants the same incompatible bytes three ways: under a RUNNING
/// execution, under a COMPLETED one, and as bare evidence with no lifecycle row at
/// all; a current program runs beside them as the non-vacuity control. The expected
/// set is read OUT OF KATA — the raw `execution_lifecycle` rows, through a second
/// read-only SQLite handle — and both sides must equal it. Finishing the running
/// execution must then clear both, which is the recourse the shared refusal names.
#[test]
fn upgrade_blocks_on_exactly_the_programs_boot_refuses() {
    use kata_workflow::execution_program_store::ExecutionLifecycleState;

    let dir = current_data_dir();
    let nucleus = dir.path().join("operational.db");
    let legacy = br#"{"schema_version":1,"workflow_name":"legacy"}"#;
    let running = Ulid::new();
    let finished = Ulid::new();
    let evidence_only = Ulid::new();
    let current = Ulid::new();
    {
        let face = ExecutionLifecycleFace::open(&nucleus).unwrap();
        face.put_raw_active_program_json(running, legacy).unwrap();
        face.put_raw_active_program_json(finished, legacy).unwrap();
        face.mark_terminal(finished, ExecutionLifecycleState::Completed)
            .unwrap();
        face.put_raw_legacy_evidence_json(evidence_only, legacy)
            .unwrap();
        face.put_raw_active_program_json(current, &current_program_json())
            .unwrap();
    }

    // The witness: which planted incompatible executions the raw lifecycle table
    // calls non-terminal. `immutable=1`, so the witness leaves no `-wal` behind for
    // the preview's own sidecar refusal to trip on.
    let non_terminal: std::collections::BTreeSet<Ulid> = {
        let raw = rusqlite::Connection::open_with_flags(
            format!("file:{}?immutable=1", nucleus.display()),
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_URI,
        )
        .unwrap();
        let mut statement = raw
            .prepare(
                "SELECT execution_id FROM execution_lifecycle \
                  WHERE state IN ('admitting', 'running', 'terminalizing')",
            )
            .unwrap();
        statement
            .query_map([], |row| row.get::<_, Vec<u8>>(0))
            .unwrap()
            .map(|id| Ulid::from_bytes(id.unwrap().try_into().unwrap()))
            .collect()
    };
    let expected: Vec<Ulid> = [running, finished, evidence_only]
        .into_iter()
        .filter(|id| non_terminal.contains(id))
        .collect();
    assert_eq!(
        expected,
        vec![running],
        "premise: only the running execution is non-terminal"
    );

    let blocking = |label: &str| -> (Vec<Ulid>, Vec<Ulid>) {
        let mut upgrade: Vec<Ulid> = execution_program_compatibility_plan(dir.path())
            .unwrap()
            .iter()
            .map(|program| program.execution_id)
            .collect();
        upgrade.sort();
        let mut boot: Vec<Ulid> = ExecutionLifecycleFace::open(&nucleus)
            .unwrap()
            .incompatible_programs()
            .unwrap()
            .iter()
            .map(|program| program.execution_id)
            .collect();
        boot.sort();
        eprintln!("{label}: upgrade={upgrade:?} boot={boot:?}");
        (upgrade, boot)
    };
    let (upgrade, boot) = blocking("before");
    assert_eq!(
        upgrade, expected,
        "upgrade must block on exactly the non-terminal incompatible programs"
    );
    assert_eq!(
        boot, expected,
        "boot must block on exactly the non-terminal incompatible programs"
    );

    // The recourse both refusals name: finish the execution on the binary that
    // wrote it. Afterwards nothing blocks, on either side.
    ExecutionLifecycleFace::open(&nucleus)
        .unwrap()
        .mark_terminal(running, ExecutionLifecycleState::Cancelled)
        .unwrap();
    let (upgrade, boot) = blocking("after");
    assert!(
        upgrade.is_empty() && boot.is_empty(),
        "{upgrade:?} {boot:?}"
    );
    run_upgrade_cmd(Some(dir.path().to_path_buf()), None, false, true)
        .expect("a directory whose incompatible programs are all terminal applies");
}

/// The preview's stdout, from the shipped binary: `kata upgrade --dry-run`.
fn dry_run_stdout(data_dir: &Path) -> String {
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_kata"))
        .args(["upgrade", "--dry-run", "--data-dir"])
        .arg(data_dir)
        .output()
        .expect("run the shipped kata binary");
    assert!(output.status.success(), "the preview exits 0: {output:?}");
    String::from_utf8(output.stdout).expect("the preview prints UTF-8")
}

/// The preview names what boot really refuses a directory for.
///
/// A directory an older binary wrote — operational stamp one behind, a RUNNING
/// execution of a schema-7 (`bwrap`) program — is refused at open by its STAMP,
/// whatever state its executions are in. The blocking-programs advice ("boot refuses
/// this directory for the same programs", the non-terminal scope) is false there, so
/// the preview must report the non-current format and its fresh-directory recourse
/// instead. The same program in a CURRENT directory is the blocked case and keeps that
/// advice — with the fresh directory as its only move, because no binary that opens
/// that directory wrote a schema-7 program. Read from the shipped binary's stdout;
/// boot's side is the lifecycle face's own open refusal.
///
/// **Watched red:** with the blocked branch taken before the format was consulted,
/// the behind-stamp preview printed the blocked status and the finish-to-clear scope.
#[test]
fn dry_run_reports_a_behind_stamp_directory_by_its_stamp_not_its_programs() {
    let schema_seven = br#"{"schema_version":7,"workflow_name":"older","sandbox_profiles":{"p":{"exec":{"kind":"bwrap"},"fs":{"kind":"host"},"net":{"kind":"host"}}}}"#;
    let behind_stamp = kata_core::OPERATIONAL_SCHEMA_VERSION - 1;

    let behind = current_data_dir();
    write_active_program(behind.path(), Ulid::new(), schema_seven);
    kata_core::OperationalDb::open(behind.path().join("operational.db"))
        .unwrap()
        .debug_stamp_user_version(behind_stamp)
        .unwrap();
    let Err(boot) = ExecutionLifecycleFace::open(behind.path().join("operational.db")) else {
        panic!("premise: boot opens no directory at stamp {behind_stamp}");
    };
    let boot = boot.to_string();
    assert!(
        boot.contains(&format!(
            "schema version {behind_stamp} is not the clean runtime"
        )),
        "premise: boot refuses the directory by its stamp: {boot}"
    );

    let preview = dry_run_stdout(behind.path());
    assert!(
        preview.contains("status = non-current format")
            && preview.contains(&format!(
                "schema version {behind_stamp} is not the clean runtime"
            )),
        "the preview must name the stamp boot refuses on:\n{preview}"
    );
    assert!(
        !preview.contains("boot refuses this directory for the same programs")
            && !preview.contains("programs of NON-TERMINAL executions"),
        "no set of programs blocks or unblocks a behind-stamp directory:\n{preview}"
    );

    let current = current_data_dir();
    write_active_program(current.path(), Ulid::new(), schema_seven);
    let preview = dry_run_stdout(current.path());
    assert!(
        preview.contains("status = blocked;")
            && preview.contains("boot refuses this directory for the same programs")
            && preview.contains("programs of NON-TERMINAL executions"),
        "a current directory's running incompatible program is the blocked case:\n{preview}"
    );
    let remediation = preview
        .lines()
        .find_map(|line| line.strip_prefix("remediation = "))
        .unwrap_or_else(|| panic!("the blocked preview prints its remediation:\n{preview}"));
    assert!(
        remediation.contains("`[node] data_dir`")
            && !remediation.to_lowercase().contains("finish")
            && !remediation.to_lowercase().contains("cancel"),
        "no binary that opens this directory wrote a schema-7 program, so the fresh \
         directory is its only move:\n{preview}"
    );
}
