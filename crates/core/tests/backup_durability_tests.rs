//! The five durability primitives on the SHIPPED backup path — content digest,
//! verify, `sync_all`, tmp→fsync→rename→directory-fsync, and a restore journal —
//! tier-differentiated by `AssetAuthority`.
//!
//! # Non-vacuity discipline
//!
//! Following `crates/test-utils/tests/git_hermeticity.rs`: every test here
//! proves the BAD state first. Where the bad state is a naive implementation, it
//! is reproduced verbatim in this file (`pre_fix_activation`) rather than
//! described, so a future edit that removes the fix cannot leave a green test
//! behind.

use std::io::Write as _;
use std::path::{Path, PathBuf};

use kata_core::durable_assets::{AssetAuthority, DURABLE_ASSETS, classify_data_dir_entry};
use kata_core::store::backup::{
    BackupManifest, CONFIG_COPY_NAME, DurabilityTier, MANIFEST_NAME, MANIFEST_VERSION,
    RECOVERY_MANIFEST_VERSION, RESTORE_JOURNAL_NAME, RESTORE_JOURNAL_SUBDIR, STORES_SUBDIR,
    TREES_SUBDIR, backup_data_dir, durability_tier, preflight_restore_artifact, read_manifest,
    restore_data_dir, restore_data_dir_aborting_before_activation, restore_journal_path,
};
use kata_types::KataError;

// This containment-lane experiment observes the product's real syscalls. Injected
// errno and SIGKILL are not ext4 delayed allocation or a physical power cut.
#[cfg(target_os = "linux")]
mod publication_fault_experiment {
    use super::*;
    use std::io::{Read as _, Seek as _};
    use std::process::{Command, Output};
    use std::time::{Duration, Instant};

    const TEST: &str = "publication_fault_experiment::publication_sync_faults_and_process_death_are_observed_at_the_syscall_boundary";
    const MODE: &str = "KATA_TEST_PUBLICATION_FAULT_MODE";
    const ROOT: &str = "KATA_TEST_PUBLICATION_FAULT_ROOT";

    thread_local! {
        static DEADLINE: std::cell::Cell<Option<Instant>> = const { std::cell::Cell::new(None) };
    }

    fn child_command(mode: &str, root: &Path) -> Command {
        let mut command = Command::new(std::env::current_exe().unwrap());
        // Inherit the parent test's per-uid inspection hold; the child is this same
        // test binary and is inside the parent's window by construction.
        kata_test_utils::inspection_lock::inherit(&mut command);
        command
            .args([
                "--exact",
                TEST,
                "--ignored",
                "--nocapture",
                "--test-threads=1",
            ])
            .env(MODE, mode)
            .env(ROOT, root);
        command
    }

    fn bounded_output(mut command: Command) -> Output {
        let child_deadline = Instant::now() + Duration::from_secs(20);
        let deadline = DEADLINE
            .get()
            .map_or(child_deadline, |end| end.min(child_deadline));
        assert!(
            Instant::now() < deadline,
            "publication experiment exhausted its 45-second budget"
        );
        // Anonymous private files cannot fill a pipe while the parent waits.
        let mut stdout = tempfile::tempfile().unwrap();
        let mut stderr = tempfile::tempfile().unwrap();
        let mut child = command
            .stdout(stdout.try_clone().unwrap())
            .stderr(stderr.try_clone().unwrap())
            .spawn()
            .unwrap();
        let mut timed_out = false;
        let status = loop {
            if let Some(status) = child.try_wait().unwrap() {
                break status;
            }
            if Instant::now() >= deadline {
                timed_out = true;
                child.kill().unwrap();
                break child.wait().unwrap();
            }
            std::thread::sleep(Duration::from_millis(20));
        };
        stdout.rewind().unwrap();
        stderr.rewind().unwrap();
        let mut output = Output {
            status,
            stdout: Vec::new(),
            stderr: Vec::new(),
        };
        stdout
            .take(1024 * 1024)
            .read_to_end(&mut output.stdout)
            .unwrap();
        stderr
            .take(1024 * 1024)
            .read_to_end(&mut output.stderr)
            .unwrap();
        assert!(
            !timed_out,
            "publication child exceeded its bounded deadline: {output:?}"
        );
        output
    }

    fn witness(database: &Path) -> String {
        let connection = rusqlite::Connection::open_with_flags(
            database,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
        )
        .unwrap();
        assert_eq!(
            connection
                .query_row("PRAGMA quick_check", [], |row| row.get::<_, String>(0))
                .unwrap(),
            "ok"
        );
        connection
            .query_row("SELECT value FROM proof", [], |row| row.get(0))
            .unwrap()
    }

    fn run_child(mode: &str, root: &Path) {
        let artifact = root.join("artifact");
        match mode {
            "capture" => match backup_data_dir(&root.join("source"), &artifact, None) {
                Ok(_) => println!("PUBLICATION-CAPTURE-OK"),
                Err(error) => println!("PUBLICATION-CAPTURE-ERR {error}"),
            },
            "restore" => {
                restore_data_dir(&artifact, &root.join("restored"), None).unwrap();
                assert_eq!(witness(&root.join("restored/operational.db")), MARKER);
                println!("PUBLICATION-RESTORE-OK raw SQLite quick_check and marker");
            }
            "refuse" => {
                let error = restore_data_dir(&artifact, &root.join("refused"), None).unwrap_err();
                assert!(!root.join("refused/operational.db").exists());
                println!("PUBLICATION-RESTORE-REFUSED {error}");
            }
            other => panic!("unknown publication experiment mode: {other}"),
        }
    }

    fn fixture() -> tempfile::TempDir {
        let root = tempfile::tempdir().unwrap();
        std::fs::create_dir(root.path().join("source")).unwrap();
        std::fs::create_dir(root.path().join("artifact")).unwrap();
        create_marked_database(&root.path().join("source/operational.db"));
        root
    }

    fn trace_capture(root: &Path, injection: Option<&str>) -> (Output, String) {
        let mut command = Command::new("strace");
        // Under strace, but still this test binary re-exec'd inside the parent's
        // per-uid inspection window.
        kata_test_utils::inspection_lock::inherit(&mut command);
        command
            .args([
                "-f",
                "-q",
                "--kill-on-exit",
                "-yy",
                "-s",
                "4096",
                "-e",
                "trace=fsync,fdatasync,rename,renameat,renameat2",
            ])
            .arg("-o")
            .arg(root.join("trace.txt"));
        if let Some(injection) = injection {
            command.arg("-e").arg(format!("inject=fsync:{injection}"));
        }
        command
            .arg(std::env::current_exe().unwrap())
            .args([
                "--exact",
                TEST,
                "--ignored",
                "--nocapture",
                "--test-threads=1",
            ])
            .env(MODE, "capture")
            .env(ROOT, root);
        let output = bounded_output(command);
        let trace = std::fs::read_to_string(root.join("trace.txt")).unwrap();
        println!("PUBLICATION-TRACE injection={injection:?}\n{trace}");
        (output, trace)
    }

    // strace injection ordinals are per tracee. Refuse an ambiguous or split
    // trace instead of silently injecting into a different file or thread.
    fn syncs(trace: &str) -> Vec<&str> {
        let lines: Vec<_> = trace
            .lines()
            .filter(|line| line.contains("fsync("))
            .collect();
        assert!(
            !lines.is_empty(),
            "strace must observe actual fsync calls: {trace}"
        );
        let thread = lines[0].split_whitespace().next().unwrap();
        assert!(
            lines
                .iter()
                .all(|line| line.split_whitespace().next() == Some(thread)
                    && !line.contains("unfinished")),
            "ambiguous fsync trace: {trace}"
        );
        lines
    }

    fn at_path(line: &str, path: &Path) -> bool {
        line.contains(&format!("<{}>", path.display()))
    }

    fn has_injected_errno(line: &str, errno: &str) -> bool {
        line.contains(&format!("= -1 {errno}")) && line.contains("INJECTED")
    }

    fn successful_rename_precedes(trace: &str, root: &Path, sync_line: &str) {
        let manifest = root.join("artifact").join(MANIFEST_NAME);
        let before = trace.split_once(sync_line).unwrap().0;
        assert!(
            before.lines().any(|line| {
                (line.contains("rename(")
                    || line.contains("renameat(")
                    || line.contains("renameat2("))
                    && line.contains(&format!("\"{}\"", manifest.display()))
                    && line.ends_with("= 0")
            }),
            "manifest rename must succeed before selected directory fsync: {trace}"
        );
    }

    fn assert_child(mode: &str, root: &Path, marker: &str) {
        let output = bounded_output(child_command(mode, root));
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            output.status.success() && stdout.contains(marker),
            "{output:?}"
        );
        println!("{stdout}");
    }

    #[test]
    #[ignore = "required containment syscall experiment; requires working strace parent-child tracing"]
    fn publication_sync_faults_and_process_death_are_observed_at_the_syscall_boundary() {
        if let Some(mode) = std::env::var_os(MODE) {
            let root = std::env::var_os(ROOT).expect("child root");
            run_child(mode.to_str().unwrap(), Path::new(&root));
            return;
        }

        // Finish our own child cleanup before nextest's default 60-second kill.
        DEADLINE.set(Some(Instant::now() + Duration::from_secs(45)));

        let baseline = fixture();
        let (output, trace) = trace_capture(baseline.path(), None);
        assert!(
            output.status.success(),
            "strace is required, never skipped: {output:?}"
        );
        assert!(String::from_utf8_lossy(&output.stdout).contains("PUBLICATION-CAPTURE-OK"));
        let calls = syncs(&trace);
        let temporary = baseline
            .path()
            .join("artifact")
            .join(format!("{MANIFEST_NAME}.restore-tmp"));
        let file_index = calls
            .iter()
            .position(|line| at_path(line, &temporary))
            .unwrap();
        assert!(calls[file_index].ends_with("= 0"));
        let dir_index = file_index + 1;
        assert!(at_path(calls[dir_index], &baseline.path().join("artifact")));
        assert!(calls[dir_index].ends_with("= 0"));
        for index in [file_index, dir_index] {
            assert!(!has_injected_errno(calls[index], "EIO"));
            assert!(!has_injected_errno(calls[index], "ENOSPC"));
        }
        successful_rename_precedes(&trace, baseline.path(), calls[dir_index]);
        assert_child("restore", baseline.path(), "PUBLICATION-RESTORE-OK");

        for (label, index, fault, visible) in [
            ("file-EIO", file_index, "error=EIO", false),
            ("file-ENOSPC", file_index, "error=ENOSPC", false),
            ("directory-EIO", dir_index, "error=EIO", true),
            ("directory-SIGKILL", dir_index, "signal=SIGKILL", true),
        ] {
            let root = fixture();
            let before = std::fs::read(root.path().join("source/operational.db")).unwrap();
            let injection = format!("{fault}:when={}", index + 1);
            let (output, trace) = trace_capture(root.path(), Some(&injection));
            let calls = syncs(&trace);
            let selected = calls
                .get(index)
                .expect("the selected syscall must be reached");
            let expected_path = if visible {
                root.path().join("artifact")
            } else {
                root.path()
                    .join("artifact")
                    .join(format!("{MANIFEST_NAME}.restore-tmp"))
            };
            assert!(
                at_path(selected, &expected_path),
                "fault hit wrong fd/path: {trace}"
            );
            let stdout = String::from_utf8_lossy(&output.stdout);
            if fault == "signal=SIGKILL" {
                assert!(
                    !output.status.success() && trace.contains("killed by SIGKILL"),
                    "{output:?}\n{trace}"
                );
                let thread = selected.split_whitespace().next().unwrap();
                assert!(
                    selected.contains("= ?")
                        && calls.len() == index + 1
                        && trace
                            .lines()
                            .any(|line| line.split_whitespace().next() == Some(thread)
                                && line.contains("killed by SIGKILL")),
                    "selected fsync thread must die at the selected syscall: {trace}"
                );
                assert!(
                    !stdout.contains("PUBLICATION-CAPTURE-"),
                    "capture must not return: {stdout}"
                );
            } else {
                let errno = fault.strip_prefix("error=").unwrap();
                assert!(has_injected_errno(selected, errno), "{trace}");
                assert_eq!(
                    trace.matches("INJECTED").count(),
                    1,
                    "exactly one fault: {trace}"
                );
                assert!(
                    output.status.success() && stdout.contains("PUBLICATION-CAPTURE-ERR"),
                    "{output:?}"
                );
                assert!(!stdout.contains("PUBLICATION-CAPTURE-OK"));
                assert!(
                    stdout.contains(if visible {
                        "fsync directory"
                    } else {
                        "stage manifest"
                    }),
                    "{stdout}"
                );
            }
            if visible {
                successful_rename_precedes(&trace, root.path(), selected);
                assert!(root.path().join("artifact").join(MANIFEST_NAME).is_file());
                assert_child("restore", root.path(), "PUBLICATION-RESTORE-OK");
            } else {
                assert!(!root.path().join("artifact").join(MANIFEST_NAME).exists());
                assert_child("refuse", root.path(), "PUBLICATION-RESTORE-REFUSED");
            }
            assert!(
                !root
                    .path()
                    .join("artifact")
                    .join(format!("{MANIFEST_NAME}.restore-tmp"))
                    .exists()
            );
            assert_eq!(
                std::fs::read(root.path().join("source/operational.db")).unwrap(),
                before
            );
            assert_eq!(witness(&root.path().join("source/operational.db")), MARKER);

            // Retry the same preserved source into a fresh artifact after the
            // injected fault is gone, then reopen in another fresh process.
            let retry = tempfile::tempdir().unwrap();
            std::fs::create_dir(retry.path().join("source")).unwrap();
            std::fs::copy(
                root.path().join("source/operational.db"),
                retry.path().join("source/operational.db"),
            )
            .unwrap();
            assert_child("capture", retry.path(), "PUBLICATION-CAPTURE-OK");
            assert_child("restore", retry.path(), "PUBLICATION-RESTORE-OK");
            println!(
                "PUBLICATION-CASE-PASS {label}: exact syscall, source intact, fresh-process snapshot restore/retry"
            );
        }
    }
}

/// A payload long enough to be findable in the file and to sit inside a record,
/// never in a page header or a b-tree pointer.
const MARKER: &str = "MARKER-MARKER-MARKER-MARKER-MARKER-MARKER-MARKER-MARKER-MARKER-M";

/// Create a real SQLite database whose sole row carries [`MARKER`] verbatim.
fn create_marked_database(path: &Path) {
    let connection = rusqlite::Connection::open(path).unwrap();
    connection
        .execute_batch(&format!(
            "CREATE TABLE proof (value TEXT NOT NULL); INSERT INTO proof VALUES ('{MARKER}');"
        ))
        .unwrap();
}

fn find_marker(bytes: &[u8]) -> Option<usize> {
    bytes
        .windows(MARKER.len())
        .position(|window| window == MARKER.as_bytes())
}

/// Flip ONE byte inside a record payload, leaving a structurally valid SQLite
/// database of exactly the same length.
///
/// Returns the byte offset that was changed, so a caller can prove the file
/// really did change.
fn flip_payload_byte(path: &Path) -> usize {
    let mut bytes = std::fs::read(path).unwrap();
    let before = bytes.len();
    let at = find_marker(&bytes).expect("the marker must survive `VACUUM INTO` verbatim");
    assert_ne!(bytes[at], b'X', "the flip must actually change the byte");
    bytes[at] = b'X';
    assert_eq!(bytes.len(), before, "a flip must not resize the file");
    std::fs::write(path, bytes).unwrap();
    at
}

/// `PRAGMA quick_check` — the ONLY content check the shipped restore path had.
fn quick_check(path: &Path) -> String {
    let connection = rusqlite::Connection::open_with_flags(
        path,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .unwrap();
    connection
        .query_row("PRAGMA quick_check(1)", [], |row| row.get::<_, String>(0))
        .unwrap()
}

/// Rewrite an artifact's manifest as a genuine v1 one: the four v1 fields and
/// nothing else, built as JSON rather than by serializing the current struct.
///
/// # It is a REFUSAL fixture, not a restore fixture
///
/// Version 1 is not a supported version, so this produces an artifact
/// `read_manifest` refuses before decoding. It is kept — and kept
/// built as raw JSON — because that is exactly what makes it a real v1 artifact
/// rather than a v2 struct with a rewritten number: it carries none of the v2
/// fields, so it also proves the refusal happens BEFORE serde meets the missing
/// fields.
fn downgrade_manifest_to_v1(artifact: &Path) {
    let manifest = read_manifest(artifact).expect("a v2 manifest to downgrade");
    let v1 = serde_json::json!({
        "version": 1,
        "created_at_ms": manifest.created_at_ms,
        "databases": manifest.databases,
        "config_included": manifest.config_included,
    });
    std::fs::write(
        artifact.join(MANIFEST_NAME),
        serde_json::to_vec_pretty(&v1).unwrap(),
    )
    .unwrap();
}

/// The ONE hand-written, COMPLETE v2 manifest document in this tree: a `cas`
/// capture's field set with the tree claim swapped for `vcs.jj_repo`, the root
/// this binary resolves nothing under.
///
/// # Why it is a named function and not an inline `json!`
///
/// Inline JSON goes stale silently: when a field such as `producer` becomes a
/// REQUIRED identity on [`BackupManifest`], hand-written JSON is invisible to the
/// type system BY CONSTRUCTION, so nothing goes red — the document simply stops
/// deserializing.
///
/// The population of hand-built manifest documents is small:
/// `grep -rln 'BackupManifest\|backup_manifest\|manifest_version' crates test`
/// returns files that are every one of them either production
/// (`crates/core/src/store/{mod,backup}.rs`, `crates/core/src/durable_assets.rs`,
/// `bin/kata/src/cli/backup.rs`) or a `crates/core/tests` suite; no file
/// under `fixtures/`, `test/fixtures/` or `crates/test-utils` mentions the type
/// at all, and no `*manifest*.json` fixture file exists in the tree. So the
/// population outside `crates/core/tests` is EMPTY, and the population INSIDE it
/// is this document plus the deliberately-incomplete one in
/// [`a_manifest_without_the_tree_keys_is_refused_rather_than_defaulted`].
///
/// [`every_hand_built_v2_manifest_document_carries_the_production_key_set`] is
/// what keeps that true when the next required field lands.
///
/// Every field this document does not VARY is copied from `real` rather than
/// re-spelled — a test DERIVES a value
/// from production instead of holding a second copy of it.
fn jj_tree_manifest_document(real: &BackupManifest) -> serde_json::Value {
    serde_json::json!({
        "version": 2,
        "created_at_ms": real.created_at_ms,
        "databases": real.databases,
        "config_included": real.config_included,
        "artifact_id": real.artifact_id.map(|id| id.to_string()),
        "assets": real.assets,
        "capture_order": real.capture_order,
        "producer": real.producer,
        "tree_roots": ["vcs.jj_repo"],
        "trees": [{
            "name": "vcs.jj_repo",
            "root": "operator_declared",
            "tier": "durable",
            "entries": [],
            "entry_count": 0,
            "total_byte_len": 0,
            "entry_digest": "3".repeat(64),
        }],
    })
}

/// THE POPULATION [`every_hand_built_v2_manifest_document_carries_the_production_key_set`]
/// sweeps: every hand-written COMPLETE v2 manifest document in the tree.
///
/// One entry today, and the sweep recorded on [`jj_tree_manifest_document`] is
/// what establishes that it is one. **Anyone who hand-builds another adds it
/// HERE** — this list is the only thing that makes such a document swept, and a
/// document built inline is a document nothing enumerates.
fn hand_built_v2_manifest_documents(
    real: &BackupManifest,
) -> Vec<(&'static str, serde_json::Value)> {
    vec![("jj_tree_manifest_document", jj_tree_manifest_document(real))]
}

/// C-3's guard: the hand-written document spells EVERY key production writes.
///
/// # The refused set, stated exactly
///
/// This refuses a hand-built COMPLETE v2 manifest document whose top-level key
/// set differs from the one `BackupManifest`'s own `Serialize` produces — in
/// EITHER direction, so a field ADDED to the type and a field REMOVED from it
/// both land here by name. It refuses nothing about VALUES, nothing about
/// nested shapes, and nothing about the deliberately-incomplete document, which
/// is not in the population and says so in its own comment.
///
/// # Why a key-set assertion and not "it deserializes"
///
/// [`a_tree_manifest_rides_v2_and_the_refusal_narrows_to_the_root_nothing_resolves`]
/// already decodes this document, so a missing REQUIRED field is caught there.
/// What that does not catch is a field serde fills silently — `artifact_id` and
/// `capture_order` are `Option` and decode from an absent key with no
/// `#[serde(default)]` — so a document that has quietly stopped saying what a
/// real artifact says still decodes. The key set is the property; decoding is
/// the weaker half of it.
///
/// WATCHED FAILING FIRST: deleting the `"producer"` line from
/// [`jj_tree_manifest_document`] reds this test naming `producer`.
#[test]
fn every_hand_built_v2_manifest_document_carries_the_production_key_set() {
    // Cross-process per-uid serialization: this test drives a product
    // immutable-SQLite inspection, whose coordinator is a per-euid singleton with a
    // NONBLOCKING 3s product deadline. Two suites under one uid made it refuse with a
    // storage-integrity message for a scheduling cause. See
    // kata_test_utils::inspection_lock.
    let _inspection_lock = kata_test_utils::inspection_lock::hold();
    let source = tempfile::tempdir().unwrap();
    create_marked_database(&source.path().join("operational.db"));
    let captured = tempfile::tempdir().unwrap();
    let real = backup_data_dir(source.path(), captured.path(), None).expect("capture");

    let production: std::collections::BTreeSet<String> = serde_json::to_value(&real)
        .expect("a real manifest serializes")
        .as_object()
        .expect("a manifest is a JSON object")
        .keys()
        .cloned()
        .collect();
    assert!(
        production.contains("producer"),
        "the oracle must be the LIVE type: if `producer` is gone from it, this test has \
         stopped asking the question C-3 exists for"
    );

    let population = hand_built_v2_manifest_documents(&real);
    assert!(
        !population.is_empty(),
        "an empty population makes this test vacuous — it would pass with every fixture in \
         the tree stale"
    );
    for (name, document) in population {
        let spelled: std::collections::BTreeSet<String> = document
            .as_object()
            .expect("a hand-built manifest document is a JSON object")
            .keys()
            .cloned()
            .collect();
        assert_eq!(
            spelled,
            production,
            "`{name}` spells a different key set than `BackupManifest` writes — missing \
             {:?}, extra {:?}. A hand-written manifest is invisible to the type system, so \
             this assertion is the only thing between a moved field and a fixture that \
             silently stopped describing a real artifact",
            production.difference(&spelled).collect::<Vec<_>>(),
            spelled.difference(&production).collect::<Vec<_>>(),
        );
    }
}

fn overwrite_manifest(artifact: &Path, manifest: &BackupManifest) {
    std::fs::write(
        artifact.join(MANIFEST_NAME),
        serde_json::to_vec_pretty(manifest).unwrap(),
    )
    .unwrap();
}

// ---------------------------------------------------------------------------
// 1. A REAL TORN WRITE — the target is never left partial.
// ---------------------------------------------------------------------------

/// A naive activation, reproduced verbatim as the baseline.
///
/// It removes the target, creates a new file at the same path, and streams into
/// it. `stop_after` models the power loss / disk-full that leaves a partial
/// target.
fn pre_fix_activation(src: &Path, dst: &Path, stop_after: usize) {
    let _ = std::fs::remove_file(dst);
    let mut output = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(dst)
        .unwrap();
    let bytes = std::fs::read(src).unwrap();
    output.write_all(&bytes[..stop_after]).unwrap();
    output.flush().unwrap();
}

/// A restore interrupted between "replacement is durable" and "target is
/// replaced" leaves the target WHOLLY OLD — never a splice of both.
///
/// RED: the shipped activation, at the same boundary, over the same bytes,
/// leaves a target that is neither the old file nor the new one.
#[test]
fn a_torn_activation_leaves_the_target_wholly_old_and_never_partial() {
    // Cross-process per-uid serialization: this test drives a product
    // immutable-SQLite inspection, whose coordinator is a per-euid singleton with a
    // NONBLOCKING 3s product deadline. Two suites under one uid made it refuse with a
    // storage-integrity message for a scheduling cause. See
    // kata_test_utils::inspection_lock.
    let _inspection_lock = kata_test_utils::inspection_lock::hold();
    let source = tempfile::tempdir().unwrap();
    create_marked_database(&source.path().join("operational.db"));
    let artifact = tempfile::tempdir().unwrap();
    backup_data_dir(source.path(), artifact.path(), None).expect("capture");

    let staged = artifact.path().join(STORES_SUBDIR).join("operational.db");
    let replacement = std::fs::read(&staged).unwrap();

    // PRECONDITION: the asset really is on the durable tier, or this test is
    // measuring the best-effort path and proves nothing about the fix.
    let manifest = read_manifest(artifact.path()).expect("manifest");
    assert_eq!(
        manifest
            .assets
            .iter()
            .find(|asset| asset.name == "operational.db")
            .expect("operational.db must have a durability record")
            .tier,
        DurabilityTier::Durable
    );

    // ---- RED: the naive activation, torn halfway -------------------------
    let red_target_dir = tempfile::tempdir().unwrap();
    let red_target = red_target_dir.path().join("operational.db");
    let sentinel = b"the database that was already there".to_vec();
    std::fs::write(&red_target, &sentinel).unwrap();
    pre_fix_activation(&staged, &red_target, replacement.len() / 2);
    let red_bytes = std::fs::read(&red_target).unwrap();
    assert_ne!(
        red_bytes, sentinel,
        "BASELINE must be the DEFECT: an in-place activation destroys the old target before the \
         new one is complete"
    );
    assert_ne!(
        red_bytes, replacement,
        "BASELINE must be the DEFECT: the shipped activation leaves the new target incomplete"
    );
    assert_eq!(
        red_bytes.len(),
        replacement.len() / 2,
        "the baseline target is a partial file — the exact state the module doc disclaimed"
    );

    // ---- GREEN: the shipped activation, aborted at the same boundary ------
    let target_dir = tempfile::tempdir().unwrap();
    let target = target_dir.path().join("operational.db");
    std::fs::write(&target, &sentinel).unwrap();

    let mut boundary_reached = false;
    let error = restore_data_dir_aborting_before_activation(
        artifact.path(),
        target_dir.path(),
        None,
        |name, tmp| {
            boundary_reached = true;
            // The replacement really is durable and complete HERE, beside the
            // target, under a name nothing reads.
            assert_eq!(name, "operational.db");
            assert_eq!(
                std::fs::read(tmp).unwrap(),
                replacement,
                "the staged replacement must be complete before the rename"
            );
            Err(KataError::Storage("power loss".to_string()))
        },
    )
    .expect_err("the restore must propagate the interruption");
    assert!(boundary_reached, "the crash boundary was never reached");
    assert!(format!("{error}").contains("power loss"), "{error}");

    assert_eq!(
        std::fs::read(&target).unwrap(),
        sentinel,
        "an interrupted durable activation must leave the target WHOLLY OLD; the replacement only \
         ever existed at `<target>.restore-tmp`"
    );
    assert!(
        !target_dir
            .path()
            .join("operational.db.restore-tmp")
            .exists(),
        "the aborted activation must clean up its temporary rather than leave a file a later \
         reader could mistake for the target"
    );

    // And re-running the restore converges: the interruption cost work, not
    // correctness.
    restore_data_dir(artifact.path(), target_dir.path(), None).expect("resume");
    assert_eq!(std::fs::read(&target).unwrap(), replacement);
}

// ---------------------------------------------------------------------------
// 2. TAMPER DETECTION — structurally valid SQLite, wrong bytes.
// ---------------------------------------------------------------------------

/// A byte flipped inside a record payload leaves `PRAGMA quick_check` reporting
/// `ok`, and the digest catches it.
///
/// RED: `quick_check` reports `ok` on the tampered copy, so without the digest
/// the tampered bytes would restore silently.
#[test]
fn a_byte_flip_that_leaves_valid_sqlite_is_caught_only_by_the_digest() {
    // Cross-process per-uid serialization: this test drives a product
    // immutable-SQLite inspection, whose coordinator is a per-euid singleton with a
    // NONBLOCKING 3s product deadline. Two suites under one uid made it refuse with a
    // storage-integrity message for a scheduling cause. See
    // kata_test_utils::inspection_lock.
    let _inspection_lock = kata_test_utils::inspection_lock::hold();
    let source = tempfile::tempdir().unwrap();
    create_marked_database(&source.path().join("operational.db"));
    let artifact = tempfile::tempdir().unwrap();
    backup_data_dir(source.path(), artifact.path(), None).expect("capture");

    let staged = artifact.path().join(STORES_SUBDIR).join("operational.db");
    let honest = std::fs::read(&staged).unwrap();
    let at = flip_payload_byte(&staged);
    let tampered = std::fs::read(&staged).unwrap();
    assert_ne!(honest, tampered, "the tamper must change the bytes");
    assert_eq!(
        honest.len(),
        tampered.len(),
        "the tamper must not change the length, or a size check would catch it"
    );

    // The tampered file is STRUCTURALLY VALID SQLite. This is the whole point:
    // the only content check the shipped path had cannot see this at all.
    assert_eq!(
        quick_check(&staged),
        "ok",
        "byte {at} must sit inside a record payload; if quick_check refuses, the tamper is a \
         structural corruption and this test is measuring the wrong property"
    );

    // ---- RED, and it is the `quick_check` above ---------------------------
    // The baseline is a mechanism rather than a version: `quick_check` — the only
    // content check SQLite offers — reports `ok` on this exact file. The digest is
    // the only thing that can refuse it.

    // ---- GREEN: the v2 manifest the capture actually wrote ----------------
    // Recapture rather than hand-restore the manifest, so the digest under test
    // is the product's and not this test's.
    let artifact2 = tempfile::tempdir().unwrap();
    backup_data_dir(source.path(), artifact2.path(), None).expect("recapture");
    let staged2 = artifact2.path().join(STORES_SUBDIR).join("operational.db");
    flip_payload_byte(&staged2);
    assert_eq!(quick_check(&staged2), "ok");

    let target = tempfile::tempdir().unwrap();
    let sentinel = target.path().join("operational.db");
    std::fs::write(&sentinel, b"untouched").unwrap();
    let error = restore_data_dir(artifact2.path(), target.path(), None)
        .expect_err("a tampered durable copy must refuse");
    let message = error.to_string();
    assert!(
        message.contains("does not match the manifest digest"),
        "the refusal must name the digest mismatch rather than a generic failure: {message}"
    );
    assert!(
        message.contains("operational.db"),
        "the refusal must name the asset: {message}"
    );
    assert_eq!(
        std::fs::read(&sentinel).unwrap(),
        b"untouched",
        "a tampered artifact must be refused before any target is mutated"
    );
}

// ---------------------------------------------------------------------------
// 3. THE READABLE WINDOW — one version, two directions of refusal.
// ---------------------------------------------------------------------------

/// A v1 artifact is REFUSED, by name, and the refusal names the recourse that
/// belongs to ITS direction.
///
/// # Why this is more than "it errors"
///
/// There is no v1 read path. The assertion is strictly more than "it errors": the refusal
/// must be the VERSION refusal (not a serde error about a missing field), and it must name
/// the recourse for a too-old artifact — take a new backup — which is the OPPOSITE of the
/// recourse a too-new artifact needs.
#[test]
fn a_v1_artifact_is_refused_by_name_and_names_the_recourse() {
    // Cross-process per-uid serialization: this test drives a product
    // immutable-SQLite inspection, whose coordinator is a per-euid singleton with a
    // NONBLOCKING 3s product deadline. Two suites under one uid made it refuse with a
    // storage-integrity message for a scheduling cause. See
    // kata_test_utils::inspection_lock.
    let _inspection_lock = kata_test_utils::inspection_lock::hold();
    let source = tempfile::tempdir().unwrap();
    create_marked_database(&source.path().join("operational.db"));
    let artifact = tempfile::tempdir().unwrap();
    backup_data_dir(source.path(), artifact.path(), None).expect("capture");
    let honest = read_manifest(artifact.path()).expect("the capture is readable");
    assert_eq!(honest.version, MANIFEST_VERSION);

    downgrade_manifest_to_v1(artifact.path());
    let error = read_manifest(artifact.path())
        .expect_err("a v1 artifact is below the readable floor and must be refused");
    let message = error.to_string();
    assert!(
        message.contains("BELOW")
            && message.contains(&format!(
                "supported versions 2 and {RECOVERY_MANIFEST_VERSION}"
            )),
        "the refusal must name the window and the DIRECTION: {message}"
    );
    assert!(
        message.contains("NEW backup"),
        "a too-old artifact's recourse is a new ARTIFACT, and the operator must be told so: \
         {message}"
    );
    assert!(
        !message.contains("missing field"),
        "the version must be read before the struct, or the operator gets a serde error about a \
         field instead of a statement about their artifact: {message}"
    );

    // And the refusal precedes everything: no target, no journal, no staging.
    let target = tempfile::tempdir().unwrap();
    let sentinel = target.path().join("operational.db");
    std::fs::write(&sentinel, b"untouched").unwrap();
    restore_data_dir(artifact.path(), target.path(), None)
        .expect_err("the restore must refuse it too");
    assert_eq!(std::fs::read(&sentinel).unwrap(), b"untouched");
}

/// Exactly two versions are readable, and EVERY other one is refused by the
/// version probe, before decoding, in the direction its position names: above
/// the newer contract is too new, anything else — including a version between
/// the two contracts — is too old.
///
/// Measured over a version range wider than both contracts, so no version can be
/// refused by a named special case while its neighbours fall through to serde.
#[test]
fn every_version_but_the_two_contracts_is_refused_before_decoding() {
    for version in 0..=RECOVERY_MANIFEST_VERSION + 2 {
        let artifact = tempfile::tempdir().unwrap();
        std::fs::write(
            artifact.path().join(MANIFEST_NAME),
            format!(r#"{{"version":{version}}}"#),
        )
        .unwrap();
        let error = read_manifest(artifact.path()).unwrap_err().to_string();
        if version == MANIFEST_VERSION || version == RECOVERY_MANIFEST_VERSION {
            assert!(
                !error.contains("manifest_too_"),
                "v{version} is a supported contract and must reach the decoder: {error}"
            );
        } else if version > RECOVERY_MANIFEST_VERSION {
            assert!(error.contains("manifest_too_new"), "v{version}: {error}");
        } else {
            assert!(error.contains("manifest_too_old"), "v{version}: {error}");
            assert!(error.contains("NEW backup"), "v{version}: {error}");
        }
    }
}

/// A recovery artifact written by a v6 kata is refused by the version probe,
/// as too old, before its treatments are decoded.
///
/// v6 had a `workers.tls.{cert,key,ca}_path` row bound to a `worker_tls` rebind
/// target. The worker TLS config is gone, so the row and the target are gone,
/// and a v6 treatment list does not fit this binary's map. The operator must be
/// told to take a new backup, not shown a serde `unknown variant` error.
#[test]
fn a_v6_recovery_artifact_with_a_worker_tls_rebind_is_refused_as_too_old() {
    let artifact = tempfile::tempdir().unwrap();
    std::fs::write(
        artifact.path().join(MANIFEST_NAME),
        r#"{"version":6,"recovery_assets":[{"location":"workers.tls.{cert,key,ca}_path","treatment":{"kind":"rebind_required","target_kind":"worker_tls"}}]}"#,
    )
    .unwrap();
    let error = read_manifest(artifact.path())
        .expect_err("a v6 recovery artifact must be refused")
        .to_string();
    assert!(error.contains("manifest_too_old"), "{error}");
    assert!(error.contains("NEW backup"), "{error}");
    assert!(!error.contains("unknown variant"), "{error}");
}

/// A TOO-NEW artifact is refused with the OPPOSITE recourse, and the two
/// messages are not interchangeable.
///
/// Non-vacuous by construction: the same reader, the same artifact, one field
/// changed, and the two refusals must disagree about which side the operator has
/// to move. A single merged "unsupported version" message would pass a test that
/// only asserted "it was refused", and would send half the operators who read it
/// to the wrong side — the defect
/// `kata_transport::control_fence::ControlRefusal::ProtocolTooNew` was split out
/// of `UnfencedCommander` to avoid.
#[test]
fn a_too_new_artifact_names_the_opposite_recourse_from_a_too_old_one() {
    // Cross-process per-uid serialization: this test drives a product
    // immutable-SQLite inspection, whose coordinator is a per-euid singleton with a
    // NONBLOCKING 3s product deadline. Two suites under one uid made it refuse with a
    // storage-integrity message for a scheduling cause. See
    // kata_test_utils::inspection_lock.
    let _inspection_lock = kata_test_utils::inspection_lock::hold();
    let source = tempfile::tempdir().unwrap();
    create_marked_database(&source.path().join("operational.db"));
    let artifact = tempfile::tempdir().unwrap();
    backup_data_dir(source.path(), artifact.path(), None).expect("capture");
    let manifest = read_manifest(artifact.path()).expect("read");

    for above in [RECOVERY_MANIFEST_VERSION + 1, u32::MAX] {
        let mut broken = manifest.clone();
        broken.version = above;
        overwrite_manifest(artifact.path(), &broken);
        let message = read_manifest(artifact.path())
            .expect_err("a version above the ceiling must be refused")
            .to_string();
        assert!(
            message.contains("ABOVE")
                && message.contains(&format!(
                    "supported versions 2 and {RECOVERY_MANIFEST_VERSION}"
                )),
            "the refusal must name the window and the DIRECTION: {message}"
        );
        assert!(
            message.contains("Upgrade the BINARY"),
            "a too-new artifact's recourse is a newer BINARY, and it is the opposite of the \
             too-old one's: {message}"
        );
        assert!(
            !message.contains("NEW backup"),
            "the two directions must not share a recourse; that is the whole reason they are \
             two refusals: {message}"
        );
    }

    // `0` is below the floor, not above the ceiling: the two arms partition
    // `u32` and neither can absorb the other.
    let mut zero = manifest;
    zero.version = 0;
    overwrite_manifest(artifact.path(), &zero);
    let message = read_manifest(artifact.path())
        .expect_err("version 0 must be refused")
        .to_string();
    assert!(
        message.contains("BELOW"),
        "version 0 is older than anything readable, and that is what the operator can act on: \
         {message}"
    );
}

/// The artifact NAMES THE BINARY that produced it.
///
/// # The question this closes
///
/// `backup-manifest.json`'s top-level keys were `artifact_id, assets,
/// capture_order, config_included, created_at_ms, databases, tree_roots, trees,
/// version` — no producer identity at all. With zero git tags and one version
/// covering every build kata has ever had, an operator holding an artifact and a
/// failing restore had no way to tell which build wrote it.
///
/// # Non-vacuous: the field is checked against the CURRENT PROCESS
///
/// Asserting "the field is present and non-empty" would pass on a constant. The
/// assertions below bind it to `std::env::current_exe()` and to that file's own
/// length, so a producer field that stopped being derived from the running
/// process reds.
#[test]
fn the_manifest_names_the_binary_that_produced_it() {
    // Cross-process per-uid serialization: this test drives a product
    // immutable-SQLite inspection, whose coordinator is a per-euid singleton with a
    // NONBLOCKING 3s product deadline. Two suites under one uid made it refuse with a
    // storage-integrity message for a scheduling cause. See
    // kata_test_utils::inspection_lock.
    let _inspection_lock = kata_test_utils::inspection_lock::hold();
    let source = tempfile::tempdir().unwrap();
    create_marked_database(&source.path().join("operational.db"));
    let artifact = tempfile::tempdir().unwrap();
    let manifest = backup_data_dir(source.path(), artifact.path(), None).expect("capture");

    let exe = std::env::current_exe().expect("the test binary can name itself");
    let metadata = std::fs::metadata(&exe).expect("stat the test binary");
    assert_eq!(
        manifest.producer.executable,
        exe.display().to_string(),
        "the producer must be the process that ran the capture, not a constant"
    );
    assert_eq!(manifest.producer.executable_len, metadata.len());
    assert!(
        manifest.producer.executable_mtime_ms > 0,
        "a build linked after 1970 must carry a positive mtime; got {}",
        manifest.producer.executable_mtime_ms
    );
    assert_eq!(manifest.producer.crate_version, env!("CARGO_PKG_VERSION"));

    // It SURVIVES the round trip, which is the only reason it is worth writing:
    // the operator reads the artifact, not the return value.
    let round_tripped = read_manifest(artifact.path()).expect("read back");
    assert_eq!(round_tripped.producer, manifest.producer);

    // …and it is a top-level manifest key an operator can `cat`, not a nested
    // detail of some other record.
    let raw: serde_json::Value =
        serde_json::from_slice(&std::fs::read(artifact.path().join(MANIFEST_NAME)).unwrap())
            .unwrap();
    assert!(
        raw["producer"]["executable"].is_string(),
        "`producer` must be a top-level manifest key: {raw}"
    );

    // REQUIRED, not defaulted: deleting it makes the artifact unreadable rather
    // than silently anonymous, which is the state the field exists to end.
    let mut without = raw.clone();
    without.as_object_mut().unwrap().remove("producer");
    std::fs::write(
        artifact.path().join(MANIFEST_NAME),
        serde_json::to_vec_pretty(&without).unwrap(),
    )
    .unwrap();
    let error = read_manifest(artifact.path())
        .expect_err("a manifest with no producer must not decode to an anonymous one");
    assert!(
        error.to_string().contains("producer"),
        "the refusal must name the missing field: {error}"
    );
}

/// A v2 manifest that lists a database and records no durability entry for it is
/// REFUSED.
///
/// Without this, stripping the `assets` array from a v2 manifest silently
/// downgrades every integrity check while the artifact still says `"version": 2`
/// — the digest comparison has nothing to compare against and passes.
#[test]
fn every_v2_database_must_carry_a_durability_record() {
    // Cross-process per-uid serialization: this test drives a product
    // immutable-SQLite inspection, whose coordinator is a per-euid singleton with a
    // NONBLOCKING 3s product deadline. Two suites under one uid made it refuse with a
    // storage-integrity message for a scheduling cause. See
    // kata_test_utils::inspection_lock.
    let _inspection_lock = kata_test_utils::inspection_lock::hold();
    let source = tempfile::tempdir().unwrap();
    create_marked_database(&source.path().join("operational.db"));
    let artifact = tempfile::tempdir().unwrap();
    backup_data_dir(source.path(), artifact.path(), None).expect("capture");

    let manifest = read_manifest(artifact.path()).unwrap();
    assert_eq!(manifest.version, MANIFEST_VERSION);
    assert!(
        !manifest.assets.is_empty(),
        "the capture must record assets"
    );

    // RED-adjacent: prove the tamper the check exists to stop would otherwise
    // work. Strip the records, keep the version, tamper a copy.
    let stripped = BackupManifest {
        assets: Vec::new(),
        ..manifest.clone()
    };
    overwrite_manifest(artifact.path(), &stripped);
    flip_payload_byte(&artifact.path().join(STORES_SUBDIR).join("operational.db"));

    let target = tempfile::tempdir().unwrap();
    let error = restore_data_dir(artifact.path(), target.path(), None)
        .expect_err("a v2 manifest with no records must be refused");
    let message = error.to_string();
    assert!(
        message.contains("records no durability entry"),
        "the refusal must name the missing record rather than the tamper it would have hidden: \
         {message}"
    );
    assert!(
        !target.path().join("operational.db").exists(),
        "the refusal must precede any target mutation"
    );

    // And a record claiming the durable tier with no digest is refused too —
    // the other half of the same downgrade.
    let mut lying = manifest;
    lying.assets[0].digest = None;
    overwrite_manifest(artifact.path(), &lying);
    let error = read_manifest(artifact.path()).expect_err("a durable record needs a digest");
    assert!(error.to_string().contains("records no digest"), "{error}");
}

// ---------------------------------------------------------------------------
// 4. TIER DIFFERENTIATION — observed, not asserted.
// ---------------------------------------------------------------------------

/// NO database can earn the cheap tier, and the durable one is enforced
/// end-to-end.
///
/// # What the cheap arm cannot show, recorded rather than absorbed
///
/// The strongest form of this test would be two databases, one capture, identical
/// stimulus (a flipped byte in each captured copy), different outcome — the
/// `Authoritative` one refusing the restore and a cheap-tier one passing straight
/// through. No `*.db` row derives `DurabilityTier::BestEffort` — `Rebuildable`
/// names are refused at discovery by `artifact_carries_database`, and no other
/// class earns it — so the cheap arm has no fixture.
///
/// What is left is stated in two halves, both falsifiable:
///
/// 1. the durable arm END-TO-END, unchanged — a tampered authoritative copy
///    refuses the restore;
/// 2. the cheap arm as a MEASUREMENT over the map — no `*.db` row derives
///    `BestEffort` — so the day one does, this test reds and the maintainer is
///    told to restore the two-arm form rather than discovering the gap.
#[test]
fn no_database_can_earn_the_cheap_tier() {
    // Cross-process per-uid serialization: this test drives a product
    // immutable-SQLite inspection, whose coordinator is a per-euid singleton with a
    // NONBLOCKING 3s product deadline. Two suites under one uid made it refuse with a
    // storage-integrity message for a scheduling cause. See
    // kata_test_utils::inspection_lock.
    let _inspection_lock = kata_test_utils::inspection_lock::hold();
    // ---- (2) the measurement that replaced the second arm ------------------
    //
    // Stated over the SHIPPED CAPTURE and not over the map, because the map
    // alone cannot answer it: `stage_cache.db` is `Rebuildable` and so derives
    // the cheap tier, and it is `artifact_carries_database` — a discovery-side
    // rule, private to the backup module — that keeps it out of every artifact.
    // A map-only assertion would either be false or would have to restate that
    // rule, which is the duplicate-authority shape this corpus refuses.
    //
    // So: plant EVERY `*.db` name the map knows, capture, and read the tiers out
    // of the artifact.
    let every = tempfile::tempdir().unwrap();
    let planted: Vec<&str> = DURABLE_ASSETS
        .iter()
        .filter_map(|asset| match asset.location {
            kata_core::durable_assets::AssetLocation::DataDirFile(name)
                if Path::new(name).extension().is_some_and(|ext| ext == "db") =>
            {
                Some(name)
            }
            _ => None,
        })
        .collect();
    assert!(
        planted.len() >= 5,
        "the fixture must be the map's whole `*.db` set, not a handful: {planted:?}"
    );
    for name in &planted {
        create_marked_database(&every.path().join(name));
    }
    let every_artifact = tempfile::tempdir().unwrap();
    let every_manifest =
        backup_data_dir(every.path(), every_artifact.path(), None).expect("capture");
    let cheap: Vec<&str> = every_manifest
        .assets
        .iter()
        .filter(|asset| asset.tier == DurabilityTier::BestEffort)
        .map(|asset| asset.name.as_str())
        .collect();
    assert!(
        cheap.is_empty(),
        "a captured database earned the cheap tier: {cheap:?}. A two-arm form of this test \
         is then buildable — add it, because a measurement over one capture is a strictly \
         weaker statement than a tampered restore that does not refuse."
    );
    assert!(
        !every_manifest.assets.is_empty(),
        "the measurement is vacuous if the capture carried nothing"
    );

    // ---- (1) the durable arm, end-to-end, through the shipped path ---------
    assert_eq!(
        classify_data_dir_entry("operational.db").unwrap().authority,
        AssetAuthority::Authoritative
    );
    let source = tempfile::tempdir().unwrap();
    create_marked_database(&source.path().join("operational.db"));
    let artifact = tempfile::tempdir().unwrap();
    backup_data_dir(source.path(), artifact.path(), None).expect("capture");

    let manifest = read_manifest(artifact.path()).unwrap();
    let record = manifest
        .assets
        .iter()
        .find(|asset| asset.name == "operational.db")
        .expect("operational.db must have a record");
    assert_eq!(record.tier, DurabilityTier::Durable);
    assert!(
        record.digest.is_some(),
        "the durable tier's cost is the digest"
    );

    let staged = artifact.path().join(STORES_SUBDIR).join("operational.db");
    flip_payload_byte(&staged);
    assert_eq!(
        quick_check(&staged),
        "ok",
        "the flip must leave structurally valid SQLite, or a structural check would catch it and \
         the tier would be irrelevant"
    );
    let target = tempfile::tempdir().unwrap();
    let error = restore_data_dir(artifact.path(), target.path(), None)
        .expect_err("a tampered AUTHORITATIVE copy must refuse the restore");
    assert!(
        error
            .to_string()
            .contains("does not match the manifest digest"),
        "{error}"
    );
}

/// Every `AssetAuthority` variant has a stated tier, and the three answers are
/// genuinely different.
///
/// The end-to-end test above can only observe the classes a `*.db` capture
/// actually reaches. This is the total function, over the whole enum, including
/// the variants nothing reaches today.
#[test]
fn every_authority_class_has_a_stated_and_distinct_tier() {
    assert_eq!(
        durability_tier(AssetAuthority::Authoritative),
        DurabilityTier::Durable
    );
    assert_eq!(
        durability_tier(AssetAuthority::Rebuildable {
            from: "a cold compile"
        }),
        DurabilityTier::BestEffort
    );
    assert_eq!(
        durability_tier(AssetAuthority::Transient),
        DurabilityTier::Excluded,
        "Transient is not a cheaper tier of capture; best-effort would still write a lock file \
         describing a process that is not running into a restored data directory"
    );
}

/// **No `Rebuildable` and no `Transient` asset reaches a backup artifact through
/// `*.db` discovery.**
///
/// # A claim about the CAPTURE, not only the map's SHAPE
///
/// The stage cache is a `Rebuildable` `*.db` row the top-level glob matches.
/// Adding its name to an allowlist in the assertion below would launder a
/// capture-TIER change — `Durable` to `BestEffort` for a database a node READS —
/// through a test edit. Instead `artifact_carries_database` refuses a
/// `Rebuildable` name inside `discover_databases`, the one site that produces the
/// set, and `restore_data_dir` clears the same set from its target. So the two
/// halves of the claim are different KINDS of claim, and both are stated here:
///
/// * REBUILDABLE — ENFORCED, and therefore measured through a real
///   `backup_data_dir` over a real `stage_cache.db`. A map-shape assertion would
///   be vacuous, since the mechanism is what holds it.
/// * TRANSIENT — still a fact about the map's shape, and still what keeps
///   `backup_data_dir_with_hooks`' `Excluded` refusal unreachable. That arm is
///   deliberately NOT covered by the discovery filter: a `Transient` `*.db` row
///   is a programming error and earns a loud stop, not a quiet omission.
#[test]
fn no_rebuildable_or_transient_asset_is_reachable_by_database_discovery() {
    // Cross-process per-uid serialization: this test drives a product
    // immutable-SQLite inspection, whose coordinator is a per-euid singleton with a
    // NONBLOCKING 3s product deadline. Two suites under one uid made it refuse with a
    // storage-integrity message for a scheduling cause. See
    // kata_test_utils::inspection_lock.
    let _inspection_lock = kata_test_utils::inspection_lock::hold();
    // ---- REBUILDABLE — measured through the shipped capture ---------------
    //
    // The fixture is built by the product's own constructor, so the file under
    // test is the one a node actually has. It writes siblings —
    // `stage_cache.db`, `cas.db` and the `cas/` tree — which is what makes the
    // counterfactual below sharp: one constructor, one directory, opposite
    // dispositions, and the only thing that differs is the map's
    // `AssetAuthority`.
    let source = tempfile::tempdir().unwrap();
    drop(
        kata_core::store::SqliteWorkflowStore::open(source.path().join("stage_cache.db"))
            .expect("the product's own stage-cache constructor must open"),
    );
    create_marked_database(&source.path().join("operational.db"));

    // PRECONDITIONS: the classes are the MAP's, and the file is really there —
    // so an empty artifact cannot pass this by accident.
    assert!(
        matches!(
            classify_data_dir_entry("stage_cache.db").unwrap().authority,
            AssetAuthority::Rebuildable { .. }
        ),
        "the fixture must be a Rebuildable map row, or this test is about something else"
    );
    assert!(
        source.path().join("stage_cache.db").is_file(),
        "the fixture must hold a real rebuildable database"
    );
    assert!(
        source.path().join("cas.db").is_file(),
        "the same constructor must have written the authoritative sibling"
    );

    let artifact = tempfile::tempdir().unwrap();
    let manifest = backup_data_dir(source.path(), artifact.path(), None).expect("capture");

    assert!(
        !manifest.databases.iter().any(|n| n == "stage_cache.db"),
        "the artifact must make no claim to a rebuildable database; claimed {:?}",
        manifest.databases
    );
    assert!(
        !manifest.assets.iter().any(|a| a.name == "stage_cache.db"),
        "and must record no durability entry for one"
    );
    assert!(
        !artifact
            .path()
            .join(STORES_SUBDIR)
            .join("stage_cache.db")
            .exists(),
        "and must not be holding the bytes it does not claim"
    );
    assert!(
        manifest
            .capture_order
            .as_ref()
            .expect("a v2 capture records its order")
            .entries()
            .iter()
            .all(|entry| entry.asset != "stage_cache.db"),
        "the capture order must order what the artifact HOLDS; an entry for an uncaptured asset \
         would make it a fiction"
    );

    // COUNTERFACTUAL — the authoritative sibling the SAME constructor wrote is
    // captured, on the durable tier, with the digest the cheap tier does not
    // buy. Without this the assertions above would pass on a capture that
    // silently dropped everything.
    let record = |name: &str| {
        manifest
            .assets
            .iter()
            .find(|asset| asset.name == name)
            .unwrap_or_else(|| panic!("{name} must have a record; got {:?}", manifest.assets))
    };
    assert_eq!(record("cas.db").tier, DurabilityTier::Durable);
    assert!(
        record("cas.db").digest.is_some(),
        "the CAS authority the constructor wrote beside the cache pays the durable cost"
    );
    assert_eq!(record("operational.db").tier, DurabilityTier::Durable);

    // ---- TRANSIENT — still a fact about the map's shape --------------------
    let transient_databases: Vec<&str> = DURABLE_ASSETS
        .iter()
        .filter(|asset| durability_tier(asset.authority) == DurabilityTier::Excluded)
        .map(|asset| asset.location.name())
        .filter(|name| Path::new(name).extension().is_some_and(|ext| ext == "db"))
        .collect();
    assert!(
        transient_databases.is_empty(),
        "a Transient asset became reachable by `*.db` discovery: {transient_databases:?}. The \
         capture's Excluded arm stops being unreachable defensive code and must be re-read — it \
         REFUSES the whole capture, deliberately, and that refusal is an operator-facing \
         failure of `kata backup`."
    );

    // The map-level version of the same question,
    // `no_database_can_earn_the_cheap_tier`, asserts the emptiness of the cheap
    // `*.db` set DIRECTLY. The emptiness asserted above is about the Transient
    // class specifically: it filters on `DurabilityTier::Excluded`.
    assert!(
        classify_data_dir_entry("events.db").is_none()
            && classify_data_dir_entry("kata.db").is_none(),
        "`events.db` and `kata.db` are not map rows; a row for either would silently change \
         what tier such a file in a data directory is captured at"
    );
}

/// A data directory holding an UNCLASSIFIED database — an `events.db` beside a
/// live `cas/` tree and `operational.db` — is captured, not refused.
///
/// # The failure this rules out
///
/// A `kata backup` that ranked an unclassified database below `cas` would refuse
/// such a directory outright: `SnapshotRank::NotCaptured` (0) sorts BEFORE
/// `cas`'s `ReferencedContent` (1), while the tree pass copies `cas` first
/// unconditionally — so the capture's own `ConsistencyToken::verify` would report
/// that a referenced asset had been captured after something that references it,
/// the whole backup would fail, and the operator's only recourse would be to
/// delete files from their data directory before backing it up.
///
/// # TWO independent mechanisms keep this green, and the test is built to notice
///
/// 1. the ordering predicate EXCLUDES `NotCaptured` entries — an asset with no
///    bytes in the artifact cannot be the referent of anything, so its position
///    carries no information the invariant is about;
/// 2. the map has no `events.db` row, so it does not rank at all.
///
/// (2) alone would hide (1): with no row, no consistency entry is emitted and
/// the token never sees it. So the assertions below are about the ARTIFACT — the
/// unclassified file is carried, the tree is carried, and the token verifies — and the
/// predicate itself is measured directly by
/// `durable_assets::tests::a_not_captured_asset_is_excluded_from_the_ordering_predicate`,
/// which builds a token with a `NotCaptured` entry by hand and cannot be
/// satisfied by a deleted row.
#[test]
fn an_unclassified_database_beside_a_cas_tree_is_captured_not_refused() {
    // Cross-process per-uid serialization: this test drives a product
    // immutable-SQLite inspection, whose coordinator is a per-euid singleton with a
    // NONBLOCKING 3s product deadline. Two suites under one uid made it refuse with a
    // storage-integrity message for a scheduling cause. See
    // kata_test_utils::inspection_lock.
    let _inspection_lock = kata_test_utils::inspection_lock::hold();
    let unclassified = tempfile::tempdir().unwrap();
    // The real shape: the live CAS tree + its metadata + the nucleus (planted by
    // `plant_cas_objects`), plus an unclassified database.
    let planted = plant_cas_objects(unclassified.path(), 2);
    create_marked_database(&unclassified.path().join("events.db"));

    let artifact = tempfile::tempdir().unwrap();
    let manifest = backup_data_dir(unclassified.path(), artifact.path(), None).expect(
        "a data directory holding BOTH an unclassified database and a CAS tree must capture",
    );

    assert!(
        manifest.databases.iter().any(|name| name == "events.db"),
        "an unclassified database is still captured — a snapshot takes what is on disk; \
         claimed {:?}",
        manifest.databases
    );
    assert_eq!(
        manifest.tree_roots,
        vec!["cas".to_string()],
        "the CAS tree must still be captured beside it"
    );
    assert_eq!(
        manifest.trees.first().expect("one tree record").entry_count,
        planted.len() as u64,
        "every planted object must be in the artifact"
    );

    // The capture verified its OWN order before publishing — the check that used
    // to fail — and the artifact carries the token that says so.
    manifest
        .capture_order
        .as_ref()
        .expect("a capture writes its consistency token")
        .verify()
        .expect("the published capture order must verify");

    // UNCLASSIFIED, and therefore captured at the EXPENSIVE tier: ignorance
    // argues for the digest. This is the behaviour change the row deletion
    // bought, and it is the opposite of what the deleted row licensed.
    let record = manifest
        .assets
        .iter()
        .find(|asset| asset.name == "events.db")
        .expect("events.db must have a record");
    assert_eq!(record.tier, DurabilityTier::Durable);
    assert!(
        record.digest.is_some(),
        "a database the map cannot classify must be digested, not carried cheaply"
    );

    // …and it restores, so the refusal is gone from the whole verb and not only
    // from the capture.
    let target = tempfile::tempdir().unwrap();
    restore_data_dir(artifact.path(), target.path(), None).expect("the artifact must restore too");
    assert_eq!(
        std::fs::read(target.path().join("events.db")).unwrap(),
        std::fs::read(artifact.path().join(STORES_SUBDIR).join("events.db")).unwrap()
    );
}

/// THE OTHER HALF of not carrying a rebuildable database: a restore must not
/// leave a stale one behind either.
///
/// # The state this refuses, and why it is reachable rather than theoretical
///
/// `kata restore` targets the node's OWN locked data directory, so the target is
/// routinely non-empty. `stage_cache.db` holds `capsule_reuse_v1` — hint rows
/// the operational plane re-verifies against its own authority on every hit —
/// and the artifact rolls `cas.db` back to the capture instant. A surviving
/// cache would be a stale hint plane over a rewound CAS, which is at best a
/// miss and at worst a hint that re-verification has to disprove; the honest
/// state after a restore is the empty one the next run rebuilds.
///
/// The removal is licensed by the same map row that licensed not carrying it:
/// `RetentionRule::Reclaimable`, *"reclaimable at any time without correctness
/// loss"*.
#[test]
fn a_restore_clears_the_rebuildable_database_it_did_not_carry() {
    // Cross-process per-uid serialization: this test drives a product
    // immutable-SQLite inspection, whose coordinator is a per-euid singleton with a
    // NONBLOCKING 3s product deadline. Two suites under one uid made it refuse with a
    // storage-integrity message for a scheduling cause. See
    // kata_test_utils::inspection_lock.
    let _inspection_lock = kata_test_utils::inspection_lock::hold();
    let source = tempfile::tempdir().unwrap();
    create_marked_database(&source.path().join("operational.db"));
    let artifact = tempfile::tempdir().unwrap();
    let manifest = backup_data_dir(source.path(), artifact.path(), None).expect("capture");
    assert!(
        !manifest.databases.iter().any(|n| n == "stage_cache.db"),
        "PRECONDITION: the artifact carries no rebuildable database"
    );

    // A target that is a LIVE data directory, not a fresh one.
    let target = tempfile::tempdir().unwrap();
    drop(
        kata_core::store::SqliteWorkflowStore::open(target.path().join("stage_cache.db"))
            .expect("open a live stage cache at the target"),
    );
    // The sidecars a running node leaves; a restore that removed only the main
    // file would leave these pointing at a database that no longer exists.
    for sidecar in ["stage_cache.db-wal", "stage_cache.db-shm"] {
        std::fs::write(target.path().join(sidecar), b"stale").unwrap();
    }

    // NON-VACUITY: the pre-restore state is the one under test.
    assert!(target.path().join("stage_cache.db").is_file());

    restore_data_dir(artifact.path(), target.path(), None).expect("restore");

    for stale in ["stage_cache.db", "stage_cache.db-wal", "stage_cache.db-shm"] {
        assert!(
            !target.path().join(stale).exists(),
            "{stale} survived a restore that did not carry it; its hint rows would name \
             occurrences the artifact's CAS no longer proves"
        );
    }
    // COUNTERFACTUAL — the restore did happen, and it did not clear an asset it
    // DID carry.
    assert!(
        target.path().join("operational.db").is_file(),
        "the restore must still place the databases the artifact claims"
    );
    // THE SHARP ONE — the clearing is scoped by the map's authority class, not
    // by the filename or by "everything the artifact did not claim". The target
    // store's own constructor wrote `cas.db` beside the cache; only the
    // rebuildable one is removed.
    assert!(
        target.path().join("cas.db").is_file(),
        "the restore cleared the AUTHORITATIVE sibling the same constructor wrote"
    );
}

// ---------------------------------------------------------------------------
// 5. THE JOURNAL — present, scoped, and cleared.
// ---------------------------------------------------------------------------

/// An interrupted restore leaves a journal naming what it finished; a completed
/// one leaves none.
///
/// The journal's PRESENCE is the signal, which is why it is removed on success:
/// a journal that outlived a successful restore would make "a restore of this
/// artifact was interrupted" unreadable.
#[test]
fn the_restore_journal_records_progress_and_is_cleared_on_success() {
    // Cross-process per-uid serialization: this test drives a product
    // immutable-SQLite inspection, whose coordinator is a per-euid singleton with a
    // NONBLOCKING 3s product deadline. Two suites under one uid made it refuse with a
    // storage-integrity message for a scheduling cause. See
    // kata_test_utils::inspection_lock.
    let _inspection_lock = kata_test_utils::inspection_lock::hold();
    let source = tempfile::tempdir().unwrap();
    create_marked_database(&source.path().join("a-first.db"));
    create_marked_database(&source.path().join("operational.db"));
    let artifact = tempfile::tempdir().unwrap();
    backup_data_dir(source.path(), artifact.path(), None).expect("capture");

    // `a-first.db` is unclassified by the map, so it takes the fail-safe durable
    // tier — which is what makes it journal-eligible.
    let manifest = read_manifest(artifact.path()).unwrap();
    assert!(classify_data_dir_entry("a-first.db").is_none());
    assert!(
        manifest
            .assets
            .iter()
            .all(|asset| asset.tier == DurabilityTier::Durable),
        "both fixtures must be on the durable tier for the journal to be exercised"
    );

    // Interrupt on the SECOND asset, so the first is durably in place.
    let target = tempfile::tempdir().unwrap();
    restore_data_dir_aborting_before_activation(artifact.path(), target.path(), None, |name, _| {
        if name == "operational.db" {
            Err(KataError::Storage("power loss".to_string()))
        } else {
            Ok(())
        }
    })
    .expect_err("the interruption must propagate");

    // The journal is under the TARGET, and the ARTIFACT was never written to.
    let journal_path = restore_journal_path(target.path());
    assert!(
        !artifact.path().join(RESTORE_JOURNAL_NAME).exists(),
        "the artifact directory must carry no journal — a restore reads its artifact and writes \
         its target, and writing here is what made a read-only artifact tear the target"
    );
    let journal: serde_json::Value = serde_json::from_slice(&std::fs::read(&journal_path).expect(
        "an interrupted restore must \
             leave a journal under the target",
    ))
    .unwrap();
    assert_eq!(
        journal["completed"],
        serde_json::json!(["a-first.db"]),
        "the journal must record exactly what was durably activated, and must not record the \
         asset the crash preceded"
    );
    assert_eq!(
        journal["artifact_id"],
        serde_json::json!(manifest.artifact_id.unwrap().to_string()),
        "the journal must be scoped to the artifact it tracks"
    );

    // Resume: same artifact, same target, no hook.
    restore_data_dir(artifact.path(), target.path(), None).expect("resume");
    assert!(
        !journal_path.exists(),
        "a completed restore must clear its journal, or the journal's presence stops meaning \
         `interrupted`"
    );
    for name in ["a-first.db", "operational.db"] {
        assert_eq!(
            std::fs::read(target.path().join(name)).unwrap(),
            std::fs::read(artifact.path().join(STORES_SUBDIR).join(name)).unwrap(),
            "{name} must be fully restored after the resume"
        );
    }
}

/// A journal left by a DIFFERENT artifact is discarded, not read as progress.
#[test]
fn a_journal_from_another_artifact_is_discarded_rather_than_misread() {
    // Cross-process per-uid serialization: this test drives a product
    // immutable-SQLite inspection, whose coordinator is a per-euid singleton with a
    // NONBLOCKING 3s product deadline. Two suites under one uid made it refuse with a
    // storage-integrity message for a scheduling cause. See
    // kata_test_utils::inspection_lock.
    let _inspection_lock = kata_test_utils::inspection_lock::hold();
    let source = tempfile::tempdir().unwrap();
    create_marked_database(&source.path().join("operational.db"));
    let artifact = tempfile::tempdir().unwrap();
    backup_data_dir(source.path(), artifact.path(), None).expect("capture");
    let manifest = read_manifest(artifact.path()).unwrap();

    // A journal claiming the asset is already done, under a foreign artifact id,
    // planted where a resume of THIS target would find it.
    let target = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(target.path().join(RESTORE_JOURNAL_SUBDIR)).unwrap();
    std::fs::write(
        restore_journal_path(target.path()),
        serde_json::to_vec_pretty(&serde_json::json!({
            "artifact_id": ulid::Ulid::new().to_string(),
            "completed": ["operational.db"],
        }))
        .unwrap(),
    )
    .unwrap();
    assert_ne!(
        manifest.artifact_id.map(|id| id.to_string()),
        None,
        "the artifact must carry an id for the scoping to mean anything"
    );

    restore_data_dir(artifact.path(), target.path(), None).expect("restore");
    assert!(
        target.path().join("operational.db").is_file(),
        "a foreign journal must not be able to make a restore SKIP an asset it never put back"
    );
}

// ---------------------------------------------------------------------------
// 6. A READ-ONLY ARTIFACT DIRECTORY — the regression the journal placement made.
// ---------------------------------------------------------------------------

/// Set a directory's mode, returning the previous one so a test can restore it
/// and let `TempDir::drop` clean up.
fn set_mode(dir: &Path, mode: u32) -> u32 {
    use std::os::unix::fs::PermissionsExt as _;
    let previous = std::fs::metadata(dir).unwrap().permissions().mode();
    let mut permissions = std::fs::metadata(dir).unwrap().permissions();
    permissions.set_mode(mode);
    std::fs::set_permissions(dir, permissions).unwrap();
    previous
}

/// Every top-level entry name in a directory, sorted.
fn entry_names(dir: &Path) -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(dir)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    names
}

/// A restore from a READ-ONLY artifact directory succeeds, leaves the target
/// WHOLLY new, and mutates nothing inside the artifact.
///
/// # The bad state, measured rather than described
///
/// A journal published INTO the artifact directory by `record_activation`, in the
/// middle of activation, makes a restore from a read-only artifact fail PARTWAY —
/// one database replaced, the next not — which is the mixed plane
/// `MANIFEST_VERSION` 2 exists to eliminate.
///
/// The RED arm below reproduces that write, at the same
/// point, in the same directory, rather than describing it: if that `File::create`
/// ever starts succeeding, the fixture is not read-only and the green arm proves
/// nothing.
#[test]
fn a_read_only_artifact_directory_restores_wholly_and_mutates_nothing() {
    // Cross-process per-uid serialization: this test drives a product
    // immutable-SQLite inspection, whose coordinator is a per-euid singleton with a
    // NONBLOCKING 3s product deadline. Two suites under one uid made it refuse with a
    // storage-integrity message for a scheduling cause. See
    // kata_test_utils::inspection_lock.
    let _inspection_lock = kata_test_utils::inspection_lock::hold();
    let source = tempfile::tempdir().unwrap();
    // TWO databases, so "half restored" is a state the target can be IN. With
    // one asset there is no partial outcome to distinguish from a clean refusal.
    create_marked_database(&source.path().join("a-first.db"));
    create_marked_database(&source.path().join("operational.db"));
    let artifact = tempfile::tempdir().unwrap();
    backup_data_dir(source.path(), artifact.path(), None).expect("capture");

    let manifest = read_manifest(artifact.path()).expect("manifest");
    assert_eq!(manifest.version, MANIFEST_VERSION);
    assert!(
        manifest
            .assets
            .iter()
            .all(|asset| asset.tier == DurabilityTier::Durable),
        "both fixtures must be on the durable tier, or no journal write is attempted and this \
         test cannot reach the defect"
    );

    let before = entry_names(artifact.path());
    let previous = set_mode(artifact.path(), 0o555);

    // ---- RED: an artifact-side journal write at this point ------
    // `durable_publish(backup_dir, RESTORE_JOURNAL_NAME, ..)` opens exactly this
    // path with `File::create`. It must FAIL, or the directory is not read-only.
    let denied = std::fs::File::create(
        artifact
            .path()
            .join(format!("{RESTORE_JOURNAL_NAME}.restore-tmp")),
    )
    .expect_err("BASELINE: the artifact directory must be genuinely unwritable");
    assert_eq!(
        denied.kind(),
        std::io::ErrorKind::PermissionDenied,
        "the fixture must be read-only for the reason under test, not unwritable by accident: \
         {denied}"
    );

    // ---- GREEN: the restore, over exactly that directory --------------------
    let target = tempfile::tempdir().unwrap();
    let restored = restore_data_dir(artifact.path(), target.path(), None);
    set_mode(artifact.path(), previous);
    restored.unwrap_or_else(|error| {
        panic!("a read-only artifact directory must restore; a v1 artifact already does: {error}")
    });

    // WHOLLY NEW: every captured database is present and byte-identical.
    for name in ["a-first.db", "operational.db"] {
        assert_eq!(
            std::fs::read(target.path().join(name)).unwrap(),
            std::fs::read(artifact.path().join(STORES_SUBDIR).join(name)).unwrap(),
            "{name} must be wholly restored, not absent and not partial"
        );
    }

    // And the artifact is untouched — the property an operator relies on when
    // their artifact is a mounted snapshot or a copy out of an archive.
    assert_eq!(
        entry_names(artifact.path()),
        before,
        "a restore must create nothing inside the artifact directory"
    );
    assert!(
        !artifact.path().join(RESTORE_JOURNAL_NAME).exists(),
        "the journal must not be in the artifact at all"
    );
    // A successful restore leaves no journal under the target either: its
    // PRESENCE is what means `interrupted`.
    assert!(!restore_journal_path(target.path()).exists());

    // What the target DOES keep, pinned rather than left incidental: the empty
    // journal directory. It is `recovery-generations`, which the strict adoption
    // inventory already names as a top-level root and which every durable boot
    // creates anyway — so leaving it costs nothing, while removing a root this
    // module does not own would be reaching. Anything ELSE appearing here is a
    // new foreign entry in a restored data directory and must fail this test.
    assert_eq!(
        entry_names(target.path()),
        vec![
            "a-first.db".to_string(),
            "operational.db".to_string(),
            RESTORE_JOURNAL_SUBDIR.to_string(),
        ],
        "a restored data directory must hold the captured databases and the already-admitted \
         journal root, and nothing else"
    );
}

/// The same read-only artifact, INTERRUPTED partway: the target is still
/// wholly-old-or-wholly-new per asset, and the resume converges.
///
/// This is the half the plain success case cannot show. The defect was not that
/// a read-only artifact failed — it was that it failed BETWEEN two activations.
#[test]
fn an_interrupted_restore_from_a_read_only_artifact_leaves_no_torn_target() {
    // Cross-process per-uid serialization: this test drives a product
    // immutable-SQLite inspection, whose coordinator is a per-euid singleton with a
    // NONBLOCKING 3s product deadline. Two suites under one uid made it refuse with a
    // storage-integrity message for a scheduling cause. See
    // kata_test_utils::inspection_lock.
    let _inspection_lock = kata_test_utils::inspection_lock::hold();
    let source = tempfile::tempdir().unwrap();
    create_marked_database(&source.path().join("a-first.db"));
    create_marked_database(&source.path().join("operational.db"));
    let artifact = tempfile::tempdir().unwrap();
    backup_data_dir(source.path(), artifact.path(), None).expect("capture");

    let target = tempfile::tempdir().unwrap();
    let sentinel = b"the database that was already there".to_vec();
    std::fs::write(target.path().join("operational.db"), &sentinel).unwrap();

    let previous = set_mode(artifact.path(), 0o555);
    let outcome = restore_data_dir_aborting_before_activation(
        artifact.path(),
        target.path(),
        None,
        |name, _| {
            if name == "operational.db" {
                Err(KataError::Storage("power loss".to_string()))
            } else {
                Ok(())
            }
        },
    );
    assert!(outcome.is_err(), "the interruption must propagate");

    // Per asset: wholly new, or wholly old. Never a splice.
    assert_eq!(
        std::fs::read(target.path().join("a-first.db")).unwrap(),
        std::fs::read(artifact.path().join(STORES_SUBDIR).join("a-first.db")).unwrap(),
        "the asset activated before the interruption is wholly new"
    );
    assert_eq!(
        std::fs::read(target.path().join("operational.db")).unwrap(),
        sentinel,
        "the asset the interruption preceded is wholly OLD"
    );
    // The journal recorded the progress, under the TARGET, while the artifact
    // stayed read-only throughout.
    let journal: serde_json::Value =
        serde_json::from_slice(&std::fs::read(restore_journal_path(target.path())).expect(
            "an interrupted restore must journal under the target even when the artifact is \
             read-only",
        ))
        .unwrap();
    assert_eq!(journal["completed"], serde_json::json!(["a-first.db"]));

    // Resume, still read-only, and converge.
    let resumed = restore_data_dir(artifact.path(), target.path(), None);
    set_mode(artifact.path(), previous);
    resumed.expect("the resume must also work against a read-only artifact");
    assert_eq!(
        std::fs::read(target.path().join("operational.db")).unwrap(),
        std::fs::read(artifact.path().join(STORES_SUBDIR).join("operational.db")).unwrap()
    );
    assert!(
        !restore_journal_path(target.path()).exists(),
        "a completed restore clears its journal"
    );
}

// ---------------------------------------------------------------------------
// 7. THE TIER IS DERIVED, NOT READ — a one-field manifest edit cannot weaken it.
// ---------------------------------------------------------------------------

/// Hand-edit one asset's record to the cheap tier with no digest — the exact
/// one-field downgrade that satisfied every rule the coverage check had.
fn downgrade_record_tier(artifact: &Path, name: &str) {
    let manifest = read_manifest(artifact).expect("a v2 manifest");
    let mut raw: serde_json::Value =
        serde_json::from_slice(&std::fs::read(artifact.join(MANIFEST_NAME)).unwrap()).unwrap();
    let record = raw["assets"]
        .as_array_mut()
        .expect("assets is an array")
        .iter_mut()
        .find(|asset| asset["name"] == serde_json::json!(name))
        .unwrap_or_else(|| panic!("{name} must have a record to downgrade"));
    record["tier"] = serde_json::json!("best_effort");
    record["digest"] = serde_json::Value::Null;
    std::fs::write(
        artifact.join(MANIFEST_NAME),
        serde_json::to_vec_pretty(&raw).unwrap(),
    )
    .unwrap();
    // The edit must leave the artifact still CLAIMING v2 with full coverage —
    // otherwise it is caught by a rule that already existed and this test is
    // measuring the wrong refusal.
    assert_eq!(raw["version"], serde_json::json!(2));
    assert_eq!(
        raw["assets"].as_array().unwrap().len(),
        manifest.assets.len(),
        "the downgrade must not delete a record; deleting one is the tamper the coverage rule \
         already catches"
    );
}

/// A manifest whose claimed tier is WEAKER than the durable-asset map's derived
/// tier is refused, by name, before any target is touched.
///
/// # It has no non-vacuity arm, and that is recorded rather than absorbed
///
/// A RED baseline would apply the same two-field edit to a row the map derives
/// `BestEffort` for — a TRUE statement about that asset — and watch the tampered
/// bytes restore, proving the refusal below is decided by `AssetAuthority` and not
/// by the shape of the edit. No `*.db` row derives the cheap tier, so no artifact
/// can carry an honest best-effort database record and the baseline has no
/// fixture.
///
/// What is left proves the refusal FIRES; it does not prove the refusal
/// DISCRIMINATES. `no_database_can_earn_the_cheap_tier` holds the emptiness that
/// makes that unavoidable, and reds if a cheap `*.db` row ever returns — at
/// which point this baseline is buildable again and should be restored.
#[test]
fn a_manifest_supplied_tier_cannot_weaken_the_derived_one() {
    // Cross-process per-uid serialization: this test drives a product
    // immutable-SQLite inspection, whose coordinator is a per-euid singleton with a
    // NONBLOCKING 3s product deadline. Two suites under one uid made it refuse with a
    // storage-integrity message for a scheduling cause. See
    // kata_test_utils::inspection_lock.
    let _inspection_lock = kata_test_utils::inspection_lock::hold();
    let source = tempfile::tempdir().unwrap();
    create_marked_database(&source.path().join("operational.db"));

    // ---- GREEN: the edit on an `Authoritative` row is REFUSED. -------------
    let artifact = tempfile::tempdir().unwrap();
    backup_data_dir(source.path(), artifact.path(), None).expect("capture");
    downgrade_record_tier(artifact.path(), "operational.db");
    flip_payload_byte(&artifact.path().join(STORES_SUBDIR).join("operational.db"));
    assert_eq!(
        quick_check(&artifact.path().join(STORES_SUBDIR).join("operational.db")),
        "ok",
        "the tamper must leave structurally valid SQLite, or a structural check would catch it \
         and the tier would be irrelevant"
    );

    let target = tempfile::tempdir().unwrap();
    let sentinel = target.path().join("operational.db");
    std::fs::write(&sentinel, b"untouched").unwrap();

    // Refused in `read_manifest`, so it fails before a lease, before staging,
    // and before any target mutation.
    let error = read_manifest(artifact.path())
        .expect_err("a weakened tier claim must be refused by the manifest reader");
    let message = error.to_string();
    assert!(
        message.contains("operational.db"),
        "the refusal must name the asset: {message}"
    );
    assert!(
        message.contains("BestEffort") && message.contains("Durable"),
        "the refusal must name BOTH the claimed tier and the derived one, or an operator cannot \
         tell which side is wrong: {message}"
    );
    assert!(
        message.contains("not authority"),
        "the refusal must say WHY a manifest-supplied tier is inadmissible: {message}"
    );

    let error = restore_data_dir(artifact.path(), target.path(), None)
        .expect_err("the restore must refuse it too");
    assert!(error.to_string().contains("operational.db"), "{error}");
    assert_eq!(
        std::fs::read(&sentinel).unwrap(),
        b"untouched",
        "the refusal must precede any target mutation"
    );
}

// The FLOOR-not-CLAMP rule (`restore_tier`) is untested end-to-end: a record
// claiming `Durable` with a real digest, on a row the map derives `BestEffort` for,
// must be accepted and then ENFORCED. Reaching it needs a database whose derived
// tier is BELOW the maximum, and every database derives `Durable`: classified
// rows are `Authoritative`, and an unclassified name is given `Durable` by
// `tier_of_database` because ignorance argues for the expensive tier.
//
// Recorded rather than silently dropped: the floor-not-clamp direction — a
// stricter artifact must not be weakened to the map's answer — is untested
// end-to-end. It becomes testable again the
// moment any `*.db` row derives a cheap tier, which is exactly what
// `no_database_can_earn_the_cheap_tier` reds on.

/// The bundled config's tier is ASKED of the durable-asset map, not written as a
/// literal beside it.
///
/// A literal `tier: DurabilityTier::Durable` with a comment saying the map's row
/// agrees is a comment nothing executes — the duplicate-authority shape: two
/// places to change, one of which fails a test.
#[test]
fn the_bundled_config_tier_is_derived_from_its_map_row() {
    // Cross-process per-uid serialization: this test drives a product
    // immutable-SQLite inspection, whose coordinator is a per-euid singleton with a
    // NONBLOCKING 3s product deadline. Two suites under one uid made it refuse with a
    // storage-integrity message for a scheduling cause. See
    // kata_test_utils::inspection_lock.
    let _inspection_lock = kata_test_utils::inspection_lock::hold();
    let row = DURABLE_ASSETS
        .iter()
        .find(|asset| asset.location.name() == "--config")
        .expect("the bundled node config must have a durable-asset map row");
    let derived = durability_tier(row.authority);

    let dir = tempfile::tempdir().unwrap();
    let data = dir.path().join("data");
    std::fs::create_dir(&data).unwrap();
    create_marked_database(&data.join("operational.db"));
    let config = bundled_config(dir.path(), &data);

    let artifact = tempfile::tempdir().unwrap();
    kata_core::store::backup::backup_data_dir(&data, artifact.path(), Some(&config))
        .expect("capture with a bundled config");
    let manifest = read_manifest(artifact.path()).unwrap();
    let record = manifest
        .assets
        .iter()
        .find(|asset| asset.name == CONFIG_COPY_NAME)
        .expect("the bundled config must have a durability record");

    assert_eq!(
        record.tier, derived,
        "the capture must record the tier the map derives from the row's `AssetAuthority`, not a \
         constant that happens to agree with it today"
    );
    // The behavioural half: digest presence follows the DERIVED tier, so a row
    // reclassified to a cheap authority stops buying a digest without anyone
    // editing this module.
    assert_eq!(
        record.digest.is_some(),
        derived == DurabilityTier::Durable,
        "a digest must be recorded exactly when the derived tier buys one"
    );
    // COUNTERFACTUAL: `durability_tier` is not a constant function, so the
    // equality above is a real derivation and not `Durable == Durable` by luck.
    assert_ne!(
        durability_tier(AssetAuthority::Rebuildable { from: "anything" }),
        derived
    );
}

// ---------------------------------------------------------------------------
// 8. THE TREE — v2 carries the vocabulary, the capture fills it, and the refusal
//    is limited to what this binary genuinely cannot place.
// ---------------------------------------------------------------------------

/// A data directory holding the nucleus plus `count` real file-backed CAS
/// objects, returned with each object's payload keyed by tree-relative path.
///
/// Real objects through `CasStore::put`, not hand-written files: the layout is
/// `CasStore::blob_path`'s and a fixture that guessed it would stop testing the
/// capture the moment the layout moved.
///
/// A hand-spelled `format!("{}/{hex}", &hex[0..2])` would be a SECOND definition of the
/// blob layout, and it rots the moment the self-describing address (`<shard>/<64
/// hex>.<function>`) moves. The member path is DERIVED by calling the production
/// definition, `kata_core::store::cas::blob_relative_path_of_address` over
/// `CasAddress::blake3`, so the next move of the scheme cannot rot it: there is one
/// spelling and the test asks for it. COST: this helper does not independently witness the
/// layout —
/// `the_cas_blob_layout_shards_on_the_first_two_bytes_and_falls_back_rather_than_panicking`
/// in `durable_asset_map.rs` is the sole known-answer check that does, and it is
/// deliberately hand-spelled for that reason.
fn plant_cas_objects(data_dir: &Path, count: u8) -> Vec<(String, Vec<u8>)> {
    use kata_core::store::cas::{CasStore, INLINE_THRESHOLD, blob_relative_path_of_address};
    use kata_types::cache::CasAddress;

    create_marked_database(&data_dir.join("operational.db"));
    let cas = CasStore::open(data_dir.join("cas.db"), data_dir.join("cas")).expect("open cas");
    let mut planted = Vec::new();
    for seed in 0..count {
        let payload = vec![0xC0 ^ seed; INLINE_THRESHOLD + 1 + usize::from(seed)];
        let object_id = cas.put(&payload).expect("put a file-backed object");
        planted.push((
            blob_relative_path_of_address(&CasAddress::blake3(object_id)),
            payload,
        ));
    }
    cas.checkpoint().expect("checkpoint cas.db");
    drop(cas);
    planted.sort();
    planted
}

/// A [`kata_core::ConfigManager`] over the shipped example config with only
/// `node.data_dir` repointed at `data`, written under `home`.
///
/// The same fixture `backup_tests.rs` uses, so a bundling arm exercises the real
/// semantic validator rather than a minimal file that only happens to parse.
fn bundled_config(home: &Path, data: &Path) -> kata_core::ConfigManager {
    let config_path = home.join(CONFIG_COPY_NAME);
    let mut config_value: toml::Value =
        toml::from_str(include_str!("../../../config/kata.example.toml")).unwrap();
    config_value["node"]["data_dir"] = toml::Value::String(data.to_string_lossy().into_owned());
    std::fs::write(&config_path, toml::to_string_pretty(&config_value).unwrap()).unwrap();
    kata_core::ConfigManager::load(&config_path).expect("load config")
}

/// The captured tree record a manifest carries, or a panic naming what it
/// carried instead.
fn sole_tree(manifest: &BackupManifest) -> &kata_core::store::backup::CapturedTree {
    assert_eq!(
        manifest.tree_roots,
        vec!["cas".to_string()],
        "the artifact must claim exactly the CAS byte tree"
    );
    manifest
        .trees
        .first()
        .expect("a claimed tree must carry a record")
}

/// A tampered CAS OBJECT is refused by name, before the target is touched.
///
/// # The bad state first
///
/// `PRAGMA quick_check` was the only content check the shipped restore had, and
/// it has nothing to say about a blob: a CAS object is opaque bytes, so a flipped
/// byte inside one leaves a file of the same length that no structural check can
/// distinguish from the original. The baseline below asserts exactly that — the
/// tampered object is byte-length-identical and differs in one position — so the
/// refusal that follows is demonstrably bought by the per-member digest and by
/// nothing else.
///
/// The refusal must NAME the object. `CapturedTreeEntry`'s own doc gives the
/// reason: a single digest over concatenated bytes says *something moved* and
/// cannot say WHICH object, which is precisely the question an operator holding
/// a corrupt artifact has to answer.
#[test]
fn a_tampered_cas_object_is_refused_by_name_and_never_reaches_the_target() {
    // Cross-process per-uid serialization: this test drives a product
    // immutable-SQLite inspection, whose coordinator is a per-euid singleton with a
    // NONBLOCKING 3s product deadline. Two suites under one uid made it refuse with a
    // storage-integrity message for a scheduling cause. See
    // kata_test_utils::inspection_lock.
    let _inspection_lock = kata_test_utils::inspection_lock::hold();
    let source = tempfile::tempdir().unwrap();
    let planted = plant_cas_objects(source.path(), 2);
    let artifact = tempfile::tempdir().unwrap();
    let manifest = backup_data_dir(source.path(), artifact.path(), None).expect("capture");
    let tree = sole_tree(&manifest);
    assert_eq!(tree.entry_count, 2, "both objects must be captured");

    // NON-VACUOUS: the untampered artifact restores, and both objects land.
    {
        let clean_target = tempfile::tempdir().unwrap();
        restore_data_dir(artifact.path(), clean_target.path(), None)
            .expect("the untampered artifact must restore");
        for (path, payload) in &planted {
            assert_eq!(
                &std::fs::read(clean_target.path().join("cas").join(path)).unwrap(),
                payload,
                "the untampered artifact must land {path} byte-for-byte"
            );
        }
    }

    // THE TAMPER — one byte, inside one object, in the artifact.
    let victim = &planted[1].0;
    let victim_path = artifact.path().join(TREES_SUBDIR).join("cas").join(victim);
    let mut bytes = std::fs::read(&victim_path).unwrap();
    let before_len = bytes.len();
    bytes[7] ^= 0xFF;
    std::fs::write(&victim_path, &bytes).unwrap();
    assert_eq!(
        std::fs::metadata(&victim_path).unwrap().len(),
        before_len as u64,
        "the flip must not resize the object; a length change would be caught without a digest \
         and this test would prove nothing about the digest"
    );

    // The read-only probe refuses it, so a tampered artifact never reaches a
    // lifecycle lease.
    let preflight =
        kata_core::store::backup::preflight_restore_artifact(artifact.path(), source.path(), None)
            .expect_err("the read-only preflight must refuse a tampered tree member");
    let message = preflight.to_string();
    assert!(
        message.contains(victim),
        "the refusal must NAME the object that failed, not merely report that the tree moved: \
         {message}"
    );
    assert!(
        message.contains("digests to") && message.contains("tampered"),
        "the refusal must say what disagreed: {message}"
    );

    // And the restore refuses without writing anything at all.
    let target = tempfile::tempdir().unwrap();
    let error = restore_data_dir(artifact.path(), target.path(), None)
        .expect_err("the restore must refuse a tampered tree member too");
    assert!(error.to_string().contains(victim), "{error}");
    assert!(
        !target.path().join("operational.db").exists()
            && !target.path().join("cas").join(&planted[0].0).exists(),
        "nothing may reach the target: the tree is verified in the artifact BEFORE any activation \
         precisely so a corrupt artifact does not half-restore a node"
    );
}

/// An EDITED ENTRY LIST is refused, and that is the property that makes the
/// per-member digests worth having.
///
/// # The bad state first, and it is the subtle one
///
/// After the edit below, every per-member check still passes: the entry that
/// remains digests to its recorded value, and the DELETED entry's bytes are
/// still sitting in the artifact, intact. `entry_count` and `total_byte_len` are
/// corrected so every arithmetic rule passes too. A validator that checked only
/// what the index NAMES would see a perfectly consistent artifact and restore
/// one object out of two — silently, because nothing else in the artifact
/// records that a second one was ever captured.
///
/// This is the same shape `refuse_weakened_tier` closes one level up: evidence
/// whose absence is indistinguishable from "there was none" is evidence that can
/// be deleted. `CapturedTree::entry_digest` is what makes the index itself
/// tamper-evident.
#[test]
fn an_edited_tree_index_is_refused_because_the_entry_list_is_itself_digested() {
    // Cross-process per-uid serialization: this test drives a product
    // immutable-SQLite inspection, whose coordinator is a per-euid singleton with a
    // NONBLOCKING 3s product deadline. Two suites under one uid made it refuse with a
    // storage-integrity message for a scheduling cause. See
    // kata_test_utils::inspection_lock.
    let _inspection_lock = kata_test_utils::inspection_lock::hold();
    let source = tempfile::tempdir().unwrap();
    let planted = plant_cas_objects(source.path(), 2);
    let artifact = tempfile::tempdir().unwrap();
    let manifest = backup_data_dir(source.path(), artifact.path(), None).expect("capture");
    assert_eq!(sole_tree(&manifest).entry_count, 2);

    // THE EDIT — drop the second entry from the index and leave everything else
    // arithmetically consistent.
    let mut edited = manifest.clone();
    let tree = edited.trees.first_mut().expect("a tree record");
    let removed = tree.entries.pop().expect("two entries");
    tree.entry_count = tree.entries.len() as u64;
    tree.total_byte_len = tree.entries.iter().map(|entry| entry.byte_len).sum();

    // THE BAD STATE, measured: nothing about the MEMBERS is wrong.
    let removed_in_artifact = artifact
        .path()
        .join(TREES_SUBDIR)
        .join("cas")
        .join(&removed.path);
    assert!(
        removed_in_artifact.is_file(),
        "the deleted entry's BYTES are still in the artifact — the index is the only thing hiding \
         them, which is exactly why the index needs its own digest"
    );
    assert_eq!(
        std::fs::metadata(&removed_in_artifact).unwrap().len(),
        removed.byte_len,
        "and they are intact"
    );
    for entry in &tree.entries {
        let path = artifact
            .path()
            .join(TREES_SUBDIR)
            .join("cas")
            .join(&entry.path);
        let digest = blake3::hash(&std::fs::read(&path).unwrap())
            .to_hex()
            .to_string();
        assert_eq!(
            Some(&digest),
            entry.digest.as_ref(),
            "every SURVIVING member still matches its recorded digest, so per-member evidence \
             alone cannot see this edit"
        );
    }

    // THE FIX — `entry_digest` no longer matches the list it covers.
    overwrite_manifest(artifact.path(), &edited);
    let error = read_manifest(artifact.path())
        .expect_err("an edited entry list must be refused before anything is restored");
    let message = error.to_string();
    assert!(
        message.contains("entry list digests to"),
        "the refusal must name the index digest rather than blame a member: {message}"
    );
    assert!(
        message.contains("cas"),
        "the refusal must name the tree: {message}"
    );

    let target = tempfile::tempdir().unwrap();
    assert!(
        restore_data_dir(artifact.path(), target.path(), None).is_err(),
        "the restore must refuse it too"
    );
    assert!(
        !target.path().join("cas").exists(),
        "and must write no part of the truncated tree"
    );

    // COUNTERFACTUAL — the UNEDITED manifest over the same artifact restores
    // both objects, so the refusal is about the index edit and not about the
    // manifest having been rewritten at all.
    overwrite_manifest(artifact.path(), &manifest);
    let honest = tempfile::tempdir().unwrap();
    restore_data_dir(artifact.path(), honest.path(), None)
        .expect("the unedited manifest must restore");
    for (path, payload) in &planted {
        assert_eq!(
            &std::fs::read(honest.path().join("cas").join(path)).unwrap(),
            payload,
            "{path} must come back"
        );
    }
}

/// The tree refusal fires for exactly the claim this binary cannot place — and
/// for no other.
///
/// # What is asserted
///
/// A tree manifest rides `MANIFEST_VERSION` 2, and a `cas` tree claim is honoured.
/// A `vcs.jj_repo` claim is not: the jj repo is under `AssetRoot::OperatorDeclared`,
/// a root nothing in this binary resolves, and its capture stays deferred. So the
/// assertion has to be the NARROWING — that `cas`
/// is honoured AND `vcs.jj_repo` is still refused by name. Asserting only the
/// first would be satisfiable by a binary that restores whatever a manifest asks
/// for.
#[test]
fn a_tree_manifest_rides_v2_and_the_refusal_narrows_to_the_root_nothing_resolves() {
    // Cross-process per-uid serialization: this test drives a product
    // immutable-SQLite inspection, whose coordinator is a per-euid singleton with a
    // NONBLOCKING 3s product deadline. Two suites under one uid made it refuse with a
    // storage-integrity message for a scheduling cause. See
    // kata_test_utils::inspection_lock.
    let _inspection_lock = kata_test_utils::inspection_lock::hold();
    let source = tempfile::tempdir().unwrap();
    let planted = plant_cas_objects(source.path(), 1);
    let artifact = tempfile::tempdir().unwrap();
    let manifest = backup_data_dir(source.path(), artifact.path(), None).expect("capture");

    // (1) v2. The field set is fixed, so a tree-carrying artifact and a
    // database-only one are the same version — which is only honest because of (3).
    assert_eq!(manifest.version, MANIFEST_VERSION);
    let tree = sole_tree(&manifest);
    assert_eq!(tree.name, "cas");
    assert_eq!(tree.root, kata_core::durable_assets::AssetRoot::MainDataDir);
    assert_eq!(tree.tier, DurabilityTier::Durable);
    assert_eq!(tree.entry_count, 1);
    assert_eq!(tree.entries[0].path, planted[0].0);
    assert!(tree.entry_digest.is_some());

    // (2) The `cas` claim is HONOURED, not refused.
    let target = tempfile::tempdir().unwrap();
    restore_data_dir(artifact.path(), target.path(), None)
        .expect("a `cas` tree claim must be restored, not refused");
    assert_eq!(
        std::fs::read(target.path().join("cas").join(&planted[0].0)).unwrap(),
        planted[0].1,
        "and the bytes must actually land"
    );

    // (3) The `vcs.jj_repo` claim is still REFUSED BY NAME. Built as raw JSON
    // rather than by mutating the struct, because this is what a manifest from a
    // jj-capable later build would look like on disk.
    let jj = jj_tree_manifest_document(&manifest);
    let bytes = serde_json::to_vec_pretty(&jj).unwrap();
    // It DESERIALIZES — the field set is shared, which is why a refusal rather
    // than a decode error is the only thing standing here.
    let decoded: BackupManifest =
        serde_json::from_slice(&bytes).expect("a jj tree manifest must deserialize");
    assert_eq!(decoded.trees[0].name, "vcs.jj_repo");

    std::fs::write(artifact.path().join(MANIFEST_NAME), &bytes).unwrap();
    let message = read_manifest(artifact.path())
        .expect_err("a tree claim this binary cannot place must be refused")
        .to_string();
    assert!(
        message.contains("vcs.jj_repo"),
        "the refusal must name the tree: {message}"
    );
    assert!(
        message.contains("cannot restore") && message.contains("no capture or restore mechanism"),
        "the refusal must say WHY — a durable root this binary does not resolve — rather than \
         report a generic decode failure: {message}"
    );
    let jj_target = tempfile::tempdir().unwrap();
    assert!(
        restore_data_dir(artifact.path(), jj_target.path(), None).is_err(),
        "the restore must refuse it too"
    );
    assert!(
        !jj_target.path().join("operational.db").exists(),
        "and must mutate nothing: restoring the databases and dropping the tree is precisely the \
         silent partial restore this refusal exists to prevent"
    );

    // (4) The claim and the evidence must AGREE. A record with no matching claim
    // would restore an asset the completeness report calls missing; a claim with
    // no record would tell an operator an asset is covered when nothing restores
    // it. Both directions, over a name this binary CAN place, so the refusal is
    // about the disagreement and not about the name.
    for (label, roots, trees) in [
        (
            "a claim with no record",
            serde_json::json!(["cas"]),
            serde_json::json!([]),
        ),
        (
            "a record with no claim",
            serde_json::json!([]),
            serde_json::json!([{
                "name": "cas",
                "root": "main_data_dir",
                "tier": "durable",
                "entries": [],
                "entry_count": 0,
                "total_byte_len": 0,
                "entry_digest": "3".repeat(64),
            }]),
        ),
    ] {
        let mut disagreeing = jj.clone();
        disagreeing["tree_roots"] = roots;
        disagreeing["trees"] = trees;
        std::fs::write(
            artifact.path().join(MANIFEST_NAME),
            serde_json::to_vec_pretty(&disagreeing).unwrap(),
        )
        .unwrap();
        let message = read_manifest(artifact.path()).unwrap_err().to_string();
        assert!(
            message.contains("disagree about") && message.contains("cas"),
            "{label} must be refused by name: {message}"
        );
    }
}

/// A manifest claiming a tree captured at a WEAKER tier than the map derives is
/// refused, exactly as `refuse_weakened_tier` does for a file asset.
///
/// The attack is the same one-field edit that defeats a file path whose tier is
/// read off the manifest: `"tier": "best_effort"` with the digests dropped satisfies every
/// coverage rule vacuously and leaves nothing to compare against. A tree makes
/// it worse, not better — the digests it drops are per-member AND the index —
/// so the derivation has to hold here too.
#[test]
fn a_tree_record_may_not_claim_a_weaker_tier_than_the_map_derives() {
    // Cross-process per-uid serialization: this test drives a product
    // immutable-SQLite inspection, whose coordinator is a per-euid singleton with a
    // NONBLOCKING 3s product deadline. Two suites under one uid made it refuse with a
    // storage-integrity message for a scheduling cause. See
    // kata_test_utils::inspection_lock.
    let _inspection_lock = kata_test_utils::inspection_lock::hold();
    let source = tempfile::tempdir().unwrap();
    plant_cas_objects(source.path(), 1);
    let artifact = tempfile::tempdir().unwrap();
    let manifest = backup_data_dir(source.path(), artifact.path(), None).expect("capture");
    assert_eq!(
        sole_tree(&manifest).tier,
        durability_tier(AssetAuthority::Authoritative),
        "the capture must record the tier the map derives from the row's `AssetAuthority`"
    );

    let mut weakened = manifest.clone();
    let tree = weakened.trees.first_mut().expect("a tree record");
    tree.tier = DurabilityTier::BestEffort;
    for entry in &mut tree.entries {
        entry.digest = None;
    }
    tree.entry_digest = None;
    overwrite_manifest(artifact.path(), &weakened);

    let message = read_manifest(artifact.path())
        .expect_err("a weakened tree tier must be refused")
        .to_string();
    assert!(
        message.contains("cas") && message.contains("BestEffort") && message.contains("Durable"),
        "the refusal must name the tree, the claim, and the derivation: {message}"
    );

    // COUNTERFACTUAL — the honest record over the same artifact is accepted, so
    // the refusal is the DOWNGRADE and not the rewrite.
    overwrite_manifest(artifact.path(), &manifest);
    read_manifest(artifact.path()).expect("the honest manifest must still read");
}

/// A manifest with the tree keys ABSENT is REFUSED, not read as "captured no
/// tree".
///
/// # Why refusal, not a default
///
/// Every artifact this binary writes
/// carries both keys — empty when nothing was captured, which is a POSITIVE
/// statement — so a manifest without them is not an older artifact, it is a
/// hand-edited one, and a default would answer it with silence about exactly the
/// asset (`cas`) whose absence a restore must not invent.
#[test]
fn a_manifest_without_the_tree_keys_is_refused_rather_than_defaulted() {
    // Cross-process per-uid serialization: this test drives a product
    // immutable-SQLite inspection, whose coordinator is a per-euid singleton with a
    // NONBLOCKING 3s product deadline. Two suites under one uid made it refuse with a
    // storage-integrity message for a scheduling cause. See
    // kata_test_utils::inspection_lock.
    let _inspection_lock = kata_test_utils::inspection_lock::hold();
    // The producer identity is COPIED from a real capture rather than
    // hand-spelled. `ProducerIdentity` is `deny_unknown_fields` with four
    // required members, so a re-spelling here is a second copy of a production
    // scheme that rots the day the scheme moves; and every field this fixture
    // does not VARY should be whatever a genuine artifact says, which is the
    // same argument the `vcs.jj_repo` fixture above makes for itself.
    let source = tempfile::tempdir().unwrap();
    create_marked_database(&source.path().join("operational.db"));
    let captured = tempfile::tempdir().unwrap();
    let real = backup_data_dir(source.path(), captured.path(), None).expect("capture");

    // This document is COMPLETE-BUT-FOR-THE-TREE-KEYS. A document that also
    // omitted `producer` would pass only by field order — serde reports the FIRST
    // missing field in DECLARATION order and `tree_roots` precedes `producer` in
    // `BackupManifest` — rather than by the property this test's name states. Varying exactly
    // one thing costs a real capture and buys a refusal that can only be about
    // the thing varied. (`artifact_id` and `capture_order` are `Option`, which
    // serde fills with `None` when absent even with no `#[serde(default)]`, so
    // those two were never load-bearing either way — they are spelled as
    // explicit nulls here so the document states what it means.)
    let raw = serde_json::json!({
        "version": 2,
        "created_at_ms": 1_u64,
        "databases": [],
        "config_included": false,
        "artifact_id": serde_json::Value::Null,
        "assets": [],
        "capture_order": serde_json::Value::Null,
        "producer": real.producer,
    });
    let error = serde_json::from_slice::<BackupManifest>(&serde_json::to_vec(&raw).unwrap())
        .expect_err("a manifest missing a required key must not decode to a defaulted one");
    assert!(
        error.to_string().contains("tree_roots"),
        "the refusal must name the missing key: {error}"
    );

    // COUNTERFACTUAL — the same document WITH the keys, empty, decodes and says
    // "captured no tree" positively. So the refusal is about the key being
    // absent, not about an empty capture being inexpressible.
    let mut present = raw;
    present["tree_roots"] = serde_json::json!([]);
    present["trees"] = serde_json::json!([]);
    let decoded: BackupManifest =
        serde_json::from_slice(&serde_json::to_vec(&present).unwrap()).expect("the complete shape");
    assert!(decoded.tree_roots.is_empty() && decoded.trees.is_empty());
}

/// A member's CONTENT is bound to the ADDRESS its path names, and a forgery
/// that satisfies every other check in the artifact is refused by that binding
/// alone.
///
/// # The bad state first, and this one defeats every per-member check
///
/// Verifying each member's bytes against the digest the manifest records FOR THAT
/// MEMBER, and the entry list against `entry_digest`, is not enough. Both are
/// statements the manifest makes about itself, and the manifest is
/// unauthenticated JSON. So: put object X's bytes at object Y's path, rewrite
/// Y's entry to X's digest and length, re-seal the index over the edited list.
/// Every per-member digest matches, every length matches, the index digest
/// matches, and the restore is ACCEPTED — the baseline below asserts all four,
/// measured, before the refusal is shown.
///
/// The consequence is specific to a content-addressed asset and is why the check
/// exists: `cas` serves an object by hashing a lookup key to a path
/// (`CasStore::blob_path`), so a store fed this artifact returns bytes under an
/// address they do not hash to.
///
/// # What this does NOT fix
///
/// The same forgery still works on the DATABASE records: the manifest has never
/// been authenticated as a whole, and `stores/operational.db` has no derivable
/// relation between its name and its bytes for a check to be built from. This
/// closes the case where the relation IS derivable, and
/// [`kata_core::durable_assets::TreeMemberAddressing`] is where an asset says
/// whether it has one.
#[test]
fn a_cas_member_may_not_hold_bytes_that_address_elsewhere() {
    // Cross-process per-uid serialization: this test drives a product
    // immutable-SQLite inspection, whose coordinator is a per-euid singleton with a
    // NONBLOCKING 3s product deadline. Two suites under one uid made it refuse with a
    // storage-integrity message for a scheduling cause. See
    // kata_test_utils::inspection_lock.
    let _inspection_lock = kata_test_utils::inspection_lock::hold();
    use kata_types::cache::object_id_for_canonical_bytes;

    let source = tempfile::tempdir().unwrap();
    let planted = plant_cas_objects(source.path(), 2);
    let artifact = tempfile::tempdir().unwrap();
    let manifest = backup_data_dir(source.path(), artifact.path(), None).expect("capture");
    assert_eq!(sole_tree(&manifest).entry_count, 2);

    let member = |relative: &str| {
        artifact
            .path()
            .join(TREES_SUBDIR)
            .join("cas")
            .join(relative)
    };
    let donor = planted[0].0.clone();
    let victim = planted[1].0.clone();
    assert_ne!(donor, victim, "two distinct objects, or there is no swap");

    // THE FORGERY — donor bytes at the victim's address, with the manifest
    // rewritten to agree with them.
    let donor_bytes = std::fs::read(member(&donor)).unwrap();
    std::fs::write(member(&victim), &donor_bytes).unwrap();
    let mut forged = manifest.clone();
    {
        let tree = forged.trees.first_mut().expect("a tree record");
        let donor_entry = tree
            .entries
            .iter()
            .find(|entry| entry.path == donor)
            .cloned()
            .expect("the donor entry");
        let victim_entry = tree
            .entries
            .iter_mut()
            .find(|entry| entry.path == victim)
            .expect("the victim entry");
        victim_entry.digest = donor_entry.digest.clone();
        victim_entry.byte_len = donor_entry.byte_len;
        tree.total_byte_len = tree.entries.iter().map(|entry| entry.byte_len).sum();
    }
    let resealed = kata_core::store::backup::reseal_tree_entry_digest(
        &forged.trees.first().expect("a tree record").entries,
    );
    forged
        .trees
        .first_mut()
        .expect("a tree record")
        .entry_digest = Some(resealed);
    overwrite_manifest(artifact.path(), &forged);

    // THE BAD STATE, MEASURED — every per-member check the artifact carries passes
    // over the forged artifact.
    {
        let tree = forged.trees.first().expect("a tree record");
        for entry in &tree.entries {
            let bytes = std::fs::read(member(&entry.path)).unwrap();
            assert_eq!(
                Some(blake3::hash(&bytes).to_hex().to_string()),
                entry.digest,
                "the per-member digest still matches {:?}; a manifest that was edited to agree \
                 with forged bytes agrees with them",
                entry.path
            );
            assert_eq!(bytes.len() as u64, entry.byte_len, "and so does the length");
        }
        assert_eq!(
            Some(kata_core::store::backup::reseal_tree_entry_digest(
                &tree.entries
            )),
            tree.entry_digest,
            "and the index digest covers the edited list, because an unkeyed digest over a list \
             an attacker holds is re-computable by that attacker"
        );
        // The damage, stated from the bytes rather than from the manifest.
        let victim_address = object_id_for_canonical_bytes(&donor_bytes).to_string();
        assert!(
            !victim.ends_with(&victim_address),
            "the bytes now sitting at {victim} address to {victim_address}: a store that served \
             this member would return bytes under an address they do not hash to"
        );
    }

    // THE FIX — the read-only preflight refuses, naming the member and the
    // address its bytes actually require.
    let message =
        kata_core::store::backup::preflight_restore_artifact(artifact.path(), source.path(), None)
            .expect_err("a member whose bytes address elsewhere must be refused")
            .to_string();
    assert!(
        message.contains(&victim),
        "the refusal must NAME the member it refused: {message}"
    );
    assert!(
        message.contains(&object_id_for_canonical_bytes(&donor_bytes).to_string()),
        "and must name the address the bytes actually require, or an operator cannot tell a \
         forgery from bit rot: {message}"
    );

    // And nothing reaches the target.
    let target = tempfile::tempdir().unwrap();
    let error = restore_data_dir(artifact.path(), target.path(), None)
        .expect_err("the restore must refuse it too");
    assert!(error.to_string().contains(&victim), "{error}");
    assert!(
        !target.path().join("cas").join(&victim).exists()
            && !target.path().join("operational.db").exists(),
        "the tree is verified in the artifact BEFORE any activation, so a forged artifact must \
         not half-restore a node"
    );

    // COUNTERFACTUAL — the honest artifact still restores and the store serves
    // both objects, so the refusal is the SWAP and not the check refusing
    // everything.
    overwrite_manifest(artifact.path(), &manifest);
    std::fs::write(member(&victim), &planted[1].1).unwrap();
    let clean = tempfile::tempdir().unwrap();
    restore_data_dir(artifact.path(), clean.path(), None).expect("the honest artifact restores");
    for (path, payload) in &planted {
        assert_eq!(
            &std::fs::read(clean.path().join("cas").join(path)).unwrap(),
            payload,
            "{path} must land byte-for-byte"
        );
    }
}

/// The SOURCE side of the same binding: a corrupt object in the live CAS fails
/// the CAPTURE, by name, instead of being copied into an artifact that this
/// binary's own restore would later refuse.
///
/// # Why the check is at both ends and not only at restore
///
/// The restore-side check is the mandatory one — the artifact is the untrusted
/// input and a forged manifest is the attack. This one buys something the other
/// cannot: WHEN the operator finds out. Without it, a bit-rotted blob is copied
/// faithfully into every artifact, each of which passes its own capture, and the
/// refusal arrives on the day of the restore — from an artifact the operator has
/// been trusting for months. With it, the same rot is named at the next backup,
/// against a live store that still holds every other object.
///
/// This is a REFUSAL and not a degradation, and the two are not in tension:
/// [`kata_core::store::backup`]'s rule is that a BOUND overrun omits the tree
/// and an INTEGRITY failure refuses. A member whose bytes do not hash to its own
/// address is not a large store, it is a corrupt one, and there is no smaller
/// true artifact to fall back to.
#[test]
fn a_corrupt_source_object_fails_the_capture_rather_than_the_restore_months_later() {
    // Cross-process per-uid serialization: this test drives a product
    // immutable-SQLite inspection, whose coordinator is a per-euid singleton with a
    // NONBLOCKING 3s product deadline. Two suites under one uid made it refuse with a
    // storage-integrity message for a scheduling cause. See
    // kata_test_utils::inspection_lock.
    let _inspection_lock = kata_test_utils::inspection_lock::hold();
    let source = tempfile::tempdir().unwrap();
    let planted = plant_cas_objects(source.path(), 2);

    // NON-VACUOUS: the untouched source captures.
    {
        let clean = tempfile::tempdir().unwrap();
        let manifest = backup_data_dir(source.path(), clean.path(), None)
            .expect("an intact source must capture");
        assert_eq!(sole_tree(&manifest).entry_count, 2);
    }

    // THE ROT — one byte inside one object in the LIVE store, same length, so
    // no structural check can see it.
    let victim = source.path().join("cas").join(&planted[1].0);
    let mut bytes = std::fs::read(&victim).unwrap();
    let before = bytes.len();
    bytes[11] ^= 0xFF;
    std::fs::write(&victim, &bytes).unwrap();
    assert_eq!(
        std::fs::metadata(&victim).unwrap().len(),
        before as u64,
        "the flip must not resize the object, or the length check would catch it and this test \
         would prove nothing about the address"
    );

    let artifact = tempfile::tempdir().unwrap();
    let message = backup_data_dir(source.path(), artifact.path(), None)
        .expect_err("a source object whose bytes do not hash to its own path must be refused")
        .to_string();
    assert!(
        message.contains(&planted[1].0),
        "the refusal must NAME the corrupt object; an operator cannot repair a store from \
         'something moved': {message}"
    );
    assert!(
        message.contains(&kata_types::cache::object_id_for_canonical_bytes(&bytes).to_string()),
        "and must name the address the rotted bytes now carry: {message}"
    );
    assert!(
        !artifact
            .path()
            .join(kata_core::store::backup::MANIFEST_NAME)
            .exists(),
        "the manifest is published strictly last, so a refused capture leaves an artifact that is \
         UNCLAIMABLE rather than one advertising a tree it did not finish"
    );
}

// ---------------------------------------------------------------------------
// 9. THE WRITE-THEN-REMOVE PATH — the only one that can hold a PREFIX of an
//    authoritative tree, and the one nothing drove.
// ---------------------------------------------------------------------------

/// Every path under `trees/`, recursively, as `trees/`-relative strings, with
/// each marked as a directory or a file.
///
/// A file-only listing would pass over the failure this section exists to catch
/// twice over: an empty `trees/cas/ab/` left behind is bytes an operator pays to
/// store that no manifest names, and it is also the evidence that the removal
/// was partial rather than complete.
fn tree_listing(artifact: &Path) -> Vec<(String, bool)> {
    fn walk(root: &Path, prefix: &str, out: &mut Vec<(String, bool)>) {
        let Ok(entries) = std::fs::read_dir(root) else {
            return;
        };
        for entry in entries {
            let entry = entry.expect("read a tree entry");
            let name = entry.file_name().to_string_lossy().into_owned();
            let relative = if prefix.is_empty() {
                name
            } else {
                format!("{prefix}/{name}")
            };
            let is_dir = entry.file_type().expect("stat a tree entry").is_dir();
            out.push((relative.clone(), is_dir));
            if is_dir {
                walk(&entry.path(), &relative, out);
            }
        }
    }
    let mut out = Vec::new();
    walk(&artifact.join(TREES_SUBDIR), "", &mut out);
    out.sort();
    out
}

/// The files in [`tree_listing`], which is what "no partial member survives"
/// means.
fn tree_files(artifact: &Path) -> Vec<String> {
    tree_listing(artifact)
        .into_iter()
        .filter(|(_, is_dir)| !is_dir)
        .map(|(path, _)| path)
        .collect()
}

/// The bytes each planted object occupies, largest first.
fn planted_lengths(planted: &[(String, Vec<u8>)]) -> Vec<u64> {
    let mut lengths: Vec<u64> = planted
        .iter()
        .map(|(_, payload)| payload.len() as u64)
        .collect();
    lengths.sort_unstable_by(|a, b| b.cmp(a));
    lengths
}

/// The assertions every bound overrun owes the operator, over a finished
/// artifact.
///
/// Factored because the two byte bounds must produce the SAME artifact-level
/// outcome — the rule in `TreeCapture` is about a bound overrun, not about which
/// bound — and two hand-written copies of it would be two chances to weaken one.
fn assert_degraded_cleanly(artifact: &Path, manifest: &BackupManifest) {
    assert!(
        manifest.tree_roots.is_empty() && manifest.trees.is_empty(),
        "the artifact must not claim a tree it does not hold: {manifest:?}"
    );
    assert!(
        manifest
            .databases
            .iter()
            .any(|name| name == "operational.db"),
        "DEGRADE CAPACITY, REFUSE CORRECTNESS: an oversized tree must not cost the operator the \
         databases, which were perfectly capturable. Captured {:?}",
        manifest.databases
    );
    assert!(
        artifact
            .join(STORES_SUBDIR)
            .join("operational.db")
            .is_file(),
        "and the database bytes are really in the artifact, not merely named"
    );
    assert_eq!(
        tree_files(artifact),
        Vec::<String>::new(),
        "NOT ONE partial member may survive in `trees/`: the members this capture wrote before it \
         hit the bound are bytes an operator pays to store and transfer that no manifest names, \
         and a later reader finding a populated `trees/cas/` beside a manifest claiming no tree \
         has to guess which one is lying"
    );
    assert_eq!(
        tree_listing(artifact),
        Vec::<(String, bool)>::new(),
        "and the removal must be COMPLETE — the shard directories the capture created are gone \
         too, so `trees/` is exactly as empty as it was before the tree pass ran"
    );
    let verdict = kata_core::store::backup::manifest_completeness(manifest);
    assert!(
        verdict.missing_authoritative.contains(&"cas"),
        "the omission must be NAMED through the completeness machinery both operator reports \
         print: {verdict:?}"
    );
    // The class is deliberately NOT asserted, and this is the second time that
    // decision has had to be made. The line here read
    // `assert_eq!(verdict.class, BackupClass::DataSnapshot, "and the omission
    // must COST the class")`, itself a replacement for an equally vacuous
    // `assert_ne!(…, Recoverable, …)`, and it was recorded as load-bearing
    // because `assess_backup_class` had stopped hardcoding the class. It is not:
    // an omission-FREE capture of the same source carries the identical class,
    // so the line could not fail for a degraded artifact or an intact one.
    //
    // `structural_inventory_alone_cannot_earn_recoverable` in
    // `crates/core/src/store/backup_tests.rs` states and measures why — the three
    // channels into `manifest_completeness`'s captured set cannot express the
    // identity, worker-node or jj-repo rows, so `DataSnapshot` is the only
    // reachable class for this structural snapshot assessment. The separate
    // verified v4 path is not the subject of this omission test.
    // The `missing_authoritative` line above is the falsifiable one; each
    // caller's counterfactual flips it.
}

/// The PER-MEMBER byte bound omits the whole tree and removes every member it
/// had already published.
///
/// # Why this path is the dangerous one, and why it had no test
///
/// `MAX_TREE_ENTRIES` is decided by `walk_tree_entries` BEFORE `capture_tree`
/// creates the destination root, so an entry-bound omission writes nothing and
/// removes nothing — a recursive walk of `trees/` after one finds zero files
/// structurally. `MAX_TREE_FILE_BYTES` and `MAX_TREE_TOTAL_BYTES` are discovered
/// MID-COPY, so they are the only two that reach
/// `TreeCapture::omitted_after_writing`, the one path in the module that writes
/// members into the artifact and then removes them again. It had zero coverage
/// (`grep -rn omitted_after_writing crates/` -> 3 hits, none a test) and neither
/// bound had a seam to drive it with.
///
/// # The fixture makes the partial DETERMINISTIC
///
/// The overrun member sits at `ff/ffff…f`, which `walk_tree_entries` always
/// visits LAST: it sorts children by name at each level, `ff` is the last shard
/// a CAS layout can produce, and 64 `f`s is the largest 64-hex name. So both
/// real objects are copied, digested, address-verified and RENAMED into the
/// artifact before the bound is discovered — the artifact genuinely holds a
/// prefix of an authoritative tree at the moment the removal runs, which is the
/// state the assertions are about. A fixture whose overrun member sorted first
/// would assert an empty `trees/` that was never populated.
///
/// The RED was established by commenting out the `remove_dir_all` in
/// `TreeCapture::omitted_after_writing` and re-running: `trees/` then held the
/// two published members and their shard directories.
#[test]
fn an_oversized_member_omits_the_tree_and_removes_the_members_already_published() {
    // Cross-process per-uid serialization: this test drives a product
    // immutable-SQLite inspection, whose coordinator is a per-euid singleton with a
    // NONBLOCKING 3s product deadline. Two suites under one uid made it refuse with a
    // storage-integrity message for a scheduling cause. See
    // kata_test_utils::inspection_lock.
    let _inspection_lock = kata_test_utils::inspection_lock::hold();
    let source = tempfile::tempdir().unwrap();
    let planted = plant_cas_objects(source.path(), 2);
    let largest = planted_lengths(&planted)[0];

    // Over the bound by one byte, and last in the walk. Not a valid CAS object,
    // which is deliberate and harmless: the SIZE check precedes both the copy
    // and `verify_member_address`, so this reaches the bound and never the
    // address rule. (A capture at production bounds over the same fixture would
    // refuse it by address — see
    // `a_corrupt_source_object_fails_the_capture_rather_than_the_restore_months_later`.)
    let last = format!("ff/{}", "f".repeat(64));
    std::fs::create_dir_all(source.path().join("cas").join("ff")).unwrap();
    std::fs::write(
        source.path().join("cas").join(&last),
        vec![0x5A; usize::try_from(largest + 1).unwrap()],
    )
    .unwrap();

    let artifact = tempfile::tempdir().unwrap();
    let outcome = kata_core::store::backup::backup_data_dir_with_tree_bounds(
        source.path(),
        artifact.path(),
        usize::MAX,
        largest,
        u64::MAX,
    )
    .expect(
        "a member over the per-member bound is a CAPACITY fact; failing the whole backup over it \
         would leave the operator with no artifact at all",
    );

    assert_degraded_cleanly(artifact.path(), &outcome.manifest);
    assert_eq!(
        outcome
            .omitted
            .iter()
            .map(|omitted| omitted.name.as_str())
            .collect::<Vec<_>>(),
        vec!["cas"],
    );
    let reason = &outcome.omitted[0].reason;
    assert!(
        reason.contains(&last)
            && reason.contains(&(largest + 1).to_string())
            && reason.contains(&largest.to_string()),
        "the reason must name the MEMBER, its size, and the bound — an operator holding a 4 TiB \
         CAS cannot act on 'a bound was hit': {reason}"
    );

    // COUNTERFACTUAL ONE — the SAME fixture with one more byte of headroom does
    // not degrade at all. The oversized member stops being a CAPACITY fact and
    // becomes a CORRECTNESS one: it is copied, address-verified, and REFUSED.
    //
    // This is the rule `TreeCapture` states, exercised on a single file by
    // moving a single number: a bound overrun degrades and names itself, an
    // integrity failure refuses and fails the capture. It also pins that the
    // omission above was reached by the bound and not by the address rule, which
    // a "and now it captures" counterfactual could not have shown here.
    let roomy = tempfile::tempdir().unwrap();
    let error = kata_core::store::backup::backup_data_dir_with_tree_bounds(
        source.path(),
        roomy.path(),
        usize::MAX,
        largest + 1,
        u64::MAX,
    )
    .expect_err("past the bound, the same member is a corrupt object rather than a large one");
    let message = error.to_string();
    assert!(
        message.contains(&last) && message.contains("content address"),
        "the refusal must name the member and the address its bytes require: {message}"
    );
    assert!(
        !roomy.path().join(MANIFEST_NAME).exists(),
        "and a REFUSED capture leaves an artifact that is unclaimable, never one advertising a \
         tree it did not finish"
    );

    // COUNTERFACTUAL TWO — the two real objects, at the same raised bound, with
    // the overrun member gone: the tree captures whole. So the degradation is
    // the oversized member and not the fixture's two ordinary ones.
    std::fs::remove_file(source.path().join("cas").join(&last)).unwrap();
    let clean = tempfile::tempdir().unwrap();
    let captured = kata_core::store::backup::backup_data_dir_with_tree_bounds(
        source.path(),
        clean.path(),
        usize::MAX,
        largest + 1,
        u64::MAX,
    )
    .expect("a tree inside every bound captures");
    assert!(captured.omitted.is_empty());
    assert_eq!(captured.manifest.tree_roots, vec!["cas".to_string()]);
    assert_eq!(
        tree_files(clean.path()).len(),
        2,
        "both real members must land, or the counterfactual is measuring something else"
    );
    assert!(
        !kata_core::store::backup::manifest_completeness(&captured.manifest)
            .missing_authoritative
            .contains(&"cas"),
        "and `assert_degraded_cleanly`'s completeness assertion must FLIP here — it is the one \
         line in that helper an artifact can change, now that the class line is gone"
    );
}

/// The TOTAL byte bound does the same, and this one trips with a member already
/// RENAMED into place rather than merely staged.
///
/// # The two bounds abort at different points, which is why both are driven
///
/// The per-member bound is checked from `symlink_metadata` before that member is
/// opened. The total bound is checked AFTER a member has been copied, hashed and
/// counted — so the abort happens with one `.capture-tmp` alive as well as every
/// earlier member published. Both residues must be gone, and a test of one bound
/// says nothing about the other's cleanup.
///
/// Deterministic by construction: with three members and a total bound equal to
/// the LARGEST single member, the first member always fits and the second always
/// overruns, whatever order the content addresses sort in.
#[test]
fn a_tree_over_the_total_byte_bound_is_removed_whole_including_its_shard_directories() {
    // Cross-process per-uid serialization: this test drives a product
    // immutable-SQLite inspection, whose coordinator is a per-euid singleton with a
    // NONBLOCKING 3s product deadline. Two suites under one uid made it refuse with a
    // storage-integrity message for a scheduling cause. See
    // kata_test_utils::inspection_lock.
    let _inspection_lock = kata_test_utils::inspection_lock::hold();
    let source = tempfile::tempdir().unwrap();
    let planted = plant_cas_objects(source.path(), 3);
    let largest = planted_lengths(&planted)[0];

    let artifact = tempfile::tempdir().unwrap();
    let outcome = kata_core::store::backup::backup_data_dir_with_tree_bounds(
        source.path(),
        artifact.path(),
        usize::MAX,
        u64::MAX,
        largest,
    )
    .expect("a tree over the total bound degrades rather than failing the backup");

    assert_degraded_cleanly(artifact.path(), &outcome.manifest);
    let reason = &outcome.omitted[0].reason;
    assert!(
        reason.contains("total") && reason.contains(&largest.to_string()),
        "the reason must say it was the TOTAL that overran, and name the bound; 'too big' is not \
         actionable when three different bounds can produce it: {reason}"
    );

    // The consistency token must not order an asset the artifact does not hold.
    assert!(
        !outcome
            .consistency
            .entries()
            .iter()
            .any(|entry| entry.asset == "cas"),
        "an entry for an omitted asset would make the recorded capture order a fiction"
    );

    // COUNTERFACTUAL — the same three objects under a total bound that fits.
    let roomy = tempfile::tempdir().unwrap();
    let captured = kata_core::store::backup::backup_data_dir_with_tree_bounds(
        source.path(),
        roomy.path(),
        usize::MAX,
        u64::MAX,
        planted_lengths(&planted).iter().sum::<u64>(),
    )
    .expect("a tree inside the total bound captures");
    assert!(captured.omitted.is_empty());
    assert_eq!(sole_tree(&captured.manifest).entry_count, 3);
    assert!(
        !kata_core::store::backup::manifest_completeness(&captured.manifest)
            .missing_authoritative
            .contains(&"cas"),
        "and `assert_degraded_cleanly`'s completeness assertion must FLIP here too"
    );
}

/// A removal the FILESYSTEM REFUSES still leaves an artifact that claims no
/// tree.
///
/// # This is the property the tidy-up is allowed to fail on
///
/// `TreeCapture::omitted_after_writing` discards the result of its
/// `remove_dir_all` deliberately: the artifact is already honest without the
/// removal, and turning tidy-up into an error would re-create the total failure
/// the whole degradation path exists to avoid. That is a claim about what
/// happens when the removal DOESN'T work, and nothing was measuring it — so the
/// removal was simultaneously best-effort and load-bearing, which is the state
/// where a later edit "helpfully" makes it fatal and nothing objects.
///
/// The refusal is real rather than injected: a previous capture's `trees/cas/`
/// is re-entered by a second capture into the same artifact (`backup_data_dir`
/// is documented idempotent to one `out_dir`), and it holds a subdirectory this
/// process cannot unlink from. `remove_dir_all` fails, some members may survive,
/// and the artifact STILL claims nothing it does not hold.
#[cfg(unix)]
#[test]
fn a_removal_the_filesystem_refuses_still_leaves_an_artifact_claiming_no_tree() {
    // Cross-process per-uid serialization: this test drives a product
    // immutable-SQLite inspection, whose coordinator is a per-euid singleton with a
    // NONBLOCKING 3s product deadline. Two suites under one uid made it refuse with a
    // storage-integrity message for a scheduling cause. See
    // kata_test_utils::inspection_lock.
    let _inspection_lock = kata_test_utils::inspection_lock::hold();
    let source = tempfile::tempdir().unwrap();
    let planted = plant_cas_objects(source.path(), 3);
    let largest = planted_lengths(&planted)[0];

    // A FIRST capture, at bounds everything fits inside, so `trees/cas/` exists
    // and is populated before the second one re-enters it.
    let artifact = tempfile::tempdir().unwrap();
    backup_data_dir(source.path(), artifact.path(), None).expect("the first capture");
    assert_eq!(tree_files(artifact.path()).len(), 3);

    // The obstruction. `remove_dir_all` must unlink `blocker/pinned` to remove
    // `trees/cas`, and unlinking from a directory needs write permission on it.
    let blocker = artifact
        .path()
        .join(TREES_SUBDIR)
        .join("cas")
        .join("blocker");
    std::fs::create_dir_all(&blocker).unwrap();
    std::fs::write(blocker.join("pinned"), b"unremovable").unwrap();
    let restore_mode = set_mode(&blocker, 0o500);
    assert!(
        std::fs::remove_file(blocker.join("pinned")).is_err(),
        "the obstruction must actually obstruct — if this unlink succeeds the process is root or \
         the mode did not take, and the rest of this test would be measuring a SUCCESSFUL removal"
    );

    // The SECOND capture into the same artifact, over the total bound.
    let outcome = kata_core::store::backup::backup_data_dir_with_tree_bounds(
        source.path(),
        artifact.path(),
        usize::MAX,
        u64::MAX,
        largest,
    )
    .expect(
        "a tidy-up the filesystem refuses must not fail the backup: the artifact is already \
         honest without the removal",
    );

    // The removal genuinely failed — measured, not assumed.
    let obstructed = blocker.join("pinned").exists();
    // Restored HERE rather than at the end so a failing assertion below still
    // leaves a `TempDir` its `Drop` can actually remove.
    set_mode(&blocker, restore_mode);
    assert!(
        obstructed,
        "this test proves nothing unless `remove_dir_all` actually failed"
    );

    // AND YET: the artifact claims no tree, and says so to the operator.
    assert!(
        outcome.manifest.tree_roots.is_empty() && outcome.manifest.trees.is_empty(),
        "an interrupted removal must not leave the artifact claiming a tree it lacks: {:?}",
        outcome.manifest
    );
    assert!(
        kata_core::store::backup::manifest_completeness(&outcome.manifest)
            .missing_authoritative
            .contains(&"cas"),
        "and the completeness report must still name the omission"
    );
    assert!(
        outcome
            .manifest
            .databases
            .iter()
            .any(|name| name == "operational.db"),
        "and the databases are still captured"
    );

    // A restore of this artifact must not resurrect the residue as a tree.
    let target = tempfile::tempdir().unwrap();
    let restored = restore_data_dir(artifact.path(), target.path(), None)
        .expect("an artifact claiming no tree restores");
    assert!(restored.tree_roots.is_empty());
    assert!(
        !target.path().join("cas").exists(),
        "the residue is unclaimed bytes inside the artifact, not an asset; a restore must not \
         place it"
    );
}

/// The capture's DESTINATION tree root may not be a symlink either.
///
/// # The bad state, which shipped
///
/// Both of the other two sides checked this and the destination did not:
/// `discover_captured_trees` refuses a symlink at `<data_dir>/cas`, and
/// `verify_captured_tree_sources` refuses one at `<artifact>/trees` on restore.
/// `capture_tree` ran a bare `create_dir_all` on `<artifact>/trees/<name>`, which
/// returns `Ok` for a symlink that resolves to a directory — so every member was
/// copied, fsynced and renamed THROUGH it, and the manifest then claimed `cas`
/// with a full entry list and the right byte total.
///
/// The artifact is not forged, not hand-edited, and reports itself healthy. The
/// harm is that it is not SELF-CONTAINED: `trees/cas` is a pointer out of the
/// directory an operator archives, copies to the recovery host, and restores
/// from. Every one of those operations drops the bytes while leaving the claim,
/// which is precisely the artifact the tree capture exists to make impossible.
///
/// The RED was measured by reverting `require_real_directory` at
/// `capture_tree`'s destination root: the capture then returned `Ok`, the
/// manifest carried `tree_roots = ["cas"]` and a 3-entry tree record, and the
/// three objects were in `escape/` rather than in the artifact.
#[cfg(unix)]
#[test]
fn a_symlinked_destination_tree_root_is_refused_rather_than_captured_through() {
    // Cross-process per-uid serialization: this test drives a product
    // immutable-SQLite inspection, whose coordinator is a per-euid singleton with a
    // NONBLOCKING 3s product deadline. Two suites under one uid made it refuse with a
    // storage-integrity message for a scheduling cause. See
    // kata_test_utils::inspection_lock.
    let _inspection_lock = kata_test_utils::inspection_lock::hold();
    use std::os::unix::fs::symlink;

    let source = tempfile::tempdir().unwrap();
    let planted = plant_cas_objects(source.path(), 3);

    // NON-VACUOUS: the same source into an unobstructed artifact captures the
    // tree whole, so the refusal below is bought by the symlink and not by the
    // fixture.
    let clean = tempfile::tempdir().unwrap();
    let clean_manifest = backup_data_dir(source.path(), clean.path(), None).expect("capture");
    assert_eq!(sole_tree(&clean_manifest).entry_count, 3);
    assert_eq!(tree_files(clean.path()).len(), 3);

    let artifact = tempfile::tempdir().unwrap();
    let escape = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(artifact.path().join(TREES_SUBDIR)).unwrap();
    symlink(
        escape.path(),
        artifact.path().join(TREES_SUBDIR).join("cas"),
    )
    .unwrap();

    let error = backup_data_dir(source.path(), artifact.path(), None).expect_err(
        "a capture may not write an authoritative tree through a symlink out of the artifact: the \
         manifest would claim `cas` while the bytes lived where a copy of the artifact cannot \
         reach them",
    );
    let message = error.to_string();
    assert!(
        message.contains("trees/cas") && message.contains("is not a real directory"),
        "the refusal must name the destination and the rule it broke: {message}"
    );

    assert!(
        entry_names(escape.path()).is_empty(),
        "NOT ONE byte may be written through the symlink: the capture wrote {:?} outside the \
         artifact",
        entry_names(escape.path())
    );
    assert!(
        !artifact.path().join(MANIFEST_NAME).exists(),
        "and a refused capture leaves an artifact that is unclaimable, never one advertising a \
         tree whose bytes are elsewhere"
    );
    // The refusal is CORRECTNESS, not capacity: it fails the capture rather than
    // degrading, for the reason `TreeCapture` states — there is no smaller true
    // artifact to fall back to when the destination itself is a lie.
    assert_eq!(
        planted.len(),
        3,
        "the fixture must have planted the objects the counterfactual above captured"
    );
}

/// EVERY directory the artifact's own layout owns refuses a symlink at its own
/// name — on the capture side and on the restore side.
///
/// # Why one test over every position rather than one test per position
///
/// Every position — including the capture's destination tree root, which
/// `a_symlinked_destination_tree_root_is_refused_rather_than_captured_through`
/// covers — goes through ONE predicate, `DirectoryState`. A per-position test
/// would restate the rule once per position while leaving the NEXT position,
/// whenever it arrives, unguarded.
///
/// **The COUNT belongs in the enumeration, not in this sentence.** This
/// paragraph said "five positions" and the loops below drove four and then two.
/// The restore loop read `["stores", TREES_SUBDIR]` while the doc line above it
/// claimed EVERY directory the layout owns — and `trees/cas`, whose absence let
/// a restore SUCCEED while reading authoritative CAS bytes from outside the
/// artifact, was in neither. The test written to stop the (n+1)th site
/// forgetting the rule had itself forgotten a site, which is what a
/// hand-maintained count in prose buys. The list that must stay complete is the
/// one on `create_owned_file` in `crates/core/src/store/backup.rs`, which
/// enumerates every write position in the module; these loops mirror it.
///
/// "These loops mirror it" is a claim a loop can silently stop meeting: a list of
/// positions and a loop over them drift apart one arm at a time, and an
/// enumeration derived from *"every WRITE position"* alone misses the READ sides
/// (`<artifact>/trees/<tree>/<shard>` on restore, where a symlink would let
/// `preflight_restore_artifact` and `restore_data_dir` both return `Ok` while
/// reading every authoritative CAS byte from outside the artifact). The
/// enumeration on `create_owned_file` is derived from a question that covers both
/// directions, and every arm asserts the refusal NAMES the position it was
/// planted at — an arm asserting only `contains("is not a real directory")` could
/// pass on a refusal from anywhere else in the restore.
///
/// So this enumerates the positions instead. Each arm replaces exactly one
/// directory with a symlink to a real directory OUTSIDE the tree it belongs to
/// and changes nothing else, and the non-vacuity arm at the top proves the same
/// fixture is otherwise capturable and restorable.
#[cfg(unix)]
#[test]
fn every_directory_the_artifact_owns_refuses_a_symlink_at_its_own_name() {
    // Cross-process per-uid serialization: this test drives a product
    // immutable-SQLite inspection, whose coordinator is a per-euid singleton with a
    // NONBLOCKING 3s product deadline. Two suites under one uid made it refuse with a
    // storage-integrity message for a scheduling cause. See
    // kata_test_utils::inspection_lock.
    let _inspection_lock = kata_test_utils::inspection_lock::hold();
    use std::os::unix::fs::symlink;

    // NON-VACUOUS: this fixture captures and restores when nothing is a link.
    {
        let source = tempfile::tempdir().unwrap();
        plant_cas_objects(source.path(), 1);
        let artifact = tempfile::tempdir().unwrap();
        backup_data_dir(source.path(), artifact.path(), None).expect("an unobstructed capture");
        let target = tempfile::tempdir().unwrap();
        restore_data_dir(artifact.path(), target.path(), None).expect("an unobstructed restore");
    }

    // CAPTURE side. `cas` is the SOURCE tree root (`discover_captured_trees`);
    // the other four are inside the artifact this capture is writing.
    //
    // The `<shard>` arm is the one a loop over the four above it loses — the
    // "the list is complete and the loop mirrors it" failure.
    for position in ["cas", "stores", "trees", "trees/cas", "trees/cas/{shard}"] {
        let source = tempfile::tempdir().unwrap();
        let planted = plant_cas_objects(source.path(), 1);
        let position = &position.replace("{shard}", &planted[0].0[..2]);
        let position = position.as_str();
        let artifact = tempfile::tempdir().unwrap();
        let escape = tempfile::tempdir().unwrap();

        let linked = if position == "cas" {
            let root = source.path().join("cas");
            let moved = escape.path().join("relocated");
            std::fs::rename(&root, &moved).unwrap();
            symlink(&moved, &root).unwrap();
            root
        } else {
            let path = artifact.path().join(position);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            symlink(escape.path(), &path).unwrap();
            path
        };

        let error = match backup_data_dir(source.path(), artifact.path(), None) {
            Err(error) => error,
            Ok(manifest) => {
                panic!("a capture must refuse a symlink at {position:?}, and produced {manifest:?}")
            }
        };
        let message = error.to_string();
        assert!(
            message.contains(&linked.display().to_string())
                && message.contains("is not a real directory"),
            "the refusal must name the position and the rule, and said: {message}"
        );
        assert!(
            !artifact.path().join(MANIFEST_NAME).exists(),
            "and a capture refused at {position:?} must leave no claimable artifact"
        );
    }

    // RESTORE side, ARTIFACT positions, over a healthy artifact whose directory
    // is swapped for a link afterwards — the artifact an operator was handed
    // rather than one they captured.
    //
    // `trees/cas` is here because "EVERY directory the artifact's own layout owns" includes
    // it, and the gap is not hypothetical: a `verify_captured_tree_sources` that guarded
    // `trees_dir` and not `trees_dir.join(&tree.name)` would let a restore from an artifact
    // whose `trees/cas` was a link SUCCEEDED while reading authoritative CAS bytes from
    // outside the artifact.
    //
    // `trees/cas/{shard}` is the level where the members live. Measured against a
    // full-path read side — an artifact whose `trees/cas/<shard>` was a link to a
    // directory outside it: `preflight_restore_artifact` returned `Ok`,
    // `restore_data_dir` returned `Ok`, and every authoritative CAS byte the
    // operator restored was read from OUTSIDE the artifact; see
    // `create_owned_file`.
    //
    // The refusal must NAME the position, for the reason the file loop above
    // states: an arm asserting only `contains("is not a real directory")` could
    // pass on a refusal from anywhere else in the restore.
    for position in ["stores", TREES_SUBDIR, "trees/cas", "trees/cas/{shard}"] {
        let source = tempfile::tempdir().unwrap();
        let planted = plant_cas_objects(source.path(), 1);
        // DERIVED from the planted object, never typed: a hand-written
        // `trees/cas/ab` names a shard no member lands in, so the arm would pass
        // by never being reached — the trap the target-side loop below already
        // fell into once.
        let member = &planted[0].0;
        let position = &position.replace("{shard}", &member[..member.find('/').unwrap()]);
        let position = position.as_str();
        let artifact = tempfile::tempdir().unwrap();
        backup_data_dir(source.path(), artifact.path(), None).expect("capture");

        let escape = tempfile::tempdir().unwrap();
        let real = artifact.path().join(position);
        let moved = escape.path().join("relocated");
        std::fs::rename(&real, &moved).unwrap();
        symlink(&moved, &real).unwrap();

        // The READ-ONLY gate `kata restore` runs first, which is what an
        // operator hits before any authority is taken. It was `Ok` for the
        // shard arm against a full-path read side.
        let error = match preflight_restore_artifact(artifact.path(), source.path(), None) {
            Err(error) => error,
            Ok(manifest) => panic!(
                "the read-only preflight must refuse a symlinked {position:?}, and produced \
                 {manifest:?}"
            ),
        };
        assert!(
            error.to_string().contains("is not a real directory")
                && error.to_string().contains(&real.display().to_string()),
            "the preflight refusal must name the position and the rule at {position:?}, and \
             said: {error}"
        );

        let target = tempfile::tempdir().unwrap();
        let error = match restore_data_dir(artifact.path(), target.path(), None) {
            Err(error) => error,
            Ok(manifest) => {
                panic!("a restore must refuse a symlinked {position:?}, and produced {manifest:?}")
            }
        };
        assert!(
            error.to_string().contains("is not a real directory")
                && error.to_string().contains(&real.display().to_string()),
            "the refusal must name the position and the rule at {position:?}, and said: {error}"
        );
        assert!(
            entry_names(target.path()).is_empty(),
            "and it must refuse BEFORE touching the target, which held {:?}",
            entry_names(target.path())
        );
    }

    // RESTORE side, TARGET positions. `activate_captured_tree` derives
    // `<data_dir>/<tree.name>` from the MANIFEST, so `DirectoryState`'s carve-out
    // for "paths the operator typed" does not reach it: the operator typed
    // `<data_dir>`, and the component below it is a name the artifact supplied.
    // A symlink there placed both authoritative objects outside the target data
    // directory — the shape the capture side already refused at the mirror
    // position.
    //
    // The SHARD arm is derived from the planted object rather than typed: a
    // hand-written `cas/ab` names a shard no member lands in, so the arm passes
    // by never being reached. It did, on the first run.
    //
    // `recovery-generations` is here because `record_activation` creates it on the
    // first DURABLE activation and the enumeration lists it.
    for depth in [0_usize, 1, 2] {
        let source = tempfile::tempdir().unwrap();
        let planted = plant_cas_objects(source.path(), 2);
        let artifact = tempfile::tempdir().unwrap();
        backup_data_dir(source.path(), artifact.path(), None).expect("capture");

        let member = &planted[0].0;
        let position = match depth {
            0 => "cas".to_string(),
            1 => format!("cas/{}", &member[..member.find('/').unwrap()]),
            _ => RESTORE_JOURNAL_SUBDIR.to_string(),
        };
        let target = tempfile::tempdir().unwrap();
        let escape = tempfile::tempdir().unwrap();
        let linked = target.path().join(&position);
        std::fs::create_dir_all(linked.parent().unwrap()).unwrap();
        symlink(escape.path(), &linked).unwrap();

        let error = match restore_data_dir(artifact.path(), target.path(), None) {
            Err(error) => error,
            Ok(manifest) => panic!(
                "a restore must refuse a symlinked target {position:?}, and produced {manifest:?}"
            ),
        };
        assert!(
            error.to_string().contains("is not a real directory")
                && error.to_string().contains(&linked.display().to_string()),
            "the refusal must name the position and the rule at target {position:?}, and said: \
             {error}"
        );
        assert!(
            entry_names(escape.path()).is_empty(),
            "NOT ONE object may land outside the target data directory: {:?}",
            entry_names(escape.path())
        );
    }
}

/// What a hostile (or merely careless) party can leave at a path this module is
/// about to write, and what each one does to the write.
#[cfg(unix)]
#[derive(Clone, Copy, Debug)]
enum Obstruction {
    /// A link to a path that does not exist yet. `open(2)` with `O_CREAT` and no
    /// `O_NOFOLLOW` CREATES the target and writes there; `rename(2)` then moves
    /// the LINK into place, so the caller's own `exists()`/`metadata()` checks
    /// all pass while the bytes sit outside.
    DanglingSymlink,
    /// A second name for an inode that already exists elsewhere. `O_NOFOLLOW`
    /// does NOT refuse one — it constrains the final component's TYPE, and a
    /// hardlink is a directory entry, not a link object — so this is the arm
    /// that separates "refuse a symlink" from "own the inode you are writing".
    Hardlink,
    /// `open(2)` for writing on a FIFO with no reader BLOCKS forever without
    /// `O_NONBLOCK` — measured: an `O_WRONLY|O_CREAT|O_TRUNC` open did not
    /// return inside a 5s budget, and `O_NOFOLLOW|O_NONBLOCK` returned `ENXIO`
    /// at once. This arm is an availability fault rather than an integrity one,
    /// and it is the reason the mechanism opens non-blocking. It is also why the
    /// arm is only assertable AFTER the fix: a path-based open does not fail
    /// here, it hangs, which is the worse of the two.
    Fifo,
}

/// Plant `kind` at `at`, returning the path whose contents prove the write
/// escaped (empty for [`Obstruction::Fifo`], which corrupts nothing and hangs).
#[cfg(unix)]
fn plant_obstruction(kind: Obstruction, at: &Path, escape: &Path) -> Option<PathBuf> {
    use std::os::unix::fs::symlink;

    match kind {
        Obstruction::DanglingSymlink => {
            let leaked = escape.join("leaked");
            symlink(&leaked, at).unwrap();
            Some(leaked)
        }
        Obstruction::Hardlink => {
            let shared = escape.join("shared");
            std::fs::write(&shared, b"bytes that belong to somebody else").unwrap();
            std::fs::hard_link(&shared, at).unwrap();
            Some(shared)
        }
        Obstruction::Fifo => {
            nix::unistd::mkfifo(at, nix::sys::stat::Mode::from_bits_truncate(0o600)).unwrap();
            None
        }
    }
}

/// EVERY file this module writes inside the artifact or inside the restore
/// target refuses a pre-placed obstruction at its own path.
///
/// # The directory fix covered every DIRECTORY and missed every FILE
///
/// Guarding every directory position is not enough. An artifact escapes through the
/// MEMBER'S STAGING FILE: a dangling symlink at
/// `<artifact>/trees/cas/<shard>/<hex>.capture-tmp` let `capture_tree` validate every
/// directory, compute the staging path, and hand it to a `File::create` that follows the
/// link. `std::fs::rename` does not follow symlinks, so it moves THE LINK into the
/// artifact.
///
/// Measured against that form, on the one-object fixture below: the capture returned
/// `Ok` with `tree_roots: ["cas"]`, `entry_count: 1`, `total_byte_len: 102401`,
/// a per-member digest, and `entry_digest: 0a922442c7f7…` — the SAME value the
/// HONEST capture of the same fixture publishes, so nothing an operator can read
/// off the artifact distinguishes them.
///
/// A per-position rule is what produced that, so this enumerates the positions
/// and the module publishes the same enumeration beside the code
/// (`create_owned_file`). Each arm plants exactly ONE obstruction at ONE path and
/// changes nothing else; the residue arm at the bottom is the non-vacuity half —
/// a plain regular file at the same paths must still be REPLACED, because
/// `backup_data_dir` is documented idempotent to one `out_dir` and a restore must
/// resume over its own `.restore-tmp`.
///
/// `<artifact>/kata.toml.restore-tmp` needs a capture that BUNDLES a config, which
/// makes it the row easiest to leave enumerated and undriven. It is driven below,
/// and every arm asserts the refusal NAMES the position it was planted at — without that, an
/// arm the capture never reaches passes on a refusal from somewhere else.
///
/// What this test does NOT cover, and where to find it: a symlink at an
/// INTERMEDIATE component of one of these paths. Every arm here plants at a
/// LEAF, which is what every guard binds; the components between the artifact
/// root and the leaf were resolved and checked nowhere. See
/// `a_symlink_inside_a_member_path_destroys_nothing_outside_the_artifact`.
#[cfg(unix)]
#[test]
fn every_file_the_artifact_writes_refuses_a_pre_placed_obstruction() {
    // Cross-process per-uid serialization: this test drives a product
    // immutable-SQLite inspection, whose coordinator is a per-euid singleton with a
    // NONBLOCKING 3s product deadline. Two suites under one uid made it refuse with a
    // storage-integrity message for a scheduling cause. See
    // kata_test_utils::inspection_lock.
    let _inspection_lock = kata_test_utils::inspection_lock::hold();
    for kind in [
        Obstruction::DanglingSymlink,
        Obstruction::Hardlink,
        Obstruction::Fifo,
    ] {
        // CAPTURE side: every staging path inside the artifact the capture is
        // writing. Planted before the capture runs, which is the artifact
        // directory an operator hands to `kata backup` rather than one it made.
        for position in [
            // `copy_hashing` -> `ProvenDir::create_owned_file` (tree member staging).
            "trees/cas/{shard}.capture-tmp",
            // `vacuum_into` -> SQLite `VACUUM INTO` (database staging).
            "stores/operational.db.capture-tmp",
            // `durable_publish` -> `create_owned_file` (the manifest itself).
            "backup-manifest.json.restore-tmp",
            // `durable_publish` -> `create_owned_file` (the bundled config copy).
            // The one position that needs a fixture (a bundled config) the other
            // three do not, which makes it the easiest to leave undriven.
            "kata.toml.restore-tmp",
        ] {
            let source = tempfile::tempdir().unwrap();
            let planted = plant_cas_objects(source.path(), 1);
            let artifact = tempfile::tempdir().unwrap();
            let escape = tempfile::tempdir().unwrap();
            let config_home = tempfile::tempdir().unwrap();
            let config = (position == "kata.toml.restore-tmp")
                .then(|| bundled_config(config_home.path(), source.path()));

            let at = artifact
                .path()
                .join(position.replace("{shard}", &planted[0].0));
            std::fs::create_dir_all(at.parent().unwrap()).unwrap();
            let leak = plant_obstruction(kind, &at, escape.path());

            let error = match backup_data_dir(source.path(), artifact.path(), config.as_ref()) {
                Err(error) => error,
                Ok(manifest) => panic!(
                    "a capture must refuse a {kind:?} at {position:?}, and produced {manifest:?}"
                ),
            };
            // NAMED, or an arm can pass on a refusal from somewhere else
            // entirely — which is how the config row sat in the enumeration
            // undriven while this loop stayed green.
            assert!(
                error.to_string().contains(&at.display().to_string()),
                "the refusal must name the position it fired at ({position:?}, {kind:?}), and \
                 said: {error}"
            );
            if let Some(leak) = &leak {
                assert!(
                    !leak.exists() || std::fs::read(leak).unwrap().starts_with(b"bytes that"),
                    "NOT ONE byte may be written through a {kind:?} at {position:?}; \
                     {} holds {:?} (refusal was: {error})",
                    leak.display(),
                    std::fs::read(leak).unwrap_or_default().len()
                );
            }
            assert!(
                !artifact.path().join(MANIFEST_NAME).is_file(),
                "and a capture refused at {position:?} ({kind:?}) must leave no claimable \
                 artifact; the refusal was: {error}"
            );
        }

        // RESTORE side: every staging path inside the TARGET data directory.
        // Captured cleanly first, so the artifact is healthy and only the target
        // is obstructed — the recovery host an operator restores onto.
        for position in [
            // `copy_hashing` -> `File::create` (tree member staging).
            "{shard}.restore-tmp",
            // `activate_staged_file` -> `File::create` (database staging).
            "operational.db.restore-tmp",
            // `durable_publish` -> `File::create` (the restore journal).
            "recovery-generations/backup-restore-journal.json.restore-tmp",
        ] {
            let source = tempfile::tempdir().unwrap();
            let planted = plant_cas_objects(source.path(), 1);
            let artifact = tempfile::tempdir().unwrap();
            backup_data_dir(source.path(), artifact.path(), None).expect("capture");

            let target = tempfile::tempdir().unwrap();
            let escape = tempfile::tempdir().unwrap();
            let at = target
                .path()
                .join(position.replace("{shard}", &format!("cas/{}", planted[0].0)));
            std::fs::create_dir_all(at.parent().unwrap()).unwrap();
            let leak = plant_obstruction(kind, &at, escape.path());

            let error = match restore_data_dir(artifact.path(), target.path(), None) {
                Err(error) => error,
                Ok(manifest) => panic!(
                    "a restore must refuse a {kind:?} at target {position:?}, and produced \
                     {manifest:?}"
                ),
            };
            // NAMED, or an arm can pass on a refusal from somewhere else
            // entirely — which is how the config row sat in the enumeration
            // undriven while this loop stayed green.
            assert!(
                error.to_string().contains(&at.display().to_string()),
                "the refusal must name the position it fired at ({position:?}, {kind:?}), and \
                 said: {error}"
            );
            if let Some(leak) = &leak {
                assert!(
                    !leak.exists() || std::fs::read(leak).unwrap().starts_with(b"bytes that"),
                    "NOT ONE byte may be written through a {kind:?} at target {position:?}; \
                     {} was modified (refusal was: {error})",
                    leak.display()
                );
            }
        }
    }

    // NON-VACUITY. The same paths carrying ORDINARY RESIDUE — a plain regular
    // file, which is exactly what an interrupted earlier run leaves — must be
    // REPLACED and not refused. This is why the mechanism is `O_NOFOLLOW` rather
    // than `O_EXCL`/`create_new`: `create_new` refuses a symlink by construction
    // too, and would also refuse every resume.
    //
    // This said "the same SIX paths" and the loops below drive SEVEN (4 capture
    // + 3 restore) — in the test whose own doc says "The COUNT belongs in the
    // enumeration, not in this sentence", one paragraph up. The count is gone
    // rather than corrected to seven, for exactly the reason that paragraph
    // gives: a hand-maintained number in prose is the thing that goes stale, and
    // the loops below are the list.
    let source = tempfile::tempdir().unwrap();
    let planted = plant_cas_objects(source.path(), 1);
    let artifact = tempfile::tempdir().unwrap();
    let config_home = tempfile::tempdir().unwrap();
    let config = bundled_config(config_home.path(), source.path());
    for position in [
        "trees/cas/{shard}.capture-tmp",
        "stores/operational.db.capture-tmp",
        "backup-manifest.json.restore-tmp",
        "kata.toml.restore-tmp",
    ] {
        let at = artifact
            .path()
            .join(position.replace("{shard}", &planted[0].0));
        std::fs::create_dir_all(at.parent().unwrap()).unwrap();
        std::fs::write(&at, b"residue of an interrupted earlier capture").unwrap();
    }
    let manifest = backup_data_dir(source.path(), artifact.path(), Some(&config))
        .expect("a capture must write straight over its own residue");
    assert_eq!(sole_tree(&manifest).entry_count, 1);
    assert!(
        manifest.config_included,
        "the residue arm must bundle a config, or the config staging position is residue-free by \
         never being written"
    );

    let target = tempfile::tempdir().unwrap();
    for position in [
        "cas/{shard}.restore-tmp",
        "operational.db.restore-tmp",
        "recovery-generations/backup-restore-journal.json.restore-tmp",
    ] {
        let at = target
            .path()
            .join(position.replace("{shard}", &planted[0].0));
        std::fs::create_dir_all(at.parent().unwrap()).unwrap();
        std::fs::write(&at, b"residue of an interrupted earlier restore").unwrap();
    }
    restore_data_dir(artifact.path(), target.path(), None)
        .expect("a restore must resume straight over its own residue");
    assert!(
        target.path().join("cas").join(&planted[0].0).is_file(),
        "and the object really lands in the target"
    );
}

/// The ONE write position inside the artifact that kata does not guard, and the
/// measurement of who does.
///
/// # Why this is a separate test and not another arm of the loop above
///
/// `<artifact>/stores/<database>.capture-tmp-journal` is SQLite's rollback
/// journal for the `VACUUM INTO` destination. Nothing in `kata` names it, so
/// `claim_owned_path` — which clears `<database>.capture-tmp` itself — never sees
/// it, and no `create_owned_file` flag reaches it. It is a real write position
/// and it belongs in the enumeration whether or not kata is what makes it safe.
///
/// What makes it safe is the vendored SQLite: `libsqlite3-sys` 0.39.1 bundles
/// SQLite 3.54.1, whose `unixOpen` ORs `O_NOFOLLOW` into `openFlags` for every
/// file it opens (`sqlite3.c:47326`). So a symlink here is refused by SQLite's
/// own open rather than by anything this module did.
///
/// **That guarantee is SQLite's, not kata's**, and the difference matters: a
/// SQLite upgrade that dropped the flag would reopen this position with nothing
/// in this repository to notice. This test is what would notice. Only the
/// dangling-symlink arm is driven — it is the obstruction `O_NOFOLLOW` is the
/// answer to; a FIFO here would test SQLite's blocking behaviour rather than
/// kata's enumeration.
#[cfg(unix)]
#[test]
fn the_sqlite_journal_beside_a_staged_database_is_guarded_by_sqlite_and_not_by_kata() {
    // Cross-process per-uid serialization: this test drives a product
    // immutable-SQLite inspection, whose coordinator is a per-euid singleton with a
    // NONBLOCKING 3s product deadline. Two suites under one uid made it refuse with a
    // storage-integrity message for a scheduling cause. See
    // kata_test_utils::inspection_lock.
    let _inspection_lock = kata_test_utils::inspection_lock::hold();
    use std::os::unix::fs::symlink;

    let source = tempfile::tempdir().unwrap();
    plant_cas_objects(source.path(), 1);
    let artifact = tempfile::tempdir().unwrap();
    let escape = tempfile::tempdir().unwrap();

    let stores = artifact.path().join(STORES_SUBDIR);
    std::fs::create_dir_all(&stores).unwrap();
    let leaked = escape.path().join("leaked-journal");
    symlink(&leaked, stores.join("operational.db.capture-tmp-journal")).unwrap();

    let error = match backup_data_dir(source.path(), artifact.path(), None) {
        Err(error) => error,
        Ok(manifest) => panic!(
            "NON-VACUITY: the capture must actually REACH this position. It produced \
             {manifest:?}, which means SQLite never opened the journal and this test proves \
             nothing about the flag it is here to measure"
        ),
    };
    assert!(
        !leaked.exists(),
        "NOT ONE byte may be written through a symlink at the SQLite journal position; \
         {} exists after {error}. If this reds, the vendored SQLite stopped passing \
         `O_NOFOLLOW` in `unixOpen` — the guarantee at this position is ITS open, not kata's, \
         and kata now needs one of its own",
        leaked.display()
    );
    assert!(
        entry_names(escape.path()).is_empty(),
        "and nothing else may land outside the artifact either: {:?}",
        entry_names(escape.path())
    );
}

/// A symlink at an INTERMEDIATE component of a member's parent path DESTROYS
/// DATA OUTSIDE THE ARTIFACT unless a guard binds that position.
///
/// # The RED, measured at production bounds against a path-based form
///
/// A path-based guard binds the FINAL path component only:
/// `mkdir(2)` does not resolve its last component but DOES resolve every
/// intermediate one, and `O_NOFOLLOW` likewise constrains only the last. A
/// member's parent is what `capture_tree` hands to `create_real_directory`, so
/// for a member at `aa/bb/member` the component `aa` is resolved by every
/// syscall in the sequence and checked by none of them.
///
/// `walk_tree_entries` admits `MAX_TREE_PATH_COMPONENTS` (8) levels, so a
/// depth-3 member under `cas/` is inside production bounds and reaches the
/// capture. With `<artifact>/trees/cas/aa` a symlink out of the artifact, the
/// path-based form: created `<escape>/bb` (a directory OUTSIDE the artifact),
/// opened the pre-existing `<escape>/bb/member.capture-tmp` through the link,
/// `set_len(0)`'d it, wrote the full 300,000 bytes of the member onto it
/// (md5-identical to the source), then failed `verify_member_address` and
/// UNLINKED it. The capture returns `Err` — and the victim is gone.
///
/// That is the same class as an `O_TRUNC` at open ("a refusal that destroyed a
/// file outside the artifact"), one directory level up.
///
/// # Two mechanisms close it, and this test does not say which one fired
///
/// `verify_member_path_shape` refuses a `CasObject` member whose component
/// count is not 2 BEFORE the parent is created, and `ProvenDir`'s `openat(2)`
/// walk refuses the symlink at `aa` when it is opened relative to a proven
/// parent fd. Either alone closes this. They are pinned separately by
/// `a_cas_member_path_shape_the_addressing_rule_cannot_produce_is_refused` and
/// `a_proven_directory_walk_refuses_a_symlink_at_any_level` in
/// `crates/core/src/store/backup.rs`; what this asserts is the property an
/// operator has — nothing outside the artifact is touched.
#[cfg(unix)]
#[test]
fn a_symlink_inside_a_member_path_destroys_nothing_outside_the_artifact() {
    // Cross-process per-uid serialization: this test drives a product
    // immutable-SQLite inspection, whose coordinator is a per-euid singleton with a
    // NONBLOCKING 3s product deadline. Two suites under one uid made it refuse with a
    // storage-integrity message for a scheduling cause. See
    // kata_test_utils::inspection_lock.
    let _inspection_lock = kata_test_utils::inspection_lock::hold();
    use std::os::unix::fs::symlink;

    const VICTIM: &[u8] = b"a file that belongs to somebody else";

    let source = tempfile::tempdir().unwrap();
    plant_cas_objects(source.path(), 1);
    let nested = source.path().join("cas").join("aa").join("bb");
    std::fs::create_dir_all(&nested).unwrap();
    std::fs::write(nested.join("member"), vec![0x5A_u8; 300_000]).unwrap();

    // The escape already holds the victim's directory AND the victim, so the
    // path-based form reaches `EEXIST` -> `require_real_directory` (which lstats
    // through the link and sees a real directory) rather than needing the
    // `create_dir_all` fallback.
    let escape = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(escape.path().join("bb")).unwrap();
    let victim = escape.path().join("bb").join("member.capture-tmp");
    std::fs::write(&victim, VICTIM).unwrap();

    let artifact = tempfile::tempdir().unwrap();
    let tree_root = artifact.path().join(TREES_SUBDIR).join("cas");
    std::fs::create_dir_all(&tree_root).unwrap();
    symlink(escape.path(), tree_root.join("aa")).unwrap();

    let error = match backup_data_dir(source.path(), artifact.path(), None) {
        Err(error) => error,
        Ok(manifest) => panic!(
            "a capture must refuse a member whose parent path runs through a symlink out of the \
             artifact, and produced {manifest:?}"
        ),
    };

    assert_eq!(
        std::fs::read(&victim).ok().as_deref(),
        Some(VICTIM),
        "NOT ONE byte outside the artifact may be truncated, overwritten or unlinked by a capture \
         that refuses; {} (refusal was: {error})",
        if victim.exists() {
            "the victim was rewritten"
        } else {
            "the victim was destroyed"
        }
    );
    assert_eq!(
        entry_names(escape.path()),
        vec!["bb".to_string()],
        "and the capture may not create directories outside the artifact either"
    );
    assert!(
        !artifact.path().join(MANIFEST_NAME).exists(),
        "and a refused capture leaves no claimable artifact"
    );
}

/// A symlink INSIDE the capture SOURCE tree is refused, because skipping it
/// published a manifest claiming a tree the artifact did not hold.
///
/// # The RED, measured against a skipping walk
///
/// A `walk_tree_entries` that skipped every symlink, on the reasoning that a
/// symlink is not an object and a copy cannot reproduce one, That is true of what a symlink
/// IS and wrong about what to do with one at a DIRECTORY position: with
/// `<data_dir>/cas/<shard>` replaced by a link to the real shard directory,
/// `backup_data_dir` returned `Ok` with `tree_roots: ["cas"]` and a
/// `CapturedTree` carrying `entry_count: 0, total_byte_len: 0`, and wrote a
/// manifest.
///
/// That is the "claims what it does not hold" shape the tree capture exists to
/// eliminate, arriving through UNDER-capture instead of through a redirected
/// write — and it is SILENT in the strong sense the omission rule cares about:
/// `manifest_completeness` reads the CLAIM, the claim is present, so the
/// completeness block reports `cas` carried and no operator is ever told the
/// bytes are absent. `discover_captured_trees` refuses the identical input at
/// the tree ROOT, so refusing below it is the same rule rather than a new one,
/// and `TreeCapture`'s discriminator puts it there: a bound overrun is capacity
/// and degrades, a tree that is not the shape the map says it is, is correctness
/// and refuses.
#[cfg(unix)]
#[test]
fn a_symlink_inside_the_source_tree_is_refused_rather_than_silently_under_captured() {
    // Cross-process per-uid serialization: this test drives a product
    // immutable-SQLite inspection, whose coordinator is a per-euid singleton with a
    // NONBLOCKING 3s product deadline. Two suites under one uid made it refuse with a
    // storage-integrity message for a scheduling cause. See
    // kata_test_utils::inspection_lock.
    let _inspection_lock = kata_test_utils::inspection_lock::hold();
    use std::os::unix::fs::symlink;

    for depth in ["shard", "member"] {
        let source = tempfile::tempdir().unwrap();
        let planted = plant_cas_objects(source.path(), 1);
        let member = &planted[0].0;
        let shard = &member[..member.find('/').unwrap()];

        // NON-VACUOUS: the same fixture, unlinked, captures the object.
        let clean = tempfile::tempdir().unwrap();
        let clean_manifest = backup_data_dir(source.path(), clean.path(), None).expect("capture");
        assert_eq!(sole_tree(&clean_manifest).entry_count, 1);

        let escape = tempfile::tempdir().unwrap();
        let real = match depth {
            "shard" => source.path().join("cas").join(shard),
            _ => source.path().join("cas").join(member),
        };
        let moved = escape.path().join("relocated");
        std::fs::rename(&real, &moved).unwrap();
        symlink(&moved, &real).unwrap();

        let artifact = tempfile::tempdir().unwrap();
        let error = match backup_data_dir(source.path(), artifact.path(), None) {
            Err(error) => error,
            Ok(manifest) => panic!(
                "a capture must refuse a symlink at the {depth} level of its source tree rather \
                 than skipping it and claiming the tree anyway; it produced {manifest:?}"
            ),
        };
        let message = error.to_string();
        assert!(
            message.contains("symlink") && message.contains("cas"),
            "the refusal must name the tree and the rule at the {depth} level: {message}"
        );
        assert!(
            !artifact.path().join(MANIFEST_NAME).exists(),
            "and a refused capture must leave no artifact claiming a tree it does not hold"
        );
    }
}

/// The same intermediate-component symlink on the RESTORE side of the mirror.
///
/// # Why the restore side is pinned too
///
/// `verify_member_address` runs BEFORE any target mutation on restore
/// (`verify_captured_tree_sources`) and AFTER `copy_hashing` on capture
/// (`capture_tree`). The path handling is identical on both sides; only that
/// call order keeps a restore from writing through a forged member before the
/// address check refuses it.
///
/// A property that holds by call order is one refactor away from not holding,
/// so it is pinned rather than left to the ordering. The
/// artifact here is FORGED by hand: a healthy capture whose manifest gains a
/// depth-3 entry and whose `trees/cas` gains the matching file, which is what an
/// unauthenticated manifest lets anybody hand an operator.
#[cfg(unix)]
#[test]
fn a_restore_places_nothing_through_a_symlink_inside_a_member_path() {
    // Cross-process per-uid serialization: this test drives a product
    // immutable-SQLite inspection, whose coordinator is a per-euid singleton with a
    // NONBLOCKING 3s product deadline. Two suites under one uid made it refuse with a
    // storage-integrity message for a scheduling cause. See
    // kata_test_utils::inspection_lock.
    let _inspection_lock = kata_test_utils::inspection_lock::hold();
    use std::os::unix::fs::symlink;

    const VICTIM: &[u8] = b"a file that belongs to somebody else";

    let source = tempfile::tempdir().unwrap();
    plant_cas_objects(source.path(), 1);
    let artifact = tempfile::tempdir().unwrap();
    backup_data_dir(source.path(), artifact.path(), None).expect("capture");

    // FORGE: a member three components deep, present in the artifact and named
    // by the manifest, which `CasStore` could never have produced.
    let payload = vec![0x5A_u8; 300_000];
    let forged_dir = artifact.path().join(TREES_SUBDIR).join("cas").join("aa");
    std::fs::create_dir_all(forged_dir.join("bb")).unwrap();
    std::fs::write(forged_dir.join("bb").join("member"), &payload).unwrap();
    let manifest_path = artifact.path().join(MANIFEST_NAME);
    let mut manifest: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&manifest_path).unwrap()).unwrap();
    manifest["trees"][0]["entries"]
        .as_array_mut()
        .unwrap()
        .push(serde_json::json!({
            "path": "aa/bb/member",
            "digest": serde_json::Value::Null,
            "byte_len": payload.len(),
        }));
    std::fs::write(
        &manifest_path,
        serde_json::to_vec_pretty(&manifest).unwrap(),
    )
    .unwrap();

    let escape = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(escape.path().join("bb")).unwrap();
    let victim = escape.path().join("bb").join("member.restore-tmp");
    std::fs::write(&victim, VICTIM).unwrap();

    let target = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(target.path().join("cas")).unwrap();
    symlink(escape.path(), target.path().join("cas").join("aa")).unwrap();

    let error = match restore_data_dir(artifact.path(), target.path(), None) {
        Err(error) => error,
        Ok(manifest) => panic!(
            "a restore must refuse a manifest-supplied member path that runs through a symlink \
             out of the target data directory, and produced {manifest:?}"
        ),
    };
    assert_eq!(
        std::fs::read(&victim).ok().as_deref(),
        Some(VICTIM),
        "NOT ONE byte outside the target data directory may be touched (refusal was: {error})"
    );
    assert_eq!(
        entry_names(escape.path()),
        vec!["bb".to_string()],
        "and no directory may be created outside it either"
    );
}

// ---------------------------------------------------------------------------
// 12. The holes a CALL-SITE derivation finds that a POSITION-indexed one cannot:
//     a second command at a position the table already carries.
// ---------------------------------------------------------------------------

/// blake3 a path, as a path-based digest would.
///
/// Reproduced here rather than described: every "bad state" below is a claim
/// about what a path-based predicate answers, and a described predicate is one
/// a future edit can quietly stop matching.
fn shipped_digest_file(path: &Path) -> String {
    let mut hasher = blake3::Hasher::new();
    let mut file = std::fs::File::open(path).expect("the path form follows whatever is here");
    std::io::copy(&mut file, &mut hasher).unwrap();
    hasher
        .finalize()
        .as_bytes()
        .iter()
        .fold(String::new(), |mut out, byte| {
            use std::fmt::Write as _;
            let _ = write!(out, "{byte:02x}");
            out
        })
}

/// The digest an artifact's record carries for `name`.
fn recorded_digest(manifest: &BackupManifest, name: &str) -> String {
    manifest
        .assets
        .iter()
        .find(|asset| asset.name == name)
        .and_then(|asset| asset.digest.clone())
        .unwrap_or_else(|| panic!("{name} must carry a recorded digest"))
}

/// The artifact's own integrity gate may not be SATISFIED by bytes from outside
/// the artifact.
///
/// # The bad state first
///
/// `preflight_restore_artifact` digested `<artifact>/kata.toml` through
/// `digest_file` — a bare `File::open`, with no `lstat`, no size bound and no
/// `O_NONBLOCK`, and with NOTHING run in front of it: the config digest happens
/// before `validate_bundled_config`. A row keyed by position alone could be true
/// of a DIFFERENT call site at the same position, which is why the derivation is
/// indexed by call site.
///
/// PART 1 is that bad state: with the real config moved out of the artifact and
/// a symlink left in its place, the shipped predicate returns the EXACT digest
/// the manifest records. The gate was satisfiable, by design, from outside the
/// thing it was gating.
///
/// # Why PART 2 exists
///
/// PART 1 alone passes without `O_NOFOLLOW` on `ProvenDir::open_source_file`: a
/// followed link simply reaches the NEXT reader — `validate_bundled_config` ->
/// `read_regular_file_bounded` -> `regular_source_metadata` — whose `lstat`
/// refuses the same path with a BYTE-IDENTICAL `is not a real regular file`.
/// Two independent refusals, one string; asserting on the string discriminated
/// nothing.
///
/// PART 2 makes the two arms say different things. The link is repointed at
/// bytes that are a VALID config for this data directory but do NOT match the
/// recorded digest, so exactly one refusal is reachable down each path:
///
/// * refused AT THE OPEN by `O_NOFOLLOW` -> `is not a real regular file`;
/// * link FOLLOWED and then caught by the digest -> `corrupt or tampered
///   artifact`, which is the wrong diagnosis for a link and, on bytes that DID
///   match, would not have fired at all.
///
/// The assertion requires the first and FORBIDS the second. Measured both ways:
/// with `OFlags::NOFOLLOW` deleted from `open_source_file` this test
/// fails on the digest message, and it passes with the flag restored.
#[cfg(unix)]
#[test]
fn the_artifact_s_integrity_gate_is_not_satisfiable_from_outside_the_artifact() {
    // Cross-process per-uid serialization: this test drives a product
    // immutable-SQLite inspection, whose coordinator is a per-euid singleton with a
    // NONBLOCKING 3s product deadline. Two suites under one uid made it refuse with a
    // storage-integrity message for a scheduling cause. See
    // kata_test_utils::inspection_lock.
    let _inspection_lock = kata_test_utils::inspection_lock::hold();
    use std::os::unix::fs::symlink;

    let dir = tempfile::tempdir().unwrap();
    let data = dir.path().join("data");
    std::fs::create_dir(&data).unwrap();
    create_marked_database(&data.join("operational.db"));
    let config = bundled_config(dir.path(), &data);
    let artifact = tempfile::tempdir().unwrap();
    let manifest = backup_data_dir(&data, artifact.path(), Some(&config)).expect("capture");

    // Honest artifact first, so every refusal below is bought by the fixture and
    // not by anything the capture got wrong.
    preflight_restore_artifact(artifact.path(), &data, None).expect("an honest artifact verifies");

    let escape = tempfile::tempdir().unwrap();
    let outside = escape.path().join("kata.toml");
    let bundled = artifact.path().join(CONFIG_COPY_NAME);
    std::fs::rename(&bundled, &outside).unwrap();
    symlink(&outside, &bundled).unwrap();

    // PART 1 — THE BAD STATE, driven: the shipped predicate reads through the
    // link and returns the recorded digest, so it was SATISFIED by bytes the
    // artifact does not contain.
    assert_eq!(
        shipped_digest_file(&bundled),
        recorded_digest(&manifest, CONFIG_COPY_NAME),
        "the artifact's gate must be satisfiable through the link, or PART 1 is measuring nothing"
    );
    // Preflight refuses this fixture and that refusal is NOT an assertion about
    // `O_NOFOLLOW`: two readers of this path emit the same string, so it holds
    // whether the open binds the final component or not. It is kept because the
    // operator-facing property — this artifact does not verify — is real.
    preflight_restore_artifact(artifact.path(), &data, None)
        .expect_err("the artifact's own gate may not read its bundled config from outside it");

    // PART 2 — the DISCRIMINATING drive. Same link, repointed at config bytes
    // that parse (so `validate_bundled_config` has no objection with
    // `restore_config_to: None`) but carry one more byte than the capture did,
    // so the recorded digest cannot match them.
    let drifted = escape.path().join("drifted-kata.toml");
    let mut drifted_text = std::fs::read_to_string(&outside).unwrap();
    drifted_text.push_str("\n# not the bytes this artifact was captured from\n");
    std::fs::write(&drifted, &drifted_text).unwrap();
    assert!(
        toml::from_str::<toml::Value>(&drifted_text).is_ok(),
        "the drifted bytes must remain a valid config, or the refusal could be bought by parsing"
    );
    std::fs::remove_file(&bundled).unwrap();
    symlink(&drifted, &bundled).unwrap();
    assert_ne!(
        shipped_digest_file(&bundled),
        recorded_digest(&manifest, CONFIG_COPY_NAME),
        "PART 2 requires bytes the digest REJECTS, so that following the link says something \
         different from refusing to follow it"
    );

    let error = preflight_restore_artifact(artifact.path(), &data, None)
        .expect_err("the artifact's own gate may not read its bundled config from outside it");
    assert!(
        error.to_string().contains("is not a real regular file")
            && error.to_string().contains(CONFIG_COPY_NAME),
        "the refusal must name the position that broke the rule: {error}"
    );
    assert!(
        !error.to_string().contains("corrupt or tampered artifact"),
        "the link must be refused AT THE OPEN, not followed and then caught by a digest that a \
         prepared artifact controls: {error}"
    );

    // The bytes outside the artifact were never touched — this is a read gate,
    // and a refusal that mutated somebody else's file would be a worse defect
    // than the one it closes.
    assert!(outside.is_file());
    assert!(drifted.is_file());
}

/// A reader-less FIFO at the bundled config does not HANG `kata restore`.
///
/// # Why this is its own test
///
/// A symlink is refused by `O_NOFOLLOW`; a FIFO is not, and `open(2)` on one
/// with no writer BLOCKS INDEFINITELY. That is worse than the wrong answer: it
/// is the first gate `kata restore` runs, before any lease, so the operator gets
/// a process that never returns and prints nothing. `O_NONBLOCK` at the open —
/// which `ProvenDir::open_source_file` carries and `File::open` cannot — turns
/// it into `ENXIO` and a named refusal.
///
/// The bad state is the hang, so it cannot be asserted directly without hanging
/// the suite. It is measured as a DEADLINE: the call must return within the
/// budget, and the budget is generous enough that only a block can miss it.
#[cfg(unix)]
#[test]
fn a_reader_less_fifo_in_the_artifact_refuses_rather_than_hanging_the_restore() {
    // Cross-process per-uid serialization: this test drives a product
    // immutable-SQLite inspection, whose coordinator is a per-euid singleton with a
    // NONBLOCKING 3s product deadline. Two suites under one uid made it refuse with a
    // storage-integrity message for a scheduling cause. See
    // kata_test_utils::inspection_lock.
    let _inspection_lock = kata_test_utils::inspection_lock::hold();
    let dir = tempfile::tempdir().unwrap();
    let data = dir.path().join("data");
    std::fs::create_dir(&data).unwrap();
    create_marked_database(&data.join("operational.db"));
    let config = bundled_config(dir.path(), &data);
    let artifact = tempfile::tempdir().unwrap();
    backup_data_dir(&data, artifact.path(), Some(&config)).expect("capture");

    let bundled = artifact.path().join(CONFIG_COPY_NAME);
    std::fs::remove_file(&bundled).unwrap();
    nix::unistd::mkfifo(&bundled, nix::sys::stat::Mode::from_bits_truncate(0o600)).unwrap();

    let (sender, receiver) = std::sync::mpsc::channel();
    let artifact_path = artifact.path().to_path_buf();
    let expected = data.clone();
    let probe = std::thread::spawn(move || {
        let outcome = preflight_restore_artifact(&artifact_path, &expected, None);
        let _ = sender.send(outcome.map(|_| ()));
    });
    let outcome = receiver
        .recv_timeout(std::time::Duration::from_secs(20))
        .expect(
            "`kata restore`'s first gate must not block on a reader-less FIFO in the artifact; a \
             timeout here IS the defect, not a slow box",
        );
    probe.join().unwrap();

    let error = outcome.expect_err("a FIFO is not a bundled config");
    assert!(
        error.to_string().contains("is not a real regular file")
            && error.to_string().contains(CONFIG_COPY_NAME),
        "the refusal must name the position: {error}"
    );
}

/// A journal entry plus a SYMLINKED target may not make a restore report success
/// having placed nothing.
///
/// # The bad state first
///
/// `journal_records_activation` was `target.exists()` — which RESOLVES — and
/// then `digest_file(target)`, which resolved it a second time. Both conditions
/// are satisfiable by a link to a file outside the target holding the captured
/// bytes, and both are asserted below on the fixture before the restore runs. On
/// the shipped form the restore then returned `Ok` with the target still holding
/// a LINK.
///
/// The TREE resume probe one level up was hardened to `ProvenDir::open_regular`
/// and carries a row in the module's FILES table; the FILE resume probe had
/// neither, because the position it reads already had rows for its WRITE and its
/// ACTIVATE and a position-indexed table has nowhere to put a third command.
#[cfg(unix)]
#[test]
fn a_journalled_resume_never_accepts_a_symlinked_target_as_already_restored() {
    // Cross-process per-uid serialization: this test drives a product
    // immutable-SQLite inspection, whose coordinator is a per-euid singleton with a
    // NONBLOCKING 3s product deadline. Two suites under one uid made it refuse with a
    // storage-integrity message for a scheduling cause. See
    // kata_test_utils::inspection_lock.
    let _inspection_lock = kata_test_utils::inspection_lock::hold();
    use std::os::unix::fs::symlink;

    let source = tempfile::tempdir().unwrap();
    create_marked_database(&source.path().join("operational.db"));
    let artifact = tempfile::tempdir().unwrap();
    let manifest = backup_data_dir(source.path(), artifact.path(), None).expect("capture");
    let captured = artifact.path().join(STORES_SUBDIR).join("operational.db");

    // A target whose journal says the database is done, and whose entry for it
    // is a LINK to bytes outside the target that digest to the captured value.
    let target = tempfile::tempdir().unwrap();
    let escape = tempfile::tempdir().unwrap();
    let outside = escape.path().join("somebody-elses.db");
    std::fs::copy(&captured, &outside).unwrap();
    symlink(&outside, target.path().join("operational.db")).unwrap();
    std::fs::create_dir_all(target.path().join(RESTORE_JOURNAL_SUBDIR)).unwrap();
    std::fs::write(
        restore_journal_path(target.path()),
        serde_json::to_vec_pretty(&serde_json::json!({
            "artifact_id": manifest.artifact_id.unwrap().to_string(),
            "completed": ["operational.db"],
        }))
        .unwrap(),
    )
    .unwrap();

    // THE BAD STATE, driven: BOTH halves of the shipped predicate hold, so the
    // shipped resume skipped this asset.
    let target_entry = target.path().join("operational.db");
    assert!(
        target_entry.exists(),
        "the shipped `target.exists()` resolves the link and answers true"
    );
    assert_eq!(
        shipped_digest_file(&target_entry),
        recorded_digest(&manifest, "operational.db"),
        "and the shipped `digest_file(target)` reads through it to the captured digest"
    );

    restore_data_dir(artifact.path(), target.path(), None).expect("the resume must complete");

    let landed = std::fs::symlink_metadata(&target_entry).unwrap();
    assert!(
        !landed.file_type().is_symlink(),
        "a restore that reports success must have PLACED the database in the target, and this \
         one left the link it found"
    );
    assert_eq!(
        std::fs::read(&target_entry).unwrap(),
        std::fs::read(&captured).unwrap(),
        "and the bytes at the target must be the captured bytes"
    );
    // The victim outside the target is untouched: the restore replaced the LINK
    // by rename, never wrote through it.
    assert_eq!(
        std::fs::read(&outside).unwrap(),
        std::fs::read(&captured).unwrap()
    );
    assert_eq!(
        entry_names(escape.path()),
        vec!["somebody-elses.db".to_string()],
        "and nothing may be created beside it"
    );
}

/// The restore journal is read through a PROVEN descriptor and under a BOUND.
///
/// # The bad state first
///
/// `load_or_reset_restore_journal` was `std::fs::read(restore_journal_path(..))`
/// — the one read on the restore path using neither `read_regular_file_bounded`
/// nor a proven descriptor. It resolved both components, so a link at the
/// journal subdirectory read from anywhere and `record_activation` would then
/// publish this restore's progress there; and it read to EOF, so a large file at
/// that name was an unstated memory bound.
///
/// Two arms, because they have different right answers. A LINK out of the target
/// is a containment fault and is refused. An OVERSIZED file at the journal name
/// is not a journal this module wrote, so it reads as *no journal* — every asset
/// is re-copied, which is the same tolerance the unparseable case always had and
/// is strictly safer than refusing to restore at all.
#[cfg(unix)]
#[test]
fn the_restore_journal_is_neither_followed_out_of_the_target_nor_read_unbounded() {
    // Cross-process per-uid serialization: this test drives a product
    // immutable-SQLite inspection, whose coordinator is a per-euid singleton with a
    // NONBLOCKING 3s product deadline. Two suites under one uid made it refuse with a
    // storage-integrity message for a scheduling cause. See
    // kata_test_utils::inspection_lock.
    let _inspection_lock = kata_test_utils::inspection_lock::hold();
    use std::os::unix::fs::symlink;

    let source = tempfile::tempdir().unwrap();
    create_marked_database(&source.path().join("operational.db"));
    let artifact = tempfile::tempdir().unwrap();
    let manifest = backup_data_dir(source.path(), artifact.path(), None).expect("capture");

    // ARM 1 — the journal subdirectory is a link out of the target.
    let target = tempfile::tempdir().unwrap();
    let escape = tempfile::tempdir().unwrap();
    symlink(escape.path(), target.path().join(RESTORE_JOURNAL_SUBDIR)).unwrap();
    // THE BAD STATE: the shipped `std::fs::read` resolves straight through it.
    std::fs::write(
        escape.path().join(RESTORE_JOURNAL_NAME),
        serde_json::to_vec_pretty(&serde_json::json!({
            "artifact_id": manifest.artifact_id.unwrap().to_string(),
            "completed": ["operational.db"],
        }))
        .unwrap(),
    )
    .unwrap();
    assert!(
        std::fs::read(restore_journal_path(target.path())).is_ok(),
        "the shipped form reads the planted journal through the link"
    );

    let error = restore_data_dir(artifact.path(), target.path(), None).expect_err(
        "a restore may not read — and would then WRITE — its own progress journal through a link \
         out of the target data directory",
    );
    assert!(
        error.to_string().contains(RESTORE_JOURNAL_SUBDIR),
        "the refusal must name the position: {error}"
    );
    assert_eq!(
        entry_names(escape.path()),
        vec![RESTORE_JOURNAL_NAME.to_string()],
        "and nothing may be written outside the target"
    );

    // ARM 2 — an oversized file at the journal name reads as NO journal, and the
    // restore completes by re-copying rather than by refusing.
    let target = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(target.path().join(RESTORE_JOURNAL_SUBDIR)).unwrap();
    std::fs::write(restore_journal_path(target.path()), vec![b'{'; 1024 * 1024]).unwrap();
    restore_data_dir(artifact.path(), target.path(), None)
        .expect("an unreadable progress file must not make a target unrestorable");
    assert_eq!(
        std::fs::read(target.path().join("operational.db")).unwrap(),
        std::fs::read(artifact.path().join(STORES_SUBDIR).join("operational.db")).unwrap(),
        "and the asset must actually be placed, never skipped on a journal nobody could read"
    );
}

/// A MEMBER that is a symlink to the real object outside the artifact is refused
/// — one level below the shard.
///
/// # Why every other check passes here, by construction
///
/// The linked-to file holds the object's REAL bytes, so the per-member digest
/// matches, the recorded `byte_len` matches, `CapturedTree::entry_digest` over
/// the entry list matches, and `verify_member_address` derives exactly the
/// address the member is recorded at. Nothing in the artifact disagrees with
/// anything else. The ONLY thing that can refuse it is `O_NOFOLLOW` on
/// `ProvenDir::open_source_file`, which is what this drives.
///
/// MEASURED: deleting that one flag fails THREE tests: this one, the strengthened
/// `the_artifact_s_integrity_gate_is_not_satisfiable_from_outside_the_artifact`,
/// and `store::backup::tests::every_proven_dir_openat_carries_o_nofollow`, which
/// names `open_source_file` from the module's own source text. Without the flag
/// the preflight and the restore both succeed with every authoritative CAS byte
/// read from OUTSIDE the artifact — the same class as the shard-level hole, one
/// level down.
#[cfg(unix)]
#[test]
fn a_member_that_is_a_link_to_the_real_object_outside_the_artifact_is_refused() {
    // Cross-process per-uid serialization: this test drives a product
    // immutable-SQLite inspection, whose coordinator is a per-euid singleton with a
    // NONBLOCKING 3s product deadline. Two suites under one uid made it refuse with a
    // storage-integrity message for a scheduling cause. See
    // kata_test_utils::inspection_lock.
    let _inspection_lock = kata_test_utils::inspection_lock::hold();
    use std::os::unix::fs::symlink;

    let source = tempfile::tempdir().unwrap();
    let planted = plant_cas_objects(source.path(), 1);
    let artifact = tempfile::tempdir().unwrap();
    let manifest = backup_data_dir(source.path(), artifact.path(), None).expect("capture");
    let tree = sole_tree(&manifest);
    let entry = tree.entries.first().expect("one member").clone();

    // Honest artifact first.
    preflight_restore_artifact(artifact.path(), source.path(), None).expect("an honest artifact");

    let member = artifact
        .path()
        .join(TREES_SUBDIR)
        .join("cas")
        .join(&entry.path);
    let escape = tempfile::tempdir().unwrap();
    let outside = escape.path().join("the-real-object");
    std::fs::rename(&member, &outside).unwrap();
    symlink(&outside, &member).unwrap();

    // THE BAD STATE, driven — every check other than the link refusal is
    // satisfied by this fixture.
    assert_eq!(
        Some(shipped_digest_file(&member)),
        entry.digest,
        "the linked-to bytes must satisfy the per-member digest"
    );
    assert_eq!(
        std::fs::metadata(&member).unwrap().len(),
        entry.byte_len,
        "and the recorded length"
    );
    assert_eq!(
        std::fs::read(&outside).unwrap(),
        planted[0].1,
        "and they are the object's real payload, so the content ADDRESS check agrees too"
    );

    let error = preflight_restore_artifact(artifact.path(), source.path(), None).expect_err(
        "a member reached through a link out of the artifact is not a member OF the artifact",
    );
    assert!(
        error.to_string().contains("is not a real regular file")
            && error.to_string().contains(&entry.path),
        "the refusal must name the member: {error}"
    );

    let target = tempfile::tempdir().unwrap();
    restore_data_dir(artifact.path(), target.path(), None)
        .expect_err("and the full restore must refuse it too");
    assert!(
        !target.path().join("cas").join(&entry.path).exists(),
        "nothing may be placed at the target"
    );
}
