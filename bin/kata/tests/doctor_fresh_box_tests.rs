//! Regression: `kata init` emits a runnable starter pack + preflight so
//! `kata doctor` is GREEN on a freshly initialized directory — even on a fresh
//! box where the bundled factory stdlib (`share/kata/{workflows,kata-factory}`)
//! is NOT installed next to the binary.
//!
//! These drive the real `kata` binary (`CARGO_BIN_EXE_kata`) end-to-end so the
//! assertions cover the full init → doctor exit-code path, not just an internal
//! helper. The fresh-box condition is reproduced by pointing `KATA_STDLIB_DIR`
//! at an empty directory: the bundled roots then resolve to a nonexistent path
//! (mirroring an install missing its bundled packs), so the factory starters'
//! `load("kata/factory.star", ...)` cannot resolve.
//!
//! The `kata_login` row of each doctor run reads a logins directory the cell
//! planted (`KATA_TEST_KATA_LOGINS_DIR`, a `test-support` door), never the
//! effective owner's own logins; on a fresh box it holds no login, so the row
//! warns naming `kata login openai`.
//!
//! The defect these refuse: `kata doctor` on a fresh init under an empty
//! `KATA_STDLIB_DIR` printing `[fail] workflow_check` rows for the factory
//! starters and exiting 1 (`kata doctor found 2 failed check(s)`). `kata init`
//! emits a self-contained `std.hello` starter that needs no bundled stdlib and
//! the bundled-stdlib factory starters score `[warn]`, so a fresh init is green.

use std::path::Path;
use std::process::{Command, Output};

fn kata() -> Command {
    Command::new(env!("CARGO_BIN_EXE_kata"))
}

/// Run `kata` with `cwd` as the working directory and an empty
/// `KATA_STDLIB_DIR` so the bundled workflow packs are unresolvable — the
/// fresh-box condition.
fn run_fresh_box(cwd: &Path, empty_stdlib: &Path, args: &[&str]) -> Output {
    kata()
        .args(args)
        .current_dir(cwd)
        .env("KATA_STDLIB_DIR", empty_stdlib.join("workflows"))
        .env(LOGINS_DIR_ENV, no_kata_logins(cwd))
        .output()
        .expect("spawn kata binary under test")
}

/// The test-support door (`kata_worker::owner_home::kata_logins_dir`) a
/// `test-support` build of `kata` takes kata's logins directory from, so its
/// `kata_login` row reads a directory this cell planted, never the effective
/// owner's own logins.
const LOGINS_DIR_ENV: &str = "KATA_TEST_KATA_LOGINS_DIR";

/// A logins directory under `cwd` that nothing creates: no kata login.
fn no_kata_logins(cwd: &Path) -> std::path::PathBuf {
    cwd.join("no-kata-logins")
}

#[test]
fn init_then_doctor_is_green_on_fresh_box_without_bundled_stdlib() {
    let dir = tempfile::tempdir().unwrap();
    let empty_stdlib = tempfile::tempdir().unwrap();

    let init = run_fresh_box(dir.path(), empty_stdlib.path(), &["init"]);
    assert!(
        init.status.success(),
        "kata init should succeed; stderr: {}",
        String::from_utf8_lossy(&init.stderr)
    );

    // The self-contained hello starter is always emitted.
    assert!(
        dir.path().join(".kata/workflows/std.hello.star").is_file(),
        "init must emit the self-contained hello starter"
    );

    let doctor = run_fresh_box(dir.path(), empty_stdlib.path(), &["doctor"]);
    let stdout = String::from_utf8_lossy(&doctor.stdout);
    assert!(
        doctor.status.success(),
        "kata doctor must be GREEN on a fresh init even without the bundled \
         stdlib; exit={:?}\nstdout:\n{stdout}\nstderr:\n{}",
        doctor.status.code(),
        String::from_utf8_lossy(&doctor.stderr)
    );

    // The hello starter is the always-green preflight: it must PASS.
    assert!(
        stdout.contains("[pass] hello_starter_file"),
        "hello starter file check must pass:\n{stdout}"
    );
    // The default agent is the embedded harness on kata's own ChatGPT login,
    // which a fresh box does not hold yet: the `kata_login` row WARNs naming
    // the command, and the report stays green.
    assert!(
        stdout.contains("[warn] kata_login")
            && stdout.contains("openai-chatgpt.json: absent; run `kata login openai`"),
        "the kata_login row warns naming `kata login openai`:\n{stdout}"
    );
    let json = run_fresh_box(
        dir.path(),
        empty_stdlib.path(),
        &["doctor", "--format", "json"],
    );
    let report: serde_json::Value = serde_json::from_slice(&json.stdout)
        .unwrap_or_else(|error| panic!("doctor --format json emits one report: {error}"));
    let row = report["checks"]
        .as_array()
        .and_then(|checks| checks.iter().find(|check| check["name"] == "kata_login"))
        .unwrap_or_else(|| panic!("a kata_login row: {report}"));
    assert_eq!(
        row["details"]["logins_dir"].as_str(),
        no_kata_logins(dir.path()).to_str(),
        "the row read the planted directory, never the owner's: {row}"
    );
    assert!(
        stdout.contains("workflow std.hello compiles to checked execution IR"),
        "hello workflow must compile-check green on a fresh box:\n{stdout}"
    );
    // The bundled-stdlib factory starters degrade to advisory warnings — never
    // hard failures — when the bundled packs are absent.
    assert!(
        stdout.contains("[warn]") && stdout.contains("optional bundled-stdlib starter"),
        "factory starters must warn (not fail) when the bundled stdlib is \
         absent:\n{stdout}"
    );
    assert!(
        !stdout.contains("[fail]"),
        "a fresh init must produce no [fail] rows:\n{stdout}"
    );
}

#[test]
fn init_then_doctor_is_green_with_bundled_stdlib() {
    // With the bundled stdlib resolvable (dev: the workflow crate's
    // compile-time manifest fallback), the factory starters compile too, so the
    // fresh init is green with the factory checks passing rather than warning.
    let dir = tempfile::tempdir().unwrap();

    let init = kata()
        .args(["init"])
        .current_dir(dir.path())
        .env_remove("KATA_STDLIB_DIR")
        .output()
        .expect("spawn kata init");
    assert!(init.status.success());

    let doctor = kata()
        .args(["doctor"])
        .current_dir(dir.path())
        .env_remove("KATA_STDLIB_DIR")
        .env(LOGINS_DIR_ENV, no_kata_logins(dir.path()))
        .output()
        .expect("spawn kata doctor");
    let stdout = String::from_utf8_lossy(&doctor.stdout);
    assert!(
        doctor.status.success(),
        "kata doctor must be green with the bundled stdlib present:\n{stdout}\n{}",
        String::from_utf8_lossy(&doctor.stderr)
    );
    assert!(
        stdout.contains("workflow std.software_factory.kata_self_improve compiles"),
        "factory starter must compile-check green when the bundled stdlib is \
         present:\n{stdout}"
    );
}

#[test]
fn doctor_fails_on_broken_factory_pack_when_bundled_stdlib_present() {
    // Green-washing guard for the dynamic requirement: when the bundled factory
    // stdlib IS resolvable (dev: the workflow crate's compile-time manifest
    // fallback), a present-but-BROKEN factory starter pack is a real fault and
    // must hard-`[fail]` / exit non-zero — it must NOT be downgraded to an
    // advisory `[warn]`. Only a genuinely absent bundled stdlib (the fresh-box
    // case, covered above) may warn.
    let dir = tempfile::tempdir().unwrap();

    let init = kata()
        .args(["init"])
        .current_dir(dir.path())
        .env_remove("KATA_STDLIB_DIR")
        .output()
        .expect("spawn kata init");
    assert!(init.status.success());

    // Corrupt the emitted factory pack to invalid Starlark.
    let pack = dir
        .path()
        .join(".kata/workflows/std.software_factory.kata_self_improve.star");
    assert!(pack.is_file(), "init must emit the factory starter pack");
    std::fs::write(&pack, "this is not valid starlark ((((\n").unwrap();

    let doctor = kata()
        .args(["doctor"])
        .current_dir(dir.path())
        .env_remove("KATA_STDLIB_DIR")
        .env(LOGINS_DIR_ENV, no_kata_logins(dir.path()))
        .output()
        .expect("spawn kata doctor");
    let stdout = String::from_utf8_lossy(&doctor.stdout);
    assert!(
        !doctor.status.success(),
        "a present-but-broken factory pack must hard-fail when the bundled \
         stdlib is present (no green-washing to [warn]):\n{stdout}\n{}",
        String::from_utf8_lossy(&doctor.stderr)
    );
    assert!(
        stdout.contains("[fail]") && stdout.contains("std.software_factory.kata_self_improve"),
        "doctor must report a [fail] for the broken factory pack:\n{stdout}"
    );
}

#[test]
fn doctor_on_uninitialized_dir_fails_honestly() {
    // Greenwashing guard: an EMPTY (un-initialized) directory has no config, so
    // doctor must report the failure honestly and exit non-zero.
    let dir = tempfile::tempdir().unwrap();
    let empty_stdlib = tempfile::tempdir().unwrap();

    let doctor = run_fresh_box(dir.path(), empty_stdlib.path(), &["doctor"]);
    assert!(
        !doctor.status.success(),
        "doctor on an un-initialized dir must fail (no greenwashing); \
         stdout:\n{}",
        String::from_utf8_lossy(&doctor.stdout)
    );
    let stdout = String::from_utf8_lossy(&doctor.stdout);
    assert!(
        stdout.contains("[fail] config_file"),
        "doctor must honestly report the missing config:\n{stdout}"
    );
}
