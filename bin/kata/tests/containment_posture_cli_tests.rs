//! The operator-facing half: `kata doctor` and
//! `kata execution-provider` must tell the truth about containment, and must be
//! CAPABLE of saying something other than "fine".
//!
//! Under the one engine the truth is the rootless-OCI route's prerequisites —
//! the pinned runtime's bytes, userns + its AppArmor profile, the runtime's
//! seccomp witness, cgroup delegation — read through the certification's own
//! folds (`kata_worker::sandbox_posture`).
//!
//! # Why these drive the real binary
//!
//! Every fact under test is a property of a PROCESS's environment, and this
//! workspace denies `unsafe_code`, so `std::env::set_var` is unavailable. A
//! subprocess measures the thing an operator would actually hit, through the full
//! clap → render → exit-code path.
//!
//! # Host-independent by construction
//!
//! These cells assert the report's SHAPE and its rules, never a host's verdict:
//! whether the host delegates a cgroup or has the pinned youki is not a fact a
//! suite that must pass on any box can assert. The verdicts' folds are pinned
//! host-free in `kata_worker::sandbox_posture`'s unit tests.

use std::path::Path;
use std::process::{Command, Output};

fn kata() -> Command {
    Command::new(env!("CARGO_BIN_EXE_kata"))
}

/// A fresh initialized project directory, so `doctor` has a config to read.
fn init_project() -> tempfile::TempDir {
    let dir = tempfile::tempdir().expect("tempdir");
    let init = kata()
        .args(["init"])
        .current_dir(dir.path())
        .output()
        .expect("spawn kata init");
    assert!(
        init.status.success(),
        "kata init must succeed; stderr: {}",
        String::from_utf8_lossy(&init.stderr)
    );
    dir
}

fn doctor_json(dir: &Path, envs: &[(&str, &str)]) -> (Output, serde_json::Value) {
    let mut cmd = kata();
    cmd.args(["doctor", "--format", "json"]).current_dir(dir);
    // The `test-support` door: the `kata_login` row reads a directory under
    // the project that holds no login, never the effective owner's own.
    cmd.env("KATA_TEST_KATA_LOGINS_DIR", dir.join("no-kata-logins"));
    for (key, value) in envs {
        cmd.env(key, value);
    }
    let out = cmd.output().expect("spawn kata doctor");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let report: serde_json::Value = serde_json::from_str(&stdout).unwrap_or_else(|e| {
        panic!(
            "kata doctor --format json must emit JSON on stdout ({e}); stdout:\n{stdout}\nstderr:\n{}",
            String::from_utf8_lossy(&out.stderr)
        )
    });
    (out, report)
}

/// The `status` of one doctor check by name.
fn check_status(report: &serde_json::Value, name: &str) -> String {
    report["checks"]
        .as_array()
        .expect("checks array")
        .iter()
        .find(|c| c["name"] == name)
        .unwrap_or_else(|| panic!("no doctor check named {name:?} in {report}"))["status"]
        .as_str()
        .expect("status string")
        .to_string()
}

fn provider(args: &[&str], envs: &[(&str, &str)]) -> Output {
    let mut cmd = kata();
    cmd.args(args);
    for (key, value) in envs {
        cmd.env(key, value);
    }
    cmd.output().expect("spawn kata execution-provider")
}

// ---------------------------------------------------------------------------
// `kata doctor`
// ---------------------------------------------------------------------------

/// Doctor reports exactly the rootless-OCI route's containment controls, and
/// none of the deleted bwrap/Landlock/toolchain rows survives as a stale row.
#[test]
fn doctor_reports_every_containment_control() {
    let dir = init_project();
    let (out, report) = doctor_json(dir.path(), &[]);
    assert!(
        out.status.success(),
        "a fresh init must not FAIL on containment (a host lacking a prerequisite warns); \
         stdout:\n{}",
        String::from_utf8_lossy(&out.stdout)
    );

    for control in [
        "containment_runtime",
        "containment_userns",
        "containment_syscall_fence",
        "containment_cgroup_delegation",
        "containment_env_levers",
    ] {
        let status = check_status(&report, control);
        assert!(
            ["pass", "warn"].contains(&status.as_str()),
            "{control} reported {status:?}; only a declared requirement this node cannot \
             honour may fail"
        );
    }
    let names: Vec<&str> = report["checks"]
        .as_array()
        .expect("checks")
        .iter()
        .filter_map(|c| c["name"].as_str())
        .collect();
    for retired in [
        "containment_provider",
        "containment_read_closure_fence",
        "containment_resource_bounds",
        "rootless_oci_prerequisite",
        "sandbox_node_default_rootfs",
    ] {
        assert!(
            !names.contains(&retired),
            "{retired} is a row for a deleted mechanism (or a second spelling of a posture fact) \
             and must not be reported: {names:?}"
        );
    }
}

/// Every lever is NAMED in the report whether or not it is set, and the set is
/// the enum's: an operator whose containment is reshaped by an inherited
/// environment variable cannot find that out from a report listing only what
/// happens to be on.
#[test]
fn doctor_names_every_containment_lever_even_when_none_is_set() {
    let dir = init_project();
    let (_, report) = doctor_json(dir.path(), &[]);
    let levers = report["checks"]
        .as_array()
        .expect("checks")
        .iter()
        .find(|c| c["name"] == "containment_env_levers")
        .expect("containment_env_levers check")["details"]
        .clone();
    // The rows are DERIVED from `ContainmentLever`; this process's own posture is
    // the enum's list, independent of what the doctor child rendered.
    let expected: Vec<&str> = kata_worker::sandbox_posture::observe()
        .kill_switches
        .iter()
        .map(|row| row.env)
        .collect();
    assert!(
        expected.len() >= 3,
        "NON-VACUITY: the lever list must not be empty or truncated: {expected:?}"
    );
    for env in expected {
        assert!(
            levers.get(env).is_some(),
            "{env} reshapes containment and must be reported even when unset; got {levers}"
        );
    }
}

/// The levers row is SCORED by the capsule route's own resolver of the provider
/// declaration: half a declaration — a provider name with no content address —
/// is a declaration admission refuses, so the real binary's row WARNS and carries
/// that refusal rather than passing as a mere report.
///
/// **Would red if:** doctor stopped asking
/// `kata_worker::capsule_route::declared_oci_provider` (the row reverts to an
/// unconditional `pass`).
#[test]
fn doctor_warns_a_provider_declaration_the_capsule_route_refuses() {
    let dir = init_project();
    let (out, report) = doctor_json(
        dir.path(),
        &[
            ("KATA_EXTERNAL_EXECUTION_PROVIDER", "youki"),
            ("KATA_EXTERNAL_EXECUTION_PROVIDER_ADDRESS", ""),
            ("KATA_EXTERNAL_PROVIDER_STORE", ""),
        ],
    );
    assert_eq!(check_status(&report, "containment_env_levers"), "warn");
    let refusal = report["checks"]
        .as_array()
        .expect("checks")
        .iter()
        .find(|c| c["name"] == "containment_env_levers")
        .expect("containment_env_levers check")["details"]["refusal"]
        .as_str()
        .expect("the warning carries admission's refusal")
        .to_string();
    assert!(
        refusal.contains("KATA_EXTERNAL_EXECUTION_PROVIDER_ADDRESS"),
        "the refusal names the missing half: {refusal}"
    );
    assert!(
        out.status.success(),
        "a refused declaration warns, never fails: {}",
        String::from_utf8_lossy(&out.stdout)
    );
}

/// The levers row RESOLVES the declaration, as admission does: a whole,
/// well-formed declaration (name, content address, store root) whose store holds
/// no entry at that address is still a provider a capsule worker cannot run, so
/// the row WARNS and carries the store's own refusal, naming the entry it looked
/// for under THIS store root.
///
/// **Would red if:** `declared_oci_provider` stopped re-hashing the declared entry
/// against its address (`installation.resolve()` dropped — the row would pass a
/// declaration whose bytes do not exist).
#[test]
fn doctor_warns_a_whole_declaration_whose_store_entry_does_not_resolve() {
    let dir = init_project();
    let store = tempfile::tempdir().expect("an empty provider store");
    let hex = "0".repeat(64);
    let address = format!("store:{hex}");
    let (out, report) = doctor_json(
        dir.path(),
        &[
            ("KATA_EXTERNAL_EXECUTION_PROVIDER", "youki"),
            ("KATA_EXTERNAL_EXECUTION_PROVIDER_ADDRESS", address.as_str()),
            (
                "KATA_EXTERNAL_PROVIDER_STORE",
                store.path().to_str().expect("a utf-8 store root"),
            ),
        ],
    );
    assert_eq!(check_status(&report, "containment_env_levers"), "warn");
    let refusal = report["checks"]
        .as_array()
        .expect("checks")
        .iter()
        .find(|c| c["name"] == "containment_env_levers")
        .expect("containment_env_levers check")["details"]["refusal"]
        .as_str()
        .expect("the warning carries the store's refusal")
        .to_string();
    assert!(
        refusal.contains("could not be read") && refusal.contains(&hex),
        "the store's resolve refusal, naming the entry it looked for: {refusal}"
    );
    assert!(
        refusal.contains(&store.path().display().to_string()),
        "resolved against THIS store root: {refusal}"
    );
    assert!(
        out.status.success(),
        "a refused declaration warns, never fails: {}",
        String::from_utf8_lossy(&out.stdout)
    );
}

/// The levers row's `detail` is a command an operator can
/// RUN: it is executed here, as the `kata` binary, and must succeed. Before the
/// rename it named `kata execution-provider inspect bwrap`, a provider spelling
/// the binary refuses.
#[test]
fn doctor_levers_detail_names_a_command_that_runs() {
    let dir = init_project();
    let (_, report) = doctor_json(dir.path(), &[]);
    let detail = report["checks"]
        .as_array()
        .expect("checks")
        .iter()
        .find(|c| c["name"] == "containment_env_levers")
        .expect("containment_env_levers check")["details"]["detail"]
        .as_str()
        .expect("the levers row carries a detail command")
        .to_string();
    let argv: Vec<&str> = detail.split_whitespace().collect();
    assert_eq!(
        argv.first(),
        Some(&"kata"),
        "the detail must be a kata command: {detail}"
    );
    let out = provider(&argv[1..], &[]);
    assert!(
        out.status.success(),
        "`{detail}` must run; stderr:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

/// `KATA_DISABLE_SECCOMP` has NO reader under the one engine: no defeat lever
/// has a reader, and a refusal of an unenforced defeat would refuse more than
/// any mechanism enforces. Every capsule's seccomp fence is
/// rendered unconditionally, so setting the variable moves no row, no starter's
/// compile, and not the exit code.
///
/// **Would red if:** a reader of the variable came back — a compile refusal
/// naming it (every `workflow_check` fails and doctor exits non-zero), a
/// lever row naming it, or a fence row it moves.
#[test]
fn kata_disable_seccomp_has_no_reader() {
    let dir = init_project();
    let (clean_out, clean) = doctor_json(dir.path(), &[]);
    let (set_out, set) = doctor_json(dir.path(), &[("KATA_DISABLE_SECCOMP", "1")]);
    let statuses = |report: &serde_json::Value| -> Vec<(String, String)> {
        report["checks"]
            .as_array()
            .expect("checks array")
            .iter()
            .map(|c| {
                (
                    c["name"].as_str().unwrap_or_default().to_string(),
                    c["status"].as_str().unwrap_or_default().to_string(),
                )
            })
            .collect()
    };
    let clean_rows = statuses(&clean);
    assert!(
        clean_rows.iter().any(|(name, _)| name == "workflow_check"),
        "NON-VACUITY: the comparison must cover the starters' compile: {clean_rows:?}"
    );
    assert_eq!(
        statuses(&set),
        clean_rows,
        "setting KATA_DISABLE_SECCOMP moved a doctor row; nothing may read it"
    );
    assert_eq!(
        set_out.status.code(),
        clean_out.status.code(),
        "setting KATA_DISABLE_SECCOMP moved doctor's exit code. stdout:\n{}",
        String::from_utf8_lossy(&set_out.stdout)
    );
    let levers = set["checks"]
        .as_array()
        .expect("checks array")
        .iter()
        .find(|c| c["name"] == "containment_env_levers")
        .expect("containment_env_levers check")["details"]
        .clone();
    assert!(
        levers.get("KATA_DISABLE_SECCOMP").is_none(),
        "KATA_DISABLE_SECCOMP is not a containment lever: {levers}"
    );
}

// ---------------------------------------------------------------------------
// `kata execution-provider`
// ---------------------------------------------------------------------------

/// The command exists at all, and lists the closed world of backends with the
/// BUILD-axis posture of each.
#[test]
fn execution_provider_list_names_every_backend_this_build_knows() {
    let out = provider(&["execution-provider", "list"], &[]);
    assert!(
        out.status.success(),
        "list must succeed offline; stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    for (exec, posture) in [("host", "unconfined"), ("oci", "certified_containment")] {
        assert!(
            stdout.contains(exec) && stdout.contains(posture),
            "list must name {exec} as {posture}:\n{stdout}"
        );
    }
}

/// The listing's closed world is DERIVED from `ExecBackend`,
/// so a variant cannot go missing from it.
///
/// # The defect this closes, and why the test above could not
///
/// A hand-typed `const` array of backends is not a COMPILE ERROR when a
/// variant is added: its consumers are `.iter()` calls over the array, and the
/// only exhaustive match nearby is on `ExecProviderPosture`, a different enum.
/// A new variant would compile and be ABSENT from the surface whose purpose is
/// making the trust model inspectable.
///
/// The sibling above hand-types the same three names, so it would stay green
/// in that case too. This one derives BOTH sides — the expectation from
/// `ExecBackend::all()`, the observation from the command's own JSON — so the
/// day a variant is added and the CLI misses it, this is RED with the missing
/// spelling in the message.
#[test]
fn execution_provider_list_is_derived_from_the_exec_backend_world() {
    use std::collections::BTreeSet;

    let world: BTreeSet<String> = kata_types::sandbox::ExecBackend::all()
        .map(|b| b.authored_spelling().to_string())
        .collect();
    assert!(
        world.len() >= 2,
        "NON-VACUITY: the derived world must not be empty or truncated; got {world:?}"
    );

    let out = provider(&["execution-provider", "list", "--format", "json"], &[]);
    assert!(
        out.status.success(),
        "list --format json must succeed offline; stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    let value: serde_json::Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("list --format json must emit JSON ({e}):\n{stdout}"));
    let rows = value
        .pointer("/providers")
        .and_then(serde_json::Value::as_array)
        .unwrap_or_else(|| panic!("no /providers array in:\n{value:#}"));
    let listed: BTreeSet<String> = rows
        .iter()
        .map(|r| {
            r["exec"]
                .as_str()
                .unwrap_or_else(|| panic!("provider row has no `exec` string: {r}"))
                .to_string()
        })
        .collect();

    assert_eq!(
        listed, world,
        "`execution-provider list` must name EVERY `ExecBackend` variant. A backend \
         missing here is one an operator cannot inspect or certify while the parser \
         still accepts its spelling — the exact silent gap a hand-typed backend \
         array leaves open."
    );
}

/// `inspect` exposes the rootless-OCI facts the trust model rests on — the
/// pinned runtime's path and digest, the userns and AppArmor state — and the
/// build's known limits with how each is known.
#[test]
fn execution_provider_inspect_exposes_the_runtime_posture() {
    let out = provider(&["execution-provider", "inspect", "oci"], &[]);
    assert!(out.status.success(), "inspect must not judge, only report");
    let stdout = String::from_utf8_lossy(&out.stdout);
    for token in [
        "containment_runtime",
        "pinned_path",
        "pinned_sha256",
        "containment_userns",
        "apparmor_restrict_unprivileged_userns",
        "containment_syscall_fence",
        "containment_cgroup_delegation",
        "KNOWN CONTAINMENT LIMITS",
        "basis:",
    ] {
        assert!(
            stdout.contains(token),
            "inspect must expose {token}; a certification nobody can read is a certification \
             on trust:\n{stdout}"
        );
    }
}

/// `--format json` must be honoured, not accepted-and-dropped — exit 0 plus
/// prose leaves a caller scripting `--format json` with garbage and nothing to
/// branch on.
#[test]
fn execution_provider_honours_format_json() {
    for args in [
        vec!["execution-provider", "list", "--format", "json"],
        vec!["execution-provider", "inspect", "oci", "--format", "json"],
        vec!["execution-provider", "certify", "oci", "--format", "json"],
    ] {
        let out = provider(&args, &[]);
        let stdout = String::from_utf8_lossy(&out.stdout);
        let value: serde_json::Value = serde_json::from_str(&stdout)
            .unwrap_or_else(|e| panic!("{args:?} must emit JSON ({e}); stdout:\n{stdout}"));
        assert!(
            value.get("op").is_none(),
            "{args:?} answers no operation, so it emits its report bare: {value}"
        );
        assert!(
            value["summary_kind"].is_string(),
            "{args:?} payload must carry its summary_kind: {value}"
        );
    }
}

/// `inspect` and `certify` refuse a provider outside the closed world as unknown,
/// naming it and the world `host, oci` — `bwrap` and `firecracker` included, never
/// aliased onto `oci`.
#[test]
fn inspect_and_certify_refuse_an_unknown_provider_naming_the_closed_world() {
    // --- Non-vacuity: certify is capable of succeeding, so the refusals below
    // are about the spelling rather than about certify being broken.
    let host = provider(&["execution-provider", "certify", "host"], &[]);
    assert!(
        host.status.success(),
        "`host` is an explicitly unconfined but SUPPORTED posture and must certify; \
         stderr: {}",
        String::from_utf8_lossy(&host.stderr)
    );

    for verb in ["inspect", "certify"] {
        for spelling in ["bwrap", "firecracker"] {
            let out = provider(&["execution-provider", verb, spelling], &[]);
            let stderr = String::from_utf8_lossy(&out.stderr);
            assert!(
                !out.status.success(),
                "`{verb} {spelling}` must be refused, not aliased onto `oci`; stdout:\n{}",
                String::from_utf8_lossy(&out.stdout)
            );
            assert!(
                stderr.contains(&format!("unknown execution provider \"{spelling}\""))
                    && stderr.contains("this build knows: host, oci"),
                "`{verb} {spelling}` must be refused as unknown, naming the closed world:\n{stderr}"
            );
        }
    }
}

/// `certify` carries the ONE certification's verdict — the same
/// `certified_oci_route` the worker admits on — and its exit code, `certified`
/// flag and refusal text all say the same thing. Host-independent: this asserts
/// agreement, never which verdict this host produces.
#[test]
fn certify_carries_the_one_certifications_verdict() {
    let out = provider(
        &["execution-provider", "certify", "oci", "--format", "json"],
        &[],
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    let value: serde_json::Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("certify --format json must emit JSON ({e}):\n{stdout}"));
    let data = &value;
    let verdict = data["certification"]["verdict"]
        .as_str()
        .unwrap_or_else(|| panic!("certify must carry the certification's verdict: {data}"));
    let certified = data["certified"].as_bool().expect("certified flag");
    assert_eq!(
        certified,
        verdict == "certified",
        "the flag and the verdict disagree: {data}"
    );
    assert_eq!(
        out.status.success(),
        certified,
        "the exit code must carry the verdict: {data}"
    );
    if !certified {
        let refusal = data["certification"]["refusal"]
            .as_str()
            .expect("a refused certification carries its sentence");
        assert!(
            data["refusal"]
                .as_str()
                .is_some_and(|text| text.contains(refusal) && text.contains(verdict)),
            "certify's refusal must QUOTE the certification's token and sentence, never a \
             second wording: {data}"
        );
    }
}
