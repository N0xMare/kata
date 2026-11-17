//! Seccomp syscall-filter tests.
//!
//! Two layers:
//!
//! 1. **Host-independent semantic decode** — a reference cBPF interpreter
//!    ([`kata_types::sandbox_seccomp::simulate`]) runs the compiled
//!    DENY-list program for chosen `(arch, nr, args)` inputs and asserts the
//!    exact `SECCOMP_RET_*` action. This PROVES every dangerous call resolves
//!    to its entry's errno, the default resolves to ALLOW, and the
//!    arch / x32-bypass guards `KILL`. No kernel needed.
//!
//! 2. **Capability-gated live enforcement of the kata seccomp floor** —
//!    kata installs the floor on a child it spawns (`attach_kata_floor`), and
//!    the child's own `/proc/self/status` proves the kernel took it.

#![cfg(target_os = "linux")]

use std::process::Stdio;

use kata_agent::CommandPrefix;
use kata_test_utils::capability::{REQUIRE_LIVE_ENV, require_live};
use kata_types::sandbox_seccomp::{
    DENIED_SYSCALLS, DenyWhen, actions, deny_list_program, simulate, simulate_call,
};

/// The default action is ALLOW: a benign syscall (`read` = 0 on x86_64)
/// passes. A DENY-list must not accidentally become an allow-list.
#[test]
fn default_action_is_allow() {
    let prog = deny_list_program();
    // read(0), write(1), close(3), execve(59) — all must ALLOW.
    for benign in [0u32, 1, 3, 59] {
        assert_eq!(
            simulate(&prog, actions::ARCH_X86_64, benign),
            actions::ALLOW,
            "benign syscall {benign} must be ALLOWed"
        );
    }
}

/// Every call the DENY-list denies resolves to the errno its entry declares,
/// and an entry denied only on some flags ALLOWs a call without them. This is
/// the precise "a denied syscall is blocked" proof at the program level: each
/// of mount / ptrace / kexec / module-load / … maps to its errno leaf, not
/// ALLOW.
#[test]
fn every_denied_call_returns_its_entrys_errno() {
    let prog = deny_list_program();
    for entry in DENIED_SYSCALLS {
        let mut denied = [0_u64; 6];
        if let DenyWhen::FlagsSet { arg, flags } = entry.when {
            denied[usize::from(arg)] = u64::from(flags);
            assert_eq!(
                simulate_call(&prog, actions::ARCH_X86_64, entry.nr, [0; 6]),
                actions::ALLOW,
                "{name} (nr {nr}) without its flags must be ALLOWed",
                name = entry.name,
                nr = entry.nr,
            );
        }
        assert_eq!(
            simulate_call(&prog, actions::ARCH_X86_64, entry.nr, denied),
            actions::errno(entry.errno),
            "denied syscall {name} (nr {nr}) must return errno {errno}, not be allowed",
            name = entry.name,
            nr = entry.nr,
            errno = entry.errno,
        );
    }
}

/// **The three doors to a user namespace, and the two ring/fault surfaces, by
/// literal number.** Written against the kernel's own ABI rather than read out
/// of `DENIED_SYSCALLS`, so a list entry that drifted off its number or flag
/// reds here:
///
/// * `clone` (56) with `CLONE_NEWUSER` (`0x1000_0000`) is EPERM, alone, with
///   `SIGCHLD`, with another namespace flag, and with garbage above bit 31
///   (the kernel reads the low word of the flags);
/// * `clone` WITHOUT it is ALLOWed — a fork's flags, glibc's thread flags, and
///   `CLONE_NEWNET` alone, which needs a capability the stage does not hold in
///   its own user namespace;
/// * `clone3` (435) is ENOSYS (38), whatever its arguments, so a libc falls
///   back to `clone`;
/// * `userfaultfd` (323) and `io_uring_setup`/`_enter`/`_register`
///   (425-427) are EPERM.
#[test]
fn clone_is_denied_only_with_clone_newuser_and_clone3_answers_enosys() {
    let prog = deny_list_program();
    let clone = |flags: u64| simulate_call(&prog, actions::ARCH_X86_64, 56, [flags, 0, 0, 0, 0, 0]);
    for denied in [0x1000_0000, 0x1000_0011, 0x5000_0011, 0xdead_beef_1000_0000] {
        assert_eq!(clone(denied), actions::ERRNO_EPERM, "clone({denied:#x})");
    }
    for allowed in [0x0120_0011, 0x003d_0f00, 0x4000_0011, 0x1_0000_0000] {
        assert_eq!(clone(allowed), actions::ALLOW, "clone({allowed:#x})");
    }
    for args in [[0; 6], [0x7fff_0000, 64, 0, 0, 0, 0]] {
        assert_eq!(
            simulate_call(&prog, actions::ARCH_X86_64, 435, args),
            actions::errno(38),
            "clone3{args:?}"
        );
    }
    for nr in [323, 425, 426, 427] {
        assert_eq!(
            simulate(&prog, actions::ARCH_X86_64, nr),
            actions::ERRNO_EPERM,
            "nr {nr}"
        );
    }
}

/// The canonical dangerous syscalls named in the task are denied.
#[test]
fn named_dangerous_syscalls_are_denied() {
    let prog = deny_list_program();
    let named: &[(&str, u32)] = &[
        ("mount", 165),
        ("ptrace", 101),
        ("kexec_load", 246),
        ("init_module", 175),
        ("finit_module", 313),
        ("delete_module", 176),
    ];
    for (name, nr) in named {
        assert_eq!(
            simulate(&prog, actions::ARCH_X86_64, *nr),
            actions::ERRNO_EPERM,
            "{name} must be denied"
        );
    }
}

/// A foreign architecture is KILLed — an arch mismatch is an
/// exploitation signal, and syscall numbers are not comparable across
/// ABIs, so we must not fall through to the number checks.
#[test]
fn foreign_arch_is_killed() {
    let prog = deny_list_program();
    const AUDIT_ARCH_AARCH64: u32 = 0xC000_00B7;
    // Even a "benign" nr under a foreign arch must KILL.
    assert_eq!(
        simulate(&prog, AUDIT_ARCH_AARCH64, 0),
        actions::KILL_PROCESS,
        "foreign-arch syscall must KILL, not be evaluated by x86_64 nr"
    );
}

/// The x32 ABI bypass (same syscall table with `__X32_SYSCALL_BIT` set)
/// is closed: any number at/above the bit KILLs, so a caller cannot dodge
/// the equality checks by setting the bit on `mount` et al.
#[test]
fn x32_bypass_is_killed() {
    let prog = deny_list_program();
    // mount (165 = 0xA5) with the x32 bit set must not slip through as ALLOW.
    let mount_x32 = 0xA5 | actions::X32_SYSCALL_BIT;
    assert_eq!(
        simulate(&prog, actions::ARCH_X86_64, mount_x32),
        actions::KILL_PROCESS,
        "x32-flagged mount must KILL (bypass closed)"
    );
    // A benign syscall with the x32 bit is likewise refused.
    assert_eq!(
        simulate(&prog, actions::ARCH_X86_64, actions::X32_SYSCALL_BIT),
        actions::KILL_PROCESS
    );
}

/// The DENY-list has no duplicate entries (a duplicate would be a
/// copy-paste error inflating the program without effect).
#[test]
fn denied_syscalls_are_unique() {
    let mut nrs: Vec<u32> = DENIED_SYSCALLS.iter().map(|e| e.nr).collect();
    let before = nrs.len();
    nrs.sort_unstable();
    nrs.dedup();
    assert_eq!(before, nrs.len(), "DENIED_SYSCALLS must have no duplicates");
}

/// Materialize `prefix` through the PRODUCTION spawn helper (the same call
/// the shell/claude/codex/opencode backends make) and append the probe
/// argv. Stdin is `/dev/null`: the seccomp program rides its OWN inherited
/// fd — never stdin.
fn production_command(prefix: &CommandPrefix, argv: &[&str]) -> tokio::process::Command {
    let mut cmd = kata_worker::process::command_with_prefix(prefix);
    for a in argv {
        cmd.arg(a);
    }
    cmd.stdin(Stdio::null());
    cmd
}

// ---------------------------------------------------------------------------
// The KATA FLOOR, installed by kata on the spawning child
// ---------------------------------------------------------------------------
//
// These tests live in THIS binary deliberately: `just oci-live-smoke` — step 1 of
// `just gate-containment`, and the lane where a capability SKIP is a FAILURE —
// selects it by name (`binary(sandbox_seccomp_tests)`). `nextest -E binary()` is
// exact, so a new binary would compile and NEVER RUN in that lane.

/// A prefix that runs `program` DIRECTLY — no wrapper, no stage
/// fence — optionally carrying the kata seccomp floor.
///
/// Floor-alone is the point. The floored and control arms differ in exactly one
/// field, so a difference observed in `/proc/self/status` is attributable to
/// `attach_kata_floor` and to nothing else. Running this under a sandbox
/// wrapper would make the observation unattributable in both directions: a
/// wrapper that sets `PR_SET_NO_NEW_PRIVS` itself and loads its own stage
/// fence reports `Seccomp: 2` whether or not kata installed anything.
fn kata_floor_only_prefix(program: &str, floor: bool) -> CommandPrefix {
    use kata_types::sandbox_seccomp::kata_floor_bpf;

    CommandPrefix {
        program: program.into(),
        args: Vec::new(),
        kata_floor_bpf: floor.then(kata_floor_bpf),
        resource_bounds: kata_agent::ResourceBounds::default(),
    }
}

/// Read one `Name:\t<u64>` field out of a `/proc/<pid>/status` dump.
///
/// EXACT-name matched: a `starts_with("Seccomp")` would also match
/// `Seccomp_filters:`, a different number, and would silently answer a question
/// nobody asked.
fn proc_status_u64(status: &str, field: &str) -> Option<u64> {
    for line in status.lines() {
        if let Some((name, value)) = line.split_once(':')
            && name == field
        {
            return value.trim().parse().ok();
        }
    }
    None
}

/// The first `candidates` entry that exists on this host.
fn locate<'a>(candidates: &[&'a str]) -> Option<&'a str> {
    candidates
        .iter()
        .copied()
        .find(|c| std::path::Path::new(c).exists())
}

/// LIVE: **the kata floor is loaded and enforcing in the kernel of
/// the process kata `execve`d.**
///
/// This is the ONLY observation in the tree that can distinguish an enforcing
/// floor from silent success. `seccomp(2)` returns 0 on success and a
/// `pre_exec` hook emits NO ARGV, so a hook that installed nothing leaves every
/// host-independent test green. The child reading its
/// OWN `/proc/self/status` after the `execve` is what closes that.
///
/// Two fields, because the floor makes two claims and each has its own way of being
/// silently false:
///
/// * `Seccomp: 2` — `SECCOMP_MODE_FILTER`. Reads 0 if the `seccomp(2)` return
///   went unchecked, or if the syscall was never issued at all.
/// * `NoNewPrivs: 1` — the `prctl` half. The floor's *unremovable* property IS this
///   bit; without it the filter is droppable and a setuid `execve` regains
///   privilege.
///
/// Both survive `execve` by kernel contract, which is the property being
/// observed: nothing inside the `cat` process installed either one.
///
/// # Non-vacuity
///
/// The control runs FIRST, on the IDENTICAL argv with `kata_floor_bpf: None`,
/// and must read `Seccomp: 0` / `NoNewPrivs: 0`. A test harness that itself ran
/// under a filter would make the floored arm's `2` unattributable, so that
/// condition is a FAILURE under `KATA_SANDBOX_REQUIRE_LIVE`, never a quiet pass.
///
/// **Would red if:** the `syscall(SYS_seccomp, …)` in `attach_kata_floor` were
/// replaced with `Ok(())` (floored arm reads `Seccomp: 0`); the `prctl` were
/// dropped or moved AFTER the seccomp call (an unprivileged `seccomp(2)` then
/// returns EACCES, the hook aborts the exec, and the spawn fails); or
/// `attach_kata_floor` were never called from `command_with_prefix`.
#[kata_test_utils::kata_timeout]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_kata_floor_is_active_in_the_kernel_live() {
    let Some(cat) = locate(&["/bin/cat", "/usr/bin/cat"]) else {
        let msg = "SKIP[the_kata_floor_is_active_in_the_kernel_live]: no `cat` binary — the \
                   floored child has to read its own /proc/self/status";
        assert!(
            !require_live(),
            "{msg}\n{env} is set, so a PROBE-TOOL absence is a FAILURE: this test's whole \
             content is the kernel's report of the floor, and without a way to read it the \
             test reports PASS having observed nothing.",
            env = REQUIRE_LIVE_ENV,
        );
        eprintln!("{msg}");
        return;
    };
    let argv = ["/proc/self/status"];

    // --- control FIRST: same argv, floor absent -----------------------------
    let control = production_command(&kata_floor_only_prefix(cat, false), &argv)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .await
        .expect("spawn the unfloored control");
    assert!(
        control.status.success(),
        "the unfloored control must run: {}",
        String::from_utf8_lossy(&control.stderr)
    );
    let control_status = String::from_utf8_lossy(&control.stdout);
    let control_seccomp = proc_status_u64(&control_status, "Seccomp");
    let control_nnp = proc_status_u64(&control_status, "NoNewPrivs");
    if control_seccomp != Some(0) || control_nnp != Some(0) {
        let msg = format!(
            "SKIP[the_kata_floor_is_active_in_the_kernel_live]: the UNFLOORED control already \
             reports Seccomp={control_seccomp:?} NoNewPrivs={control_nnp:?}; this test process \
             is itself confined, so the floored arm's verdict would be unattributable"
        );
        assert!(
            !require_live(),
            "{msg}\n{env} is set, so a FAILED NON-VACUITY CONTROL is a FAILURE: the floored arm \
             below asserts Seccomp=2/NoNewPrivs=1, and if the control already reports them it \
             proves nothing about `attach_kata_floor`.",
            env = REQUIRE_LIVE_ENV,
        );
        eprintln!("{msg}");
        return;
    }

    // --- floored: the SAME argv, `kata_floor_bpf: Some(kata_floor_bpf())` ---
    let floored = production_command(&kata_floor_only_prefix(cat, true), &argv)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .await
        .expect("spawn the floored child");
    assert!(
        floored.status.success(),
        "the floored child must still RUN — the floor denies nothing `cat` needs. \
         status={:?} stderr={:?}",
        floored.status,
        String::from_utf8_lossy(&floored.stderr)
    );
    let floored_status = String::from_utf8_lossy(&floored.stdout);
    let floored_seccomp = proc_status_u64(&floored_status, "Seccomp");
    let floored_nnp = proc_status_u64(&floored_status, "NoNewPrivs");
    assert_eq!(
        floored_seccomp,
        Some(2),
        "the kernel must report SECCOMP_MODE_FILTER (2) in the process kata execve'd; the \
         control read {control_seccomp:?}, and an unissued or unchecked seccomp(2) leaves the \
         floored arm reading exactly that"
    );
    assert_eq!(
        floored_nnp,
        Some(1),
        "PR_SET_NO_NEW_PRIVS must be set — it is the floor's `unremovable` property, and \
         without it the floor is droppable"
    );
    println!(
        "KATA-FLOOR live control=Seccomp:{control_seccomp:?}/NoNewPrivs:{control_nnp:?} \
         floored=Seccomp:{floored_seccomp:?}/NoNewPrivs:{floored_nnp:?}"
    );
}

/// LIVE: the floor does not merely EXIST in the kernel — it
/// **denies a `KataFloor` syscall**.
///
/// `Seccomp: 2` above proves a filter is loaded; it does not prove the loaded
/// filter is the floor. An allow-everything program would report 2 just the
/// same. `ptrace(101)` is a `KataFloor` entry (the shipped partition), so an `EPERM` here
/// — where the IDENTICAL unfloored argv succeeds — is the delta that says the
/// bytes kata compiled are the bytes the kernel enforces.
///
/// Floor-alone again: no stage fence. Under the stage fence this observation
/// would be unattributable, because the stage fence denies `ptrace`
/// regardless of what kata installed.
///
/// **Would red if:** `kata_floor_program()` stopped emitting the `KataFloor`
/// subset, the compiled bytes were dropped between the prefix and the kernel,
/// or `attach_kata_floor` loaded an allow-all program.
#[kata_test_utils::kata_timeout]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_kata_floor_denies_a_floored_syscall_live() {
    let Some(strace) = locate(&["/usr/bin/strace", "/bin/strace"]) else {
        let msg = "SKIP[the_kata_floor_denies_a_floored_syscall_live]: `strace` not installed \
                   — the_kata_floor_is_active_in_the_kernel_live still proves the filter is \
                   LOADED; this test is what proves it DENIES";
        assert!(
            !require_live(),
            "{msg}\n{env} is set, so a PROBE-TOOL absence is a FAILURE here for the same \
             reason it is in seccomp_blocks_ptrace_live: this test's whole content is the \
             ptrace delta, and without a ptrace-using tool it reports PASS having observed \
             nothing.",
            env = REQUIRE_LIVE_ENV,
        );
        eprintln!("{msg}");
        return;
    };
    let argv = ["-f", "/bin/true"];

    // --- control: same argv, floor absent — must SUCCEED --------------------
    let control = production_command(&kata_floor_only_prefix(strace, false), &argv)
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .output()
        .await
        .expect("spawn the unfloored strace control");
    if !control.status.success() {
        let msg = format!(
            "SKIP[the_kata_floor_denies_a_floored_syscall_live]: the UNFLOORED control could \
             not ptrace on this host (status={status:?} stderr={stderr:?}); a floored failure \
             would be unattributable",
            status = control.status,
            stderr = String::from_utf8_lossy(&control.stderr),
        );
        assert!(
            !require_live(),
            "{msg}\n{env} is set, so a FAILED NON-VACUITY CONTROL is a FAILURE. A host where \
             this genuinely cannot work (Yama ptrace_scope, a nested container) must not claim \
             to be live-capable.",
            env = REQUIRE_LIVE_ENV,
        );
        eprintln!("{msg}");
        return;
    }

    // --- floored: the SAME argv, the floor on -------------------------------
    let floored = production_command(&kata_floor_only_prefix(strace, true), &argv)
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .output()
        .await
        .expect("spawn the floored strace");
    assert!(
        !floored.status.success(),
        "strace must FAIL under the kata floor — ptrace(101) is a KataFloor entry; it exited \
         {:?}",
        floored.status
    );
    let stderr = String::from_utf8_lossy(&floored.stderr).to_lowercase();
    assert!(
        stderr.contains("ptrace") && stderr.contains("not permitted"),
        "the floored failure must be the ptrace EPERM the floor emits, not an unrelated \
         error; stderr={stderr:?}"
    );
    println!("KATA-FLOOR live ptrace-denied tool={strace}");
}

// ---------------------------------------------------------------------------
// The floor survives a NAMESPACE CHANGE
// ---------------------------------------------------------------------------
//
// The claim: a child that successfully calls `unshare(CLONE_NEWUSER)` gains
// full capabilities in the new namespace, but a seccomp filter is per-task,
// inherited and unremovable under `NO_NEW_PRIVS`, so every floored syscall
// stays denied, with its entry's errno, regardless of which namespace the
// caller sits in. These two
// tests prove it by observation rather than by a `/proc/<pid>/ns/user` inode
// argument.
//
// FLOOR-ALONE, and that is forced rather than tidy. `unshare` (nr 272) is a
// `ConstructionResidue` entry, so it is EPERM under the FULL stage
// fence — a child under it could not reach the namespace change at all, which
// is exactly why this proof cannot fold into the adversarial suite's A1 and
// why the prefix below carries `kata_floor_bpf` and nothing else.
//
// Same binary as the floor block above, for the same reason: `just
// oci-live-smoke` selects an EXACT binary union and a new file would
// compile and never run in either required lane.

/// Locate the built `kata` binary next to the current test binary.
///
/// Under the workspace suite (`just test` / `just gate`) and under `just
/// oci-live-smoke` (which runs `cargo build -p kata --bin kata` before the
/// tests) the binary exists at `target/<profile>/kata`; an isolated crate-only
/// run that never built it self-skips.
fn locate_kata_bin() -> Option<std::path::PathBuf> {
    let exe = std::env::current_exe().ok()?;
    let mut cur = exe.parent();
    while let Some(dir) = cur {
        let cand = dir.join("kata");
        if cand.is_file() {
            return Some(cand);
        }
        if dir.file_name().and_then(|n| n.to_str()) == Some("target") {
            break;
        }
        cur = dir.parent();
    }
    None
}

/// [`locate_kata_bin`], with the absence routed through the live knob.
///
/// A missing `kata` is a RIG deficiency, not a host capability: the probe under
/// test lives INSIDE this workspace's own binary, so a proof that skipped
/// because nobody built it would be measuring the build.
fn kata_bin_or_skip(test: &str) -> Option<String> {
    let found = locate_kata_bin().and_then(|p| p.to_str().map(str::to_owned));
    if let Some(path) = found {
        return Some(path);
    }
    let msg = format!(
        "SKIP[{test}]: `kata` binary not locatable next to the test binary — `kata \
         __syscall-probe` IS the instrument, so there is nothing to observe without it"
    );
    assert!(
        !require_live(),
        "{msg}\n{env} is set, so a MISSING BUILD ARTIFACT is a FAILURE. `just \
         oci-live-smoke` builds it (`cargo build -p kata --bin kata`); a lane that let \
         this skip would certify the namespace-change proof having run no probe at all.",
        env = REQUIRE_LIVE_ENV,
    );
    eprintln!("{msg}");
    None
}

/// One parsed `kata __syscall-probe` report: the single `context` row plus one
/// `floor_entry` row per attempted floored syscall.
struct ProbeReport {
    context: serde_json::Value,
    entries: Vec<serde_json::Value>,
}

/// Parse the probe's NDJSON, refusing anything it does not recognise.
///
/// Strict on purpose: a row shape that drifted, a stray log line on stdout, or
/// a second context row would otherwise be skipped over and the report read as
/// shorter than it is — which is the same defect as a probe that silently
/// skipped an entry.
fn parse_probe_report(test: &str, stdout: &str) -> ProbeReport {
    let mut context: Option<serde_json::Value> = None;
    let mut entries = Vec::new();
    for line in stdout.lines().filter(|l| !l.trim().is_empty()) {
        let row: serde_json::Value = serde_json::from_str(line).unwrap_or_else(|e| {
            panic!("{test}: `kata __syscall-probe` wrote a non-JSON stdout line ({e}): {line:?}")
        });
        match row.get("kind").and_then(serde_json::Value::as_str) {
            Some("context") => assert!(
                context.replace(row).is_none(),
                "{test}: the probe emitted TWO context rows; the second would silently \
                 replace the first and the arm's preconditions would be read off the wrong one"
            ),
            Some("floor_entry") => entries.push(row),
            other => panic!("{test}: unrecognised probe row kind {other:?} in {line:?}"),
        }
    }
    ProbeReport {
        context: context.unwrap_or_else(|| {
            panic!(
                "{test}: the probe emitted NO context row, so `unshare` and `CapEff` are \
                 unknown and every syscall row below it is uninterpretable"
            )
        }),
        entries,
    }
}

/// A dotted path into a probe row, as an integer. Absence PANICS: a missing
/// field read as a default is how a report that stopped saying anything passes.
fn probe_i64(test: &str, row: &serde_json::Value, path: &str) -> i64 {
    let mut cur = row;
    for seg in path.split('.') {
        cur = &cur[seg];
    }
    cur.as_i64()
        .unwrap_or_else(|| panic!("{test}: probe row has no integer at `{path}`: {row}"))
}

/// A dotted path into a probe row, as a string.
fn probe_str<'a>(test: &str, row: &'a serde_json::Value, path: &str) -> &'a str {
    let mut cur = row;
    for seg in path.split('.') {
        cur = &cur[seg];
    }
    cur.as_str()
        .unwrap_or_else(|| panic!("{test}: probe row has no string at `{path}`: {row}"))
}

/// `CapEff:` as a bitmask. Zero means "this process holds no capability at
/// all", which is what the capability REGAIN is measured against.
fn cap_bits(test: &str, row: &serde_json::Value, path: &str) -> u64 {
    let raw = probe_str(test, row, path);
    u64::from_str_radix(raw, 16).unwrap_or_else(|e| {
        panic!("{test}: `{path}` is not the hex mask /proc prints ({e}): {raw}")
    })
}

/// Run `kata __syscall-probe` through the PRODUCTION spawn path with the floor
/// on or off, and parse its report.
async fn run_syscall_probe(test: &str, kata: &str, floor: bool, unshare: bool) -> ProbeReport {
    let mut argv = vec!["__syscall-probe"];
    if unshare {
        argv.push("--unshare-userns");
    }
    let out = production_command(&kata_floor_only_prefix(kata, floor), &argv)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .await
        .unwrap_or_else(|e| panic!("{test}: spawning the probe (floor={floor}) failed: {e}"));
    assert!(
        out.status.success(),
        "{test}: `kata __syscall-probe` must RUN to completion with floor={floor} — the floor \
         denies nothing the probe itself needs, and a non-zero exit means the report below is \
         partial. status={status:?} stderr={stderr}",
        status = out.status,
        stderr = String::from_utf8_lossy(&out.stderr),
    );
    parse_probe_report(test, &String::from_utf8_lossy(&out.stdout))
}

/// The probe ATTEMPTS every floor entry — host-independently, so a floor entry
/// added without giving the probe a way to issue it is caught in `just gate`
/// rather than 25 minutes into the containment lane.
///
/// This needs no kernel capability: no `unshare`, no floor. It reads only the
/// probe's own coverage of `shipped_partition().kata_floor`.
///
/// # Non-vacuity
///
/// The rows are compared against the partition by NAME AND NUMBER IN ORDER, not
/// by count — two entries swapping numbers leaves a count identical. And
/// `attempted` is asserted per row, because the probe reports an entry it has
/// no argument set for as `attempted: false` rather than omitting it: a report
/// that silently shrank would otherwise still match its own length.
///
/// **Would red if:** a `DeniedSyscall::floor(...)` entry were added to
/// `DENIED_SYSCALLS` without a matching arm in the probe's
/// `floor_syscall_args` (that entry reports `attempted: false` and names
/// itself); or the probe stopped deriving its list from `shipped_partition()`.
#[kata_test_utils::kata_timeout]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_syscall_probe_attempts_every_kata_floor_entry() {
    use kata_types::sandbox_seccomp::shipped_partition;

    let test = "the_syscall_probe_attempts_every_kata_floor_entry";
    let Some(kata) = kata_bin_or_skip(test) else {
        return;
    };
    let floor = shipped_partition().kata_floor;
    assert!(
        !floor.is_empty(),
        "{test}: the derived kata floor is EMPTY, so every assertion below would hold by \
         having no subject"
    );

    let report = run_syscall_probe(test, &kata, false, false).await;
    assert_eq!(
        probe_i64(test, &report.context, "floor_entries"),
        i64::try_from(floor.len()).expect("floor length fits i64"),
        "{test}: the probe and this test must derive the SAME floor size from \
         `shipped_partition()`; a disagreement means one of them is quoting a number instead \
         of deriving it"
    );
    assert_eq!(
        report.entries.len(),
        floor.len(),
        "{test}: the probe emitted {emitted} rows for a {expected}-entry floor",
        emitted = report.entries.len(),
        expected = floor.len(),
    );
    for (row, entry) in report.entries.iter().zip(&floor) {
        assert_eq!(
            probe_str(test, row, "name"),
            entry.name,
            "{test}: probe rows must follow the partition's own order"
        );
        assert_eq!(
            probe_i64(test, row, "nr"),
            i64::from(entry.nr),
            "{test}: the probe must issue the number `{name}` is DECLARED at, not another one",
            name = entry.name,
        );
        assert!(
            row["attempted"].as_bool() == Some(true),
            "{test}: the probe did not attempt `{name}` — {reason}. An entry the floor claims \
             to deny and the probe never issues makes the namespace-change proof report success over a \
             smaller set than it names.",
            name = entry.name,
            reason = row["skipped_reason"],
        );
    }
    println!(
        "FLOOR-AFTER-UNSHARE probe-coverage floor-entries={} attempted={}",
        floor.len(),
        report.entries.len(),
    );
}

/// **The namespace-change proof**, LIVE: *a child that successfully calls
/// `unshare(CLONE_NEWUSER)` and gains capabilities in the new namespace is
/// still denied all floored syscalls.*
///
/// # The order IS the proof
///
/// Every precondition is asserted BEFORE a single syscall row is read:
///
/// 1. the control arm establishes that this host can create an unprivileged
///    user namespace at all, and that a process starts with NO capabilities;
/// 2. the floored arm's `Seccomp: 2` / `NoNewPrivs: 1` identify it as the
///    floored arm from the report itself, not from which prefix the test
///    believes it passed;
/// 3. its `unshare(CLONE_NEWUSER)` returned **0** — under the floor;
/// 4. its `CapEff` went from zero to the SAME non-zero mask the unfloored
///    control reached.
///
/// A reader that skipped to the syscall rows would let a child that never
/// entered the namespace "pass" the whole proof by being denied things it was
/// never capable of.
///
/// # Non-vacuity: the paired control, and what it can and cannot attribute
///
/// The control runs the IDENTICAL argv in a NEW user namespace with
/// `kata_floor_bpf: None`. Two disjoint sets come out of it and both are
/// asserted non-empty:
///
/// * **attributable** — the control reached an outcome other than the entry's
///   errno, so the floored errno is the filter's. Measured on the reference
///   host: 14 of 22.
/// * **already `EPERM` unfloored** — `swapon`, `reboot`, the module and kexec
///   calls. Their capability check runs against the INITIAL user namespace, so
///   an unprivileged caller is refused there whatever the filter says. Their
///   floored `EPERM` is asserted (the floor claims *all* floored syscalls) but is
///   NOT counted as attributable, which is the whole point of running the
///   control: an `EPERM` that capability stripping already explains must not be
///   spent as evidence about the floor.
///
/// The sharpest arm is the subset that **succeeds** unfloored —
/// `process_vm_readv`/`process_vm_writev` against this process's own one-byte
/// buffer — and is `EPERM` under the floor. That flip cannot be explained by
/// capabilities, namespaces, or argument validity.
///
/// `unshare` itself is the floor's built-in positive control: it is nr 272, a
/// `ConstructionResidue` entry, so a floored child that reached the new
/// namespace also proves the floor is not a blanket deny and that the residue
/// really is excluded from it.
///
/// **Would red if:** the floor were not installed on the child (the floored arm
/// reports `Seccomp: 0` and its `EPERM`s vanish); `kata_floor_program()`
/// stopped emitting the `KataFloor` subset (a floored row reports the control's
/// errno); a seccomp filter did NOT survive `unshare(CLONE_NEWUSER)` — the
/// claim this proof exists for — (floored rows report the control's
/// errnos after a successful unshare); or `unshare` were moved into the floor
/// (the floored arm's `unshare_rc` becomes -1 and the test fails on the
/// precondition rather than on a syscall row).
#[kata_test_utils::kata_timeout]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_kata_floor_survives_a_user_namespace_change_live() {
    use kata_types::sandbox_seccomp::shipped_partition;

    let test = "the_kata_floor_survives_a_user_namespace_change_live";
    let Some(kata) = kata_bin_or_skip(test) else {
        return;
    };
    let floor = shipped_partition().kata_floor;
    assert!(
        !floor.is_empty(),
        "{test}: the derived kata floor is EMPTY — every syscall assertion below would hold \
         over no subject at all"
    );

    // --- CONTROL FIRST: identical argv, new userns, floor ABSENT ------------
    let control = run_syscall_probe(test, &kata, false, true).await;
    let ctl = &control.context;
    let before_seccomp = probe_i64(test, ctl, "before.seccomp");
    let before_nnp = probe_i64(test, ctl, "before.no_new_privs");
    let before_caps = cap_bits(test, ctl, "before.cap_eff");
    if before_seccomp != 0 || before_nnp != 0 || before_caps != 0 {
        let msg = format!(
            "SKIP[{test}]: the UNFLOORED control already starts confined or privileged \
             (Seccomp={before_seccomp} NoNewPrivs={before_nnp} CapEff={before_caps:#x}); the \
             floored arm's verdict would be unattributable"
        );
        assert!(
            !require_live(),
            "{msg}\n{env} is set, so a FAILED NON-VACUITY CONTROL is a FAILURE: the proof \
             below reads a capability REGAIN as the delta from zero and a floor as the delta \
             from Seccomp 0, and neither delta exists here.",
            env = REQUIRE_LIVE_ENV,
        );
        eprintln!("{msg}");
        return;
    }
    let control_unshare = probe_i64(test, ctl, "unshare_rc");
    let control_caps = cap_bits(test, ctl, "after.cap_eff");
    if control_unshare != 0 || control_caps == 0 {
        let msg = format!(
            "SKIP[{test}]: this host does not grant an unprivileged process capabilities in a \
             new user namespace (unshare_rc={control_unshare} \
             errno={errno} CapEff after={control_caps:#x}); the namespace-change proof's PREMISE — a \
             child that successfully unshares AND gains capabilities — cannot be established \
             here, so a green would mean nothing",
            errno = probe_i64(test, ctl, "unshare_errno"),
        );
        assert!(
            !require_live(),
            "{msg}\n{env} is set, so an UNESTABLISHABLE PREMISE is a FAILURE: on this host \
             the proof cannot be run, and a lane that reported success would be certifying \
             the floor's argument against a child that never gained anything.",
            env = REQUIRE_LIVE_ENV,
        );
        eprintln!("{msg}");
        return;
    }

    // --- FLOORED: the SAME argv, `kata_floor_bpf: Some(kata_floor_bpf())` ---
    let floored = run_syscall_probe(test, &kata, true, true).await;
    let flr = &floored.context;

    // (2) the arm identifies ITSELF, so a floored arm that silently lost its
    //     floor cannot agree with the control and be read as agreement.
    assert_eq!(
        probe_i64(test, flr, "before.seccomp"),
        2,
        "{test}: the floored arm must start in SECCOMP_MODE_FILTER; it read the control's \
         value, so `attach_kata_floor` did not install on this child and every EPERM below \
         would be the control's"
    );
    assert_eq!(
        probe_i64(test, flr, "before.no_new_privs"),
        1,
        "{test}: NO_NEW_PRIVS is the floor's `unremovable` property and the reason the filter cannot \
         be dropped inside the new namespace"
    );
    assert_eq!(
        cap_bits(test, flr, "before.cap_eff"),
        0,
        "{test}: the floored child must START with no capabilities, else the regain below is \
         not a regain"
    );

    // (3) + (4) the premise, UNDER the floor.
    assert_eq!(
        probe_i64(test, flr, "unshare_rc"),
        0,
        "{test}: `unshare(CLONE_NEWUSER)` must SUCCEED under the floor (errno={errno}). \
         `unshare` is nr 272, a ConstructionResidue entry — a failure here means the residue \
         leaked into the floor, and it would also make the rest of this proof vacuous by \
         never entering the namespace.",
        errno = probe_i64(test, flr, "unshare_errno"),
    );
    let floored_caps = cap_bits(test, flr, "after.cap_eff");
    assert_ne!(
        floored_caps, 0,
        "{test}: the floored child must GAIN capabilities in the new namespace — that is the \
         precondition the namespace-change proof is about, and without it the EPERMs below are just a \
         process that could never have done any of this"
    );
    assert_eq!(
        floored_caps, control_caps,
        "{test}: the floored and unfloored children must reach the SAME capability set \
         ({floored_caps:#x} vs {control_caps:#x}). Identical capabilities, identical argv, \
         identical namespace — the ONLY difference between the arms is `kata_floor_bpf`, \
         which is what makes the syscall deltas below attributable to the filter."
    );

    // --- ONLY NOW the syscall rows -----------------------------------------
    assert_eq!(
        floored.entries.len(),
        floor.len(),
        "{test}: the floored arm attempted {got} of the {want} derived floor entries",
        got = floored.entries.len(),
        want = floor.len(),
    );
    assert_eq!(
        control.entries.len(),
        floor.len(),
        "{test}: the control arm attempted {got} of the {want} derived floor entries; the two \
         arms must probe the same set or the pairing below compares different things",
        got = control.entries.len(),
        want = floor.len(),
    );

    let mut attempted = 0usize;
    let mut attributable: Vec<&str> = Vec::new();
    let mut control_succeeded: Vec<&str> = Vec::new();
    let mut capability_shadowed: Vec<&str> = Vec::new();
    for ((f, c), entry) in floored.entries.iter().zip(&control.entries).zip(&floor) {
        let name = entry.name;
        assert_eq!(
            probe_str(test, f, "name"),
            name,
            "{test}: floored rows must follow the partition's own order"
        );
        assert_eq!(
            probe_str(test, c, "name"),
            name,
            "{test}: control rows must follow the partition's own order"
        );
        assert!(
            f["attempted"].as_bool() == Some(true) && c["attempted"].as_bool() == Some(true),
            "{test}: `{name}` was not attempted in both arms ({reason}); an entry the proof \
             names and the probe skips must not read as denied",
            reason = f["skipped_reason"],
        );
        attempted += 1;

        let floored_errno = probe_i64(test, f, "errno");
        let control_errno = probe_i64(test, c, "errno");
        let declared = i64::from(entry.errno);
        assert_eq!(
            floored_errno,
            declared,
            "{test}: `{name}` (nr {nr}) must fail with errno {declared}, the one its entry \
             declares, under the floor AFTER the namespace change — this is exactly the claim \
             the namespace-change proof makes. It returned rc={rc} errno={floored_errno} \
             ({text}); the unfloored control returned errno={control_errno}.",
            nr = entry.nr,
            rc = probe_i64(test, f, "rc"),
            text = f["errno_text"],
        );
        if control_errno == declared {
            capability_shadowed.push(name);
        } else {
            attributable.push(name);
            if probe_i64(test, c, "rc") >= 0 {
                control_succeeded.push(name);
            }
        }
    }
    assert_eq!(
        attempted,
        floor.len(),
        "{test}: {attempted} of {want} floor entries were attempted",
        want = floor.len(),
    );
    assert!(
        !attributable.is_empty(),
        "{test}: EVERY floored syscall was ALREADY EPERM in the unfloored control, so not one \
         of the {n} denials can be attributed to the filter rather than to this host's \
         capability checks. Proof 2 would be reporting success while observing nothing about \
         the floor.",
        n = floor.len(),
    );
    assert!(
        !control_succeeded.is_empty(),
        "{test}: no floored syscall SUCCEEDED in the unfloored control. The sharpest arm of \
         this proof is a syscall that genuinely works with the capabilities the new namespace \
         granted and is EPERM once the floor is on; without one, every delta is between two \
         kinds of failure. Attributable-by-errno: {attributable:?}"
    );
    println!(
        "FLOOR-AFTER-UNSHARE live floor-entries={n} denied-after-unshare={n} unshare_rc=0 \
         cap_eff={floored_caps:#x} attributable={a} control-succeeded={s} \
         capability-shadowed={cs} attributable-set={attributable:?} \
         control-succeeded-set={control_succeeded:?} shadowed-set={capability_shadowed:?}",
        n = floor.len(),
        a = attributable.len(),
        s = control_succeeded.len(),
        cs = capability_shadowed.len(),
    );
}
