//! The LIVE half of the rootless-OCI certification.
//!
//! # This file must PASS on a host that can run the containment lane, and RED on one that cannot
//!
//! It NEVER SKIPS. AGENTS.md: *"Inside containment a capability SKIP is a FAILURE
//! — a host that cannot prove containment cannot produce a green."* The whole
//! value of the certification is the claim *"this host CAN deliver rootless OCI"*, and a
//! test that quietly returned on a host without youki would convert that claim
//! into the absence of evidence — the defect class this repository pays for most
//! often. So there is no capability probe and no capability skip: on a host with no
//! pinned youki, no installed AppArmor profile, or no delegated user scope, every test
//! here FAILS and the panic names which refusal fired. The one early return is not a
//! skip: the race cell returns on a verdict a run in this target dir recorded for the
//! very youki bytes it reads now (`RaceVerdictKey`), while its siblings certify the
//! host on every run.
//!
//! # Why it is nonetheless `#[ignore]`d
//!
//! `just gate` is host-independent BY DESIGN (`exec = "host"` is a first-class
//! install, and the gate is the pre-commit lane on any host), so a
//! youki-dependent test cannot ride the default suite. The containment side is
//! where it belongs: `just _containment-preconditions`, whose youki lane BLOCKS
//! on the very same functional fact (`probe_youki`'s `passed` row — a real
//! container in a delegated scope), and the containment lane's `oci-live-smoke`
//! step, which selects `binary(oci_runtime_live)`;
//! `bin/kata-eval/tests/gate_exclusion.rs` is what keeps that selection from
//! being left to memory.
//!
//! Run it explicitly:
//!
//! ```text
//! cargo nextest run -p kata-worker -P live-smoke -E 'binary(oci_runtime_live)' --run-ignored all
//! ```
//!
//! # Why three of the five tests RE-EXEC themselves
//!
//! `certify_youki`'s delegation check measures the CALLING process's own cgroup
//! (`sandbox_bounds::measure_cgroup_delegation`), and a login session's cgroup is
//! not delegated on this class of host. So the three tests that certify re-exec
//! this binary inside `systemd-run --user --scope -p Delegate=yes`, the same
//! mechanism the other OCI live binaries here (`oci_provider_live.rs`,
//! `oci_adversarial_live.rs`) use, rather than minting a second one. A body
//! that measured in the test's own process would report this host unable to
//! deliver rootless OCI and be WRONG about the host.
//!
//! # What is asserted against something that does not share the code under test
//!
//! * the pinned binary's digest is compared against `sha256sum`'s own value,
//!   read out of `config/youki-pin.toml` — a file no Rust in this repository
//!   writes;
//! * the AppArmor profile text is compared against `/etc/apparmor.d/youki`, a
//!   file installed by root — the template itself is pinned byte for byte by
//!   the literal golden in `oci_runtime`'s unit suite; and
//! * the functional arm's verdict is the exit status of a container started by
//!   youki, a process kata does not link.

use std::{
    process::Command,
    time::{Duration, Instant},
};

use kata_types::youki_pin::YoukiPin;
use kata_worker::oci_runtime::{
    OciPrerequisiteRefusal, UsernsRestriction, YoukiCertification, certified_oci_route,
    certify_youki, render_apparmor_profile, run_throwaway_container_with, static_payload,
    verify_pinned_youki_unchanged,
};

/// Marks the re-exec'd inner run, carrying the name of the test that asked for
/// it — one variable rather than one per test, so the child can never run a
/// different body than the parent selected.
const INNER_ENV: &str = "KATA_OCI_CERTIFY_DELEGATED_INNER";

/// Run `body` inside a delegated user scope, re-exec'ing this binary if needed.
///
/// There is no capability probe and no skip: a host without `systemd-run --user`
/// fails at the spawn, which is the answer.
fn delegated(test: &'static str, body: fn()) {
    delegated_with_path(test, None, body);
}

/// [`delegated`], with the re-exec's `PATH` (and so the inner body's) replaced
/// by `path` when one is given.
fn delegated_with_path(test: &'static str, path: Option<&std::path::Path>, body: fn()) {
    if is_delegated_inner(test) {
        return body();
    }
    let exe = std::env::current_exe().expect("the test binary's own path");
    let mut command = Command::new("systemd-run");
    if let Some(path) = path {
        command.env("PATH", path);
    }
    let output = command
        .args(kata_test_utils::delegated_scope::systemd_run_args())
        .arg(&exe)
        .args([
            "--exact",
            test,
            "--include-ignored",
            "--nocapture",
            "--test-threads",
            "1",
        ])
        .env(INNER_ENV, test)
        .output()
        .unwrap_or_else(|error| {
            panic!(
                "re-exec of `{test}` inside `systemd-run --user --scope -p Delegate=yes` could \
                 not be spawned ({error}). A delegated scope is what lets an unprivileged \
                 process write a cgroup limit, and without one this host cannot bound an OCI \
                 stage at all — see `just _containment-preconditions`."
            )
        });
    eprintln!(
        "--- delegated inner run of `{test}` stdout ---\n{}\n--- stderr ---\n{}\n---",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    kata_test_utils::delegated_scope::assert_inner_ran_the_one_test(test, &output);
}

/// Whether this process is `test`'s re-exec'd inner run.
fn is_delegated_inner(test: &str) -> bool {
    std::env::var(INNER_ENV).as_deref() == Ok(test)
}

fn certified() -> YoukiCertification {
    certify_youki(YoukiPin::embedded()).unwrap_or_else(|refusal| {
        panic!(
            "this host cannot deliver the rootless-OCI prerequisite ({token}), and a SKIP here \
             would be a green with no subject. Run `just _containment-preconditions` for the \
             one-line diagnosis. Refusal: {refusal}",
            token = refusal.token(),
        )
    })
}

/// **The certification, live: every arm observed on this host.**
///
/// Would red if: the pin were re-pinned without re-rendering the profile, the
/// pinned store path were garbage-collected, the profile were unloaded, cgroup
/// delegation lost memory or pids, or youki stopped starting a container.
#[test]
#[ignore = "HOST-DEPENDENT (pinned youki, its installed AppArmor \
             profile, a delegated user scope). `just gate` is host-independent by design, so \
             this rides the containment side: `_containment-preconditions` blocks on the same \
             functional fact today, and the containment lane's `oci-live-smoke` step runs it. Run it now with `cargo nextest run -p kata-worker -P live-smoke -E 'binary(oci_runtime_live)' \
             --run-ignored all`."]
fn the_pinned_youki_certifies_on_this_host() {
    delegated("the_pinned_youki_certifies_on_this_host", || {
        let pin = YoukiPin::embedded();
        let cert = certified();

        assert_eq!(
            cert.store_path,
            std::path::Path::new(pin.store_path()),
            "the certification must be about the PINNED path and no other"
        );
        assert_eq!(
            cert.sha256,
            pin.sha256(),
            "the digest is re-derived from the bytes on disk and must equal the pin's"
        );
        assert!(
            cert.version >= pin.version_tuple(),
            "certified version {:?} is below the pinned floor {:?}",
            cert.version,
            pin.version_tuple()
        );
        assert!(
            cert.spec_version >= (1, 0, 0),
            "certified OCI spec version {:?} is below 1.0",
            cert.spec_version
        );
        assert!(
            !cert.libseccomp_version.is_empty(),
            "the certification must carry the libseccomp version the binary REPORTED; an empty \
             string would mean `fold_seccomp_support` returned a witness it did not read"
        );
        // The WHOLE line, not a substring scan for the version: a bare
        // `windows()` search would also match the version appearing inside
        // `commit:` or `rustc:`, so it could pass on a runtime printing no
        // `libseccomp:` line at all — which is the one thing this axis is about.
        // Read from the binary's own bytes, outside the code under test.
        let identification = String::from_utf8_lossy(
            &Command::new(pin.store_path())
                .arg("--version")
                .output()
                .expect("the pinned youki identifies itself")
                .stdout,
        )
        .into_owned();
        let expected_line = format!("libseccomp: {}", cert.libseccomp_version);
        assert!(
            identification
                .lines()
                .any(|line| line.trim() == expected_line),
            "the certification's libseccomp version must come from a whole `{expected_line}` line \
             in what the BINARY printed:\n{identification}"
        );
        assert_ne!(
            cert.userns_restriction,
            UsernsRestriction::Unknown,
            "the reference host exposes kernel.apparmor_restrict_unprivileged_userns; an `unknown` \
             here means the read moved or the knob vanished, which is a fact worth learning"
        );
        assert!(
            cert.delegation
                .has(kata_worker::sandbox_bounds::CgroupController::Memory)
                && cert
                    .delegation
                    .has(kata_worker::sandbox_bounds::CgroupController::Pids),
            "the certification must not be reachable without the two controllers a bounded OCI stage \
             needs: {}",
            cert.delegation.evidence
        );
    });
}

/// **The functional arm runs on a host that has no `runc`.**
///
/// A fresh Ubuntu 24.04 has no `runc` (the E9 clean-machine VM measured it): the
/// certification's throwaway bundle must not depend on a generator that only a
/// Docker host carries. The inner run's `PATH` is one directory linking every
/// program this host's `PATH` resolves, in `PATH` order, except `runc`: this
/// host with runc removed and nothing else changed (youki's own systemd cgroup
/// manager, for one, runs `busctl` by name). The verdict is the exit status of
/// the container youki ran.
///
/// Would red if: the bundle's spec came from `runc` with a hand-written
/// fallback (youki 0.7.0 refuses a user-namespace spec without a mount: `no
/// mount in spec`).
#[test]
#[ignore = "HOST-DEPENDENT (pinned youki, its installed AppArmor \
             profile, a delegated user scope). `just gate` is host-independent by design, so \
             this rides the containment side: `_containment-preconditions` blocks on the same \
             functional fact today, and the containment lane's `oci-live-smoke` step runs it. Run it now with `cargo nextest run -p kata-worker -P live-smoke -E 'binary(oci_runtime_live)' \
             --run-ignored all`."]
fn the_functional_arm_runs_without_runc_on_path_live() {
    const TEST: &str = "the_functional_arm_runs_without_runc_on_path_live";
    let bin = tempfile::tempdir().expect("a PATH directory");
    if std::env::var(INNER_ENV).as_deref() != Ok(TEST) {
        let search = std::env::var_os("PATH").expect("the outer run has a PATH");
        for dir in std::env::split_paths(&search) {
            let Ok(entries) = std::fs::read_dir(&dir) else {
                continue;
            };
            for entry in entries.flatten() {
                let name = entry.file_name();
                let link = bin.path().join(&name);
                // The first directory on PATH that holds a name wins, as a lookup would.
                if name != "runc" && std::fs::symlink_metadata(&link).is_err() {
                    std::os::unix::fs::symlink(entry.path(), &link).expect("linking a PATH entry");
                }
            }
        }
    }
    delegated_with_path(TEST, Some(bin.path()), || {
        let search = std::env::var_os("PATH").expect("the inner run has a PATH");
        assert!(
            std::env::split_paths(&search).all(|dir| !dir.join("runc").exists()),
            "the positive control: the inner run must not be able to resolve `runc`, or this \
             cell measures the Docker-host path it exists to exclude (PATH {search:?})"
        );
        let id = kata_worker::oci_runtime::run_functional_probe(YoukiPin::embedded())
            .unwrap_or_else(|refusal| {
                panic!("the functional arm refused on a host without runc: {refusal}")
            });
        assert!(!id.is_empty(), "the probe names the container that ran");
    });
}

/// **The digest is compared, not merely computed.**
///
/// Drives the PRODUCTION re-verification function against a certification whose
/// digest is wrong, because a test that re-implemented the comparison would pass
/// exactly when its copy and the real one agreed — including when both are wrong.
#[test]
#[ignore = "HOST-DEPENDENT (pinned youki, its installed AppArmor \
             profile, a delegated user scope). `just gate` is host-independent by design, so \
             this rides the containment side: `_containment-preconditions` blocks on the same \
             functional fact today, and the containment lane's `oci-live-smoke` step runs it. Run it now with `cargo nextest run -p kata-worker -P live-smoke -E 'binary(oci_runtime_live)' \
             --run-ignored all`."]
fn a_changed_digest_refuses_the_pinned_youki() {
    delegated("a_changed_digest_refuses_the_pinned_youki", || {
        let cert = certified();
        assert_eq!(
            verify_pinned_youki_unchanged(&cert),
            Ok(()),
            "the freshly certified binary must re-verify"
        );

        let stale = YoukiCertification {
            sha256: "0".repeat(64),
            ..cert
        };
        let refusal =
            verify_pinned_youki_unchanged(&stale).expect_err("a wrong digest must be refused");
        assert_eq!(refusal.token(), "digest_mismatch");
        let rendered = refusal.to_string();
        assert!(
            rendered.contains(&"0".repeat(64)) && rendered.contains(YoukiPin::embedded().sha256()),
            "the refusal must name BOTH digests so an operator can tell which is stale: {rendered}"
        );
    });
}

/// **The installed profile is what binds the profile NAME to the pinned path.**
///
/// The kernel's loaded list is keyed by name, and on this host it is not even
/// readable without `CAP_MAC_ADMIN`. So the byte comparison against
/// `/etc/apparmor.d/<name>` is the only thing that establishes the binding, and
/// this reads that file directly — outside the code under test — to prove the
/// certification is not passing on a vacuous comparison.
#[test]
#[ignore = "HOST-DEPENDENT (pinned youki, its installed AppArmor \
             profile, a delegated user scope). `just gate` is host-independent by design, so \
             this rides the containment side: `_containment-preconditions` blocks on the same \
             functional fact today, and the containment lane's `oci-live-smoke` step runs it. Run it now with `cargo nextest run -p kata-worker -P live-smoke -E 'binary(oci_runtime_live)' \
             --run-ignored all`."]
fn the_installed_profile_names_the_pinned_executable() {
    let pin = YoukiPin::embedded();
    let installed = std::path::Path::new("/etc/apparmor.d").join(pin.profile_name());
    let text = std::fs::read_to_string(&installed).unwrap_or_else(|error| {
        panic!(
            "{} must hold the rendered profile ({error}); install it with `sudo kata host \
             apparmor-install`",
            installed.display()
        )
    });
    assert!(
        text.contains(pin.store_path()),
        "the installed profile must name the pinned executable's exact path: {text}"
    );
    assert_eq!(text, render_apparmor_profile(pin));
}

/// **The WATCHDOG actually reaps a hung container, and the teardown still runs.**
///
/// Drives the production launch with a payload that sleeps for five minutes and a
/// three-second budget. Three things must hold, and every one is read from
/// OUTSIDE the code under test:
///
/// 1. the refusal is `functional_run_refused` with no exit code — the watchdog
///    fired rather than the container exiting;
/// 2. `systemctl --user status <id>.scope` exits non-zero — the transient scope,
///    and therefore everything in it, is GONE. Killing the `systemd-run` client
///    alone would leave it `running`;
/// 3. `youki list` names no container with that id — `delete --force` ran AFTER
///    the kill.
///
/// # RED before this was fixed, measured
///
/// With `Stdio::piped()` stderr, the write end is inherited by the container's
/// init. `wait_with_output` then reads until EOF, which a sleeping container never
/// gives: the watchdog SIGKILLed the `systemd-run` client, the read stayed
/// blocked on the surviving container's fd, and the function never returned — so
/// assertion 1 never arrived (the test hung past its nextest kill cap) and
/// `delete --force` never ran. Reverting `spawn_with_timeout` to a piped
/// `wait_with_output` reproduces exactly that.
#[test]
#[ignore = "HOST-DEPENDENT (pinned youki, its installed AppArmor \
             profile, a delegated user scope). `just gate` is host-independent by design, so \
             this rides the containment side: `_containment-preconditions` blocks on the same \
             functional fact today, and the containment lane's `oci-live-smoke` step runs it. Run it now with `cargo nextest run -p kata-worker -P live-smoke -E 'binary(oci_runtime_live)' \
             --run-ignored all`."]
fn a_hung_container_is_killed_by_the_watchdog_and_torn_down() {
    delegated(
        "a_hung_container_is_killed_by_the_watchdog_and_torn_down",
        || {
            let pin = YoukiPin::embedded();
            let payload = static_payload().expect("this host has a statically linked payload");
            assert!(
                payload.to_string_lossy().contains("busybox"),
                "this proof needs a MULTI-CALL static payload so `/bin/sh -c 'sleep 300'` can hang \
             inside a rootfs holding nothing else; the static payload here is {payload:?}, which \
             cannot sleep. Install busybox-static rather than skipping — a watchdog nobody \
             watched fire is a watchdog nobody has.",
            );

            let id = format!("kata-oci-watchdog-{}", std::process::id());
            let unit = format!("{id}.scope");
            let budget = Duration::from_secs(3);
            let started = Instant::now();
            let refusal = run_throwaway_container_with(
                std::path::Path::new(pin.store_path()),
                &id,
                &["sh", "sleep"],
                &["/bin/sh", "-c", "sleep 300"],
                budget,
            )
            .expect_err("a container that sleeps for five minutes must not certify this host");
            let elapsed = started.elapsed();

            assert_eq!(
                refusal.token(),
                "functional_run_refused",
                "the watchdog's refusal is a REFUSED RUN, not a harness failure: {refusal}"
            );
            assert!(
                refusal.to_string().contains("no exit within"),
                "the refusal must say the container never exited, not quote an exit code it did not \
             produce: {refusal}"
            );
            assert!(
                elapsed < Duration::from_secs(30),
                "the launch returned after {elapsed:?}, far past the {budget:?} budget — the wait is \
             blocked on something the watchdog cannot reach (this is the pipe deadlock)"
            );

            // (2) The scope is gone. `status` on an unknown unit exits 4; on a live
            // one it exits 0 (running) or 3 (inactive but loaded).
            let status = Command::new("systemctl")
                .args(["--user", "status", &unit])
                .output()
                .expect("systemctl --user is present on a host that delegated this scope");
            assert!(
                !status.status.success(),
                "`systemctl --user status {unit}` still reports a live scope, so the container's init \
             survived the watchdog:\n{}",
                String::from_utf8_lossy(&status.stdout)
            );

            // (3) Nothing is left registered. This is what `delete --force` is for,
            // and it is the assertion the pipe deadlock made unreachable.
            let listed = Command::new(pin.store_path())
                .arg("list")
                .output()
                .expect("the pinned youki can list containers");
            let table = format!(
                "{}{}",
                String::from_utf8_lossy(&listed.stdout),
                String::from_utf8_lossy(&listed.stderr)
            );
            // A listing that FAILED prints no table — `list` loads every container's
            // `state.json` before it writes a line — so its absence of `{id}` is no
            // evidence; it is refused rather than read as an empty registry.
            assert!(
                listed.status.success(),
                "`youki list` failed ({}), so it says nothing about whether `{id}` is still \
             registered:\n{table}",
                listed.status
            );
            assert!(
                !table.contains(&id),
                "`youki list` still names `{id}`, so the teardown did not run after the watchdog \
             fired:\n{table}"
            );
        },
    );
}

/// **The one certification a node takes, memoized.**
///
/// `certified_oci_route` is what `CapsuleRoute::admit` asks, unconditionally, on every
/// node — there is one engine and no switch. On this host it must
/// certify, and a second ask must return the SAME measurement: the functional probe id
/// names the one throwaway container the first ask started, so a memo that re-certified
/// would hand back a different id.
///
/// Would red if: the memo re-measured per call (a second probe id), or this host could
/// not deliver the prerequisite an `oci` node requires.
#[test]
#[ignore = "HOST-DEPENDENT (pinned youki, its installed AppArmor \
             profile, a delegated user scope). `just gate` is host-independent by design, so \
             this rides the containment side: `_containment-preconditions` blocks on the same \
             functional fact today, and the containment lane's `oci-live-smoke` step runs it. Run it now with `cargo nextest run -p kata-worker -P live-smoke -E 'binary(oci_runtime_live)' \
             --run-ignored all`."]
fn an_oci_node_certifies_once_and_memoizes_the_measurement() {
    delegated(
        "an_oci_node_certifies_once_and_memoizes_the_measurement",
        || {
            let first = certified_oci_route().unwrap_or_else(|refusal: OciPrerequisiteRefusal| {
                panic!(
                    "an `oci` node requires the rootless-OCI prerequisite, and this host cannot \
                     deliver it ({token}): {refusal}",
                    token = refusal.token(),
                )
            });
            let second = certified_oci_route().expect("the memo answers as it did");
            // The probe id, not pointer identity: a `&'static` into a `OnceLock` is the
            // same address by construction, so only the id can show a second measurement.
            assert_eq!(
                first.functional_probe_id, second.functional_probe_id,
                "one functional probe per process"
            );
        },
    );
}

// ---------------------------------------------------------------------------
// The STAGE FENCE, observed from inside the container.
// ---------------------------------------------------------------------------

/// **The `linux.seccomp` section kata writes is READ by the pinned runtime, and it
/// is a SECOND filter on top of the kata seccomp floor.**
///
/// # What this test exists to catch
///
/// A youki 0.7.0 built from `nixpkgs#youki` reports
/// `Seccomp_filters: 0` inside a container whose `config.json` carried every
/// deny-list entry. That derivation passes `--features systemd` to a binary crate with no
/// default features that takes `libcontainer` with `default-features = false`, so
/// `libcontainer/libseccomp` was OFF; `libcontainer`'s init gates every seccomp
/// call behind `#[cfg(feature = "libseccomp")]` and the `cfg(not(...))` arm only
/// `tracing::warn!`s, which the caller never sees. The fence is written and never
/// read, and nothing refuses. `nix/youki.nix` is the pin that fixes it and
/// `oci_runtime::fold_seccomp_support` is the refusal that keeps it fixed — and
/// neither of those is this observation. THIS is the observation.
///
/// # Two arms, because a count alone is not attributable
///
/// Both arms run the SAME bundle, carrying kata's real
/// `kata_types::sandbox_seccomp::oci_seccomp_rules` — derived by simulating the
/// very BPF program `deny_list_bpf` ships, so the fence under test is the shipped
/// one and not a fixture. They differ in exactly one field of one
/// `kata_agent::CommandPrefix`: `kata_floor_bpf`. So
///
/// * `control` (no floor) must read **1** — the stage fence alone, which a
///   runtime without libseccomp reads as 0; and
/// * `floored` (production) must read **2** — the floor kata installs on itself
///   before `execve`, PLUS the fence the runtime installed. Two filters is what
///   the OCI route is supposed to deliver.
///
/// The spawn goes through `kata_worker::process::command_with_prefix`, the one
/// production function that turns a `CommandPrefix` into a child: a test that
/// built its own `Command` would measure a copy of the `pre_exec` hook rather
/// than the hook.
///
/// A per-syscall `EPERM` is deliberately NOT asserted here: the container has
/// empty capability sets, so a denied syscall a busybox applet can reach is
/// refused by the capability check either way and the verdict would not be
/// attributable to the filter. `oci_provider_live.rs`'s header states the same
/// bound.
///
/// # THIS TEST CANNOT PASS WITHOUT THE PROFILE FOR THE PINNED STORE PATH
///
/// If `/etc/apparmor.d/youki` names a store path other than the pinned one, then
/// with `kernel.apparmor_restrict_unprivileged_userns` on, the unprofiled binary
/// transitions into the kernel's `unprivileged_userns` profile, which denies
/// `capability` — measured on the reference host as
/// `failed to unshare namespace err=Nix(EPERM) namespace=… Pid`. That is the
/// pin's refusal mechanism working, not a defect in this test, and the panic
/// below says so. Install the profile as root:
///
/// ```text
/// sudo kata host apparmor-install
/// ```
///
/// # Would red if
///
/// The pin moved back to a runtime without libseccomp (control → 0), the floor
/// stopped surviving the `execve` into youki (floored == control), or something
/// else installed a filter too (either count high).
#[test]
#[ignore = "HOST-DEPENDENT (pinned youki, its installed AppArmor \
             profile rendered for the pinned store path, a delegated user scope) — see this \
             test's docs. `just gate` \
             is host-independent by design, so this rides the containment side like its siblings; \
             the containment lane's `oci-live-smoke` step runs it. Run it now with `cargo \
             nextest run -p kata-worker -P live-smoke -E 'binary(oci_runtime_live)' --run-ignored all`."]
fn the_stage_fence_reaches_the_container_live() {
    delegated(
        "the_stage_fence_reaches_the_container_live",
        the_stage_fence_body,
    );
}

fn the_stage_fence_body() {
    use std::collections::BTreeMap;

    let test = "the_stage_fence_reaches_the_container_live";
    let pin = YoukiPin::embedded();
    let payload = static_payload().expect("this host has a statically linked payload");
    assert!(
        payload.to_string_lossy().contains("busybox"),
        "this proof needs a MULTI-CALL static payload so a rootfs holding nothing else can run \
         `sh -c 'cat /proc/self/status > /out/status'`; the static payload here is {payload}. \
         Install busybox-static rather than skipping — a fence nobody read from inside a \
         container is a fence nobody has.",
        payload = payload.display(),
    );

    // THE BASELINE, read in THIS process, which is every container init's
    // ancestor: seccomp filters are inherited across `fork` and `execve`, so
    // whatever this process already carries is carried down into both arms and the
    // counts below are only attributable as a DELTA from it. Zero on an ordinary
    // run; non-zero the moment this binary is run under a filter of its own (a
    // sandboxed CI shell, an operator's own `bwrap`), where hard-coded 1 and 2
    // would red for a reason that has nothing to do with the fence.
    let base = own_seccomp_filters(test);

    let mut counts = BTreeMap::new();
    for (arm, floor) in [
        ("control", None),
        (
            "floored",
            Some(kata_types::sandbox_seccomp::kata_floor_bpf()),
        ),
    ] {
        let status = observe_container_status(test, arm, pin, &payload, floor);
        let field = |name: &str| -> i64 {
            status
                .lines()
                .find_map(|line| line.strip_prefix(&format!("{name}:")))
                .unwrap_or_else(|| {
                    panic!(
                        "{test}[{arm}]: the guest's /proc/self/status has no `{name}` line, so the \
                         kernel did not report the thing this arm compares:\n{status}"
                    )
                })
                .trim()
                .parse()
                .expect("a /proc/self/status number")
        };
        assert_eq!(
            field("NoNewPrivs"),
            1,
            "{test}[{arm}]: the container's `noNewPrivileges` did not take, and a filter's \
             preservation across `execve` is not separable from it:\n{status}"
        );
        counts.insert(arm, (field("Seccomp"), field("Seccomp_filters"), status));
    }

    let (control_mode, control_filters, control_status) = counts["control"].clone();
    let (floored_mode, floored_filters, floored_status) = counts["floored"].clone();

    assert_eq!(
        control_filters,
        base + 1,
        "{test}: the UNFLOORED container must carry EXACTLY ONE seccomp filter MORE than this \
         test process, which carries {base} — the `linux.seccomp` fence kata wrote, installed by \
         the runtime. A runtime built without libcontainer/libseccomp reads a delta of 0 here, \
         dropping the section in silence. A delta of 0 means \
         the pin regressed to such a runtime (and `oci_runtime::fold_seccomp_support` should have \
         refused BEFORE this ran, so check that too).\n{control_status}"
    );
    assert_eq!(
        control_mode, 2,
        "{test}: the unfloored container's init must be in seccomp FILTER mode (2) as the kernel \
         reports it:\n{control_status}"
    );
    assert_eq!(
        floored_filters,
        base + 2,
        "{test}: the FLOORED container must carry EXACTLY TWO filters more than this test \
         process, which carries {base} — kata's seccomp floor, installed on this process's \
         child before `execve` and inherited through youki into the container's init, PLUS the \
         stage fence the runtime installed. The two arms differ in one field of one \
         `CommandPrefix` and in nothing else, so a delta of 1 means one of the two is \
         missing.\nfloored:\n{floored_status}\ncontrol:\n{control_status}"
    );
    assert_eq!(
        floored_mode, 2,
        "{test}: the floored container's init must be in seccomp FILTER mode (2):\n{floored_status}"
    );

    println!(
        "OCI-RUNTIME STAGE-FENCE base-filters={base} control-filters={control_filters} \
         floored-filters={floored_filters} fence-delta=1 floor-delta=1 fence=read-by-runtime \
         floor=inherited youki={path}",
        path = pin.store_path(),
    );
}

/// This process's own `Seccomp_filters` — the baseline both arms are a delta from.
///
/// Read from `/proc/self/status` INSIDE the re-exec'd body, so it is the count of
/// the process that actually `fork`s the runtime. The outer `systemd-run` parent
/// is a different process and a baseline taken there could differ from the one
/// the containers inherit.
fn own_seccomp_filters(test: &str) -> i64 {
    let status = std::fs::read_to_string("/proc/self/status")
        .unwrap_or_else(|error| panic!("{test}: this process has no /proc/self/status: {error}"));
    status
        .lines()
        .find_map(|line| line.strip_prefix("Seccomp_filters:"))
        .unwrap_or_else(|| {
            panic!(
                "{test}: /proc/self/status has no `Seccomp_filters` line, so this kernel does not \
                 report the quantity both arms are a delta from:\n{status}"
            )
        })
        .trim()
        .parse()
        .expect("a /proc/self/status number")
}

/// Run one observing container and return the `/proc/self/status` it left in `/out`.
///
/// The bundle is written HERE rather than by `oci_bundle::spec_for`, and that is
/// deliberate: this measures whether the RUNTIME reads a `linux.seccomp` section,
/// so the section has to be the subject and not a by-product of a capsule fold
/// that has its own golden. The rules themselves are kata's shipped ones.
fn observe_container_status(
    test: &str,
    arm: &str,
    pin: &YoukiPin,
    payload: &std::path::Path,
    floor: Option<Vec<u8>>,
) -> String {
    use std::{os::unix::fs::PermissionsExt as _, process::Stdio};

    let temporary = tempfile::Builder::new()
        .prefix("kata-oci-fence-")
        .tempdir()
        .expect("a bundle tempdir");
    let bundle = temporary.path().join("bundle");
    let out = temporary.path().join("out");
    let state = temporary.path().join("state");
    let bin = bundle.join("rootfs").join("bin");
    std::fs::create_dir_all(&bin).expect("the bundle rootfs");
    std::fs::create_dir_all(bundle.join("rootfs").join("proc")).expect("a /proc mountpoint");
    // A `/dev` MOUNTPOINT, and it is not optional. MEASURED: without it `youki run`
    // exits 255 in the CONTROL arm with
    //
    //   ERROR libcontainer::rootfs::symlink: failed to symlink kcore
    //   ERROR … failed to prepare rootfs err=Symlink(… NotFound …)
    //
    // libcontainer unconditionally creates its default device symlinks
    // (`/dev/kcore -> /proc/kcore` among them) inside the rootfs, so a bundle with
    // no `dev` directory and no `/dev` mount cannot start. `oci_bundle::spec_for`
    // renders both, which is why the PRODUCTION path never met this; this bundle is
    // hand-built precisely so the fence can be varied, and that is exactly the kind
    // of divergence a hand-built fixture buys.
    std::fs::create_dir_all(bundle.join("rootfs").join("dev")).expect("a /dev mountpoint");
    std::fs::create_dir_all(bundle.join("rootfs").join("out")).expect("an /out mountpoint");
    std::fs::create_dir_all(&out).expect("the host side of /out");
    // busybox dispatches on argv[0], so a static busybox copied to `sh` IS `sh`.
    for applet in ["busybox", "sh", "cat"] {
        let target = bin.join(applet);
        std::fs::copy(payload, &target).expect("the static payload copies into the rootfs");
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o755))
            .expect("the payload is executable");
    }

    let rules = kata_types::sandbox_seccomp::oci_seccomp_rules()
        .expect("kata's shipped deny list renders as OCI seccomp rules");
    let syscalls: Vec<serde_json::Value> = rules
        .syscalls
        .iter()
        .map(|rule| {
            let mut object = serde_json::json!({
                "names": rule.names,
                "action": rule.action.token(),
            });
            if let Some(errno) = rule.errno_ret {
                object["errnoRet"] = serde_json::json!(errno);
            }
            // A conditional rule keeps its condition: dropped, `clone`'s
            // CLONE_NEWUSER rule would deny every fork in the container.
            if !rule.args.is_empty() {
                object["args"] = rule
                    .args
                    .iter()
                    .map(|arg| {
                        serde_json::json!({
                            "index": arg.index,
                            "value": arg.flags,
                            "valueTwo": arg.flags,
                            "op": "SCMP_CMP_MASKED_EQ",
                        })
                    })
                    .collect();
            }
            object
        })
        .collect();
    let config = serde_json::json!({
        "ociVersion": "1.0.2",
        "root": { "path": "rootfs", "readonly": true },
        "process": {
            "args": ["/bin/sh", "-c", "cat /proc/self/status > /out/status"],
            "cwd": "/",
            "terminal": false,
            "user": { "uid": 0, "gid": 0 },
            "env": ["PATH=/bin"],
            "noNewPrivileges": true,
            "capabilities": { "bounding": [], "effective": [], "permitted": [] },
        },
        "mounts": [
            { "destination": "/proc", "type": "proc", "source": "proc" },
            // See the `rootfs/dev` comment above: libcontainer's default device
            // setup needs this, and its absence is a rootfs-preparation failure
            // before the process this test is about ever starts.
            {
                "destination": "/dev",
                "type": "tmpfs",
                "source": "tmpfs",
                "options": ["nosuid", "strictatime", "mode=755", "size=65536k"],
            },
            {
                "destination": "/out",
                "type": "none",
                "source": out.display().to_string(),
                "options": ["rbind", "rw", "nosuid", "nodev", "private"],
            },
        ],
        "linux": {
            "namespaces": [
                { "type": "pid" }, { "type": "ipc" }, { "type": "uts" },
                { "type": "mount" }, { "type": "user" }, { "type": "cgroup" },
                { "type": "network" },
            ],
            "uidMappings": [
                { "containerID": 0, "hostID": nix::unistd::getuid().as_raw(), "size": 1 },
            ],
            "gidMappings": [
                { "containerID": 0, "hostID": nix::unistd::getgid().as_raw(), "size": 1 },
            ],
            "seccomp": {
                "defaultAction": rules.default_action.token(),
                "architectures": rules.architectures,
                "syscalls": syscalls,
            },
        },
    });
    std::fs::write(
        bundle.join("config.json"),
        serde_json::to_string_pretty(&config).expect("the config serializes"),
    )
    .expect("config.json is written");

    let id = format!("kata-oci-fence-{arm}-{}", std::process::id());
    // EXHAUSTIVE literal, no `..Default::default()`: a new `CommandPrefix` field
    // must be re-decided here rather than absorbed, the discipline
    // `provider_supervisor::provider_command_prefix`'s literal keeps.
    let prefix = kata_agent::CommandPrefix {
        program: pin.store_path().into(),
        args: vec![
            "--root".into(),
            state.display().to_string().into(),
            "run".into(),
            "--bundle".into(),
            bundle.display().to_string().into(),
            id.clone().into(),
        ],
        kata_floor_bpf: floor,
        resource_bounds: kata_agent::resource_bounds::ResourceBounds::default(),
    };
    // FILES, never pipes. The write end of a piped stderr is inherited by the
    // container's init, and reading it to EOF is the deadlock this file's watchdog
    // test documents.
    // The FINALLY, on every path INCLUDING a panic: a container left registered
    // makes the next run on this host fail on a name collision rather than on the
    // fact it measures, and a stranded one is residue every later run pays for.
    let _finally = DeleteOnDrop {
        youki: std::path::PathBuf::from(pin.store_path()),
        state: state.clone(),
        id: id.clone(),
    };
    let captured = temporary.path().join("youki.err");
    let status = kata_worker::process::command_with_prefix(&prefix)
        .as_std_mut()
        .stdin(Stdio::null())
        .stdout(Stdio::from(
            std::fs::File::create(temporary.path().join("youki.out")).expect("a capture file"),
        ))
        .stderr(Stdio::from(
            std::fs::File::create(&captured).expect("a capture file"),
        ))
        .spawn()
        // BOUNDED. Not `.status()`, which waits forever — and youki
        // 0.7.0's lost-SIGCHLD race (see `fast_exiting_containers_…`) is exactly a
        // `youki run` that never returns. An unbounded wait here outlives nextest's
        // kill, and a SIGKILL from nextest leaves the client and its container
        // behind; a bound kata owns kills the client itself and runs the `delete`
        // below on every path.
        .map(|mut child| match wait_bounded(&mut child, OBSERVE_BUDGET) {
            Some(status) => status,
            None => panic!(
                "{test}[{arm}]: `youki run` did not return within {}s. A container whose init \
                 is `cat` finishes in milliseconds, so this is the runtime client stranded — \
                 the lost-SIGCHLD race `fast_exiting_containers_never_strand_the_runtime_client_live` \
                 measures. The client was SIGKILLed and the container deleted.",
                OBSERVE_BUDGET.as_secs(),
            ),
        });
    let stderr = std::fs::read_to_string(&captured).unwrap_or_default();
    let denial = if stderr.contains("EPERM") || stderr.contains("Operation not permitted") {
        "\n\nThe stderr above is a CAPABILITY DENIAL, which on this host means the pinned \
         store path has no AppArmor profile attaching to it: /etc/apparmor.d/youki names a \
         different path, and with \
         kernel.apparmor_restrict_unprivileged_userns on an unprofiled binary transitions into \
         the kernel's `unprivileged_userns` profile, which denies `capability`. That is the \
         pin's refusal mechanism working. Install the profile as root — `sudo \
         kata host apparmor-install` — and re-run."
    } else {
        ""
    };
    let status = status
        .unwrap_or_else(|error| panic!("{test}[{arm}]: the pinned youki did not spawn: {error}"));
    assert!(
        status.success(),
        "{test}[{arm}]: `youki run` exited {code:?} instead of 0.\nstderr:\n{stderr}{denial}",
        code = status.code(),
    );
    std::fs::read_to_string(out.join("status")).unwrap_or_else(|error| {
        panic!(
            "{test}[{arm}]: the container left no /proc/self/status in /out ({error}). /out is a \
             read-write rbind of a host directory this process owns, so an absent file means the \
             guest could not write it — which is itself the finding.\nstderr:\n{stderr}{denial}"
        )
    })
}

/// How long [`observe_container_status`] lets one `youki run` take. Its container
/// runs `cat` once; anything near this is a stranded client, not a slow stage.
const OBSERVE_BUDGET: Duration = Duration::from_secs(30);

/// `youki --root <state> delete --force <id>` when dropped — on every path out of a
/// rig that started a container, a panic included.
struct DeleteOnDrop {
    youki: std::path::PathBuf,
    state: std::path::PathBuf,
    id: String,
}

impl Drop for DeleteOnDrop {
    fn drop(&mut self) {
        let _ = Command::new(&self.youki)
            .arg("--root")
            .arg(&self.state)
            .args(["delete", "--force", &self.id])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status();
    }
}

/// Wait for `child` at most `budget`; on expiry SIGKILL it, reap it, and return
/// `None`. The runtime client is this process's own direct child, so the kill is by
/// handle and cannot reach anything else.
fn wait_bounded(
    child: &mut std::process::Child,
    budget: Duration,
) -> Option<std::process::ExitStatus> {
    let deadline = Instant::now() + budget;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return Some(status),
            Ok(None) if Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(20));
            }
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                return None;
            }
        }
    }
}

// ---------------------------------------------------------------------------
// youki 0.7.0's lost-SIGCHLD race — the regression cell for the patched pin
// ---------------------------------------------------------------------------

/// Containers the race cell runs. MEASURED against the unpatched pin
/// (`ar8227j9…-youki-seccomp-0.7.0`) with this cell's final contention: 4 of 300
/// stranded in 73 s (an earlier 150-run pass: 3), so ~1.5-2%, and 300 misses it with
/// probability under 1%. (A shell loop of plain `youki run`
/// with three busy PROCESSES measured 20 of 200; six busy threads here made each run
/// so slow the cell hit nextest's 300 s kill — see [`RACE_WALL_BUDGET`].)
const RACE_ITERATIONS: usize = 300;

/// Per-run budget. A `true` container returns in well under a second; a stranded
/// client never returns at all, so the budget only bounds how long a hang costs.
const RACE_BUDGET: Duration = Duration::from_secs(5);

/// The cell's own wall-clock ceiling, inside the `live-smoke` profile's 300 s kill.
/// A nextest kill SIGKILLs the test mid-`youki run` and orphans the client (measured:
/// a `youki run` reparented to init, `SigBlk: 0`, its child unreaped), so the cell
/// stops ITSELF first and reports how far it got.
const RACE_WALL_BUDGET: Duration = Duration::from_secs(200);

/// Busy threads sharing this process's single pinned CPU. The race needs the init
/// to exit before the client blocks signals, and starving the client is what widens
/// that window: MEASURED idle, 0 hangs in 120.
const RACE_HOGS: usize = 3;

/// **The pinned youki must not strand its client when the container's init exits
/// before `handle_foreground` blocks signals.**
///
/// # The upstream bug
///
/// youki 0.7.0's `commands/run.rs` calls `container.start()` and only THEN blocks the
/// signals `handle_foreground` `sigwait`s on. `SIGCHLD`'s default disposition is
/// IGNORE, so an init that exits in that window has its `SIGCHLD` DISCARDED by the
/// kernel (`kernel/signal.c`, `prepare_signal`) rather than left pending, and the
/// client waits forever with its child a zombie. Upstream fixed it on main
/// (youki-dev/youki#3639, commit c06504aa7e); kata's pin carries the same fix as
/// `nix/youki-0.7.0-foreground-prereap.patch` until a release contains it.
///
/// # The measurement
///
/// `RACE_ITERATIONS` plain `youki run`s of a `true` container — the fastest-exiting
/// init there is — with this process pinned to ONE CPU shared with `RACE_HOGS` busy
/// threads, each bounded by `RACE_BUDGET`. Plain `youki run` and not the provider,
/// because the defect and the fix are both in the runtime binary; the provider only
/// ever runs the pinned one. Watched red: against the UNPATCHED pin this cell strands
/// clients (the count is printed either way).
///
/// # Proved once per pinned binary
///
/// The property belongs to the runtime binary's bytes, which `YoukiPin.sha256` fixes, so
/// a pass is recorded under this build's `target/` keyed by the digest of the bytes it
/// ran and the digest of this file ([`RaceVerdictKey`]), and a later run with the same
/// key prints the recorded verdict instead of re-running ~1 minute of CPU-pinned
/// containers. A re-pinned youki, an edited cell, a fresh target directory or
/// `KATA_YOUKI_RACE_REPROVE=1` re-proves. NOT keyed: the kernel and the host's load —
/// the race and its fix are both in the binary. A recorded pass is ONE sample of
/// `RACE_ITERATIONS` runs, which misses the race on an unpatched binary with probability
/// under 1%; that sample stands for every later run on those bytes until
/// `KATA_YOUKI_RACE_REPROVE=1` re-samples.
#[test]
#[ignore = "HOST-DEPENDENT (pinned youki, its installed AppArmor \
            profile, a delegated user scope). ~1 minute when it proves; seconds when this \
            target dir holds the pinned bytes' verdict. Runs in the containment lane's \
            `oci-live-smoke` step. Run it with `cargo nextest run -p kata-worker -P \
            live-smoke -E 'binary(oci_runtime_live) and test(fast_exiting)' --run-ignored \
            all` (`KATA_YOUKI_RACE_REPROVE=1` to re-prove a recorded verdict)."]
fn fast_exiting_containers_never_strand_the_runtime_client_live() {
    let test = "fast_exiting_containers_never_strand_the_runtime_client_live";
    if !is_delegated_inner(test) {
        let key = RaceVerdictKey::of(YoukiPin::embedded());
        if let Some(verdict) = key.recorded(&race_verdict_dir(), race_reprove_forced()) {
            println!(
                "OCI-RUNTIME LOST-SIGCHLD RECORDED youki_sha256={youki} cell_sha256={cell} \
                 (proved on these bytes by this cell; {RACE_REPROVE_ENV}=1 re-proves): {verdict}",
                youki = key.youki_sha256,
                cell = key.cell_sha256,
            );
            return;
        }
    }
    delegated(test, fast_exiting_containers_body);
}

/// Set to `1`, the race cell re-proves a pin whose verdict this target dir records.
const RACE_REPROVE_ENV: &str = "KATA_YOUKI_RACE_REPROVE";

fn race_reprove_forced() -> bool {
    std::env::var(RACE_REPROVE_ENV).as_deref() == Ok("1")
}

/// Where the race cell's verdicts live: this build's `target/tmp`, so `cargo clean` or a
/// fresh worktree re-proves.
fn race_verdict_dir() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_TARGET_TMPDIR")).join("kata-youki-race-verdicts")
}

/// What a recorded race verdict stands for: the youki bytes it ran, and the cell that
/// ran them.
struct RaceVerdictKey {
    /// sha256 of the runtime binary's bytes, read now — `YoukiPin.sha256` on any host
    /// whose pin certifies, and a different key for any other bytes.
    youki_sha256: String,
    /// sha256 of this file, so an edited cell is a new key.
    cell_sha256: String,
}

impl RaceVerdictKey {
    fn of(pin: &YoukiPin) -> Self {
        let bytes = std::fs::read(pin.store_path()).unwrap_or_else(|error| {
            panic!(
                "the pinned youki `{}` is unreadable ({error}); a verdict about its \
                 bytes cannot be looked up or proved",
                pin.store_path()
            )
        });
        Self {
            youki_sha256: sha256_hex(&bytes),
            cell_sha256: sha256_hex(include_bytes!("oci_runtime_live.rs")),
        }
    }

    fn path_in(&self, dir: &std::path::Path) -> std::path::PathBuf {
        dir.join(format!(
            "youki-{}.cell-{}",
            self.youki_sha256, self.cell_sha256
        ))
    }

    /// The verdict recorded for this key, unless `reprove`.
    fn recorded(&self, dir: &std::path::Path, reprove: bool) -> Option<String> {
        if reprove {
            return None;
        }
        std::fs::read_to_string(self.path_in(dir)).ok()
    }

    /// Record `verdict` for this key: written beside its final name and renamed, so a
    /// reader never sees a partial record.
    fn record(&self, dir: &std::path::Path, verdict: &str) {
        std::fs::create_dir_all(dir).expect("the race verdict directory");
        let path = self.path_in(dir);
        let partial = path.with_extension("partial");
        std::fs::write(&partial, verdict).expect("the race verdict is written");
        std::fs::rename(&partial, &path).expect("the race verdict is renamed into place");
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::Digest as _;
    hex::encode(sha2::Sha256::digest(bytes))
}

/// **A recorded race verdict stands only for the bytes and the cell that proved it.**
///
/// Host-free: the key's refused set, on a tempdir. A re-pinned youki (other bytes), an
/// edited cell, or a forced re-proof finds no verdict; only the exact key does.
///
/// Would red if: the key dropped either digest, or `recorded` ignored the force.
#[test]
fn a_race_verdict_stands_only_for_the_bytes_and_the_cell_that_proved_it() {
    let dir = tempfile::tempdir().expect("a verdict tempdir");
    let key = |youki: &str, cell: &str| RaceVerdictKey {
        youki_sha256: youki.to_string(),
        cell_sha256: cell.to_string(),
    };
    key("pinned", "cell").record(dir.path(), "containers=300/300 stranded=0");

    assert_eq!(
        key("pinned", "cell").recorded(dir.path(), false).as_deref(),
        Some("containers=300/300 stranded=0")
    );
    assert_eq!(key("repinned", "cell").recorded(dir.path(), false), None);
    assert_eq!(key("pinned", "edited").recorded(dir.path(), false), None);
    assert_eq!(key("pinned", "cell").recorded(dir.path(), true), None);
    // Exactly one record, and no partial left beside it.
    assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);
}

fn fast_exiting_containers_body() {
    use std::os::unix::fs::PermissionsExt as _;
    use std::process::Stdio;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};

    let test = "fast_exiting_containers_never_strand_the_runtime_client_live";
    let pin = YoukiPin::embedded();
    let payload = static_payload().expect("this host has a statically linked payload");

    let temporary = tempfile::Builder::new()
        .prefix("kata-oci-race-")
        .tempdir()
        .expect("a bundle tempdir");
    let bundle = temporary.path().join("bundle");
    let rootfs = bundle.join("rootfs");
    for dir in ["bin", "proc", "dev"] {
        std::fs::create_dir_all(rootfs.join(dir)).expect("the bundle rootfs");
    }
    // A static `true` (or a multi-call busybox, which dispatches on argv[0]).
    let init = rootfs.join("bin").join("true");
    std::fs::copy(&payload, &init).expect("the static payload copies into the rootfs");
    std::fs::set_permissions(&init, std::fs::Permissions::from_mode(0o755))
        .expect("the payload is executable");
    let config = serde_json::json!({
        "ociVersion": "1.0.2",
        "root": { "path": "rootfs", "readonly": true },
        "process": {
            "args": ["/bin/true"],
            "cwd": "/",
            "terminal": false,
            "user": { "uid": 0, "gid": 0 },
            "env": ["PATH=/bin"],
            "noNewPrivileges": true,
            "capabilities": { "bounding": [], "effective": [], "permitted": [] },
        },
        "mounts": [
            { "destination": "/proc", "type": "proc", "source": "proc" },
            {
                "destination": "/dev",
                "type": "tmpfs",
                "source": "tmpfs",
                "options": ["nosuid", "strictatime", "mode=755", "size=65536k"],
            },
        ],
        "linux": {
            "namespaces": [
                { "type": "pid" }, { "type": "ipc" }, { "type": "uts" },
                { "type": "mount" }, { "type": "user" }, { "type": "cgroup" },
                { "type": "network" },
            ],
            "uidMappings": [
                { "containerID": 0, "hostID": nix::unistd::getuid().as_raw(), "size": 1 },
            ],
            "gidMappings": [
                { "containerID": 0, "hostID": nix::unistd::getgid().as_raw(), "size": 1 },
            ],
        },
    });
    std::fs::write(
        bundle.join("config.json"),
        serde_json::to_string(&config).expect("the config serializes"),
    )
    .expect("config.json is written");

    // PIN every thread of this process to the highest CPU, then start the hogs as
    // threads — created after the pin, so they inherit it — and every `youki run`
    // below inherits it too. `taskset` rather than `sched_setaffinity`: the
    // workspace's `nix` has no `sched` feature.
    let cpu = std::thread::available_parallelism().map_or(1, usize::from) - 1;
    let pinned = Command::new("taskset")
        .args([
            "-a",
            "-p",
            "-c",
            &cpu.to_string(),
            &std::process::id().to_string(),
        ])
        .output()
        .expect("taskset runs");
    assert!(
        pinned.status.success(),
        "{test}: could not pin this process to CPU {cpu}: {}",
        String::from_utf8_lossy(&pinned.stderr)
    );
    let stop = Arc::new(AtomicBool::new(false));
    let hogs: Vec<_> = (0..RACE_HOGS)
        .map(|_| {
            let stop = Arc::clone(&stop);
            std::thread::spawn(move || {
                while !stop.load(Ordering::Relaxed) {
                    std::hint::spin_loop();
                }
            })
        })
        .collect();

    let started = Instant::now();
    let mut stranded = Vec::new();
    let mut ran = 0usize;
    for i in 0..RACE_ITERATIONS {
        if started.elapsed() > RACE_WALL_BUDGET {
            break;
        }
        ran += 1;
        let state = temporary.path().join(format!("state-{i}"));
        let id = format!("kata-oci-race-{}-{i}", std::process::id());
        let _finally = DeleteOnDrop {
            youki: std::path::PathBuf::from(pin.store_path()),
            state: state.clone(),
            id: id.clone(),
        };
        let mut child = Command::new(pin.store_path())
            .arg("--root")
            .arg(&state)
            .args(["run", "--bundle"])
            .arg(&bundle)
            .arg(&id)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap_or_else(|e| panic!("{test}: the pinned youki did not spawn: {e}"));
        match wait_bounded(&mut child, RACE_BUDGET) {
            Some(status) => assert!(
                status.success(),
                "{test}: iteration {i}: `youki run` of a `true` container exited {:?}",
                status.code()
            ),
            None => stranded.push(i),
        }
    }
    stop.store(true, Ordering::Relaxed);
    for hog in hogs {
        let _ = hog.join();
    }

    let verdict = format!(
        "youki={youki} containers={ran}/{RACE_ITERATIONS} stranded={n} cpu={cpu} \
         hogs={RACE_HOGS} budget={b}s elapsed={e}s",
        youki = pin.store_path(),
        n = stranded.len(),
        b = RACE_BUDGET.as_secs(),
        e = started.elapsed().as_secs(),
    );
    println!("OCI-RUNTIME LOST-SIGCHLD {verdict}");
    assert!(
        stranded.is_empty(),
        "{test}: {n} of {ran} `youki run`s of a `true` container did not return \
         within {b}s (iterations {stranded:?}). That is youki 0.7.0's lost-SIGCHLD race — the \
         init exited before `handle_foreground` blocked signals — and the pinned binary \
         `{youki}` does not carry `nix/youki-0.7.0-foreground-prereap.patch` (or a release with \
         upstream c06504aa7e).",
        n = stranded.len(),
        b = RACE_BUDGET.as_secs(),
        youki = pin.store_path(),
    );
    // NON-VACUITY, after the property: a cell that hit its wall budget early ran too
    // few containers to have reproduced a 2% race, and must not read as a pass.
    assert!(
        ran >= RACE_ITERATIONS / 2,
        "{test}: only {ran} of {RACE_ITERATIONS} containers ran inside {}s, too few to have \
         reproduced a ~2% race; this host is too loaded to measure it",
        RACE_WALL_BUDGET.as_secs(),
    );
    // Only a pass is recorded, and only after both assertions held.
    RaceVerdictKey::of(pin).record(&race_verdict_dir(), &verdict);
}

// ---------------------------------------------------------------------------
// youki 0.7.0's torn state.json — the regression cell for the atomic save
// ---------------------------------------------------------------------------

/// **No reader sees a torn `state.json` while `youki start` saves `running`.**
///
/// # The upstream bug
///
/// youki 0.7.0's `State::save` opened `state.json` with `O_TRUNC` and wrote it
/// through a `BufWriter`, and `Container::start` releases the init BEFORE it saves
/// `running`. So a `youki kill`, `state`, `list` or `delete` racing the start could
/// open a 0-byte document and fail on `EOF while parsing` — the race behind the
/// vendor-process signal flake. kata's pin carries
/// `nix/youki-0.7.0-atomic-state-save.patch`, which writes a temporary file, syncs it
/// and renames it into place.
///
/// # The measurement
///
/// `scripts/youki-state-tear-probe.sh` against the pinned binary: one rootless
/// container, `youki start` under strace with every `write(2)` delayed, and three
/// readers inside the delayed state write — the FILE read with `wc`/`jq`, `youki
/// state`, and `youki kill`. The file read shares no youki code; the probe exits 2
/// (`UNPROVEN`) when its trace does not show the reads inside the window, so a
/// timing slip cannot pass. MEASURED 2026-10-30: `TORN` on every run of the
/// previous `gs3ykqgl…` pin (6 of 6; the file 0 bytes, both youki readers `EOF while
/// parsing`), `INTACT` on every run of the patched pin.
///
/// # Would red if
///
/// The pin were rebuilt without the patch, or re-pinned to a release whose save
/// truncates in place.
#[test]
#[ignore = "HOST-DEPENDENT (pinned youki, its installed AppArmor profile, a delegated \
             user scope, strace, jq, a static busybox). `just gate` is host-independent by \
             design, so this rides the containment lane's `oci-live-smoke` step with its \
             siblings. Run it now with `cargo nextest run -p kata-worker -P live-smoke -E \
             'binary(oci_runtime_live)' --run-ignored all`."]
fn a_state_save_is_never_read_torn_live() {
    let pin = YoukiPin::embedded();
    let payload = static_payload().expect("this host has a statically linked payload");
    let probe = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../scripts/youki-state-tear-probe.sh");
    let output = Command::new("bash")
        .arg(&probe)
        .arg(pin.store_path())
        .env("BUSYBOX", &payload)
        .output()
        .expect("the tear probe runs");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let report = format!("{stdout}{}", String::from_utf8_lossy(&output.stderr));
    assert!(
        output.status.success() && stdout.lines().last() == Some("INTACT"),
        "the pinned youki `{}` let a reader see an incomplete state.json during `youki start`'s \
         save (probe exit {:?}; `TORN` is the race, `UNPROVEN` a window the probe could not \
         hold):\n{report}",
        pin.store_path(),
        output.status.code(),
    );
    println!("{report}");
}

/// The variable names of an environment block (`NAME=value`, NUL-separated), sorted.
fn environ_names(block: &[u8]) -> Vec<String> {
    let mut names: Vec<String> = block
        .split(|b| *b == 0)
        .filter(|entry| !entry.is_empty())
        .map(|entry| {
            let name = entry.split(|b| *b == b'=').next().unwrap_or_default();
            String::from_utf8_lossy(name).into_owned()
        })
        .collect();
    names.sort();
    names
}

/// **The certification's runtime invocations keep nothing of the worker's
/// environment but what `systemd-run` needs.**
///
/// The production throwaway launch is driven with a stand-in for the pinned runtime:
/// a shell script that copies the environment it was started with (`/proc/$$/environ`,
/// the kernel's copy of its `execve` block) to a file named for its verb, then `exec`s
/// the real `youki` with the same arguments — so each runtime invocation runs with
/// exactly the recorded environment, and the container still has to run for the
/// launch to succeed. This process's own environment (read from `/proc/self/environ`)
/// holds the re-exec marker and cargo's variables, so an inherited one is not empty.
///
/// `spec` and `delete` are asserted to start with NO variable; `run` — exec'd by
/// `systemd-run --user --scope` — with exactly `PATH` and `XDG_RUNTIME_DIR` from the
/// worker plus `INVOCATION_ID`, which `systemd-run` sets itself (measured), the names
/// spelled here independently of the code under test.
///
/// # Would red if
///
/// `runtime_command` stopped clearing the environment, or the `systemd-run` spawn
/// passed any variable but those two (measured: with both clears absent, every
/// record holds this process's whole environment).
#[test]
#[ignore = "HOST-DEPENDENT (pinned youki, its installed AppArmor profile, a delegated user \
             scope); the containment lane's `oci-live-smoke` step runs it."]
fn the_certification_runtime_keeps_only_the_allowlisted_environment_live() {
    delegated(
        "the_certification_runtime_keeps_only_the_allowlisted_environment_live",
        || {
            use std::os::unix::fs::PermissionsExt as _;
            let own = std::fs::read("/proc/self/environ").expect("this process's environment");
            assert!(
                environ_names(&own).iter().any(|name| name == INNER_ENV),
                "the re-exec marker is not in this process's own environment, so an empty \
                 record would prove nothing: {:?}",
                environ_names(&own),
            );
            let pin = YoukiPin::embedded();
            let record = tempfile::Builder::new()
                .prefix("kata-oci-certify-environ-")
                .tempdir()
                .expect("a record directory");
            let script = record.path().join("youki");
            std::fs::write(
                &script,
                format!(
                    "#!/bin/sh\n/bin/cat /proc/$$/environ > {dir}/environ.$1\nexec {real} \"$@\"\n",
                    dir = record.path().display(),
                    real = pin.store_path(),
                ),
            )
            .expect("the recording runtime is written");
            std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755))
                .expect("the recording runtime is executable");
            run_throwaway_container_with(
                &script,
                &format!("kata-oci-environ-{}", std::process::id()),
                &["true"],
                &["/bin/true"],
                Duration::from_secs(30),
            )
            .unwrap_or_else(|refusal| {
                panic!(
                    "the throwaway container did not run through the recording runtime: {refusal}"
                )
            });
            let names = |verb: &str| {
                environ_names(
                    &std::fs::read(record.path().join(format!("environ.{verb}")))
                        .unwrap_or_else(|e| panic!("`youki {verb}` recorded nothing: {e}")),
                )
            };
            let (spec, run, delete) = (names("spec"), names("run"), names("delete"));
            println!("OCI-CERTIFY ENVIRON spec={spec:?} run={run:?} delete={delete:?}");
            assert_eq!(
                spec,
                Vec::<String>::new(),
                "`youki spec` kept an environment"
            );
            assert_eq!(
                delete,
                Vec::<String>::new(),
                "`youki delete` kept an environment"
            );
            assert_eq!(
                run,
                vec![
                    "INVOCATION_ID".to_owned(),
                    "PATH".to_owned(),
                    "XDG_RUNTIME_DIR".to_owned()
                ],
                "`youki run` under `systemd-run` kept more or other than its two names and \
                 systemd-run's own `INVOCATION_ID`"
            );
        },
    );
}
