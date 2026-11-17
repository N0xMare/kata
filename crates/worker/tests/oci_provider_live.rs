//! The planned bundle started by the
//! external provider kata does NOT link, through a real `ProviderSupervisor`,
//! and every verdict read back from the HOST.
//!
//! # What is different from `oci_bundle_live.rs`, and why both exist
//!
//! That file launches the planned bundle through `oci_runtime::run_bundle` — kata's
//! own linked seam — and asks whether the `config.json` kata plans produces the
//! container kata planned. This file asks the provider question instead: does a
//! PROCESS KATA DOES NOT LINK, handed only the frame, start that same container,
//! answer for it, and leave nothing behind when it is cancelled? The two share the
//! plan producer and nothing else: there is no `run_bundle` here, and the only
//! kata code inside the launching process is `kata-provider-protocol`.
//!
//! # It NEVER SKIPS, and the binary it needs is not a host capability
//!
//! Like its two siblings, every test here FAILS on a host that cannot deliver
//! rootless OCI and names what refused. `kata-provider-youki` is a different kind
//! of prerequisite — it is this workspace's own artifact — so its absence is a
//! panic naming the `cargo build`, never a skip: a proof whose instrument nobody
//! built would be measuring the build.
//!
//! **THE STALE-BINARY TRAP.** `cargo nextest run -p kata-worker` builds the test
//! binary and NOT the provider, so a `target/debug/kata-provider-youki` from an
//! older source tree is what these tests would drive. It is a real trap and not a
//! hypothetical: the provider's refusals are text, so a stale binary fails on the
//! wording of a refusal it no longer has, which reads as a broken assertion rather
//! than as a stale artifact. Build it in the same command:
//!
//! ```text
//! cargo build -p kata-provider-youki --bin kata-provider-youki &&
//!   cargo nextest run -p kata-worker -P live-smoke -E 'binary(oci_provider_live)' --run-ignored all
//! ```
//!
//! # Every test RE-EXECS ITSELF inside a delegated user scope
//!
//! `certify_youki`'s delegation arm measures the CALLING process's own cgroup, and a
//! login session's cgroup is not delegated on this class of host — so without a
//! scope there is no measured basis, and without a basis this provider has nothing
//! admissible to announce. `systemd-run --user --scope -p Delegate=yes` supplies one
//! at zero privilege, which is the same mechanism `oci_runtime_live.rs` already
//! re-execs through. There is no probe and
//! no skip: a host without `systemd-run --user` fails at the spawn, and that is the
//! answer.
//!
//! # What is asserted against something that does not share the code under test
//!
//! * the container's exit status arrives as a `completed` FRAME the provider wrote
//!   and this process decoded — not as a return value;
//! * after a cancellation, `youki list` against the provider's own state root, the
//!   user manager's unit list, the init's cgroup DIRECTORY and `/proc/<init pid>`
//!   are read from the HOST. None of them is produced by kata or by the provider;
//! * after a cancellation that landed BEFORE registration — where there is no pid
//!   to follow — every process on the host is scanned through `/proc/*/cgroup` for
//!   one whose cgroup names the container's scope, so *"nothing survived"* is a
//!   claim about the kernel's answer rather than about the one pid this test knew;
//! * the floor arm reads `/proc/self/status` INSIDE the container — the kernel's
//!   own answer about how many seccomp filters the container's process carries —
//!   and compares the floored arm against the `ProviderFloor::AbsentForProofControl`
//!   arm, so the number is a difference rather than a claim.
//!
//! # Two things this file deliberately does NOT claim
//!
//! 1. **That a floored syscall returns `EPERM` inside the container.** It would,
//!    and the verdict would be UNATTRIBUTABLE: the container runs with empty
//!    capability sets, so `swapon`, `reboot` and every other floor entry a busybox
//!    applet can reach returns `EPERM` from the capability check whether or not the
//!    floor is loaded — the chain stops at `unshare`. The attributable observation
//!    is the FILTER COUNT, and the per-syscall table belongs to
//!    `oci_adversarial_live.rs`, which puts a probe binary in the closure.
//! 2. **That the container's own `linux.seccomp` fence is loaded.** It
//!    IS — the control arm asserts it. MEASURED: one filter in the control
//!    container's own `/proc/self/status` with no kata floor installed, under the
//!    pinned `…-youki-seccomp-0.7.0`. What this file does NOT claim is the
//!    per-syscall table — which entries the kernel refuses — because the filter
//!    COUNT is what a `/proc/self/status` read can attribute. That table is
//!    `crates/worker/tests/oci_adversarial_live.rs`'s A1' row, in a binary whose
//!    closure carries a probe.

//!
//! # One cell drives a FAKE provider through the production DRIVER
//!
//! `the_prepare_budget_is_checked_again_after_the_provider_handshake_live` provisions a
//! shell script as `kata-provider-youki` and drives `OciStageDriver` to the check it pins,
//! which sits after the plan's parent cgroup is created — the only reason it is live. No
//! container runs in it.

#![cfg(target_os = "linux")]

mod common;

use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::time::Duration;

use kata_agent::resource_bounds::{TeardownOutcome, TeardownProbe};
use kata_provider_protocol::{OciBundlePlan, OciMeasuredBasis, PinnedRuntime};
use kata_test_utils::youki_registry::youki_list;
use kata_types::{
    execution_contract::{
        ArtifactId, ArtifactPrivacy, Capsule, CapsuleBudgets, CapsuleNetwork, CapsuleProcess,
        EnvironmentId, GuestAccess, GuestMapping, GuestPath, OccurrenceId, PlatformRef,
        PreparedActionId,
    },
    nix_environment::{
        ClosureEntry, IntegrityPolicy, NarVerification, NixEnvironmentManifest, Provenance,
        RetentionClass, RetentionIntent, StorePath,
    },
    primitives::ContentHash,
    sandbox::NetPolicy,
    youki_pin::YoukiPin,
};
use kata_worker::oci_bundle::{BundleMounts, spec_for};
use kata_worker::oci_cgroup::{AttemptContainment, CONTAINER_LEAF, OciParentCgroup};
use kata_worker::oci_runtime::certify_youki;
use kata_worker::provider_supervisor::{
    ProviderFloor, ProviderLaunchSpec, ProviderSupervisor, StageAssignment,
    measured_basis_from_certification,
};

/// The same real store path the golden and `oci_bundle_live.rs` name. One
/// statically linked busybox is the whole closure.
const BUSYBOX: &str =
    "/nix/store/qddzvnv6b0805nkvbqddbswddcfhx814-busybox-static-x86_64-unknown-linux-musl-1.37.0";
const BUSYBOX_NAR_HASH: &str = "sha256-d7JNm1d4Wo1oSA2pvoRLt1vqyAhSlIsjE0GckcLiSeA=";
const BUSYBOX_NAR_SIZE: u64 = 1_495_056;

/// The provider an operator would declare, and the binary it resolves to.
const PROVIDER: &str = "youki";

fn hash(byte: u8) -> ContentHash {
    ContentHash::new([byte; 32])
}

fn environment() -> NixEnvironmentManifest {
    NixEnvironmentManifest::new(
        "provider-live-busybox",
        PlatformRef::new("x86_64-linux", hash(11)),
        Provenance::StorePaths {
            nixpkgs_attribute: "nixpkgs#pkgsStatic.busybox".into(),
        },
        vec![StorePath::new(BUSYBOX).expect("a real store path")],
        vec![ClosureEntry {
            store_path: StorePath::new(BUSYBOX).expect("a real store path"),
            nar_hash: BUSYBOX_NAR_HASH.into(),
            nar_size: BUSYBOX_NAR_SIZE,
            references: vec![],
            ca: None,
        }],
        vec![GuestPath::new(format!("{BUSYBOX}/bin")).expect("the closure's bin directory")],
        IntegrityPolicy {
            verify: NarVerification::NarHashAndSignatures,
            sigs_needed: 1,
            required_signers: vec!["cache.nixos.org-1".into()],
            allow_unsigned_content_addressed: false,
            verify_contents_at_declare: false,
        },
        ArtifactPrivacy::Public,
        RetentionIntent {
            class: RetentionClass::Cache,
        },
        "nix-store --realise",
    )
    .expect("the fixture environment is well formed")
}

fn mapping(path: &str, access: GuestAccess, artifact: u8) -> GuestMapping {
    GuestMapping {
        artifact: ArtifactId(hash(artifact)),
        guest_path: GuestPath::new(path.to_owned()).expect("a guest path"),
        access,
    }
}

/// `occurrence` varies per container so the ids differ: `container_id` is derived
/// from the capsule's content address, and a runtime holding a container under that
/// name refuses the next `run` on a collision.
fn capsule(occurrence: u8, argv: &[&str]) -> Capsule {
    capsule_with_output_bytes(occurrence, argv, 1 << 20)
}

/// [`capsule`], with the COMBINED capture bound the author promised — v6's
/// `CaptureSpec::limit_bytes` is read off it by the drivers.
fn capsule_with_output_bytes(occurrence: u8, argv: &[&str], output_bytes: u64) -> Capsule {
    Capsule::new(
        OccurrenceId(hash(occurrence)),
        PreparedActionId(hash(2)),
        EnvironmentId(hash(3)),
        PlatformRef::new("x86_64-linux", hash(11)).id(),
        vec![
            mapping("/work", GuestAccess::ReadWrite, 20),
            mapping("/out", GuestAccess::ReadWrite, 21),
            mapping("/tmp", GuestAccess::ReadWrite, 22),
            mapping(BUSYBOX, GuestAccess::ReadOnly, 23),
        ],
        CapsuleProcess::Command {
            argv: argv.iter().copied().map(smol_str::SmolStr::new).collect(),
        },
        CapsuleNetwork::Offline,
        None,
        CapsuleBudgets {
            wall_time_ms: 30_000,
            output_bytes,
            memory_bytes: 512 * 1024 * 1024,
            process_count: 64,
            result_bytes: 4 * 1024 * 1024,
            result_entries: 128,
            work_delta_bytes: kata_types::execution_contract::CAPSULE_WORK_DELTA_BYTES,
            work_delta_entries: kata_types::execution_contract::CAPSULE_WORK_DELTA_ENTRIES,
        },
        None,
    )
    .expect("the fixture capsule is well formed")
}

/// One container's inputs on disk, alive until after teardown.
struct Staged {
    _root: tempfile::TempDir,
    /// The KATA-OWNED parent cgroup this container's leaf is created beneath, held
    /// for the run's lifetime. Its `Drop` removes the two directories, so dropping
    /// it early would `rmdir` the cgroup the container is living in.
    parent: OciParentCgroup,
    out: PathBuf,
    plan: OciBundlePlan,
    /// The capture spec handed to the assignment — `<attempt>/capture`, created
    /// EMPTY by the supervisor, bounded combined at the capsule's `output_bytes`.
    /// v6: the completion frame reports only sizes; the bytes are in these files.
    capture: kata_provider_protocol::CaptureSpec,
}

impl Staged {
    /// The text a completion reports only the SIZE of — read it off the spool
    /// file the provider wrote, which is where the bytes live.
    fn spooled(&self, stream: &str) -> String {
        std::fs::read_to_string(std::path::Path::new(&self.capture.spool_dir).join(stream))
            .expect("the provider spooled the stream")
    }

    /// Where the provider puts this container's bundle and runtime state — derived
    /// here the same way the provider derives it, and read as a HOST fact
    /// afterwards. A rig that asked the provider where it wrote would be taking the
    /// subject's word for the one thing the teardown assertions are about.
    fn runtime_state(&self) -> PathBuf {
        Path::new(&self.plan.state_root)
            .join(&self.plan.container_id)
            .join("state")
    }

    /// The directory the provider writes this container's bundle and captures into.
    fn home(&self) -> PathBuf {
        Path::new(&self.plan.state_root).join(&self.plan.container_id)
    }

    /// The cgroup the RUNTIME will create for the container, derived from the parent
    /// kata owns. Asserted against `/proc/<init>/cgroup`, which is the kernel's
    /// answer rather than this rig's.
    fn leaf(&self) -> PathBuf {
        self.parent.leaf()
    }

    /// The same leaf as `linux.cgroupsPath` spells it — absolute, relative to the
    /// cgroup v2 mount point. This is the text inside `config_json`, which is what a
    /// rig doctoring the placement has to match.
    fn leaf_in_hierarchy(&self) -> PathBuf {
        Path::new("/").join(
            self.leaf()
                .strip_prefix("/sys/fs/cgroup")
                .expect("the leaf is beneath the cgroup root"),
        )
    }
}

/// Plan a container for `argv` and put its `/work`, `/out` and attempt root on
/// disk. **The bundle is NOT written here** — writing it is the provider's job, and
/// this file never touches `config.json`.
///
/// `sweep_root` is the SUPERVISOR's own outer cgroup, read off the live supervisor
/// rather than composed here: the whole point of the placement is that the
/// container's leaf is inside the subtree `ProviderSupervisor::contain` sweeps, and
/// a rig that invented a parent of its own would be asserting about a subtree the
/// supervisor never looks at.
fn stage(sweep_root: &Path, occurrence: u8, argv: &[&str]) -> Staged {
    stage_bounded(sweep_root, occurrence, argv, 1 << 20)
}

/// [`stage`], with the COMBINED capture bound carried to the spool.
fn stage_bounded(sweep_root: &Path, occurrence: u8, argv: &[&str], output_bytes: u64) -> Staged {
    assert!(
        Path::new(BUSYBOX).join("bin/busybox").is_file(),
        "the closure's only store object is not realised at {BUSYBOX}. The container rbinds that \
         exact path and execs the binary inside it, so there is nothing to observe without it. \
         Realise it with `nix-store --realise {BUSYBOX}`."
    );
    let root = tempfile::Builder::new()
        .prefix("kata-oci-provider-live-")
        .tempdir()
        .expect("creating the staging tempdir");
    let attempt = root.path().join("attempt");
    let mounts = BundleMounts::under(&attempt, 16 * 1024 * 1024)
        .expect("an absolute attempt root with a non-zero /tmp size");
    let out = mounts.out().to_path_buf();
    for directory in [mounts.work(), mounts.out()] {
        std::fs::create_dir_all(directory).expect("creating a materialized root");
    }
    // THE KATA-OWNED PARENT, created inside the supervisor's own sweep root and
    // populated from the capsule's budgets by the production producer.
    let capsule = capsule_with_output_bytes(occurrence, argv, output_bytes);
    let delegation = kata_worker::sandbox_bounds::cgroup_delegation();
    let container_id = format!("kata-{}", capsule.id().0);
    let parent =
        OciParentCgroup::establish(sweep_root, &container_id, delegation, &capsule.budgets())
            .unwrap_or_else(|e| {
                panic!(
                    "the kata-owned parent cgroup under the supervisor's sweep root {} could not \
                     be established: {e}. Without it there is no placement to plan and every \
                     teardown assertion below would be about youki's own transient scope.",
                    sweep_root.display(),
                )
            });
    let containment = AttemptContainment::new(parent.path().to_path_buf(), attempt.join("oci"))
        .expect("the parent is beneath the cgroup root and the state root is absolute");
    let plan = spec_for(
        &capsule,
        &environment(),
        &mounts,
        &containment,
        NetPolicy::Offline,
        None,
    )
    .expect("the staged capsule plans");
    assert_eq!(
        plan.container_id, container_id,
        "the rig derived the container id the same way the producer does; a divergence would name \
         the parent cgroup after a container that is not the one started"
    );
    Staged {
        _root: root,
        parent,
        out,
        plan,
        capture: kata_provider_protocol::CaptureSpec {
            spool_dir: attempt.join("capture").to_string_lossy().into_owned(),
            limit_bytes: capsule.budgets().output_bytes,
        },
    }
}

/// The supervisor's own outer cgroup, or the panic that says why there is nothing
/// to place a container inside of.
///
/// Read off the LIVE supervisor rather than derived: `outer_cgroup_bounds` names it
/// from the measured delegation and this process's pid, and a rig that recomputed
/// that would pass while the supervisor swept somewhere else.
fn sweep_root(supervisor: &ProviderSupervisor, test: &str) -> PathBuf {
    supervisor.outer_cgroup().map_or_else(
        || {
            panic!(
                "{test}: the supervisor established NO outer cgroup, so there is no subtree kata \
                 sweeps and nowhere to place the container. The teardown probe reads \
                 that subtree's population; without one this host cannot prove containment at \
                 all — see `just _containment-preconditions`."
            )
        },
        Path::to_path_buf,
    )
}

/// Marks the re-exec'd inner run, carrying the NAME of the test that asked for it —
/// one variable rather than one per test, so the child can never run a different body
/// than the parent selected.
const INNER_ENV: &str = "KATA_OCI_PROVIDER_DELEGATED_INNER";

/// Run an async `body` inside a delegated user scope, re-exec'ing this binary if
/// needed.
///
/// Deliberately re-spelled rather than shared with `oci_runtime_live.rs`' `delegated`:
/// that one takes a `fn()` and every body here is `async` (a `ProviderSupervisor` is
/// spawned and awaited), so the runtime is built INSIDE the scope. The duplication is
/// a dozen lines of rig and is named here so a reader finds the sibling; the thing
/// that must not be duplicated — what a delegated scope IS — is one `systemd-run`
/// argv in both, and `_containment-preconditions` blocks the lane on the same fact.
fn delegated<F>(test: &'static str, body: F)
where
    F: std::future::Future<Output = ()>,
{
    if std::env::var(INNER_ENV).as_deref() == Ok(test) {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .expect("a tokio runtime inside the delegated scope")
            .block_on(body);
        return;
    }
    let exe = std::env::current_exe().expect("the test binary's own path");
    let output = std::process::Command::new("systemd-run")
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
        // Every inner run holds a planted `env:`-shaped key in the environment of the
        // process that launches the provider — the worker's role in this rig. The
        // environment cell reads it out of `/proc`; the others never look.
        .env(CREDENTIAL_WITNESS_VAR, CREDENTIAL_WITNESS_VALUE)
        .output()
        .unwrap_or_else(|error| {
            panic!(
                "re-exec of `{test}` inside `systemd-run --user --scope -p Delegate=yes` could not \
                 be spawned ({error}). A delegated scope is what lets an unprivileged process \
                 write a cgroup limit, and without one this host cannot certify the rootless-OCI \
                 prerequisite at all — see `just _containment-preconditions`."
            )
        });
    eprintln!(
        "--- delegated inner run of `{test}` stdout ---\n{}\n--- stderr ---\n{}\n---",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    kata_test_utils::delegated_scope::assert_inner_ran_the_one_test(test, &output);
}

/// Locate a workspace binary next to the current test binary — the same walk the
/// sibling provider rigs use.
fn workspace_bin(name: &str) -> PathBuf {
    let exe = std::env::current_exe().expect("the test binary has a path");
    let mut cur = exe.parent();
    while let Some(dir) = cur {
        let candidate = dir.join(name);
        if candidate.is_file() {
            common::require_current_provider_protocol("provider rig", name, &candidate);
            return candidate;
        }
        if dir.file_name().and_then(|n| n.to_str()) == Some("target") {
            break;
        }
        cur = dir.parent();
    }
    panic!(
        "`{name}` is not next to the test binary, and it IS the instrument of this proof — there \
         is nothing to observe without it. `cargo nextest run -p kata-worker` does NOT build it. \
         Run `cargo build -p kata-provider-youki --bin kata-provider-youki` in the same command, \
         which is also what keeps a STALE one from being driven."
    );
}

/// Kata's own measurement of this host's rootless-OCI mechanism.
///
/// The real thing, from `certify_youki`: it is what the provider's certificate must
/// restate byte for byte, so a rig that supplied a synthetic basis would be
/// comparing kata's fixture with the provider's echo of kata's fixture and would
/// never touch the producer. A host that cannot certify fails HERE, naming the
/// refusal, which is the same no-skip rule the two sibling live files hold.
fn measured_basis() -> OciMeasuredBasis {
    let certification = certify_youki(YoukiPin::embedded()).unwrap_or_else(|refusal| {
        panic!(
            "this host cannot deliver the rootless-OCI prerequisite, so there is no measured basis \
             for a provider to quote and no container to start: {refusal}. `just \
             _containment-preconditions` gives the one-line diagnosis. There is no skip here on \
             purpose."
        )
    });
    measured_basis_from_certification(&certification)
}

/// A launch spec for the OCI provider: the production spec plus the basis kata
/// measured, with tight budgets so a hang fails in seconds.
fn launch_spec(binary: &Path, floor: ProviderFloor, basis: OciMeasuredBasis) -> ProviderLaunchSpec {
    let mut spec =
        ProviderLaunchSpec::production(binary.to_path_buf(), PROVIDER, Duration::from_secs(90));
    spec.floor = floor;
    spec.measured_basis = Some(basis);
    spec.handshake_timeout = Duration::from_secs(30);
    spec.stage_timeout = Duration::from_secs(90);
    spec
}

/// The assignment for a staged container: its id and the staged capture spool.
fn assignment<'a>(id: &'a str, staged: &'a Staged) -> StageAssignment<'a> {
    StageAssignment {
        assignment_id: id,
        capture: &staged.capture,
    }
}

/// `youki list`, polled until it reports a `Running` container or [`RUNNING_BOUND`]
/// passes; returns the LAST listing either way, so a caller's assertion states what the
/// runtime actually said.
///
/// Polled because a container's init pid appears in the runtime's state at CREATE, and
/// `Running` follows only once the start completes: a single read right after the pid
/// appears races the runtime rather than observing it.
async fn youki_list_once_running(state: &Path) -> String {
    let mut listed = youki_list(state);
    let deadline = std::time::Instant::now() + RUNNING_BOUND;
    while !listed.contains("Running") && std::time::Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(100)).await;
        listed = youki_list(state);
    }
    listed
}

/// How long a created container is given to reach `Running` before a cell calls it
/// not running.
const RUNNING_BOUND: Duration = Duration::from_secs(10);

/// The transient scopes the user manager currently holds for youki containers.
fn youki_scopes() -> String {
    let output = std::process::Command::new("systemctl")
        .args([
            "--user",
            "list-units",
            "--type=scope",
            "--all",
            "--no-legend",
        ])
        .output()
        .expect("systemctl --user lists units");
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter(|line| line.contains("youki-"))
        .collect::<Vec<_>>()
        .join("\n")
}

/// Every process on this host whose cgroup line names the container's own leaf, read
/// out of `/proc/*/cgroup`.
///
/// # Why a cgroup scan and not a pid
///
/// The registration-race arm cancels before any container init has been OBSERVED,
/// so there is no pid to follow — and that is the whole point of it: the survivor
/// this arm is hunting is one this test never saw. The kernel's own per-process
/// cgroup line names the container's cgroup for every descendant the runtime forked,
/// whatever its pid, and a scan of it is therefore the only observation that can
/// say NOTHING survived rather than *"the pid I happened to know about is gone"*.
///
/// The needle is the leaf kata PLANNED rather than a scope name the runtime would
/// have chosen: the container lives where kata put it.
fn processes_in_container_subtree(leaf: &Path) -> Vec<String> {
    let needle = leaf
        .strip_prefix("/sys/fs/cgroup")
        .expect("the leaf is beneath the cgroup root")
        .to_str()
        .expect("the leaf path is UTF-8")
        .to_owned();
    let needle = format!("/{}", needle.trim_start_matches('/'));
    let Ok(entries) = std::fs::read_dir("/proc") else {
        return Vec::new();
    };
    let mut found = Vec::new();
    for entry in entries.flatten() {
        let path = entry.path();
        let Some(pid) = path.file_name().and_then(OsStr::to_str) else {
            continue;
        };
        if !pid.chars().all(|c| c.is_ascii_digit()) {
            continue;
        }
        // A process that exits between the read_dir and the read is simply gone,
        // which is the answer this function is looking for — so an unreadable entry
        // is skipped rather than reported.
        if std::fs::read_to_string(path.join("cgroup")).is_ok_and(|c| c.contains(&needle)) {
            let cmdline = std::fs::read_to_string(path.join("cmdline")).unwrap_or_default();
            found.push(format!(
                "{pid} {}",
                cmdline.replace('\0', " ").trim().to_owned()
            ));
        }
    }
    found
}

/// **THE EXIT CRITERION, first half: the provider kata does not link starts the
/// planned container and answers for it.**
///
/// `busybox true` — the cheapest possible subject, and the control for every arm
/// below: if this reds, the cause is the launch, and the cancellation and refusal
/// arms cannot be read as evidence about anything.
///
/// # Would red if
///
/// The provider re-serialized `config.json`, resolved a path of its own, refused a
/// plan it must apply, dropped the exit status, or never wrote a terminal frame.
#[test]
#[ignore = "HOST-DEPENDENT (pinned youki, its installed AppArmor \
             profile, a delegated user scope, the fixture closure's store path realised) AND \
             instrument-dependent (`cargo build -p kata-provider-youki`). `just gate` is \
             host-independent by design, so this rides the containment side like its two \
             siblings; the containment lane's `oci-live-smoke` step runs it. Run it now \
             with `cargo build -p kata-provider-youki --bin kata-provider-youki && cargo nextest \
             run -p kata-worker -P live-smoke -E 'binary(oci_provider_live)' --run-ignored all`."]
fn the_youki_provider_starts_the_planned_container_live() {
    delegated(
        "the_youki_provider_starts_the_planned_container_live",
        the_youki_provider_starts_the_planned_container_body(),
    );
}

async fn the_youki_provider_starts_the_planned_container_body() {
    let test = "the_youki_provider_starts_the_planned_container_live";
    let binary = workspace_bin("kata-provider-youki");
    let basis = measured_basis();

    // The SUPERVISOR FIRST, because the placement is inside ITS cgroup: the
    // container's leaf goes under a parent kata creates in the supervisor's own
    // sweep root, so there is no plan to make until that root exists.
    let mut supervisor = ProviderSupervisor::launch(&launch_spec(
        &binary,
        ProviderFloor::Installed,
        basis.clone(),
    ))
    .await
    .unwrap_or_else(|e| panic!("{test}: launching the OCI provider failed: {e}"));
    let root = sweep_root(&supervisor, test);
    let staged = stage(&root, 31, &[&format!("{BUSYBOX}/bin/busybox"), "true"]);
    assert_eq!(
        supervisor.admitted().certificate().measured_basis.as_ref(),
        Some(&basis),
        "{test}: the provider was admitted on a certificate that must RESTATE what \
         `certify_youki` measured, byte for byte. This is the measured basis's whole \
         mechanism: a `provider_enforced` claim is admissible only as an echo of kata's own \
         measurement"
    );

    let outcome = supervisor
        .run_stage(assignment("oci-true", &staged), staged.plan.clone())
        .await
        .unwrap_or_else(|e| {
            panic!(
                "{test}: the provider did not run the planned container: {e}. Every containment \
                 property of that container is kata's — the provider writes `config.json`'s bytes \
                 unchanged — so a failure here is the HANDOFF and not the plan, which \
                 `oci_bundle_live.rs` runs through kata's own seam."
            )
        });
    assert_eq!(
        outcome.accepted.assignment_id, "oci-true",
        "{test}: the acceptance must be about the assignment kata sent"
    );
    assert_eq!(
        outcome.completed.exit_code,
        Some(0),
        "{test}: the container's exit status arrives as a `completed` frame the provider wrote \
         and this process decoded.\nstdout: {out}\nstderr: {err}",
        out = staged.spooled("stdout"),
        err = staged.spooled("stderr"),
    );
    assert!(
        !outcome.completed.capture_exceeded,
        "{test}: `busybox true` writes nothing, so a truncation flag here means the capture bound \
         is being applied to the wrong bytes"
    );

    // THE FINALLY, read from the host: `delete --force` runs unconditionally, so the
    // runtime holds no container under this id even after a clean exit. Without it the
    // NEXT run on this host fails on a name collision rather than on the fact it measures.
    let listing = youki_list(&staged.runtime_state());
    assert!(
        !listing.contains(&staged.plan.container_id),
        "{test}: the runtime still holds `{id}` after a clean exit. `youki delete --force` is the \
         provider's unconditional finally, and a container left registered is state kata cannot \
         see and did not ask for.\n{listing}",
        id = staged.plan.container_id,
    );
    let _ = supervisor.shutdown().await;

    println!(
        "OCI-PROVIDER live-provider container={id} exit=0 bundle-bytes={bytes} \
         basis-youki={youki} basis-probe={probe} registered-after-exit=0",
        id = staged.plan.container_id,
        bytes = staged.plan.config_json.len(),
        youki = basis.youki.sha256,
        probe = basis.functional_probe_id,
    );
}

/// **THE EXIT CRITERION, second half: a CANCELLED assignment leaves nothing
/// behind, and the host says so.**
///
/// The container sleeps for five minutes; kata cancels with `SIGTERM` after the
/// container's init is observed running, and then four independent host facts must
/// all say it is gone: `youki list` against the provider's own state root, the user
/// manager's scope list, the init's `/proc` entry, and the cgroup directory the
/// init was in (captured from `/proc/<pid>/cgroup` BEFORE the cancellation, so the
/// path is the kernel's own and not one this test composed).
///
/// # The baseline this arm was watched to FAIL from
///
/// With the provider's teardown reduced to killing the runtime CLIENT — the obvious
/// implementation — the container stays `Running`: MEASURED by hand on the reference
/// host before the teardown was written (`SIGKILL` on the `youki run` client left
/// `youki list` reporting `Running` and the `sleep 300` alive in
/// `youki-<id>.scope`), and again by deleting the `youki kill` and the
/// `delete --force` from `cancel` and watching every assertion below red. The order
/// is the whole lesson: the container's own transient scope is
/// not the client's cgroup, so the client's death reaches nothing.
///
/// # Would red if
///
/// The provider dropped its `SIGTERM` handler (it would die with the container
/// running), killed the client before the container, skipped `delete --force`, or
/// reported the cancellation as an ordinary exit code — `youki run` exits with the
/// container's SIGNAL NUMBER, which would be indistinguishable from a stage that
/// exited 9 on its own.
#[test]
#[ignore = "HOST-DEPENDENT (pinned youki, its installed AppArmor \
             profile, a delegated user scope, the fixture closure's store path realised) AND \
             instrument-dependent (`cargo build -p kata-provider-youki`). `just gate` is \
             host-independent by design, so this rides the containment side like its two \
             siblings; the containment lane's `oci-live-smoke` step runs it. Run it now \
             with `cargo build -p kata-provider-youki --bin kata-provider-youki && cargo nextest \
             run -p kata-worker -P live-smoke -E 'binary(oci_provider_live)' --run-ignored all`."]
fn a_cancelled_assignment_leaves_no_container_behind_live() {
    delegated(
        "a_cancelled_assignment_leaves_no_container_behind_live",
        a_cancelled_assignment_leaves_no_container_behind_body(),
    );
}

async fn a_cancelled_assignment_leaves_no_container_behind_body() {
    let test = "a_cancelled_assignment_leaves_no_container_behind_live";
    let binary = workspace_bin("kata-provider-youki");
    let mut supervisor = ProviderSupervisor::launch(&launch_spec(
        &binary,
        ProviderFloor::Installed,
        measured_basis(),
    ))
    .await
    .unwrap_or_else(|e| panic!("{test}: launching the OCI provider failed: {e}"));
    let provider_pid = supervisor
        .provider_pid()
        .unwrap_or_else(|| panic!("{test}: kata observed no pid for the provider it spawned"));
    let root = sweep_root(&supervisor, test);
    let staged = stage(
        &root,
        37,
        &[&format!("{BUSYBOX}/bin/busybox"), "sh", "-c", "sleep 300"],
    );

    // The SPLIT path, for the crash proof's reason one plane over: a cancellation
    // can only be observed against an assignment that is in flight, and `run_stage`
    // returns only after the terminal frame.
    supervisor
        .assign_stage(assignment("oci-sleep", &staged), staged.plan.clone())
        .await
        .unwrap_or_else(|e| panic!("{test}: the provider did not accept the assignment: {e}"));

    let state = staged.runtime_state();
    let appeared = tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            if let Some(pid) = container_init_pid(&state, &staged.plan.container_id)
                && let Ok(cgroup) = std::fs::read_to_string(format!("/proc/{pid}/cgroup"))
            {
                return (pid, cgroup.trim().to_owned());
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await;
    let Ok((init_pid, init_cgroup)) = appeared else {
        // The provider has almost certainly already ANSWERED — a container that
        // refused to start, or a plan it declined — and that answer is the finding.
        // Reading it is what keeps this panic from being "something did not
        // happen": a bare timeout here sent a reader hunting for a race that was
        // really a refusal.
        let said = supervisor.await_stage_completion("oci-sleep").await;
        panic!(
            "{test}: no container init appeared under the provider's state root ({state}) within \
             30s, so there is nothing for the cancellation to clean up and every assertion below \
             would pass against an empty host. What the provider said instead: {said:?}",
            state = state.display(),
        );
    };
    // NON-VACUITY, from the host: the container really is running before it is cancelled.
    let before = youki_list_once_running(&state).await;
    assert!(
        before.contains("Running"),
        "{test}: the runtime does not report a RUNNING container within {RUNNING_BOUND:?} of \
         its init appearing, before the cancellation. Last listing:\n{before}"
    );
    let scope_path = init_cgroup.rsplit_once(':').map_or_else(
        || panic!("{test}: /proc/{init_pid}/cgroup is not a cgroup v2 line: {init_cgroup}"),
        |(_, path)| PathBuf::from("/sys/fs/cgroup").join(path.trim_start_matches('/')),
    );
    assert_eq!(
        scope_path,
        staged.leaf(),
        "{test}: the container's init is not in the leaf kata PLANNED under its own parent. \
         That is the premise of every teardown claim on this route, and the \
         two shapes it could be instead are both leaks: youki's own transient \
         `youki-<id>.scope` (what `linux.cgroupsPath` unset produces) and a systemd slice from a \
         `slice:prefix:name` path — neither is a subtree kata sweeps.\n/proc/{init_pid}/cgroup: \
         {init_cgroup}"
    );
    assert!(
        scope_path.is_dir(),
        "{test}: the init's cgroup directory {} does not exist before the cancellation, so its \
         absence afterwards would prove nothing",
        scope_path.display()
    );

    // THE CANCELLATION. `SIGTERM` rather than closing stdin, because this arm needs
    // the provider to survive long enough to ANSWER: a provider that dies with the
    // container running is the residue nobody looks at, and the frame is how kata
    // learns which of the two happened.
    nix::sys::signal::kill(
        nix::unistd::Pid::from_raw(i32::try_from(provider_pid).expect("a pid fits in pid_t")),
        nix::sys::signal::Signal::SIGTERM,
    )
    .unwrap_or_else(|e| panic!("{test}: could not SIGTERM the provider: {e}"));

    let completed = supervisor
        .await_stage_completion("oci-sleep")
        .await
        .unwrap_or_else(|e| {
            panic!(
                "{test}: the cancelled provider produced no terminal frame: {e}. A provider that \
                 exits instead of answering is a crash, and the container it was holding would be \
                 the residue nobody looked at."
            )
        });
    assert_eq!(
        completed.exit_code,
        None,
        "{test}: a cancellation must be reported as a SIGNAL DEATH and not as an exit code. \
         `youki run` exits with the container's signal NUMBER when its init is killed, so a \
         `Some(9)` here is indistinguishable from a stage that exited 9 on its own.\nstderr: {err}",
        err = staged.spooled("stderr"),
    );

    // ---- four host facts, none of them produced by kata or by the provider ----
    let after = youki_list(&state);
    assert!(
        !after.contains(&staged.plan.container_id),
        "{test}: the runtime still holds `{id}` after the cancellation:\n{after}",
        id = staged.plan.container_id,
    );
    let scopes = youki_scopes();
    assert!(
        !scopes.contains(&staged.plan.container_id),
        "{test}: the user manager holds a transient scope for `{id}`. With a kata-owned \
         `linux.cgroupsPath` the runtime creates no scope AT ALL, so one here means the placement \
         was ignored and the container is somewhere kata does not sweep.\n{scopes}",
        id = staged.plan.container_id,
    );
    assert!(
        !scope_path.exists(),
        "{test}: the container's cgroup directory {path} survives the cancellation, so the \
         subtree kata's stage ran in was never reaped",
        path = scope_path.display(),
    );
    let init_alive =
        std::fs::read_to_string(format!("/proc/{init_pid}/cgroup")).is_ok_and(|cgroup| {
            cgroup.contains(
                staged
                    .leaf()
                    .strip_prefix("/sys/fs/cgroup")
                    .expect("the leaf is beneath the cgroup root")
                    .to_str()
                    .expect("the leaf path is UTF-8"),
            )
        });
    assert!(
        !init_alive,
        "{test}: the container's init (pid {init_pid}) is still alive in the container's scope. \
         The cgroup membership is re-read rather than the bare /proc entry, so a recycled pid \
         cannot pass for the stage."
    );

    let _ = supervisor.shutdown().await;
    println!(
        "OCI-PROVIDER CANCELLATION container={id} init-pid={init_pid} \
         scope={scope} reported-exit=None(signal) registered-after=0 scope-after=absent \
         cgroup-dir-after=absent init-after=gone",
        id = staged.plan.container_id,
        scope = scope_path.display(),
    );
}

/// **A cancellation that lands BEFORE the container is registered still leaves
/// nothing behind.**
///
/// The sibling arm above cancels a container it has OBSERVED running. This one
/// cancels in the window between `spawn` and registration — `SIGTERM` is sent as
/// soon as the acceptance frame is read, with no wait for an init — which is the
/// window a single `youki kill` cannot cover: it fails (there is nothing to resolve
/// yet), and a provider that then `SIGKILL`ed the runtime client would kill it
/// MID-CREATE, leaving `delete --force` with no state to clear and whatever the
/// runtime had already forked alive with nothing watching it.
///
/// # The observation is a CGROUP SCAN, because there is no pid to follow
///
/// This arm never sees an init, so it cannot assert about one. `/proc/*/cgroup` is
/// read for every process on the host and any process whose cgroup names
/// `youki-<id>.scope` is a survivor — whatever its pid, and whether or not this test
/// ever knew it existed. `youki list` and the user manager's scope list are read too,
/// so the runtime's own registry, systemd's and the kernel's all have to agree that
/// nothing is left.
///
/// # Would red if
///
/// The kill were not retried until it reached the container. **MEASURED:** with the
/// loop in `cancel` reduced to a single `youki kill`, this arm reds — the scope and
/// the stage survive. It is a RACE arm, so it can also pass without the race ever
/// occurring; the printed line below is what says how far the cancellation got.
#[test]
#[ignore = "HOST-DEPENDENT (pinned youki, its installed AppArmor \
             profile, a delegated user scope, the fixture closure's store path realised) AND \
             instrument-dependent (`cargo build -p kata-provider-youki`). `just gate` is \
             host-independent by design, so this rides the containment side like its two \
             siblings; the containment lane's `oci-live-smoke` step runs it. Run it now \
             with `cargo build -p kata-provider-youki --bin kata-provider-youki && cargo nextest \
             run -p kata-worker -P live-smoke -E 'binary(oci_provider_live)' --run-ignored all`."]
fn a_cancellation_before_the_container_is_registered_leaves_nothing_behind_live() {
    delegated(
        "a_cancellation_before_the_container_is_registered_leaves_nothing_behind_live",
        a_cancellation_before_the_container_is_registered_leaves_nothing_behind_body(),
    );
}

async fn a_cancellation_before_the_container_is_registered_leaves_nothing_behind_body() {
    let test = "a_cancellation_before_the_container_is_registered_leaves_nothing_behind_live";
    let binary = workspace_bin("kata-provider-youki");
    let mut supervisor = ProviderSupervisor::launch(&launch_spec(
        &binary,
        ProviderFloor::Installed,
        measured_basis(),
    ))
    .await
    .unwrap_or_else(|e| panic!("{test}: launching the OCI provider failed: {e}"));
    let provider_pid = supervisor
        .provider_pid()
        .unwrap_or_else(|| panic!("{test}: kata observed no pid for the provider it spawned"));
    let root = sweep_root(&supervisor, test);
    let staged = stage(
        &root,
        61,
        &[&format!("{BUSYBOX}/bin/busybox"), "sh", "-c", "sleep 300"],
    );

    supervisor
        .assign_stage(assignment("oci-race", &staged), staged.plan.clone())
        .await
        .unwrap_or_else(|e| panic!("{test}: the provider did not accept the assignment: {e}"));

    // NO WAIT. The acceptance frame is written before the provider has spawned the
    // runtime at all, so this `SIGTERM` lands in the create window on any host where
    // the window exists.
    nix::sys::signal::kill(
        nix::unistd::Pid::from_raw(i32::try_from(provider_pid).expect("a pid fits in pid_t")),
        nix::sys::signal::Signal::SIGTERM,
    )
    .unwrap_or_else(|e| panic!("{test}: could not SIGTERM the provider: {e}"));

    let completed = supervisor
        .await_stage_completion("oci-race")
        .await
        .unwrap_or_else(|e| {
            panic!(
                "{test}: the provider produced no terminal frame after a cancellation that landed \
                 during create: {e}. A provider that exits instead of answering here is the worst \
                 case of this race — it died mid-create AND said nothing."
            )
        });
    assert_eq!(
        completed.exit_code,
        None,
        "{test}: a cancellation is reported as a signal death whether it landed before or after \
         registration.\nstderr: {err}",
        err = staged.spooled("stderr"),
    );

    // The provider gets its own teardown grace before the HOST is asked, so the three
    // reads below are about a settled host rather than about a provider still working.
    let _ = supervisor.shutdown().await;

    let state = staged.runtime_state();
    let listing = youki_list(&state);
    assert!(
        !listing.contains(&staged.plan.container_id),
        "{test}: the runtime still holds `{id}` after a cancellation during create:\n{listing}",
        id = staged.plan.container_id,
    );
    let scopes = youki_scopes();
    assert!(
        !scopes.contains(&staged.plan.container_id),
        "{test}: the user manager still holds a transient scope for `{id}`. The runtime created \
         the container after the cancellation's only `youki kill` had already failed, and nothing \
         killed it afterwards.\n{scopes}",
        id = staged.plan.container_id,
    );
    let survivors = processes_in_container_subtree(&staged.leaf());
    assert!(
        survivors.is_empty(),
        "{test}: {n} process(es) are still in the container's cgroup after the cancellation, so \
         the runtime was killed mid-create and what it had forked outlived it: {survivors:?}",
        n = survivors.len(),
    );

    println!(
        "OCI-PROVIDER CANCEL-DURING-CREATE container={id} reported-exit=None(signal) \
         registered-after=0 scope-after=absent processes-in-scope-after=0",
        id = staged.plan.container_id,
    );
}

/// **A plan whose pinned runtime does not hash to what the plan says is REFUSED,
/// and nothing is started.**
///
/// The plan carries a path AND a digest because either alone is a weaker claim, and
/// this is the arm that makes the pair mean something on the provider's side. The
/// refusal is observed as a FRAME, and the absence of a container is observed from
/// the FILESYSTEM: the provider verifies the digest BEFORE it writes a bundle, so a
/// refusal that had nonetheless materialized one would be visible as a state
/// directory.
///
/// # Would red if
///
/// The provider execed the path without reading its bytes — the natural
/// implementation, and the one that would let whatever currently sits at a
/// filesystem location start a container kata believes is the certified runtime.
#[test]
#[ignore = "HOST-DEPENDENT (pinned youki, its installed AppArmor \
             profile, a delegated user scope, the fixture closure's store path realised) AND \
             instrument-dependent (`cargo build -p kata-provider-youki`). `just gate` is \
             host-independent by design, so this rides the containment side like its two \
             siblings; the containment lane's `oci-live-smoke` step runs it. Run it now \
             with `cargo build -p kata-provider-youki --bin kata-provider-youki && cargo nextest \
             run -p kata-worker -P live-smoke -E 'binary(oci_provider_live)' --run-ignored all`."]
fn a_plan_whose_pinned_runtime_digest_moved_is_refused_and_nothing_starts_live() {
    delegated(
        "a_plan_whose_pinned_runtime_digest_moved_is_refused_and_nothing_starts_live",
        a_plan_whose_pinned_runtime_digest_moved_is_refused_and_nothing_starts_body(),
    );
}

async fn a_plan_whose_pinned_runtime_digest_moved_is_refused_and_nothing_starts_body() {
    let test = "a_plan_whose_pinned_runtime_digest_moved_is_refused_and_nothing_starts_live";
    let binary = workspace_bin("kata-provider-youki");
    let mut supervisor = ProviderSupervisor::launch(&launch_spec(
        &binary,
        ProviderFloor::Installed,
        measured_basis(),
    ))
    .await
    .unwrap_or_else(|e| panic!("{test}: launching the OCI provider failed: {e}"));
    let root = sweep_root(&supervisor, test);
    let staged = stage(&root, 41, &[&format!("{BUSYBOX}/bin/busybox"), "true"]);
    let mut doctored = staged.plan.clone();
    doctored.youki = PinnedRuntime {
        store_path: staged.plan.youki.store_path.clone(),
        sha256: "f".repeat(64),
    };

    let refusal = supervisor
        .run_stage(assignment("oci-wrong-digest", &staged), doctored)
        .await
        .err()
        .unwrap_or_else(|| {
            panic!(
                "{test}: the provider STARTED a container with a runtime whose digest is not the \
                 pinned one. A store path is immutable, so a moved digest means the pin was \
                 re-realized or the store damaged — and the container would have none of the \
                 properties kata certified while the frame said `completed`."
            )
        })
        .to_string();
    assert!(
        refusal.contains("hashes to") && refusal.contains(&"f".repeat(64)),
        "{test}: the refusal must name both digests so an operator can tell which moved: {refusal}"
    );
    let frame = supervisor.stage_refusal().unwrap_or_else(|| {
        panic!("{test}: the digest refusal reached kata as a message but not as a FRAME")
    });
    assert_eq!(frame.assignment_id, "oci-wrong-digest");

    let home = staged.home();
    assert!(
        !home.exists(),
        "{test}: the provider wrote a bundle at {home} for an assignment it refused. The digest is \
         verified BEFORE anything is written precisely so a refusal leaves no rootfs, no state \
         tree and no container behind",
        home = home.display(),
    );
    let listing = youki_list(&staged.runtime_state());
    assert!(
        !listing.contains(&staged.plan.container_id),
        "{test}: a refused assignment registered a container:\n{listing}"
    );

    let _ = supervisor.shutdown().await;
    println!(
        "OCI-PROVIDER DIGEST-REFUSAL container={id} bundle-written=no registered=0 \
         refusal-observed-as-frame=yes",
        id = staged.plan.container_id,
    );
}

/// **The three placement-and-state-root refusals, each observed as a FRAME with
/// nothing started.**
///
/// One table over three doctored assignments, for the reason the plan-refusal rigs
/// elsewhere give: the property is *"the stated refused set is the refused set"*, and
/// a clause documented in the provider's header with no mechanism behind it is
/// visible here as a missing row.
///
/// # Why each row is a refusal and not a default
///
/// * **no `cgroup_parent`** — the container would be placed by the RUNTIME, in its
///   own transient scope, outside the subtree kata sweeps. Every teardown claim on
///   this route would then be about a cgroup the stage was never in, which is exactly
///   the false `Confirmed` the kata-owned parent closes.
/// * **a relative `state_root`** — the bundle and the runtime state would land
///   wherever the provider happened to be started, so kata could neither tear the
///   container down nor read it back.
/// * **the plan's two halves disagree about the placement** — `cgroup_parent` names
///   the parent kata created while `config.json`'s `linux.cgroupsPath` puts the leaf
///   elsewhere, so the provider would verify a directory the container never enters.
///
/// # Would red if
///
/// The provider defaulted any of the three instead of refusing — and the absence of
/// a bundle directory afterwards is what says the refusal happened BEFORE anything
/// was written.
#[test]
#[ignore = "HOST-DEPENDENT (pinned youki, its installed AppArmor \
             profile, a delegated user scope, the fixture closure's store path realised) AND \
             instrument-dependent (`cargo build -p kata-provider-youki`). `just gate` is \
             host-independent by design, so this rides the containment side like its siblings; \
             the containment lane's `oci-live-smoke` step runs it. Run it now with \
             `cargo build -p kata-provider-youki --bin kata-provider-youki && cargo nextest run \
             -p kata-worker -E 'binary(oci_provider_live)' --run-ignored all`."]
fn the_placement_and_state_root_refusals_are_observed_as_frames_live() {
    delegated(
        "the_placement_and_state_root_refusals_are_observed_as_frames_live",
        the_placement_and_state_root_refusals_are_observed_as_frames_body(),
    );
}

async fn the_placement_and_state_root_refusals_are_observed_as_frames_body() {
    let test = "the_placement_and_state_root_refusals_are_observed_as_frames_live";
    let binary = workspace_bin("kata-provider-youki");
    let basis = measured_basis();
    let mut supervisor = ProviderSupervisor::launch(&launch_spec(
        &binary,
        ProviderFloor::Installed,
        basis.clone(),
    ))
    .await
    .unwrap_or_else(|e| panic!("{test}: launching the OCI provider failed: {e}"));
    let root = sweep_root(&supervisor, test);
    let staged = stage(&root, 43, &[&format!("{BUSYBOX}/bin/busybox"), "true"]);

    let unplaced = OciBundlePlan {
        cgroup_parent: None,
        ..staged.plan.clone()
    };
    let relative_state = OciBundlePlan {
        state_root: "attempts/relative/oci".to_owned(),
        ..staged.plan.clone()
    };
    // The plan's TWO HALVES made to disagree: `cgroup_parent` still names the parent
    // kata created, and the config the RUNTIME acts on places the container somewhere
    // else. Rewritten as TEXT because that is what the provider receives — a plan
    // built through `spec_for` cannot express the disagreement, which is the point.
    let elsewhere = "/kata.test/somewhere-kata-does-not-sweep/container";
    let displaced_leaf = OciBundlePlan {
        config_json: staged.plan.config_json.replace(
            &format!(
                "\"cgroupsPath\": \"{}\"",
                staged.leaf_in_hierarchy().display()
            ),
            &format!("\"cgroupsPath\": \"{elsewhere}\""),
        ),
        ..staged.plan.clone()
    };
    assert_ne!(
        displaced_leaf.config_json, staged.plan.config_json,
        "{test}: the doctored plan must actually differ, or the row below asserts nothing about a \
         disagreement"
    );

    for (row, id, plan, expected) in [
        (
            "no cgroup parent",
            "oci-unplaced",
            unplaced,
            "names NO parent cgroup",
        ),
        (
            "relative state root",
            "oci-relative-state",
            relative_state,
            "is RELATIVE",
        ),
        (
            "the plan's two halves disagree about the placement",
            "oci-displaced-leaf",
            displaced_leaf,
            "two halves DISAGREE",
        ),
    ] {
        // A FRESH spool dir per row: the supervisor creates it EMPTY at assign
        // (v6's contract), so a second row on the same attempt root would trip
        // the existence check before the plan refusal the row exists to see.
        let capture = kata_provider_protocol::CaptureSpec {
            spool_dir: format!("{}-{id}", staged.capture.spool_dir),
            ..staged.capture.clone()
        };
        let mut assignment = assignment(id, &staged);
        assignment.capture = &capture;
        let refusal = supervisor
            .run_stage(assignment, plan)
            .await
            .err()
            .unwrap_or_else(|| {
                panic!(
                    "{test}[{row}]: the provider RAN this assignment. Each row is something kata \
                     said that this provider cannot honour exactly, and running it anyway is the \
                     silent degradation the refusal exists to prevent."
                )
            })
            .to_string();
        assert!(
            refusal.contains(expected),
            "{test}[{row}]: the refusal must name what it refused ({expected:?}): {refusal}"
        );
        let frame = supervisor.stage_refusal().unwrap_or_else(|| {
            panic!("{test}[{row}]: the refusal reached kata as a message but not as a FRAME")
        });
        assert_eq!(frame.assignment_id, id);
        assert!(
            !staged.home().exists(),
            "{test}[{row}]: the provider wrote a bundle at {home} for an assignment it refused. \
             Every one of these is checked BEFORE anything is materialized, so a refusal leaves \
             no rootfs, no state tree and no container behind",
            home = staged.home().display(),
        );
    }

    let _ = supervisor.shutdown().await;
    println!(
        "OCI-PROVIDER REFUSALS container={id} rows=3 bundle-written=no \
         refusals-observed-as-frames=3",
        id = staged.plan.container_id,
    );
}

/// **The floor proof ON THIS ROUTE: the seccomp floor kata installed on the
/// provider is INHERITED INTO THE CONTAINER.**
///
/// The floor is installed by kata on the provider, in the provider's own
/// `pre_exec`, before the provider exists as the provider. The container's init is
/// the provider's grandchild — provider → `youki run` → container init → `sh` — so a
/// filter observed inside the container is the floor having survived two `fork`s,
/// two `execve`s, a user namespace and a pivoted root.
///
/// # The observation is a DIFFERENCE, because a verdict would not be attributable
///
/// Both arms read `/proc/self/status` inside the container and differ in exactly one
/// field of one `CommandPrefix`: `kata_floor_bpf`, nulled by
/// `ProviderFloor::AbsentForProofControl`, which no operator knob can reach
/// (`no_containment_lever_can_null_the_provider_floor`). The floored arm must report
/// exactly ONE filter more than the control. A per-syscall `EPERM` is deliberately
/// not asserted: the container has empty capability sets, so every floor entry a
/// busybox applet can reach is refused by the capability check either way — see this
/// file's header.
///
/// # What the control ALSO measures
///
/// The control reports ONE filter inside a container whose `config.json` carries all
/// of kata's `linux.seccomp` entries: the stage fence, which the pinned youki (a libseccomp
/// build) applies. The floored arm's one extra filter is the floor, which is what
/// makes it attributable to kata.
///
/// Both arms also issue an i386-ABI `getpid` (`int 0x80`), a call no deny list names,
/// and both are KILLED by SIGSYS: the control arm — the stage fence alone — is the
/// measurement that the OCI form kills a foreign architecture rather than falling
/// through to `defaultAction` (`kata_types::sandbox_seccomp`'s `OCI_ARCHITECTURES`).
///
/// # The doors to a nested user namespace, on the stage fence ALONE
///
/// Both arms also try every door to a nested user namespace: `busybox unshare -U`,
/// and `clone(CLONE_NEWUSER)` and `clone3(CLONE_NEWUSER)` as static probes. None
/// needs a capability, and the container inherits the pinned youki's AppArmor
/// `userns` grant, so nothing but a seccomp filter refuses them. In production the
/// floor refuses `clone` and `clone3` too, which would hide a stage-fence rule that
/// never matches; the control arm is the one place the stage fence's conditional
/// `clone` rule — `oci_bundle::seccomp_arg`'s `SCMP_CMP_MASKED_EQ` as the pinned
/// youki reads it — is measured on its own. Both arms must read `unshare` refused,
/// `clone` errno 1 and `clone3` errno 38.
///
/// # Would red if
///
/// The floor were not installed on the provider, did not survive the handoff, or the
/// control arm somehow carried one too — each of which would collapse the delta this
/// arm is made of; either arm's filters let a foreign-arch call through; or either
/// arm let a door to a nested user namespace open, or answered it with another errno.
#[test]
#[ignore = "HOST-DEPENDENT (pinned youki, its installed AppArmor \
             profile, a delegated user scope, the fixture closure's store path realised) AND \
             instrument-dependent (`cargo build -p kata-provider-youki`). `just gate` is \
             host-independent by design, so this rides the containment side like its two \
             siblings; the containment lane's `oci-live-smoke` step runs it. Run it now \
             with `cargo build -p kata-provider-youki --bin kata-provider-youki && cargo nextest \
             run -p kata-worker -P live-smoke -E 'binary(oci_provider_live)' --run-ignored all`."]
fn the_kata_floor_is_inherited_into_the_container_live() {
    delegated(
        "the_kata_floor_is_inherited_into_the_container_live",
        the_kata_floor_is_inherited_into_the_container_body(),
    );
}

async fn the_kata_floor_is_inherited_into_the_container_body() {
    let test = "the_kata_floor_is_inherited_into_the_container_live";
    let binary = workspace_bin("kata-provider-youki");
    let basis = measured_basis();
    let mut reports = Vec::new();
    // An i386-ABI `getpid` — a call no deny list names — so its outcome is each
    // arm's answer for a foreign architecture and nothing else.
    let i386_getpid = common::static_probe::static_elf(
        &[
            common::static_probe::I386_GETPID,
            common::static_probe::I386_REPORT,
        ]
        .concat(),
    );
    let door = |code: &[u8]| {
        common::static_probe::static_elf(&[code, common::static_probe::NAMESPACE_REPORT].concat())
    };
    let bb = format!("{BUSYBOX}/bin/busybox");
    // `unshare -U` is discriminated by the printed word, as the adversarial A1'
    // row does: the probe's own exit is the shell's, 0 on both outcomes.
    let observe = format!(
        "grep -E '^(Seccomp|Seccomp_filters|NoNewPrivs|CapEff):' /proc/self/status > /out/status; \
         {{ {}; }} >> /out/status; \
         {{ {}; }} >> /out/status; \
         {{ {}; }} >> /out/status; \
         {{ {bb} unshare -U {bb} true && echo unshare=created || echo unshare=refused; }} \
         >> /out/status 2>&1",
        common::static_probe::write_and_run(&bb, "/tmp", &i386_getpid),
        common::static_probe::write_and_run_as(
            &bb,
            "/tmp",
            &door(common::static_probe::CLONE_NEWUSER),
            "clone"
        ),
        common::static_probe::write_and_run_as(
            &bb,
            "/tmp",
            &door(common::static_probe::CLONE3_NEWUSER),
            "clone3"
        ),
    );

    for (arm, occurrence, floor) in [
        ("floored", 51u8, ProviderFloor::Installed),
        ("control", 53, ProviderFloor::AbsentForProofControl),
    ] {
        let mut supervisor =
            ProviderSupervisor::launch(&launch_spec(&binary, floor, basis.clone()))
                .await
                .unwrap_or_else(|e| {
                    panic!("{test}[{arm}]: launching the OCI provider failed: {e}")
                });
        let root = sweep_root(&supervisor, test);
        let staged = stage(
            &root,
            occurrence,
            &[&format!("{BUSYBOX}/bin/busybox"), "sh", "-c", &observe],
        );
        let outcome = supervisor
            .run_stage(assignment("oci-floor", &staged), staged.plan.clone())
            .await
            .unwrap_or_else(|e| panic!("{test}[{arm}]: the container did not run: {e}"));
        assert_eq!(
            outcome.completed.exit_code,
            Some(0),
            "{test}[{arm}]: the observing container did not exit 0.\nstderr: {err}",
            err = staged.spooled("stderr"),
        );
        let status = std::fs::read_to_string(staged.out.join("status")).unwrap_or_else(|e| {
            panic!(
                "{test}[{arm}]: the container left no /proc/self/status in /out ({e}). /out is a \
                 read-write rbind of a host directory this process owns; an absent file means the \
                 guest could not write it, which is itself the finding"
            )
        });
        let field =
            |name: &str| -> i64 {
                status
                .lines()
                .find_map(|line| line.strip_prefix(&format!("{name}:")))
                .map_or_else(
                    || {
                        panic!(
                            "{test}[{arm}]: the guest's /proc/self/status has no `{name}` line, so \
                             the kernel did not report the thing this arm compares:\n{status}"
                        )
                    },
                    |value| value.trim().parse::<i64>().expect("a /proc/self/status number"),
                )
            };
        let filters = field("Seccomp_filters");
        let mode = field("Seccomp");
        // A foreign architecture is KILLED in both arms: the floor's arch guard
        // kills it, and so does the stage fence ALONE — libseccomp's bad-arch
        // action, which the pinned youki leaves at its default. The control arm is
        // the measurement `OCI_ARCHITECTURES` states.
        let foreign_arch = common::static_probe::probe_exit(&status);
        assert_eq!(
            foreign_arch,
            Some(common::static_probe::ProbeExit::KilledBySigsys),
            "{test}[{arm}]: an i386-ABI `getpid` inside the container must be KILLED by \
             SIGSYS; it read {foreign_arch:?}, so a foreign-arch call reaches the kernel \
             through this arm's filters:\n{status}"
        );
        let clone = common::static_probe::exit_of(&status, "clone");
        let clone3 = common::static_probe::exit_of(&status, "clone3");
        assert_eq!(
            clone,
            Some(common::static_probe::ProbeExit::Errno(1)),
            "{test}[{arm}]: `clone(CLONE_NEWUSER)` inside the container must read EPERM; it \
             read {clone:?}. On the control arm the stage fence's conditional `clone` rule is \
             the only filter that can refuse it:\n{status}"
        );
        assert_eq!(
            clone3,
            Some(common::static_probe::ProbeExit::Errno(38)),
            "{test}[{arm}]: `clone3(CLONE_NEWUSER)` inside the container must read ENOSYS; it \
             read {clone3:?}:\n{status}"
        );
        assert!(
            status.contains("unshare=refused") && !status.contains("unshare=created"),
            "{test}[{arm}]: `unshare -U` inside the container must be refused; it needs no \
             capability, so only the fence refuses it:\n{status}"
        );
        println!(
            "OCI-PROVIDER FLOOR-INHERITANCE arm={arm} i386-getpid={foreign_arch:?} \
             clone={clone:?} clone3={clone3:?} unshare=refused"
        );
        assert_eq!(
            field("NoNewPrivs"),
            1,
            "{test}[{arm}]: the container's `noNewPrivileges` did not take, and the floor's \
             preservation across `execve` is not separable from it"
        );
        let _ = supervisor.shutdown().await;
        reports.push((arm, mode, filters, status));
    }

    let (_, floored_mode, floored_filters, floored_status) = reports[0].clone();
    let (_, control_mode, control_filters, control_status) = reports[1].clone();
    assert_eq!(
        floored_filters,
        control_filters + 1,
        "{test}: the floored container must carry EXACTLY ONE seccomp filter more than the \
         control. That difference IS the floor: the two arms differ in one field of one \
         `CommandPrefix` and in nothing else, so a delta of 0 means the floor did not survive the \
         handoff into the container and a delta of 2 means something else installed a filter \
         too.\nfloored:\n{floored_status}\ncontrol:\n{control_status}"
    );
    assert_eq!(
        floored_mode, 2,
        "{test}: the floored container's init must be in seccomp FILTER mode (2) as the kernel \
         reports it:\n{floored_status}"
    );
    // The CONTROL arm carries the container's own stage fence: the pinned runtime
    // applies `linux.seccomp`.
    //
    // MEASURED on the reference host, pinned youki 0.7.0 (a `…-youki-seccomp` build):
    //
    //   $ youki --version                 -> libseccomp: 2.6.1
    //   $ youki features | jq .linux.seccomp   -> null
    //   CONTROL arm's guest /proc/self/status  -> Seccomp: 2, Seccomp_filters: 1
    //
    // The runtime APPLIES `linux.seccomp` while its own `features` output still
    // reports the capability as absent. So `youki features` is not a witness for this
    // axis and the `libseccomp:` line in `--version` is — which is the witness
    // `oci_runtime::certify_youki`'s `SeccompUnsupported` arm reads.
    //
    // The DELTA assertion above is what isolates kata's floor: floored carries 2
    // filters where the control carries 1, and the extra one is the floor. That the
    // control carries the container's own stage fence makes this arm a stronger
    // statement, not a weaker one — the two filters are distinguishable by count.
    assert_eq!(
        control_mode, 2,
        "{test}: the CONTROL container reports seccomp mode {control_mode}. The \
         pinned youki APPLIES the container's own `linux.seccomp` (measured: \
         `libseccomp: 2.6.1` in `--version`, one filter in the guest's own \
         /proc/self/status, while `youki features` still reports `linux.seccomp: null`). A 0 \
         here means the stage fence STOPPED reaching the container, which retires the claim \
         `the_stage_fence_reaches_the_container_live` exists to make.\n{control_status}"
    );

    println!(
        "OCI-PROVIDER FLOOR-INHERITANCE floored-mode={floored_mode} floored-filters={floored_filters} \
         control-mode={control_mode} control-filters={control_filters} delta=1 \
         attributable=floor-only(one-filter-more-than-the-containers-own-fence)"
    );
}

/// **The container runs in the cgroup KATA PLANNED, and this capsule's bounds are
/// on it — read from the host, at both levels.**
///
/// # What this closes
///
/// With `linux.cgroupsPath` unset the container's init lands in youki's own
/// transient `youki-<id>.scope`, and everything kata said about bounding and
/// tearing down a stage on this route would be about a subtree the stage was
/// never in. This arm is the placement, observed from `/proc/<init>/cgroup` — the
/// kernel's own answer — plus the knob files themselves.
///
/// # The bounds are asserted at BOTH levels because only one of them is enforced
///
/// The parent's knobs are kata's writes and they are the enforced mechanism; the
/// leaf's are the runtime's rendering of `linux.resources`, which is defence in
/// depth. **MEASURED: youki 0.7.0 does not apply the swap half** — a leaf under an
/// absolute `cgroupsPath` reads `memory.swap.max: max` from a spec carrying
/// `swap == limit` — so the swap denial is asserted on the PARENT only, and that
/// asymmetry is the finding rather than a gap in this test.
///
/// # Would red if
///
/// `spec_for` stopped setting `cgroupsPath`, set a relative one (the container would
/// not start at all), or set one outside the parent; if `OciParentCgroup` stopped
/// writing a knob or stopped enabling the controllers the leaf needs (the container
/// would fail its own `linux.resources` write); or if the runtime started placing
/// the container somewhere of its own again.
#[test]
#[ignore = "HOST-DEPENDENT (pinned youki, its installed AppArmor \
             profile, a delegated user scope, the fixture closure's store path realised) AND \
             instrument-dependent (`cargo build -p kata-provider-youki`). `just gate` is \
             host-independent by design, so this rides the containment side like its siblings; \
             the containment lane's `oci-live-smoke` step runs it. Run it now with \
             `cargo build -p kata-provider-youki --bin kata-provider-youki && cargo nextest run \
             -p kata-worker -E 'binary(oci_provider_live)' --run-ignored all`."]
fn the_container_is_placed_in_katas_own_cgroup_with_its_bounds_live() {
    delegated(
        "the_container_is_placed_in_katas_own_cgroup_with_its_bounds_live",
        the_container_is_placed_in_katas_own_cgroup_with_its_bounds_body(),
    );
}

async fn the_container_is_placed_in_katas_own_cgroup_with_its_bounds_body() {
    let test = "the_container_is_placed_in_katas_own_cgroup_with_its_bounds_live";
    let binary = workspace_bin("kata-provider-youki");
    let mut supervisor = ProviderSupervisor::launch(&launch_spec(
        &binary,
        ProviderFloor::Installed,
        measured_basis(),
    ))
    .await
    .unwrap_or_else(|e| panic!("{test}: launching the OCI provider failed: {e}"));
    let root = sweep_root(&supervisor, test);
    let staged = stage(
        &root,
        71,
        &[&format!("{BUSYBOX}/bin/busybox"), "sh", "-c", "sleep 300"],
    );
    let budgets = capsule(71, &["/bin/true"]).budgets();

    supervisor
        .assign_stage(assignment("oci-placed", &staged), staged.plan.clone())
        .await
        .unwrap_or_else(|e| panic!("{test}: the provider did not accept the assignment: {e}"));

    let state = staged.runtime_state();
    let appeared = tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            if let Some(pid) = container_init_pid(&state, &staged.plan.container_id)
                && let Ok(cgroup) = std::fs::read_to_string(format!("/proc/{pid}/cgroup"))
            {
                return (pid, cgroup.trim().to_owned());
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await;
    let Ok((init_pid, init_cgroup)) = appeared else {
        let said = supervisor.await_stage_completion("oci-placed").await;
        panic!(
            "{test}: no container init appeared under the provider's state root ({state}) within \
             30s, so there is no placement to read. What the provider said instead: {said:?}",
            state = state.display(),
        );
    };

    // (a) THE PLACEMENT, from the kernel's own per-process cgroup line.
    let observed = init_cgroup.rsplit_once(':').map_or_else(
        || panic!("{test}: /proc/{init_pid}/cgroup is not a cgroup v2 line: {init_cgroup}"),
        |(_, path)| PathBuf::from("/sys/fs/cgroup").join(path.trim_start_matches('/')),
    );
    assert_eq!(
        observed,
        staged.leaf(),
        "{test}: the container's init is not in the leaf kata planned. Everything kata claims \
         about bounding and tearing this stage down is a claim about that subtree, so a container \
         anywhere else makes all of it vacuous.\n/proc/{init_pid}/cgroup: {init_cgroup}"
    );
    assert!(
        observed.starts_with(&root),
        "{test}: the container's cgroup {} is not inside the SUPERVISOR's own sweep root {}, which \
         is the subtree `contain` walks",
        observed.display(),
        root.display(),
    );
    assert!(
        observed.ends_with(CONTAINER_LEAF),
        "{test}: the leaf is not the one kata names: {}",
        observed.display()
    );
    let scopes = youki_scopes();
    assert!(
        !scopes.contains(&staged.plan.container_id),
        "{test}: the user manager holds a transient scope for this container, which is what an \
         IGNORED `cgroupsPath` produces:\n{scopes}"
    );

    // (b) THE BOUNDS, from the knob files on the host.
    let knob = |dir: &Path, name: &str| -> String {
        std::fs::read_to_string(dir.join(name))
            .unwrap_or_else(|e| {
                let present: Vec<String> = std::fs::read_dir(dir)
                    .map(|entries| {
                        entries
                            .flatten()
                            .filter_map(|entry| entry.file_name().into_string().ok())
                            .collect()
                    })
                    .unwrap_or_default();
                panic!(
                    "{test}: {name} is not readable at {dir} ({e}). A bound kata cannot read back \
                     is a bound kata cannot claim. What IS in that cgroup: {present:?}",
                    dir = dir.display(),
                )
            })
            .trim()
            .to_owned()
    };
    let parent = staged.parent.path();
    assert_eq!(
        knob(parent, "memory.max"),
        budgets.memory_bytes.to_string(),
        "{test}: the kata-owned parent does not carry this capsule's memory ceiling. These writes \
         are the ENFORCED mechanism on this route"
    );
    assert_eq!(
        knob(parent, "memory.swap.max"),
        "0",
        "{test}: the parent does not deny swap, so the memory ceiling above is a throttle that \
         spills into the host's swap rather than a bound. It is asserted HERE and not on the leaf \
         because youki 0.7.0 does not apply the swap half of `linux.resources.memory`"
    );
    assert_eq!(
        knob(parent, "pids.max"),
        budgets.process_count.to_string(),
        "{test}: the parent does not carry this capsule's process-count ceiling"
    );
    assert_eq!(
        knob(&observed, "memory.max"),
        budgets.memory_bytes.to_string(),
        "{test}: the container's OWN leaf does not carry the memory ceiling `linux.resources` \
         asked for. That is the defence-in-depth half, and its absence means the runtime ignored \
         the section or the parent never enabled the memory controller for its children"
    );
    assert_eq!(
        knob(&observed, "pids.max"),
        budgets.process_count.to_string(),
        "{test}: the container's own leaf does not carry the process-count ceiling"
    );
    // EVERY value read BEFORE the shutdown, which sweeps the subtree and removes
    // these directories. A `println!` that read them afterwards would fail on an
    // absent path and report it as an unreadable bound — which is how this arm first
    // reded.
    let leaf_swap = knob(&observed, "memory.swap.max");
    let parent_swap = knob(parent, "memory.swap.max");
    let leaf_memory = knob(&observed, "memory.max");
    let leaf_pids = knob(&observed, "pids.max");

    let _ = supervisor.shutdown().await;
    println!(
        "OCI-PROVIDER PLACEMENT container={id} init-pid={init_pid} leaf={leaf} \
         parent-memory.max={pmem} parent-memory.swap.max={parent_swap} parent-pids.max={ppids} \
         leaf-memory.max={leaf_memory} leaf-pids.max={leaf_pids} \
         leaf-memory.swap.max={leaf_swap} youki-scopes=0 enforced-by=kata-parent-knobs",
        id = staged.plan.container_id,
        leaf = observed.display(),
        pmem = budgets.memory_bytes,
        ppids = budgets.process_count,
    );
}

/// **The SUPERVISOR's abrupt teardown reaps the container, and
/// `TeardownOutcome::Confirmed` is true of it.**
///
/// # The exact defect this pins
///
/// `ProviderSupervisor::kill_and_contain` `SIGKILL`s the provider — which gets no
/// chance to run its own cancellation — then sweeps its outer cgroup and scores
/// `TeardownProbe::CgroupPopulation` over it. With `linux.cgroupsPath` unset the
/// container was not in that subtree, so the verdict was `Confirmed` over a RUNNING
/// container: the strongest teardown claim kata makes, about a stage it had not
/// touched. This arm is that path with the placement in place.
///
/// # Non-vacuity, and it is the whole of the arm
///
/// The container's init is OBSERVED running, and the observation of its absence
/// afterwards is `/proc` plus the cgroup directory plus `youki list` — none of them
/// produced by kata or by the provider. Without the "before" the four reads below
/// would pass against an empty host.
///
/// # WATCHED RED
///
/// With `linux.cgroupsPath` removed from the plan, the
/// sweep reports `Confirmed` and the `youki list` and `/proc` reads show the
/// container still `Running` — the false verdict, reproduced on demand. Measured by
/// hand first: `SIGKILL` on the runtime client leaves the init alive in its own
/// scope, and one write to the sweep root's `cgroup.kill` is what reaps it once the
/// container is inside.
///
/// # Would red if
///
/// The placement moved outside the sweep root, `contain` stopped writing
/// `cgroup.kill`, or the probe stopped recursing into child cgroups.
#[test]
#[ignore = "HOST-DEPENDENT (pinned youki, its installed AppArmor \
             profile, a delegated user scope, the fixture closure's store path realised) AND \
             instrument-dependent (`cargo build -p kata-provider-youki`). `just gate` is \
             host-independent by design, so this rides the containment side like its siblings; \
             the containment lane's `oci-live-smoke` step runs it. Run it now with \
             `cargo build -p kata-provider-youki --bin kata-provider-youki && cargo nextest run \
             -p kata-worker -E 'binary(oci_provider_live)' --run-ignored all`."]
fn the_supervisors_abrupt_teardown_reaps_the_container_live() {
    delegated(
        "the_supervisors_abrupt_teardown_reaps_the_container_live",
        the_supervisors_abrupt_teardown_reaps_the_container_body(),
    );
}

async fn the_supervisors_abrupt_teardown_reaps_the_container_body() {
    let test = "the_supervisors_abrupt_teardown_reaps_the_container_live";
    let binary = workspace_bin("kata-provider-youki");
    let mut supervisor = ProviderSupervisor::launch(&launch_spec(
        &binary,
        ProviderFloor::Installed,
        measured_basis(),
    ))
    .await
    .unwrap_or_else(|e| panic!("{test}: launching the OCI provider failed: {e}"));
    let root = sweep_root(&supervisor, test);
    let staged = stage(
        &root,
        73,
        &[&format!("{BUSYBOX}/bin/busybox"), "sh", "-c", "sleep 300"],
    );

    supervisor
        .assign_stage(assignment("oci-abrupt", &staged), staged.plan.clone())
        .await
        .unwrap_or_else(|e| panic!("{test}: the provider did not accept the assignment: {e}"));

    let state = staged.runtime_state();
    let appeared = tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            if let Some(pid) = container_init_pid(&state, &staged.plan.container_id) {
                return pid;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await;
    let Ok(init_pid) = appeared else {
        let said = supervisor.await_stage_completion("oci-abrupt").await;
        panic!(
            "{test}: no container init appeared within 30s, so there is nothing for the abrupt \
             teardown to reap and every assertion below would pass against an empty host. What \
             the provider said instead: {said:?}"
        );
    };
    // NON-VACUITY, from the runtime and from the kernel.
    let before = youki_list_once_running(&state).await;
    assert!(
        before.contains("Running"),
        "{test}: the runtime does not report a RUNNING container within {RUNNING_BOUND:?} of \
         its init appearing, before the teardown. Last listing:\n{before}"
    );
    let leaf = staged.leaf();
    assert!(
        !processes_in_container_subtree(&leaf).is_empty(),
        "{test}: no process is in the container's own cgroup {} before the teardown, so its \
         emptiness afterwards would prove nothing",
        leaf.display()
    );

    // THE ABRUPT PATH. No stdin EOF, no grace, no `SIGTERM`: `kill_and_contain` is
    // kata's crash arm, and the provider's own cancellation never runs.
    let report = supervisor
        .kill_and_contain("this arm SIGKILLs the provider to measure kata's own containment")
        .await;
    assert!(
        report.precondition().satisfies_crash_proof_precondition(),
        "{test}: the provider must have ACCEPTED and framed the assignment before it was killed, \
         or this arm measures kata's error handling and nothing about a running container: {:?}",
        report.precondition()
    );
    assert_eq!(
        report.residue().outer_cgroup.as_deref(),
        Some(root.as_path()),
        "{test}: the sweep must have happened in the supervisor's own outer cgroup"
    );

    // ---- the verdict, and then four host facts that have to agree with it ----
    let teardown = &report.residue().teardown;
    assert!(
        teardown.is_confirmed(),
        "{test}: the abrupt teardown is not CONFIRMED: {teardown:?}. Without the placement it is \
         confirmed and WRONG — the container is outside the swept subtree — so a regression here \
         is either a placement that moved or a sweep that stopped reaching it. swept: {swept:?}",
        swept = report.residue().swept,
    );
    assert!(
        matches!(
            teardown,
            TeardownOutcome::Confirmed {
                probe: TeardownProbe::CgroupPopulation,
                ..
            }
        ),
        "{test}: kata scores a provider teardown from the cgroup population ALONE — a \
         signal probe says nothing about a descendant that left the process group: {teardown:?}"
    );
    let survivors = processes_in_container_subtree(&leaf);
    assert!(
        survivors.is_empty(),
        "{test}: {n} process(es) are still in the container's cgroup after kata's sweep, so the \
         `Confirmed` verdict above is a verdict about something else: {survivors:?}",
        n = survivors.len(),
    );
    assert!(
        !leaf.exists() && !staged.parent.path().exists(),
        "{test}: the container's cgroup directories survive the sweep ({leaf} / {parent}). \
         `contain` removes the subtree bottom-up once its emptiness is OBSERVED, and directories \
         left behind read as a stage that is still somewhere",
        leaf = leaf.display(),
        parent = staged.parent.path().display(),
    );
    assert!(
        std::fs::read_to_string(format!("/proc/{init_pid}/cgroup"))
            .is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound)
            || !std::fs::read_to_string(format!("/proc/{init_pid}/cgroup"))
                .is_ok_and(|c| c.contains(CONTAINER_LEAF)),
        "{test}: the container's init (pid {init_pid}) is still alive in a container leaf. The \
         cgroup membership is re-read rather than the bare /proc entry, so a recycled pid cannot \
         pass for the stage"
    );
    let after = youki_list(&state);
    assert!(
        !after.contains("Running"),
        "{test}: the RUNTIME still reports a running container after kata's sweep. `youki list` \
         is read from the host and is not produced by kata or by the provider — the provider was \
         `SIGKILL`ed, so nothing ran `delete --force` and a `Created`/`Stopped` row is expected; a \
         `Running` one is the leak.\n{after}"
    );

    println!(
        "OCI-PROVIDER SUPERVISOR-ABRUPT container={id} init-pid={init_pid} \
         sweep-root={root} leaf-before=populated verdict={verdict} probe=cgroup_population \
         processes-after=0 cgroup-dirs-after=absent runtime-running-after=no",
        id = staged.plan.container_id,
        root = root.display(),
        verdict = teardown.label(),
    );
}

/// The container init's pid, as the RUNTIME reports it under the provider's own
/// state root.
///
/// `youki state <id>` and not a process scan: the pid has to be the one the runtime
/// is holding, so that the `/proc` and cgroup facts afterwards are about the
/// container this assignment started and not about something else on the host.
fn container_init_pid(state: &Path, container_id: &str) -> Option<i32> {
    let pin = YoukiPin::embedded();
    let output = std::process::Command::new(pin.store_path())
        .arg("--root")
        .arg(state)
        .arg("state")
        .arg(container_id)
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).ok()?;
    let pid = value.get("pid")?.as_i64()?;
    i32::try_from(pid).ok()
}

/// **A supervisor DROPPED with a container running — a panicking or cancelled stage
/// task — kills the container through the outer cgroup.**
///
/// # The production defect this pins
///
/// `ProviderSupervisor`'s two terminal paths are async and consume `self`, and
/// nothing forces either to run. Without a `Drop`, dropping it lets tokio's
/// `kill_on_drop` `SIGKILL` the provider — the one process that tears the container
/// down — and leaves `youki run` reparented to init with the container alive, in a
/// subtree named for a LIVE worker's pid that the boot sweep therefore skips.
///
/// # Watched red
///
/// With the `cgroup.kill` write removed from `ProviderSupervisor::drop`, the
/// container's init is still alive in its leaf after the drop, and the runtime still
/// reports it `Running`.
///
/// # And the NEXT launch on the same worker succeeds and reclaims the dropped root
///
/// The Drop kills but cannot observe emptiness, so it leaves the sweep root. When that
/// root was named `kata.provider.<name>.<pid>` alone, every later launch on this worker
/// refused `already exists` until restart — which this cell hid behind a hand-`rmdir`.
/// Watched red with that `rmdir` removed and the per-launch sequence not yet in the
/// name: the second `launch` failed `provider sweep root … already exists`.
#[test]
#[ignore = "HOST-DEPENDENT (pinned youki, its installed AppArmor \
            profile, a delegated user scope) AND instrument-dependent (`cargo build -p \
            kata-provider-youki`). Runs in the containment lane's `oci-live-smoke` step. Run \
            it with `cargo build -p kata-provider-youki --bin kata-provider-youki && cargo \
            nextest run -p kata-worker -P live-smoke -E 'binary(oci_provider_live) and \
            test(dropped)' --run-ignored all`."]
fn a_dropped_supervisor_kills_its_running_container_live() {
    delegated(
        "a_dropped_supervisor_kills_its_running_container_live",
        a_dropped_supervisor_kills_its_running_container_body(),
    );
}

async fn a_dropped_supervisor_kills_its_running_container_body() {
    let test = "a_dropped_supervisor_kills_its_running_container_live";
    let binary = workspace_bin("kata-provider-youki");
    let mut supervisor = ProviderSupervisor::launch(&launch_spec(
        &binary,
        ProviderFloor::Installed,
        measured_basis(),
    ))
    .await
    .unwrap_or_else(|e| panic!("{test}: launching the OCI provider failed: {e}"));
    let root = sweep_root(&supervisor, test);
    let staged = stage(
        &root,
        79,
        &[&format!("{BUSYBOX}/bin/busybox"), "sh", "-c", "sleep 300"],
    );
    supervisor
        .assign_stage(assignment("oci-dropped", &staged), staged.plan.clone())
        .await
        .unwrap_or_else(|e| panic!("{test}: the provider did not accept the assignment: {e}"));

    let state = staged.runtime_state();
    let init_pid = tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            if let Some(pid) = container_init_pid(&state, &staged.plan.container_id) {
                return pid;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("{test}: no container init appeared within 30s"));
    // NON-VACUITY: a running container, in the leaf, before the drop. POLLED for at most
    // `RUNNING_BOUND`, for `youki_list_once_running`'s reason — and the init joins the leaf
    // only once the start completes, too.
    let leaf = staged.leaf();
    let listed = youki_list_once_running(&state).await;
    let mut in_leaf = processes_in_container_subtree(&leaf);
    let deadline = std::time::Instant::now() + RUNNING_BOUND;
    while in_leaf.is_empty() && std::time::Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(100)).await;
        in_leaf = processes_in_container_subtree(&leaf);
    }
    assert!(
        listed.contains("Running") && !in_leaf.is_empty(),
        "{test}: no RUNNING container in {} within {RUNNING_BOUND:?} of its init pid {init_pid} appearing, \
         so its absence after the drop would prove nothing. Last `youki list`:\n{listed}\nLast \
         processes in the leaf: {in_leaf:?}",
        leaf.display()
    );

    // THE DEFECT'S SHAPE: the supervisor goes away with no `shutdown` and no
    // `kill_and_contain` — exactly what a panicking stage task does to it.
    drop(supervisor);

    // Read from the HOST: the leaf's population and the init's own cgroup. Polled,
    // because the kernel's kill and the membership update are not one instant.
    let mut survivors = processes_in_container_subtree(&leaf);
    for _ in 0..100 {
        if survivors.is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
        survivors = processes_in_container_subtree(&leaf);
    }
    assert!(
        survivors.is_empty(),
        "{test}: {n} process(es) still in the container's leaf {leaf} 5s after the supervisor \
         was DROPPED: {survivors:?}. Without `ProviderSupervisor`'s `Drop` writing \
         `cgroup.kill`, a panicking stage task leaves a running container nothing reaps.",
        n = survivors.len(),
        leaf = leaf.display(),
    );
    assert!(
        !std::fs::read_to_string(format!("/proc/{init_pid}/cgroup"))
            .is_ok_and(|c| c.contains(CONTAINER_LEAF)),
        "{test}: the container's init (pid {init_pid}) is still alive in a container leaf"
    );
    assert!(
        !youki_list(&state).contains("Running"),
        "{test}: the runtime still reports the container RUNNING after the drop"
    );

    // THE WEDGE a hand-`rmdir` of the sweep root would hide: the
    // Drop cannot observe emptiness and so leaves the directories, and a sweep root
    // named for this pid alone would make every later launch on this worker refuse
    // `already exists` — which the boot sweep never clears, because this pid is live.
    // No hand cleanup here: the NEXT launch on the same worker must succeed, and must
    // itself reclaim the orphaned root.
    drop(staged);
    let second = ProviderSupervisor::launch(&launch_spec(
        &binary,
        ProviderFloor::Installed,
        measured_basis(),
    ))
    .await
    .unwrap_or_else(|e| {
        panic!(
            "{test}: a SECOND launch on the same worker after a dropped supervisor was refused: \
             {e}. One cancelled or panicked stage must not wedge every later launch until \
             restart."
        )
    });
    let second_root = sweep_root(&second, test);
    assert_ne!(
        second_root, root,
        "{test}: the second launch reused the dropped supervisor's sweep root"
    );
    // Read off the cgroup filesystem, not off the supervisor.
    assert!(
        !root.exists(),
        "{test}: the dropped supervisor's sweep root {} still exists after the next launch on \
         this worker, so its residue has no owner until restart",
        root.display()
    );
    let report = second.shutdown().await;
    assert!(
        !second_root.exists(),
        "{test}: the second supervisor's own sweep root {} survived its shutdown ({report:?})",
        second_root.display()
    );
    println!(
        "OCI-PROVIDER SUPERVISOR-DROPPED init-pid={init_pid} leaf-after=empty \
         runtime-running-after=no relaunch=ok dropped-root-after=absent"
    );
}

/// **The prepare budget is checked AGAIN after the provider's handshake, as the last step
/// before the assignment — so a launch that outlived the budget assigns nothing.**
///
/// The drive checks the budget before it launches the provider, and the launch itself (the
/// spawn and up to `DEFAULT_HANDSHAKE_TIMEOUT` of handshake) can carry it past the bound.
/// A FAKE `kata-provider-youki`, provisioned through the real by-hash store, sleeps three
/// seconds and then says a hello the route admits (the certificate restating this host's
/// own measured basis); the drive's `assign_by` is 1.5 s away, so it passes the pre-launch
/// check and elapses during the handshake. The fake records every byte it is handed on
/// stdin after its hello, so *"nothing was assigned"* is read off the filesystem rather
/// than asked of kata.
///
/// Live only for the plan that precedes the check: it creates the kata-owned parent cgroup
/// inside the supervisor's sweep root, which needs a delegated scope. No container runs.
///
/// **Would red if:** the post-handshake check were removed (the assignment would reach the
/// fake — its stdin record non-empty — and the refusal would be the provider's, not the
/// budget's).
#[test]
#[ignore = "HOST-DEPENDENT (pinned youki certified, its installed AppArmor profile, a \
            delegated user scope). Runs in the containment lane's `oci-live-smoke` step. Run \
            it with `cargo nextest run -p kata-worker -P live-smoke -E \
            'binary(oci_provider_live) and test(prepare_budget)' --run-ignored all`."]
fn the_prepare_budget_is_checked_again_after_the_provider_handshake_live() {
    delegated(
        "the_prepare_budget_is_checked_again_after_the_provider_handshake_live",
        the_prepare_budget_is_checked_again_after_the_provider_handshake_body(),
    );
}

async fn the_prepare_budget_is_checked_again_after_the_provider_handshake_body() {
    use kata_provider_protocol::{
        CERTIFICATE_VERSION, PROTOCOL_VERSION, ProviderFrame, ProviderHello, encode_frame,
        measured_certificate,
    };
    use kata_worker::execution_route::{ExternalProviderAddress, OciRoute};
    use kata_worker::oci_driver::{
        OCI_PROVIDER_NAME, OciProviderInstallation, OciStageDriver, OciStageRequest,
    };

    struct EmptyTrees;
    impl kata_worker::materialize::TreeResolver for EmptyTrees {
        fn tree_manifest(
            &self,
            _artifact: ArtifactId,
        ) -> kata_types::error::KataResult<kata_types::tree_artifact::TreeManifest> {
            kata_types::tree_artifact::TreeManifest::new(vec![])
        }

        fn tree_reference(
            &self,
            artifact: ArtifactId,
        ) -> kata_types::error::KataResult<kata_types::execution_contract::ArtifactRef> {
            panic!(
                "the driver looked up the reference for tree artifact {artifact:?}. The fixture \
                 resolves MANIFESTS for the materializer — nothing below execute_capsule_frame \
                 asks for a reference"
            );
        }
    }
    struct BytesForbidden;
    impl kata_worker::materialize::BlobSource for BytesForbidden {
        fn read_verified(
            &self,
            object: kata_types::primitives::ObjectId,
            _expected: u64,
            _maximum: u64,
        ) -> kata_types::error::KataResult<Vec<u8>> {
            panic!("every mapped tree is empty; no member's bytes are read ({object:?})")
        }
    }
    struct ClosurePresent;
    impl kata_worker::materialize::StorePathProbe for ClosurePresent {
        fn present(&self, _path: &StorePath) -> kata_types::error::KataResult<bool> {
            Ok(true)
        }
    }

    let certification = certify_youki(YoukiPin::embedded()).unwrap_or_else(|refusal| {
        panic!(
            "this host cannot deliver the rootless-OCI prerequisite, so the route this drive \
             needs does not exist: {refusal}. `just _containment-preconditions` gives the \
             one-line diagnosis."
        )
    });
    let route = OciRoute::new(certification);
    let root = tempfile::tempdir().expect("a temporary worker state root");
    // Declared AFTER the `TempDir` so it drops BEFORE it: the by-hash provider store is
    // sealed `0500`, which `TempDir`'s own removal cannot get through. See
    // `kata_worker::UnsealOnDrop`.
    let _unseal = kata_worker::UnsealOnDrop::new(root.path());
    let hello = root.path().join("hello.frame");
    std::fs::write(
        &hello,
        encode_frame(&ProviderFrame::Hello(ProviderHello {
            protocol_version: PROTOCOL_VERSION,
            certificate_version: CERTIFICATE_VERSION,
            certificate: measured_certificate(OCI_PROVIDER_NAME, route.measured_basis().clone()),
        }))
        .expect("the hello encodes"),
    )
    .expect("the hello frame is written");
    let launched = root.path().join("the-provider-was-launched");
    let assigned = root.path().join("stdin-after-hello");
    let source = root.path().join("provider-src");
    std::fs::create_dir_all(&source).expect("the provider source directory");
    let script = source.join(format!("kata-provider-{OCI_PROVIDER_NAME}"));
    std::fs::write(
        &script,
        format!(
            "#!/bin/sh\ntouch {launched}\nsleep 3\ncat {hello}\nhead -c 1 > {assigned}\n",
            launched = launched.display(),
            hello = hello.display(),
            assigned = assigned.display(),
        ),
    )
    .expect("the fake provider is written");
    std::fs::set_permissions(&script, std::os::unix::fs::PermissionsExt::from_mode(0o755))
        .expect("the fake provider is executable");
    let store_root = root.path().join("provider-store");
    let provisioned = kata_worker::ProviderStore::new(&store_root)
        .provision(OCI_PROVIDER_NAME, &source)
        .expect("the fake provider provisions into a by-hash store");
    let driver = OciStageDriver::new(
        route,
        root.path().join("worker-state"),
        OciProviderInstallation::new(
            store_root,
            ExternalProviderAddress::parse(&provisioned.address.to_string())
                .expect("a minted address parses"),
        ),
    );

    // `capsule`'s fixture also maps the closure's store path, which a container binds at
    // its own path and the materializer refuses as a tree; this drive materializes.
    let capsule = Capsule::new(
        OccurrenceId(hash(0x5B)),
        PreparedActionId(hash(2)),
        EnvironmentId(hash(3)),
        PlatformRef::new("x86_64-linux", hash(11)).id(),
        vec![
            mapping("/work", GuestAccess::ReadWrite, 20),
            mapping("/out", GuestAccess::ReadWrite, 21),
            mapping("/tmp", GuestAccess::ReadWrite, 22),
        ],
        CapsuleProcess::Command {
            argv: vec![smol_str::SmolStr::new(format!("{BUSYBOX}/bin/true"))],
        },
        CapsuleNetwork::Offline,
        None,
        CapsuleBudgets {
            wall_time_ms: 30_000,
            output_bytes: 1 << 20,
            memory_bytes: 512 * 1024 * 1024,
            process_count: 64,
            result_bytes: 4 * 1024 * 1024,
            result_entries: 128,
            work_delta_bytes: kata_types::execution_contract::CAPSULE_WORK_DELTA_BYTES,
            work_delta_entries: kata_types::execution_contract::CAPSULE_WORK_DELTA_ENTRIES,
        },
        None,
    )
    .expect("the fixture capsule is well formed");
    let (_never, cancel) = tokio::sync::oneshot::channel();
    let refusal = driver
        .drive_cancellable(
            "prepare-budget-after-handshake",
            &OciStageRequest {
                capsule: &capsule,
                environment: &environment(),
                network: NetPolicy::Offline,
                trees: &EmptyTrees,
                source: &BytesForbidden,
                probe: &ClosurePresent,
                execution_id: ulid::Ulid::new(),
            },
            std::time::Instant::now() + Duration::from_millis(1_500),
            cancel,
        )
        .await
        .err()
        .expect("the prepare budget elapsed during the handshake");
    assert!(
        launched.exists(),
        "non-vacuity: the pre-launch check passed and the provider was launched; got {refusal}"
    );
    assert_eq!(refusal.label(), "prepare_budget_elapsed", "{refusal}");
    assert!(refusal.rules_out_a_container(), "nothing was assigned");
    let handed = std::fs::read(&assigned).expect("the fake exited through its stdin read");
    assert!(
        handed.is_empty(),
        "the provider was handed {} byte(s) of an assignment past the prepare budget",
        handed.len()
    );
    println!(
        "PREPARE-BUDGET-AFTER-HANDSHAKE refusal={} stdin-after-hello-bytes=0",
        refusal.label()
    );
}

// ---------------------------------------------------------------------------
// The combined capture bound, live
// ---------------------------------------------------------------------------

/// **512 KiB of stdout under a 1 MiB COMBINED bound completes, spooled — and the
/// frame reports the size, not the bytes.**
///
/// The container's argv is `head -c 524288 /dev/zero | tr '\\0' a` through
/// `busybox sh`: exactly 512 KiB of `a`, no newline. The assertions this cell
/// exists for, none of which the frame could tell without the spool read:
///
/// * `stdout_bytes` == 524288 and `stderr_bytes` == 0 — the provider counted;
/// * `!capture_exceeded` — nothing was killed;
/// * the FILE the spool holds is byte-identical to what `head` produced — read
///   off disk and hashed independently (`sha256sum` through `std::process`, a
///   second spelling of the same primitive kata uses).
///
/// **Would red if:** the bound were applied per-stream and 512 KiB+0 fit anyway
/// (this cell cannot see the distinction — the COMBINED cells below can), or if
/// the provider wrote the files but the frame still inlined the text.
#[test]
#[ignore = "Host-dependent for its siblings' reasons — a real container on the
             reference host. `just gate`'s oci-live-smoke runs it."]
fn a_capture_under_the_combined_bound_is_spooled_and_counted_live() {
    delegated(
        "a_capture_under_the_combined_bound_is_spooled_and_counted_live",
        a_capture_under_the_bound_body(),
    );
}

async fn a_capture_under_the_bound_body() {
    let test = "a_capture_under_the_combined_bound_is_spooled_and_counted_live";
    let binary = workspace_bin("kata-provider-youki");
    let basis = measured_basis();
    let mut supervisor =
        ProviderSupervisor::launch(&launch_spec(&binary, ProviderFloor::Installed, basis))
            .await
            .unwrap_or_else(|e| panic!("{test}: the OCI provider launches: {e}"));
    let root = sweep_root(&supervisor, test);
    // 512 KiB of 'a' — under the 1 MiB default bound, over nothing.
    let argv = [
        format!("{BUSYBOX}/bin/busybox"),
        "sh".to_owned(),
        "-c".to_owned(),
        "head -c 524288 /dev/zero | tr '\\0' a".to_owned(),
    ];
    let argv: Vec<&str> = argv.iter().map(String::as_str).collect();
    let staged = stage_bounded(&root, 41, &argv, 1 << 20);
    let outcome = supervisor
        .run_stage(assignment("capture-under", &staged), staged.plan.clone())
        .await
        .unwrap_or_else(|e| panic!("{test}: the capture-bound stage runs: {e}"));
    assert_eq!(outcome.completed.exit_code, Some(0));
    assert_eq!(
        outcome.completed.stdout_bytes, 524_288,
        "{test}: the frame reports the byte COUNT, which is all the wire carries"
    );
    assert_eq!(outcome.completed.stderr_bytes, 0);
    assert!(
        !outcome.completed.capture_exceeded,
        "{test}: 512 KiB is under the bound — a kill here means the bound counts wrong"
    );
    // THE BYTES, read off the spool and hashed by a second program: the file is
    // the result, the frame's `*_bytes` only promise it exists.
    let spooled = std::fs::read(Path::new(&staged.capture.spool_dir).join("stdout"))
        .expect("the provider wrote the spool it reported");
    assert_eq!(spooled.len(), 524_288);
    assert!(
        spooled.iter().all(|b| *b == b'a'),
        "{test}: 512 KiB of 'a' — the container's exact stdout, spooled"
    );
    let _ = supervisor.shutdown().await;
    println!("CAPTURE-UNDER-BOUND bytes=524288 exceeded=false");
}

/// **A stage that writes PAST the combined bound is KILLED mid-capture — the same
/// kill a wall-time cancel uses — and the frame says `capture_exceeded`.**
///
/// 2 MiB of `a` against a 1 MiB promise. Two host facts close it out: the
/// runtime holds no container afterward (the kill is the unconditional finally),
/// and the spool the completion reports contains the PREFIX the bound allowed —
/// not the whole stream, which is the point of killing rather than truncating.
///
/// **Would red if:** the bound were enforced post-hoc (the frame would carry the
/// whole 2 MiB, or the container would still be listed), or if `capture_exceeded`
/// were never set (the stage would read as a clean exit).
#[test]
#[ignore = "Host-dependent for its siblings' reasons."]
fn a_capture_past_the_combined_bound_kills_the_stage_live() {
    delegated(
        "a_capture_past_the_combined_bound_kills_the_stage_live",
        a_capture_past_the_bound_body(),
    );
}

async fn a_capture_past_the_bound_body() {
    let test = "a_capture_past_the_combined_bound_kills_the_stage_live";
    let binary = workspace_bin("kata-provider-youki");
    let basis = measured_basis();
    let mut supervisor =
        ProviderSupervisor::launch(&launch_spec(&binary, ProviderFloor::Installed, basis))
            .await
            .unwrap_or_else(|e| panic!("{test}: the OCI provider launches: {e}"));
    let root = sweep_root(&supervisor, test);
    let argv = [
        format!("{BUSYBOX}/bin/busybox"),
        "sh".to_owned(),
        "-c".to_owned(),
        "head -c 2097152 /dev/zero | tr '\\0' a".to_owned(),
    ];
    let argv: Vec<&str> = argv.iter().map(String::as_str).collect();
    let staged = stage_bounded(&root, 42, &argv, 1 << 20);
    let outcome = supervisor
        .run_stage(assignment("capture-over", &staged), staged.plan.clone())
        .await
        .unwrap_or_else(|e| panic!("{test}: the over-bound stage reaches a terminal frame: {e}"));
    assert!(
        outcome.completed.capture_exceeded,
        "{test}: a stage over the COMBINED bound reports `capture_exceeded` — the provider killed it, so the frame must SAY so rather than come back clean. Got: {:?}",
        outcome.completed,
    );
    assert!(
        outcome.completed.stdout_bytes <= (1 << 20),
        "{test}: the spool never holds more than the bound — got {} bytes",
        outcome.completed.stdout_bytes,
    );
    // THE KILL, read off the runtime: `delete --force` is the unconditional
    // finally, so no container of this id is registered.
    let listing = youki_list(&staged.runtime_state());
    assert!(
        !listing.contains(&staged.plan.container_id),
        "{test}: the runtime still holds `{id}` after the capture kill — the bound must take \
         the same kill path a cancel does.\n{listing}",
        id = staged.plan.container_id,
    );
    let spooled = std::fs::read(Path::new(&staged.capture.spool_dir).join("stdout"))
        .expect("the provider spooled the prefix it allowed");
    assert_eq!(
        spooled.len() as u64,
        outcome.completed.stdout_bytes,
        "{test}: the file and the frame agree on what was collected"
    );
    let _ = supervisor.shutdown().await;
    println!(
        "CAPTURE-OVER-BOUND exceeded=true spooled={} gone=true",
        spooled.len()
    );
}

/// **The bound is COMBINED: 700 KiB of stdout PLUS 700 KiB of stderr trips a 1 MiB
/// promise even though neither stream alone is over it.**
///
/// This is the property a per-stream bound cannot express and the one the v6
/// protocol switched to: the stage's two spool files are bounded TOGETHER because
/// what they cost the wire and the store is their sum.
///
/// **Would red if:** the bound were applied per-stream (each 700 KiB under 1 MiB
/// → `capture_exceeded` would be false), which is exactly why the two streams
/// are generated in parallel halves of one script.
#[test]
#[ignore = "Host-dependent for its siblings' reasons."]
fn the_combined_bound_counts_stdout_and_stderr_together_live() {
    delegated(
        "the_combined_bound_counts_stdout_and_stderr_together_live",
        the_combined_bound_body(),
    );
}

async fn the_combined_bound_body() {
    let test = "the_combined_bound_counts_stdout_and_stderr_together_live";
    let binary = workspace_bin("kata-provider-youki");
    let basis = measured_basis();
    let mut supervisor =
        ProviderSupervisor::launch(&launch_spec(&binary, ProviderFloor::Installed, basis))
            .await
            .unwrap_or_else(|e| panic!("{test}: the OCI provider launches: {e}"));
    let root = sweep_root(&supervisor, test);
    // 700 KiB to stdout AND 700 KiB to stderr — each under the bound, the pair
    // over it.
    let argv = [
        format!("{BUSYBOX}/bin/busybox"),
        "sh".to_owned(),
        "-c".to_owned(),
        "head -c 716800 /dev/zero | tr '\\0' a; head -c 716800 /dev/zero | tr '\\0' b >&2"
            .to_owned(),
    ];
    let argv: Vec<&str> = argv.iter().map(String::as_str).collect();
    let staged = stage_bounded(&root, 43, &argv, 1 << 20);
    let outcome = supervisor
        .run_stage(assignment("capture-combined", &staged), staged.plan.clone())
        .await
        .unwrap_or_else(|e| panic!("{test}: the combined-bound stage reaches a terminal: {e}"));
    assert!(
        outcome.completed.capture_exceeded,
        "{test}: 700 KiB + 700 KiB trips a 1 MiB COMBINED bound even though each stream is under it — a per-stream read of the bound would answer `false` here. Got: {:?}",
        outcome.completed,
    );
    let listing = youki_list(&staged.runtime_state());
    assert!(
        !listing.contains(&staged.plan.container_id),
        "{test}: the runtime still holds the container after the combined-bound kill:\n{listing}"
    );
    let _ = supervisor.shutdown().await;
    println!("CAPTURE-COMBINED exceeded=true");
}

/// **A runtime client that fails in its OWN delete after the stage exited reports NO
/// exit status — not youki's `255` as if the stage had chosen it.**
///
/// youki 0.7.0's `run` waits for the init, deletes the container, and only then
/// exits with the init's status; an error anywhere on that path is exited as `-1`,
/// which is `255`, with the init's status discarded. The race that reaches it in
/// production — a concurrent `youki kill`'s `stopped` save creating its temporary
/// file after the client's delete listed the container directory, so the final
/// `rmdir` fails `ENOTEMPTY` (`kata_worker::interactive_capsule`'s third outcome, 1 of 60
/// undelayed runs) — has no deterministic trigger without fault injection. This
/// cell reaches the SAME branch deterministically: once the init is running, the
/// host plants an entry the client's `remove_dir_all` cannot unlink (a file inside
/// a `0500` directory in the container directory), then releases the init, which
/// prints a line and exits `7`. The client's delete fails `EACCES`, it exits `255`,
/// and the container directory survives — read off the host before cleanup, which
/// is what proves the branch was reached rather than skipped.
///
/// **Would red if:** the provider forwarded the client's status without first
/// looking for the container directory its delete removes (`Some(255)`).
#[test]
#[ignore = "Host-dependent for its siblings' reasons."]
fn a_client_whose_own_delete_failed_reports_no_exit_status_live() {
    delegated(
        "a_client_whose_own_delete_failed_reports_no_exit_status_live",
        a_client_whose_own_delete_failed_body(),
    );
}

async fn a_client_whose_own_delete_failed_body() {
    use std::os::unix::fs::PermissionsExt as _;

    let test = "a_client_whose_own_delete_failed_reports_no_exit_status_live";
    let binary = workspace_bin("kata-provider-youki");
    let mut supervisor = ProviderSupervisor::launch(&launch_spec(
        &binary,
        ProviderFloor::Installed,
        measured_basis(),
    ))
    .await
    .unwrap_or_else(|e| panic!("{test}: launching the OCI provider failed: {e}"));
    let root = sweep_root(&supervisor, test);
    let staged = stage(
        &root,
        47,
        &[
            &format!("{BUSYBOX}/bin/busybox"),
            "sh",
            "-c",
            "while [ ! -e /out/release ]; do sleep 0.05; done; echo exiting-7; exit 7",
        ],
    );
    supervisor
        .assign_stage(assignment("oci-delete-fails", &staged), staged.plan.clone())
        .await
        .unwrap_or_else(|e| panic!("{test}: the provider did not accept the assignment: {e}"));

    let state = staged.runtime_state();
    let container_dir = state.join(&staged.plan.container_id);
    let running = tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            if container_init_pid(&state, &staged.plan.container_id).is_some() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await;
    if running.is_err() {
        let said = supervisor.await_stage_completion("oci-delete-fails").await;
        panic!(
            "{test}: no container init appeared under {state} within 30s, so there is no \
             running container whose delete could fail. What the provider said instead: {said:?}",
            state = state.display(),
        );
    }
    let pin = container_dir.join("kata-live-undeletable");
    std::fs::create_dir(&pin).expect("the pin directory is created in the container directory");
    std::fs::write(pin.join("held"), b"").expect("the pinned entry is written");
    std::fs::set_permissions(&pin, std::fs::Permissions::from_mode(0o500))
        .expect("the pin directory is made unwritable");
    std::fs::write(staged.out.join("release"), b"").expect("the release file is written");

    let completed = supervisor
        .await_stage_completion("oci-delete-fails")
        .await
        .unwrap_or_else(|e| panic!("{test}: the provider produced no terminal frame: {e}"));
    // NON-VACUITY, from the host: the init ran to its own exit, and the client's
    // delete did NOT finish — its directory, and the entry it could not unlink, are
    // still there.
    let stdout = staged.spooled("stdout");
    let residue = pin.join("held").exists();
    std::fs::set_permissions(&pin, std::fs::Permissions::from_mode(0o700)).ok();
    std::fs::remove_dir_all(&container_dir).ok();
    let _ = supervisor.shutdown().await;
    assert_eq!(
        stdout, "exiting-7\n",
        "{test}: the init did not reach its own exit, so the client's delete was not what \
         failed"
    );
    assert!(
        residue,
        "{test}: the container directory's pinned entry is gone, so the client's delete did not \
         fail and this cell proved nothing about a failed one"
    );
    assert_eq!(
        completed.exit_code,
        None,
        "{test}: the client exited youki's own 255 with its delete unfinished; that number is \
         not the stage's exit status and must not be reported as one.\nstderr: {err}",
        err = staged.spooled("stderr"),
    );
    println!(
        "OCI-PROVIDER CLIENT-DELETE-FAILED container={id} init-stdout=exiting-7 \
         residue-at-answer=present reported-exit=None",
        id = staged.plan.container_id,
    );
}

/// **A stage that EXITS 255 by itself still reports `Some(255)`.** The twin of the
/// cell above: the client's delete finishes, so its 255 is the init's, forwarded.
///
/// **Would red if:** the provider read every 255 as the client's own, or looked for
/// residue somewhere present on every run.
#[test]
#[ignore = "Host-dependent for its siblings' reasons."]
fn a_stage_that_exits_255_reports_255_live() {
    delegated(
        "a_stage_that_exits_255_reports_255_live",
        a_stage_that_exits_255_body(),
    );
}

async fn a_stage_that_exits_255_body() {
    let test = "a_stage_that_exits_255_reports_255_live";
    let binary = workspace_bin("kata-provider-youki");
    let mut supervisor = ProviderSupervisor::launch(&launch_spec(
        &binary,
        ProviderFloor::Installed,
        measured_basis(),
    ))
    .await
    .unwrap_or_else(|e| panic!("{test}: launching the OCI provider failed: {e}"));
    let root = sweep_root(&supervisor, test);
    let staged = stage(
        &root,
        53,
        &[&format!("{BUSYBOX}/bin/busybox"), "sh", "-c", "exit 255"],
    );
    let outcome = supervisor
        .run_stage(assignment("oci-exit-255", &staged), staged.plan.clone())
        .await
        .unwrap_or_else(|e| panic!("{test}: the provider did not run the stage: {e}"));
    let listing = youki_list(&staged.runtime_state());
    let _ = supervisor.shutdown().await;
    assert_eq!(
        outcome.completed.exit_code,
        Some(255),
        "{test}: the stage exited 255 by itself.\nstderr: {err}",
        err = staged.spooled("stderr"),
    );
    assert!(
        !listing.contains(&staged.plan.container_id),
        "{test}: the runtime still holds `{id}` after a clean exit:\n{listing}",
        id = staged.plan.container_id,
    );
    println!(
        "OCI-PROVIDER STAGE-EXIT-255 container={id} reported-exit=Some(255)",
        id = staged.plan.container_id,
    );
}

/// The planted `env:` key: an admissible credential name (not reserved, not
/// `KATA_`) and a value no host variable holds.
const CREDENTIAL_WITNESS_VAR: &str = "WITNESS_PROVIDER_API_KEY";
const CREDENTIAL_WITNESS_VALUE: &str = "sk-witness-7f3a9c1e5d2b8046";

/// A process's initial environment as the kernel serves it, `NAME=value` per entry.
fn proc_environ(pid: u32) -> std::io::Result<Vec<Vec<u8>>> {
    let bytes = std::fs::read(format!("/proc/{pid}/environ"))?;
    Ok(bytes
        .split(|b| *b == 0)
        .filter(|entry| !entry.is_empty())
        .map(<[u8]>::to_vec)
        .collect())
}

/// The variable NAMES of an environment read by [`proc_environ`].
fn environ_names(environ: &[Vec<u8>]) -> Vec<String> {
    let mut names: Vec<String> = environ
        .iter()
        .map(|entry| {
            let name = entry.split(|b| *b == b'=').next().unwrap_or_default();
            String::from_utf8_lossy(name).into_owned()
        })
        .collect();
    names.sort();
    names
}

/// A stand-in for the pinned runtime: a shell script that copies the environment it was
/// started with (`/proc/$$/environ`, the kernel's copy of its `execve` block) into
/// `record`, one file per invocation, then `exec`s the real `youki` with the same
/// arguments — so the runtime runs with exactly the environment the record holds.
///
/// Why a stand-in: the `youki` client is not dumpable, so its own
/// `/proc/<pid>/environ` refuses a same-uid reader (`EACCES`, measured). The plan pins
/// the stand-in's own digest, which the provider checks as it would the real one's.
fn recording_runtime(record: &Path, real: &str) -> PinnedRuntime {
    use sha2::Digest as _;
    use std::os::unix::fs::PermissionsExt as _;
    let script = record.join("youki");
    let body = format!(
        "#!/bin/sh\n{BUSYBOX}/bin/busybox cp /proc/$$/environ {record}/environ.$$\nexec {real} \"$@\"\n",
        record = record.display(),
    );
    std::fs::write(&script, body.as_bytes()).expect("writing the recording runtime");
    std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755))
        .expect("making the recording runtime executable");
    PinnedRuntime {
        store_path: script.to_string_lossy().into_owned(),
        sha256: format!("{:x}", sha2::Sha256::digest(body.as_bytes())),
    }
}

/// **An `env:` key in the worker's environment is in neither the provider's nor the
/// runtime's.**
///
/// The process that launches the provider (this test, in the worker's role) holds a
/// planted key. The provider runs a stage to completion, so it spawns the runtime for
/// `run` and its own teardown. The provider's environment is read from the kernel's
/// `/proc/<pid>/environ` while it is alive; each runtime invocation's environment is
/// the kernel's copy recorded by [`recording_runtime`]. Neither read goes through
/// kata: the witness shares no code with the spawn.
///
/// Both environments are asserted EMPTY — the allowlist is no variable at all, stated
/// here independently — so the cell refuses any inherited variable, not just this one.
///
/// # Would red if
///
/// Either spawn inherited the worker's environment (the R2-07 defect), or passed any
/// variable at all.
#[test]
#[ignore = "Host-dependent for its siblings' reasons."]
fn an_env_credential_reaches_neither_the_provider_nor_the_runtime_live() {
    delegated(
        "an_env_credential_reaches_neither_the_provider_nor_the_runtime_live",
        an_env_credential_reaches_neither_the_provider_nor_the_runtime_body(),
    );
}

async fn an_env_credential_reaches_neither_the_provider_nor_the_runtime_body() {
    let test = "an_env_credential_reaches_neither_the_provider_nor_the_runtime_live";
    let planted = format!("{CREDENTIAL_WITNESS_VAR}={CREDENTIAL_WITNESS_VALUE}").into_bytes();
    let value = CREDENTIAL_WITNESS_VALUE.as_bytes();
    let holds_value = |environ: &[Vec<u8>]| {
        environ
            .iter()
            .any(|entry| entry.windows(value.len()).any(|w| w == value))
    };

    // PRESENT where it must be: the worker's own environment, from the kernel.
    let worker = proc_environ(std::process::id())
        .unwrap_or_else(|e| panic!("{test}: /proc/self/environ unreadable: {e}"));
    assert!(
        worker.contains(&planted),
        "{test}: the planted key is not in the worker-role process's own environment, so its \
         absence below would prove nothing. Names: {:?}",
        environ_names(&worker),
    );

    let binary = workspace_bin("kata-provider-youki");
    let mut supervisor = ProviderSupervisor::launch(&launch_spec(
        &binary,
        ProviderFloor::Installed,
        measured_basis(),
    ))
    .await
    .unwrap_or_else(|e| panic!("{test}: launching the OCI provider failed: {e}"));
    let provider_pid = supervisor
        .provider_pid()
        .unwrap_or_else(|| panic!("{test}: kata observed no pid for the provider it spawned"));
    let provider = proc_environ(provider_pid)
        .unwrap_or_else(|e| panic!("{test}: /proc/{provider_pid}/environ unreadable: {e}"));

    let root = sweep_root(&supervisor, test);
    let mut staged = stage(&root, 83, &[&format!("{BUSYBOX}/bin/busybox"), "true"]);
    let record = tempfile::Builder::new()
        .prefix("kata-oci-provider-environ-")
        .tempdir()
        .expect("creating the record directory");
    let real = staged.plan.youki.store_path.clone();
    staged.plan.youki = recording_runtime(record.path(), &real);
    let outcome = supervisor
        .run_stage(assignment("oci-environ", &staged), staged.plan.clone())
        .await;
    let _ = supervisor.shutdown().await;
    let outcome =
        outcome.unwrap_or_else(|e| panic!("{test}: the provider did not run the stage: {e}"));
    // NON-VACUITY: the real runtime ran the container under the recorded environment.
    assert_eq!(
        outcome.completed.exit_code,
        Some(0),
        "{test}: the stage did not exit 0 through the recording runtime.\nstderr: {err}",
        err = staged.spooled("stderr"),
    );

    let mut runtime: Vec<(String, Vec<Vec<u8>>)> = std::fs::read_dir(record.path())
        .expect("reading the record directory")
        .flatten()
        .filter(|entry| entry.file_name().to_string_lossy().starts_with("environ."))
        .map(|entry| {
            let bytes = std::fs::read(entry.path()).expect("reading a recorded environment");
            let environ = bytes
                .split(|b| *b == 0)
                .filter(|e| !e.is_empty())
                .map(<[u8]>::to_vec)
                .collect();
            (entry.file_name().to_string_lossy().into_owned(), environ)
        })
        .collect();
    runtime.sort();
    assert!(
        !runtime.is_empty(),
        "{test}: the recording runtime recorded no invocation, so nothing was observed of the \
         runtime's environment"
    );

    let allowlist: Vec<String> = Vec::new();
    assert!(
        !holds_value(&provider) && environ_names(&provider) == allowlist,
        "{test}: the provider's environment is not empty: names {:?}, holds the \
         planted key's value: {}",
        environ_names(&provider),
        holds_value(&provider),
    );
    for (file, environ) in &runtime {
        assert!(
            !holds_value(environ) && environ_names(environ) == allowlist,
            "{test}: a runtime invocation ({file})'s environment is not exactly the allowlist: \
             names {:?}, holds the planted key's value: {}",
            environ_names(environ),
            holds_value(environ),
        );
    }
    println!(
        "OCI-PROVIDER ENVIRON worker-holds-key=yes provider={provider_pid} names={:?} \
         runtime-invocations={} names={:?}",
        environ_names(&provider),
        runtime.len(),
        runtime
            .iter()
            .map(|(_, environ)| environ_names(environ))
            .collect::<Vec<_>>(),
    );
}
