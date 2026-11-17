//! The planned bundle, run as a real
//! rootless container, observed from INSIDE and read back from the HOST.
//!
//! # This file must PASS on a host that can deliver rootless OCI, and RED on one that cannot
//!
//! It NEVER SKIPS and has no capability probe, for the reason
//! `tests/oci_runtime_live.rs` states at length: the claim under test is *"the
//! `config.json` kata plans starts a container whose mount table is exactly what
//! kata planned"*, and a test that quietly returned on a host without youki would
//! convert that claim into the absence of evidence. On a host with no pinned
//! youki, no installed AppArmor profile, no delegated user scope, or no realised
//! fixture store path, every test here FAILS and the panic names what refused.
//!
//! # Why it is nonetheless `#[ignore]`d, exactly as `oci_runtime_live.rs` is
//!
//! `just gate` is host-independent BY DESIGN — AGENTS.md requires both L1 tiers
//! before every push, and `gate_exclusion`'s
//! `the_gate_names_the_containment_it_does_not_prove` pins the gate's own
//! statement that it proves no containment — so a binary that needs a pinned
//! youki, an installed AppArmor profile, a delegated user scope AND a realised
//! Nix store path cannot ride the pre-commit lane. It rides the containment side,
//! where `_containment-preconditions` already BLOCKS on the same functional fact
//! (a real rootless container in a delegated scope).
//!
//! The containment lane's `oci-live-smoke` step selects `binary(oci_bundle_live)`.
//! By hand:
//!
//! ```text
//! cargo nextest run -p kata-worker -P live-smoke -E 'binary(oci_bundle_live)' --run-ignored all
//! ```
//!
//! # The realised store path is a HOST fact this test inherits and refuses
//!
//! The closure's one store object must already exist at its exact path, because
//! the container rbinds THAT path and execs the binary inside it. There is no
//! probe-and-skip: `stage` fails with the `nix-store --realise <path>` command
//! that fixes it, which is kata's own rule — inherit the host's answer, refuse
//! when there is none, never invent one. **Owning that root is the environment
//! plane's job, not this test's**: `kata_types::nix_environment`'s environment
//! plane declares, ROOTS and reconciles a closure (`nix_environments`). The bare
//! `nix-store --realise` here is a fixture's precondition, on purpose: it has no
//! `--add-root`, so a `nix-store --gc` reds this test.
//!
//! # What is asserted against something that does not share the code under test
//!
//! * the container's mount table is read out of `/proc/self/mountinfo` BY THE
//!   GUEST — the kernel's own answer, written to a file kata reads afterwards from
//!   the host. Nothing in kata produced it and nothing in kata parsed the spec to
//!   get it;
//! * the `config.json` youki reads is the plan's bytes VERBATIM
//!   (`oci_bundle::materialize_bundle` writes `plan.config_json` with no
//!   re-serialization), so the container is built from the same bytes the golden
//!   pins;
//! * the read-only-root verdict is `touch(1)`'s exit status and `errno` string
//!   inside the container against `/` itself — a path that EXISTS — so the only
//!   refusal is `EROFS`, not a kata assertion about a mount option;
//! * the namespaces, the id mapping and the capability sets are read by the GUEST
//!   out of `/proc/self/ns/*`, `/proc/self/{uid,gid}_map` and `/proc/self/status`,
//!   and the namespace inodes are compared against the HOST process's own;
//! * the launch is `kata_worker::oci_runtime::run_bundle` — the production seam
//!   the certification uses — so the `systemd-run --user --scope -p
//!   Delegate=yes` argv, the watchdog and the `delete --force` teardown are kata's
//!   and not this file's.

#![cfg(target_os = "linux")]

use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Path, PathBuf},
    time::Duration,
};

use kata_provider_protocol::OciBundlePlan;
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
use kata_worker::oci_bundle::{BundleMounts, materialize_bundle, spec_for};
use kata_worker::oci_cgroup::{AttemptContainment, OciParentCgroup};

/// The same real store path the golden names — see
/// `tests/oci_bundle_golden.rs::BUSYBOX`. One statically linked busybox is the
/// whole closure, so the mount table this test reads has exactly one store entry
/// in it and a second one would be visible immediately.
const BUSYBOX: &str =
    "/nix/store/qddzvnv6b0805nkvbqddbswddcfhx814-busybox-static-x86_64-unknown-linux-musl-1.37.0";
const BUSYBOX_NAR_HASH: &str = "sha256-d7JNm1d4Wo1oSA2pvoRLt1vqyAhSlIsjE0GckcLiSeA=";
const BUSYBOX_NAR_SIZE: u64 = 1_495_056;

/// Watchdog budget for one container. Generous: the container runs `true` or one
/// `sh -c`, so anything approaching this is a hang rather than slow work.
const BUDGET: Duration = Duration::from_secs(60);

fn hash(byte: u8) -> ContentHash {
    ContentHash::new([byte; 32])
}

fn environment() -> NixEnvironmentManifest {
    NixEnvironmentManifest::new(
        "bundle-busybox",
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

/// `occurrence` varies per run so the two containers in this file have DIFFERENT
/// ids: `OciBundlePlan::container_id` is derived from the capsule's content
/// address, and a runtime that already holds a container under that name refuses
/// the second `run` on a name collision.
fn capsule(occurrence: u8, argv: &[&str]) -> Capsule {
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
    .expect("the fixture capsule is well formed")
}

/// Everything one container run needs on disk, alive until after teardown.
struct Staged {
    _root: tempfile::TempDir,
    /// The KATA-OWNED parent cgroup the container's leaf is created beneath, held
    /// for the run's lifetime: its `Drop` is what removes the two directories, and
    /// dropping it early would `rmdir` the cgroup the container is living in.
    ///
    /// Never READ, and that is what it is for — a lifetime, not a value. The
    /// underscore says so to the compiler; `oci_provider_live.rs`'s sibling is read,
    /// because that file asserts about the placement.
    _parent: OciParentCgroup,
    bundle: PathBuf,
    out: PathBuf,
    plan: OciBundlePlan,
}

/// Marks the re-exec'd inner run, carrying the NAME of the test that asked for it.
const INNER_ENV: &str = "KATA_OCI_BUNDLE_DELEGATED_INNER";

/// Run `body` inside a delegated user scope, re-exec'ing this binary if needed.
///
/// **The placement forces it.** Kata owns
/// the parent cgroup the container's leaf goes under, and creating one requires a
/// cgroup this process may write a child into — which a login session's is not on
/// this class of host. There is no probe and no skip: a host without `systemd-run
/// --user` fails at the spawn, and that is the answer.
///
/// Deliberately re-spelled rather than shared with the two sibling live files, for
/// the reason `oci_provider_live.rs` states: what must not be duplicated is what a
/// delegated scope IS, and that is one `systemd-run` argv in all three plus
/// `just _containment-preconditions` blocking the lane on the same fact.
fn delegated(test: &'static str, body: fn()) {
    if std::env::var(INNER_ENV).as_deref() == Ok(test) {
        return body();
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
        .output()
        .unwrap_or_else(|error| {
            panic!(
                "re-exec of `{test}` inside `systemd-run --user --scope -p Delegate=yes` could not \
                 be spawned ({error}). A delegated scope is what lets an unprivileged process \
                 create the parent cgroup kata places this container under, and without one there \
                 is no placement to plan — see `just _containment-preconditions`."
            )
        });
    eprintln!(
        "--- delegated inner run of `{test}` stdout ---\n{}\n--- stderr ---\n{}\n---",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    kata_test_utils::delegated_scope::assert_inner_ran_the_one_test(test, &output);
}

/// Plan a container for `argv`, then put its bundle, `/work` and `/out` on disk.
///
/// The bundle's `config.json` is `plan.config_json` written byte-for-byte by
/// production code; this function never touches the JSON.
fn stage(occurrence: u8, argv: &[&str]) -> Staged {
    assert!(
        Path::new(BUSYBOX).join("bin/busybox").is_file(),
        "the closure's only store object is not realised at {BUSYBOX}. This test rbinds that exact \
         path into a container and execs the binary inside it, so there is nothing to observe \
         without it. Realise it with `nix-store --realise {BUSYBOX}`."
    );

    let root = tempfile::Builder::new()
        .prefix("kata-oci-bundle-live-")
        .tempdir()
        .expect("creating the staging tempdir");
    // The ATTEMPT ROOT, and `BundleMounts::under` derives `work` and `out` beneath
    // it — the same two names the worker's materializer uses. This test creates
    // exactly the directories the constructor named, so a layout change in
    // production moves both sides at once instead of leaving this rig binding paths
    // nobody writes to.
    let attempt_root = root.path().join("attempt");
    let mounts = BundleMounts::under(&attempt_root, 16 * 1024 * 1024)
        .expect("an absolute attempt root with a non-zero /tmp size");
    let out = mounts.out().to_path_buf();
    let bundle = root.path().join("bundle");
    for directory in [mounts.work(), mounts.out()] {
        std::fs::create_dir_all(directory).expect("creating a materialized root");
    }

    // THE KATA-OWNED PARENT, created under the delegation this host MEASURED — not
    // under a directory that happens to exist. The container id it is named for is
    // derived from the capsule, so it is planned first.
    let capsule = capsule(occurrence, argv);
    let delegation = kata_worker::sandbox_bounds::cgroup_delegation();
    let usable = delegation.usable_parent.as_deref().unwrap_or_else(|| {
        panic!(
            "this host delegates no cgroup kata may create a child under, so there is no parent to \
             place the container beneath and nothing here can be observed. The measurement says: \
             {evidence}",
            evidence = delegation.evidence,
        )
    });
    let sweep_root = usable.join(format!("kata.oci-bundle-live.{}", std::process::id()));
    std::fs::create_dir_all(&sweep_root).expect("creating this rig's own sweep root");
    for controller in kata_worker::sandbox_bounds::capsule_subtree_controllers(delegation) {
        let _ = std::fs::write(
            sweep_root.join("cgroup.subtree_control"),
            format!("+{}", controller.token()),
        );
    }
    let container_id = format!("kata-{}", capsule.id().0);
    let parent =
        OciParentCgroup::establish(&sweep_root, &container_id, delegation, &capsule.budgets())
            .unwrap_or_else(|e| {
                panic!("the kata-owned parent cgroup could not be established: {e}")
            });
    let containment =
        AttemptContainment::new(parent.path().to_path_buf(), attempt_root.join("oci"))
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
        "the rig derived the container id the same way the producer does; a divergence here would \
         name the parent cgroup after a container that is not the one started"
    );
    materialize_bundle(&plan, &bundle).expect("writing the bundle");

    Staged {
        _root: root,
        _parent: parent,
        bundle,
        out,
        plan,
    }
}

/// Run a staged bundle through the PRODUCTION launch seam and return its exit
/// code plus whatever it wrote.
fn run(staged: &Staged) -> (Option<String>, String, String) {
    let pin = YoukiPin::embedded();
    let observed = kata_worker::oci_runtime::run_bundle(
        Path::new(pin.store_path()),
        &staged.bundle,
        staged.bundle.parent().expect("the bundle has a parent"),
        &staged.plan.container_id,
        BUDGET,
    )
    .unwrap_or_else(|error| {
        panic!(
            "the delegated-scope launch of the planned bundle could not run ({error}). A host \
             without the pinned youki at {path}, without its installed AppArmor profile, or \
             without `systemd-run --user` cannot deliver the rootless-OCI prerequisite at all — \
             run `just _containment-preconditions` for the one-line diagnosis. There is no skip \
             here on purpose.",
            path = pin.store_path(),
        )
    });
    (observed.exit, observed.stdout, observed.stderr)
}

/// **The planned bundle starts, runs and exits 0.**
///
/// The cheapest possible subject, and it is not redundant with the observation
/// test below: if this reds and that one also reds, the cause is the LAUNCH, and if
/// only the other reds the cause is the MOUNT TABLE. Two failures that would
/// otherwise be one panic.
///
/// # Would red if
///
/// The spec named a namespace this kernel will not unshare rootless, a mount youki
/// refuses, a resource bound a non-delegated cgroup cannot carry, or a seccomp
/// fence libseccomp will not load.
#[test]
#[ignore = "HOST-DEPENDENT (pinned youki, its installed AppArmor \
             profile, a delegated user scope, and the fixture closure's store path realised). \
             `just gate` is host-independent by design, so this rides the containment side: \
             `_containment-preconditions` blocks on the same functional fact today, and \
             the containment lane's `oci-live-smoke` step runs it. Run it now with \
             `cargo nextest run -p kata-worker -P live-smoke -E 'binary(oci_bundle_live)' --run-ignored all`."]
fn the_planned_bundle_runs_a_real_rootless_container() {
    delegated(
        "the_planned_bundle_runs_a_real_rootless_container",
        the_planned_bundle_runs_a_real_rootless_container_body,
    );
}

fn the_planned_bundle_runs_a_real_rootless_container_body() {
    let staged = stage(1, &[&format!("{BUSYBOX}/bin/busybox"), "true"]);
    let (exit, stdout, stderr) = run(&staged);
    assert_eq!(
        exit.as_deref(),
        Some("0"),
        "the planned container did not exit 0 (exit {exit:?}).\nstdout: {stdout}\nstderr: {stderr}"
    );
    println!(
        "OCI-BUNDLE live-launch container={} exit=0 bundle-bytes={}",
        staged.plan.container_id,
        staged.plan.config_json.len()
    );
}

/// **THE EXIT CRITERION: the guest's own mount table is exactly what kata planned,
/// and the root really is read-only.**
///
/// The container writes `/proc/self/mountinfo` and the result of a `touch` against
/// the read-only rootfs into `/out`, which is a host directory this process reads
/// afterwards. Every verdict below therefore comes out of the kernel and out of
/// busybox, neither of which shares a line of code with `oci_bundle`.
///
/// # What "exactly" means here, stated rather than approximated
///
/// The observed mount points must be the CORE set — `/`, the closure's one store
/// path, `/work`, `/out`, `/tmp`, `/proc`, `/dev`, `/dev/pts`, `/dev/shm` — plus
/// nothing except entries drawn from runc's own rootless `maskedPaths` /
/// `readonlyPaths`, which a runtime materializes as binds over `/proc` entries. A
/// mount point outside that union fails and is printed by name. In particular
/// there is NO `/sys` and no host path anywhere.
///
/// # Would red if
///
/// A host directory leaked in (a `/etc`, a `/usr`, the whole `/nix/store`), `/sys`
/// came back, `root.readonly` were dropped, or a planned mount silently did not
/// land.
#[test]
#[ignore = "HOST-DEPENDENT (pinned youki, its installed AppArmor \
             profile, a delegated user scope, and the fixture closure's store path realised). \
             `just gate` is host-independent by design, so this rides the containment side: \
             `_containment-preconditions` blocks on the same functional fact today, and \
             the containment lane's `oci-live-smoke` step runs it. Run it now with \
             `cargo nextest run -p kata-worker -P live-smoke -E 'binary(oci_bundle_live)' --run-ignored all`."]
fn the_containers_own_mount_table_is_exactly_the_plan() {
    delegated(
        "the_containers_own_mount_table_is_exactly_the_plan",
        the_containers_own_mount_table_is_exactly_the_plan_body,
    );
}

fn the_containers_own_mount_table_is_exactly_the_plan_body() {
    let staged = stage(
        7,
        &[
            "busybox",
            "sh",
            "-c",
            // `/x` and not `/etc/x`: the rootfs holds no `/etc`, so `touch /etc/x` is
            // `ENOENT` on ANY rootfs, read-only or not. `/` exists, so creating a file
            // directly beneath it is refused by exactly one thing — a read-only mount.
            "cat /proc/self/mountinfo > /out/mountinfo; touch /x 2>/out/root_err; \
             echo $? > /out/root_rc",
        ],
    );
    let (exit, stdout, stderr) = run(&staged);
    assert_eq!(
        exit.as_deref(),
        Some("0"),
        "the observing container did not exit 0 (exit {exit:?}).\nstdout: {stdout}\nstderr: \
         {stderr}"
    );

    let read = |name: &str| {
        std::fs::read_to_string(staged.out.join(name)).unwrap_or_else(|error| {
            panic!(
                "the container did not leave {name} in /out ({error}). /out is a read-write rbind \
                 of a host directory this process owns; an absent file means the guest could not \
                 write it, which is itself the finding"
            )
        })
    };
    let mountinfo = read("mountinfo");
    let root_rc = read("root_rc");
    let root_err = read("root_err");

    // `/proc/self/mountinfo`, per `proc(5)`:
    //
    //   36 35 98:0 /mnt1 /mnt2 rw,noatime <optional…> - ext3 /dev/root rw,errors=…
    //   1  2  3    4     5     6          7..          8 9    10       11
    //
    // Fields 1..=6 are positional; the OPTIONAL fields run from 7 up to the `-`
    // separator, and the propagation tags (`shared:`, `master:`, `propagate_from:`)
    // are among them. So the mount point is index 4, the per-mount options index 5,
    // and the optional fields are everything from index 6 to the `-`.
    struct MountRow {
        options: BTreeSet<String>,
        optional: Vec<String>,
    }
    let rows: BTreeMap<String, MountRow> = mountinfo
        .lines()
        .filter_map(|line| {
            let fields: Vec<&str> = line.split_whitespace().collect();
            let point = (*fields.get(4)?).to_owned();
            let options = fields
                .get(5)?
                .split(',')
                .map(str::to_owned)
                .collect::<BTreeSet<String>>();
            let separator = fields.iter().position(|field| *field == "-")?;
            let optional = fields
                .get(6..separator)?
                .iter()
                .map(|field| (*field).to_owned())
                .collect();
            Some((point, MountRow { options, optional }))
        })
        .collect();
    let observed: BTreeSet<String> = rows.keys().cloned().collect();
    assert!(
        observed.len() > 5,
        "the guest reported only {} mount points, which is too few to be a real container's table \
         — the parse is wrong and every comparison below would pass against almost nothing. Raw:\n\
         {mountinfo}",
        observed.len()
    );

    let core: BTreeSet<String> = [
        "/", BUSYBOX, "/work", "/out", "/tmp", "/proc", "/dev", "/dev/pts", "/dev/shm",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect();
    let missing: Vec<&String> = core.difference(&observed).collect();
    assert!(
        missing.is_empty(),
        "the container is MISSING mount points kata planned: {missing:?}. Observed:\n{observed:#?}"
    );

    // THE OCI SPEC'S DEFAULT DEVICES. Not in the plan and not omittable: a runtime
    // MUST provide these six, and a rootless runtime cannot `mknod`, so it binds
    // the host's `devtmpfs` nodes. Asserted PRESENT rather than merely tolerated —
    // a container with no /dev/null is broken, so their disappearance is a failure
    // in the other direction. See `oci_bundle`'s module docs.
    let default_devices: BTreeSet<String> = [
        "/dev/null",
        "/dev/zero",
        "/dev/full",
        "/dev/tty",
        "/dev/random",
        "/dev/urandom",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect();
    let missing_devices: Vec<&String> = default_devices.difference(&observed).collect();
    assert!(
        missing_devices.is_empty(),
        "the container is missing OCI default devices {missing_devices:?}. The spec requires them \
         and a rootless runtime binds the host's nodes to provide them; a container without \
         /dev/null is broken rather than hermetic. Full table:\n{mountinfo}"
    );

    // runc 1.3.6's rootless maskedPaths + readonlyPaths, the same list
    // `oci_bundle::MASKED_PATHS` / `READONLY_PATHS` render — quoted here as the
    // reference runtime's own answer so the permitted extras are not whatever the
    // run happened to show.
    let protections: BTreeSet<String> = [
        "/proc/acpi",
        "/proc/asound",
        "/proc/kcore",
        "/proc/keys",
        "/proc/latency_stats",
        "/proc/timer_list",
        "/proc/timer_stats",
        "/proc/sched_debug",
        "/sys/firmware",
        "/proc/scsi",
        "/proc/bus",
        "/proc/fs",
        "/proc/irq",
        "/proc/sys",
        "/proc/sysrq-trigger",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect();
    let unexpected: Vec<&String> = observed
        .difference(&core)
        .filter(|point| !protections.contains(*point) && !default_devices.contains(*point))
        .collect();
    assert!(
        unexpected.is_empty(),
        "the container carries mount points that are NEITHER what kata planned, NOR one of the \
         OCI spec's default devices, NOR one of runc's rootless protections: {unexpected:?}. \
         Anything here is host state reaching a stage that was told it was hermetic. Full \
         table:\n{mountinfo}"
    );
    assert!(
        !observed.contains("/sys"),
        "the container mounted /sys. This route deliberately does not: /sys exposes the host's \
         devices, firmware and kernel tunables, and its cgroup hierarchy is how a stage would \
         read — and on a delegated tree widen — the bounds kata placed on it"
    );
    assert!(
        observed
            .iter()
            .filter(|point| point.starts_with("/nix/store"))
            .count()
            == 1,
        "the closure has ONE store object and the container must see exactly one store mount: \
         {observed:#?}"
    );

    // ---------------------------------------------------------------------
    // The OPTIONS, not just the mount points. A mount that landed at the
    // right place with the wrong flags is the failure a point-set comparison
    // cannot see — a writable Nix store, an executable /out, a /work the stage
    // cannot write to. Read out of the KERNEL's own per-mount option field.
    // ---------------------------------------------------------------------
    let row = |point: &str| -> &MountRow {
        rows.get(point)
            .unwrap_or_else(|| panic!("no mountinfo row for {point}; table:\n{mountinfo}"))
    };
    for (point, required, forbidden) in [
        // THE ROOTFS itself, from the kernel's own option field. `root.readonly` is
        // what makes it `ro`; the `touch /x` below is the behavioural half.
        ("/", &["ro"][..], &["rw"][..]),
        // The closure's store object is READ-ONLY. A writable store bind would let
        // one stage change another's inputs, since store objects are shared by
        // every capsule binding the same closure.
        (BUSYBOX, &["ro", "nosuid", "nodev"][..], &["rw"][..]),
        // `/work` is the stage's own tree: writable, and executable because a
        // stage legitimately builds and runs binaries in it.
        (
            "/work",
            &["rw", "nosuid", "nodev"][..],
            &["ro", "noexec"][..],
        ),
        // `/out` is a RESULT directory kata reads afterwards; nothing in it is
        // ever meant to run.
        (
            "/out",
            &["rw", "nosuid", "nodev", "noexec"][..],
            &["ro"][..],
        ),
        ("/tmp", &["rw", "nosuid", "nodev"][..], &["ro"][..]),
    ] {
        let observed_options = &row(point).options;
        for option in required {
            assert!(
                observed_options.contains(*option),
                "the {point} mount is missing `{option}`. The kernel reports \
                 {observed_options:?}, and an option kata planned that did not land is a \
                 containment property silently absent"
            );
        }
        for option in forbidden {
            assert!(
                !observed_options.contains(*option),
                "the {point} mount carries `{option}`, which kata did not plan. The kernel \
                 reports {observed_options:?}"
            );
        }
    }

    // PROPAGATION. Every planned mount must be detached from the host's peer
    // groups: a `shared:` or `master:` tag means a later HOST mount under that
    // subtree appears inside a running container that was told it was hermetic.
    // This is what `rprivate` buys and what a bare `private` measurably does not —
    // under `private` the closure path, `/work` and `/out` all report `master:1` here.
    //
    // `/` is EXCLUDED and named: it is `root.path`, not a `spec.mounts` entry, and
    // this route sets no `linux.rootfsPropagation`. Detaching the rootfs is a
    // separate decision with its own consequences and is not claimed here.
    let planned: Vec<&str> = [
        BUSYBOX, "/work", "/out", "/tmp", "/proc", "/dev", "/dev/pts", "/dev/shm",
    ]
    .to_vec();
    for point in &planned {
        let tags: Vec<&String> = row(point)
            .optional
            .iter()
            .filter(|field| {
                field.starts_with("shared:")
                    || field.starts_with("master:")
                    || field.starts_with("propagate_from:")
            })
            .collect();
        assert!(
            tags.is_empty(),
            "the {point} mount carries propagation tag(s) {tags:?}, so it is still in a peer \
             group with the host. A host mount under that subtree would appear inside a running \
             container that was told it was hermetic. TWO levers remove this and both are \
             required: `linux.rootfsPropagation = \"private\"` (the tree-level one — unset, youki \
             makes the rootfs rslave and every mount created beneath it inherits slave-ness, which \
             is how this tag survived `rprivate` on the rbind itself), and `rprivate` rather than \
             `private` in each rbind's own options (a bare `private` covers the top mount only). \
             MEASURED: dropping either one reds this assertion"
        );
    }

    // The read-only root, read out of `touch`'s own answer.
    assert_ne!(
        root_rc.trim(),
        "0",
        "`touch /x` SUCCEEDED inside the container. root.readonly is the only thing standing \
         between a stage and a writable rootfs it can leave state in; a success here means the \
         plan's `readonly: true` did not take. stderr the guest captured: {root_err:?}"
    );
    assert!(
        root_err.to_lowercase().contains("read-only file system"),
        "`touch /x` failed with something other than EROFS: {root_err:?} (rc {rc:?}). `/` \
         exists, so the one refusal a read-only rootfs produces is EROFS — ENOENT here would mean \
         the probe never reached the question",
        rc = root_rc.trim()
    );

    println!(
        "OCI-BUNDLE EXIT-CRITERION container={} mountinfo-points={} core-present={} \
         default-devices=6 protections-seen={} sys=absent store-mounts=1 store=ro work=rw \
         out=rw,noexec root=ro propagation-tags-on-planned-mounts=0 root-write-rc={} \
         root-write-errno={:?}",
        staged.plan.container_id,
        observed.len(),
        core.len(),
        observed
            .difference(&core)
            .filter(|point| protections.contains(*point))
            .count(),
        root_rc.trim(),
        root_err.trim(),
    );
    println!("OCI-BUNDLE observed-mount-points (point :: kernel options :: optional fields):");
    for (point, row) in &rows {
        println!(
            "  {point} :: {} :: {}",
            row.options.iter().cloned().collect::<Vec<_>>().join(","),
            if row.optional.is_empty() {
                "-".to_owned()
            } else {
                row.optional.join(" ")
            }
        );
    }
}

/// **The namespaces, the id mapping, the capability sets and the network are OBSERVED
/// from inside, not read off kata's rendering.**
///
/// Each of these was, until this cell, a GOLDEN claim: `oci_bundle_golden.rs` pins what
/// `spec_for` renders, which says what kata ASKED for and nothing about what the runtime
/// delivered. Here the guest reads the kernel's answers and the host compares them:
///
/// * `/proc/self/ns/{user,uts,ipc,cgroup,net,pid,mnt}` inside must each name a DIFFERENT
///   namespace inode than the same link read by this (host) process;
/// * `/proc/self/uid_map` and `gid_map` must be EXACTLY one line, `0 <host id> 1`;
/// * `CapEff`, `CapPrm` and `CapAmb` must be zero, and `CapBnd` zero too — the plan
///   renders an EMPTY bounding set, so no `execve` inside can gain anything;
/// * `/proc/net/dev` must list `lo` and nothing else, and `ip addr` records `lo`'s state
///   under the pinned runtime (the egress mechanism's precondition).
///
/// # Would red if
///
/// The runtime ignored a `namespaces[]` entry (a shared inode), mapped a wider id range
/// or root-to-root, left any capability in a set, or gave the container an interface.
#[test]
#[ignore = "HOST-DEPENDENT (pinned youki, its installed AppArmor \
             profile, a delegated user scope, and the fixture closure's store path realised). \
             Runs in the containment lane's `oci-live-smoke` step. Run it now with \
             `cargo nextest run -p kata-worker -P live-smoke -E 'binary(oci_bundle_live)' --run-ignored all`."]
fn the_containers_namespaces_ids_and_capabilities_are_observed_from_inside() {
    delegated(
        "the_containers_namespaces_ids_and_capabilities_are_observed_from_inside",
        the_containers_namespaces_ids_and_capabilities_are_observed_from_inside_body,
    );
}

/// The namespaces this route unshares, as `/proc/self/ns/<name>` spells them.
const NAMESPACES: [&str; 7] = ["user", "uts", "ipc", "cgroup", "net", "pid", "mnt"];

fn the_containers_namespaces_ids_and_capabilities_are_observed_from_inside_body() {
    use std::os::unix::fs::MetadataExt as _;

    let staged = stage(
        9,
        &[
            "busybox",
            "sh",
            "-c",
            "for n in user uts ipc cgroup net pid mnt; do echo \"$n $(readlink /proc/self/ns/$n)\"; \
             done > /out/ns; cat /proc/self/uid_map > /out/uid_map; \
             cat /proc/self/gid_map > /out/gid_map; grep '^Cap' /proc/self/status > /out/caps; \
             cat /proc/net/dev > /out/netdev; busybox ip addr > /out/ipaddr 2>&1; true",
        ],
    );
    let (exit, stdout, stderr) = run(&staged);
    assert_eq!(
        exit.as_deref(),
        Some("0"),
        "the observing container did not exit 0 (exit {exit:?}).\nstdout: {stdout}\nstderr: \
         {stderr}"
    );
    let read = |name: &str| {
        std::fs::read_to_string(staged.out.join(name))
            .unwrap_or_else(|error| panic!("the container did not leave {name} in /out ({error})"))
    };

    // -- NAMESPACES: inside vs this host process, inode by inode -------------------
    let inside: BTreeMap<String, String> = read("ns")
        .lines()
        .filter_map(|line| line.split_once(' '))
        .map(|(name, link)| (name.to_owned(), link.trim().to_owned()))
        .collect();
    for name in NAMESPACES {
        let host = std::fs::read_link(format!("/proc/self/ns/{name}"))
            .unwrap_or_else(|e| panic!("reading this process's own {name} namespace: {e}"))
            .display()
            .to_string();
        let guest = inside
            .get(name)
            .unwrap_or_else(|| panic!("the guest reported no {name} namespace: {inside:?}"));
        assert!(
            guest.starts_with(&format!("{name}:[")),
            "the guest's {name} namespace link is not a namespace: {guest:?}"
        );
        assert_ne!(
            guest, &host,
            "the container SHARES the host's {name} namespace ({host}); the plan asks for a new \
             one and the runtime did not deliver it"
        );
    }

    // -- THE ID MAPPING: exactly `0 <host id> 1` ----------------------------------
    let me = std::fs::metadata("/proc/self").expect("this process's own /proc entry");
    for (file, host_id) in [("uid_map", me.uid()), ("gid_map", me.gid())] {
        let map = read(file);
        let rows: Vec<Vec<&str>> = map
            .lines()
            .map(|line| line.split_whitespace().collect())
            .collect();
        let host_id = host_id.to_string();
        assert_eq!(
            rows,
            vec![vec!["0", host_id.as_str(), "1"]],
            "the guest's {file} must be the SINGLE rootless mapping `0 {host_id} 1`: {map:?}"
        );
    }

    // -- CAPABILITIES: every set empty ----------------------------------------------
    let caps: BTreeMap<String, String> = read("caps")
        .lines()
        .filter_map(|line| line.split_once(':'))
        .map(|(key, value)| (key.to_owned(), value.trim().to_owned()))
        .collect();
    for set in ["CapEff", "CapPrm", "CapAmb", "CapBnd"] {
        assert_eq!(
            caps.get(set).map(String::as_str),
            Some("0000000000000000"),
            "the guest's {set} is not empty: {caps:?}. `spec_for` renders every capability set \
             EMPTY, bounding included, so a bit here is a capability the runtime granted that \
             kata did not ask for"
        );
    }

    // -- THE NETWORK: `lo` and nothing else -----------------------------------------
    let netdev = read("netdev");
    let interfaces: Vec<&str> = netdev
        .lines()
        .skip(2)
        .filter_map(|line| line.split_once(':').map(|(name, _)| name.trim()))
        .collect();
    assert_eq!(
        interfaces,
        vec!["lo"],
        "the offline container must have exactly one interface, `lo`: {netdev}"
    );
    let ipaddr = read("ipaddr");
    let lo_up = ipaddr
        .lines()
        .find(|line| line.contains(" lo:"))
        .is_some_and(|line| line.contains(",UP") || line.contains("<UP"));

    println!(
        "OCI-BUNDLE inside-observed container={} namespaces-distinct={} uid_map=0:{}:1 \
         gid_map=0:{}:1 CapEff=0 CapPrm=0 CapAmb=0 CapBnd=0 interfaces=lo lo-up={lo_up} \
         youki={}",
        staged.plan.container_id,
        NAMESPACES.join(","),
        me.uid(),
        me.gid(),
        YoukiPin::embedded().store_path(),
    );
    println!("OCI-BUNDLE ip-addr-inside:\n{ipaddr}");
}
