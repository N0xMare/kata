//! The rootless OCI `config.json` kata plans, pinned
//! BYTE-FOR-BYTE, plus every refusal [`kata_worker::oci_bundle::spec_for`] claims.
//!
//! # Why a byte golden and not a field-by-field assertion
//!
//! The bytes are the artifact. A container runtime reads `config.json` and
//! nothing else, so an assertion that walked the produced `Spec` and checked the
//! fields a test author thought of would miss precisely the field nobody thought
//! of — which on this route is a containment property. The committed fixture
//! under `tests/fixtures/oci/` is therefore the whole file, reviewable in a diff,
//! and a change anywhere in it has to be read rather than absorbed.
//!
//! **Re-baseline ONLY deliberately.** A moved byte here is a different container.
//!
//! # What does not share the code under test
//!
//! * the golden fixture is a FILE no Rust in this repository writes at test time;
//! * the store path, its NAR hash and its NAR size are `nix path-info`'s own
//!   values for a real substituted store object, not values kata computed;
//! * `linux.maskedPaths` / `linux.readonlyPaths` are compared against the list
//!   `runc spec --rootless` emits, which is another implementation's answer to
//!   the same question. The comparison is by TEXT here and by a live container in
//!   `tests/oci_bundle_live.rs`.

#![cfg(target_os = "linux")]

use std::path::{Path, PathBuf};

use kata_provider_protocol::OciBundlePlan;
use kata_types::{
    execution_contract::{
        ArtifactId, Capsule, CapsuleBudgets, CapsuleNetwork, CapsuleProcess, EnvironmentId,
        GuestAccess, GuestMapping, GuestPath, OccurrenceId, PlatformRef, PreparedActionId,
    },
    nix_environment::{
        ClosureEntry, IntegrityPolicy, NarVerification, NixEnvironmentManifest, Provenance,
        RetentionClass, RetentionIntent, StorePath,
    },
    primitives::ContentHash,
    sandbox::NetPolicy,
};
use kata_worker::egress_proxy::EgressPlumbing;
use kata_worker::oci_bundle::{BundleMounts, spec_for, spec_for_as};
use kata_worker::oci_cgroup::{AttemptContainment, CONTAINER_LEAF};

/// The REAL store path of a statically linked busybox, substituted from
/// `cache.nixos.org`. Real and not synthetic because `tests/oci_bundle_live.rs`
/// rbinds this exact path into a container and execs the binary inside it: a
/// fabricated path would make the golden a description of a bundle that cannot
/// run, which is the failure mode a plan-only test has by construction.
const BUSYBOX: &str =
    "/nix/store/qddzvnv6b0805nkvbqddbswddcfhx814-busybox-static-x86_64-unknown-linux-musl-1.37.0";

/// `nix path-info --json`'s own `narHash` for [`BUSYBOX`].
const BUSYBOX_NAR_HASH: &str = "sha256-d7JNm1d4Wo1oSA2pvoRLt1vqyAhSlIsjE0GckcLiSeA=";
/// `nix path-info --json`'s own `narSize` for [`BUSYBOX`].
const BUSYBOX_NAR_SIZE: u64 = 1_495_056;

/// The uid/gid the GOLDEN's single rootless mapping points at.
///
/// Fixed, and driven through `spec_for_as` rather than `spec_for`, so the fixture
/// is the same bytes on every host. The claim that production reads the PROCESS's
/// own ids is a separate test — [`spec_for_reads_the_processs_own_uid_and_gid`] —
/// because a golden that embedded `getuid()` would be re-baselined per host
/// instead of compared.
const GOLDEN_UID: u32 = 1000;
/// See [`GOLDEN_UID`].
const GOLDEN_GID: u32 = 1000;

/// The committed golden, repo-relative.
fn golden_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/oci/command-offline.config.json")
}

fn hash(byte: u8) -> ContentHash {
    ContentHash::new([byte; 32])
}

/// The environment the fixture capsule binds: one closure entry, the real
/// busybox, with `<path>/bin` on `PATH`.
///
/// `references` is EMPTY and the real store object's is self-referential — a
/// statically linked busybox's only reference is itself. `NixEnvironmentManifest`
/// refuses an entry that references its own index (a self-edge is not a closure
/// edge), so the manifest carries the closure's shape and drops the self-loop.
/// Stated here because it is the one field of this fixture that is not
/// `nix path-info`'s value verbatim.
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
        vec![GuestPath::new(format!("{BUSYBOX}/bin")).expect("a store path's bin directory")],
        IntegrityPolicy {
            verify: NarVerification::NarHashAndSignatures,
            sigs_needed: 1,
            required_signers: vec!["cache.nixos.org-1".into()],
            allow_unsigned_content_addressed: false,
            verify_contents_at_declare: false,
        },
        kata_types::execution_contract::ArtifactPrivacy::Public,
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

fn budgets() -> CapsuleBudgets {
    CapsuleBudgets {
        wall_time_ms: 30_000,
        output_bytes: 1 << 20,
        memory_bytes: 512 * 1024 * 1024,
        process_count: 64,
        result_bytes: 4 * 1024 * 1024,
        result_entries: 128,
        work_delta_bytes: kata_types::execution_contract::CAPSULE_WORK_DELTA_BYTES,
        work_delta_entries: kata_types::execution_contract::CAPSULE_WORK_DELTA_ENTRIES,
    }
}

/// The fixture capsule: `/work` and `/out` read-write, `/tmp` read-write, the
/// closure's store path read-only.
fn capsule_with(inputs: Vec<GuestMapping>, budgets: CapsuleBudgets) -> Capsule {
    Capsule::new(
        OccurrenceId(hash(1)),
        PreparedActionId(hash(2)),
        EnvironmentId(hash(3)),
        PlatformRef::new("x86_64-linux", hash(11)).id(),
        inputs,
        CapsuleProcess::Command { argv: argv() },
        CapsuleNetwork::Offline,
        None,
        budgets,
        None,
    )
    .expect("the fixture capsule is well formed")
}

fn capsule() -> Capsule {
    capsule_with(
        vec![
            mapping("/work", GuestAccess::ReadWrite, 20),
            mapping("/out", GuestAccess::ReadWrite, 21),
            mapping("/tmp", GuestAccess::ReadWrite, 22),
            mapping(BUSYBOX, GuestAccess::ReadOnly, 23),
        ],
        budgets(),
    )
}

/// The attempt root the golden names. A FIXED absolute path, because a tempdir
/// would put a per-run path in a byte golden.
const ATTEMPT_ROOT: &str = "/var/lib/kata/attempts/fixture/root";

/// The kata-owned parent cgroup the golden's container is placed beneath.
///
/// FIXED and FICTIONAL, for [`GOLDEN_UID`]'s reason one field over: the real path
/// is `<this host's delegated scope>/kata.provider.youki.<pid>/kata.oci.<id>`, and a
/// golden carrying it would pin this machine's user slice and this run's pid into
/// the tree. `linux.cgroupsPath` is derived from it by stripping `/sys/fs/cgroup`,
/// so what the golden pins is the DERIVATION — that the leaf is named, that it is
/// absolute, and that it is beneath the parent kata was handed. The live arms drive
/// the same producer with a real, measured parent.
const GOLDEN_CGROUP_PARENT: &str =
    "/sys/fs/cgroup/kata.test/kata.provider.youki.1/kata.oci.kata-fixture";

/// The attempt-local state root the golden names, for the same reason.
const GOLDEN_STATE_ROOT: &str = "/var/lib/kata/attempts/fixture/oci";

/// The containment the golden plans under.
fn containment() -> AttemptContainment {
    AttemptContainment::new(
        PathBuf::from(GOLDEN_CGROUP_PARENT),
        PathBuf::from(GOLDEN_STATE_ROOT),
    )
    .expect("an absolute kata-owned parent beneath the cgroup root and an absolute state root")
}

/// The host roots the golden names, derived by the one constructor.
///
/// `BundleMounts::under` and not two literal paths: `/work` and `/out` are the two
/// subdirectories of ONE attempt root, and a test that could name them
/// independently would be exercising a shape production cannot produce.
fn mounts() -> BundleMounts {
    BundleMounts::under(Path::new(ATTEMPT_ROOT), 64 * 1024 * 1024)
        .expect("an absolute attempt root with a non-zero /tmp size")
}

/// The argument vector the golden's capsule carries.
///
/// As of contract v5 it is a field of the CAPSULE rather than a parameter of
/// `spec_for`, so it is folded into `CapsuleId` — which is why the golden's container
/// id moved when this vector moved into the identity.
fn argv() -> Vec<smol_str::SmolStr> {
    vec![
        smol_str::SmolStr::new(format!("{BUSYBOX}/bin/busybox")),
        smol_str::SmolStr::new("true"),
    ]
}

fn plan() -> OciBundlePlan {
    spec_for_as(
        &capsule(),
        &environment(),
        &mounts(),
        &containment(),
        NetPolicy::Offline,
        None,
        GOLDEN_UID,
        GOLDEN_GID,
    )
    .expect("the fixture plans")
}

// ---------------------------------------------------------------------------
// The golden
// ---------------------------------------------------------------------------

/// **BYTE GOLDEN: the whole `config.json` for an offline command capsule.**
///
/// # Would red if
///
/// Any byte of the plan moved — a mount option added or removed, a namespace
/// dropped, a capability set left unset, `readonly` flipped, a masked path
/// deleted, the seccomp fence renamed an action, the rootless mapping widened
/// past `size 1`. **Watched red:** removing `private` from the closure entry's
/// options produces a byte diff against the golden.
///
/// To re-baseline deliberately:
/// `KATA_REBASELINE_OCI_GOLDEN=1 cargo nextest run -p kata-worker -E
/// 'binary(oci_bundle_golden)'` writes the file and then FAILS, so the new bytes
/// land in a diff a reviewer reads rather than in a green run nobody looks at.
#[test]
fn the_offline_command_bundle_matches_its_committed_golden() {
    let produced = plan().config_json;
    let path = golden_path();

    if std::env::var_os("KATA_REBASELINE_OCI_GOLDEN").is_some() {
        std::fs::create_dir_all(path.parent().expect("the fixture directory"))
            .expect("creating the fixture directory");
        std::fs::write(&path, produced.as_bytes()).expect("writing the golden");
        panic!(
            "re-baselined {} ({} bytes). This is always a FAILURE: the new bytes describe a \
             different container and must be read in a diff before they are trusted.",
            path.display(),
            produced.len()
        );
    }

    let golden = std::fs::read_to_string(&path).unwrap_or_else(|error| {
        panic!(
            "the committed golden {} could not be read ({error}). It is the whole subject of this \
             test; without it there is nothing to compare and a green would mean nothing.",
            path.display()
        )
    });
    assert!(
        golden.len() > 2_000,
        "the golden is only {} bytes, which is too small to be a full rootless OCI spec — a \
         truncated fixture would make this comparison pass against almost nothing",
        golden.len()
    );

    if produced != golden {
        let first_difference = produced
            .lines()
            .zip(golden.lines())
            .enumerate()
            .find(|(_, (a, b))| a != b)
            .map_or_else(
                || "no differing line; the files differ in LENGTH".to_string(),
                |(index, (a, b))| format!("line {}: produced {a:?} / golden {b:?}", index + 1),
            );
        panic!(
            "the planned config.json no longer matches {}. THIS IS A CONTAINMENT CHANGE: the \
             bytes below are what a runtime reads. {first_difference}\nRe-baseline with \
             KATA_REBASELINE_OCI_GOLDEN=1 only after reading the diff.",
            path.display()
        );
    }
}

/// **The golden agrees with `runc spec --rootless` about the masked and read-only
/// paths.**
///
/// A SECOND IMPLEMENTATION's answer, read out of the golden's text rather than
/// out of `oci_bundle`'s constants — asserting kata's list against kata's list
/// would be the suite asking kata whether kata was right.
#[test]
fn the_golden_carries_runcs_own_rootless_masked_and_readonly_paths() {
    let golden = std::fs::read_to_string(golden_path()).expect("the golden");
    // Verbatim from `runc spec --rootless` (runc 1.3.6, spec 1.2.1) on the
    // reference host, in runc's own order.
    for path in [
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
    ] {
        assert!(
            golden.contains(&format!("\"{path}\"")),
            "the golden does not mask or protect {path}, which runc's own rootless spec does"
        );
    }
    assert!(
        !golden.contains("\"/sys\","),
        "the golden mounts /sys. This route deliberately does not: /sys is a window onto the \
         HOST's devices, firmware and kernel tunables, and the cgroup hierarchy under it is how a \
         stage would read — and on a delegated tree widen — the bounds kata placed on it"
    );
    // Every rbind detaches its WHOLE subtree. `private` covers the top mount
    // only, which measurably leaves `master:1` on all three; `rprivate` is what the
    // guest's own mountinfo now reports as absent.
    assert_eq!(
        golden.matches("\"rprivate\"").count(),
        3,
        "the golden must carry rprivate on all three rbinds — the closure entry, /work and /out. \
         An rbind whose propagation is `private` keeps every mount already beneath its source in \
         the host's peer group, so a later host mount appears inside a running container"
    );
    assert_eq!(
        golden.matches("\"rootfsPropagation\": \"private\"").count(),
        1,
        "the golden must set linux.rootfsPropagation. It is the half that actually detaches the \
         container: unset, youki makes the rootfs `rslave` and every mount created beneath it \
         inherits slave-ness, so the closure rbind came back `master:1` even carrying `rprivate` \
         itself. `private` and not `rprivate` — youki 0.7.0 refuses the recursive spelling on \
         THIS field by name (`UnknownRootfsPropagation`) and applies `private` recursively"
    );
    assert!(
        !golden.contains("\"options\": [\n        \"private\""),
        "an rbind's own propagation option must be `rprivate`: a bare `private` covers the top \
         mount only and leaves every mount already beneath the source in its peer group"
    );
    assert_eq!(
        golden.matches("\"cgroupsPath\"").count(),
        1,
        "the golden must set linux.cgroupsPath EXACTLY ONCE, to the leaf beneath the parent kata \
         owns. Unset, youki asks the user manager for its own \
         transient `youki-<id>.scope` and the container lands outside every subtree kata sweeps, \
         which makes `TeardownProbe::CgroupPopulation` answer about a cgroup the stage was never in"
    );
    assert!(
        golden.contains("\"cgroupsPath\": \"/"),
        "linux.cgroupsPath must be ABSOLUTE: youki 0.7.0 routes a non-absolute path to its systemd \
         manager, which refuses it as malformed and starts no container at all"
    );
}

/// **The container's fence is the STAGE fence, not the kata seccomp floor.**
///
/// # Why this is not a byte search
///
/// Serializing the whole plan and searching the bytes for `kata_floor_bpf()`
/// could never fail if `config_json` were a `Vec<u8>`, which encodes on a JSON
/// wire as an array of NUMBERS, so no byte sequence could appear in it as
/// itself. A search that cannot match is a green with no subject — the exact
/// defect class this repository pays for most often — and the field is a
/// `String` partly so nobody writes that test.
///
/// The two real guarantees are split where each can actually be checked:
///
/// * **Structural** — `OciBundlePlan` has no field a compiled filter could ride
///   in. That is a property of the plan's FIELD SET and is pinned in the crate
///   that owns the wire, by
///   `kata_provider_protocol`'s `the_oci_plan_carries_no_filter_bytes_field`.
/// * **Semantic, and here** — the fence the bundle DOES carry is the WHOLE
///   STAGE deny-list, not the floor's KataFloor subset. The discriminator is the
///   `ConstructionResidue` entries: `kata_floor_program()` omits every one of them
///   (that omission is what makes it installable before a provider builds a
///   sandbox), so a bundle rendered from the floor by mistake would be missing
///   `unshare`, `mount`, `pivot_root`, `setns` and the rest. This test requires
///   every residue entry BY NAME, which is what such a mistake would fail.
///
/// # Would red if
///
/// `oci_seccomp_rules` were pointed at `kata_floor_program`'s subset, an entry
/// were dropped from the rendering, or the default/deny actions moved.
#[test]
fn the_bundles_fence_is_the_stage_fence_and_not_the_kata_floor() {
    let config = plan().config_json;

    let partition = kata_types::sandbox_seccomp::shipped_partition();
    assert!(
        !partition.construction_residue.is_empty(),
        "the partition reports no construction residue, so the discriminator below would hold \
         vacuously for the floor and the stage fence alike"
    );
    for entry in &partition.construction_residue {
        assert!(
            config.contains(&format!("\"{}\"", entry.name)),
            "the bundle's linux.seccomp does not deny {}, which is a CONSTRUCTION RESIDUE entry. \
             The floor omits every residue entry by design, so a fence missing one is the floor \
             rendered where the stage fence belongs — and the container would be free to unshare, \
             mount and pivot_root",
            entry.name
        );
    }
    for entry in kata_types::sandbox_seccomp::DENIED_SYSCALLS {
        assert!(
            config.contains(&format!("\"{}\"", entry.name)),
            "the bundle's linux.seccomp does not deny {}. The container's fence is the STAGE \
             fence — all {} entries of kata_types::sandbox_seccomp::DENIED_SYSCALLS",
            entry.name,
            kata_types::sandbox_seccomp::DENIED_SYSCALLS.len()
        );
    }
    assert!(
        config.contains("\"SCMP_ACT_ALLOW\"") && config.contains("\"SCMP_ACT_ERRNO\""),
        "the bundle's fence must be ALLOW-by-default with an ERRNO deny leaf: {config}"
    );

    // And the plan still has to survive the wire, since that is where a provider
    // reads it from.
    let wire = plan();
    let decoded: OciBundlePlan =
        serde_json::from_slice(&serde_json::to_vec(&wire).expect("serializes"))
            .expect("round-trips");
    assert_eq!(decoded, wire);
}

/// **Production reads the PROCESS's own uid and gid; the golden's are a seam.**
///
/// Without this, `spec_for_as` could be handed anything and the golden would keep
/// passing — the seam would have replaced the mechanism instead of exposing it.
#[test]
fn spec_for_reads_the_processs_own_uid_and_gid() {
    let uid = nix::unistd::getuid().as_raw();
    let gid = nix::unistd::getgid().as_raw();

    let produced = spec_for(
        &capsule(),
        &environment(),
        &mounts(),
        &containment(),
        NetPolicy::Offline,
        None,
    )
    .expect("the fixture plans");

    // THE SEAM IS THE SAME FUNCTION. Byte-equality against `spec_for_as` with the
    // process's own ids is what makes the golden's use of the seam honest: without
    // it, `spec_for_as` could differ from production anywhere at all and both this
    // test and the golden would still pass.
    let through_the_seam = spec_for_as(
        &capsule(),
        &environment(),
        &mounts(),
        &containment(),
        NetPolicy::Offline,
        None,
        uid,
        gid,
    )
    .expect("the fixture plans through the seam");
    assert_eq!(
        produced, through_the_seam,
        "spec_for must be spec_for_as with the process's own ids and nothing else. A seam that \
         differs from production is a golden about code nobody ships"
    );

    let config = produced.config_json;
    assert!(
        config.contains(&format!("\"hostID\": {uid}")),
        "spec_for must map container 0 onto THIS process's uid ({uid}); a rootless mapping onto \
         any other id is one an unprivileged process cannot write"
    );
    assert!(
        config.contains(&format!("\"hostID\": {gid}")),
        "spec_for must map container 0 onto THIS process's gid ({gid})"
    );
    assert!(
        config.contains("\"size\": 1"),
        "the mapping must be size 1: a wider range needs newuidmap and an /etc/subuid grant, \
         which is a host fact kata would have to inherit and could not refuse the absence of"
    );

    // And the seam really carries what it is HANDED — two ids this process does
    // not have, so a body that quietly read `getuid()` anyway would fail here.
    let foreign = spec_for_as(
        &capsule(),
        &environment(),
        &mounts(),
        &containment(),
        NetPolicy::Offline,
        None,
        4242,
        4243,
    )
    .expect("the fixture plans for foreign ids");
    assert!(
        foreign.config_json.contains("\"hostID\": 4242")
            && foreign.config_json.contains("\"hostID\": 4243"),
        "spec_for_as must map container 0 onto the ids it was GIVEN, not the ones it could read: \
         {}",
        foreign.config_json
    );
    assert_ne!(
        (uid, gid),
        (4242, 4243),
        "this process happens to run as 4242:4243, so the assertion above cannot distinguish a \
         seam that honours its arguments from one that ignores them"
    );
}

/// **The plan survives the wire, and an unknown field is refused there.**
#[test]
fn the_oci_plan_round_trips_the_wire_and_refuses_an_unknown_field() {
    let plan = plan();
    let bytes = serde_json::to_vec(&plan).expect("serializes");
    let decoded: OciBundlePlan = serde_json::from_slice(&bytes).expect("round-trips");
    assert_eq!(
        decoded, plan,
        "a plan that does not survive its own encoding cannot be assigned"
    );

    let mut doctored: serde_json::Value = serde_json::from_slice(&bytes).expect("json");
    doctored["landlock_ruleset"] = serde_json::json!("/whatever");
    let refusal = serde_json::from_value::<OciBundlePlan>(doctored)
        .expect_err("an unknown field on the plan must be refused");
    assert!(
        refusal.to_string().contains("landlock_ruleset"),
        "the refusal must name the field the peer added: {refusal}"
    );
}

// ---------------------------------------------------------------------------
// The refused set, item by item
// ---------------------------------------------------------------------------

fn refusal(
    capsule: &Capsule,
    environment: &NixEnvironmentManifest,
    mounts: &BundleMounts,
    network: NetPolicy,
) -> String {
    spec_for_as(
        capsule,
        environment,
        mounts,
        &containment(),
        network,
        None,
        GOLDEN_UID,
        GOLDEN_GID,
    )
    .expect_err("this input is in spec_for's refused set")
    .to_string()
}

/// **Every clause of `spec_for`'s stated refused set refuses, and names itself.**
///
/// One test over a table rather than ten near-identical ones: the property is
/// *"the stated set is the refused set"*, and a table is the only shape in which a
/// clause added to the doc with no mechanism behind it is visible as a missing row.
#[test]
fn the_stated_refused_set_is_the_refused_set() {
    let env = environment();
    let base_mounts = mounts();

    // 1. A network posture with no mechanism on this route.
    let message = refusal(&capsule(), &env, &base_mounts, NetPolicy::Host);
    assert!(
        message.contains("`host` has no form on the rootless-OCI route"),
        "a non-offline posture must be refused BY NAME: {message}"
    );

    // 2. No process — REFUSED BY THE CAPSULE, not by this renderer. `argv` is a
    // capsule field folded into `CapsuleId`, so an empty one is unconstructible
    // and `spec_for` carries no second door for it. Asserted here, beside the
    // renderer's own refusals, so the refusal is visible where a reader looks.
    let empty = Capsule::new(
        OccurrenceId(hash(1)),
        PreparedActionId(hash(2)),
        EnvironmentId(hash(3)),
        PlatformRef::new("x86_64-linux", hash(11)).id(),
        vec![
            mapping("/work", GuestAccess::ReadWrite, 20),
            mapping("/out", GuestAccess::ReadWrite, 21),
            mapping("/tmp", GuestAccess::ReadWrite, 22),
        ],
        CapsuleProcess::Command { argv: Vec::new() },
        CapsuleNetwork::Offline,
        None,
        budgets(),
        None,
    )
    .expect_err("a capsule with no argv is one nothing can run");
    assert!(
        empty.to_string().contains("capsule argv is empty"),
        "{empty}"
    );

    // 3/4. `BundleMounts::under`'s OWN refused set, which `spec_for` no longer
    // re-checks because these three are unrepresentable by the time it runs. The
    // fields are private and this constructor is the only way in, so the
    // refusals are asserted where they now live.
    let message = BundleMounts::under(Path::new("attempts/fixture/root"), 64 * 1024 * 1024)
        .expect_err("a relative attempt root is refused")
        .to_string();
    assert!(message.contains("is not absolute"), "{message}");
    let message = BundleMounts::under(Path::new(ATTEMPT_ROOT), 0)
        .expect_err("a zero-byte /tmp is refused")
        .to_string();
    assert!(message.contains("/tmp tmpfs size is 0 bytes"), "{message}");
    // The two derived sources are DISTINCT, which is what makes the aliasing
    // refusal unreachable while the two directory names are distinct literals —
    // asserted rather than assumed, because that is the premise the refusal's own
    // doc rests on.
    let derived = BundleMounts::under(Path::new(ATTEMPT_ROOT), 1).expect("well formed");
    assert_ne!(derived.work(), derived.out());
    assert_eq!(derived.work(), Path::new(ATTEMPT_ROOT).join("work"));
    assert_eq!(derived.out(), Path::new(ATTEMPT_ROOT).join("out"));
    assert_eq!(derived.tmp_bytes(), 1);

    // A non-UTF-8 host source has no representation in a config.json. Built
    // through `under` from a root carrying a byte no UTF-8 sequence contains, so
    // the refusal is reached the way production would reach it.
    {
        use std::os::unix::ffi::OsStrExt as _;
        let invalid = std::ffi::OsStr::from_bytes(b"/var/lib/kata/attempts/\xff/root");
        let mounts = BundleMounts::under(Path::new(invalid), 64 * 1024 * 1024)
            .expect("a non-UTF-8 path is still absolute, so the constructor accepts it");
        let message = refusal(&capsule(), &env, &mounts, NetPolicy::Offline);
        assert!(
            message.contains("is not valid UTF-8"),
            "a lossy conversion would name a DIFFERENT file and bind whatever is there: {message}"
        );
    }

    // 5/6. A bound nobody set, in both places a zero means "unlimited".
    let unbounded_memory = capsule_with(
        capsule().inputs().to_vec(),
        CapsuleBudgets {
            memory_bytes: 0,
            ..budgets()
        },
    );
    let message = refusal(&unbounded_memory, &env, &base_mounts, NetPolicy::Offline);
    assert!(message.contains("memory_bytes budget is 0"), "{message}");
    let unbounded_pids = capsule_with(
        capsule().inputs().to_vec(),
        CapsuleBudgets {
            process_count: 0,
            ..budgets()
        },
    );
    let message = refusal(&unbounded_pids, &env, &base_mounts, NetPolicy::Offline);
    assert!(message.contains("process_count budget is 0"), "{message}");

    // 7. A mapping outside the capsule's own authority. `GuestPath` already
    // refuses a traversal and a path under an unlisted root, so the stray has to
    // be a path that IS a valid guest path and is still outside this closure.
    let outside = capsule_with(
        vec![
            mapping("/work", GuestAccess::ReadWrite, 20),
            mapping("/out", GuestAccess::ReadWrite, 21),
            mapping(
                "/nix/store/zzzzvnv6b0805nkvbqddbswddcfhx814-not-in-this-closure",
                GuestAccess::ReadOnly,
                24,
            ),
        ],
        budgets(),
    );
    let message = refusal(&outside, &env, &base_mounts, NetPolicy::Offline);
    assert!(
        message.contains("is not one of the 1 store paths in the authorized closure"),
        "{message}"
    );

    // 8. A writable Nix store path.
    let writable_store = capsule_with(
        vec![
            mapping("/work", GuestAccess::ReadWrite, 20),
            mapping("/out", GuestAccess::ReadWrite, 21),
            mapping(BUSYBOX, GuestAccess::ReadWrite, 23),
        ],
        budgets(),
    );
    let message = refusal(&writable_store, &env, &base_mounts, NetPolicy::Offline);
    assert!(message.contains("READ-WRITE. A store object"), "{message}");

    // 9. A /work the capsule says is read-only and this route mounts read-write.
    let ro_work = capsule_with(
        vec![
            mapping("/work", GuestAccess::ReadOnly, 20),
            mapping("/out", GuestAccess::ReadWrite, 21),
        ],
        budgets(),
    );
    let message = refusal(&ro_work, &env, &base_mounts, NetPolicy::Offline);
    assert!(message.contains("maps /work READ-ONLY"), "{message}");

    // 10. A missing writable root, each of the THREE directions. `/tmp` is
    // required and not merely permitted: `capsule_assembly` always emits
    // it, so a capsule short of one did not come from the assembler and this route
    // must not invent the mount.
    for (inputs, missing) in [
        (
            vec![
                mapping("/out", GuestAccess::ReadWrite, 21),
                mapping("/tmp", GuestAccess::ReadWrite, 22),
            ],
            "/work",
        ),
        (
            vec![
                mapping("/work", GuestAccess::ReadWrite, 20),
                mapping("/tmp", GuestAccess::ReadWrite, 22),
            ],
            "/out",
        ),
        (
            vec![
                mapping("/work", GuestAccess::ReadWrite, 20),
                mapping("/out", GuestAccess::ReadWrite, 21),
            ],
            "/tmp",
        ),
    ] {
        let partial = capsule_with(inputs, budgets());
        let message = refusal(&partial, &env, &base_mounts, NetPolicy::Offline);
        assert!(
            message.contains(&format!("no read-write mapping for {missing}")),
            "{message}"
        );
    }

    // 11. An environment with nothing in it, and one with no PATH.
    let empty_path_prepend = NixEnvironmentManifest::new(
        "no-path",
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
        vec![],
        IntegrityPolicy {
            verify: NarVerification::NarHashAndSignatures,
            sigs_needed: 1,
            required_signers: vec!["cache.nixos.org-1".into()],
            allow_unsigned_content_addressed: false,
            verify_contents_at_declare: false,
        },
        kata_types::execution_contract::ArtifactPrivacy::Public,
        RetentionIntent {
            class: RetentionClass::Cache,
        },
        "nix-store --realise",
    )
    .expect("a manifest with no PATH entry is still a valid manifest");
    let empty_closure = NixEnvironmentManifest::new(
        "empty",
        PlatformRef::new("x86_64-linux", hash(11)),
        Provenance::StorePaths {
            nixpkgs_attribute: "nixpkgs#pkgsStatic.busybox".into(),
        },
        vec![],
        vec![],
        vec![],
        IntegrityPolicy {
            verify: NarVerification::NarHashAndSignatures,
            sigs_needed: 1,
            required_signers: vec!["cache.nixos.org-1".into()],
            allow_unsigned_content_addressed: false,
            verify_contents_at_declare: false,
        },
        kata_types::execution_contract::ArtifactPrivacy::Public,
        RetentionIntent {
            class: RetentionClass::Cache,
        },
        "nix-store --realise",
    )
    .expect("an empty manifest is a valid manifest; it is this ROUTE that has no use for one");
    let no_store = capsule_with(
        vec![
            mapping("/work", GuestAccess::ReadWrite, 20),
            mapping("/out", GuestAccess::ReadWrite, 21),
        ],
        budgets(),
    );
    let message = refusal(&no_store, &empty_closure, &base_mounts, NetPolicy::Offline);
    assert!(message.contains("binds an EMPTY closure"), "{message}");

    let message = refusal(
        &capsule(),
        &empty_path_prepend,
        &base_mounts,
        NetPolicy::Offline,
    );
    assert!(
        message.contains("declares no path_prepend"),
        "an empty path_prepend renders `PATH=:/bin`, whose leading empty entry every shell reads \
         as the current directory: {message}"
    );
}

/// **`AttemptContainment`'s OWN refused set, and the derivation it exists for.**
///
/// One table, for the reason the sibling above gives: the property is *"the stated
/// set is the refused set"*, and a clause documented with no mechanism behind it is
/// visible here as a missing row.
///
/// # Would red if
///
/// The constructor accepted a relative path, a `..` component, a parent outside the
/// cgroup v2 mount point, or the mount point itself — each of which produces a
/// `linux.cgroupsPath` that names a leaf kata does not own and therefore cannot
/// sweep, which is the exact defect the kata-owned parent closes.
#[test]
fn the_attempt_containments_refused_set_is_the_refused_set() {
    let ok_parent = PathBuf::from(GOLDEN_CGROUP_PARENT);
    let ok_state = PathBuf::from(GOLDEN_STATE_ROOT);
    let refused = |parent: &str, state: &str| -> String {
        AttemptContainment::new(PathBuf::from(parent), PathBuf::from(state))
            .expect_err("this input is in AttemptContainment's refused set")
            .to_string()
    };

    // 1/2. Relative, on either field.
    let message = refused("sys/fs/cgroup/kata.test/p", GOLDEN_STATE_ROOT);
    assert!(
        message.contains("parent cgroup") && message.contains("is not absolute"),
        "{message}"
    );
    let message = refused(GOLDEN_CGROUP_PARENT, "attempts/fixture/oci");
    assert!(
        message.contains("state root") && message.contains("is not absolute"),
        "{message}"
    );

    // 3/4. A `..` component, on either field.
    let message = refused("/sys/fs/cgroup/kata.test/../escape", GOLDEN_STATE_ROOT);
    assert!(message.contains("`..` component"), "{message}");
    let message = refused(GOLDEN_CGROUP_PARENT, "/var/lib/kata/attempts/../oci");
    assert!(message.contains("`..` component"), "{message}");

    // 5. A parent outside the cgroup v2 mount point: `linux.cgroupsPath` is read
    // FROM that mount point, so such a parent cannot be expressed at all.
    let message = refused("/var/lib/kata/not-a-cgroup", GOLDEN_STATE_ROOT);
    assert!(
        message.contains("not strictly beneath the cgroup v2 mount point"),
        "{message}"
    );

    // 6. The mount point ITSELF, which is not a cgroup kata created or may sweep.
    let message = refused("/sys/fs/cgroup", GOLDEN_STATE_ROOT);
    assert!(
        message.contains("not strictly beneath the cgroup v2 mount point"),
        "{message}"
    );

    // And the accepted case DERIVES the leaf: absolute, relative to the mount
    // point, with the container leaf appended. This is what lands in
    // `linux.cgroupsPath`, and it is the one spelling youki 0.7.0 honours as a
    // path — a relative one is refused by its systemd manager as malformed.
    let containment = AttemptContainment::new(ok_parent.clone(), ok_state.clone())
        .expect("the golden's own containment is well formed");
    assert_eq!(
        containment.cgroups_path(),
        PathBuf::from("/kata.test/kata.provider.youki.1/kata.oci.kata-fixture")
            .join(CONTAINER_LEAF),
        "`linux.cgroupsPath` is the parent with /sys/fs/cgroup stripped and the leaf appended"
    );
    assert_eq!(containment.cgroup_parent(), ok_parent);
    assert_eq!(containment.state_root(), ok_state);
}

/// **The golden's placement is in the bundle AND on the plan, and they agree.**
///
/// Two surfaces carry it — `linux.cgroupsPath` inside `config_json`, which the
/// RUNTIME reads, and `OciBundlePlan::cgroup_parent`, which the PROVIDER checks —
/// and a plan whose two halves disagreed would put the container somewhere the
/// provider had verified nothing about.
///
/// # Would red if
///
/// `spec_for` left `cgroupsPath` unset (the container then
/// lands in youki's own transient scope, outside the subtree kata sweeps), filled
/// `cgroup_parent` with a `None`, or derived the two from different inputs.
#[test]
fn the_golden_places_the_container_under_the_kata_owned_parent() {
    let planned = plan();
    assert_eq!(
        planned.cgroup_parent.as_deref(),
        Some(GOLDEN_CGROUP_PARENT),
        "the plan must carry the kata-owned parent the provider verifies"
    );
    assert_eq!(
        planned.state_root, GOLDEN_STATE_ROOT,
        "the state root rides the PLAN"
    );
    let expected = format!(
        "\"cgroupsPath\": \"{}\"",
        containment().cgroups_path().display()
    );
    assert!(
        planned.config_json.contains(&expected),
        "the bundle must place the container's own leaf beneath the kata-owned parent, or the \
         runtime picks its own cgroup and kata's teardown probe answers about a subtree the stage \
         was never in. Expected {expected} in the config.json"
    );
    let leaf = containment().cgroups_path();
    assert!(
        leaf.starts_with("/") && leaf.ends_with(CONTAINER_LEAF),
        "the leaf must be an absolute path ending in the leaf kata names: {}",
        leaf.display()
    );
}

/// The fixture hook inputs — the worker-resolved halves an `Egress` capsule's
/// plan renders `hooks.createContainer` from.
///
/// FIXED strings, for [`GOLDEN_UID`]'s reason: the real values are the provider
/// entry's own paths and the hook binary's sha256, all host facts. What this test
/// pins is the RENDER — two `createContainer` entries in a fixed order, argv laid
/// out `program subcommand --flag value` — not this host's store.
fn hook_inputs() -> kata_worker::oci_bundle::EgressHookInputs {
    kata_worker::oci_bundle::EgressHookInputs {
        program: kata_provider_protocol::PinnedRuntime {
            store_path: "/nix/store/egress0000000000000000000000000-hook-kata-oci-hook".to_owned(),
            sha256: "00000000000000000000000000000000000000000000000000000000000000ee".to_owned(),
        },
        ip: PathBuf::from("/nix/store/egress0000000000000000000000000-iproute2/bin/ip"),
    }
}

/// The fixture capsule as `Egress`: one allowlisted authority, everything else
/// identical to [`capsule`] — the two share a fixture so the bundle diff isolates
/// the network posture's contribution and nothing else.
fn egress_capsule() -> Capsule {
    let allowlist = [
        kata_types::execution_contract::EgressAuthority::new("example.com", 443)
            .expect("a well-formed authority"),
    ]
    .into_iter()
    .collect();
    Capsule::new(
        OccurrenceId(hash(1)),
        PreparedActionId(hash(2)),
        EnvironmentId(hash(3)),
        PlatformRef::new("x86_64-linux", hash(11)).id(),
        capsule().inputs().to_vec(),
        CapsuleProcess::Command { argv: argv() },
        CapsuleNetwork::Egress { allowlist },
        None,
        budgets(),
        None,
    )
    .expect("the egress fixture capsule is well formed")
}

/// **An `Egress` capsule's bundle is the Offline bundle plus
/// EXACTLY three differences — the eight plumbing env entries, the `hooks` object, and
/// the plan's `egress_hook` pin — and no other byte moves.**
///
/// # Would red if
///
/// `BundleMounts::with_egress` grew a mount, a namespace, a capability or a
/// capability-adjacent field; if the eight env entries or the two hook entries were
/// rendered in a non-deterministic order; if the hook argv stopped leading with
/// the pinned program path; or if the no-egress plan stopped being byte-identical
/// to the committed golden — which is the half that keeps this arm from silently
/// changing every capsule's container.
///
/// A `unix:` proxy socket spelling is absent on purpose and cannot be
/// produced: see `kata_worker::egress_proxy`'s module doc for the measurement (undici
/// refuses it, reqwest IGNORES it and goes direct).
#[test]
fn egress_plumbing_adds_exactly_eight_env_entries() {
    let without = plan().config_json;
    let plumbing = EgressPlumbing::loopback("/attempt/egress/proxy.sock".into(), 18080)
        .expect("an absolute socket path and a non-zero port");
    let planned = spec_for_as(
        &egress_capsule(),
        &environment(),
        &mounts().with_egress(plumbing),
        &containment(),
        NetPolicy::Offline,
        Some(&hook_inputs()),
        GOLDEN_UID,
        GOLDEN_GID,
    )
    .expect("the egress fixture plans");
    let with = planned.config_json.clone();

    // THE PLAN'S OWN PIN — the second half of the `hooks` claim, verified by the
    // provider against the config's bytes before the runtime may exec it.
    let pin = planned
        .egress_hook
        .as_ref()
        .expect("an Egress plan carries the hook's byte pin");
    assert_eq!(
        pin.store_path, "/nix/store/egress0000000000000000000000000-hook-kata-oci-hook",
        "the plan pins the hook binary by its provider-entry path"
    );
    assert!(
        planned
            .egress_hook
            .as_ref()
            .expect("pin")
            .sha256
            .ends_with("ee"),
        "the pin carries the sha256 the provider re-derives: {pin:?}"
    );

    let mut bare: serde_json::Value =
        serde_json::from_str(&without).expect("the no-egress plan is JSON");
    let full: serde_json::Value = serde_json::from_str(&with).expect("the egress plan is JSON");

    let bare_env = bare["process"]["env"]
        .as_array()
        .expect("process.env is an array")
        .clone();
    let full_env = full["process"]["env"]
        .as_array()
        .expect("process.env is an array")
        .clone();
    assert_eq!(
        bare_env.len(),
        1,
        "a capsule without egress carries PATH and nothing else: {bare_env:?}"
    );
    assert_eq!(
        full_env
            .iter()
            .map(|entry| entry.as_str().expect("an env entry is a string"))
            .collect::<Vec<_>>(),
        vec![
            bare_env[0].as_str().expect("PATH"),
            "HTTP_PROXY=http://127.0.0.1:18080",
            "HTTPS_PROXY=http://127.0.0.1:18080",
            "http_proxy=http://127.0.0.1:18080",
            "https_proxy=http://127.0.0.1:18080",
            "ALL_PROXY=http://127.0.0.1:18080",
            "all_proxy=http://127.0.0.1:18080",
            "NO_PROXY=localhost,127.0.0.1,[::1]",
            "no_proxy=localhost,127.0.0.1,[::1]",
        ],
        "PATH first, then the eight plumbing entries in a fixed order — the proxy pair, its lowercase spellings and `ALL_PROXY`, then the loopback bypass, each under both casings"
    );

    // THE HOOKS — two `createContainer` entries, `loopback-up` then
    // `hand-listener`, each leading with the pinned program path. Asserted
    // field-by-field rather than by golden because the pin's sha256 is a fixture
    // string and the value under review is the SHAPE.
    let hooks = full["hooks"]["createContainer"]
        .as_array()
        .expect("an Egress plan renders hooks.createContainer");
    assert_eq!(
        hooks.len(),
        2,
        "exactly the loopback-up and hand-listener entries: {hooks:?}"
    );
    let args_of = |index: usize| -> Vec<String> {
        hooks[index]["args"]
            .as_array()
            .expect("hook args is an array")
            .iter()
            .map(|a| a.as_str().expect("a string arg").to_owned())
            .collect()
    };
    assert_eq!(
        args_of(0),
        vec![
            "/nix/store/egress0000000000000000000000000-hook-kata-oci-hook",
            "loopback-up",
            "--ip",
            "/nix/store/egress0000000000000000000000000-iproute2/bin/ip",
        ],
        "loopback-up runs first and execs the provider's `ip` by absolute path"
    );
    assert_eq!(
        args_of(1),
        vec![
            "/nix/store/egress0000000000000000000000000-hook-kata-oci-hook",
            "hand-listener",
            "--port",
            "18080",
            "--to",
            "/attempt/egress/proxy.sock",
        ],
        "hand-listener binds the guest's proxy port and names the handoff socket"
    );
    for entry in hooks {
        assert_eq!(
            entry["path"].as_str().expect("hook path is a string"),
            "/nix/store/egress0000000000000000000000000-hook-kata-oci-hook",
            "every createContainer entry execs the pinned hook binary"
        );
        assert!(
            entry.get("env").is_none() || entry["env"].is_null(),
            "a hook carries no env: its whole input is its argv, and ambient would be a channel"
        );
    }
    // No OTHER hook phase: `createRuntime` etc. are phases kata never emits and
    // `verify_egress_hooks` refuses — the render must not produce what its own
    // checker declines.
    let phases = full["hooks"]
        .as_object()
        .expect("hooks is an object")
        .keys()
        .cloned()
        .collect::<Vec<_>>();
    assert_eq!(
        phases,
        vec!["createContainer"],
        "no other hook phase renders"
    );

    // EVERYTHING ELSE, compared as a whole: replace `process.env` and `hooks` and
    // the two documents must be identical. A mount, a namespace or a capability
    // added by the egress arm is red here without this test having to enumerate
    // the fields.
    bare["process"]["env"] = serde_json::Value::Array(full_env);
    bare["hooks"] = full["hooks"].clone();
    assert_eq!(
        bare, full,
        "egress is two environment entries and the hooks object. Anything else in the bundle \
         would be a containment change wearing an environment change's review"
    );
    assert!(
        !with.contains("unix:"),
        "a `unix:` proxy URL is SILENTLY IGNORED by reqwest and the request goes direct, so it is \
         a fail-open egress bypass and must never appear in a rendered bundle"
    );
}

/// **The three-way agreement `spec_for` refuses to break.** The declared
/// posture, the plumbing env and the hook inputs are halves of ONE claim; a plan
/// carrying only some of them describes a posture nobody declared.
///
/// # Would red if
///
/// The `(declared_network, mounts.egress(), egress)` match in `spec_for_as`
/// admitted any partial combination.
#[test]
fn the_egress_halves_arrive_together_or_not_at_all() {
    let env = environment();
    let plumbing =
        EgressPlumbing::loopback("/attempt/egress/proxy.sock".into(), 18080).expect("well formed");
    let inputs = hook_inputs();

    // Offline + anything egress: refused — the declaration is the authority.
    for (mounts, inputs_opt) in [
        (mounts().with_egress(plumbing.clone()), None),
        (mounts(), Some(&inputs)),
        (mounts().with_egress(plumbing.clone()), Some(&inputs)),
    ] {
        let message = spec_for_as(
            &capsule(),
            &env,
            &mounts,
            &containment(),
            NetPolicy::Offline,
            inputs_opt,
            GOLDEN_UID,
            GOLDEN_GID,
        )
        .expect_err("an Offline capsule arriving with egress machinery is refused")
        .to_string();
        assert!(
            message.contains("declares `network: offline` but arrives with egress machinery"),
            "{message}"
        );
    }

    // Egress + only some of its mechanism: refused — a plan naming part of the
    // arm would describe a posture nobody declared.
    for (mounts, inputs_opt) in [
        (mounts().with_egress(plumbing.clone()), None),
        (mounts(), Some(&inputs)),
        (mounts(), None),
    ] {
        let message = spec_for_as(
            &egress_capsule(),
            &env,
            &mounts,
            &containment(),
            NetPolicy::Offline,
            inputs_opt,
            GOLDEN_UID,
            GOLDEN_GID,
        )
        .expect_err("an Egress capsule arriving short of its mechanism is refused")
        .to_string();
        assert!(
            message.contains("arrives short of its mechanism"),
            "{message}"
        );
    }
}

/// **The rendered `process.env` carries no name twice.** An `Egress` agent
/// capsule — the proxy pair, kata's `HOME` and a declared variable on one list —
/// renders `config.json` on disk whose `process.env` names `HOME` exactly once
/// and no name twice: the declared-env refusal (`capsule_agent_env_channel_owned`)
/// is what makes the no-duplicate claim hold, and the bytes on disk, not kata's
/// plan struct, are the oracle.
#[test]
fn the_rendered_process_env_repeats_no_name() {
    use kata_types::agent::AdapterKind;
    use kata_types::execution_contract::{AgentTurnSpec, ArtifactId};
    use kata_types::primitives::ContentHash;

    let allowlist: std::collections::BTreeSet<kata_types::execution_contract::EgressAuthority> = [
        kata_types::execution_contract::EgressAuthority::new("example.com", 443)
            .expect("a well-formed authority"),
    ]
    .into_iter()
    .collect();
    let capsule = Capsule::new(
        OccurrenceId(hash(1)),
        PreparedActionId(hash(2)),
        EnvironmentId(hash(3)),
        PlatformRef::new("x86_64-linux", hash(11)).id(),
        capsule().inputs().to_vec(),
        CapsuleProcess::Agent(AgentTurnSpec {
            adapter: AdapterKind::NanocodeOpenai,
            model: None,
            reasoning_effort: None,
            output_schema: None,
            prompt: ArtifactId(ContentHash::new([0x77; 32])),
            credential: None,
            env: [(
                smol_str::SmolStr::new("TERM"),
                smol_str::SmolStr::new("dumb"),
            )]
            .into_iter()
            .collect(),
        }),
        CapsuleNetwork::Egress { allowlist },
        None,
        budgets(),
        None,
    )
    .expect("the egress agent capsule is well formed");
    let root = tempfile::tempdir().expect("an attempt root");
    let plumbing = EgressPlumbing::loopback("/attempt/egress/proxy.sock".into(), 18080)
        .expect("an absolute socket path and a non-zero port");
    let mounts = BundleMounts::under(root.path(), 64 * 1024 * 1024)
        .expect("the mounts build")
        .with_egress(plumbing)
        .with_toolhost(PathBuf::from(GOLDEN_TOOLHOST_DIR))
        .expect("an absolute toolhost directory");
    let plan = spec_for_as(
        &capsule,
        &environment(),
        &mounts,
        &containment(),
        NetPolicy::Offline,
        Some(&hook_inputs()),
        GOLDEN_UID,
        GOLDEN_GID,
    )
    .expect("the egress agent capsule plans");
    let config: serde_json::Value =
        serde_json::from_str(&plan.config_json).expect("the rendered config parses");
    let names: Vec<&str> = config["process"]["env"]
        .as_array()
        .expect("env is an array")
        .iter()
        .filter_map(|entry| entry.as_str()?.split('=').next())
        .collect();
    let mut counts = std::collections::BTreeMap::new();
    for name in &names {
        *counts.entry(*name).or_insert(0_usize) += 1;
    }
    assert!(
        counts.values().all(|count| *count == 1),
        "process.env repeats a name: {counts:?}"
    );
    for name in ["HOME", "HTTP_PROXY", "TERM"] {
        assert_eq!(
            counts.get(name),
            Some(&1),
            "{name} lands exactly once: {counts:?}"
        );
    }
}

/// **The `read_write_scratch` tag is `/work`'s alone.** A scratch `/work` plans
/// — the mount is a writable bind like a workspace's, the never-apply semantic
/// being the main's adoption door, not the bundle's — while the same tag on
/// `/out` (or any other guest path) is a mapping no assembler mints and is
/// refused BY NAME, never coerced to plain read-write.
#[test]
fn the_scratch_access_tag_is_works_alone() {
    let scratch = capsule_with(
        vec![
            mapping("/work", GuestAccess::ReadWriteScratch, 20),
            mapping("/out", GuestAccess::ReadWrite, 21),
            mapping("/tmp", GuestAccess::ReadWrite, 22),
            mapping(BUSYBOX, GuestAccess::ReadOnly, 23),
        ],
        budgets(),
    );
    let plan = spec_for_as(
        &scratch,
        &environment(),
        &mounts(),
        &containment(),
        NetPolicy::Offline,
        None,
        GOLDEN_UID,
        GOLDEN_GID,
    )
    .expect("a scratch /work plans — its mount is a writable bind");
    let config: serde_json::Value =
        serde_json::from_str(&plan.config_json).expect("the rendered config parses");
    let work = config["mounts"]
        .as_array()
        .expect("mounts is an array")
        .iter()
        .find(|mount| mount["destination"] == "/work")
        .expect("/work is mounted");
    let options: Vec<&str> = work["options"]
        .as_array()
        .expect("options is an array")
        .iter()
        .filter_map(|option| option.as_str())
        .collect();
    assert!(
        !options.contains(&"ro"),
        "a scratch /work mounts writable — recording-not-applying is the adoption door's job: {options:?}"
    );

    // The same tag ANYWHERE else is refused, never coerced.
    let misused = capsule_with(
        vec![
            mapping("/work", GuestAccess::ReadWrite, 20),
            mapping("/out", GuestAccess::ReadWriteScratch, 21),
            mapping("/tmp", GuestAccess::ReadWrite, 22),
            mapping(BUSYBOX, GuestAccess::ReadOnly, 23),
        ],
        budgets(),
    );
    let err = spec_for_as(
        &misused,
        &environment(),
        &mounts(),
        &containment(),
        NetPolicy::Offline,
        None,
        GOLDEN_UID,
        GOLDEN_GID,
    )
    .expect_err("a scratch /out is a mapping kata does not mint")
    .to_string();
    assert!(
        err.contains("read_write_scratch") && err.contains("/work"),
        "the refusal names the tag and its one legal path: {err}"
    );
}

// ---------------------------------------------------------------------------
// The tool host: a nanocode agent capsule's init and its read-only directory
// ---------------------------------------------------------------------------

/// The provider entry's `toolhost/` directory the toolhost golden binds. FIXED,
/// for [`ATTEMPT_ROOT`]'s reason: the real one is `<store>/<address>/toolhost`.
const GOLDEN_TOOLHOST_DIR: &str = "/var/lib/kata/providers/youki/0000/toolhost";

/// The committed toolhost golden, repo-relative.
fn toolhost_golden_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/oci/toolhost-agent-offline.config.json")
}

/// A nanocode agent turn of `adapter` over the golden's mappings: the kind
/// fixes the launch, and the turn declares one variable.
fn toolhost_capsule(adapter: kata_types::agent::AdapterKind) -> Capsule {
    use kata_types::execution_contract::AgentTurnSpec;
    let base = capsule();
    Capsule::new(
        base.occurrence(),
        base.action(),
        base.environment(),
        base.platform(),
        base.inputs().to_vec(),
        CapsuleProcess::Agent(AgentTurnSpec {
            adapter,
            model: None,
            reasoning_effort: None,
            output_schema: None,
            prompt: ArtifactId(hash(0x51)),
            credential: None,
            env: std::collections::BTreeMap::from([(
                smol_str::SmolStr::new("TERM"),
                smol_str::SmolStr::new("dumb"),
            )]),
        }),
        CapsuleNetwork::Offline,
        None,
        budgets(),
        None,
    )
    .expect("a nanocode turn is well formed")
}

fn toolhost_mounts() -> BundleMounts {
    mounts()
        .with_toolhost(PathBuf::from(GOLDEN_TOOLHOST_DIR))
        .expect("an absolute toolhost directory")
}

fn plan_toolhost(
    capsule: &Capsule,
    mounts: &BundleMounts,
) -> kata_types::KataResult<OciBundlePlan> {
    spec_for_as(
        capsule,
        &environment(),
        mounts,
        &containment(),
        NetPolicy::Offline,
        None,
        GOLDEN_UID,
        GOLDEN_GID,
    )
}

/// **BYTE GOLDEN: the whole `config.json` of an offline nanocode agent capsule,
/// the same for both nanocode kinds.** The kind is in the capsule id, not in the
/// container's description, so the two render one file.
///
/// **Would red if:** any byte of the toolhost arm moved (the `/.kata` bind or its
/// options, `process.args`, the rendered `HOME`), or the two kinds rendered
/// apart. Re-baseline as the command golden does (`KATA_REBASELINE_OCI_GOLDEN=1`).
#[test]
fn the_toolhost_agent_bundle_matches_its_committed_golden() {
    use kata_types::agent::AdapterKind;
    let produced = plan_toolhost(
        &toolhost_capsule(AdapterKind::NanocodeOpenai),
        &toolhost_mounts(),
    )
    .expect("the toolhost capsule plans")
    .config_json;
    let anthropic = plan_toolhost(
        &toolhost_capsule(AdapterKind::NanocodeAnthropic),
        &toolhost_mounts(),
    )
    .expect("the toolhost capsule plans")
    .config_json;
    assert_eq!(
        produced, anthropic,
        "both nanocode kinds render one container"
    );
    let path = toolhost_golden_path();
    if std::env::var_os("KATA_REBASELINE_OCI_GOLDEN").is_some() {
        std::fs::write(&path, produced.as_bytes()).expect("writing the toolhost golden");
        panic!(
            "re-baselined {} ({} bytes). This is always a FAILURE: read the diff first.",
            path.display(),
            produced.len()
        );
    }
    let golden = std::fs::read_to_string(&path).unwrap_or_else(|error| {
        panic!(
            "the committed golden {} could not be read ({error})",
            path.display()
        )
    });
    assert!(
        golden.len() > 2_000,
        "the golden is too small to be a full spec"
    );
    if produced != golden {
        let first_difference = produced
            .lines()
            .zip(golden.lines())
            .enumerate()
            .find(|(_, (a, b))| a != b)
            .map_or_else(
                || "no differing line; the files differ in LENGTH".to_string(),
                |(index, (a, b))| format!("line {}: produced {a:?} / golden {b:?}", index + 1),
            );
        panic!(
            "the toolhost config.json no longer matches {}. THIS IS A CONTAINMENT CHANGE. \
             {first_difference}",
            path.display()
        );
    }
}

/// **The toolhost arm, read out of the rendered JSON against literals:** exactly
/// one mount at `/.kata`, sourced from the provider entry's `toolhost/`,
/// `bind,ro,nosuid,nodev,rprivate` and NOT `noexec` (it holds the init);
/// `process.args` is `["/.kata/kata-toolhost"]` whatever the capsule's (empty)
/// argv; the cwd is `/work`; the env is `PATH`, `HOME=/tmp` and the declared
/// variable, in that order, and nothing else; and the provider is told to create
/// the `/.kata` directory mount point. A command capsule's plan has none of it.
///
/// **Would red if:** the bind were writable, `noexec`, a file bind, or absent;
/// the init were anything but the toolhost; `HOME` were not kata's; or `/.kata`
/// leaked into a capsule whose init is not the toolhost.
#[test]
fn the_toolhost_bundle_binds_its_directory_read_only_and_execs_the_toolhost() {
    use kata_types::agent::AdapterKind;
    let plan = plan_toolhost(
        &toolhost_capsule(AdapterKind::NanocodeOpenai),
        &toolhost_mounts(),
    )
    .expect("the toolhost capsule plans");
    let config: serde_json::Value = serde_json::from_str(&plan.config_json).unwrap();
    let toolhost_mounts: Vec<&serde_json::Value> = config["mounts"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|mount| mount["destination"] == "/.kata")
        .collect();
    assert_eq!(toolhost_mounts.len(), 1, "{}", plan.config_json);
    assert_eq!(toolhost_mounts[0]["source"], GOLDEN_TOOLHOST_DIR);
    assert_eq!(
        toolhost_mounts[0]["options"],
        serde_json::json!(["bind", "ro", "nosuid", "nodev", "rprivate"])
    );
    assert_eq!(
        config["process"]["args"],
        serde_json::json!(["/.kata/kata-toolhost"])
    );
    assert_eq!(config["process"]["cwd"], "/work");
    assert_eq!(
        config["process"]["env"],
        serde_json::json!([format!("PATH={BUSYBOX}/bin:/bin"), "HOME=/tmp", "TERM=dumb"])
    );
    assert!(plan.rootfs_mountpoints.contains(&"/.kata".to_owned()));

    let command = plan_toolhost(&capsule(), &mounts()).expect("the command capsule plans");
    assert!(!command.config_json.contains("/.kata"));
    assert!(
        !command
            .rootfs_mountpoints
            .iter()
            .any(|point| point == "/.kata")
    );
}

/// **The capsule's kind and the mounts' toolhost directory arrive together or
/// not at all.** An agent capsule without the directory is refused (its init
/// would be a program the rootfs does not hold); a command capsule WITH it is
/// refused (a mount nobody declared), even one whose argv names the toolhost's
/// path; and a relative directory is refused by the mounts' constructor.
///
/// **Would red if:** the agreement check admitted either half alone.
#[test]
fn the_toolhost_halves_arrive_together_or_not_at_all() {
    use kata_types::agent::AdapterKind;
    let message = plan_toolhost(&toolhost_capsule(AdapterKind::NanocodeAnthropic), &mounts())
        .expect_err("a toolhost capsule without the directory")
        .to_string();
    assert!(message.contains("carry no toolhost directory"), "{message}");

    let base = capsule();
    let named = Capsule::new(
        base.occurrence(),
        base.action(),
        base.environment(),
        base.platform(),
        base.inputs().to_vec(),
        CapsuleProcess::Command {
            argv: vec!["/.kata/kata-toolhost".into()],
        },
        CapsuleNetwork::Offline,
        None,
        budgets(),
        None,
    )
    .expect("a command naming the toolhost's path is still a command");
    for (case, capsule) in [
        ("a command capsule", capsule()),
        ("a command naming the toolhost", named),
    ] {
        let message = plan_toolhost(&capsule, &toolhost_mounts())
            .expect_err("a toolhost directory on a capsule whose init is not the toolhost")
            .to_string();
        assert!(
            message.contains("init is not kata-toolhost"),
            "{case}: {message}"
        );
    }
    let message = mounts()
        .with_toolhost(PathBuf::from("toolhost"))
        .expect_err("a relative toolhost directory")
        .to_string();
    assert!(message.contains("is not absolute"), "{message}");
}

/// **A nanocode capsule carries no credential.** Its harness's credential stays
/// in the worker and the bundle has no channel to render one through, so the
/// rendered env of a nanocode plan holds no name beyond `PATH`, `HOME` and the
/// declared one.
///
/// **Would red if:** the toolhost arm rendered any other variable (a credential
/// would reach the capsule every tool process can read).
#[test]
fn a_nanocode_capsule_carries_no_credential() {
    use kata_types::agent::AdapterKind;
    let plan = plan_toolhost(
        &toolhost_capsule(AdapterKind::NanocodeOpenai),
        &toolhost_mounts(),
    )
    .expect("the toolhost capsule plans");
    let config: serde_json::Value = serde_json::from_str(&plan.config_json).unwrap();
    let names: Vec<&str> = config["process"]["env"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|entry| entry.as_str()?.split('=').next())
        .collect();
    assert_eq!(names, ["PATH", "HOME", "TERM"]);
}
