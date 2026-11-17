//! The OCI stage driver's ORDER of refusals, on a host
//! with no youki, no cgroup delegation and no container runtime.
//!
//! # The one property this file exists for
//!
//! *"A capsule this node cannot serve costs no process."* The driver resolves the
//! provider's bytes and materializes the capsule BEFORE it launches anything, so a
//! closure entry that is absent from this worker's store is a refusal that never
//! spawned `kata-provider-youki`.
//!
//! That is asserted against something the driver does not share: the provisioned
//! provider is a shell script whose only job is to `touch` a marker file, and the
//! assertion is that the marker does not exist. A test that checked a boolean the
//! driver set would be asking kata whether kata spawned anything.
//!
//! It also pins WHO OWNS the attempt root after a refusal: the driver removes
//! `<worker_state>/attempts/<tag>` on every refusal but an ambiguous teardown, because
//! nothing downstream will read a refused drive's inputs and a directory nobody reclaims
//! is disk growth keyed on an operator's bad luck.
//!
//! Host-free and rides `just gate`: nothing here reaches a cgroup, a namespace or
//! the pinned runtime.

#![cfg(target_os = "linux")]

use std::path::{Path, PathBuf};

use kata_types::error::KataResult;
use kata_types::execution_contract::{
    ArtifactId, ArtifactPrivacy, Capsule, CapsuleBudgets, CapsuleNetwork, CapsuleProcess,
    EnvironmentId, GuestAccess, GuestMapping, GuestPath, OccurrenceId, PlatformRef,
    PreparedActionId,
};
use kata_types::nix_environment::{
    ClosureEntry, IntegrityPolicy, NarVerification, NixEnvironmentManifest, Provenance,
    RetentionClass, RetentionIntent, StorePath,
};
use kata_types::primitives::{ContentHash, ObjectId};
use kata_types::sandbox::NetPolicy;
use kata_types::tree_artifact::TreeManifest;
use kata_worker::execution_route::{ExternalProviderAddress, OciRoute};
use kata_worker::materialize::{BlobSource, StorePathProbe, TreeResolver};
use kata_worker::oci_driver::{
    OCI_PROVIDER_NAME, OciProviderInstallation, OciStageDriver, OciStageRequest,
};

// ---------------------------------------------------------------------------
// Stubs that PANIC — the order under test is what keeps them unreached
// ---------------------------------------------------------------------------

/// A store probe that reports every closure entry ABSENT. This is the refusal under
/// test, and it answers from a fixed verdict so the test is deterministic on a box
/// with no Nix at all.
struct EverythingAbsent;

impl StorePathProbe for EverythingAbsent {
    fn present(&self, _path: &StorePath) -> KataResult<bool> {
        Ok(false)
    }
}

/// A resolver that must NOT be reached: the closure check runs before any mapping is
/// materialized, so a capsule whose environment is unavailable never has its trees
/// looked up.
struct TreesForbidden;

impl TreeResolver for TreesForbidden {
    fn tree_manifest(&self, artifact: ArtifactId) -> KataResult<TreeManifest> {
        panic!(
            "the driver looked up tree artifact {artifact:?} for a capsule whose environment \
             closure is not present on this worker. The closure is checked FIRST so a host missing \
             a store object fails with nothing written and nothing spawned."
        );
    }

    fn tree_reference(
        &self,
        artifact: ArtifactId,
    ) -> KataResult<kata_types::execution_contract::ArtifactRef> {
        panic!(
            "the driver looked up the reference for tree artifact {artifact:?} — the same \
             forbidden lookup as `tree_manifest`, one step earlier"
        );
    }
}

/// A blob source that must NOT be reached, for the same reason.
struct BytesForbidden;

impl BlobSource for BytesForbidden {
    fn read_verified(
        &self,
        object: ObjectId,
        _expected: u64,
        _maximum: u64,
    ) -> KataResult<Vec<u8>> {
        panic!(
            "the driver read object {object:?} for a capsule whose environment closure is not \
             present on this worker."
        );
    }
}

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

fn hash(byte: u8) -> ContentHash {
    ContentHash::new([byte; 32])
}

/// A store path that is SHAPED like one and is not realised anywhere. The probe
/// above is what decides its absence; this value only has to parse.
const ABSENT_STORE_PATH: &str = "/nix/store/0000000000000000000000000000000d-absent-fixture";

fn environment() -> NixEnvironmentManifest {
    let store_path = StorePath::new(ABSENT_STORE_PATH).expect("a valid store path");
    NixEnvironmentManifest::new(
        "oci-driver-refusal-fixture",
        PlatformRef::new("x86_64-linux", hash(11)),
        Provenance::StorePaths {
            nixpkgs_attribute: "nixpkgs#pkgsStatic.busybox".into(),
        },
        vec![store_path.clone()],
        vec![ClosureEntry {
            store_path: store_path.clone(),
            nar_hash: "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".into(),
            nar_size: 2_048,
            references: Vec::new(),
            ca: None,
        }],
        vec![GuestPath::new(format!("{ABSENT_STORE_PATH}/bin")).expect("the closure's bin")],
        IntegrityPolicy {
            verify: NarVerification::NarHashOnly,
            sigs_needed: 0,
            required_signers: Vec::new(),
            allow_unsigned_content_addressed: true,
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

fn mapping(path: &str, artifact: u8) -> GuestMapping {
    GuestMapping {
        artifact: ArtifactId(hash(artifact)),
        guest_path: GuestPath::new(path.to_owned()).expect("a guest path"),
        access: GuestAccess::ReadWrite,
    }
}

fn capsule() -> Capsule {
    Capsule::new(
        OccurrenceId(hash(1)),
        PreparedActionId(hash(2)),
        EnvironmentId(hash(3)),
        PlatformRef::new("x86_64-linux", hash(11)).id(),
        vec![
            mapping("/work", 20),
            mapping("/out", 21),
            mapping("/tmp", 22),
        ],
        CapsuleProcess::Command {
            argv: vec!["/bin/true".into()],
        },
        CapsuleNetwork::Offline,
        None,
        CapsuleBudgets {
            wall_time_ms: 30_000,
            output_bytes: 1 << 20,
            memory_bytes: 512 * 1024 * 1024,
            process_count: 64,
            result_bytes: kata_types::execution_contract::CAPSULE_RESULT_BYTES,
            result_entries: kata_types::execution_contract::CAPSULE_RESULT_ENTRIES,
            work_delta_bytes: kata_types::execution_contract::CAPSULE_WORK_DELTA_BYTES,
            work_delta_entries: kata_types::execution_contract::CAPSULE_WORK_DELTA_ENTRIES,
        },
        None,
    )
    .expect("the fixture capsule is well formed")
}

/// Provision a FAKE `kata-provider-youki` into a real by-hash provider store, and
/// return the installation plus the marker path the fake writes when it is spawned.
///
/// A real `ProviderStore`, not a stub: *"the driver resolves the provider
/// content-addressed"* is a claim about that store's verification, and a fake store
/// would make the refusal above pass for a driver that resolved nothing.
fn install_fake_provider(root: &Path) -> (OciProviderInstallation, PathBuf) {
    let marker = root.join("the-provider-was-spawned");
    let source = root.join("src");
    std::fs::create_dir_all(&source).expect("source dir");
    let binary = source.join(format!("kata-provider-{OCI_PROVIDER_NAME}"));
    std::fs::write(
        &binary,
        format!(
            "#!/bin/sh\ntouch {marker}\nexit 0\n",
            marker = marker.display()
        ),
    )
    .expect("fake provider bytes");
    // EXECUTABLE, or the non-vacuity twin below cannot run it and the spawn assertion
    // in its sibling would be about a file nothing could ever execute.
    std::fs::set_permissions(&binary, std::os::unix::fs::PermissionsExt::from_mode(0o755))
        .expect("the fake provider is executable");
    let store_root = root.join("store");
    let store = kata_worker::ProviderStore::new(&store_root);
    let provisioned = store
        .provision(OCI_PROVIDER_NAME, &source)
        .expect("the fake provider provisions");
    let address = ExternalProviderAddress::parse(&provisioned.address.to_string())
        .expect("a minted address parses");
    (OciProviderInstallation::new(store_root, address), marker)
}

// ---------------------------------------------------------------------------
// The test
// ---------------------------------------------------------------------------

/// **A capsule whose environment closure is not present on this worker is refused
/// before any provider process exists.**
///
/// **Would red if:** the driver launched the supervisor before materializing (the
/// marker file would exist), or reported the absence as anything but
/// `materialization_refused` — in particular as a plan or a provider refusal, which
/// would send an operator to look at youki for a missing store object.
#[tokio::test]
async fn an_absent_closure_entry_refuses_before_any_provider_spawn() {
    let root = tempfile::tempdir().expect("a tempdir");
    // Declared AFTER the `TempDir` so it drops BEFORE it: `ProviderStore::provision`
    // SEALS its entry and `TempDir`'s `Drop` cannot remove a sealed tree.
    let unseal = kata_worker::UnsealOnDrop::new(root.path());
    let (installation, marker) = install_fake_provider(root.path());

    let driver = OciStageDriver::new(
        OciRoute::new(fixture_certification(root.path())),
        root.path().join("worker-state"),
        installation,
    );

    let capsule = capsule();
    let environment = environment();
    let refusal = driver
        .drive(
            "attempt-fixture",
            &OciStageRequest {
                capsule: &capsule,
                environment: &environment,
                network: NetPolicy::Offline,
                trees: &TreesForbidden,
                source: &BytesForbidden,
                probe: &EverythingAbsent,
                execution_id: ulid::Ulid::new(),
            },
        )
        .await
        .err()
        .expect("a capsule whose closure is absent must be refused");

    assert_eq!(
        refusal.label(),
        "materialization_refused",
        "the absence of a closure entry is the MATERIALIZER's refusal; reporting it as a plan or a \
         provider refusal would send an operator to look at youki for a missing store object. \
         Got: {refusal}"
    );
    assert!(
        refusal.rules_out_a_container(),
        "a refusal returned before any provider exists is reported PROVEN NOT PERFORMED; the \
         marker below is the independent read that nothing ran"
    );
    assert!(
        refusal.to_string().contains(ABSENT_STORE_PATH),
        "the refusal must name the store path this worker does not have; got: {refusal}"
    );
    // THE PROPERTY, read from the filesystem rather than from the driver: no provider
    // process ever ran, because the fake provider's only behaviour is to leave this
    // file behind.
    assert!(
        !marker.exists(),
        "the driver SPAWNED `kata-provider-{OCI_PROVIDER_NAME}` for a capsule it then refused. A \
         capsule this node cannot serve must cost no process: the closure check runs before the \
         launch precisely so a host missing a store object pays nothing. Marker: {}",
        marker.display()
    );
    // And no attempt root survives. Two mechanisms make this true and the assertion
    // does not care which one did it here: the closure check runs BEFORE the
    // materializer creates anything, and the driver removes the tree on every refusal
    // but an ambiguous teardown. The next test is the one that isolates the removal.
    assert!(
        !driver.attempt_root("attempt-fixture").exists(),
        "a refused drive must leave no attempt root behind: nothing downstream reads a refused \
         drive's inputs, so the tree is disk an operator would have to reclaim by hand"
    );
    drop(unseal);
    drop(root);
}

/// Non-vacuity for the marker: the fake provider really does leave the file when it
/// is executed, so the assertion above is about the driver's ORDER rather than about
/// a marker nothing could ever write.
///
/// Without this, `an_absent_closure_entry_refuses_before_any_provider_spawn` passes
/// against a fake provider with a typo in it.
#[test]
fn the_fake_provider_leaves_its_marker_when_it_is_actually_run() {
    let root = tempfile::tempdir().expect("a tempdir");
    let unseal = kata_worker::UnsealOnDrop::new(root.path());
    let (installation, marker) = install_fake_provider(root.path());
    let resolved = installation
        .resolve()
        .expect("the provisioned entry re-hashes to its own name and holds the provider");
    let status = std::process::Command::new(resolved.binary())
        .status()
        .expect("the fake provider runs");
    assert!(status.success(), "the fake provider exits 0");
    assert!(
        marker.exists(),
        "the fake provider must leave {} when it runs, else the spawn assertion in the sibling \
         test is vacuous",
        marker.display()
    );
    drop(unseal);
    drop(root);
}

/// **A refusal AFTER the materializer wrote the attempt root REMOVES it.**
///
/// The sibling above refuses before anything is written, so it cannot tell "the driver
/// cleaned up" from "there was nothing to clean up". This one lets the materialization
/// SUCCEED — a present closure, a real published tree — and then refuses at the plan,
/// so the tree provably existed before the refusal and provably does not after.
///
/// The refusal is forced by `NetPolicy::Host`, which `oci_bundle::spec_for` refuses by
/// name: every capsule on this route runs in the empty namespace — an `Egress`
/// declaration included, whose only reach is the hook-handed loopback listener, so
/// `Host` is still the namespace posture that cannot be honoured. It is reached before
/// the supervisor launches anything — the provider resolve and the materialization both
/// succeed first — and on this undelegated host it would refuse at the placement
/// anyway; either way the attempt root has been written by then, which is all
/// this test needs.
///
/// **Would red if:** `drive` returned the refusal without disposing of the tree.
/// WATCHED RED with the refusal arm's `attempt_root.remove` call deleted:
/// `work/src/a.txt` was still on disk after the refusal.
#[tokio::test]
async fn a_refusal_after_materialization_removes_the_attempt_root() {
    let root = tempfile::tempdir().expect("a tempdir");
    let unseal = kata_worker::UnsealOnDrop::new(root.path());
    let (installation, _marker) = install_fake_provider(root.path());

    // A REAL CAS, so the materialization really writes: the refusal under test must
    // happen with bytes already on disk, or the assertion is the sibling's again.
    let cas_db = root.path().join("cas.db");
    let cas_blobs = root.path().join("cas");
    let cas = kata_core::store::cas::CasStore::open(&cas_db, &cas_blobs).expect("a fresh CAS");
    let member = cas
        .put_durable(b"work bytes\n")
        .expect("the member publishes");
    let work_manifest = TreeManifest::new(vec![kata_types::tree_artifact::TreeEntry {
        path: kata_types::tree_artifact::TreePath::new("src/a.txt").expect("a tree path"),
        node: kata_types::tree_artifact::TreeNode::File {
            mode: kata_types::tree_artifact::TreeEntryMode::Regular,
            object: member.object_id(),
            size_bytes: member.size(),
        },
    }])
    .expect("a valid manifest");
    let work = publish(&cas, &work_manifest);
    let empty = publish(
        &cas,
        &TreeManifest::new(Vec::new()).expect("an empty manifest"),
    );

    let driver = OciStageDriver::new(
        OciRoute::new(fixture_certification(root.path())),
        root.path().join("worker-state"),
        installation,
    );
    let attempt_root = driver.attempt_root("materialized-then-refused");
    let capsule = kata_types::execution_contract::Capsule::new(
        OccurrenceId(hash(1)),
        PreparedActionId(hash(2)),
        EnvironmentId(hash(3)),
        PlatformRef::new("x86_64-linux", hash(11)).id(),
        vec![
            GuestMapping {
                artifact: work.id(),
                guest_path: GuestPath::new("/work").expect("a guest path"),
                access: GuestAccess::ReadWrite,
            },
            GuestMapping {
                artifact: empty.id(),
                guest_path: GuestPath::new("/out").expect("a guest path"),
                access: GuestAccess::ReadWrite,
            },
            GuestMapping {
                artifact: empty.id(),
                guest_path: GuestPath::new("/tmp").expect("a guest path"),
                access: GuestAccess::ReadWrite,
            },
        ],
        CapsuleProcess::Command {
            argv: vec!["/bin/true".into()],
        },
        CapsuleNetwork::Offline,
        None,
        CapsuleBudgets {
            wall_time_ms: 30_000,
            output_bytes: 1 << 20,
            memory_bytes: 512 * 1024 * 1024,
            process_count: 64,
            result_bytes: kata_types::execution_contract::CAPSULE_RESULT_BYTES,
            result_entries: kata_types::execution_contract::CAPSULE_RESULT_ENTRIES,
            work_delta_bytes: kata_types::execution_contract::CAPSULE_WORK_DELTA_BYTES,
            work_delta_entries: kata_types::execution_contract::CAPSULE_WORK_DELTA_ENTRIES,
        },
        None,
    )
    .expect("the fixture capsule is well formed");

    let source = kata_worker::materialize::LocalCasBlobSource::open(&cas_db, &cas_blobs)
        .expect("the CAS opens read-only");
    let trees = kata_worker::materialize::DeclaredTreeResolver::new(vec![work, empty], &source);
    // A probe that reports the fixture closure PRESENT, so materialization proceeds. It
    // answers from a fixed list rather than the host's store, so this stays host-free.
    struct EverythingPresent;
    impl StorePathProbe for EverythingPresent {
        fn present(&self, _path: &StorePath) -> KataResult<bool> {
            Ok(true)
        }
    }
    let refusal = driver
        .drive(
            "materialized-then-refused",
            &OciStageRequest {
                capsule: &capsule,
                environment: &environment(),
                // `spec_for` admits only `Offline` on this route.
                network: NetPolicy::Host,
                trees: &trees,
                source: &source,
                probe: &EverythingPresent,
                execution_id: ulid::Ulid::new(),
            },
        )
        .await
        .err()
        .expect("`NetPolicy::Host` has no form on the rootless-OCI route");

    // NON-VACUITY, stated as the NEGATIVE so it cannot rot: the refusal must not be one
    // of the three that fire BEFORE the materializer runs, else this test is the sibling
    // above wearing a different name and proves nothing about removal. Which
    // post-materialization arm it is depends on the host — undelegated, the fake
    // provider's failed handshake gets there first; delegated, the `NetPolicy::Host`
    // plan refusal does — and the removal is the same either way, so the assertion does
    // not name one.
    assert!(
        !matches!(
            refusal.label(),
            "provider_unresolved" | "runtime_changed" | "materialization_refused"
        ),
        "the refusal must be a POST-materialization one, so the attempt root provably existed \
         before it; got {label}: {refusal}",
        label = refusal.label()
    );
    assert!(
        !attempt_root.exists(),
        "the attempt root {} survived a refusal. The driver removes it on every refusal but an \
         ambiguous teardown: nothing downstream reads a refused drive's inputs, and a tree nobody \
         reclaims is disk growth keyed on an operator's bad luck.",
        attempt_root.display()
    );
    drop(unseal);
    drop(root);
}

/// **A drive whose attempt root already holds a previous drive's files is refused before
/// anything is launched, touches none of those files, and does NOT rule a container out.**
///
/// An attempt tag is an attempt id, so a non-empty root is another drive of the same
/// attempt — possibly a retained `teardown_ambiguous` tree whose container is alive. Read
/// off the filesystem: the fake provider's marker stays absent and the previous drive's
/// file survives.
///
/// **Would red if:** the driver went on to materialize into a non-empty root. WATCHED RED
/// with the emptiness check disabled: the drive refused `materialization_refused` (here the
/// closure check refuses first), which reports NOT PERFORMED, and a non-ambiguous refusal
/// disposes of the root — the previous drive's tree with it.
#[tokio::test]
async fn a_root_holding_a_previous_drives_files_is_refused_untouched_and_ambiguous() {
    let root = tempfile::tempdir().expect("a tempdir");
    let unseal = kata_worker::UnsealOnDrop::new(root.path());
    let (installation, marker) = install_fake_provider(root.path());
    let driver = OciStageDriver::new(
        OciRoute::new(fixture_certification(root.path())),
        root.path().join("worker-state"),
        installation,
    );
    let previous = driver.attempt_root("attempt-driven-before");
    std::fs::create_dir_all(previous.join("work")).expect("a previous drive's tree");
    std::fs::write(
        previous.join("work").join("left.txt"),
        b"a previous drive\n",
    )
    .expect("a previous drive's file");

    let capsule = capsule();
    let environment = environment();
    let refusal = driver
        .drive(
            "attempt-driven-before",
            &OciStageRequest {
                capsule: &capsule,
                environment: &environment,
                network: NetPolicy::Offline,
                trees: &TreesForbidden,
                source: &BytesForbidden,
                probe: &EverythingAbsent,
                execution_id: ulid::Ulid::new(),
            },
        )
        .await
        .err()
        .expect("a second drive of one attempt is refused");
    assert_eq!(refusal.label(), "attempt_root_unavailable", "{refusal}");
    assert!(
        !refusal.rules_out_a_container(),
        "another drive of this attempt may have run its container"
    );
    assert!(
        !marker.exists(),
        "nothing was launched: {}",
        marker.display()
    );
    assert_eq!(
        std::fs::read(previous.join("work").join("left.txt")).expect("the file survives"),
        b"a previous drive\n",
        "the previous drive's bytes are not this drive's to remove"
    );
    drop(unseal);
    drop(root);
}

/// **A capsule whose prepare budget has elapsed is refused before the provider is
/// launched, after its inputs were materialized, and reports PROVEN NOT PERFORMED.**
///
/// The budget is what makes the main's wall-time grace a derivation
/// (`kata_types::capsule_timing`): the worker never hands a container to the provider
/// later than `CAPSULE_PREPARE_BUDGET` after the anchor it took before its start
/// checkpoint. Driven with an `assign_by` already in the past over a capsule whose
/// materialization SUCCEEDS, so the refusal is the budget's and no earlier step's; read
/// off the filesystem, no provider process ran.
///
/// **Would red if:** the drive launched the provider without checking the budget (the
/// fake provider's marker appears and the refusal is a launch one).
#[tokio::test]
async fn an_elapsed_prepare_budget_refuses_before_the_provider_is_launched() {
    let root = tempfile::tempdir().expect("a tempdir");
    let unseal = kata_worker::UnsealOnDrop::new(root.path());
    let (installation, marker) = install_fake_provider(root.path());
    let cas_db = root.path().join("cas.db");
    let cas_blobs = root.path().join("cas");
    let cas = kata_core::store::cas::CasStore::open(&cas_db, &cas_blobs).expect("a fresh CAS");
    let empty = publish(
        &cas,
        &TreeManifest::new(Vec::new()).expect("an empty manifest"),
    );
    let driver = OciStageDriver::new(
        OciRoute::new(fixture_certification(root.path())),
        root.path().join("worker-state"),
        installation,
    );
    let capsule = kata_types::execution_contract::Capsule::new(
        OccurrenceId(hash(1)),
        PreparedActionId(hash(2)),
        EnvironmentId(hash(3)),
        PlatformRef::new("x86_64-linux", hash(11)).id(),
        ["/work", "/out", "/tmp"]
            .into_iter()
            .map(|guest| GuestMapping {
                artifact: empty.id(),
                guest_path: GuestPath::new(guest).expect("a guest path"),
                access: GuestAccess::ReadWrite,
            })
            .collect(),
        CapsuleProcess::Command {
            argv: vec!["/bin/true".into()],
        },
        CapsuleNetwork::Offline,
        None,
        CapsuleBudgets {
            wall_time_ms: 30_000,
            output_bytes: 1 << 20,
            memory_bytes: 512 * 1024 * 1024,
            process_count: 64,
            result_bytes: kata_types::execution_contract::CAPSULE_RESULT_BYTES,
            result_entries: kata_types::execution_contract::CAPSULE_RESULT_ENTRIES,
            work_delta_bytes: kata_types::execution_contract::CAPSULE_WORK_DELTA_BYTES,
            work_delta_entries: kata_types::execution_contract::CAPSULE_WORK_DELTA_ENTRIES,
        },
        None,
    )
    .expect("the fixture capsule is well formed");
    let source = kata_worker::materialize::LocalCasBlobSource::open(&cas_db, &cas_blobs)
        .expect("the CAS opens read-only");
    let trees = kata_worker::materialize::DeclaredTreeResolver::new(vec![empty], &source);
    struct EverythingPresent;
    impl StorePathProbe for EverythingPresent {
        fn present(&self, _path: &StorePath) -> KataResult<bool> {
            Ok(true)
        }
    }
    let (_never, cancel) = tokio::sync::oneshot::channel();
    let refusal = driver
        .drive_cancellable(
            "prepare-budget-elapsed",
            &OciStageRequest {
                capsule: &capsule,
                environment: &environment(),
                network: NetPolicy::Offline,
                trees: &trees,
                source: &source,
                probe: &EverythingPresent,
                execution_id: ulid::Ulid::new(),
            },
            // Already past by the time any step can check it.
            std::time::Instant::now(),
            cancel,
        )
        .await
        .err()
        .expect("an elapsed prepare budget is refused");
    assert_eq!(refusal.label(), "prepare_budget_elapsed", "{refusal}");
    assert!(
        refusal.rules_out_a_container(),
        "nothing was assigned, so the verdict is PROVEN NOT PERFORMED"
    );
    assert!(
        !marker.exists(),
        "the provider was launched for an attempt past its prepare budget: {}",
        marker.display()
    );
    assert!(
        !driver.attempt_root("prepare-budget-elapsed").exists(),
        "the refused drive's materialized root is removed"
    );
    drop(unseal);
    drop(root);
}

/// **The capsule route LAUNCHES its provider with the capsule's own wall clock plus
/// `PROVIDER_FRAME_MARGIN` — exactly, neither shorter nor longer.**
///
/// The existing cells pin `capsule_provider_spec` as a function, which says nothing about
/// what the drive hands the launch: a drive that built the spec over any other budget —
/// say, one inflated to the one-hour authoring default at the call site — would keep
/// every host-free cell green, and a provider wedged under it would hold the worker's slot
/// for an hour past a five-second stage. So this reads the budget off the LAUNCH DOOR
/// itself (`launched_frame_budgets_for_test`, recorded before anything can refuse), on a
/// drive that really materializes and really launches: the fake provider then fails its
/// handshake, which is the refusal this host-free rig ends in.
///
/// **Would red if:** the drive launched with any budget but `wall_time_ms` + margin.
#[tokio::test]
async fn the_capsule_route_launches_its_provider_with_the_capsules_own_wall_clock() {
    use kata_worker::provider_supervisor::{
        PROVIDER_FRAME_MARGIN, launched_frame_budgets_for_test,
    };
    struct ClosurePresent;
    impl StorePathProbe for ClosurePresent {
        fn present(&self, _path: &StorePath) -> KataResult<bool> {
            Ok(true)
        }
    }
    let root = tempfile::tempdir().expect("a tempdir");
    let unseal = kata_worker::UnsealOnDrop::new(root.path());
    let (installation, marker) = install_fake_provider(root.path());
    let cas_db = root.path().join("cas.db");
    let cas_blobs = root.path().join("cas");
    let cas = kata_core::store::cas::CasStore::open(&cas_db, &cas_blobs).expect("a fresh CAS");
    let empty = publish(
        &cas,
        &TreeManifest::new(Vec::new()).expect("an empty manifest"),
    );
    let wall_time_ms = 5_000;
    let capsule = Capsule::new(
        OccurrenceId(hash(1)),
        PreparedActionId(hash(2)),
        EnvironmentId(hash(3)),
        PlatformRef::new("x86_64-linux", hash(11)).id(),
        ["/work", "/out", "/tmp"]
            .into_iter()
            .map(|guest| GuestMapping {
                artifact: empty.id(),
                guest_path: GuestPath::new(guest).expect("a guest path"),
                access: GuestAccess::ReadWrite,
            })
            .collect(),
        CapsuleProcess::Command {
            argv: vec!["/bin/true".into()],
        },
        CapsuleNetwork::Offline,
        None,
        CapsuleBudgets {
            wall_time_ms,
            output_bytes: 1 << 20,
            memory_bytes: 512 * 1024 * 1024,
            process_count: 64,
            result_bytes: kata_types::execution_contract::CAPSULE_RESULT_BYTES,
            result_entries: kata_types::execution_contract::CAPSULE_RESULT_ENTRIES,
            work_delta_bytes: kata_types::execution_contract::CAPSULE_WORK_DELTA_BYTES,
            work_delta_entries: kata_types::execution_contract::CAPSULE_WORK_DELTA_ENTRIES,
        },
        None,
    )
    .expect("the fixture capsule is well formed");
    let driver = OciStageDriver::new(
        OciRoute::new(fixture_certification(root.path())),
        root.path().join("worker-state"),
        installation,
    );
    let source = kata_worker::materialize::LocalCasBlobSource::open(&cas_db, &cas_blobs)
        .expect("the CAS opens read-only");
    let trees = kata_worker::materialize::DeclaredTreeResolver::new(vec![empty], &source);
    assert!(
        launched_frame_budgets_for_test().is_empty(),
        "the premise: nothing in this process launched a provider yet"
    );
    let refusal = driver
        .drive(
            "frame-budget-attempt",
            &OciStageRequest {
                capsule: &capsule,
                environment: &environment(),
                network: NetPolicy::Offline,
                trees: &trees,
                source: &source,
                probe: &ClosurePresent,
                execution_id: ulid::Ulid::new(),
            },
        )
        .await
        .err()
        .expect("the fake provider answers no handshake");
    assert!(
        marker.exists(),
        "non-vacuity: the drive reached the launch and SPAWNED the provider; got {refusal}"
    );
    assert_eq!(
        launched_frame_budgets_for_test(),
        vec![(
            OCI_PROVIDER_NAME.to_owned(),
            std::time::Duration::from_millis(wall_time_ms) + PROVIDER_FRAME_MARGIN
        )],
        "the ONE launch this drive made holds the provider to the capsule's own wall clock plus \
         the margin"
    );
    drop(unseal);
    drop(root);
}

/// Publish a manifest and return the artifact reference that names it.
fn publish(
    cas: &kata_core::store::cas::CasStore,
    manifest: &TreeManifest,
) -> kata_types::execution_contract::ArtifactRef {
    let bytes = manifest.manifest_bytes().expect("the manifest serializes");
    let receipt = cas.put_durable(&bytes).expect("the manifest publishes");
    kata_types::execution_contract::ArtifactRef::new(
        receipt.object_id(),
        receipt.size(),
        ArtifactPrivacy::Public,
    )
}

/// A `YoukiCertification` over a RUNTIME FILE THIS TEST OWNS, with the sha256 read off
/// the bytes it just wrote.
///
/// The store path cannot be fictional: the driver re-derives the pinned binary's
/// digest before every launch, so a certification naming a path that does not exist
/// is refused `runtime_changed` before anything else happens — which is correct
/// behaviour and would make these tests assert the wrong refusal. So the fixture
/// writes a file under the test's own
/// tempdir and records its real digest, and the per-stage verification passes for the
/// reason it is supposed to: the bytes are the bytes.
///
/// Nothing here depends on the fixture being true of a HOST — no test in this file
/// plans a container, so the profile, the seccomp witness and the delegation are never
/// consulted.
fn fixture_certification(root: &Path) -> kata_worker::oci_runtime::YoukiCertification {
    let store_path = root.join("pinned-runtime");
    let bytes = b"not really a container runtime, but really these bytes\n";
    std::fs::write(&store_path, bytes).expect("the fixture runtime file is written");
    kata_worker::oci_runtime::YoukiCertification {
        store_path,
        sha256: kata_worker::oci_runtime::sha256_hex(bytes),
        version: (0, 7, 0),
        spec_version: (1, 0, 2),
        libseccomp_version: "2.6.1".to_owned(),
        profile: kata_worker::oci_runtime::ApparmorProfile::Loaded,
        installed_profile_sha256: "e".repeat(64),
        userns_restriction: kata_worker::oci_runtime::UsernsRestriction::Restricted,
        delegation: kata_worker::sandbox_bounds::cgroup_delegation().clone(),
        functional_probe_id: "kata-oci-driver-refusal-fixture".to_owned(),
    }
}

/// **`egress_listener_unavailable` reports `rules_out_a_container` — the handoff's
/// ack is why.**
///
/// The one refusal named PAST the assignment that is still `ProvenNotPerformed`:
/// the `hand-listener` hook exits successfully only on the worker's ack, so a
/// missing or refused listener means the create cannot have completed and the
/// container's init never ran.
/// The cell pins the LABEL and the arm's place in the classification — the timeout
/// and foreign-peer shapes of `HandoffRefusal` have their own cells in
/// `egress_proxy_tests.rs`.
#[test]
fn the_egress_listener_refusal_is_named_and_proven_not_performed() {
    let refusal = kata_worker::oci_driver::OciDriveRefusal::EgressListenerUnavailable(
        "no listener fd arrived within 30s, so the worker never sent the ack".to_owned(),
    );
    assert_eq!(refusal.label(), "egress_listener_unavailable", "{refusal}");
    assert!(
        refusal.rules_out_a_container(),
        "the create cannot have completed without the hook's ack: {refusal}"
    );
}

/// **The `CapsuleDriver` seam answers the attempt root the driver binds.**
/// `capsule_execution` publishes `/out` from, and the interactive launch roots its
/// attempt under, `CapsuleDriver::attempt_root` — reached only through the trait
/// object — so the seam must answer the SAME `<worker_state>/attempts/<tag>` the
/// driver's own bind is built from, never a second spelling.
///
/// **Would red if:** the trait impl answered any other path (the nightly mutation
/// sample's `attempt_root -> Default::default()` survivor: an empty path).
#[test]
fn the_driver_seam_answers_the_attempt_root_the_driver_binds() {
    let root = tempfile::tempdir().expect("a tempdir");
    let unseal = kata_worker::UnsealOnDrop::new(root.path());
    let (installation, _marker) = install_fake_provider(root.path());
    let driver = OciStageDriver::new(
        OciRoute::new(fixture_certification(root.path())),
        root.path().join("worker-state"),
        installation,
    );
    let seam: &dyn kata_worker::oci_driver::CapsuleDriver = &driver;
    assert_eq!(
        seam.attempt_root("attempt-seam"),
        root.path()
            .join("worker-state")
            .join("attempts")
            .join("attempt-seam"),
        "the seam's attempt root is the driver's own `<worker_state>/attempts/<tag>`"
    );
    drop(unseal);
}
