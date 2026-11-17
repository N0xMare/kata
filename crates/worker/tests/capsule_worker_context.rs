//! The WORKER's capsule execution context, driven on a
//! host that starts no container.
//!
//! # What each cell asserts against
//!
//! * the two-carrier occurrence check: a capsule whose OWN BYTES name another occurrence,
//!   published into a real CAS and fetched back through the production reader;
//! * the environment lookup: a plane row that points an [`EnvironmentId`] at another
//!   environment's manifest, and one whose closure names a store path this host does not
//!   have;
//! * the whole composition up to the container: a stub [`CapsuleDriver`] records the
//!   [`OciStageRequest`] it was handed, and the cell asserts about THAT REQUEST — the
//!   capsule it names, the environment it resolved, the network posture — rather than
//!   about the code that built it.
//!
//! Nothing here starts a container, and nothing asks kata whether kata wired itself: the
//! capsule and the manifest are published into a real `CasStore` and read back through
//! `LocalCasBlobSource`, and the request is observed from the double's own recording.
//!
//! The live cell that runs the real container is
//! `crates/workflow/tests/oci_stage_live.rs` and
//! `bin/kata/tests/oci_main_live.rs`.

use std::sync::Mutex;

use kata_agent::resource_bounds::TeardownOutcome;
use kata_core::store::cas::CasStore;
use kata_transport::types::{CapsuleAssignment, CapsuleRef, TraceContext, WorkerMessage};
use kata_types::agent::AdapterKind;
use kata_types::execution_contract::{
    AgentTurnSpec, ArtifactId, ArtifactPrivacy, ArtifactRef, Capsule, CapsuleBudgets,
    CapsuleNetwork, CapsuleProcess, EgressAuthority, EnvironmentId, GuestAccess, GuestMapping,
    GuestPath, OccurrenceId, PlatformRef, PreparedActionId,
};
use kata_types::nix_environment::{
    ClosureEntry, IntegrityPolicy, NarVerification, NixEnvironmentManifest, Provenance,
    RetentionClass, RetentionIntent, StorePath,
};
use kata_types::primitives::FixedBytes;
use kata_types::sandbox::NetPolicy;
use kata_types::tree_artifact::TreeManifest;
use kata_worker::capsule_execution::{CapsuleExecution, execute_capsule_frame};
use kata_worker::materialize::{StorePathProbe, TreeResolver};
use kata_worker::oci_driver::{CapsuleDriver, OciDriveRefusal, OciStageOutput, OciStageRequest};
use kata_worker::plane_index::{
    EnvironmentClaim, EnvironmentIndex, ObjectClaim, resolve_environment,
};
use kata_worker::result_publication::{BlobSink, CasBlobSink};

// The production registry installs kata's Code Mode limits, which run each
// cell of a nanocode turn in an interpreter process: this binary, re-executed.
kata_code_mode_host::interpreter_entry!();

// ---------------------------------------------------------------------------
// Rig
// ---------------------------------------------------------------------------

struct Rig {
    dir: tempfile::TempDir,
    cas: CasStore,
}

fn rig() -> Rig {
    let dir = tempfile::tempdir().expect("a temporary directory");
    let cas = CasStore::open(dir.path().join("cas.db"), dir.path().join("cas"))
        .expect("the content store opens");
    Rig { dir, cas }
}

impl Rig {
    /// The production READER over this rig's store: `cas.db` opened read-only from paths,
    /// which is how a worker reaches a store it does not own.
    fn reader(&self) -> kata_worker::materialize::LocalCasBlobSource {
        kata_worker::materialize::LocalCasBlobSource::open(
            &self.dir.path().join("cas.db"),
            &self.dir.path().join("cas"),
        )
        .expect("the store opens read-only")
    }
}

/// The two store paths these cells name. Their VALUES are the environment goldens' own,
/// for the goldens' reason: that they are FIXED is the point, and a fixture that invented
/// its own would drift from the plane's.
const PRESENT: &str = "/nix/store/0000000000000000000000000000000a-bash-5.2";
const ABSENT: &str = "/nix/store/1111111111111111111111111111111b-coreutils-9.5";

/// A [`StorePathProbe`] with a FIXED answer.
///
/// The probe is a trait for exactly this: whether `/nix/store/<x>` exists is a property of
/// a HOST, and these cells are about the composition. `LocalStorePathProbe`'s own
/// behaviour — that it stats with `AT_SYMLINK_NOFOLLOW` and answers on existence only —
/// is proven against the real filesystem in `crates/worker/tests/materialize_live.rs`,
/// which is where a claim about a host belongs.
struct FixedProbe(bool);

impl StorePathProbe for FixedProbe {
    fn present(&self, _path: &StorePath) -> kata_types::KataResult<bool> {
        Ok(self.0)
    }
}

fn manifest_with(label: &str, path: &str) -> NixEnvironmentManifest {
    let store_path = StorePath::new(path).expect("a legal store path");
    NixEnvironmentManifest::new(
        label,
        PlatformRef::new(
            "x86_64-linux",
            kata_types::primitives::ContentHash::new([0x33; 32]),
        ),
        Provenance::StorePaths {
            nixpkgs_attribute: smol_str::SmolStr::new("fixture"),
        },
        vec![store_path.clone()],
        vec![ClosureEntry {
            store_path,
            nar_hash: smol_str::SmolStr::new("sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="),
            nar_size: 2_048,
            references: Vec::new(),
            ca: None,
        }],
        Vec::new(),
        IntegrityPolicy {
            verify: NarVerification::NarHashOnly,
            sigs_needed: 0,
            required_signers: Vec::new(),
            allow_unsigned_content_addressed: true,
            verify_contents_at_declare: false,
        },
        ArtifactPrivacy::Public,
        RetentionIntent {
            class: RetentionClass::Authoritative,
        },
        "fixture",
    )
    .expect("the manifest is well formed")
}

/// Publish a manifest and return the claim a plane row would make about it.
fn publish_manifest(rig: &Rig, manifest: &NixEnvironmentManifest) -> (EnvironmentId, ObjectClaim) {
    let bytes = manifest.manifest_bytes().expect("manifest bytes");
    let durable = rig.cas.put_durable(&bytes).expect("the manifest publishes");
    let claim = ObjectClaim {
        object: durable.object_id(),
        size_bytes: durable.size(),
    };
    // The manifest's artifact id is the BYTES' OWN CAS ADDRESS — the derivation
    // `kata_core::environment::declare_environment` mints an environment id from, reached
    // through the same function rather than restated. `ArtifactRef::new(object, size,
    // privacy).id()` is the ARTIFACT plane's derivation and is NOT this one; using it here
    // would make these cells disagree with production.
    let artifact = ArtifactId(kata_types::cache::cas_address_for_canonical_bytes(&bytes).hash());
    (manifest.environment_ref(artifact).id(), claim)
}

/// An [`EnvironmentIndex`] that answers with exactly what it was given — the rig's stand-in
/// for a `nix_environments` row, which is the only thing a worker's plane contributes.
struct FixedIndex(Option<EnvironmentClaim>);

impl EnvironmentIndex for FixedIndex {
    fn environment_claim(
        &self,
        _environment: EnvironmentId,
    ) -> kata_types::KataResult<Option<EnvironmentClaim>> {
        Ok(self.0)
    }
}

fn live_claim(manifest: ObjectClaim) -> EnvironmentClaim {
    EnvironmentClaim {
        manifest,
        released: false,
        root_promoted: true,
    }
}

// ---------------------------------------------------------------------------
// The two-carrier occurrence check
// ---------------------------------------------------------------------------

fn empty_tree(rig: &Rig) -> ArtifactId {
    let manifest = TreeManifest::new(Vec::new()).expect("the empty manifest");
    let bytes = manifest.manifest_bytes().expect("manifest bytes");
    let durable = rig
        .cas
        .put_durable(&bytes)
        .expect("the empty tree publishes");
    ArtifactRef::new(durable.object_id(), durable.size(), ArtifactPrivacy::Public).id()
}

fn capsule_for(occurrence: OccurrenceId, environment: EnvironmentId, tree: ArtifactId) -> Capsule {
    capsule_shaped(
        occurrence,
        environment,
        tree,
        CapsuleProcess::Command {
            argv: vec!["sh".into(), "-c".into(), "echo context".into()],
        },
        CapsuleNetwork::Offline,
    )
}

/// The fixture's twin with the v8 arms open: every worker cell against an
/// `Agent` or `Egress` capsule builds the same object and varies only the two
/// fields under test.
fn capsule_shaped(
    occurrence: OccurrenceId,
    environment: EnvironmentId,
    tree: ArtifactId,
    process: CapsuleProcess,
    network: CapsuleNetwork,
) -> Capsule {
    let mapping = |guest: &str| GuestMapping {
        artifact: tree,
        guest_path: GuestPath::new(guest).expect("a guest path"),
        access: GuestAccess::ReadWrite,
    };
    Capsule::new(
        occurrence,
        PreparedActionId(FixedBytes([9u8; 32])),
        environment,
        PlatformRef::new(
            "x86_64-linux",
            FixedBytes(*blake3::hash(b"capsule-worker-context").as_bytes()),
        )
        .id(),
        vec![mapping("/work"), mapping("/out"), mapping("/tmp")],
        process,
        network,
        None,
        CapsuleBudgets {
            wall_time_ms: 30_000,
            output_bytes: 64 * 1024,
            memory_bytes: 512 * 1024 * 1024,
            process_count: 64,
            result_bytes: 64 * 1024 * 1024,
            result_entries: 10_000,
            work_delta_bytes: kata_types::execution_contract::CAPSULE_WORK_DELTA_BYTES,
            work_delta_entries: kata_types::execution_contract::CAPSULE_WORK_DELTA_ENTRIES,
        },
        None,
    )
    .expect("the capsule is well formed")
}

fn publish_capsule(rig: &Rig, capsule: &Capsule) -> CapsuleRef {
    let bytes = serde_json::to_vec(capsule).expect("the capsule serializes");
    let durable = rig.cas.put_durable(&bytes).expect("the capsule publishes");
    CapsuleRef {
        id: capsule.id(),
        object: durable.object_id(),
        size_bytes: durable.size(),
    }
}

fn frame_for(capsule: CapsuleRef, occurrence: OccurrenceId) -> CapsuleAssignment {
    CapsuleAssignment {
        attempt_id: ulid::Ulid::new(),
        execution_id: ulid::Ulid::new(),
        occurrence_id: occurrence,
        capsule,
        lease_epoch: 3,
        placed_on: smol_str::SmolStr::new("worker-context-1"),
        command_id: None,
        effect_domain: None,
        start_deadline_ms: None,
        progress_visibility: kata_types::workflow::ProgressVisibility::Off,
        trace: TraceContext::default(),
    }
}

/// A capsule whose OWN BYTES name another occurrence is refused, and the refusal comes
/// from the CAPSULE's occurrence rather than from the frame's self-agreement.
#[test]
fn a_capsule_naming_another_occurrence_than_the_frame_is_refused() {
    let rig = rig();
    let tree = empty_tree(&rig);
    let manifest = manifest_with("worker-context-fixture", PRESENT);
    let (environment, _) = publish_manifest(&rig, &manifest);

    let carried = OccurrenceId(FixedBytes([1u8; 32]));
    let claimed = OccurrenceId(FixedBytes([2u8; 32]));
    let capsule = capsule_for(carried, environment, tree);
    let reference = publish_capsule(&rig, &capsule);
    // The frame claims `claimed` and names the capsule's REAL id and address, so the only
    // disagreement left is the one between the two carriers.
    let frame = frame_for(reference, claimed);

    let source = rig.reader();
    let refusal = kata_worker::capsule_frame::resolve(&source, &frame)
        .expect_err("a capsule assembled for another occurrence must be refused")
        .to_string();
    assert!(
        refusal.contains("was assembled for occurrence")
            && refusal.contains(&carried.0.to_string()),
        "the refusal must name the occurrence THE CAPSULE'S BYTES carry, which is the \
         independent carrier: {refusal}"
    );
    assert!(
        refusal.contains(&claimed.0.to_string()),
        "and the one the frame claimed, so an operator can see which side to look at: {refusal}"
    );
    drop(rig.dir);
}

/// The agreeing case, so the cell above is not passing because everything is refused.
#[test]
fn a_capsule_whose_bytes_agree_with_the_frame_resolves() {
    let rig = rig();
    let tree = empty_tree(&rig);
    let manifest = manifest_with("worker-context-fixture", PRESENT);
    let (environment, _) = publish_manifest(&rig, &manifest);
    let occurrence = OccurrenceId(FixedBytes([7u8; 32]));
    let capsule = capsule_for(occurrence, environment, tree);
    let frame = frame_for(publish_capsule(&rig, &capsule), occurrence);
    let source = rig.reader();
    let resolved = kata_worker::capsule_frame::resolve(&source, &frame)
        .expect("two agreeing carriers resolve");
    assert_eq!(resolved.id(), capsule.id());
    assert_eq!(resolved.occurrence(), occurrence);
    drop(rig.dir);
}

// ---------------------------------------------------------------------------
// The environment lookup
// ---------------------------------------------------------------------------

/// A plane row that points an environment id at ANOTHER environment's manifest is refused
/// by name: the row is a hint, the capsule's id is the authority.
#[test]
fn a_row_pointing_at_another_environments_manifest_is_refused_by_name() {
    let rig = rig();
    let wanted = manifest_with("worker-context-fixture", PRESENT);
    let (wanted_id, _) = publish_manifest(&rig, &wanted);
    // A DIFFERENT environment: same shape, different closure, so a different id.
    let other = manifest_with("another-environment", ABSENT);
    let (other_id, other_claim) = publish_manifest(&rig, &other);
    assert_ne!(
        wanted_id, other_id,
        "the fixture must publish two environments"
    );

    let source = rig.reader();
    let refusal = resolve_environment(
        &FixedIndex(Some(live_claim(other_claim))),
        &source,
        wanted_id,
    )
    .expect_err("a row pointing at another environment's bytes must be refused")
    .to_string();
    assert!(
        refusal.contains("environment_identity_mismatch"),
        "refused by name: {refusal}"
    );
    assert!(
        refusal.contains(&wanted_id.0.to_string()) && refusal.contains(&other_id.0.to_string()),
        "and the refusal names both ids, so an operator sees which pairing is wrong: {refusal}"
    );
    drop(rig.dir);
}

/// A closure of `entries` store paths, each name padded so the manifest grows by roughly
/// 350 bytes an entry — the shape a real large closure has (one entry per store path),
/// not a label stuffed to size.
fn manifest_of_closure(entries: u32) -> NixEnvironmentManifest {
    const NIX_BASE32: &[u8] = b"0123456789abcdfghijklmnpqrsvwxyz";
    let closure: Vec<ClosureEntry> = (0..entries)
        .map(|index| {
            let mut digest = [b'0'; 32];
            let mut rest = index;
            for slot in digest.iter_mut().rev() {
                *slot = NIX_BASE32[(rest % 32) as usize];
                rest /= 32;
            }
            let digest = std::str::from_utf8(&digest).expect("base32 is ASCII");
            ClosureEntry {
                store_path: StorePath::new(format!(
                    "/nix/store/{digest}-package-{index}-{}",
                    "x".repeat(160)
                ))
                .expect("a legal store path"),
                nar_hash: smol_str::SmolStr::new(
                    "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
                ),
                nar_size: 2_048,
                references: Vec::new(),
                ca: None,
            }
        })
        .collect();
    let root = closure[0].store_path.clone();
    NixEnvironmentManifest::new(
        "a-large-closure",
        PlatformRef::new(
            "x86_64-linux",
            kata_types::primitives::ContentHash::new([0x33; 32]),
        ),
        Provenance::StorePaths {
            nixpkgs_attribute: smol_str::SmolStr::new("fixture"),
        },
        vec![root],
        closure,
        Vec::new(),
        IntegrityPolicy {
            verify: NarVerification::NarHashOnly,
            sigs_needed: 0,
            required_signers: Vec::new(),
            allow_unsigned_content_addressed: true,
            verify_contents_at_declare: false,
        },
        ArtifactPrivacy::Public,
        RetentionIntent {
            class: RetentionClass::Authoritative,
        },
        "fixture",
    )
    .expect("the manifest is well formed")
}

/// A manifest the MAIN authorizes is one the WORKER reads.
///
/// The main's authorization (`kata_workflow::authorization`) reads an environment
/// manifest under [`NixEnvironmentManifest::MAXIMUM_ENCODED_BYTES`] (16 MiB); a worker
/// that read the same object under a smaller ceiling would refuse
/// `environment_manifest_unreadable` for a closure authorized on the main. The size is
/// measured off the length the real
/// `CasStore` recorded, not computed by the code under test. The other side of the one
/// ceiling is checked too: a claim one byte over it is refused, so the cell pins the
/// bound rather than proving only that some large read succeeds.
#[test]
fn an_environment_manifest_the_main_authorizes_is_one_the_worker_reads() {
    const FORMER_WORKER_CEILING: u64 = 4 * 1024 * 1024;
    let rig = rig();
    let manifest = manifest_of_closure(18_000);
    let (environment, claim) = publish_manifest(&rig, &manifest);
    assert!(
        claim.size_bytes > FORMER_WORKER_CEILING
            && claim.size_bytes <= NixEnvironmentManifest::MAXIMUM_ENCODED_BYTES,
        "the fixture must land between the two ceilings, or this cell measures nothing: {} bytes",
        claim.size_bytes
    );

    let source = rig.reader();
    let resolved = resolve_environment(&FixedIndex(Some(live_claim(claim))), &source, environment)
        .expect("a manifest the main authorizes must be readable by the worker");
    assert_eq!(resolved, manifest);

    // One byte over the shared ceiling: `CasStore::read_verified` compares the claimed
    // length against the bound before it looks the object up, and names that refusal.
    let over = ObjectClaim {
        object: claim.object,
        size_bytes: NixEnvironmentManifest::MAXIMUM_ENCODED_BYTES + 1,
    };
    let refusal = resolve_environment(&FixedIndex(Some(live_claim(over))), &source, environment)
        .expect_err("a manifest over the one ceiling is refused")
        .to_string();
    assert!(
        refusal.contains("environment_manifest_unreadable"),
        "refused by name: {refusal}"
    );
    // And refused by the CEILING, not by the stored length disagreeing with the claim —
    // that later check would refuse this claim under any ceiling at all.
    assert!(
        refusal.contains("declared length exceeds the caller's bound"),
        "the one ceiling is what refused: {refusal}"
    );
    drop(rig.dir);
}

/// An environment no row names, a released one and an unpromoted one are each refused by
/// their own name — the three states a lookup can be in besides "resolvable".
#[test]
fn the_absent_released_and_unpromoted_states_are_each_refused_by_name() {
    let rig = rig();
    let manifest = manifest_with("worker-context-fixture", PRESENT);
    let (id, claim) = publish_manifest(&rig, &manifest);
    let source = rig.reader();

    let absent = resolve_environment(&FixedIndex(None), &source, id)
        .expect_err("a worker cannot invent a closure")
        .to_string();
    assert!(
        absent.contains("environment_unknown_to_this_worker"),
        "refused by name: {absent}"
    );

    let released = resolve_environment(
        &FixedIndex(Some(EnvironmentClaim {
            manifest: claim,
            released: true,
            root_promoted: true,
        })),
        &source,
        id,
    )
    .expect_err("a released environment's bytes may already be collected")
    .to_string();
    assert!(
        released.contains("environment_released"),
        "refused by name: {released}"
    );

    let unpromoted = resolve_environment(
        &FixedIndex(Some(EnvironmentClaim {
            manifest: claim,
            released: false,
            root_promoted: false,
        })),
        &source,
        id,
    )
    .expect_err("an unpromoted gc root is not bindable")
    .to_string();
    assert!(
        unpromoted.contains("environment_root_unpromoted"),
        "refused by name: {unpromoted}"
    );

    resolve_environment(&FixedIndex(Some(live_claim(claim))), &source, id)
        .expect("a live, promoted row whose bytes recompute to the id resolves");
    drop(rig.dir);
}

// ---------------------------------------------------------------------------
// The composition, up to the container boundary
// ---------------------------------------------------------------------------

/// What the stub driver was asked to run.
struct RecordedRequest {
    attempt_tag: String,
    capsule_id: String,
    environment_label: String,
    environment_closure: Vec<String>,
    network: NetPolicy,
    /// The CAPSULE's declared network arm — distinct from `network`, which is the
    /// namespace posture the request carries (`Offline` for BOTH declared arms:
    /// an `Egress` capsule still runs in the empty namespace, its whole reach
    /// being the hook-handed loopback listener).
    capsule_network: CapsuleNetwork,
    argv: Vec<String>,
}

/// A [`CapsuleDriver`] that RECORDS the request and starts nothing.
struct RecordingDriver {
    recorded: Mutex<Option<RecordedRequest>>,
    /// The attempt root the composition will publish `/out` from. The double creates it
    /// with an empty `out/`, which is what a container that wrote nothing leaves.
    attempt_root: std::path::PathBuf,
}

#[async_trait::async_trait]
impl CapsuleDriver for RecordingDriver {
    async fn drive_capsule(
        &self,
        attempt_tag: &str,
        request: &OciStageRequest<'_>,
        _assign_by: std::time::Instant,
        _cancel: tokio::sync::oneshot::Receiver<String>,
    ) -> Result<OciStageOutput, OciDriveRefusal> {
        *self.recorded.lock().expect("the recording latch") = Some(RecordedRequest {
            attempt_tag: attempt_tag.to_owned(),
            capsule_id: request.capsule.id().0.to_string(),
            environment_label: request.environment.label().to_owned(),
            environment_closure: request
                .environment
                .closure()
                .iter()
                .map(|entry| entry.store_path.as_str().to_owned())
                .collect(),
            network: request.network.clone(),
            capsule_network: request.capsule.network().clone(),
            argv: match request.capsule.process() {
                kata_types::execution_contract::CapsuleProcess::Command { argv } => argv,
                kata_types::execution_contract::CapsuleProcess::Agent(..) => {
                    panic!("the fixture capsule is a Command")
                }
            }
            .iter()
            .map(std::string::ToString::to_string)
            .collect(),
        });
        std::fs::create_dir_all(self.attempt_root.join("out"))
            .expect("the double leaves an empty /out, as a container that wrote nothing does");
        // And an empty `/work`, the same shape: the materializer creates the
        // directory for the mapping whether or not the stage writes into it, so
        // a faithful double leaves one for the delta walk to find.
        std::fs::create_dir_all(self.attempt_root.join("work"))
            .expect("the double leaves an empty /work, as a container that wrote nothing does");
        // v6: the provider SPOOLS captures under `<attempt>/capture` and reports
        // sizes — the double leaves the same two files so `publish_captures`
        // reads real bytes at real lengths, not a claim about them.
        let spool = self.attempt_root.join("capture");
        std::fs::create_dir(&spool).expect("the double leaves an empty capture dir");
        std::fs::write(spool.join("stdout"), b"recorded")
            .expect("the double spools the stdout it reports");
        std::fs::write(spool.join("stderr"), b"").expect("the double spools the stderr it reports");
        Ok(OciStageOutput {
            exit_code: Some(0),
            stdout_bytes: 8,
            stderr_bytes: 0,
            capture_exceeded: false,
            teardown: TeardownOutcome::Confirmed {
                // The authoritative probe, which is what the production driver refuses to
                // proceed without: a double that claimed a weaker one would let the
                // publish follow a teardown the real route would have called ambiguous.
                probe: kata_agent::resource_bounds::TeardownProbe::CgroupPopulation,
                elapsed_ms: 0,
            },
            // OWNED, as the production driver hands it: the composition publishes `/out`
            // and then removes the tree through this value.
            attempt_root: kata_worker::attempt_root::OwnedAttemptRoot::acquire(&self.attempt_root)
                .expect("the double owns its attempt root"),
            container_id: "recorded-container".into(),
            // A double drives no materialize; the composition tolerates the
            // absent record by hashing every member, which is the slow path
            // the snapshot exists to skip.
            work_snapshot: None,
            // The fixture capsule is `Offline`: no proxy, no record.
            egress: None,
        })
    }

    fn attempt_root(&self, _attempt_tag: &str) -> std::path::PathBuf {
        self.attempt_root.clone()
    }

    fn describe_driver(&self) -> String {
        "a recording double that starts no container".into()
    }
}

/// A [`TreeResolver`] over the one empty tree this fixture maps.
struct OneTree(ArtifactId);

impl TreeResolver for OneTree {
    fn tree_manifest(&self, artifact: ArtifactId) -> kata_types::KataResult<TreeManifest> {
        assert_eq!(artifact, self.0, "the fixture maps exactly one artifact");
        TreeManifest::new(Vec::new())
    }

    fn tree_reference(
        &self,
        artifact: ArtifactId,
    ) -> kata_types::KataResult<kata_types::execution_contract::ArtifactRef> {
        assert_eq!(artifact, self.0, "the fixture maps exactly one artifact");
        let bytes = TreeManifest::new(Vec::new())
            .and_then(|manifest| manifest.manifest_bytes())
            .expect("the empty manifest encodes");
        Ok(kata_types::execution_contract::ArtifactRef::new(
            kata_types::cache::object_id_for_canonical_bytes(&bytes),
            bytes.len() as u64,
            // `empty_tree` mints this fixture's artifact as Public — the ref it
            // answers must be the one that reproduces the id.
            ArtifactPrivacy::Public,
        ))
    }
}

/// The WHOLE composition up to the container: the frame is resolved, the environment is
/// resolved from the CAPSULE's id through the plane, the closure is checked, and the driver
/// is handed a request naming all three. Asserted from the driver's own recording.
#[tokio::test]
async fn the_composition_hands_the_driver_the_capsule_and_the_resolved_environment() {
    let rig = rig();
    let tree = empty_tree(&rig);
    let manifest = manifest_with("worker-context-fixture", PRESENT);
    let (environment, claim) = publish_manifest(&rig, &manifest);
    let occurrence = OccurrenceId(FixedBytes([11u8; 32]));
    let capsule = capsule_for(occurrence, environment, tree);
    let frame = frame_for(publish_capsule(&rig, &capsule), occurrence);

    let source = rig.reader();
    let driver = RecordingDriver {
        recorded: Mutex::new(None),
        attempt_root: rig.dir.path().join("attempt"),
    };
    let reported = {
        let sink = CasBlobSink(&rig.cas);
        execute_capsule_frame(
            &CapsuleExecution {
                driver: &driver,
                environments: &FixedIndex(Some(live_claim(claim))),
                trees: &OneTree(tree),
                source: &source,
                probe: &FixedProbe(true),
                sink: &sink,
                adapters: &*AGENT_ADAPTERS,
                credentials: &AMBIENT_CREDENTIALS,
            },
            &frame,
            std::time::Instant::now(),
            tokio::sync::oneshot::channel().1,
            None,
        )
        .await
        .expect("the composition runs to a reported frame")
    };

    // -- THE REQUEST, from the double's own recording -------------------------
    let recorded = driver
        .recorded
        .lock()
        .expect("the recording latch")
        .take()
        .expect("the driver was asked to run something");
    assert_eq!(
        recorded.attempt_tag,
        frame.attempt_id.to_string(),
        "the attempt root is named by the ATTEMPT id, so a host observer finds an attempt's \
         bytes under the name the durable row spells"
    );
    assert_eq!(
        recorded.capsule_id,
        capsule.id().0.to_string(),
        "the driver runs the capsule the frame named, resolved from the store"
    );
    assert_eq!(
        recorded.environment_label, "worker-context-fixture",
        "and the environment RESOLVED from the capsule's own id — not one handed in beside it"
    );
    assert_eq!(
        recorded.environment_closure,
        vec![PRESENT.to_string()],
        "with the closure the manifest's bytes carry"
    );
    assert!(
        matches!(recorded.network, NetPolicy::Offline),
        "the one posture this route admits"
    );
    assert_eq!(
        recorded.argv,
        vec![
            "sh".to_string(),
            "-c".to_string(),
            "echo context".to_string()
        ],
        "and the argv the capsule's id folds"
    );

    // -- THE REPORTED FRAME --------------------------------------------------
    let WorkerMessage::CompletedCapsule {
        attempt_id,
        fence,
        result,
        work_delta,
        exit_code,
        provenance,
        agent,
        ..
    } = reported
    else {
        panic!("a capsule execution reports the capsule terminal and nothing else");
    };
    assert_eq!(attempt_id, frame.attempt_id);
    assert!(
        work_delta.is_some(),
        "a capsule that maps /work reports the delta — here the EMPTY delta over the unchanged \
         fixture tree, which is a different answer from `None`"
    );
    assert_eq!(
        fence.lease_epoch, frame.lease_epoch,
        "the epoch is ECHOED off the frame the main stamped, never minted here"
    );
    assert!(
        agent.is_none(),
        "a Command capsule's completed frame carries NO agent report — the band is the Agent \
         turn's alone"
    );
    assert_eq!(fence.worker_id.as_str(), "worker-context-1");
    assert_eq!(exit_code, Some(0));
    assert_eq!(provenance.label(), "local_oci_runtime");
    // Read off the FILESYSTEM: once `/out` is an artifact, the attempt root — the
    // materialized `/work`, the bundle, the runtime state — is gone.
    assert!(
        !rig.dir.path().join("attempt").exists(),
        "a published attempt's root must be removed, or every successful stage leaks its tree"
    );
    assert_eq!(
        result.privacy(),
        ArtifactPrivacy::Public,
        "an EMPTY result tree is the one public result: identical on every node, with no \
         content to protect"
    );
    drop(rig.dir);
}

/// A closure entry this host does not have is refused by name, BEFORE the driver is asked
/// for anything — asserted by the double having recorded nothing.
#[tokio::test]
async fn a_closure_entry_this_host_lacks_is_refused_before_the_driver_is_asked() {
    let rig = rig();
    let tree = empty_tree(&rig);
    let manifest = manifest_with("worker-context-fixture", ABSENT);
    let (environment, claim) = publish_manifest(&rig, &manifest);
    let occurrence = OccurrenceId(FixedBytes([13u8; 32]));
    let capsule = capsule_for(occurrence, environment, tree);
    let frame = frame_for(publish_capsule(&rig, &capsule), occurrence);

    let source = rig.reader();
    let driver = RecordingDriver {
        recorded: Mutex::new(None),
        attempt_root: rig.dir.path().join("attempt"),
    };
    let sink = CasBlobSink(&rig.cas);
    let refusal = execute_capsule_frame(
        &CapsuleExecution {
            driver: &driver,
            environments: &FixedIndex(Some(live_claim(claim))),
            trees: &OneTree(tree),
            source: &source,
            // The host does NOT have this closure entry, which is the fact under test.
            probe: &FixedProbe(false),
            sink: &sink,
            adapters: &*AGENT_ADAPTERS,
            credentials: &AMBIENT_CREDENTIALS,
        },
        &frame,
        std::time::Instant::now(),
        tokio::sync::oneshot::channel().1,
        None,
    )
    .await
    .expect_err("a closure this host cannot bind is not runnable");
    assert!(
        refusal.reason.contains("environment_closure_incomplete"),
        "refused by name: {}",
        refusal.reason
    );
    assert!(
        refusal.reason.contains(ABSENT),
        "and the refusal names the absent path: {}",
        refusal.reason
    );
    assert_eq!(
        refusal.performed,
        kata_types::effect::DeliveryFailureProvenance::ProvenNotPerformed,
        "a refusal before the container is an OBSERVATION that nothing ran, and the main's \
         settlement of the attempt turns on exactly that"
    );
    assert!(
        driver
            .recorded
            .lock()
            .expect("the recording latch")
            .is_none(),
        "the driver must not have been asked: a closure this host cannot bind is refused \
         BEFORE a container is planned"
    );
    drop(rig.dir);
}

/// The fixture registry every `CapsuleExecution` carries — the production
/// kind→adapter map, so the fixture's dispatch sees what the route sees.
static AGENT_ADAPTERS: std::sync::LazyLock<
    kata_agent::adapter::capsule_registry::StaticAgentAdapterRegistry,
> = std::sync::LazyLock::new(kata_worker::adapter_registry::production);

static AMBIENT_CREDENTIALS: std::sync::LazyLock<
    kata_worker::agent_credential::AgentCredentialSource,
> = std::sync::LazyLock::new(kata_worker::agent_credential::AgentCredentialSource::ambient);

/// A [`CapsuleDriver`] that refuses with a chosen [`OciDriveRefusal`] and starts nothing.
struct RefusingDriver(fn() -> OciDriveRefusal);

#[async_trait::async_trait]
impl CapsuleDriver for RefusingDriver {
    async fn drive_capsule(
        &self,
        _attempt_tag: &str,
        _request: &OciStageRequest<'_>,
        _assign_by: std::time::Instant,
        _cancel: tokio::sync::oneshot::Receiver<String>,
    ) -> Result<OciStageOutput, OciDriveRefusal> {
        Err((self.0)())
    }

    fn attempt_root(&self, _attempt_tag: &str) -> std::path::PathBuf {
        std::path::PathBuf::new()
    }

    fn describe_driver(&self) -> String {
        "a double that refuses and starts no container".into()
    }
}

/// A DRIVE refusal's reported verdict is drawn on whether the refusing step precedes the
/// provider's assignment: a MATERIALIZATION refusal or a provider LAUNCH refusal (nothing
/// was handed to the provider) reports PROVEN NOT PERFORMED; a refusal from the running
/// stage, or a root another drive of the same attempt holds, reports PROVEN AMBIGUOUS.
/// Which arm the production driver returns before the assignment is
/// `oci_driver_refusals.rs`'s, read off the filesystem.
///
/// The charge follows the verdict: a refusal that proves nothing ran states none (the
/// main records the authoritative `0`), and an ambiguous one of this SHELL capsule is
/// charged the authoritative `0` explicitly — a `Command` makes no billable call, the
/// rule the main settles a lost shell attempt by.
///
/// **Would red if:** every drive refusal were reported ambiguous again (the first case),
/// a launch or handshake refusal were (the second), the classification ruled a
/// container out for an arm at or after the assignment, or an ambiguous shell refusal
/// were left uncharged for the worker loop to fill with an `Unavailable` naming nothing.
#[tokio::test]
async fn a_drive_refusal_reports_not_performed_only_when_no_container_was_assigned() {
    let cases: [(
        fn() -> OciDriveRefusal,
        kata_types::effect::DeliveryFailureProvenance,
    ); 4] = [
        (
            || {
                OciDriveRefusal::MaterializationRefused(kata_types::KataError::Validation(
                    "a /work member is unreadable".into(),
                ))
            },
            kata_types::effect::DeliveryFailureProvenance::ProvenNotPerformed,
        ),
        (
            || {
                OciDriveRefusal::ProviderLaunchRefused(kata_types::KataError::Protocol(
                    "the provider was refused at the handshake".into(),
                ))
            },
            kata_types::effect::DeliveryFailureProvenance::ProvenNotPerformed,
        ),
        (
            || OciDriveRefusal::ProviderRefusedStage("the provider stopped answering".into()),
            kata_types::effect::DeliveryFailureProvenance::ProvenAmbiguous,
        ),
        (
            || OciDriveRefusal::AttemptRootUnavailable("held by another live drive".into()),
            kata_types::effect::DeliveryFailureProvenance::ProvenAmbiguous,
        ),
    ];
    for (index, (refusal, expected)) in cases.into_iter().enumerate() {
        let rig = rig();
        let tree = empty_tree(&rig);
        let manifest = manifest_with("worker-context-fixture", PRESENT);
        let (environment, claim) = publish_manifest(&rig, &manifest);
        let occurrence = OccurrenceId(FixedBytes([0x40 + u8::try_from(index).unwrap(); 32]));
        let capsule = capsule_for(occurrence, environment, tree);
        let frame = frame_for(publish_capsule(&rig, &capsule), occurrence);
        let source = rig.reader();
        let sink = CasBlobSink(&rig.cas);
        let reported = execute_capsule_frame(
            &CapsuleExecution {
                driver: &RefusingDriver(refusal),
                environments: &FixedIndex(Some(live_claim(claim))),
                trees: &OneTree(tree),
                source: &source,
                probe: &FixedProbe(true),
                sink: &sink,
                adapters: &*AGENT_ADAPTERS,
                credentials: &AMBIENT_CREDENTIALS,
            },
            &frame,
            std::time::Instant::now(),
            tokio::sync::oneshot::channel().1,
            None,
        )
        .await
        .expect_err("the driver refused");
        assert_eq!(
            reported.performed, expected,
            "{}: the verdict follows the refusing step",
            reported.reason
        );
        let charged = (expected == kata_types::effect::DeliveryFailureProvenance::ProvenAmbiguous)
            .then(kata_types::metering::StageUsage::unbilled);
        assert_eq!(
            reported.usage.as_deref(),
            charged.as_ref(),
            "{}: a shell capsule's charge is the authoritative 0, stated when it may have run",
            reported.reason
        );
        drop(rig.dir);
    }
}

/// A registry that carries no adapter: every kind answers `None`.
struct NoAdapters;

impl kata_agent::adapter::capsule_registry::AgentAdapterRegistry for NoAdapters {
    fn adapter(
        &self,
        _kind: AdapterKind,
    ) -> Option<std::sync::Arc<dyn kata_agent::adapter::AgentAdapter>> {
        None
    }
}

/// **A capsule declaring an adapter this worker cannot answer is refused by
/// name before the container — and nothing on disk shows the attempt ran.**
/// An `AdapterKind` with no registry entry (here: a worker whose registry
/// carries no adapter at all) is a capsule this worker cannot open a session
/// for; the worker-side name is `adapter_unavailable`. The
/// `Egress` arm is NOT here — it runs; the next cell drives it.
///
/// **Would red if:** `execute_capsule_frame` reached the driver with an
/// un-runnable arm (the recording double would carry a request), classified the
/// refusal `ProvenAmbiguous` (the main would wait on a sweep that never comes),
/// or left an attempt root behind (the filesystem assert).
#[tokio::test]
async fn an_adapter_the_worker_has_no_driver_for_refuses_by_name_before_the_container() {
    let rig = rig();
    let tree = empty_tree(&rig);
    let manifest = manifest_with("worker-context-fixture", PRESENT);
    let (environment, claim) = publish_manifest(&rig, &manifest);
    let occurrence = OccurrenceId(FixedBytes([0x50; 32]));
    let capsule = capsule_shaped(
        occurrence,
        environment,
        tree,
        CapsuleProcess::Agent(AgentTurnSpec {
            // A qualified kind, served by a registry that carries no adapter.
            adapter: AdapterKind::NanocodeOpenai,
            model: Some("vendor/small".into()),
            reasoning_effort: None,
            output_schema: None,
            prompt: ArtifactId(FixedBytes([0x66; 32])),
            credential: None,
            env: std::collections::BTreeMap::new(),
        }),
        CapsuleNetwork::Offline,
    );
    let frame = frame_for(publish_capsule(&rig, &capsule), occurrence);
    let attempt_root = rig.dir.path().join("attempt");
    let source = rig.reader();
    let driver = RecordingDriver {
        recorded: Mutex::new(None),
        attempt_root: attempt_root.clone(),
    };
    let sink = CasBlobSink(&rig.cas);
    let refusal = execute_capsule_frame(
        &CapsuleExecution {
            driver: &driver,
            environments: &FixedIndex(Some(live_claim(claim))),
            trees: &OneTree(tree),
            source: &source,
            probe: &FixedProbe(true),
            sink: &sink,
            adapters: &NoAdapters,
            credentials: &AMBIENT_CREDENTIALS,
        },
        &frame,
        std::time::Instant::now(),
        tokio::sync::oneshot::channel().1,
        None,
    )
    .await
    .expect_err("a capsule declaring an adapter this worker cannot answer is refused");
    assert!(
        refusal.reason.contains("adapter_unavailable"),
        "the refusal is BY NAME so an operator meets it on purpose: {}",
        refusal.reason
    );
    assert_eq!(
        refusal.performed,
        kata_types::effect::DeliveryFailureProvenance::ProvenNotPerformed,
        "the refusal is an observation that nothing ran: {}",
        refusal.reason
    );
    assert!(
        driver.recorded.lock().unwrap().is_none(),
        "the driver was never asked to run the turn"
    );
    assert!(
        !attempt_root.exists(),
        "no attempt root on disk for the refused arm: {}",
        attempt_root.display()
    );
}

/// The `env:` variable the nanocode cell's own credential source holds.
const FIXTURE_KEY_VAR: &str = "NANOCODE_FIXTURE_KEY";

/// **The production worker serves both nanocode kinds: a nanocode capsule
/// reaches its interactive launch.** The production registry carries the embedded
/// harness's adapter for each kind, so a capsule naming one passes the adapter
/// lookup (never `adapter_unavailable`) and the worker asks the driver to
/// launch its toolhost init; this fixture's driver cannot launch an interactive capsule and
/// says so, which is the witness that the launch was asked for. No container
/// ran: the refusal is proven-not-performed and the driver ran no command.
///
/// **Would red if:** the production registry did not serve a nanocode kind
/// (the worker refuses `adapter_unavailable` before the launch).
#[tokio::test]
async fn a_nanocode_capsule_reaches_its_interactive_launch_through_the_production_worker() {
    for adapter in [AdapterKind::NanocodeOpenai, AdapterKind::NanocodeAnthropic] {
        let rig = rig();
        let tree = empty_tree(&rig);
        let manifest = manifest_with("worker-context-fixture", PRESENT);
        let (environment, claim) = publish_manifest(&rig, &manifest);
        let occurrence = OccurrenceId(FixedBytes([0x51; 32]));
        let capsule = capsule_shaped(
            occurrence,
            environment,
            tree,
            CapsuleProcess::Agent(AgentTurnSpec {
                adapter,
                model: Some("vendor/small".into()),
                reasoning_effort: None,
                output_schema: None,
                // A prompt the fixture resolves, so the served kind reaches
                // the driver rather than the fixture's assert.
                prompt: tree,
                // The harness's credential (an `env:` key of the cell's own
                // source): a nanocode turn naming none is refused
                // `credential_undeclared` before the launch.
                credential: Some(kata_types::execution_contract::TurnCredentialRef {
                    mode: kata_types::metering::CredentialMode::ApiKey,
                    source: kata_types::execution_contract::CredentialSource::EnvVar {
                        var: FIXTURE_KEY_VAR.into(),
                    },
                }),
                env: std::collections::BTreeMap::new(),
            }),
            CapsuleNetwork::Offline,
        );
        let frame = frame_for(publish_capsule(&rig, &capsule), occurrence);
        let attempt_root = rig.dir.path().join("attempt");
        let source = rig.reader();
        let driver = RecordingDriver {
            recorded: Mutex::new(None),
            attempt_root: attempt_root.clone(),
        };
        let sink = CasBlobSink(&rig.cas);
        let credentials = kata_worker::agent_credential::AgentCredentialSource::for_test(
            std::collections::BTreeMap::from([(
                FIXTURE_KEY_VAR.to_owned(),
                "fixture-key".to_owned(),
            )]),
        );
        let refusal = execute_capsule_frame(
            &CapsuleExecution {
                driver: &driver,
                environments: &FixedIndex(Some(live_claim(claim))),
                trees: &OneTree(tree),
                source: &source,
                probe: &FixedProbe(true),
                sink: &sink,
                adapters: &*AGENT_ADAPTERS,
                credentials: &credentials,
            },
            &frame,
            std::time::Instant::now(),
            tokio::sync::oneshot::channel().1,
            None,
        )
        .await
        .expect_err("this fixture's driver launches no interactive capsule");
        assert!(
            refusal
                .reason
                .contains("this driver cannot launch an interactive capsule")
                && !refusal.reason.contains("adapter_unavailable"),
            "{}: the worker asked the driver to launch the kind's init: {}",
            adapter.as_label(),
            refusal.reason
        );
        assert_eq!(
            refusal.performed,
            kata_types::effect::DeliveryFailureProvenance::ProvenNotPerformed,
            "{}: {}",
            adapter.as_label(),
            refusal.reason
        );
        assert!(
            driver.recorded.lock().unwrap().is_none(),
            "{}: the driver ran no command",
            adapter.as_label()
        );
        assert!(
            !attempt_root.exists(),
            "{}: no attempt root",
            adapter.as_label()
        );
    }
}

/// **The `Egress` arm REACHES the driver, declared allowlist intact, under the
/// namespace posture both arms share.**
///
/// The mechanism is `crate::egress_handoff` + `crate::egress_proxy`. What this cell
/// pins at the composition boundary is what the driver is handed: the CAPSULE still declares
/// `Egress { allowlist }` (the driver reads it to build the hook inputs, the
/// plumbing env and the proxy's allowlist), while the REQUEST's `network` is
/// `NetPolicy::Offline` — the namespace posture, which is empty-namespace for
/// both declared arms because the guest's only reach is the listener the
/// `createContainer` hook hands the worker.
///
/// **Would red if:** the composition refused the arm, rewrote the declared network
/// before the driver saw it (the recorded request would carry the wrong arm), or
/// handed the driver a non-`Offline`
/// namespace posture (the bundle's `spec_for` would then plan a namespace this
/// route does not have).
#[tokio::test]
async fn the_v8_egress_arm_reaches_the_driver_with_its_declaration_intact() {
    let rig = rig();
    let tree = empty_tree(&rig);
    let manifest = manifest_with("worker-context-fixture", PRESENT);
    let (environment, claim) = publish_manifest(&rig, &manifest);
    let occurrence = OccurrenceId(FixedBytes([0x51; 32]));
    let allowlist = [EgressAuthority::new("api.vendor.test", 443).unwrap()]
        .into_iter()
        .collect();
    let capsule = capsule_shaped(
        occurrence,
        environment,
        tree,
        CapsuleProcess::Command {
            argv: vec!["sh".into(), "-c".into(), "echo context".into()],
        },
        CapsuleNetwork::Egress { allowlist },
    );
    let frame = frame_for(publish_capsule(&rig, &capsule), occurrence);
    let attempt_root = rig.dir.path().join("attempt");
    let source = rig.reader();
    let driver = RecordingDriver {
        recorded: Mutex::new(None),
        attempt_root: attempt_root.clone(),
    };
    let sink = CasBlobSink(&rig.cas);
    let reported = execute_capsule_frame(
        &CapsuleExecution {
            driver: &driver,
            environments: &FixedIndex(Some(live_claim(claim))),
            trees: &OneTree(tree),
            source: &source,
            probe: &FixedProbe(true),
            sink: &sink,
            adapters: &*AGENT_ADAPTERS,
            credentials: &AMBIENT_CREDENTIALS,
        },
        &frame,
        std::time::Instant::now(),
        tokio::sync::oneshot::channel().1,
        None,
    )
    .await
    .expect("the egress arm runs on this route now");

    let recorded = driver
        .recorded
        .lock()
        .expect("the recording latch")
        .as_ref()
        .expect("the driver was asked")
        .capsule_network
        .clone();
    match recorded {
        CapsuleNetwork::Egress { allowlist } => {
            assert!(
                allowlist
                    .iter()
                    .any(|a| a.host() == "api.vendor.test" && a.port() == 443),
                "the capsule's declared allowlist reached the driver intact: {allowlist:?}"
            );
        }
        CapsuleNetwork::Offline => {
            panic!(
                "the driver's capsule still declares Egress — an Offline arrival means the \
                    composition rewrote the declaration"
            )
        }
    }
    let network = driver
        .recorded
        .lock()
        .expect("the recording latch")
        .as_ref()
        .expect("the driver was asked")
        .network
        .clone();
    assert!(
        matches!(network, NetPolicy::Offline),
        "the namespace posture is Offline for an Egress capsule — its only reach is the \
         hook-handed loopback listener: {network:?}"
    );
    let WorkerMessage::CompletedCapsule {
        egress_refusals, ..
    } = &reported
    else {
        panic!("a capsule that ran reports a completion: {reported:?}")
    };
    assert!(
        egress_refusals.is_empty(),
        "the recording double produced no proxy record, so the completion carries none: \
         {egress_refusals:?}"
    );
    drop(rig.dir);
}

/// A [`CapsuleDriver`] that RECORDS the `assign_by` it was handed, then refuses.
struct AssignByDriver(Mutex<Option<std::time::Instant>>);

#[async_trait::async_trait]
impl CapsuleDriver for AssignByDriver {
    async fn drive_capsule(
        &self,
        _attempt_tag: &str,
        _request: &OciStageRequest<'_>,
        assign_by: std::time::Instant,
        _cancel: tokio::sync::oneshot::Receiver<String>,
    ) -> Result<OciStageOutput, OciDriveRefusal> {
        *self.0.lock().unwrap() = Some(assign_by);
        Err(OciDriveRefusal::PlanRefused(
            kata_types::KataError::Validation("recorded the prepare deadline (rig)".into()),
        ))
    }

    fn attempt_root(&self, _attempt_tag: &str) -> std::path::PathBuf {
        std::path::PathBuf::new()
    }

    fn describe_driver(&self) -> String {
        "a double that records its prepare deadline and starts no container".into()
    }
}

/// The PREPARE BUDGET is measured from the start anchor the worker loop took BEFORE it
/// sent the start checkpoint (`execute_capsule_frame`'s `started`), not from the moment
/// the composition reaches the driver: `assign_by` is exactly `started` plus
/// `CAPSULE_PREPARE_BUDGET`. That anchor is what the main's wall-time grace is derived
/// against (`kata_types::capsule_timing`); a deadline taken at the drive would let the
/// resolution and verification before it go unbounded. The anchor here is five seconds in
/// the past, so the two readings differ by that much.
///
/// **Would red if:** the composition measured the budget from the drive (the recorded
/// deadline would be five seconds later).
#[tokio::test]
async fn the_prepare_budget_runs_from_the_workers_start_anchor() {
    let rig = rig();
    let tree = empty_tree(&rig);
    let manifest = manifest_with("worker-context-fixture", PRESENT);
    let (environment, claim) = publish_manifest(&rig, &manifest);
    let occurrence = OccurrenceId(FixedBytes([0x7A; 32]));
    let capsule = capsule_for(occurrence, environment, tree);
    let frame = frame_for(publish_capsule(&rig, &capsule), occurrence);
    let source = rig.reader();
    let sink = CasBlobSink(&rig.cas);
    let driver = AssignByDriver(Mutex::new(None));
    let started = std::time::Instant::now()
        .checked_sub(std::time::Duration::from_secs(5))
        .expect("the monotonic clock is at least five seconds old");
    execute_capsule_frame(
        &CapsuleExecution {
            driver: &driver,
            environments: &FixedIndex(Some(live_claim(claim))),
            trees: &OneTree(tree),
            source: &source,
            probe: &FixedProbe(true),
            sink: &sink,
            adapters: &*AGENT_ADAPTERS,
            credentials: &AMBIENT_CREDENTIALS,
        },
        &frame,
        started,
        tokio::sync::oneshot::channel().1,
        None,
    )
    .await
    .expect_err("the double refuses");
    let assign_by = driver.0.lock().unwrap().expect("the driver was asked");
    assert_eq!(
        assign_by.duration_since(started),
        kata_worker::oci_driver::CAPSULE_PREPARE_BUDGET,
        "the prepare deadline is the start anchor plus the budget"
    );
    drop(rig.dir);
}

/// A `BlobSink` that refuses every publish, to prove the result path is reached through the
/// sink and not around it.
struct RefusingSink;

impl BlobSink for RefusingSink {
    fn publish(
        &self,
        _bytes: &[u8],
    ) -> kata_types::KataResult<kata_core::store::cas::DurableObject> {
        Err(kata_types::KataError::Storage("the sink refuses".into()))
    }
}

/// The result is published THROUGH the sink: a refusing sink makes the attempt fail, which
/// is what proves no other writer is reaching the store.
#[tokio::test]
async fn the_result_is_published_through_the_sink_and_nowhere_else() {
    let rig = rig();
    let tree = empty_tree(&rig);
    let manifest = manifest_with("worker-context-fixture", PRESENT);
    let (environment, claim) = publish_manifest(&rig, &manifest);
    let occurrence = OccurrenceId(FixedBytes([17u8; 32]));
    let capsule = capsule_for(occurrence, environment, tree);
    let frame = frame_for(publish_capsule(&rig, &capsule), occurrence);
    let source = rig.reader();
    let driver = RecordingDriver {
        recorded: Mutex::new(None),
        attempt_root: rig.dir.path().join("attempt"),
    };
    let error = execute_capsule_frame(
        &CapsuleExecution {
            driver: &driver,
            environments: &FixedIndex(Some(live_claim(claim))),
            trees: &OneTree(tree),
            source: &source,
            probe: &FixedProbe(true),
            sink: &RefusingSink,
            adapters: &*AGENT_ADAPTERS,
            credentials: &AMBIENT_CREDENTIALS,
        },
        &frame,
        std::time::Instant::now(),
        tokio::sync::oneshot::channel().1,
        None,
    )
    .await
    .expect_err("a sink that refuses is an attempt with no result");
    assert!(
        error.reason.contains("the sink refuses"),
        "the sink's own refusal reaches the caller rather than being swallowed: {}",
        error.reason
    );
    assert_eq!(
        error.performed,
        kata_types::effect::DeliveryFailureProvenance::ProvenAmbiguous,
        "the container HAD run, so a worker that reported `not performed` here would be the \
         false negative that would let the work be run again"
    );
    assert!(
        driver
            .recorded
            .lock()
            .expect("the recording latch")
            .is_some(),
        "and it happened AFTER the container: the publish follows a confirmed teardown"
    );
    assert!(
        !rig.dir.path().join("attempt").exists(),
        "a refused publish after a CONFIRMED teardown leaves nothing anyone reads, so the root \
         is removed too"
    );
    drop(rig.dir);
}

/// The WORKER-START sweep of attempt roots removes what no live process owns and keeps
/// what one does — read off the filesystem. A root still `flock`ed by a drive (here, one
/// this process holds) is skipped; an unlocked one with no live container is removed; a
/// `teardown_ambiguous` one is listed for `kata doctor` until the sweep proves its
/// container gone and removes it.
#[test]
fn the_worker_start_sweep_removes_only_unowned_attempt_roots() {
    use kata_worker::attempt_root::{
        OwnedAttemptRoot, attempts_directory, retained_attempt_roots, sweep_attempt_roots,
    };
    let worker_state = tempfile::tempdir().expect("a worker state directory");
    let attempts = attempts_directory(worker_state.path());

    let live = OwnedAttemptRoot::acquire(&attempts.join("live")).expect("a live drive's root");
    std::fs::create_dir_all(live.join("work")).expect("its /work");
    // A crashed drive: the tree survives, the lock died with its process — and
    // so does its capture SPOOL (v6's `<attempt>/capture/{stdout,stderr}`), the
    // directory the provider was writing when the process died. Sweeping the
    // root must take the spool with it; a partial sweep that left `capture/`
    // behind would be a leak the crash window defines away.
    let crashed = attempts.join("crashed");
    std::fs::create_dir_all(crashed.join("oci/kata-no-such-container/bundle"))
        .expect("a crashed drive's bundle");
    std::fs::create_dir_all(crashed.join("capture")).expect("a crashed drive's spool directory");
    std::fs::write(crashed.join("capture/stdout"), b"partial")
        .expect("a spool file the crash left mid-write");
    OwnedAttemptRoot::acquire(&attempts.join("ambiguous"))
        .expect("an ambiguous drive's root")
        .retain_ambiguous("ambiguous", "Ambiguous { .. }");

    assert!(
        OwnedAttemptRoot::acquire(live.path()).is_err(),
        "a second owner of a live attempt root is refused, never shared"
    );
    let listed = retained_attempt_roots(worker_state.path()).expect("readable");
    assert_eq!(
        listed.iter().map(|(p, _)| p.clone()).collect::<Vec<_>>(),
        vec![attempts.join("ambiguous")],
        "exactly the marked root is what doctor lists"
    );

    let swept = sweep_attempt_roots(worker_state.path());

    assert!(
        live.path().join("work").is_dir(),
        "the sweep removed a root a live drive holds"
    );
    assert!(
        !crashed.exists() && !attempts.join("ambiguous").exists(),
        "an unowned root with no live container must be removed — spool included, since \
         `capture/` is just another subtree under the attempt root: {swept:?}"
    );
    assert!(swept.retained.is_empty(), "{swept:?}");
    drop(live);
}

/// A removal-failed marker outlives its root only across a crash between the root's
/// removal and the marker's: the worker-start sweep deletes a `<tag>.REMOVAL_FAILED` file
/// in `attempts/` whose root is gone, and leaves every other file there — one whose root
/// is still a directory, and one that is not a marker. Read through `std::fs`.
///
/// **Would red if:** the sweep skipped every non-directory entry, so a crash-window marker
/// stayed in `attempts/` for good.
#[test]
fn the_worker_start_sweep_deletes_a_removal_failed_marker_whose_root_is_gone() {
    use kata_worker::attempt_root::{
        REMOVAL_FAILED_SUFFIX, attempts_directory, retained_attempt_roots, sweep_attempt_roots,
    };
    let worker_state = tempfile::tempdir().expect("a worker state directory");
    let attempts = attempts_directory(worker_state.path());
    std::fs::create_dir_all(&attempts).unwrap();
    let orphan = attempts.join(format!("gone{REMOVAL_FAILED_SUFFIX}"));
    std::fs::write(&orphan, b"EBUSY\n").unwrap();
    let unrelated = attempts.join("notes.txt");
    std::fs::write(&unrelated, b"not a marker\n").unwrap();
    assert!(
        retained_attempt_roots(worker_state.path())
            .expect("readable")
            .is_empty(),
        "a marker with no root lists nothing"
    );

    let _swept = sweep_attempt_roots(worker_state.path());

    assert!(!orphan.exists(), "the orphaned marker is deleted");
    assert!(unrelated.exists(), "a file that is not a marker is left");
}

/// Removing an attempt root that is already gone is silent: `OwnedAttemptRoot::remove`
/// finds `NotFound` and writes no `<tag>.REMOVAL_FAILED` marker beside it, so `kata doctor`
/// never lists a removal that had nothing left to remove. Read through `std::fs`.
///
/// **Would red if:** `remove` treated a vanished root as a failed removal and recorded it.
#[test]
fn removing_a_vanished_attempt_root_writes_no_removal_failed_marker() {
    use kata_worker::attempt_root::{OwnedAttemptRoot, REMOVAL_FAILED_SUFFIX, attempts_directory};
    let worker_state = tempfile::tempdir().expect("a worker state directory");
    let attempts = attempts_directory(worker_state.path());
    let root = attempts.join("vanished");
    let owned = OwnedAttemptRoot::acquire(&root).expect("the root is created and locked");
    std::fs::remove_dir(&root).expect("the empty root is removed out from under its owner");

    owned.remove("vanished", "test");

    let marker = attempts.join(format!("vanished{REMOVAL_FAILED_SUFFIX}"));
    assert!(
        !marker.exists(),
        "a vanished root writes no removal-failed marker"
    );
    let left: Vec<_> = std::fs::read_dir(&attempts)
        .expect("attempts/ is still readable")
        .map(|entry| entry.expect("an entry").file_name())
        .collect();
    assert!(left.is_empty(), "attempts/ holds nothing: {left:?}");
}

/// **A guest that drops its own directories' modes cannot keep its attempt root on the
/// host.** The guest owns every directory under `work/`, `out/` and `git/` through its
/// single-uid mapping, so it can `chmod` any of them, the mount roots included; the
/// worker holds no `CAP_DAC_OVERRIDE`, so an unlink under a `0500` directory, or any read
/// of a `0000` one, fails `EACCES`. Planted here: `work/` itself at `0500`, a nested
/// `0000` directory holding a file, and a `0500` directory under `git/`. Beside them a
/// symlink in `work/` names a HOST directory at `0500`; restoring modes must not follow it.
/// Both removal paths run: `OwnedAttemptRoot::remove` after a publish, and the worker-start
/// sweep over a root a dead drive left. The filesystem is read through `std::fs`.
///
/// **Would red if:** the removal stopped restoring the owner's access before it unlinks,
/// or restored it through a link.
#[test]
fn a_guest_chmod_does_not_keep_the_attempt_root_on_the_host() {
    use std::os::unix::fs::PermissionsExt as _;

    use kata_worker::attempt_root::{OwnedAttemptRoot, attempts_directory, sweep_attempt_roots};
    let worker_state = tempfile::tempdir().expect("a worker state directory");
    let host_dir = worker_state.path().join("host-only");
    std::fs::create_dir(&host_dir).unwrap();
    std::fs::set_permissions(&host_dir, std::fs::Permissions::from_mode(0o500)).unwrap();
    let plant = |root: &std::path::Path| {
        let sealed = root.join("work/d/sealed");
        std::fs::create_dir_all(&sealed).unwrap();
        std::fs::write(sealed.join("f"), b"head bytes\n").unwrap();
        std::os::unix::fs::symlink(&host_dir, root.join("work/link")).unwrap();
        std::fs::create_dir_all(root.join("git/refs/heads")).unwrap();
        std::fs::write(root.join("git/refs/heads/x"), b"0\n").unwrap();
        std::fs::set_permissions(&sealed, std::fs::Permissions::from_mode(0o000)).unwrap();
        std::fs::set_permissions(
            root.join("git/refs"),
            std::fs::Permissions::from_mode(0o500),
        )
        .unwrap();
        std::fs::set_permissions(root.join("work"), std::fs::Permissions::from_mode(0o500))
            .unwrap();
    };
    let attempts = attempts_directory(worker_state.path());

    let published = attempts.join("published");
    let root = OwnedAttemptRoot::acquire(&published).expect("a drive's root");
    plant(root.path());
    root.remove("published", "result_published");
    let after_remove = published.exists();

    let crashed = attempts.join("crashed");
    drop(OwnedAttemptRoot::acquire(&crashed).expect("a crashed drive's root"));
    plant(&crashed);
    let swept = sweep_attempt_roots(worker_state.path());
    let after_sweep = crashed.exists();

    let host_mode = std::fs::metadata(&host_dir).unwrap().permissions().mode() & 0o7777;
    // Let the tempdir delete itself whatever the verdict.
    for root in [&published, &crashed] {
        for dir in [
            root.join("work"),
            root.join("work/d/sealed"),
            root.join("git/refs"),
        ] {
            let _ = std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700));
        }
    }
    std::fs::set_permissions(&host_dir, std::fs::Permissions::from_mode(0o700)).unwrap();

    let mut failures = Vec::new();
    if after_remove {
        failures.push("the published root is still on disk after `remove`".to_owned());
    }
    if after_sweep || swept.removed != vec![crashed] {
        failures.push(format!(
            "the worker-start sweep did not reclaim the crashed root: {swept:?}"
        ));
    }
    if host_mode != 0o500 {
        failures.push(format!(
            "restoring modes followed the guest's link: the host directory is now {host_mode:o}"
        ));
    }
    assert!(failures.is_empty(), "{failures:#?}");
}

/// **No depth of guest-built directory chain keeps its attempt root on the host, or takes
/// the worker down with it.** The guest can nest directories under `work/` as deep as
/// the filesystem allows, so the removal's cost in descriptors and in stack must not
/// grow with that depth. Two chains, each built descriptor-relative (no path is longer
/// than one name), both removed by `OwnedAttemptRoot::remove`:
///
/// * 400 levels with a `0500` directory at the bottom holding a file, removed — and,
///   for a second root a dead drive left, swept — under a soft `RLIMIT_NOFILE` of 64: a
///   walk holding one descriptor per level runs out at the 60-odd level and leaves the
///   root on disk;
/// * 30 000 levels removed on a thread with a 256 KiB stack, under the hard descriptor
///   limit: a walk that recurses once per level overflows it, and Rust aborts the
///   process.
///
/// The filesystem is read through `std::fs`.
///
/// **Would red if:** the removal held a descriptor per level, or recursed per level.
#[test]
fn a_guest_directory_chain_of_any_depth_does_not_keep_the_attempt_root() {
    use kata_worker::attempt_root::{OwnedAttemptRoot, attempts_directory, sweep_attempt_roots};
    let flags = rustix::fs::OFlags::RDONLY
        | rustix::fs::OFlags::DIRECTORY
        | rustix::fs::OFlags::NOFOLLOW
        | rustix::fs::OFlags::CLOEXEC;
    // `depth` levels of `d/` under `<root>/work`, one descriptor at a time; the deepest
    // directory gets a file and `bottom_mode`.
    let chain = |root: &std::path::Path, depth: usize, bottom_mode: u32| {
        std::fs::create_dir_all(root.join("work")).unwrap();
        let mut fd = rustix::fs::open(root.join("work"), flags, rustix::fs::Mode::empty()).unwrap();
        for _ in 0..depth {
            rustix::fs::mkdirat(&fd, "d", rustix::fs::Mode::from_raw_mode(0o755)).unwrap();
            fd = rustix::fs::openat(&fd, "d", flags, rustix::fs::Mode::empty()).unwrap();
        }
        let file = rustix::fs::openat(
            &fd,
            "f",
            rustix::fs::OFlags::WRONLY | rustix::fs::OFlags::CREATE | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::from_raw_mode(0o644),
        )
        .unwrap();
        drop(file);
        rustix::fs::fchmod(&fd, rustix::fs::Mode::from_raw_mode(bottom_mode)).unwrap();
    };
    let worker_state = tempfile::tempdir().expect("a worker state directory");
    let attempts = attempts_directory(worker_state.path());
    let limits = rustix::process::getrlimit(rustix::process::Resource::Nofile);
    let mut failures = Vec::new();

    let published = attempts.join("deep-published");
    let root = OwnedAttemptRoot::acquire(&published).expect("a drive's root");
    chain(root.path(), 400, 0o500);
    let crashed = attempts.join("deep-crashed");
    drop(OwnedAttemptRoot::acquire(&crashed).expect("a crashed drive's root"));
    chain(&crashed, 400, 0o500);
    rustix::process::setrlimit(
        rustix::process::Resource::Nofile,
        rustix::process::Rlimit {
            current: Some(64),
            maximum: limits.maximum,
        },
    )
    .expect("lower the soft descriptor limit");
    root.remove("deep-published", "result_published");
    let swept = sweep_attempt_roots(worker_state.path());
    rustix::process::setrlimit(rustix::process::Resource::Nofile, limits)
        .expect("restore the descriptor limit");
    if published.exists() {
        failures.push("400 levels under 64 descriptors: still on disk after `remove`".to_owned());
    }
    if crashed.exists() || swept.removed != vec![crashed.clone()] {
        failures.push(format!(
            "400 levels under 64 descriptors: the sweep did not reclaim the root: {swept:?}"
        ));
    }

    rustix::process::setrlimit(
        rustix::process::Resource::Nofile,
        rustix::process::Rlimit {
            current: limits.maximum,
            maximum: limits.maximum,
        },
    )
    .expect("raise the soft descriptor limit to the hard one");
    let deepest = attempts.join("deepest");
    let root = OwnedAttemptRoot::acquire(&deepest).expect("a drive's root");
    chain(root.path(), 30_000, 0o755);
    let joined = std::thread::Builder::new()
        .stack_size(256 << 10)
        .spawn(move || root.remove("deepest", "result_published"))
        .expect("a removal thread")
        .join();
    rustix::process::setrlimit(rustix::process::Resource::Nofile, limits)
        .expect("restore the descriptor limit");
    if joined.is_err() || deepest.exists() {
        failures.push(format!(
            "30 000 levels on a 256 KiB stack: joined cleanly = {}, still on disk = {}",
            joined.is_ok(),
            deepest.exists()
        ));
    }
    assert!(failures.is_empty(), "{failures:#?}");
}

/// **No width of guest-built directory keeps a worker removing its attempt root for
/// longer than a cost linear in the entries.** The guest can fill one directory with as
/// many non-empty directories as the filesystem allows; a removal that reads that
/// directory's listing again from its start after emptying each child is quadratic on
/// ext4, which keeps the emptied blocks and walks them again on every read — a stage
/// that pins its worker long after it ended, and again at every worker start's sweep.
///
/// The cell builds `work/` holding 60 000 directories, each named by 248 bytes (longer
/// names spread the same entries over more blocks, so the quadratic form shows sooner)
/// and holding one file, on `target/`'s disk — NOT the suite's tmpfs `TMPDIR`, where
/// reading a listing again skips the removed entries and both forms are linear. It then
/// runs `OwnedAttemptRoot::remove` on a thread and reads that thread's on-CPU time from
/// `/proc/<pid>/task/<tid>/schedstat`, so the bound is the kernel's accounting and holds
/// on a loaded host. Measured on ext4, debug build, a 128-core host at load 100–450: the
/// linear walk takes 0.65 s, 1.35 s and 2.6 s on CPU at 10 000, 20 000 and 40 000 such
/// directories, and 4.0 s at this cell's 60 000; the walk that read its listing again
/// from the start took 4.3 s, 14.8 s and 59 s, and was still running at 40 s on CPU at
/// 60 000. The bound is 45 s on CPU: over ten times the linear walk's measurement, and
/// about a third of the quadratic one's (59 s at 40 000, times 2.25).
///
/// What it cannot see: it refuses only a tmpfs, so on a disk filesystem that skips emptied
/// directory blocks as a tmpfs does it proves the bound without being able to catch the
/// regression — it catches it where emptied blocks persist (ext4, `target/`'s filesystem
/// on the reference host). Its tree is two levels deep, so `work/`'s listing is never
/// closed: the other half of the linear walk — a CLOSED listing reopened at the emptied
/// child's cookie — is pinned structurally, on any filesystem, by the unit cell
/// `attempt_root::tests::a_reopened_listing_goes_on_at_the_emptied_childs_cookie`.
///
/// **Would red if:** the removal read a directory's OPEN listing again from its start
/// after each child it emptied.
#[test]
fn a_wide_guest_directory_is_removed_in_time_linear_in_its_entries() {
    use std::time::Duration;

    use kata_worker::attempt_root::{OwnedAttemptRoot, attempts_directory};
    const WIDTH: usize = 60_000;
    const BOUND: Duration = Duration::from_secs(45);
    const TMPFS_MAGIC: i64 = 0x0102_1994;
    fn on_cpu(task: &std::path::Path) -> Option<Duration> {
        let text = std::fs::read_to_string(task.join("schedstat")).ok()?;
        let nanos = text.split_whitespace().next()?.parse().ok()?;
        Some(Duration::from_nanos(nanos))
    }

    let disk = tempfile::tempdir_in(env!("CARGO_TARGET_TMPDIR")).expect("a directory on disk");
    let filesystem = rustix::fs::statfs(disk.path()).expect("statfs").f_type;
    assert_ne!(
        filesystem, TMPFS_MAGIC,
        "target/ is on a tmpfs, where this cell cannot tell a quadratic removal from a linear one"
    );
    let path = attempts_directory(disk.path()).join("wide");
    let root = OwnedAttemptRoot::acquire(&path).expect("a drive's root");
    std::fs::create_dir(path.join("work")).unwrap();
    let flags = rustix::fs::OFlags::RDONLY
        | rustix::fs::OFlags::DIRECTORY
        | rustix::fs::OFlags::NOFOLLOW
        | rustix::fs::OFlags::CLOEXEC;
    let work = rustix::fs::open(path.join("work"), flags, rustix::fs::Mode::empty()).unwrap();
    let padding = "x".repeat(240);
    for n in 0..WIDTH {
        let name = format!("{n:08}{padding}");
        rustix::fs::mkdirat(&work, name.as_str(), rustix::fs::Mode::from_raw_mode(0o755)).unwrap();
        let child =
            rustix::fs::openat(&work, name.as_str(), flags, rustix::fs::Mode::empty()).unwrap();
        drop(
            rustix::fs::openat(
                &child,
                "f",
                rustix::fs::OFlags::WRONLY
                    | rustix::fs::OFlags::CREATE
                    | rustix::fs::OFlags::CLOEXEC,
                rustix::fs::Mode::from_raw_mode(0o644),
            )
            .unwrap(),
        );
    }
    drop(work);

    let (sender, receiver) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let task = std::path::Path::new("/proc")
            .join(std::fs::read_link("/proc/thread-self").expect("this thread's /proc entry"));
        let before = on_cpu(&task).expect("this thread's schedstat");
        let _ = sender.send(Ok(task.clone()));
        root.remove("wide", "result_published");
        if let Some(after) = on_cpu(&task) {
            let _ = sender.send(Err(after.saturating_sub(before)));
        }
    });
    let Ok(task) = receiver.recv().expect("the removal thread's task") else {
        unreachable!("the removal thread names its task first");
    };
    let start = on_cpu(&task).expect("the removal thread's schedstat");
    let spent = loop {
        match receiver.recv_timeout(Duration::from_millis(100)) {
            Ok(Err(spent)) => break spent,
            Ok(Ok(_)) => unreachable!("the removal thread names its task once"),
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                if let Some(now) = on_cpu(&task)
                    && now.saturating_sub(start) > BOUND
                {
                    panic!(
                        "{WIDTH} non-empty directories: the removal is still running after \
                         {BOUND:?} on CPU"
                    );
                }
            }
            Err(error) => panic!("the removal thread ended without a verdict: {error}"),
        }
    };
    eprintln!("{WIDTH} non-empty directories removed in {spent:?} on CPU");
    assert!(
        !path.exists() && spent <= BOUND,
        "{WIDTH} non-empty directories: removed = {}, {spent:?} on CPU (bound {BOUND:?})",
        !path.exists()
    );
}
