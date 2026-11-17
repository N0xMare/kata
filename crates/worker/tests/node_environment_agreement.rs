//! The worker's plane index and the environment DECLARER agree on an
//! environment's identity, and the standalone daemon's capsule route names the main's
//! planes or refuses to start.
//!
//! # Why the agreement is a cell
//!
//! An `EnvironmentId` folds the manifest's RAW CAS address, while an artifact id folds
//! `(object, size, privacy)` (see `kata_types::execution_contract::ArtifactId`'s docs).
//! The worker's `LocalPlaneIndex` once recomputed the environment id through the
//! artifact fold and refused a correct row; only a live run caught it. This cell
//! declares through the PRODUCTION declarer over a real nix (a disposable local store)
//! and resolves through the PRODUCTION reader, on the same data directory a worker
//! opens read-only — so a second spelling of the derivation on either side goes red here
//! rather than on a host with a container.

use kata_core::OperationalDb;
use kata_core::environment::nix as nix_cli;
use kata_core::environment::{NixStore, bind_node_environment};
use kata_core::store::cas::CasStore;
use kata_types::config::NodeEnvironmentConfig;
use kata_types::execution_contract::{ArtifactPrivacy, ArtifactRef};
use kata_types::nix_environment::{IntegrityPolicy, NarVerification};
use kata_worker::capsule_route::{CapsuleRoute, WORKER_MAIN_DATA_DIR_UNDECLARED};
use kata_worker::plane_index::{LocalPlaneIndex, resolve_environment};

#[test]
fn the_plane_index_resolves_the_environment_the_node_declared() {
    nix_cli::require_available()
        .expect("this cell requires the nix CLI; a host that cannot run it produces a RED");
    let dir = tempfile::tempdir().unwrap();
    let data_dir = dir.path().join("data");
    std::fs::create_dir_all(&data_dir).unwrap();
    let store = NixStore::Local(dir.path().join("store"));
    let source = dir.path().join("tree");
    std::fs::create_dir_all(&source).unwrap();
    std::fs::write(source.join("payload"), "closure\n").unwrap();
    let path = nix_cli::add_path(&store, &source).expect("add-path into the disposable store");

    let bound = {
        let db = OperationalDb::open(data_dir.join("operational.db")).unwrap();
        let cas = CasStore::open(data_dir.join("cas.db"), data_dir.join("cas")).unwrap();
        bind_node_environment(
            &db,
            &cas,
            &store,
            &data_dir,
            &NodeEnvironmentConfig {
                label: "agreement".to_owned(),
                system: "x86_64-linux".to_owned(),
                nixpkgs_attribute: "fixture#tree".into(),
                store_paths: vec![path],
                path_prepend: Vec::new(),
                integrity_policy: IntegrityPolicy {
                    verify: NarVerification::NarHashOnly,
                    sigs_needed: 0,
                    required_signers: Vec::new(),
                    allow_unsigned_content_addressed: true,
                    verify_contents_at_declare: true,
                },
            },
            kata_types::node_profile::node_platform().as_ref(),
        )
        .expect("the node binds its environment")
    };

    // The WORKER's reader, opened read-only by path, as a daemon opens `main_data_dir`.
    let index = LocalPlaneIndex::open(&data_dir).expect("the planes open read-only");
    let manifest = resolve_environment(&index, &index, bound.environment).expect(
        "the plane index must resolve the id the declarer minted; a refusal naming \
         environment_identity_mismatch is the two derivations disagreeing",
    );
    assert_eq!(manifest.platform().id(), bound.platform);

    // And the rule the agreement rests on, pinned from outside the resolver: the
    // manifest field an environment id folds is NOT the artifact plane's id for the same
    // bytes, so a reader that used `ArtifactRef::new` would compute a different id.
    let bytes = manifest.manifest_bytes().unwrap();
    let raw_address = kata_types::nix_environment::environment_manifest_id(&bytes);
    let artifact_fold =
        ArtifactRef::new(raw_address.0, bytes.len() as u64, ArtifactPrivacy::Public).id();
    assert_ne!(raw_address, artifact_fold);
    assert_eq!(
        manifest.environment_ref(raw_address).id(),
        bound.environment
    );
    assert_ne!(
        manifest.environment_ref(artifact_fold).id(),
        bound.environment
    );
}

#[test]
fn a_daemon_without_the_mains_data_dir_refuses_to_start_by_name() {
    let cfg = kata_types::config::WorkerNodeConfig {
        main_data_dir: None,
        home_node_endpoint: "unix:///nonexistent/kata.sock".to_string(),
        credential_path: std::path::PathBuf::from("/nonexistent/worker.cred"),
        expected_membrane_id: kata_types::identity::WorkerMembraneId(ulid::Ulid::new()),
        capabilities: vec![],
    };
    let refusal = CapsuleRoute::admit_for_daemon(
        &cfg,
        kata_worker::owner_home::KataLoginsDir::Resolved(std::path::PathBuf::from(
            "/nonexistent/logins",
        )),
    )
    .expect_err("a daemon resolves capsules through the main's planes, and names none")
    .to_string();
    assert!(
        refusal.contains(WORKER_MAIN_DATA_DIR_UNDECLARED),
        "refused by name: {refusal}"
    );
}

/// Every `kata-worker` (the node `kata serve` supervises, or a daemon) admits
/// through `admit_for`: a node that declares no OCI provider must refuse
/// to START, not come up routeless and refuse every frame. Host-free because
/// `CapsuleRoute::admit` reaches the provider refusal before the certification, which is
/// the step that starts a container — this process declares no external provider.
#[test]
fn a_worker_with_no_declared_provider_refuses_to_start_by_name() {
    assert!(
        std::env::var_os(kata_worker::execution_route::EXTERNAL_PROVIDER_ENV).is_none(),
        "the premise: this test process declares no provider"
    );
    let dir = tempfile::tempdir().unwrap();
    let refusal = CapsuleRoute::admit_for(
        dir.path(),
        kata_worker::owner_home::KataLoginsDir::Resolved(std::path::PathBuf::from(
            "/nonexistent/logins",
        )),
    )
    .expect_err("a worker without a provider must not start")
    .to_string();
    assert!(
        refusal.contains(kata_worker::capsule_route::OCI_PROVIDER_UNDECLARED),
        "refused by name: {refusal}"
    );
    // And refused BEFORE the certification, which starts a throwaway container: the memo
    // is untouched, whether or not this host could have certified.
    assert!(
        !kata_worker::oci_runtime::oci_route_measured_for_test(),
        "the provider refusal must precede the certification"
    );
}
