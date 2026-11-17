//! Extracted from `crates/worker/src/daemon.rs` inline `#[cfg(test)] mod tests`.

use std::path::PathBuf;

use kata_types::BackendType;
use kata_types::config::WorkerNodeConfig;
use kata_types::identity::WorkerResource;
use kata_worker::daemon::testing::render_provision_summary;
use kata_worker::daemon::{load_local_enrollment_secret, provision_worker, worker_run_loop};
use smol_str::SmolStr;

mod common;

// An `oci` daemon that cannot admit its capsule route refuses BEFORE it dials its main:
// the admission runs ahead of `connect_main_transport`, so a node that cannot run capsules
// never takes a connection slot. Observed through an endpoint whose scheme the dial would
// refuse — if the dial ran first, THAT refusal is the one returned. Host-free: a missing
// `main_data_dir` is refused before anything is measured.
#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn an_oci_daemon_refuses_its_capsule_route_before_it_dials() {
    let cfg = WorkerNodeConfig {
        main_data_dir: None,
        home_node_endpoint: "http://foo.example".to_string(),
        credential_path: PathBuf::from("/nonexistent/worker.cred"),
        expected_membrane_id: kata_types::identity::WorkerMembraneId(ulid::Ulid::new()),
        capabilities: vec![],
    };
    let err = worker_run_loop(
        cfg,
        "secret".to_string(),
        kata_worker::owner_home::KataLoginsDir::Resolved(PathBuf::from("/nonexistent/logins")),
    )
    .await
    .expect_err("an oci daemon with no main_data_dir must not start");
    let msg = format!("{err:#}");
    assert!(
        msg.contains(kata_worker::capsule_route::WORKER_MAIN_DATA_DIR_UNDECLARED),
        "the capsule-route refusal must come first: {msg}"
    );
    assert!(
        !msg.contains("unsupported endpoint scheme"),
        "the dial must not have run: {msg}"
    );
}

/// `provision_worker` must write the `--capability` flags it was passed into
/// the generated `WorkerNodeConfig.capabilities`, so the operator never has to
/// hand-edit the TOML to add `agent_backend = "..."`. A provisioner that wrote
/// `capabilities = []` regardless of what was passed would leave the operator
/// to add every label by hand.
#[test]
fn provision_worker_writes_capabilities_into_config_toml() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let out = tmp.path().join("worker.toml");
    let caps = vec![
        WorkerResource::AgentBackend(BackendType::Harness),
        WorkerResource::Shell,
        WorkerResource::Custom(SmolStr::new("experimental")),
    ];

    let main_data = tmp.path().join("main-data");
    provision_worker(
        "unix:///tmp/kata-test.sock".to_string(),
        "topsecret".to_string(),
        Some(out.clone()),
        caps.clone(),
        main_data.clone(),
    )
    .expect("provision_worker should succeed");

    // Round-trip the written TOML through the canonical loader so
    // any format drift (kebab-case, tag names, missing fields)
    // surfaces as a load error rather than a silent string match.
    let written = kata_types::config::load_worker_config(&out)
        .expect("written worker.toml must parse via load_worker_config");
    assert_eq!(written.capabilities, caps);
    assert_eq!(written.home_node_endpoint, "unix:///tmp/kata-test.sock");
    // The provisioned worker resolves its capsule route through the main's
    // data directory.
    assert_eq!(written.main_data_dir.as_deref(), Some(main_data.as_path()));

    // Also assert the raw TOML contains a `[[capabilities]]`
    // entry — this is the "no hand-edit needed" surface the
    // operator inspects with `cat worker.toml`.
    let raw = std::fs::read_to_string(&out).expect("read worker.toml");
    assert!(
        raw.contains("[[capabilities]]"),
        "expected `[[capabilities]]` in written TOML, got:\n{raw}"
    );
    assert!(
        raw.contains("agent_backend"),
        "expected `agent_backend` in written TOML, got:\n{raw}"
    );
    // kata reads no other tool's login, so the file carries no host-login
    // consent knob.
    assert!(
        !raw.contains("host_logins"),
        "a removed knob must not be written, got:\n{raw}"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        for path in [&out, &out.with_file_name("worker.cred")] {
            assert_eq!(
                std::fs::metadata(path).unwrap().permissions().mode() & 0o777,
                0o600,
                "explicit create mode must remain owner-only even under a permissive umask"
            );
        }
    }
}

/// Empty `--capability` list still works (writes `capabilities = []`
/// — operator can later hand-edit, or pass `--capability` at
/// provision time). Pinned so the no-flag default doesn't quietly
/// regress to an error.
#[test]
fn provision_worker_empty_capabilities_writes_empty_list() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let out = tmp.path().join("worker.toml");

    provision_worker(
        "unix:///tmp/kata-test.sock".to_string(),
        "topsecret".to_string(),
        Some(out.clone()),
        vec![],
        tmp.path().join("main-data"),
    )
    .expect("provision_worker with no caps must still succeed");

    let written = kata_types::config::load_worker_config(&out)
        .expect("written worker.toml must parse via load_worker_config");
    assert!(written.capabilities.is_empty());
}

#[cfg(unix)]
#[test]
fn enrollment_secret_file_must_be_owner_only_and_not_a_symlink() {
    use std::os::unix::fs::{PermissionsExt as _, symlink};

    let tmp = tempfile::tempdir().unwrap();
    let secret = tmp.path().join("local-worker.secret");
    std::fs::write(&secret, "topsecret\n").unwrap();
    let error = load_local_enrollment_secret(&secret).expect_err("0644 must fail");
    assert!(error.to_string().contains("group/world"), "{error:#}");

    std::fs::set_permissions(&secret, std::fs::Permissions::from_mode(0o600)).unwrap();
    assert_eq!(load_local_enrollment_secret(&secret).unwrap(), "topsecret");

    let link = tmp.path().join("secret-link");
    symlink(&secret, &link).unwrap();
    let error = load_local_enrollment_secret(&link).expect_err("symlink must fail");
    assert!(error.to_string().contains("symlink"));
}

#[cfg(unix)]
#[test]
fn provision_refuses_symlink_output_without_touching_target() {
    use std::os::unix::fs::{PermissionsExt as _, symlink};

    let tmp = tempfile::tempdir().unwrap();
    let victim = tmp.path().join("victim");
    std::fs::write(&victim, "do-not-replace").unwrap();
    std::fs::set_permissions(&victim, std::fs::Permissions::from_mode(0o600)).unwrap();
    let out = tmp.path().join("worker.toml");
    symlink(&victim, &out).unwrap();

    let error = provision_worker(
        "unix:///tmp/kata-test.sock".to_string(),
        "topsecret".to_string(),
        Some(out),
        vec![],
        tmp.path().join("main-data"),
    )
    .expect_err("symlink output must fail closed");
    assert!(error.to_string().contains("not a regular file"));
    assert_eq!(std::fs::read_to_string(victim).unwrap(), "do-not-replace");
}

#[test]
fn provision_worker_rejects_network_endpoints_without_writing_files() {
    for endpoint in [
        "ws://127.0.0.1:8410",
        "wss://worker.example",
        "tcp://127.0.0.1:8410",
    ] {
        let tmp = tempfile::tempdir().expect("tempdir");
        let out = tmp.path().join("worker.toml");
        let error = provision_worker(
            endpoint.to_string(),
            "topsecret".to_string(),
            Some(out.clone()),
            vec![],
            tmp.path().join("main-data"),
        )
        .expect_err("network provisioning must fail closed");

        assert!(
            error.to_string().contains("unix://<socket>"),
            "unexpected diagnostic for {endpoint}: {error}"
        );
        assert!(!out.exists(), "rejected endpoint wrote {}", out.display());
        assert!(
            !tmp.path().join("worker.cred").exists(),
            "rejected endpoint wrote a credential"
        );
    }
}
#[test]
fn provision_publishes_bound_membrane_and_refuses_in_place_reprovision() {
    let root = tempfile::tempdir().unwrap();
    let config_path = root.path().join("worker.toml");
    provision_worker(
        "unix:///tmp/test-worker-domain.sock".into(),
        "test-secret".into(),
        Some(config_path.clone()),
        vec![],
        root.path().join("main-data"),
    )
    .unwrap();
    let config = kata_types::config::load_worker_config(&config_path).unwrap();
    let db_path = root.path().join("idempotency.db");
    let store =
        kata_core::IdempotencyStore::open_existing_bound(&db_path, config.expected_membrane_id)
            .unwrap();
    assert_eq!(store.membrane_id().unwrap(), config.expected_membrane_id);
    drop(store);
    let members = [
        config_path.clone(),
        config.credential_path.clone(),
        db_path.clone(),
    ];
    let before = members
        .iter()
        .map(std::fs::read)
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    assert!(
        provision_worker(
            "unix:///tmp/test-worker-domain.sock".into(),
            "replacement-secret".into(),
            Some(config_path),
            vec![],
            root.path().join("main-data"),
        )
        .is_err()
    );
    assert_eq!(
        members
            .iter()
            .map(std::fs::read)
            .collect::<Result<Vec<_>, _>>()
            .unwrap(),
        before
    );
    assert!(
        kata_core::IdempotencyStore::open_existing_bound(
            &db_path,
            kata_types::identity::WorkerMembraneId(ulid::Ulid::new())
        )
        .is_err()
    );
}

#[test]
fn provision_refuses_orphan_sqlite_sidecars_before_publishing_authority() {
    for name in [
        "idempotency.db-wal",
        "idempotency.db-shm",
        "idempotency.db-journal",
    ] {
        let root = tempfile::tempdir().unwrap();
        let sidecar = root.path().join(name);
        std::fs::write(&sidecar, b"retained-authority").unwrap();
        assert!(
            provision_worker(
                "unix:///tmp/test-worker-domain.sock".into(),
                "test-secret".into(),
                Some(root.path().join("worker.toml")),
                vec![],
                root.path().join("main-data"),
            )
            .is_err()
        );
        assert_eq!(std::fs::read(sidecar).unwrap(), b"retained-authority");
        assert!(!root.path().join("worker.toml").exists());
        assert!(!root.path().join("idempotency.db").exists());
    }
}
#[test]
fn provision_summary_lists_dedicated_entrypoint_and_local_boundary() {
    let config = PathBuf::from("/tmp/kata-worker.toml");
    let credential = PathBuf::from("/tmp/worker.cred");
    let summary = render_provision_summary(&config, &credential, "unix:///tmp/kata-worker.sock");

    assert!(!summary.contains("kata run --role"));
    assert!(
        summary.contains("kata-worker run --config /tmp/kata-worker.toml"),
        "summary must keep the dedicated worker run path visible; got:\n{summary}"
    );
    assert!(
        summary.contains("local unix socket")
            && summary.contains("remote enrollment is not supported"),
        "summary must state the supported local boundary; got:\n{summary}"
    );
    assert!(summary.contains("main:       unix:///tmp/kata-worker.sock")); // kata-spacing: intentional
    assert!(!summary.contains("home:"));
}

// ---------------------------------------------------------------------------
// The Hello frame really carries the containment claim. It lives beside the
// other worker-node-config tests because it must construct a real worker node
// config.
// ---------------------------------------------------------------------------

/// The capsule route these Hello cells pass — a stand-in, so no container
/// starts and the claim it mints is the fixture's own
/// (`ClaimedContainment::rig_worker_containment`).
fn stand_in_capsule_route() -> kata_worker::capsule_route::CapsuleRoute {
    struct NeverExecuted;
    #[async_trait::async_trait]
    impl kata_worker::capsule_route::StandInExecution for NeverExecuted {
        async fn execute(
            &self,
            _frame: &kata_transport::types::CapsuleAssignment,
            _cancel: tokio::sync::oneshot::Receiver<String>,
            _progress: Option<&kata_worker::capsule_progress::CapsuleProgress>,
        ) -> Result<
            kata_transport::types::WorkerMessage,
            kata_worker::capsule_execution::CapsuleAttemptRefusal,
        > {
            Err(kata_worker::capsule_execution::CapsuleAttemptRefusal {
                reason: "fixture worker executes nothing".to_string(),
                performed:
                    kata_worker::capsule_execution::ExecutionProvenanceVerdict::ProvenNotPerformed,
                usage: None,
                provider_failure: None,
            })
        }
    }
    kata_worker::capsule_route::CapsuleRoute::stand_in_for_test(std::sync::Arc::new(NeverExecuted))
}

/// The ADVERTISE half, end to end through the function the daemon actually calls
/// — not a hand-assembled JSON object, which is how a writer and a reader come
/// to disagree about a key.
///
/// Host-independent by construction: it asserts the claim is PRESENT and DECODES
/// with the main's own reader, never which verdict the host produces.
#[test]
fn the_hello_frame_carries_a_decodable_containment_claim() {
    let worker_cfg = kata_types::config::WorkerNodeConfig {
        main_data_dir: None,
        home_node_endpoint: "unix:///tmp/kata-worker-not-dialed.sock".to_string(),
        credential_path: std::path::PathBuf::from("/tmp/kata-worker-credential-not-read"),
        expected_membrane_id: kata_types::identity::WorkerMembraneId(ulid::Ulid::new()),
        capabilities: vec![kata_types::identity::WorkerResource::Shell],
    };
    let capsule_route = stand_in_capsule_route();
    let worker_info =
        kata_worker::daemon::testing::build_hello_worker_info(&worker_cfg, &capsule_route)
            .expect("the Hello worker-info blob builds");

    assert!(
        worker_info
            .get(kata_types::containment_claim::ClaimedContainment::HELLO_KEY)
            .is_some(),
        "a Hello without the containment capability leaves the main nothing to read; the key \
         must be present: \
         {worker_info}"
    );

    let claim =
        kata_types::containment_claim::ClaimedContainment::in_hello_worker_info(&worker_info)
            .expect("the main's own reader must decode what the worker's own writer produced");
    assert!(
        matches!(
            claim,
            kata_types::containment_claim::ClaimedContainment::Available { .. }
                | kata_types::containment_claim::ClaimedContainment::Unavailable { .. }
        ),
        "a worker advertises a MEASURED verdict; `unstated` is the main's arm and no sender may \
         assert it. got {claim:?}"
    );
    assert!(
        !claim.evidence().is_empty(),
        "the claim must carry the observation, because the main's placement refusal quotes it"
    );

    assert!(
        worker_info.get("capabilities").is_some(),
        "the containment claim rides its OWN key and must not have displaced the operator's \
         capability list: {worker_info}"
    );
    let capabilities = worker_info["capabilities"].to_string();
    assert!(
        !capabilities.contains("containment"),
        "containment must NOT appear in the free-form capability vocabulary — that list is \
         operator-written and `kata_types::identity` says of it that it never certifies \
         containment: {capabilities}"
    );
}

/// A capsule worker serves `agent = "shell"` stages because the admitted
/// route delivers `sh` inside the container — the daemon must advertise
/// `agent:shell` on Hello itself, the way the dispatch preflight and the
/// `checked_command_live` rig depend on. A daemon that advertised only the
/// operator's labels would leave every shell stage unplaceable on it.
#[test]
fn the_hello_advertises_agent_shell_through_the_capsule_route() {
    let worker_cfg = kata_types::config::WorkerNodeConfig {
        main_data_dir: None,
        home_node_endpoint: "unix:///tmp/kata-shell-cap-not-dialed.sock".to_string(),
        credential_path: std::path::PathBuf::from("/tmp/kata-shell-cap-not-read"),
        expected_membrane_id: kata_types::identity::WorkerMembraneId(ulid::Ulid::new()),
        // A `custom=` token the way `agent_change_rig`'s provision passes the
        // authored agent label — it must survive verbatim beside the
        // daemon-minted `agent:shell`.
        capabilities: vec![kata_types::identity::WorkerResource::Custom(
            "agent:claude_code".into(),
        )],
    };
    let capsule_route = stand_in_capsule_route();
    let worker_info =
        kata_worker::daemon::testing::build_hello_worker_info(&worker_cfg, &capsule_route)
            .expect("the Hello worker-info blob builds");

    // Lower the frame the way the main's accept loop does
    // (`local_capacity::worker_capabilities`): `agent_backend` lowers to the
    // `agent:<label>` scheduling token the stage's `agent = "..."` requires.
    let resources: Vec<kata_types::identity::WorkerResource> =
        serde_json::from_value(worker_info["capabilities"].clone())
            .expect("the capability list the main decodes");
    let lowered: Vec<String> = resources
        .iter()
        .map(|resource| match resource {
            kata_types::identity::WorkerResource::AgentBackend(backend) => {
                format!("agent:{}", backend.label())
            }
            kata_types::identity::WorkerResource::Shell => "shell".to_string(),
            kata_types::identity::WorkerResource::Network => "network".to_string(),
            kata_types::identity::WorkerResource::Disk { min_gb } => format!("disk:{min_gb}"),
            kata_types::identity::WorkerResource::Gpu { min_vram_gb } => {
                format!("gpu:{min_vram_gb}")
            }
            kata_types::identity::WorkerResource::Custom(value) => value.to_string(),
        })
        .collect();
    assert!(
        lowered.iter().any(|cap| cap == "agent:shell"),
        "a capsule worker must advertise `agent:shell` — a stage's `agent = \"shell\"` \
         placement requirement matches on exactly that token: {lowered:?}"
    );
    assert!(
        lowered.iter().any(|cap| cap == "agent:claude_code"),
        "the operator-declared label must pass through verbatim: {lowered:?}"
    );
    assert_eq!(
        lowered.iter().filter(|cap| *cap == "agent:shell").count(),
        1,
        "the daemon mints `agent:shell` once: {lowered:?}"
    );
}

/// An operator who declares `agent_backend = "shell"` explicitly must not get
/// the label twice — the augmentation is a floor, not a duplicate.
#[test]
fn an_operator_declared_shell_agent_is_not_double_advertised() {
    let worker_cfg = kata_types::config::WorkerNodeConfig {
        main_data_dir: None,
        home_node_endpoint: "unix:///tmp/kata-shell-declared-not-dialed.sock".to_string(),
        credential_path: std::path::PathBuf::from("/tmp/kata-shell-declared-not-read"),
        expected_membrane_id: kata_types::identity::WorkerMembraneId(ulid::Ulid::new()),
        capabilities: vec![kata_types::identity::WorkerResource::AgentBackend(
            kata_types::BackendType::Shell,
        )],
    };
    let capsule_route = stand_in_capsule_route();
    let worker_info =
        kata_worker::daemon::testing::build_hello_worker_info(&worker_cfg, &capsule_route)
            .expect("the Hello worker-info blob builds");
    let resources: Vec<kata_types::identity::WorkerResource> =
        serde_json::from_value(worker_info["capabilities"].clone())
            .expect("the capability list the main decodes");
    assert_eq!(
        resources
            .iter()
            .filter(|cap| matches!(
                cap,
                kata_types::identity::WorkerResource::AgentBackend(kata_types::BackendType::Shell)
            ))
            .count(),
        1,
        "an operator-declared `agent_backend=shell` stays a no-op: {resources:?}"
    );
}
