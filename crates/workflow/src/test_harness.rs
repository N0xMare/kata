//! The node RIGS the runtime's cells drive: an `oci` main over one data directory
//! (`OciNodeRig`) with a scripted worker answering its delivered capsules
//! (`ScriptedWorkerHandle`), the fixture environment and program probe a rig
//! authorizes against, the seeded capsule attempts, and the interleave seams a cell
//! installs its mover at — all behind `test-support`. The fixture-driven harness
//! behind `kata workflows test` is `kata_program::test_harness`.

#[cfg(any(test, feature = "test-support"))]
use smol_str::SmolStr;

/// The containment claim a RIG worker registers with — the ONE spelling every
/// rig in this crate's `tests/` already uses, kept as a free function so those
/// ~20 call sites are untouched.
///
/// The VALUE is defined once, on
/// [`kata_types::containment_claim::ClaimedContainment::rig_worker_containment`],
/// beside the `unstated_no_handshake` it is the mirror of.
#[must_use]
pub fn rig_worker_containment() -> kata_types::containment_claim::ClaimedContainment {
    kata_types::containment_claim::ClaimedContainment::rig_worker_containment()
}

/// The mover [`interleave_before_a_stage_submit`] installs: called with the execution and
/// the stage about to be submitted.
#[cfg(any(test, feature = "test-support"))]
pub type StageSubmitMover = std::sync::Arc<dyn Fn(ulid::Ulid, &str) + Send + Sync>;

/// Install a rig's MOVER at the stage-submit seam — the window in which a runner has
/// decided a stage is ready and has written nothing for it yet: between two stages, with
/// nothing of the execution live. The mover runs on entry to
/// `WorkflowRunner::submit_stage`, on both execution profiles, with the execution and the
/// stage name, and the submission continues when it returns. See
/// `runner::STAGE_SUBMIT_INTERLEAVE`.
#[cfg(any(test, feature = "test-support"))]
pub fn interleave_before_a_stage_submit(mover: StageSubmitMover) {
    crate::runner::install_stage_submit_interleave(mover);
}

/// The mover [`interleave_before_the_pass_fold`] installs: called once per runner
/// drive-pass iteration with the execution, between the pass's owed-obligation drives
/// and its last fold — the window in which a completion can commit with its derived
/// `/work` apply unclaimed by any pass.
#[cfg(any(test, feature = "test-support"))]
pub type PassFoldMover = std::sync::Arc<dyn Fn(ulid::Ulid) + Send + Sync>;

/// Install a rig's MOVER at the pass-fold seam — the window between the pass's
/// `drive_pending_work_applies` and the fold that would land a late completion in the
/// same pass. The mover runs inside `run_replay`'s drive loop. See
/// `runner::PASS_FOLD_INTERLEAVE`.
#[cfg(any(test, feature = "test-support"))]
pub fn interleave_before_the_pass_fold(mover: PassFoldMover) {
    crate::runner::install_pass_fold_interleave(mover);
}

/// The mover [`interleave_after_a_member_read`] installs: called with the execution and
/// the member occurrence an expansion drive has just read unaccepted.
#[cfg(any(test, feature = "test-support"))]
pub type MemberReadMover = std::sync::Arc<dyn Fn(ulid::Ulid, [u8; 32]) + Send + Sync>;

/// Install a rig's MOVER at the member-read seam — the window between an expansion
/// drive's read of an unaccepted member occurrence (a loop member, a topology member, or
/// a loop member that is a nested topology) and its live/dead judgment of that member.
/// See `runner::MEMBER_READ_INTERLEAVE`.
#[cfg(any(test, feature = "test-support"))]
pub fn interleave_after_a_member_read(mover: MemberReadMover) {
    crate::runner::install_member_read_interleave(mover);
}

#[cfg(test)]
#[path = "test_harness_tests.rs"]
mod tests;

/// The fixture store path [`fixture_environment_manifest_bytes`] declares; nothing exists
/// there on any host, which is why a rig pairs it with [`FixtureProgramProbe`].
#[cfg(any(test, feature = "test-support"))]
pub const FIXTURE_ENVIRONMENT_STORE_PATH: &str =
    "/nix/store/0000000000000000000000000000000f-fixture-shell";

/// Canonical bytes of a REAL environment manifest over [`FIXTURE_ENVIRONMENT_STORE_PATH`]
/// with `<it>/bin` on `PATH` — what a rig publishes so capsule authorization can read the
/// environment it gates on.
///
/// # Panics
///
/// Never on the fixed inputs.
#[cfg(any(test, feature = "test-support"))]
#[must_use]
pub fn fixture_environment_manifest_bytes() -> Vec<u8> {
    use kata_types::nix_environment::{
        ClosureEntry, IntegrityPolicy, NarVerification, NixEnvironmentManifest, Provenance,
        RetentionClass, RetentionIntent, StorePath,
    };
    let path = StorePath::new(FIXTURE_ENVIRONMENT_STORE_PATH).expect("a fixture store path");
    NixEnvironmentManifest::new(
        "fixture",
        kata_types::node_profile::node_platform().unwrap_or_else(|| {
            kata_types::execution_contract::PlatformRef::new(
                "x86_64-linux",
                kata_types::primitives::ContentHash::new([0x33; 32]),
            )
        }),
        Provenance::StorePaths {
            nixpkgs_attribute: "fixture#shell".into(),
        },
        vec![path.clone()],
        vec![ClosureEntry {
            store_path: path,
            nar_hash: "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".into(),
            nar_size: 1024,
            references: Vec::new(),
            ca: None,
        }],
        vec![
            kata_types::execution_contract::GuestPath::new(format!(
                "{FIXTURE_ENVIRONMENT_STORE_PATH}/bin"
            ))
            .expect("a guest path"),
        ],
        IntegrityPolicy {
            verify: NarVerification::NarHashOnly,
            sigs_needed: 0,
            required_signers: Vec::new(),
            allow_unsigned_content_addressed: true,
            verify_contents_at_declare: false,
        },
        kata_types::execution_contract::ArtifactPrivacy::Public,
        RetentionIntent {
            class: RetentionClass::Authoritative,
        },
        "nix-daemon",
    )
    .and_then(|manifest| manifest.manifest_bytes())
    .expect("the fixture manifest is valid")
}

/// The `[node] environment` declaration a host-free rig writes into its node
/// config so boot binds the FIXTURE environment: the whole closure is the one
/// unrealisable store path, which `bind_configured_node_environment` keys on
/// (`declaration_names_fixture_environment`) to skip Nix and write the same
/// durable rows the production bind commits. `verify_contents_at_declare` is
/// off — there are no bytes to verify against.
#[cfg(any(test, feature = "test-support"))]
#[must_use]
pub fn fixture_environment_declaration() -> kata_types::config::NodeEnvironmentConfig {
    kata_types::config::NodeEnvironmentConfig {
        label: "fixture-shell".to_owned(),
        system: "x86_64-linux".to_owned(),
        nixpkgs_attribute: "fixture#shell".into(),
        store_paths: vec![
            kata_types::nix_environment::StorePath::new(FIXTURE_ENVIRONMENT_STORE_PATH)
                .expect("a fixture store path"),
        ],
        path_prepend: vec![
            kata_types::execution_contract::GuestPath::new(format!(
                "{FIXTURE_ENVIRONMENT_STORE_PATH}/bin"
            ))
            .expect("a guest path"),
        ],
        integrity_policy: kata_types::nix_environment::IntegrityPolicy {
            verify: kata_types::nix_environment::NarVerification::NarHashOnly,
            sigs_needed: 0,
            required_signers: Vec::new(),
            allow_unsigned_content_addressed: true,
            verify_contents_at_declare: false,
        },
    }
}

/// A [`crate::authorization::ProgramProbe`] that answers for the fixture environment:
/// exactly the listed program names exist in `<FIXTURE_ENVIRONMENT_STORE_PATH>/bin`.
#[cfg(any(test, feature = "test-support"))]
pub struct FixtureProgramProbe(pub Vec<&'static str>);

#[cfg(any(test, feature = "test-support"))]
impl crate::authorization::ProgramProbe for FixtureProgramProbe {
    fn executable(&self, path: &std::path::Path) -> bool {
        self.0.iter().any(|name| {
            path == std::path::Path::new(FIXTURE_ENVIRONMENT_STORE_PATH)
                .join("bin")
                .join(name)
        })
    }
}

/// Seed ONE capsule attempt for an ALREADY-ADMITTED `execution_id`, through the
/// production verbs, and DISPATCH it to `worker` — the durable shape a main leaves behind
/// when it dies with a capsule in flight. With `started_at_ms`, the worker's start is
/// folded too (`running` at that instant).
///
/// Every row goes through the plane's own doors (the `/work` artifact, a declared
/// environment, a declared capsule, a claim bound to the occurrence, the placement
/// transaction), and the attempt's at-rest frame is the CAPSULE arm, so every reader that
/// classifies attempts by arm sees what production writes. Returns the attempt id.
///
/// # Panics
///
/// On any refusal: a rig that cannot seed its premise has nothing to assert.
#[cfg(any(test, feature = "test-support"))]
pub fn seed_dispatched_capsule_attempt(
    db: &kata_core::OperationalDb,
    cas: &kata_core::store::cas::CasStore,
    execution_id: ulid::Ulid,
    program_hash: kata_types::primitives::ContentHash,
    stage: &str,
    worker: &str,
    started_at_ms: Option<i64>,
) -> ulid::Ulid {
    use kata_core::operational::{CommandSpec, MainSideTransition};
    let (attempt_id, assignment_json) =
        seed_claimed_capsule_attempt(db, cas, execution_id, program_hash, stage);
    db.dispatch_claimed_attempt(
        attempt_id,
        worker,
        ulid::Ulid::new(),
        &CommandSpec {
            command_json: assignment_json,
        },
    )
    .expect("the placement");
    if let Some(started_at_ms) = started_at_ms {
        db.record_main_side_transition(
            attempt_id,
            &MainSideTransition {
                started_at_ms: Some(started_at_ms),
                ..MainSideTransition::bare("running")
            },
        )
        .expect("the start");
    }
    attempt_id
}

/// [`seed_dispatched_capsule_attempt`]'s first half: the attempt CLAIMED, bound to its
/// occurrence and capsule, and never placed — `pending`, no `dispatched_at_ms`. Returns
/// the attempt id and its at-rest capsule frame.
///
/// # Panics
///
/// On any refusal: a rig that cannot seed its premise has nothing to assert.
#[cfg(any(test, feature = "test-support"))]
pub fn seed_claimed_capsule_attempt(
    db: &kata_core::OperationalDb,
    cas: &kata_core::store::cas::CasStore,
    execution_id: ulid::Ulid,
    program_hash: kata_types::primitives::ContentHash,
    stage: &str,
) -> (ulid::Ulid, Vec<u8>) {
    use kata_types::execution_contract::{OccurrenceRef, OperationContractId, OperationPath};
    use kata_types::primitives::ContentHash;
    let occurrence = OccurrenceRef::new(
        kata_types::workflow::ExecutionId(execution_id),
        program_hash,
        OperationContractId(ContentHash::new([0x6D; 32])),
        OperationPath(vec![0]),
    );
    seed_claimed_capsule_attempt_at(db, cas, stage, &occurrence)
}

/// [`seed_claimed_capsule_attempt`] at an arbitrary occurrence: a cell pinning
/// seat coordinates or contract identity needs the claim bound where the
/// production check reads it, not where the default puts it.
#[cfg(any(test, feature = "test-support"))]
pub fn seed_claimed_capsule_attempt_at(
    db: &kata_core::OperationalDb,
    cas: &kata_core::store::cas::CasStore,
    stage: &str,
    occurrence: &kata_types::execution_contract::OccurrenceRef,
) -> (ulid::Ulid, Vec<u8>) {
    use kata_core::operational::{
        ArtifactDeclaration, AttemptClaimSpec, CapsuleDeclaration, CasRootOwner,
        EnvironmentDeclaration, OccurrenceBinding,
    };
    use kata_types::execution_contract::{
        ArtifactPrivacy, ArtifactRef, Capsule, CapsuleBudgets, CapsuleNetwork, CapsuleProcess,
        EnvironmentId, GuestAccess, GuestMapping, GuestPath, PlatformId, PreparedActionId,
    };

    // The `/work` input is a TREE artifact — one regular file over the seeded
    // bytes — because a capsule that maps `/work` produces a `/work` delta whose
    // base must decode as a `TreeManifest`. A blob row would refuse the delta at
    // adoption before the cell under test could run.
    let member = cas
        .put_durable(format!("seeded-capsule-work-{:?}-{stage}", occurrence.id()).as_bytes())
        .expect("the /work member");
    let work_manifest =
        kata_types::tree_artifact::TreeManifest::new(vec![kata_types::tree_artifact::TreeEntry {
            path: kata_types::tree_artifact::TreePath::new("w").expect("w"),
            node: kata_types::tree_artifact::TreeNode::File {
                mode: kata_types::tree_artifact::TreeEntryMode::Regular,
                object: member.object_id(),
                size_bytes: member.size(),
            },
        }])
        .expect("the /work manifest");
    let work = cas
        .put_durable(&work_manifest.manifest_bytes().expect("the manifest bytes"))
        .expect("the /work tree object");
    let work_ref = ArtifactRef::new(work.object_id(), work.size(), ArtifactPrivacy::Private);
    db.declare_artifact(
        &ArtifactDeclaration::for_durable_tree(
            &work_manifest,
            work_ref.privacy(),
            CasRootOwner::Execution(occurrence.execution.0),
            &work,
        )
        .expect("a /work declaration"),
    )
    .expect("the /work row");
    let environment = [0x5E; 32];
    if db.environment(environment).expect("readable").is_none() {
        // Bytes of its OWN, not `fixture_environment_manifest_bytes`: a rig that already
        // declared an environment over the fixture manifest would share its node-owned
        // root, which the plane refuses. Nothing a settlement does reads the manifest.
        let manifest = cas
            .put_durable(b"seeded-capsule-environment-manifest")
            .expect("the environment manifest");
        db.declare_environment(
            &EnvironmentDeclaration::for_staged_root(
                environment,
                &manifest,
                [0x5F; 32],
                "seeded-capsule-environment",
                [0x33; 32],
                "01JZZZZZZZZZZZZZZZZZZZZZE9",
            )
            .expect("an environment declaration"),
        )
        .expect("the environment row");
    }
    let capsule = Capsule::new(
        occurrence.id(),
        PreparedActionId(kata_types::primitives::ContentHash::new([0x03; 32])),
        EnvironmentId(kata_types::primitives::ContentHash::new(environment)),
        PlatformId(kata_types::primitives::ContentHash::new([0x33; 32])),
        vec![GuestMapping {
            artifact: work_ref.id(),
            guest_path: GuestPath::new("/work").expect("/work"),
            access: GuestAccess::ReadWrite,
        }],
        CapsuleProcess::Command {
            argv: vec!["sh".into(), "-c".into(), "true".into()],
        },
        CapsuleNetwork::Offline,
        None,
        CapsuleBudgets {
            wall_time_ms: 30_000,
            output_bytes: 1 << 20,
            memory_bytes: 512 * 1024 * 1024,
            process_count: 64,
            result_bytes: 1 << 20,
            result_entries: 64,
            work_delta_bytes: kata_types::execution_contract::CAPSULE_WORK_DELTA_BYTES,
            work_delta_entries: kata_types::execution_contract::CAPSULE_WORK_DELTA_ENTRIES,
        },
        None,
    )
    .expect("a capsule");
    let bytes = serde_json::to_vec(&capsule).expect("capsule bytes");
    let durable = cas.put_durable(&bytes).expect("the capsule object");
    db.declare_capsule(
        &CapsuleDeclaration::for_durable_object(&capsule, &bytes, &durable)
            .expect("a capsule declaration"),
    )
    .expect("the capsule row");
    let attempt_id = ulid::Ulid::new();
    let frame = kata_transport::types::DispatchFrame::Capsule(Box::new(
        kata_transport::types::CapsuleAssignment {
            attempt_id,
            execution_id: occurrence.execution.0,
            occurrence_id: occurrence.id(),
            capsule: kata_transport::types::CapsuleRef {
                id: capsule.id(),
                object: durable.object_id(),
                size_bytes: durable.size(),
            },
            lease_epoch: 0,
            placed_on: smol_str::SmolStr::default(),
            command_id: None,
            effect_domain: None,
            start_deadline_ms: None,
            progress_visibility: kata_types::workflow::ProgressVisibility::Off,
            trace: kata_transport::types::TraceContext::default(),
        },
    ));
    let assignment_json = serde_json::to_vec(&frame).expect("the at-rest frame");
    db.claim_attempt(
        occurrence.execution.0,
        attempt_id,
        &AttemptClaimSpec {
            stage_id: stage.to_owned(),
            assignment_json: assignment_json.clone(),
            initial_state: "pending".to_owned(),
            run_ordinal: 0,
            worker_id: None,
            occurrence: OccurrenceBinding::new(
                occurrence.clone(),
                Some(capsule.action()),
                Some(capsule.id()),
            ),
        },
    )
    .expect("the claim");
    (attempt_id, assignment_json)
}

/// The worker id [`OciNodeRig`] registers.
#[cfg(any(test, feature = "test-support"))]
pub const OCI_RIG_WORKER: &str = "worker-capsule-1";

/// The environment id [`OciNodeRig::declare_bound_environment`] declares and the rig's
/// dispatcher is BOUND to, as boot binds `[node] environment`.
#[cfg(any(test, feature = "test-support"))]
pub const OCI_RIG_ENVIRONMENT_ID: [u8; 32] = [0x5A; 32];

/// The executor term every [`OciNodeRig`] store carries unless a cell opens it with
/// another ([`OciNodeRig::open_with_executor_term`]). A FIXED stand-in, not this
/// build's: `kata-workflow` does not link the renderer the real term is derived from
/// (`kata_worker::executor_term`), and a rig's subject is the consult, not the fence.
///
/// # Panics
///
/// Never: one named property is inside `ExecutorTerm::derive`'s accepted set.
#[cfg(any(test, feature = "test-support"))]
#[must_use]
pub fn oci_rig_executor_term() -> kata_types::execution_platform::ExecutorTerm {
    kata_types::execution_platform::ExecutorTerm::derive(&[("oci_node_rig", b"executor")])
        .expect("one named property")
}

/// A node on the `oci` execution profile over ONE data directory, for the capsule
/// approval-gate and subworkflow-invoke cells in this crate's and `kata-api`'s `tests/`:
/// the operational plane bound to the stage-cache store's `cas.db`, a dispatcher bound to
/// [`OCI_RIG_ENVIRONMENT_ID`], and ONE registered worker claiming certified containment,
/// advertising `agent:shell` and STATING `oci`, over an `InProcessTransport` whose worker end is
/// [`Self::worker_side`] — where a delivered frame lands.
///
/// Opening it again over the same directory is a restarted main: every plane is re-opened
/// from disk and nothing in memory survives.
#[cfg(any(test, feature = "test-support"))]
pub struct OciNodeRig {
    /// `<dir>/operational.db`, for a raw second handle.
    pub op_path: std::path::PathBuf,
    /// The operational plane.
    pub db: std::sync::Arc<kata_core::OperationalDb>,
    /// A second handle on the node's content store.
    pub cas: kata_core::store::cas::CasStore,
    /// The stage-cache store that owns `cas.db`.
    pub store: std::sync::Arc<kata_core::store::SqliteWorkflowStore>,
    /// The worker pool.
    pub supervisor: std::sync::Arc<kata_transport::WorkerPoolSupervisor>,
    /// The dispatcher, on the `oci` profile.
    pub dispatcher: std::sync::Arc<crate::dispatcher::Dispatcher>,
    /// The MAIN end of the registered transport — where a spawned
    /// `ResultReactor` reads the worker's `send_result` answers.
    /// Retained, not just registered into the supervisor: the scripted worker's
    /// rig wires the real result path, which is on this end.
    pub main_side: std::sync::Arc<kata_transport::InProcessTransport>,
    /// The WORKER end of the registered transport.
    pub worker_side: std::sync::Arc<kata_transport::InProcessTransport>,
}

#[cfg(any(test, feature = "test-support"))]
impl OciNodeRig {
    /// Open (or re-open) the node over `path`.
    ///
    /// # Panics
    ///
    /// On any refusal: a rig that cannot build its node has nothing to assert.
    #[must_use]
    pub fn open(path: &std::path::Path) -> Self {
        Self::open_with_programs(path, &["sh"])
    }

    /// `open` for a rig whose fixture environment ALSO provides the listed
    /// program names, each asked the same `capsule_program_not_in_environment`
    /// question `sh` is.
    ///
    /// # Panics
    ///
    /// On any refusal, as [`Self::open`].
    #[must_use]
    pub fn open_with_programs(path: &std::path::Path, programs: &[&'static str]) -> Self {
        Self::open_with_caps(path, programs, vec!["agent:shell".to_owned()])
    }

    /// [`Self::open_with_programs`] with the registered worker's advertised
    /// capability strings widened beyond `agent:shell` — the fixture rigs
    /// register `agent:<label>` for every label their packs select.
    ///
    /// # Panics
    ///
    /// On any refusal, as [`Self::open`].
    #[must_use]
    pub fn open_with_caps(
        path: &std::path::Path,
        programs: &[&'static str],
        worker_caps: Vec<String>,
    ) -> Self {
        Self::open_with_caps_and_dispatch_limit(path, programs, worker_caps, None)
    }

    /// [`Self::open_with_caps`] with the rig's dispatcher built under
    /// `runtime.max_concurrent_dispatches`'s mechanism — the cap a cell proving
    /// dispatch-admission backpressure needs on the REAL submit path.
    ///
    /// # Panics
    ///
    /// On any refusal, as [`Self::open`].
    #[must_use]
    pub fn open_with_caps_and_dispatch_limit(
        path: &std::path::Path,
        programs: &[&'static str],
        worker_caps: Vec<String>,
        max_concurrent_dispatches: Option<usize>,
    ) -> Self {
        Self::open_node(
            path,
            programs,
            worker_caps,
            max_concurrent_dispatches,
            kata_types::config::ModelReuseMaxAge::Default,
            oci_rig_executor_term(),
            oci_rig_executor_term(),
        )
    }

    /// [`Self::open`] with the stage-cache store carrying `term` as the node's executor
    /// term — what boot installs from `kata_worker::executor_term`. Every other
    /// rig carries [`oci_rig_executor_term`]; re-opening a directory under a different
    /// term is a kata upgrade that changed the fence.
    ///
    /// # Panics
    ///
    /// On any refusal, as [`Self::open`].
    #[must_use]
    pub fn open_with_executor_term(
        path: &std::path::Path,
        term: kata_types::execution_platform::ExecutorTerm,
    ) -> Self {
        Self::open_node(
            path,
            &["sh"],
            vec!["agent:shell".to_owned()],
            None,
            kata_types::config::ModelReuseMaxAge::Default,
            term,
            term,
        )
    }

    /// [`Self::open_with_programs`] with the stage-cache store carrying `bound` as the
    /// node's memoised-spend bound — what boot installs from `[runtime]
    /// model_reuse_max_age_secs`. Every other rig carries the
    /// 7-day default, as a node whose config omits the key does.
    ///
    /// # Panics
    ///
    /// On any refusal, as [`Self::open`].
    #[must_use]
    pub fn open_with_model_reuse_max_age(
        path: &std::path::Path,
        programs: &[&'static str],
        bound: kata_types::config::ModelReuseMaxAge,
    ) -> Self {
        Self::open_node(
            path,
            programs,
            vec!["agent:shell".to_owned()],
            None,
            bound,
            oci_rig_executor_term(),
            oci_rig_executor_term(),
        )
    }

    /// [`Self::open`] with the registered worker STATING `worker_term` — a standalone
    /// `kata-worker` built from another kata, whose fence is not the main's — while the
    /// stage-cache store keeps [`oci_rig_executor_term`]. Placement is unchanged: the
    /// worker still takes every capsule.
    ///
    /// # Panics
    ///
    /// On any refusal, as [`Self::open`].
    #[must_use]
    pub fn open_with_worker_executor_term(
        path: &std::path::Path,
        worker_term: kata_types::execution_platform::ExecutorTerm,
    ) -> Self {
        Self::open_node(
            path,
            &["sh"],
            vec!["agent:shell".to_owned()],
            None,
            kata_types::config::ModelReuseMaxAge::Default,
            oci_rig_executor_term(),
            worker_term,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn open_node(
        path: &std::path::Path,
        programs: &[&'static str],
        worker_caps: Vec<String>,
        max_concurrent_dispatches: Option<usize>,
        model_reuse_max_age: kata_types::config::ModelReuseMaxAge,
        executor_term: kata_types::execution_platform::ExecutorTerm,
        worker_executor_term: kata_types::execution_platform::ExecutorTerm,
    ) -> Self {
        use std::sync::Arc;
        let op_path = path.join("operational.db");
        let store = Arc::new(
            kata_core::store::SqliteWorkflowStore::open(path.join("workflow.db"))
                .expect("the stage-cache store opens")
                .with_model_reuse_max_age(model_reuse_max_age)
                .with_executor_term(executor_term),
        );
        let db = Arc::new(
            kata_core::OperationalDb::open_with_cas(&op_path, store.shared_cas())
                .expect("the operational plane opens"),
        );
        let cas = kata_core::store::cas::CasStore::open(path.join("cas.db"), path.join("cas"))
            .expect("the content store opens");
        let supervisor = Arc::new(kata_transport::WorkerPoolSupervisor::new());
        let (main_side, worker_side) = kata_transport::InProcessTransport::pair(8);
        let domain = db
            .enroll_worker_domain(
                "oci-node-rig",
                kata_types::identity::WorkerMembraneId(ulid::Ulid::new()),
            )
            .expect("the worker enrolls a membrane");
        let main_side = Arc::new(main_side);
        let _peer = supervisor.register_worker_with_effect_domain(
            smol_str::SmolStr::new(OCI_RIG_WORKER),
            Arc::clone(&main_side) as Arc<dyn kata_transport::WorkerTransport>,
            worker_caps,
            rig_worker_containment(),
            *worker_executor_term.digest(),
            domain,
        );
        let dispatcher = crate::dispatcher::Dispatcher::new(
            Arc::clone(&supervisor),
            Arc::new(kata_transport::heartbeat::HeartbeatMonitor::new(
                std::time::Duration::from_secs(30),
                std::time::Duration::from_secs(30),
            )),
            kata_core::InFlightLedger::in_memory(),
        )
        .with_node_environment(kata_core::environment::NodeEnvironment {
            environment: kata_types::execution_contract::EnvironmentId(
                kata_types::primitives::ContentHash::new(OCI_RIG_ENVIRONMENT_ID),
            ),
            platform: kata_types::node_profile::node_platform()
                .expect("the reference host is x86_64-linux")
                .id(),
        })
        .with_execution_lifecycle(crate::execution_lifecycle::ExecutionLifecycleFace::new(
            Arc::clone(&db),
        ))
        .with_program_probe(Arc::new(FixtureProgramProbe(programs.to_vec())));
        let dispatcher = match max_concurrent_dispatches {
            Some(cap) => dispatcher.with_max_concurrent_dispatches(cap),
            None => dispatcher,
        };
        // The same bind `boot.rs` performs on an installed node: without it the
        // ledger writes execution evidence to RAM only, and cells reading the
        // durable `execution_evidence` table see nothing — an installed node's
        // evidence is durable, so the rig's must be too.
        dispatcher
            .ledger()
            .bind_operational(&db)
            .expect("the rig's evidence plane binds to its operational db");
        Self {
            op_path,
            db,
            cas,
            store,
            supervisor,
            dispatcher: Arc::new(dispatcher),
            main_side,
            worker_side: Arc::new(worker_side),
        }
    }

    /// A SECOND `CasStore` handle on this node's `cas.db`/`cas/` — `CasStore`
    /// is not `Clone` (its sqlite connection is exclusive), and the scripted
    /// worker's pump task owns its own, exactly as [`Self::open`]'s separate
    /// `cas` and `store.shared_cas()` connections already coexist.
    ///
    /// # Panics
    ///
    /// On open failure — the rig's CAS exists by construction.
    #[must_use]
    pub fn cas_handle(&self) -> kata_core::store::cas::CasStore {
        let dir = self
            .op_path
            .parent()
            .expect("op_path lives in the node dir");
        kata_core::store::cas::CasStore::open(dir.join("cas.db"), dir.join("cas"))
            .expect("the rig's content store re-opens")
    }

    /// Declare [`OCI_RIG_ENVIRONMENT_ID`] over the fixture manifest and PROMOTE its gc
    /// root — what boot leaves. A no-op when a re-opened node already holds it.
    ///
    /// # Panics
    ///
    /// On any refusal.
    pub fn declare_bound_environment(&self) {
        if self
            .db
            .environment(OCI_RIG_ENVIRONMENT_ID)
            .expect("readable")
            .is_some()
        {
            return;
        }
        let manifest = self
            .cas
            .put_durable(&fixture_environment_manifest_bytes())
            .expect("the manifest publishes");
        self.db
            .declare_environment(
                &kata_core::operational::EnvironmentDeclaration::for_staged_root(
                    OCI_RIG_ENVIRONMENT_ID,
                    &manifest,
                    [0x5C; 32],
                    "pkgs-static-busybox",
                    kata_types::node_profile::node_platform()
                        .expect("the reference host is x86_64-linux")
                        .id()
                        .0
                        .0,
                    "01JZZZZZZZZZZZZZZZZZZZZZE1",
                )
                .expect("the declaration is well formed"),
            )
            .expect("the environment declares");
        self.db
            .promote_environment_root(
                OCI_RIG_ENVIRONMENT_ID,
                chrono::Utc::now().timestamp_millis(),
            )
            .expect("the gc root promotes");
    }

    /// A runner over `program` for `execution`, the program ADMITTED through the
    /// production door (`put_current_program`) and the execution's durable `/work`
    /// head seeded through the production verb — an `oci` execution reaches
    /// dispatch only with a recorded root head, and the rig's twin of the api's
    /// scratch walk is an empty per-execution directory under the node's data
    /// dir, which a re-opened rig re-seeds identically.
    ///
    /// # Panics
    ///
    /// On any refusal.
    #[must_use]
    pub fn runner(
        &self,
        program: &kata_program::execution_program::ExecutionProgram,
        execution: ulid::Ulid,
    ) -> crate::runner::WorkflowRunner {
        self.dispatcher
            .execution_lifecycle()
            .put_current_program(execution, program)
            .expect("the program is retained");
        self.runner_over_admitted(program, execution)
    }

    /// [`Self::runner`] for a `worktree_isolated` program, admitted carrying
    /// `target` — the frozen target an isolated admission must carry (a cell
    /// over a real repository resolves it through its provider). Re-admitting
    /// a reopened rig's execution with the SAME target converges.
    ///
    /// # Panics
    ///
    /// On any refusal.
    #[must_use]
    pub fn runner_with_target(
        &self,
        program: &kata_program::execution_program::ExecutionProgram,
        execution: ulid::Ulid,
        target: kata_types::target::ExecutionTarget,
    ) -> crate::runner::WorkflowRunner {
        self.dispatcher
            .execution_lifecycle()
            .put_current_program_with_target(execution, program, target)
            .expect("the program is retained");
        self.runner_over_admitted(program, execution)
    }

    /// [`Self::runner`] for an execution admitted carrying `invocation` — its
    /// resolved params, say — through the production admission door.
    ///
    /// # Panics
    ///
    /// On any refusal.
    #[must_use]
    pub fn runner_with_invocation(
        &self,
        program: &kata_program::execution_program::ExecutionProgram,
        execution: ulid::Ulid,
        invocation: &crate::execution_program_store::ExecutionInvocation,
    ) -> crate::runner::WorkflowRunner {
        self.dispatcher
            .execution_lifecycle()
            .admit_current_execution(execution, program, invocation)
            .expect("the program and invocation are admitted");
        self.runner_over_admitted(program, execution)
    }

    /// The runner over an execution already admitted, its scratch head seeded.
    fn runner_over_admitted(
        &self,
        program: &kata_program::execution_program::ExecutionProgram,
        execution: ulid::Ulid,
    ) -> crate::runner::WorkflowRunner {
        self.seed_scratch_head(execution);
        crate::runner::WorkflowRunner::new_from_program(
            program.clone(),
            std::sync::Arc::clone(&self.dispatcher),
            execution,
        )
        .expect("the runner builds")
        .with_cache_store(std::sync::Arc::clone(&self.store))
    }

    /// Seed `execution`'s durable `/work` head the way admission owes an `oci`
    /// execution — the production verb over an EMPTY per-execution scratch dir
    /// under the node's data dir (the rig materializes no workspace), which a
    /// re-opened rig re-seeds identically. The door for cells that admit through
    /// `put_current_program` directly rather than [`Self::runner`].
    ///
    /// # Panics
    ///
    /// On any refusal.
    pub fn seed_scratch_head(&self, execution: ulid::Ulid) {
        // Admission-once: a runner built over an execution whose head is
        // already recorded is a RESUME — the recorded tree is authoritative
        // and re-deriving a seed over it reads as a second input under one
        // execution (`work_tree_head_divergent`). Cells that simulate a
        // crash by building a second `runner` after members applied real
        // `/work` deltas depend on this.
        if self
            .db
            .execution_work_tree_head(execution)
            .expect("the head row reads")
            .is_some()
        {
            return;
        }
        let scratch = self
            .op_path
            .parent()
            .expect("the node dir")
            .join("rig-scratch")
            .join(execution.to_string());
        std::fs::create_dir_all(&scratch).expect("the rig's scratch dir");
        kata_core::work_tree::publish_scratch_tree_head(&self.db, &self.cas, execution, &scratch)
            .expect("the root /work head seeds");
    }

    /// The resolved directive `stage`'s own sandbox profile produces for `execution`,
    /// through the production resolver.
    ///
    /// # Panics
    ///
    /// On an absent stage or a resolver refusal.
    pub async fn directive(
        &self,
        program: &kata_program::execution_program::ExecutionProgram,
        stage: &str,
        execution: ulid::Ulid,
    ) -> Option<kata_types::sandbox::SandboxDirective> {
        let stage = program
            .stages
            .get(&kata_types::workflow::StageId(smol_str::SmolStr::new(
                stage,
            )))
            .expect("the stage is present");
        self.dispatcher
            .resolve_sandbox(
                stage.policies.sandbox.as_ref(),
                &program.sandbox_profiles,
                ulid::Ulid::new(),
                execution,
                stage.should_confine_to_declared_inputs(),
                stage.is_content_cacheable(),
            )
            .await
            .expect("the stage's profile resolves")
    }
}

/// The `/work` delta a stub worker reports for the attempt on `occurrence`:
/// `Some(empty)` — the frame's "the stage changed nothing" — when the
/// occurrence was bound to a walked `/work` tree, `None` when it was not, which
/// is the `Some`/`None` law the real worker's `capsule_execution` follows. The
/// base is resolved off the OCCURRENCE's recorded `work_tree_artifact_id` and
/// the `artifacts` row — never off the capsule object, so a corrupt capsule
/// fixture cannot crash the stub on its way to the verdict under test.
///
/// # Panics
///
/// On any store failure or a `/work` artifact row the seeding did not write.
#[cfg(any(test, feature = "test-support"))]
pub fn stub_work_delta(
    db: &kata_core::OperationalDb,
    cas: &kata_core::store::cas::CasStore,
    occurrence: kata_types::execution_contract::OccurrenceId,
) -> Option<kata_types::execution_contract::ArtifactRef> {
    use kata_types::execution_contract::{ArtifactPrivacy, ArtifactRef};

    let work_tree = db
        .occurrence(occurrence.0.0)
        .expect("the occurrence reads")
        .expect("the occurrence row exists — the dispatch wrote it")
        .work_tree_artifact_id?;
    let row = db
        .artifact(work_tree)
        .expect("the artifact row reads")
        .expect("the /work artifact row exists — the authorization declared it");
    let base = ArtifactRef::new(
        kata_types::primitives::FixedBytes(row.object_id),
        row.size_bytes,
        row.privacy,
    );
    let delta = kata_types::tree_delta::TreeDelta::new(base, Vec::new())
        .expect("an empty delta over the mapped base");
    let receipt = cas
        .put_durable(&delta.delta_bytes().expect("the delta encodes"))
        .expect("the delta publishes");
    Some(ArtifactRef::new(
        receipt.object_id(),
        receipt.size(),
        ArtifactPrivacy::Private,
    ))
}

// ============================================================================
// The scripted capsule worker, scripted by a `MockAgentBackend` queue
// ============================================================================
//
// A queue of `kata_test_utils::MockResponse` drives what each delivered capsule
// frame resolves to, and a shared counter is the "the model was not invoked"
// observable — a replayed or cache-hit stage dispatches no frame, so the
// counter at 0 is the proof `calls()` gives.
//
// The worker is IN-PROCESS but goes over the real wire: it reads
// `DispatchFrame`s off the rig's worker end and answers with `send_result`, so
// the spawned [`crate::reactor::ResultReactor`] adjudicates exactly what a
// remote worker's message would.
//
// The mapping, deliberately:
//
// * `Text`/`Json`/`Default` → `CompletedCapsule` whose
//   `agent.response` (agent capsule) or `stdout` (command capsule) blob carries
//   the bytes the stage's output contract is judged against.
// * `Echo`/`EchoModelHint` read the delivered capsule's spec from CAS — what
//   the turn actually carried, not what the caller hoped it carried.
// * `Sleep` delays the answer by wall clock, holding the worker; `Rendezvous`
//   delays it until the barrier fills, on its own task so later frames can be
//   its parties (`scripted_capsule_pump`).
// * `Hang` → `Failed{verdict: PerformedButFailed}` — an agent process that ran
//   and errored.

/// The trivial `/out` tree a scripted completion reports — one `result.txt`
/// member — the same body the capsule cells' `publish_result` builds.
#[cfg(any(test, feature = "test-support"))]
fn stub_result_tree(
    cas: &kata_core::store::cas::CasStore,
) -> kata_types::execution_contract::ArtifactRef {
    use kata_types::execution_contract::{ArtifactPrivacy, ArtifactRef};
    use kata_types::tree_artifact::{TreeEntry, TreeEntryMode, TreeManifest, TreeNode, TreePath};

    let member = cas
        .put_durable(b"done\n")
        .expect("the result member publishes");
    let manifest = TreeManifest::new(vec![TreeEntry {
        path: TreePath::new("result.txt").expect("a manifest-legal path"),
        node: TreeNode::File {
            mode: TreeEntryMode::Regular,
            object: member.object_id(),
            size_bytes: member.size(),
        },
    }])
    .expect("the result manifest builds");
    let receipt = cas
        .put_durable(&manifest.manifest_bytes().expect("the manifest encodes"))
        .expect("the result tree publishes");
    ArtifactRef::new(
        receipt.object_id(),
        receipt.size(),
        ArtifactPrivacy::Private,
    )
}

/// A CAS-published blob the scripted completion names.
#[cfg(any(test, feature = "test-support"))]
fn publish_blob(
    cas: &kata_core::store::cas::CasStore,
    bytes: &[u8],
) -> kata_types::execution_contract::ArtifactRef {
    use kata_types::execution_contract::{ArtifactPrivacy, ArtifactRef};

    let receipt = cas.put_durable(bytes).expect("the blob publishes");
    ArtifactRef::new(
        receipt.object_id(),
        receipt.size(),
        ArtifactPrivacy::Private,
    )
}

/// The test-facing half of [`OciNodeRig::scripted_worker`]: the queue and the
/// invocation counter, deliberately the `MockAgentBackend` API shape —
/// `push`/`pop`/`len`/`is_empty`/`calls`/`calls_handle` — so a cell swapped onto
/// the `oci` builders scripts and asserts with the same names. Wrapping the
/// backend (rather than duplicating its state) keeps `MockResponse` the ONE
/// scripting enum and the counters the same cells.
#[cfg(any(test, feature = "test-support"))]
#[derive(Debug)]
pub struct ScriptedWorkerHandle {
    backend: kata_test_utils::MockAgentBackend,
    /// Every capsule frame the pump answered, as `(stage_name, prompt)` — the
    /// capsule-plane observable for "what the stage was actually told". Shared
    /// `Arc` so the pump's clone records into the same log.
    delivered: std::sync::Arc<std::sync::Mutex<Vec<(String, String)>>>,
}

#[cfg(any(test, feature = "test-support"))]
impl ScriptedWorkerHandle {
    /// An empty queue — `pop` serves `MockResponse::Default` until `push`ed.
    #[must_use]
    pub fn new() -> Self {
        Self {
            backend: kata_test_utils::MockAgentBackend::new(),
            delivered: std::sync::Arc::default(),
        }
    }

    /// Adopt an existing `MockAgentBackend` — a rig built from a pre-scripted
    /// backend passes it through verbatim, queue, counter and overlays
    /// included.
    #[must_use]
    pub fn from_backend(backend: kata_test_utils::MockAgentBackend) -> Self {
        Self {
            backend,
            delivered: std::sync::Arc::default(),
        }
    }

    /// Append a single response to the tail of the queue.
    pub fn push(&self, response: kata_test_utils::MockResponse) {
        self.backend.push(response);
    }

    /// Pop the next scripted response, `MockResponse::Default` when empty.
    #[must_use]
    pub fn pop(&self) -> kata_test_utils::MockResponse {
        self.backend.pop()
    }

    /// Queued-but-unconsumed responses.
    #[must_use]
    pub fn len(&self) -> usize {
        self.backend.len()
    }

    /// True when no responses are queued.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.backend.is_empty()
    }

    /// Capsule frames answered so far — the `oci` spelling of "the model was
    /// invoked this many times".
    #[must_use]
    pub fn calls(&self) -> usize {
        self.backend.calls()
    }

    /// A shared handle on the invocation counter, taken before the worker
    /// handle moves.
    #[must_use]
    pub fn calls_handle(&self) -> std::sync::Arc<std::sync::atomic::AtomicUsize> {
        self.backend.calls_handle()
    }

    /// `(stage_name, prompt)` for every capsule frame the pump answered —
    /// the delivered-prompt read the scripted plane exposes.
    #[must_use]
    pub fn delivered(&self) -> Vec<(String, String)> {
        self.delivered.lock().unwrap().clone()
    }

    /// The prompt the capsule carried for `stage`, or `None` when it never
    /// dispatched (command capsules record an empty prompt).
    #[must_use]
    pub fn delivered_prompt(&self, stage: &str) -> Option<String> {
        self.delivered
            .lock()
            .unwrap()
            .iter()
            .rev()
            .find(|(name, _)| name == stage)
            .map(|(_, prompt)| prompt.clone())
    }
}

#[cfg(any(test, feature = "test-support"))]
impl Default for ScriptedWorkerHandle {
    fn default() -> Self {
        Self::new()
    }
}

/// `&stack.mock` derefs to the wrapped `MockAgentBackend`, so every helper
/// written against `&MockAgentBackend` (`push_verdict`, the per-file `push_*`s)
/// scripts the `oci` worker without a signature change.
/// Consuming `with_*` builders stay unreachable — a `&` receiver cannot move.
#[cfg(any(test, feature = "test-support"))]
impl std::ops::Deref for ScriptedWorkerHandle {
    type Target = kata_test_utils::MockAgentBackend;
    fn deref(&self) -> &Self::Target {
        &self.backend
    }
}

/// The pump: read a capsule frame, count it, answer it from the scripted queue,
/// deliver over `send_result`. The worker end dies when its half of the
/// transport closes (the rig's drop) — the JoinHandle is `abort`ed by
/// `Stack::retire_projection_writers` like any other rig task.
///
/// # One frame at a time, except a rendezvous
///
/// Every arm but one is answered on the pump, in arrival order: a `Sleep` holds
/// the whole worker, and the frames behind it wait in the transport, dispatched
/// and unanswered. A `Rendezvous` frame is answered on its own task instead,
/// because its barrier's other parties may be LATER frames — a pump parked in
/// `wait` could never receive them, so frames sharing one barrier would deadlock
/// the worker instead of proving they were in flight together. Those tasks live
/// in a `JoinSet` this future owns: aborting the pump aborts every rendezvous
/// still waiting, and a panic in one is re-raised on the pump before it takes
/// its next frame.
///
/// `node_dir` is the `TempDir` the pump's `db`/`cas` paths live under, held
/// FOR THE TASK'S LIFE — the pump's and every rendezvous task's: a dropped
/// `JoinHandle` detaches the task rather than stopping it, so the rig's own ref
/// cannot order the directory's removal after this task's last poll — the task
/// has to carry that ordering itself.
#[cfg(any(test, feature = "test-support"))]
async fn scripted_capsule_pump(
    worker_side: std::sync::Arc<kata_transport::InProcessTransport>,
    db: std::sync::Arc<kata_core::OperationalDb>,
    cas: kata_core::store::cas::CasStore,
    node_dir: std::sync::Arc<tempfile::TempDir>,
    script: ScriptedWorkerHandle,
) {
    use kata_test_utils::MockResponse;
    use kata_transport::types::{DispatchFrame, StageCheckpoint, WorkerMessage};
    use std::sync::Arc;

    let cas = Arc::new(cas);
    let script = Arc::new(script);
    let calls = script.calls_handle();
    let mut rendezvous = tokio::task::JoinSet::new();
    loop {
        while let Some(answered) = rendezvous.try_join_next() {
            if let Err(error) = answered
                && error.is_panic()
            {
                std::panic::resume_unwind(error.into_panic());
            }
        }
        let frame = match worker_side.recv_frame().await {
            Ok(DispatchFrame::Capsule(frame)) => *frame,
            Err(_) => return,
        };
        calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        // A real capsule worker reports its start before it runs — sequence 0
        // folds the attempt `running` with `started_at_ms`, the anchor both
        // deadline sweeps and the `running` stop path read.
        if worker_side
            .send_result(WorkerMessage::Checkpoint(StageCheckpoint::capsule_started(
                &frame,
            )))
            .await
            .is_err()
        {
            return;
        }
        // The delay arms resolve BEFORE the answer is built so the wait shapes
        // the delivery timing.
        match script.pop() {
            MockResponse::Rendezvous(barrier) => {
                let worker_side = Arc::clone(&worker_side);
                let db = Arc::clone(&db);
                let cas = Arc::clone(&cas);
                let script = Arc::clone(&script);
                let node_dir = Arc::clone(&node_dir);
                rendezvous.spawn(async move {
                    let _node_dir = node_dir;
                    barrier.wait().await;
                    let response = MockResponse::Rendezvous(barrier);
                    let message = scripted_frame_answer(&db, &cas, &frame, &script, response);
                    // A closed result channel is the rig's teardown: no reader is
                    // left to answer, exactly as the pump's own send returns.
                    let _ = worker_side.send_result(message).await;
                });
            }
            response => {
                if let MockResponse::Sleep(ms) = &response {
                    tokio::time::sleep(std::time::Duration::from_millis(*ms)).await;
                }
                let message = scripted_frame_answer(&db, &cas, &frame, &script, response);
                if worker_side.send_result(message).await.is_err() {
                    return;
                }
            }
        }
    }
}

/// Map one popped `MockResponse` onto the frame's `WorkerMessage` — the whole
/// `MockResponse` → `CompletedCapsule`/`Failed` truth table lives here.
#[cfg(any(test, feature = "test-support"))]
fn scripted_frame_answer(
    db: &kata_core::OperationalDb,
    cas: &kata_core::store::cas::CasStore,
    frame: &kata_transport::types::CapsuleAssignment,
    script: &ScriptedWorkerHandle,
    response: kata_test_utils::MockResponse,
) -> kata_transport::types::WorkerMessage {
    use kata_test_utils::MockResponse;
    use kata_transport::types::WorkerMessage;
    use kata_types::effect::DeliveryFailureProvenance;

    let fence = kata_transport::types::AttemptFence::echoing_capsule(frame);
    match response {
        MockResponse::Hang => WorkerMessage::Failed {
            assignment_id: frame.attempt_id,
            reason: "mock agent hang — simulated backend failure".to_owned(),
            verdict: DeliveryFailureProvenance::PerformedButFailed,
            provider_failure: None,
            usage: None,
            fence,
        },
        MockResponse::ProviderRefused => WorkerMessage::Failed {
            assignment_id: frame.attempt_id,
            reason: "mock provider refusal — the model request was refused".to_owned(),
            verdict: DeliveryFailureProvenance::ProvenNotPerformed,
            provider_failure: Some(kata_types::effect::ProviderFailureClass::Refused),
            usage: None,
            fence,
        },
        other => {
            // The completion arms — content and echoes — all answer
            // CompletedCapsule; only WHERE the bytes land differs (agent
            // report vs command stdout).
            let capsule_bytes = cas
                .get(&frame.capsule.object)
                .expect("the CAS reads")
                .expect("the delivered capsule object is published");
            let capsule: kata_types::execution_contract::Capsule =
                serde_json::from_slice(&capsule_bytes).expect("the capsule decodes");
            let agent_turn = match capsule.process() {
                kata_types::execution_contract::CapsuleProcess::Agent(turn) => Some(turn.clone()),
                kata_types::execution_contract::CapsuleProcess::Command { .. } => None,
            };
            // Log the delivered stage + prompt BEFORE mapping the response —
            // the log is the scripted plane's "what was it told" observable.
            {
                let stage = db
                    .recovered_attempt(frame.attempt_id)
                    .ok()
                    .flatten()
                    .map_or_else(|| "<unknown>".to_owned(), |attempt| attempt.row.stage_id);
                let prompt = agent_turn
                    .as_ref()
                    .map(|turn| {
                        String::from_utf8_lossy(&capsule_prompt_bytes(db, cas, turn)).into_owned()
                    })
                    .unwrap_or_default();
                script.delivered.lock().unwrap().push((stage, prompt));
            }

            let content: Vec<u8> = match &other {
                MockResponse::Text(text) => text.clone().into_bytes(),
                MockResponse::Json(value) => {
                    serde_json::to_vec(value).expect("the scripted JSON encodes")
                }
                MockResponse::Echo => {
                    if let Some(turn) = &agent_turn {
                        capsule_prompt_bytes(db, cas, turn)
                    } else {
                        panic!(
                            "mock_response_echo_needs_an_agent_capsule: `Echo` answers \
                                     with the delivered prompt, and a Command capsule carries none"
                        )
                    }
                }
                MockResponse::EchoModelHint => agent_turn
                    .as_ref()
                    .and_then(|turn| turn.model.as_ref().map(ToString::to_string))
                    .unwrap_or_else(|| "<none>".to_owned())
                    .into_bytes(),
                MockResponse::Sleep(_) | MockResponse::Rendezvous(_) | MockResponse::Default => {
                    b"mock response".to_vec()
                }
                MockResponse::Hang | MockResponse::ProviderRefused => {
                    unreachable!("the failure arms returned above")
                }
            };
            let work_delta = stub_work_delta(db, cas, frame.occurrence_id);

            let usage = script.backend.scripted_usage();
            let agent = agent_turn.map(|turn| kata_types::agent::AgentTurnReport {
                response: publish_blob(cas, &content),
                usage,
                // The report claims the adapter the capsule's turn DECLARED —
                // adoption checks the claim against the capsule, and a scripted
                // worker inventing a different one would red on the wrong fact.
                adapter: turn.adapter,
                model_reported: None,
                // The scripted vendor's own word for the end of its turn.
                stop_reason: Some(SmolStr::new("end_turn")),
                session_evidence: Some(publish_blob(
                    cas,
                    b"{\"events\":[],\"events_dropped\":0,\"scratch_commits\":[]}",
                )),
            });
            let stdout = if agent.is_none() && !content.is_empty() {
                publish_blob(cas, &content)
            } else {
                publish_blob(cas, b"")
            };
            WorkerMessage::CompletedCapsule {
                attempt_id: frame.attempt_id,
                fence,
                result: stub_result_tree(cas),
                work_delta,
                exit_code: Some(0),
                stdout,
                stderr: publish_blob(cas, b""),
                capture_exceeded: false,
                agent,
                provenance:
                    kata_types::execution_provenance::ExecutionProvenance::local_oci_runtime(
                        "scripted capsule worker",
                    ),
                egress_refusals: vec![],
            }
        }
    }
}

/// The prompt blob an agent turn's spec names — resolved through the
/// `artifacts` row, never off the in-memory contract.
#[cfg(any(test, feature = "test-support"))]
fn capsule_prompt_bytes(
    db: &kata_core::OperationalDb,
    cas: &kata_core::store::cas::CasStore,
    turn: &kata_types::execution_contract::AgentTurnSpec,
) -> Vec<u8> {
    let row = db
        .artifact(turn.prompt.0.0)
        .expect("the prompt's artifact row reads")
        .expect("the prompt's artifact row exists");
    cas.get(&kata_types::primitives::FixedBytes(row.object_id))
        .expect("the CAS reads")
        .expect("the prompt object is published")
}

#[cfg(any(test, feature = "test-support"))]
impl OciNodeRig {
    /// Spawn the scripted capsule worker on this rig's worker end: every
    /// delivered `DispatchFrame::Capsule` is answered from the returned
    /// handle's queue, over `send_result` — the real transport — to the spawned
    /// reactor. The handle is the `Stack::mock` twin: script it like a
    /// `MockAgentBackend`.
    ///
    /// `node_dir` is the `TempDir` this rig was opened under: the pump
    /// publishes result objects through the CAS inside it, so the task holds a
    /// ref for its whole life and the directory cannot vanish between the
    /// caller's last use and the task's last poll.
    ///
    /// # Panics
    ///
    /// On a delivery that is not a capsule — `DispatchFrame` has no second arm,
    /// so the pump's destructure is a profile regression guard, never a
    /// scripting shape.
    #[must_use]
    pub fn scripted_worker(
        &self,
        node_dir: std::sync::Arc<tempfile::TempDir>,
    ) -> (ScriptedWorkerHandle, tokio::task::JoinHandle<()>) {
        self.scripted_worker_with(kata_test_utils::MockAgentBackend::new(), node_dir)
    }

    /// [`Self::scripted_worker`] adopting a pre-scripted backend — the
    /// `with_responses` fixtures pass theirs through.
    #[must_use]
    pub fn scripted_worker_with(
        &self,
        backend: kata_test_utils::MockAgentBackend,
        node_dir: std::sync::Arc<tempfile::TempDir>,
    ) -> (ScriptedWorkerHandle, tokio::task::JoinHandle<()>) {
        Self::scripted_worker_on(
            std::sync::Arc::clone(&self.worker_side),
            std::sync::Arc::clone(&self.db),
            self.cas_handle(),
            backend,
            node_dir,
        )
    }

    /// `scripted_worker_with` over node pieces assembled OUTSIDE
    /// [`Self::open_with_caps`]: the api suite's executor builders bind their
    /// dispatcher to a caller's ledger, operational face, or
    /// workspace-manager choice the fixed constructor cannot express, so they
    /// pass that dispatcher's registered worker side, the SAME operational db
    /// the dispatcher's face owns (the pump reads attempt rows and capsule
    /// prompts through it), and a `CasStore` handle on the store the executor
    /// publishes through. `node_dir` is the `TempDir` those paths live under,
    /// held by the pump task for its life — see [`Self::scripted_worker`].
    ///
    /// # Panics
    ///
    /// On a delivery that is not a capsule, exactly as
    /// [`Self::scripted_worker`].
    #[must_use]
    pub fn scripted_worker_on(
        worker_side: std::sync::Arc<kata_transport::InProcessTransport>,
        db: std::sync::Arc<kata_core::OperationalDb>,
        cas: kata_core::store::cas::CasStore,
        backend: kata_test_utils::MockAgentBackend,
        node_dir: std::sync::Arc<tempfile::TempDir>,
    ) -> (ScriptedWorkerHandle, tokio::task::JoinHandle<()>) {
        let handle = ScriptedWorkerHandle::from_backend(backend);
        let pump = tokio::spawn(scripted_capsule_pump(
            worker_side,
            db,
            cas,
            node_dir,
            ScriptedWorkerHandle {
                backend: backend_clone_for_pump(&handle),
                delivered: std::sync::Arc::clone(&handle.delivered),
            },
        ));
        (handle, pump)
    }
}

/// The pump needs its own handle onto the same queue/counter — the
/// `MockAgentBackend`'s interior `Arc`/`Mutex` make a fresh handle cheap and
/// exactly shared. `MockAgentBackend` is not `Clone` (the queue state would be
/// ambiguous under it), so this reconstructs one over the same internals.
#[cfg(any(test, feature = "test-support"))]
fn backend_clone_for_pump(handle: &ScriptedWorkerHandle) -> kata_test_utils::MockAgentBackend {
    handle.backend.share_state()
}

/// The capability strings a scripted rig's worker registers for `labels` —
/// `agent:<label>` for exactly the labels given, plus `agent:shell`, as a
/// configured fleet advertises them. No placement, preflight or agent-run read
/// demands them. A workspace effect or forge export
/// is performed by the main and demands no label, so no rig's fixed label
/// list carries `workspace_effect`. `extra` capabilities are added to the set.
#[cfg(any(test, feature = "test-support"))]
#[must_use]
pub fn rig_worker_caps(labels: &[String], extra: &[String]) -> Vec<String> {
    let mut caps: Vec<String> = labels
        .iter()
        .map(|label| format!("agent:{label}"))
        .chain(extra.iter().cloned())
        .collect();
    caps.push("agent:shell".to_owned());
    caps.sort();
    caps.dedup();
    caps
}

/// The program names the fixture environment answers `executable` for —
/// `"sh"` (the `SHELL_PROGRAM` rule) plus each agent label.
/// `FixtureProgramProbe` keys on `&'static str`, so callers leak dynamic
/// labels with `Box::leak` — a rig lives for one test, the leak is the
/// process's.
#[cfg(any(test, feature = "test-support"))]
#[must_use]
pub fn rig_program_names(labels: &[String]) -> Vec<&'static str> {
    let mut names = vec!["sh"];
    names.extend(
        labels
            .iter()
            .map(|label| &*Box::leak(label.clone().into_boxed_str())),
    );
    names
}
