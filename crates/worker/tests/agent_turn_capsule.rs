//! The `CapsuleProcess::Agent` arm's WHOLE composition, host-free: the real
//! `NanocodeAdapter` runs a turn against a mock model provider over the
//! in-process toolhost double as the capsule's init, launched through a
//! `InteractivePlacement` double — so the launch / open / prompt / outcome / close /
//! teardown / publish pipeline is exercised end to end without a container.
//!
//! External oracles, per cell: the response bytes are read out of the rig's
//! CAS by their published ref, the attempt root's disposition is read off the
//! filesystem, and the refusal classes are the composition's own verdicts
//! against `DeliveryFailureProvenance`.

use kata_agent::adapter::InteractiveProcess;
use kata_agent::resource_bounds::TeardownOutcome;
use kata_core::store::cas::CasStore;
use kata_transport::types::{CapsuleAssignment, CapsuleRef, TraceContext, WorkerMessage};
use kata_types::effect::DeliveryFailureProvenance;
use kata_types::execution_contract::OccurrenceId;
use kata_types::execution_contract::{
    AgentTurnSpec, ArtifactPrivacy, ArtifactRef, Capsule, CapsuleBudgets, CapsuleNetwork,
    CapsuleProcess, GuestAccess, GuestMapping, GuestPath, PlatformRef, PreparedActionId,
};
use kata_types::execution_contract::{ArtifactId, EnvironmentId};
use kata_types::primitives::FixedBytes;
use kata_types::tree_artifact::TreeManifest;
use kata_worker::capsule_execution::{CapsuleExecution, execute_capsule_frame};
use kata_worker::interactive_capsule::{InteractivePlacement, InteractiveTeardown};
use kata_worker::materialize::TreeResolver;
use kata_worker::oci_driver::{OciDriveRefusal, OciStageOutput, OciStageRequest};
use kata_worker::work_delta::MaterializationSnapshot;

#[path = "../../agent-nanocode/tests/fixtures/mock_provider.rs"]
#[allow(dead_code)]
mod mock_provider;
#[path = "../../agent-nanocode/tests/fixtures/quickjs_threads.rs"]
#[allow(dead_code)]
mod quickjs_threads;
#[path = "../../agent-nanocode/tests/fixtures/toolhost_double.rs"]
#[allow(dead_code)]
mod toolhost_double;

// The production registry installs kata's Code Mode limits, which run each
// cell in an interpreter process: this binary, re-executed.
kata_code_mode_host::interpreter_entry!();

static AGENT_ADAPTERS: std::sync::LazyLock<
    kata_agent::adapter::capsule_registry::StaticAgentAdapterRegistry,
> = std::sync::LazyLock::new(kata_worker::adapter_registry::production);

// ---------------------------------------------------------------------------
// The rig — the same CAS + directory shape capsule_worker_context's carries
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
    fn reader(&self) -> kata_worker::materialize::LocalCasBlobSource {
        kata_worker::materialize::LocalCasBlobSource::open(
            &self.dir.path().join("cas.db"),
            &self.dir.path().join("cas"),
        )
        .expect("the store opens read-only")
    }

    /// The prompt's durable artifact: published Private, resolved by id.
    fn publish_prompt(&self, text: &str) -> ArtifactId {
        let durable = self
            .cas
            .put_durable(text.as_bytes())
            .expect("the prompt publishes");
        ArtifactRef::new(
            durable.object_id(),
            durable.size(),
            ArtifactPrivacy::Private,
        )
        .id()
    }
}

// ---------------------------------------------------------------------------
// The doubles — the capsule's init is the in-process toolhost double; only the
// container is faked.
// ---------------------------------------------------------------------------

/// The teardown half of the fake placement — no cgroup exists, so the verdict
/// is the Confirmed a real empty subtree reports.
struct FakeTeardown {
    attempt_root: std::path::PathBuf,
    owned_root: Option<kata_worker::attempt_root::OwnedAttemptRoot>,
}

#[async_trait::async_trait]
impl InteractiveTeardown for FakeTeardown {
    fn attempt_root(&self) -> &std::path::Path {
        &self.attempt_root
    }

    fn container_id(&self) -> &'static str {
        "fake-vendor"
    }

    fn work_snapshot(&self) -> Option<&MaterializationSnapshot> {
        None
    }

    fn take_attempt_root(&mut self) -> Option<kata_worker::attempt_root::OwnedAttemptRoot> {
        self.owned_root.take()
    }

    fn take_egress(&mut self) -> Option<kata_worker::egress_proxy::EgressProxy> {
        None
    }

    async fn teardown(self: Box<Self>) -> TeardownOutcome {
        INJECTED_TEARDOWN
            .lock()
            .expect("the teardown injector is unpoisoned")
            .take()
            .unwrap_or(TeardownOutcome::Confirmed {
                probe: kata_agent::resource_bounds::TeardownProbe::CgroupPopulation,
                elapsed_ms: 0,
            })
    }
}

static INJECTED_TEARDOWN: std::sync::Mutex<Option<TeardownOutcome>> = std::sync::Mutex::new(None);

// ---------------------------------------------------------------------------
// The planes — the two artifacts the composition resolves by id
// ---------------------------------------------------------------------------

/// A [`TreeResolver`] answering the work tree's manifest AND the prompt's ref —
/// the two lookups `execute_agent_turn` makes by artifact id.
struct FixtureTrees {
    tree: ArtifactId,
    refs: Vec<(ArtifactId, ArtifactRef)>,
}

impl TreeResolver for FixtureTrees {
    fn tree_manifest(&self, artifact: ArtifactId) -> kata_types::KataResult<TreeManifest> {
        assert_eq!(artifact, self.tree, "the fixture maps one tree manifest");
        TreeManifest::new(Vec::new())
    }

    fn tree_reference(&self, artifact: ArtifactId) -> kata_types::KataResult<ArtifactRef> {
        self.refs
            .iter()
            .find(|(id, _)| *id == artifact)
            .map(|(_, reference)| reference.clone())
            .ok_or_else(|| {
                kata_types::KataError::Validation(format!(
                    "fixture resolver: artifact {} is unmapped",
                    artifact.0
                ))
            })
    }
}

struct FixedIndex(Option<kata_worker::plane_index::EnvironmentClaim>);

impl kata_worker::plane_index::EnvironmentIndex for FixedIndex {
    fn environment_claim(
        &self,
        _environment: EnvironmentId,
    ) -> kata_types::KataResult<Option<kata_worker::plane_index::EnvironmentClaim>> {
        Ok(self.0)
    }
}

struct FixedProbe(bool);

impl kata_worker::materialize::StorePathProbe for FixedProbe {
    fn present(
        &self,
        _path: &kata_types::nix_environment::StorePath,
    ) -> kata_types::KataResult<bool> {
        Ok(self.0)
    }
}

fn publish_manifest(rig: &Rig) -> (EnvironmentId, kata_worker::plane_index::EnvironmentClaim) {
    use kata_types::nix_environment::{
        ClosureEntry, IntegrityPolicy, NarVerification, NixEnvironmentManifest, Provenance,
        RetentionClass, RetentionIntent,
    };
    let store_path = kata_types::nix_environment::StorePath::new(
        "/nix/store/0000000000000000000000000000000a-bash-5.2",
    )
    .expect("a legal store path");
    let manifest = NixEnvironmentManifest::new(
        "agent-turn-fixture",
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
    .expect("the manifest is well formed");
    let bytes = manifest.manifest_bytes().expect("manifest bytes");
    let durable = rig.cas.put_durable(&bytes).expect("the manifest publishes");
    let claim = kata_worker::plane_index::ObjectClaim {
        object: durable.object_id(),
        size_bytes: durable.size(),
    };
    // The environment id is the BYTES' OWN CAS ADDRESS — the same derivation
    // `declare_environment` uses; see the sibling fixture's note about reaching
    // it through `environment_ref`, never restating it.
    let artifact = ArtifactId(kata_types::cache::cas_address_for_canonical_bytes(&bytes).hash());
    (
        manifest.environment_ref(artifact).id(),
        kata_worker::plane_index::EnvironmentClaim {
            manifest: claim,
            released: false,
            root_promoted: true,
        },
    )
}

fn empty_tree(rig: &Rig) -> (ArtifactId, ArtifactRef) {
    let manifest = TreeManifest::new(Vec::new()).expect("the empty manifest");
    let bytes = manifest.manifest_bytes().expect("manifest bytes");
    let durable = rig
        .cas
        .put_durable(&bytes)
        .expect("the empty tree publishes");
    let reference = ArtifactRef::new(durable.object_id(), durable.size(), ArtifactPrivacy::Public);
    (reference.id(), reference)
}

/// The fixture's `nanocode_openai` capsule, declaring `env:KATA_FIXTURE_TOKEN`
/// ([`fixture_credentials`] sets it), so a cell's refusal is the one it plants
/// and not the credential load's.
fn agent_capsule(
    occurrence: OccurrenceId,
    environment: EnvironmentId,
    tree: ArtifactId,
    prompt: ArtifactId,
) -> Capsule {
    agent_capsule_with(
        occurrence,
        environment,
        tree,
        prompt,
        kata_types::agent::AdapterKind::NanocodeOpenai,
        Some(credential_ref(
            kata_types::metering::CredentialMode::ApiKey,
            kata_types::execution_contract::CredentialSource::EnvVar {
                var: smol_str::SmolStr::new("KATA_FIXTURE_TOKEN"),
            },
        )),
        Some("gpt-6-luna".into()),
    )
}

/// A credential source whose environment sets `KATA_FIXTURE_TOKEN`, the
/// variable [`agent_capsule`] declares.
fn fixture_credentials() -> kata_worker::agent_credential::AgentCredentialSource {
    kata_worker::agent_credential::AgentCredentialSource::for_test(
        std::collections::BTreeMap::from([(
            "KATA_FIXTURE_TOKEN".to_owned(),
            "sk-fixture-token".to_owned(),
        )]),
    )
}

/// The same fixture capsule, with the adapter and credential reference the
/// credential cells need to vary.
fn agent_capsule_with(
    occurrence: OccurrenceId,
    environment: EnvironmentId,
    tree: ArtifactId,
    prompt: ArtifactId,
    adapter: kata_types::agent::AdapterKind,
    credential: Option<kata_types::execution_contract::TurnCredentialRef>,
    model: Option<smol_str::SmolStr>,
) -> Capsule {
    agent_capsule_budgeted(
        occurrence,
        environment,
        tree,
        prompt,
        adapter,
        credential,
        model,
        30_000,
    )
}

/// `agent_capsule_with` with the wall clock under test — the timeout cell's
/// door, since a deadline that cannot be shortened is a deadline a cell
/// cannot watch fire.
fn agent_capsule_budgeted(
    occurrence: OccurrenceId,
    environment: EnvironmentId,
    tree: ArtifactId,
    prompt: ArtifactId,
    adapter: kata_types::agent::AdapterKind,
    credential: Option<kata_types::execution_contract::TurnCredentialRef>,
    model: Option<smol_str::SmolStr>,
    wall_time_ms: u64,
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
            FixedBytes(*blake3::hash(b"agent-turn-capsule").as_bytes()),
        )
        .id(),
        vec![mapping("/work"), mapping("/out"), mapping("/tmp")],
        CapsuleProcess::Agent(AgentTurnSpec {
            adapter,
            model,
            reasoning_effort: None,
            output_schema: None,
            prompt,
            credential,
            env: std::collections::BTreeMap::new(),
        }),
        CapsuleNetwork::Offline,
        None,
        CapsuleBudgets {
            wall_time_ms,
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
        placed_on: smol_str::SmolStr::new("agent-turn-1"),
        command_id: None,
        effect_domain: None,
        start_deadline_ms: None,
        progress_visibility: kata_types::workflow::ProgressVisibility::Off,
        trace: TraceContext::default(),
    }
}

use kata_worker::result_publication::CasBlobSink;

/// THE PROMPT'S REF, resolved off the fixture's own published bytes.
fn prompt_ref(rig: &Rig, _prompt: ArtifactId) -> ArtifactRef {
    let durable = rig
        .cas
        .put_durable(b"write the file")
        .expect("the prompt bytes publish");
    ArtifactRef::new(
        durable.object_id(),
        durable.size(),
        ArtifactPrivacy::Private,
    )
}

// ---------------------------------------------------------------------------
// Credentials — the load, and the hygiene proof that a token never lands in
// the durable record.
// ---------------------------------------------------------------------------

/// A `TurnCredentialRef` builder for the cells below.
fn credential_ref(
    mode: kata_types::metering::CredentialMode,
    source: kata_types::execution_contract::CredentialSource,
) -> kata_types::execution_contract::TurnCredentialRef {
    kata_types::execution_contract::TurnCredentialRef { mode, source }
}

/// Read every blob the rig's CAS durably holds and assert the synthetic
/// token's substring is in NONE of them — the hygiene rule's proof shape:
/// the lifted credential rides the wire and the attempt root, never a
/// durable object. BOTH storages are read: the `cas/` FILES the large
/// objects live as, and `cas_objects.blob` INLINE rows — a small blob (an
/// evidence record is well under `INLINE_THRESHOLD`) never touches a file,
/// so the file scan alone could pass over a leaked token a raw row read
/// would not.
/// A token is more than its whole string: a cut that splits it leaves a
/// PREFIX the whole-string scan cannot see, so the durable assert scans
/// every 12-byte window — any 12 contiguous bytes of the lifted value are
/// already a credential fragment nothing durable may hold.
fn contains_token_window(text: &str, token: &str) -> bool {
    const WINDOW: usize = 12;
    if token.len() < WINDOW {
        return text.contains(token);
    }
    (0..=token.len() - WINDOW).any(|offset| text.contains(&token[offset..offset + WINDOW]))
}

fn assert_token_absent_from_cas(rig: &Rig, token: &str) {
    let cas_dir = rig.dir.path().join("cas");
    let mut hits = Vec::new();
    fn scan(dir: &std::path::Path, token: &str, hits: &mut Vec<String>) {
        for entry in std::fs::read_dir(dir).expect("a cas subdirectory lists") {
            let entry = entry.expect("a cas entry");
            if entry.file_type().expect("a file type").is_dir() {
                scan(&entry.path(), token, hits);
            } else {
                let bytes = std::fs::read(entry.path()).expect("a cas blob reads");
                if let Ok(text) = String::from_utf8(bytes)
                    && contains_token_window(&text, token)
                {
                    hits.push(entry.path().display().to_string());
                }
            }
        }
    }
    scan(&cas_dir, token, &mut hits);
    assert!(
        hits.is_empty(),
        "a 12-byte window of the lifted token landed in durable objects: {hits:?}"
    );

    // THE INLINE HALF, on a SECOND raw read-only handle — never the handle
    // the code under test wrote through.
    let raw = rusqlite::Connection::open_with_flags(
        rig.dir.path().join("cas.db"),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .expect("the raw cas.db handle opens");
    let mut statement = raw
        .prepare("SELECT object_id, blob FROM cas_objects WHERE blob IS NOT NULL")
        .expect("the inline-blob query prepares");
    let rows = statement
        .query_map([], |row| {
            Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?))
        })
        .expect("the inline rows read");
    let mut inline_hits = Vec::new();
    for row in rows {
        let (id, blob) = row.expect("an inline row decodes");
        if let Ok(text) = String::from_utf8(blob)
            && contains_token_window(&text, token)
        {
            inline_hits.push(format!("cas_objects row {}", hex::encode(id)));
        }
    }
    assert!(
        inline_hits.is_empty(),
        "a 12-byte window of the lifted token landed in INLINE cas rows: {inline_hits:?}"
    );
}

/// The accepting transition's `payload_json` for `refusal`, fed through the
/// REAL accept path (`buffer_worker_failure` + `adjudicate_worker_failure` on a
/// real `OperationalDb` under `dir`) and read back off a SECOND raw read-only
/// handle: the durable record of the attempt's reason and its terminal charge.
fn durable_failure_transition(
    dir: &std::path::Path,
    refusal: &kata_worker::capsule_execution::CapsuleAttemptRefusal,
) -> String {
    use kata_core::operational::{
        AttemptClaimSpec, CommandSpec, OccurrenceBinding, WorkerFailureInput, WorkerFailurePlan,
        WorkerFailureResolution,
    };
    let op_path = dir.join("operational.db");
    let db = kata_core::OperationalDb::open(&op_path).expect("the operational db opens");
    let execution_id = ulid::Ulid::new();
    let attempt_id = ulid::Ulid::new();
    let program_hash = kata_types::primitives::ContentHash::new([7; 32]);
    let invocation =
        kata_types::idempotency::canonicalize_args(&serde_json::json!({"schema_version":1}));
    db.submit_execution(
        execution_id,
        &kata_core::ProgramRecord {
            program_hash,
            schema_version: 4,
            program_json: b"{}".to_vec(),
        },
        &kata_core::InvocationRecord {
            schema_version: 1,
            kind: kata_core::InvocationKind::Workflow,
            admission_digest: kata_types::identity_algebra::AdmissionDigest(
                kata_types::primitives::ContentHash::new(*blake3::hash(&invocation).as_bytes()),
            ),
            invocation_json: invocation,
        },
    )
    .expect("the execution submits");
    db.mark_running(execution_id).expect("the execution runs");
    db.dispatch_attempt(
        execution_id,
        attempt_id,
        ulid::Ulid::new(),
        &AttemptClaimSpec {
            stage_id: "only".into(),
            initial_state: "pending".to_string(),
            assignment_json: br#"{"capsule":{"stage_name":"fixture"}}"#.to_vec(),
            run_ordinal: 0,
            worker_id: Some("worker".into()),
            occurrence: OccurrenceBinding::for_test(execution_id, "only"),
        },
        &CommandSpec {
            command_json: b"{}".to_vec(),
        },
    )
    .expect("the attempt dispatches");
    let current = db
        .recovered_attempt(attempt_id)
        .expect("the attempt reads")
        .expect("the dispatched attempt exists");
    let input = WorkerFailureInput {
        execution_id,
        attempt_id,
        attempt_ordinal: current.row.attempt_ordinal,
        lease_epoch: current.row.lease_epoch,
        worker_id: "worker".into(),
        // The production string verbatim — what a scrubbed leaf would poison.
        reason: refusal.reason.clone(),
        verdict: refusal.performed,
        usage: refusal.usage.clone().map(|usage| *usage),
        provider_failure: refusal.provider_failure,
    };
    let plan = WorkerFailurePlan {
        expected: current.placement_expectation().expect("the placement"),
        program_hash,
        expected_standing_stop: false,
        resolution: WorkerFailureResolution::Failed {
            reason: "the checked program's terminal policy".into(),
        },
    };
    assert_eq!(
        db.buffer_worker_failure(&input)
            .expect("the failure buffers"),
        kata_core::operational::WorkerFailureOffer::Ready,
        "the generated input is current"
    );
    db.adjudicate_worker_failure(&input, &plan)
        .expect("the failure adjudicates")
        .expect("the current fence accepts it");
    drop(db);
    // THE RAW HANDLE — a second read-only connection, the operational cells'
    // own oracle shape: asking kata whether kata wrote is the anti-pattern.
    let raw = rusqlite::Connection::open_with_flags(
        &op_path,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .expect("the raw handle opens");
    let payload: Vec<u8> = raw
        .query_row(
            "SELECT payload_json FROM transitions WHERE kind='event_accepted'",
            [],
            |row| row.get(0),
        )
        .expect("the acceptance transition row reads");
    String::from_utf8(payload).expect("the transition payload is UTF-8")
}

/// A driver whose every interactive launch is a PLAN refusal with a planted reason —
/// the shape a too-long handoff socket path produced before sockets were
/// addressed through their parent's descriptor.
struct PlanRefusingDriver {
    attempt_root: std::path::PathBuf,
}

/// The planted reason [`PlanRefusingDriver`] refuses with.
const PLANTED_PLAN_REASON: &str =
    "the egress handoff endpoint /planted/egress/handoff.sock could not be bound: planted cause";

#[async_trait::async_trait]
impl kata_worker::oci_driver::CapsuleDriver for PlanRefusingDriver {
    async fn drive_capsule(
        &self,
        _attempt_tag: &str,
        _request: &OciStageRequest<'_>,
        _assign_by: std::time::Instant,
        _cancel: tokio::sync::oneshot::Receiver<String>,
    ) -> Result<OciStageOutput, OciDriveRefusal> {
        unreachable!("the fixture mints only Agent capsules")
    }

    async fn launch_interactive(
        &self,
        _attempt_tag: &str,
        _request: &OciStageRequest<'_>,
    ) -> Result<
        Box<dyn InteractivePlacement>,
        kata_worker::interactive_capsule::InteractiveLaunchRefusal,
    > {
        Err(
            kata_worker::interactive_capsule::InteractiveLaunchRefusal::Placement(
                OciDriveRefusal::PlanRefused(kata_types::error::KataError::Validation(
                    PLANTED_PLAN_REASON.to_owned(),
                )),
            ),
        )
    }

    fn attempt_root(&self, _attempt_tag: &str) -> std::path::PathBuf {
        self.attempt_root.clone()
    }

    fn describe_driver(&self) -> String {
        "a double whose every interactive launch is a plan refusal".into()
    }
}

/// **A plan refusal reaches the durable record with its reason, not only its
/// label.** The agent turn's launch is refused `plan_refused` with a planted
/// cause; the attempt's refusal — adjudicated through a real `operational.db`
/// and read back through a second read-only handle — carries the label AND the
/// cause, and stays PROVEN NOT PERFORMED.
///
/// Watched red: before the reason was carried, the durable payload held
/// `...before the container was assigned: plan_refused` and nothing else.
#[tokio::test]
async fn a_plan_refused_launch_reaches_the_durable_record_with_its_reason() {
    let rig = rig();
    let (tree, tree_ref) = empty_tree(&rig);
    let (environment, claim) = publish_manifest(&rig);
    let prompt = rig.publish_prompt("write the file");
    let occurrence = OccurrenceId(FixedBytes([0x6b; 32]));
    let capsule = agent_capsule(occurrence, environment, tree, prompt);
    let frame = frame_for(publish_capsule(&rig, &capsule), occurrence);
    let source = rig.reader();
    let refs = vec![(prompt, prompt_ref(&rig, prompt)), (tree, tree_ref)];
    let trees = FixtureTrees { tree, refs };
    let driver = PlanRefusingDriver {
        attempt_root: rig.dir.path().join("attempt"),
    };
    let sink = CasBlobSink(&rig.cas);
    let refusal = execute_capsule_frame(
        &CapsuleExecution {
            driver: &driver,
            environments: &FixedIndex(Some(claim)),
            trees: &trees,
            source: &source,
            probe: &FixedProbe(true),
            sink: &sink,
            adapters: &*AGENT_ADAPTERS,
            credentials: &fixture_credentials(),
        },
        &frame,
        std::time::Instant::now(),
        tokio::sync::oneshot::channel().1,
        None,
    )
    .await
    .expect_err("a plan-refused launch is a refusal");
    assert_eq!(
        refusal.performed,
        DeliveryFailureProvenance::ProvenNotPerformed,
        "{}",
        refusal.reason
    );
    let stored = durable_failure_transition(rig.dir.path(), &refusal);
    for needle in ["plan_refused", PLANTED_PLAN_REASON] {
        assert!(
            stored.contains(needle),
            "the durable record carries `{needle}`: {stored}"
        );
    }
}

/// The toolhost double's placement: the `InteractiveProcess` half is the double
/// (`crates/agent-nanocode/tests/fixtures/toolhost_double.rs`), speaking the
/// toolhost protocol in-process as a nanocode capsule's init would; the
/// teardown half is the fake's.
struct ToolhostPlacement {
    process: Box<dyn InteractiveProcess>,
    attempt_root: std::path::PathBuf,
    owned_root: kata_worker::attempt_root::OwnedAttemptRoot,
}

impl InteractivePlacement for ToolhostPlacement {
    fn attempt_root(&self) -> &std::path::Path {
        &self.attempt_root
    }

    fn container_id(&self) -> &'static str {
        "fake-toolhost"
    }

    fn into_halves(self: Box<Self>) -> (Box<dyn InteractiveProcess>, Box<dyn InteractiveTeardown>) {
        (
            self.process,
            Box::new(FakeTeardown {
                attempt_root: self.attempt_root,
                owned_root: Some(self.owned_root),
            }),
        )
    }
}

/// The driver a nanocode capsule meets: `launch_interactive` records the request's
/// the toolhost double, whose
/// witness the cell reads back.
struct ToolhostDriver {
    attempt_root: std::path::PathBuf,
    config: toolhost_double::DoubleConfig,
    witness: std::sync::Mutex<Option<toolhost_double::DoubleWitness>>,
}

#[async_trait::async_trait]
impl kata_worker::oci_driver::CapsuleDriver for ToolhostDriver {
    async fn drive_capsule(
        &self,
        _attempt_tag: &str,
        _request: &OciStageRequest<'_>,
        _assign_by: std::time::Instant,
        _cancel: tokio::sync::oneshot::Receiver<String>,
    ) -> Result<OciStageOutput, OciDriveRefusal> {
        unreachable!("the fixture mints only Agent capsules")
    }

    async fn launch_interactive(
        &self,
        _attempt_tag: &str,
        _request: &OciStageRequest<'_>,
    ) -> Result<
        Box<dyn InteractivePlacement>,
        kata_worker::interactive_capsule::InteractiveLaunchRefusal,
    > {
        let owned_root = kata_worker::attempt_root::OwnedAttemptRoot::acquire(&self.attempt_root)
            .map_err(|error| {
            kata_worker::interactive_capsule::InteractiveLaunchRefusal::Placement(
                OciDriveRefusal::AttemptRootUnavailable(error),
            )
        })?;
        for guest in ["work", "out"] {
            std::fs::create_dir_all(self.attempt_root.join(guest)).expect("the guest roots");
        }
        let (process, witness) = toolhost_double::start(self.config.clone());
        *self.witness.lock().expect("the witness slot") = Some(witness);
        Ok(Box::new(ToolhostPlacement {
            process,
            attempt_root: self.attempt_root.clone(),
            owned_root,
        }))
    }

    fn attempt_root(&self, _attempt_tag: &str) -> std::path::PathBuf {
        self.attempt_root.clone()
    }

    fn describe_driver(&self) -> String {
        "a double that starts the in-process toolhost double".into()
    }
}

/// **An `env:` key reaches a nanocode turn's provider and never its capsule.**
/// A `nanocode_openai` capsule declaring `env:<VAR>`, the variable SET in the
/// worker's environment, dispatched through a registry that carries the
/// nanocode adapter pointed at a mock Responses endpoint (the production
/// registry's points at the provider's own), over the toolhost double as the
/// capsule's init. The turn completes, and:
///
/// * the mock provider's OWN log holds the key as the request's bearer: the
///   worker lifted it into the in-process carrier, and the model call left
///   from the worker;
/// * the toolhost double received no frame carrying the key;
/// * the key is in no CAS object.
///
/// **Would red if:** the nanocode kinds' `env:` lift were refused again (no
/// completion), or reached the capsule (a toolhost frame carrying it).
#[tokio::test]
async fn an_env_key_reaches_a_nanocode_provider_and_never_its_capsule() {
    const TOKEN: &str = "sk-nanocode-capsule-must-not-see-91c4";
    let rig = rig();
    let mut env = std::collections::BTreeMap::new();
    env.insert("KATA_FIXTURE_TOKEN".to_string(), TOKEN.to_string());
    let credentials = kata_worker::agent_credential::AgentCredentialSource::for_test(env);
    let mock = mock_provider::MockProvider::start(vec![mock_provider::message_reply(
        "r1",
        "done",
        mock_provider::usage(30, 0, 4),
    )])
    .await;

    let (tree, tree_ref) = empty_tree(&rig);
    let (environment, claim) = publish_manifest(&rig);
    let prompt = rig.publish_prompt("write the file");
    let occurrence = OccurrenceId(FixedBytes([0x6e; 32]));
    let capsule = agent_capsule_with(
        occurrence,
        environment,
        tree,
        prompt,
        kata_types::agent::AdapterKind::NanocodeOpenai,
        Some(credential_ref(
            kata_types::metering::CredentialMode::ApiKey,
            kata_types::execution_contract::CredentialSource::EnvVar {
                var: smol_str::SmolStr::new("KATA_FIXTURE_TOKEN"),
            },
        )),
        Some("gpt-6-luna".into()),
    );
    let frame = frame_for(publish_capsule(&rig, &capsule), occurrence);
    let attempt_root = rig.dir.path().join("attempt");

    let source = rig.reader();
    let refs = vec![(prompt, prompt_ref(&rig, prompt)), (tree, tree_ref)];
    let trees = FixtureTrees { tree, refs };
    let driver = ToolhostDriver {
        attempt_root: attempt_root.clone(),
        config: toolhost_double::DoubleConfig::default(),
        witness: std::sync::Mutex::new(None),
    };
    let sink = CasBlobSink(&rig.cas);
    let adapters = kata_agent::adapter::capsule_registry::StaticAgentAdapterRegistry::new([
        std::sync::Arc::new(
            kata_agent_nanocode::NanocodeAdapter::openai().with_endpoint(
                kata_agent_nanocode::adapter::TestEndpoint {
                    url: mock.url.clone(),
                    websocket_url: None,
                },
            ),
        ) as std::sync::Arc<dyn kata_agent::adapter::AgentAdapter>,
    ]);
    let reported = execute_capsule_frame(
        &CapsuleExecution {
            driver: &driver,
            environments: &FixedIndex(Some(claim)),
            trees: &trees,
            source: &source,
            probe: &FixedProbe(true),
            sink: &sink,
            adapters: &adapters,
            credentials: &credentials,
        },
        &frame,
        std::time::Instant::now(),
        tokio::sync::oneshot::channel().1,
        None,
    )
    .await
    .unwrap_or_else(|refusal| panic!("the env: key carries the turn: {refusal}"));

    let WorkerMessage::CompletedCapsule { agent, .. } = reported else {
        panic!("an agent capsule execution reports the capsule terminal");
    };
    let report = agent.expect("the completed frame carries the turn report");
    assert_eq!(
        report.adapter,
        kata_types::agent::AdapterKind::NanocodeOpenai
    );
    assert_eq!(
        mock.authorizations(),
        vec![format!("Bearer {TOKEN}")],
        "the provider saw the key as the bearer of the turn's one model request"
    );
    let witness = driver
        .witness
        .lock()
        .expect("the witness slot")
        .take()
        .expect("the toolhost double was started");
    for frame in witness.frames() {
        let text = format!("{frame:?}");
        assert!(
            !text.contains(TOKEN),
            "a frame to the capsule carried the key: {text}"
        );
    }
    assert!(
        !attempt_root.exists(),
        "a confirmed teardown removed the root"
    );
    assert_token_absent_from_cas(&rig, TOKEN);
}

/// **An `env:` key no HTTP header can carry is refused `credential_unavailable`
/// before the container, on either nanocode kind.** Both of nanocode's model
/// clients send the key as an HTTP header value, which admits no control byte
/// but a tab, so a key exported with its trailing newline can never reach the
/// provider. A `nanocode_openai` and a `nanocode_anthropic` capsule declaring
/// `env:<VAR>`, the variable set to such a value in the worker's environment,
/// dispatched through a registry that carries the nanocode adapter pointed at
/// a mock provider, over the toolhost double:
///
/// * the frame is refused `credential_unavailable`, naming the variable and not
///   the value, PROVEN NOT PERFORMED;
/// * the driver never placed the capsule (the double never started) and the
///   attempt root was never created;
/// * the mock provider's OWN log holds no request;
/// * the value is in no CAS object.
///
/// **Would red if:** the lift handed such a value to the harness, which today
/// fails the turn after the capsule is placed (the double starts, and the
/// outcome names no credential).
#[tokio::test]
async fn a_nanocode_env_key_no_header_can_carry_is_refused_before_the_container() {
    const VALUE: &str = "kata-fixture-key-exported-with-its-newline\n";
    for (index, kind) in [
        kata_types::agent::AdapterKind::NanocodeOpenai,
        kata_types::agent::AdapterKind::NanocodeAnthropic,
    ]
    .into_iter()
    .enumerate()
    {
        let rig = rig();
        let credentials = kata_worker::agent_credential::AgentCredentialSource::for_test(
            std::collections::BTreeMap::from([("KATA_FIXTURE_TOKEN".to_owned(), VALUE.to_owned())]),
        );
        let (reply, url, adapter, model) = match kind {
            kata_types::agent::AdapterKind::NanocodeOpenai => (
                mock_provider::message_reply("r1", "done", mock_provider::usage(1, 0, 1)),
                None,
                kata_agent_nanocode::NanocodeAdapter::openai(),
                "gpt-6-luna",
            ),
            kata_types::agent::AdapterKind::NanocodeAnthropic => (
                mock_provider::claude_text_reply("done"),
                Some("/messages"),
                kata_agent_nanocode::NanocodeAdapter::anthropic(),
                "claude-sonnet-5-5",
            ),
        };
        let mock = mock_provider::MockProvider::start(vec![reply]).await;
        let (tree, tree_ref) = empty_tree(&rig);
        let (environment, claim) = publish_manifest(&rig);
        let prompt = rig.publish_prompt("say done");
        let occurrence = OccurrenceId(FixedBytes([0x75 + u8::try_from(index).unwrap(); 32]));
        let capsule = agent_capsule_with(
            occurrence,
            environment,
            tree,
            prompt,
            kind,
            Some(credential_ref(
                kata_types::metering::CredentialMode::ApiKey,
                kata_types::execution_contract::CredentialSource::EnvVar {
                    var: smol_str::SmolStr::new("KATA_FIXTURE_TOKEN"),
                },
            )),
            Some(model.into()),
        );
        let frame = frame_for(publish_capsule(&rig, &capsule), occurrence);
        let attempt_root = rig.dir.path().join("attempt");
        let source = rig.reader();
        let refs = vec![(prompt, prompt_ref(&rig, prompt)), (tree, tree_ref)];
        let trees = FixtureTrees { tree, refs };
        let driver = ToolhostDriver {
            attempt_root: attempt_root.clone(),
            config: toolhost_double::DoubleConfig::default(),
            witness: std::sync::Mutex::new(None),
        };
        let sink = CasBlobSink(&rig.cas);
        let adapters = kata_agent::adapter::capsule_registry::StaticAgentAdapterRegistry::new([
            std::sync::Arc::new(
                adapter.with_endpoint(kata_agent_nanocode::adapter::TestEndpoint {
                    url: format!("{}{}", mock.url, url.unwrap_or("")),
                    websocket_url: None,
                }),
            ) as std::sync::Arc<dyn kata_agent::adapter::AgentAdapter>,
        ]);
        let executed = execute_capsule_frame(
            &CapsuleExecution {
                driver: &driver,
                environments: &FixedIndex(Some(claim)),
                trees: &trees,
                source: &source,
                probe: &FixedProbe(true),
                sink: &sink,
                adapters: &adapters,
                credentials: &credentials,
            },
            &frame,
            std::time::Instant::now(),
            tokio::sync::oneshot::channel().1,
            None,
        )
        .await;
        let placed = driver.witness.lock().expect("the witness slot").is_some();
        let requests = mock.requests().len();
        let refusal = match executed {
            Err(refusal) => refusal,
            Ok(reported) => panic!(
                "{}: a key no header can carry is refused before the container, not run \
                 (placed: {placed}, provider requests: {requests}): {reported:?}",
                kind.as_label()
            ),
        };
        let text = format!("{refusal}");
        assert!(
            text.contains("credential_unavailable") && text.contains("env:KATA_FIXTURE_TOKEN"),
            "{}: the refusal is named: {text}",
            kind.as_label()
        );
        assert!(
            !text.contains(VALUE.trim_end()),
            "{}: the refusal names the variable, never its value: {text}",
            kind.as_label()
        );
        assert!(
            refusal.performed == DeliveryFailureProvenance::ProvenNotPerformed,
            "{}: a pre-container refusal proves nothing ran: {text}",
            kind.as_label()
        );
        assert!(!placed, "{}: the capsule was never placed", kind.as_label());
        assert!(
            !attempt_root.exists(),
            "{}: no attempt root was created",
            kind.as_label()
        );
        assert_eq!(
            requests,
            0,
            "{}: the provider was asked nothing",
            kind.as_label()
        );
        assert_token_absent_from_cas(&rig, VALUE.trim_end());
    }
}

/// A nanocode cell that writes one 60,000-byte text, past nanocode's
/// 12,000-token visible budget for a tool result on either kind, then
/// allocates 384 MiB, past kata's 256 MiB Code Mode heap limit.
const LONG_TEXT_THEN_ALLOCATE: &str = "text(\"x\".repeat(60000));\n\
     const chunks = [];\n\
     for (let i = 0; i < 384; i++) chunks.push(new Uint8Array(1 << 20).fill(1));\n\
     text(`allocated ${chunks.length} MiB`);";

/// One `kind` nanocode turn through the whole capsule composition under
/// kata's Code Mode limits, over the toolhost double, against a mock provider
/// that answers `cells` as the model's cells, one a reply, and then ends the
/// turn. Answers the mock's own log of the request bodies it received, and
/// the session evidence the worker published, read back off the rig's CAS by
/// the report's ref and decoded as the wire type.
async fn nanocode_cells_through_the_worker(
    kind: kata_types::agent::AdapterKind,
    cells: &[&str],
) -> (Vec<serde_json::Value>, kata_types::agent::SessionEvidence) {
    let replies = (1..).zip(cells);
    let script = match kind {
        kata_types::agent::AdapterKind::NanocodeOpenai => replies
            .map(|(cell, source)| {
                mock_provider::code_reply(
                    &format!("r{cell}"),
                    source,
                    mock_provider::usage(1, 0, 1),
                )
            })
            .chain([mock_provider::message_reply(
                "done",
                "DONE",
                mock_provider::usage(1, 0, 1),
            )])
            .collect(),
        kata_types::agent::AdapterKind::NanocodeAnthropic => replies
            .map(|(cell, source)| mock_provider::claude_code_reply(&format!("r{cell}"), source))
            .chain([mock_provider::claude_text_reply("DONE")])
            .collect(),
    };
    let mock = mock_provider::MockProvider::start(script).await;
    let evidence = nanocode_turn_through_the_worker(kind, &mock).await;
    (mock.requests(), evidence)
}

/// One `kind` nanocode turn through the whole capsule composition under
/// kata's Code Mode limits, over the toolhost double, its model `mock`: the
/// session evidence the worker published, read back off the rig's CAS by the
/// report's ref and decoded as the wire type.
async fn nanocode_turn_through_the_worker(
    kind: kata_types::agent::AdapterKind,
    mock: &mock_provider::MockProvider,
) -> kata_types::agent::SessionEvidence {
    const TOKEN: &str = "sk-nanocode-limit-record-7e20";
    kata_agent_nanocode::install_code_mode_limits();
    let rig = rig();
    let credentials = kata_worker::agent_credential::AgentCredentialSource::for_test(
        std::collections::BTreeMap::from([("KATA_FIXTURE_TOKEN".to_owned(), TOKEN.to_owned())]),
    );
    let (adapter, model) = match kind {
        kata_types::agent::AdapterKind::NanocodeOpenai => {
            (kata_agent_nanocode::NanocodeAdapter::openai(), "gpt-6-luna")
        }
        kata_types::agent::AdapterKind::NanocodeAnthropic => (
            kata_agent_nanocode::NanocodeAdapter::anthropic(),
            "claude-sonnet-4-6",
        ),
    };
    let url = match kind {
        kata_types::agent::AdapterKind::NanocodeAnthropic => format!("{}/messages", mock.url),
        kata_types::agent::AdapterKind::NanocodeOpenai => mock.url.clone(),
    };

    let (tree, tree_ref) = empty_tree(&rig);
    let (environment, claim) = publish_manifest(&rig);
    let prompt = rig.publish_prompt("write, then allocate");
    let occurrence = OccurrenceId(FixedBytes([0x6c; 32]));
    let capsule = agent_capsule_with(
        occurrence,
        environment,
        tree,
        prompt,
        kind,
        Some(credential_ref(
            kata_types::metering::CredentialMode::ApiKey,
            kata_types::execution_contract::CredentialSource::EnvVar {
                var: smol_str::SmolStr::new("KATA_FIXTURE_TOKEN"),
            },
        )),
        Some(model.into()),
    );
    let frame = frame_for(publish_capsule(&rig, &capsule), occurrence);
    let source = rig.reader();
    let refs = vec![(prompt, prompt_ref(&rig, prompt)), (tree, tree_ref)];
    let trees = FixtureTrees { tree, refs };
    let driver = ToolhostDriver {
        attempt_root: rig.dir.path().join("attempt"),
        config: toolhost_double::DoubleConfig::default(),
        witness: std::sync::Mutex::new(None),
    };
    let sink = CasBlobSink(&rig.cas);
    let adapters = kata_agent::adapter::capsule_registry::StaticAgentAdapterRegistry::new([
        std::sync::Arc::new(
            adapter.with_endpoint(kata_agent_nanocode::adapter::TestEndpoint {
                url,
                websocket_url: None,
            }),
        ) as std::sync::Arc<dyn kata_agent::adapter::AgentAdapter>,
    ]);
    let reported = execute_capsule_frame(
        &CapsuleExecution {
            driver: &driver,
            environments: &FixedIndex(Some(claim)),
            trees: &trees,
            source: &source,
            probe: &FixedProbe(true),
            sink: &sink,
            adapters: &adapters,
            credentials: &credentials,
        },
        &frame,
        std::time::Instant::now(),
        tokio::sync::oneshot::channel().1,
        None,
    )
    .await
    .unwrap_or_else(|refusal| panic!("a limit hit is a cell outcome, not a refusal: {refusal}"));

    let WorkerMessage::CompletedCapsule { agent, .. } = reported else {
        panic!("an agent capsule execution reports the capsule terminal");
    };
    let report = agent.expect("the completed frame carries the turn report");
    assert_eq!(report.adapter, kind);
    let evidence_ref = report
        .session_evidence
        .expect("a completed turn names its session evidence");
    let bytes = kata_worker::materialize::BlobSource::read_verified(
        &source,
        evidence_ref.object_id(),
        evidence_ref.size_bytes(),
        evidence_ref.size_bytes(),
    )
    .expect("the evidence artifact reads");
    serde_json::from_slice(&bytes).expect("the blob decodes as SessionEvidence")
}

/// The limits a published evidence record names, in order.
fn limits_in(evidence: &kata_types::agent::SessionEvidence) -> Vec<&str> {
    evidence
        .events
        .iter()
        .filter_map(|event| match event {
            kata_types::agent::SessionEvidenceEvent::CodeModeLimit { which } => {
                Some(which.as_str())
            }
            _ => None,
        })
        .collect()
}

/// The engine's error for a cell that ran out of its heap, as the model is
/// told it (`Script error:` and the engine's message).
const OUT_OF_MEMORY: &str = "Script error:\nScript stopped: the cell ran out of memory.";

/// kata's report of its heap limit, a Code Mode notification the interpreter
/// sends before the cell's error.
const MEMORY_REPORT: &str = "Code Mode cell exceeded its 268435456-byte memory limit";

/// **A Code Mode limit hit past nanocode's visible budget reaches the model
/// and the worker's published evidence on the Responses kind.** A
/// `nanocode_openai` turn through the whole capsule composition: the model's
/// one cell writes a 60,000-byte text, then allocates past kata's heap limit.
/// MEASURED at 8ec3b215: the request after it hands the model the cell's
/// result as its header and ONE text, nanocode's join of the cell's text and
/// its `Script error:` middle-truncated to its 10,000-token budget (`Warning:
/// truncated output (original token count: 15015)` first, the engine's
/// out-of-memory error last), and the engine's report of the memory limit as
/// an output of its own. The session evidence the worker published, read back
/// off the CAS by its ref, names one `CodeModeLimit{memory}`.
///
/// **Would red if:** the limit were read off the visible result alone and
/// the worker published the evidence without the adapter's limit records (no
/// `memory` record), or nanocode's truncation dropped or cut the error again
/// (the text does not end with it).
#[tokio::test]
async fn a_limit_hit_past_the_visible_budget_reaches_the_model_and_the_published_evidence_on_the_responses_kind()
 {
    let (requests, evidence) = nanocode_cells_through_the_worker(
        kata_types::agent::AdapterKind::NanocodeOpenai,
        &[LONG_TEXT_THEN_ALLOCATE],
    )
    .await;
    assert_eq!(requests.len(), 2, "one model call per response");
    let outputs = mock_provider::call_outputs(&requests[1], "call_r1");
    let [result, report] = outputs.as_slice() else {
        panic!(
            "the cell's result and one report, not {} outputs",
            outputs.len()
        );
    };
    let texts: Vec<&str> = result
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|item| item["text"].as_str())
        .collect();
    let [header, joined] = texts.as_slice() else {
        panic!("the result is its header and one joined text: {texts:.400?}");
    };
    assert!(
        header.starts_with("Script failed")
            && joined.starts_with("Warning: truncated output (original token count: ")
            && joined.contains(" tokens truncated")
            && joined.ends_with(&format!("x\n{OUT_OF_MEMORY}"))
            && !joined.contains("allocated"),
        "the cell failed and its truncated text ends with its error: {}",
        &joined[joined.len().saturating_sub(200)..]
    );
    assert_eq!(
        *report,
        serde_json::json!(MEMORY_REPORT),
        "the model is handed the engine's report"
    );
    assert_eq!(limits_in(&evidence), ["memory"], "{evidence:?}");
}

/// **A Code Mode limit hit past nanocode's visible budget reaches the
/// worker's published evidence on the Messages kind, which does not tell the
/// model (MEASURED RESIDUAL).** The same turn as `nanocode_anthropic`: the
/// request after the cell hands the model a `tool_result` whose visible blocks
/// end with `[<n> more text blocks omitted]`, the cell's out-of-memory error
/// and kata's report of the limit among the dropped (MEASURED at 8ec3b215:
/// nanocode's Messages kind still drops whole blocks past its 12,000-token
/// budget, where its Responses kind now joins and middle-truncates them). The session evidence the worker
/// published, read back off the CAS by its ref, names one
/// `CodeModeLimit{memory}` all the same.
///
/// **Would red if:** the adapter read the Messages kind's limits off its
/// visible result, or not at all (the record is missing from the durable
/// evidence).
#[tokio::test]
async fn a_limit_hit_past_the_visible_budget_is_in_the_published_evidence_on_the_messages_kind() {
    let (requests, evidence) = nanocode_cells_through_the_worker(
        kata_types::agent::AdapterKind::NanocodeAnthropic,
        &[LONG_TEXT_THEN_ALLOCATE],
    )
    .await;
    assert_eq!(requests.len(), 2, "one model call per response");
    let texts = mock_provider::tool_result_texts(&requests[1], "toolu_r1")
        .expect("the model was told the cell");
    let last = texts.last().map_or("", String::as_str);
    assert!(
        last.starts_with('[')
            && last.ends_with(" more text blocks omitted]")
            && !texts.iter().any(|text| text.contains("memory")),
        "the cell's error and the guard's report are past nanocode's visible budget; the last \
         text is: {last}"
    );
    assert_eq!(limits_in(&evidence), ["memory"], "{evidence:?}");
}

/// A cell that fills the heap with small objects until djs stops it: a heap
/// hit, which no script can catch.
const SMALL_OBJECT_FLOOD: &str =
    "const objects = [];\nfor (;;) objects.push({ i: objects.length });";

/// A cell that allocates 128 MiB of filled typed arrays, half of kata's heap
/// limit, and says so.
const HALF_THE_HEAP: &str = "const chunks = [];\n\
     for (let i = 0; i < 128; i++) chunks.push(new Uint8Array(1 << 20).fill(1));\n\
     text(`allocated ${chunks.length} MiB`);";

/// The model's cells, in order: a heap flood, a cell allocating half the heap,
/// a trivial cell, then the flood and the allocation again.
const CELLS_AFTER_HEAP_HITS: [&str; 5] = [
    SMALL_OBJECT_FLOOD,
    HALF_THE_HEAP,
    "text(\"the next cell ran\");",
    SMALL_OBJECT_FLOOD,
    HALF_THE_HEAP,
];

/// The text each of [`CELLS_AFTER_HEAP_HITS`] must tell the model: `None` for
/// a flood (its result is the engine's out-of-memory error, and kata's report
/// beside it), the cell's own text otherwise.
const TOLD_AFTER_HEAP_HITS: [Option<&str>; 5] = [
    None,
    Some("allocated 128 MiB"),
    Some("the next cell ran"),
    None,
    Some("allocated 128 MiB"),
];

/// Every text `request` handed the model for cell `cell` of a `kind` turn:
/// on the Responses kind every output of the cell's call, its result's texts
/// first, then each notification, an output of its own; on the Messages
/// kind its `tool_result`'s texts.
fn told_for_cell(
    kind: kata_types::agent::AdapterKind,
    request: &serde_json::Value,
    cell: usize,
) -> Vec<String> {
    match kind {
        kata_types::agent::AdapterKind::NanocodeOpenai => {
            mock_provider::call_outputs(request, &format!("call_r{cell}"))
                .into_iter()
                .flat_map(|output| match output {
                    serde_json::Value::String(text) => vec![text],
                    items => items
                        .as_array()
                        .into_iter()
                        .flatten()
                        .filter_map(|item| item["text"].as_str().map(str::to_owned))
                        .collect(),
                })
                .collect()
        }
        kata_types::agent::AdapterKind::NanocodeAnthropic => {
            mock_provider::tool_result_texts(request, &format!("toolu_r{cell}")).unwrap_or_default()
        }
    }
}

/// **A nanocode turn whose cells hit the heap completes through the worker,
/// and the cells after each hit run.** On each kind, a turn through the whole
/// capsule composition under kata's Code Mode limits: the model's first cell
/// floods the heap, its second allocates 128 MiB, half the heap limit, its
/// third writes a text, its fourth floods the heap again and its fifth
/// allocates 128 MiB again. The worker reports a completed capsule; the
/// model's last request carries every cell's result, MEASURED at 8ec3b215:
/// each flood's failed with the engine's `Script stopped: the cell ran out of
/// memory.` and kata's report of the limit beside it (on the Responses kind
/// an output of its own), each other cell's completed with its own text; and
/// the session evidence the worker published, read back off the rig's CAS by
/// the report's ref, names two `CodeModeLimit{memory}`. The process this runs
/// in stands for the node hosting the worker (the child twin below reads its
/// exit status).
///
/// **Would red if:** a heap hit left the heap it filled to the next cell (the
/// 128 MiB cell after a flood fails with the out-of-memory error), a heap hit
/// failed the turn instead of the cell (no completed capsule), or the adapter
/// did not record a limit kata reported (fewer than two `memory` records).
#[tokio::test]
async fn a_turn_whose_cells_hit_the_heap_completes_and_its_later_cells_run() {
    for kind in [
        kata_types::agent::AdapterKind::NanocodeOpenai,
        kata_types::agent::AdapterKind::NanocodeAnthropic,
    ] {
        let (requests, evidence) =
            nanocode_cells_through_the_worker(kind, &CELLS_AFTER_HEAP_HITS).await;
        assert_eq!(requests.len(), 6, "{kind:?}: one model call per response");
        let last = &requests[5];
        for (cell, told) in (1..).zip(TOLD_AFTER_HEAP_HITS) {
            let texts = told_for_cell(kind, last, cell);
            let (header, told) = match told {
                None => (
                    "Script failed",
                    texts.iter().any(|text| text.ends_with(OUT_OF_MEMORY))
                        && texts.iter().any(|text| text == MEMORY_REPORT),
                ),
                Some(own) => (
                    "Script completed",
                    texts.iter().any(|text| text == own)
                        && !texts.iter().any(|text| text.contains("memory")),
                ),
            };
            assert!(
                texts.first().is_some_and(|first| first.starts_with(header)) && told,
                "{kind:?}: cell {cell} told the model: {texts:?}"
            );
        }
        assert_eq!(
            limits_in(&evidence),
            ["memory", "memory"],
            "{kind:?}: {evidence:?}"
        );
    }
}

/// A cell that yields at 200 ms and then waits a minute on a timer: running,
/// with its interpreter process live, when the model's next request arrives.
const WAITER: &str = "// @exec: {\"yield_time_ms\": 200}\n\
     await new Promise((resolve) => setTimeout(resolve, 60000));\n\
     text(\"the timer fired\");";

/// A cell that states it ran.
const RAN: &str = "text(\"a cell ran\");";

/// A Messages stream whose content is one Code Mode `wait` call on cell
/// `cell_id`.
fn claude_wait_reply(id: &str, cell_id: &str) -> mock_provider::Reply {
    let input = serde_json::json!({"cell_id": cell_id}).to_string();
    mock_provider::Reply::Events(vec![
        serde_json::json!({
            "type": "message_start",
            "message": {
                "id": format!("msg_{id}"), "type": "message", "role": "assistant",
                "model": "claude-mock", "content": [], "stop_reason": null,
                "stop_sequence": null,
                "usage": {"input_tokens": 10, "output_tokens": 1},
            },
        }),
        serde_json::json!({
            "type": "content_block_start", "index": 0,
            "content_block": {"type": "tool_use", "id": format!("toolu_{id}"), "name": "wait", "input": {}},
        }),
        serde_json::json!({
            "type": "content_block_delta", "index": 0,
            "delta": {"type": "input_json_delta", "partial_json": input},
        }),
        serde_json::json!({"type": "content_block_stop", "index": 0}),
        serde_json::json!({
            "type": "message_delta",
            "delta": {"stop_reason": "tool_use", "stop_sequence": null},
            "usage": {"output_tokens": 3},
        }),
        serde_json::json!({"type": "message_stop"}),
    ])
}

/// The model's replies for a `kind` turn whose cells are, in order, a
/// [`WAITER`], a `wait` on it held on `first` (cell 1), [`RAN`], a second
/// [`WAITER`], a `wait` on it held on `second` (cell 3), [`RAN`], then the
/// turn's answer: seven model calls.
fn cells_ending_their_interpreter(
    kind: kata_types::agent::AdapterKind,
    first: &mock_provider::Gate,
    second: &mock_provider::Gate,
) -> Vec<mock_provider::Reply> {
    let gated = |gate: &mock_provider::Gate, reply| {
        mock_provider::Reply::Gated(gate.clone(), Box::new(reply))
    };
    match kind {
        kata_types::agent::AdapterKind::NanocodeOpenai => {
            let code = |id: &str, source| {
                mock_provider::code_reply(id, source, mock_provider::usage(1, 0, 1))
            };
            let wait = |id: &str, cell| {
                mock_provider::wait_reply(id, cell, false, mock_provider::usage(1, 0, 1))
            };
            vec![
                code("r1", WAITER),
                gated(first, wait("r2", "1")),
                code("r3", RAN),
                code("r4", WAITER),
                gated(second, wait("r5", "3")),
                code("r6", RAN),
                mock_provider::message_reply("r7", "DONE", mock_provider::usage(1, 0, 1)),
            ]
        }
        kata_types::agent::AdapterKind::NanocodeAnthropic => vec![
            mock_provider::claude_code_reply("r1", WAITER),
            gated(first, claude_wait_reply("r2", "1")),
            mock_provider::claude_code_reply("r3", RAN),
            mock_provider::claude_code_reply("r4", WAITER),
            gated(second, claude_wait_reply("r5", "3")),
            mock_provider::claude_code_reply("r6", RAN),
            mock_provider::claude_text_reply("DONE"),
        ],
    }
}

/// How long [`kill_the_waiter`] waits, in real time, for the kernel to list
/// the waiter's interpreter process alone.
const WAITER_LISTED_BOUND: std::time::Duration = std::time::Duration::from_secs(20);

/// Once `mock` has recorded `requests` model requests (the waiter has
/// yielded, so its cell runs), kills by SIGKILL the one interpreter process
/// the kernel lists of this one, the waiter's (an earlier cell's is reaped
/// when its host drops, so the listing is awaited until it holds exactly
/// one), then opens `killed`, letting the model's `wait` go out.
async fn kill_the_waiter(
    mock: &mock_provider::MockProvider,
    requests: usize,
    killed: &mock_provider::Gate,
) {
    mock.wait_for_requests(requests).await;
    let alone = async {
        loop {
            let listed = quickjs_threads::interpreters();
            if listed.len() == 1 {
                return listed;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    };
    let listed = tokio::time::timeout(WAITER_LISTED_BOUND, alone)
        .await
        .unwrap_or_else(|_| {
            panic!(
                "the waiter's interpreter was not listed alone within {WAITER_LISTED_BOUND:?}: \
                 {:?}",
                quickjs_threads::interpreters()
            )
        });
    let pid = listed.first().copied().expect("one interpreter");
    let pid =
        rustix::process::Pid::from_raw(i32::try_from(pid).expect("a pid")).expect("a nonzero pid");
    rustix::process::kill_process(pid, rustix::process::Signal::KILL)
        .expect("kill the waiter's interpreter");
    killed.open();
}

/// **A nanocode turn whose cells' interpreter processes are killed while they
/// run completes through the worker, and the published evidence records each
/// end.** On each kind, a turn through the whole capsule composition under
/// kata's Code Mode limits: the model's cells are a waiter, a `wait` on it, a
/// text, a second waiter, a `wait` on it and a text. While each waiter runs,
/// this test kills its interpreter process (the one the kernel lists) by
/// SIGKILL, the signal the kernel's OOM killer delivers (every interpreter
/// runs at `oom_score_adj` 1000, the first it picks); MEASURED at 8ec3b215, no
/// cell-reachable way to end a djs interpreter by a signal is known (a bind
/// flood, which ended QuickJS's by SIGSEGV, is a plain heap hit under djs:
/// `kata-agent-nanocode`'s `code_mode_interpreter_through_adapter.rs`), so the
/// end comes from outside. The worker reports a completed capsule; each
/// `wait`'s result carries the cell's error naming the end (`Script
/// error:\nCode Mode's interpreter process ended by SIGKILL`) and each text
/// cell after it its own text; the session evidence the worker published,
/// read back off the rig's CAS by the report's ref, names two
/// `CodeModeInterpreterEnded{SIGKILL}`; and once the worker returned the kernel
/// lists no interpreter process of this one. The process this runs in stands
/// for the node hosting the worker (the child twin below reads its exit
/// status).
///
/// **Would red if:** the supervisor did not report an interpreter that ended
/// while its cell ran (no record), the worker published the evidence without
/// the adapter's records of it, an interpreter's end failed the turn instead
/// of the cell (no completed capsule) or ended Code Mode for the turn (the
/// text cell after it fails), or the cells ran in this process (no interpreter
/// is listed: the bounded listing fails).
#[tokio::test]
async fn a_turn_whose_cells_end_their_interpreter_completes_and_records_each_end() {
    let error = format!("Script error:\n{}SIGKILL", kata_code_mode_host::ENDED_BY);
    for kind in [
        kata_types::agent::AdapterKind::NanocodeOpenai,
        kata_types::agent::AdapterKind::NanocodeAnthropic,
    ] {
        let (first, second) = (
            mock_provider::Gate::default(),
            mock_provider::Gate::default(),
        );
        let mock = mock_provider::MockProvider::start(cells_ending_their_interpreter(
            kind, &first, &second,
        ))
        .await;
        let (evidence, ()) = tokio::join!(nanocode_turn_through_the_worker(kind, &mock), async {
            kill_the_waiter(&mock, 2, &first).await;
            kill_the_waiter(&mock, 5, &second).await;
        });
        let requests = mock.requests();
        assert_eq!(requests.len(), 7, "{kind:?}: one model call per response");
        for (request, cell, told) in [
            (1, 1, "Script running with cell ID 1"),
            (2, 2, error.as_str()),
            (3, 3, "a cell ran"),
            (4, 4, "Script running with cell ID 3"),
            (5, 5, error.as_str()),
            (6, 6, "a cell ran"),
        ] {
            let texts = told_for_cell(kind, &requests[request], cell);
            assert!(
                texts.iter().any(|text| text.starts_with(told)),
                "{kind:?}: call r{cell} told the model {told:?}: {texts:?}"
            );
        }
        let ended: Vec<_> = evidence
            .events
            .iter()
            .filter(|event| {
                matches!(
                    event,
                    kata_types::agent::SessionEvidenceEvent::CodeModeInterpreterEnded { .. }
                )
            })
            .collect();
        let killed = kata_types::agent::SessionEvidenceEvent::CodeModeInterpreterEnded {
            signal: Some("SIGKILL".into()),
        };
        assert_eq!(ended, [&killed, &killed], "{kind:?}: {evidence:?}");
        assert!(
            quickjs_threads::interpreters().is_empty(),
            "{kind:?}: every interpreter process was reaped: {:?}",
            quickjs_threads::interpreters()
        );
    }
}

/// **Twin, in a CHILD: a worker turn whose cells end their
/// interpreter process ends no other process.** A child of this binary runs
/// `a_turn_whose_cells_end_their_interpreter_completes_and_records_each_end`
/// alone, and the kernel reports it exited 0 with that cell passed.
///
/// **Would red if:** an interpreter's death took down the process that
/// hosts the worker (the child ends by its signal, or by the panic of a
/// supervisor that met its interpreter's end unprepared: exit status 101), or
/// the cells ran in that process (no interpreter is listed to kill: the
/// bounded listing panics, exit status 101).
#[test]
fn a_worker_turn_whose_cells_end_their_interpreter_ends_no_other_process() {
    let output = std::process::Command::new(std::env::current_exe().expect("this test binary"))
        .args([
            "--exact",
            "a_turn_whose_cells_end_their_interpreter_completes_and_records_each_end",
            "--nocapture",
            "--test-threads=1",
        ])
        .output()
        .expect("run the turn in a child");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "the child ended {:?} (signal {:?}):\n{stderr}",
        output.status,
        std::os::unix::process::ExitStatusExt::signal(&output.status)
    );
    assert!(
        String::from_utf8_lossy(&output.stdout).contains("test result: ok. 1 passed"),
        "the child ran the one cell"
    );
}

/// **Twin, in a CHILD: a worker turn whose cells hit the heap ends
/// no process.** A child of this binary runs
/// `a_turn_whose_cells_hit_the_heap_completes_and_its_later_cells_run` alone,
/// and the kernel reports it exited 0 with that cell passed.
///
/// **Would red if:** a heap hit ended the process that hosts the worker (the
/// child ends by its signal: an engine that aborted on an allocation failure,
/// as QuickJS's did, inside that process), or a cell after a heap hit ran in
/// the heap the hit filled (the child's turn fails, exit status 101).
#[test]
fn a_worker_turn_whose_cells_hit_the_heap_ends_no_process() {
    let output = std::process::Command::new(std::env::current_exe().expect("this test binary"))
        .args([
            "--exact",
            "a_turn_whose_cells_hit_the_heap_completes_and_its_later_cells_run",
            "--nocapture",
            "--test-threads=1",
        ])
        .output()
        .expect("run the turn in a child");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "the child ended {:?} (signal {:?}):\n{stderr}",
        output.status,
        std::os::unix::process::ExitStatusExt::signal(&output.status)
    );
    assert!(
        String::from_utf8_lossy(&output.stdout).contains("test result: ok. 1 passed"),
        "the child ran the one cell"
    );
}

/// How long [`hold_the_clock_until_the_mock_records`] waits, in real time, for
/// the request it holds the clock on.
const CLOCK_HOLD_BOUND: std::time::Duration = std::time::Duration::from_secs(20);

/// Holds the cell's tokio clock still until `mock` has recorded `requests`
/// model requests, then lets it run on: whether they arrived inside
/// [`CLOCK_HOLD_BOUND`] of real time.
///
/// A turn's wall arms at its launch on the runtime's clock (`agent_turn`, "THE
/// TURN'S WALL CLOCK"), and everything before the turn's first request bills
/// against it: the attempt root's directories on `TMPDIR`'s filesystem,
/// nanocode's read of `/work/AGENTS.md`, its agent's build, the requests before
/// the one held. A cell whose subject is what follows a request stalled at the
/// wall raced all of that against a 1.5 s budget, and lost it when `TMPDIR`'s
/// disk stalled (watched: every `mkdir` delayed 500 ms, and no request reached
/// the mock before the wall). With the clock held, the wall arms at the held
/// instant and counts its whole budget from the release, so it expires with
/// that request stalled at the mock however long the turn took to send it.
/// From the release on, every timer — the wall, the worker's stop grace,
/// nanocode's own turn end — runs on real time, as in production.
///
/// The cell's runtime starts paused (`#[tokio::test(start_paused = true)]`) and
/// takes this hold before the turn starts: a paused runtime advances its clock
/// to the next timer whenever it idles, and a running blocking task is what
/// stops that (tokio's `test-util`). No timer fires while the clock is held,
/// so the turn up to the held request must wait on none; past
/// [`CLOCK_HOLD_BOUND`] the clock runs on anyway and the cell names the
/// premise it missed.
fn hold_the_clock_until_the_mock_records(
    mock: &mock_provider::MockProvider,
    requests: usize,
) -> tokio::task::JoinHandle<bool> {
    let recorded = mock.request_counter();
    tokio::task::spawn_blocking(move || {
        let started = std::time::Instant::now();
        let arrived = loop {
            if recorded() >= requests {
                break true;
            }
            if started.elapsed() >= CLOCK_HOLD_BOUND {
                break false;
            }
            std::thread::sleep(std::time::Duration::from_millis(5));
        };
        tokio::time::resume();
        arrived
    })
}

/// **A nanocode stop confirmed during the turn's end is not lost to the
/// deadline race.** The wall budget expires while the turn's model request
/// stalls at the mock provider: the cell holds its clock until the mock has
/// recorded that request ([`hold_the_clock_until_the_mock_records`]), and the
/// wall counts its 1.5 s from there. The token stops the turn and nanocode confirms
/// the cancel at once, but the session's turn end then waits out a `KillAll`
/// the toolhost double never answers (5 s) before `prompt` hands the
/// `Cancelled` back: more than the worker's own five-second grace. The worker
/// waits the session's stated `stop_grace` instead, so the attempt settles as
/// the confirmed cancel the wall demanded, with its usage reported (the
/// `Unavailable` shape: no call reported usage), not as an unconfirmed stop.
///
/// **Would red if:** the worker's race ignored the session's stop grace (the
/// reason would say the grace passed without the harness confirming).
#[tokio::test(start_paused = true)]
async fn a_nanocode_stop_confirmed_during_its_turn_end_is_not_lost_to_the_race() {
    const TOKEN: &str = "sk-nanocode-stop-grace-5a1e";
    let rig = rig();
    let mut env = std::collections::BTreeMap::new();
    env.insert("KATA_FIXTURE_TOKEN".to_string(), TOKEN.to_string());
    let credentials = kata_worker::agent_credential::AgentCredentialSource::for_test(env);
    let mock = mock_provider::MockProvider::start(vec![mock_provider::Reply::Stall]).await;
    let held = hold_the_clock_until_the_mock_records(&mock, 1);
    let (tree, tree_ref) = empty_tree(&rig);
    let (environment, claim) = publish_manifest(&rig);
    let prompt = rig.publish_prompt("write the file");
    let occurrence = OccurrenceId(FixedBytes([0x6f; 32]));
    let capsule = agent_capsule_budgeted(
        occurrence,
        environment,
        tree,
        prompt,
        kata_types::agent::AdapterKind::NanocodeOpenai,
        Some(credential_ref(
            kata_types::metering::CredentialMode::ApiKey,
            kata_types::execution_contract::CredentialSource::EnvVar {
                var: smol_str::SmolStr::new("KATA_FIXTURE_TOKEN"),
            },
        )),
        Some("gpt-6-luna".into()),
        1_500,
    );
    let frame = frame_for(publish_capsule(&rig, &capsule), occurrence);
    let attempt_root = rig.dir.path().join("attempt");
    let source = rig.reader();
    let refs = vec![(prompt, prompt_ref(&rig, prompt)), (tree, tree_ref)];
    let trees = FixtureTrees { tree, refs };
    let driver = ToolhostDriver {
        attempt_root: attempt_root.clone(),
        config: toolhost_double::DoubleConfig {
            swallow_kill_all: true,
            ..toolhost_double::DoubleConfig::default()
        },
        witness: std::sync::Mutex::new(None),
    };
    let sink = CasBlobSink(&rig.cas);
    let adapters = kata_agent::adapter::capsule_registry::StaticAgentAdapterRegistry::new([
        std::sync::Arc::new(
            kata_agent_nanocode::NanocodeAdapter::openai().with_endpoint(
                kata_agent_nanocode::adapter::TestEndpoint {
                    url: mock.url.clone(),
                    websocket_url: None,
                },
            ),
        ) as std::sync::Arc<dyn kata_agent::adapter::AgentAdapter>,
    ]);
    let refusal = execute_capsule_frame(
        &CapsuleExecution {
            driver: &driver,
            environments: &FixedIndex(Some(claim)),
            trees: &trees,
            source: &source,
            probe: &FixedProbe(true),
            sink: &sink,
            adapters: &adapters,
            credentials: &credentials,
        },
        &frame,
        std::time::Instant::now(),
        tokio::sync::oneshot::channel().1,
        None,
    )
    .await
    .expect_err("a turn the wall stopped is a refusal");
    assert!(
        held.await.expect("the clock hold"),
        "the model request reached the mock within {CLOCK_HOLD_BOUND:?} of a held clock: {}",
        refusal.reason
    );
    assert_eq!(mock.requests().len(), 1, "the one model request stalled");
    assert!(
        refusal.reason.contains("agent_turn_timed_out")
            && refusal.reason.contains("confirmed the cancel"),
        "the confirmed cancel rides through the race: {}",
        refusal.reason
    );
    let usage = refusal
        .usage
        .as_ref()
        .expect("a confirmed cancel names its usage");
    assert!(
        matches!(
            usage.cost,
            kata_types::metering::MeteredCost::Unavailable { .. }
        ),
        "no call reported usage, so the burn is Unavailable, never zero: {usage:?}"
    );
    let witness = driver
        .witness
        .lock()
        .expect("the witness slot")
        .take()
        .expect("the toolhost double was started");
    assert!(
        witness.stdin_closed(),
        "the turn's end dropped the toolhost's stdin after the unconfirmed KillAll"
    );
}

/// **A `nanocode_openai` `api_key` turn's recorded charge is `Unavailable`,
/// with its tokens.** The turn asks for `gpt-5.4-mini` — a model the built-in
/// OpenAI table has a row for — under an `env:` key. The model's first call
/// runs one Code Mode cell and reports 1200 input and 80 output tokens; its
/// second call stalls until the wall stops the turn, and nanocode confirms the
/// cancel. The cell holds its clock until the mock has recorded that second
/// call ([`hold_the_clock_until_the_mock_records`]), and the wall counts its
/// 1.5 s from there. The attempt's refusal then goes through the real accept path, and
/// the accepting transition's `terminal_charge`, read off a second raw
/// handle, is `Unavailable` naming the kind and the model, with the tokens the
/// first call reported: the table is not re-verified for a nanocode kind, so
/// no estimate is recorded from it, and the spend is never zero.
///
/// **Would red if:** `nanocode_openai` billed against OpenAI's table (the
/// charge would be `Estimated`), or the burn before the stop were dropped.
#[tokio::test(start_paused = true)]
async fn a_nanocode_api_key_turn_records_its_tokens_and_an_unavailable_cost() {
    const TOKEN: &str = "sk-nanocode-metered-unavailable-3b7d";
    let rig = rig();
    let mut env = std::collections::BTreeMap::new();
    env.insert("KATA_FIXTURE_TOKEN".to_string(), TOKEN.to_string());
    let credentials = kata_worker::agent_credential::AgentCredentialSource::for_test(env);
    let mock = mock_provider::MockProvider::start(vec![
        mock_provider::code_reply("r1", "text(\"one\");", mock_provider::usage(1200, 0, 80)),
        mock_provider::Reply::Stall,
    ])
    .await;
    let held = hold_the_clock_until_the_mock_records(&mock, 2);
    let (tree, tree_ref) = empty_tree(&rig);
    let (environment, claim) = publish_manifest(&rig);
    let prompt = rig.publish_prompt("write the file");
    let occurrence = OccurrenceId(FixedBytes([0x70; 32]));
    let capsule = agent_capsule_budgeted(
        occurrence,
        environment,
        tree,
        prompt,
        kata_types::agent::AdapterKind::NanocodeOpenai,
        Some(credential_ref(
            kata_types::metering::CredentialMode::ApiKey,
            kata_types::execution_contract::CredentialSource::EnvVar {
                var: smol_str::SmolStr::new("KATA_FIXTURE_TOKEN"),
            },
        )),
        Some("gpt-5.4-mini".into()),
        1_500,
    );
    let frame = frame_for(publish_capsule(&rig, &capsule), occurrence);
    let source = rig.reader();
    let refs = vec![(prompt, prompt_ref(&rig, prompt)), (tree, tree_ref)];
    let trees = FixtureTrees { tree, refs };
    let driver = ToolhostDriver {
        attempt_root: rig.dir.path().join("attempt"),
        config: toolhost_double::DoubleConfig::default(),
        witness: std::sync::Mutex::new(None),
    };
    let sink = CasBlobSink(&rig.cas);
    let adapters = kata_agent::adapter::capsule_registry::StaticAgentAdapterRegistry::new([
        std::sync::Arc::new(
            kata_agent_nanocode::NanocodeAdapter::openai().with_endpoint(
                kata_agent_nanocode::adapter::TestEndpoint {
                    url: mock.url.clone(),
                    websocket_url: None,
                },
            ),
        ) as std::sync::Arc<dyn kata_agent::adapter::AgentAdapter>,
    ]);
    let refusal = execute_capsule_frame(
        &CapsuleExecution {
            driver: &driver,
            environments: &FixedIndex(Some(claim)),
            trees: &trees,
            source: &source,
            probe: &FixedProbe(true),
            sink: &sink,
            adapters: &adapters,
            credentials: &credentials,
        },
        &frame,
        std::time::Instant::now(),
        tokio::sync::oneshot::channel().1,
        None,
    )
    .await
    .expect_err("a turn the wall stopped is a refusal");
    assert!(
        held.await.expect("the clock hold"),
        "both model requests reached the mock within {CLOCK_HOLD_BOUND:?} of a held clock: {}",
        refusal.reason
    );
    assert_eq!(
        mock.requests().len(),
        2,
        "the cell's call, then the stalled one: {}",
        refusal.reason
    );

    let payload: serde_json::Value =
        serde_json::from_str(&durable_failure_transition(rig.dir.path(), &refusal))
            .expect("the transition payload is JSON");
    let charge = &payload["terminal_charge"]["token_usage"];
    assert_eq!(
        (&charge["input"], &charge["output"]),
        (&serde_json::json!(1200), &serde_json::json!(80)),
        "the durable charge keeps the tokens the first call reported: {payload}"
    );
    assert_eq!(
        charge["cost"],
        serde_json::json!({
            "quality": "unavailable",
            "backend": "nanocode_openai",
            "model": "gpt-5.4-mini",
        }),
        "the durable charge is Unavailable, never an estimate from the table: {payload}"
    );
    assert!(
        charge.get("cost_micro_usd").is_none(),
        "an Unavailable charge carries no figure a reader could sum: {payload}"
    );
}

/// **A `nanocode_anthropic` `api_key` turn is PRICED from the Anthropic rows — the
/// mock provider's usage, the worker's charge, the arithmetic.** The Messages mock
/// answers one call stating 1000 uncached input, 5000 cache read, 800 cache
/// creation and 300 output tokens for `claude-sonnet-5-5`. The worker's own
/// completion carries the turn's report, whose usage holds those four classes
/// apart and an `Estimated` cost read off the `anthropic` row dated
/// `PRICE_TABLE_AS_OF`: 1000 × $2 + 300 × $10 + 5000 × $0.10 (0.05× input)
/// + 800 × $2.50 (the 5-minute write, 1.25× input), per million — $0.0075, 7500
/// micro-USD. No live provider: a funded turn's charge is a maintainer's live
/// acceptance, and this is its no-spend proof.
///
/// **Would red if:** the kind were unpriced (`Unavailable`), the cache writes were
/// counted inside `input` too (9100 micro-USD: the 800 written tokens billed at
/// both rates), or a class were priced at another rate.
#[tokio::test]
async fn a_nanocode_anthropic_api_key_turn_is_priced_from_the_anthropic_rows() {
    const TOKEN: &str = "sk-ant-fake";
    let rig = rig();
    let mut env = std::collections::BTreeMap::new();
    env.insert("KATA_FIXTURE_TOKEN".to_string(), TOKEN.to_string());
    let credentials = kata_worker::agent_credential::AgentCredentialSource::for_test(env);
    let mock = mock_provider::MockProvider::start(vec![mock_provider::claude_text_reply_using(
        "done",
        serde_json::json!({
            "input_tokens": 1_000,
            "cache_read_input_tokens": 5_000,
            "cache_creation_input_tokens": 800,
            "output_tokens": 1,
        }),
        300,
    )])
    .await;
    let (tree, tree_ref) = empty_tree(&rig);
    let (environment, claim) = publish_manifest(&rig);
    let prompt = rig.publish_prompt("say done");
    let occurrence = OccurrenceId(FixedBytes([0x71; 32]));
    let capsule = agent_capsule_with(
        occurrence,
        environment,
        tree,
        prompt,
        kata_types::agent::AdapterKind::NanocodeAnthropic,
        Some(credential_ref(
            kata_types::metering::CredentialMode::ApiKey,
            kata_types::execution_contract::CredentialSource::EnvVar {
                var: smol_str::SmolStr::new("KATA_FIXTURE_TOKEN"),
            },
        )),
        Some("claude-sonnet-5-5".into()),
    );
    let frame = frame_for(publish_capsule(&rig, &capsule), occurrence);
    let source = rig.reader();
    let refs = vec![(prompt, prompt_ref(&rig, prompt)), (tree, tree_ref)];
    let trees = FixtureTrees { tree, refs };
    let driver = ToolhostDriver {
        attempt_root: rig.dir.path().join("attempt"),
        config: toolhost_double::DoubleConfig::default(),
        witness: std::sync::Mutex::new(None),
    };
    let sink = CasBlobSink(&rig.cas);
    let adapters = kata_agent::adapter::capsule_registry::StaticAgentAdapterRegistry::new([
        std::sync::Arc::new(
            kata_agent_nanocode::NanocodeAdapter::anthropic().with_endpoint(
                kata_agent_nanocode::adapter::TestEndpoint {
                    url: format!("{}/messages", mock.url),
                    websocket_url: None,
                },
            ),
        ) as std::sync::Arc<dyn kata_agent::adapter::AgentAdapter>,
    ]);
    let completed = execute_capsule_frame(
        &CapsuleExecution {
            driver: &driver,
            environments: &FixedIndex(Some(claim)),
            trees: &trees,
            source: &source,
            probe: &FixedProbe(true),
            sink: &sink,
            adapters: &adapters,
            credentials: &credentials,
        },
        &frame,
        std::time::Instant::now(),
        tokio::sync::oneshot::channel().1,
        None,
    )
    .await
    .unwrap_or_else(|refusal| panic!("the turn completes: {}", refusal.reason));
    let WorkerMessage::CompletedCapsule {
        agent: Some(report),
        ..
    } = completed
    else {
        panic!("an agent capsule's completion carries its turn report: {completed:?}");
    };
    let usage = report.usage.expect("the provider reported usage");
    assert_eq!(
        (
            usage.input,
            usage.output,
            usage.cache_read,
            usage.cache_write
        ),
        (1_000, 300, 5_000, 800),
        "the four classes the provider stated, disjoint: {usage:?}"
    );
    assert_eq!(
        usage.cost,
        kata_types::metering::MeteredCost::Estimated {
            micro_usd: 7_500,
            basis: kata_types::metering::EstimateBasis::PriceTable {
                rates_as_of: kata_worker::pricing::PRICE_TABLE_AS_OF.into(),
            },
        },
        "priced from the claude-sonnet-5-5 row: {usage:?}"
    );
    assert_eq!(usage.cost_micro_usd, Some(7_500));
    assert_eq!(mock.requests().len(), 1, "one model call");
}

/// Every path under `root`, each with its modification time; empty when `root`
/// is absent. A file created, or truncated and rewritten, under `root` changes
/// this set, and so does an entry added to any directory in it.
fn tree_stamps(
    root: &std::path::Path,
) -> std::collections::BTreeSet<(std::path::PathBuf, std::time::SystemTime)> {
    let mut stamps = std::collections::BTreeSet::new();
    let mut pending = vec![root.to_path_buf()];
    while let Some(path) = pending.pop() {
        let Ok(metadata) = std::fs::symlink_metadata(&path) else {
            continue;
        };
        stamps.insert((path.clone(), metadata.modified().expect("an mtime")));
        if metadata.is_dir() {
            for entry in std::fs::read_dir(&path).expect("a readable directory") {
                pending.push(entry.expect("a directory entry").path());
            }
        }
    }
    stamps
}

/// **A nanocode turn's background `Bash` leaves no task output file on the
/// worker.** nanocode's own Claude `Bash` (`claude_bash`) spools a background
/// task's output to `temp_dir()/nanocode/<session>/tasks/<id>.output` in the
/// process hosting the agent loop, which is the worker, and never removes it; its
/// process integration roots shells at `temp_dir()/nanocode-shell-<pid>-…`. The
/// adapter installs nanocode's HOST `Bash` instead, which spools nothing: the
/// output stays in the capsule's session and reaches the worker only as the
/// call's result. Through the worker, an Anthropic turn starts `sleep 600` in
/// the background, waits for its `Exec`, and stops it with `TaskStop`; afterwards
/// the worker's own filesystem, read directly, holds nothing new or rewritten
/// under `temp_dir()/nanocode` and no `nanocode-shell-<this pid>-…` root, and the
/// `Bash` result the model read (the mock's recorded request) names no file
/// there.
///
/// **Would red if:** the adapter took nanocode's default Claude tool selection
/// (watched: `nanocode_backend_claude::runner_tools_with_executor` in
/// `Seam::install_claude_tools` creates `nanocode/local/tasks/local-bash-0.output`).
#[tokio::test]
async fn a_nanocode_background_bash_leaves_no_task_file_on_the_worker() {
    const TOKEN: &str = "sk-ant-fake";
    let spool = std::env::temp_dir().join("nanocode");
    let shell_root = format!("nanocode-shell-{}-", std::process::id());
    let before = tree_stamps(&spool);
    let rig = rig();
    let mut env = std::collections::BTreeMap::new();
    env.insert("KATA_FIXTURE_TOKEN".to_string(), TOKEN.to_string());
    let credentials = kata_worker::agent_credential::AgentCredentialSource::for_test(env);
    let mock = mock_provider::MockProvider::start(vec![
        mock_provider::claude_code_reply(
            "r1",
            &toolhost_double::stop_a_background_bash_once_its_exec_arrived(),
        ),
        mock_provider::claude_text_reply("stopped"),
    ])
    .await;
    let (tree, tree_ref) = empty_tree(&rig);
    let (environment, claim) = publish_manifest(&rig);
    let prompt = rig.publish_prompt("go");
    let occurrence = OccurrenceId(FixedBytes([0x72; 32]));
    let capsule = agent_capsule_with(
        occurrence,
        environment,
        tree,
        prompt,
        kata_types::agent::AdapterKind::NanocodeAnthropic,
        Some(credential_ref(
            kata_types::metering::CredentialMode::ApiKey,
            kata_types::execution_contract::CredentialSource::EnvVar {
                var: smol_str::SmolStr::new("KATA_FIXTURE_TOKEN"),
            },
        )),
        Some("claude-sonnet-5-5".into()),
    );
    let frame = frame_for(publish_capsule(&rig, &capsule), occurrence);
    let source = rig.reader();
    let refs = vec![(prompt, prompt_ref(&rig, prompt)), (tree, tree_ref)];
    let trees = FixtureTrees { tree, refs };
    let driver = ToolhostDriver {
        attempt_root: rig.dir.path().join("attempt"),
        config: toolhost_double::DoubleConfig {
            execs: vec![toolhost_double::ExecMode::Hold],
            exec_marker: Some(toolhost_double::EXEC_MARKER.to_owned()),
            ..toolhost_double::DoubleConfig::default()
        },
        witness: std::sync::Mutex::new(None),
    };
    let sink = CasBlobSink(&rig.cas);
    let adapters = kata_agent::adapter::capsule_registry::StaticAgentAdapterRegistry::new([
        std::sync::Arc::new(
            kata_agent_nanocode::NanocodeAdapter::anthropic().with_endpoint(
                kata_agent_nanocode::adapter::TestEndpoint {
                    url: format!("{}/messages", mock.url),
                    websocket_url: None,
                },
            ),
        ) as std::sync::Arc<dyn kata_agent::adapter::AgentAdapter>,
    ]);
    let completed = execute_capsule_frame(
        &CapsuleExecution {
            driver: &driver,
            environments: &FixedIndex(Some(claim)),
            trees: &trees,
            source: &source,
            probe: &FixedProbe(true),
            sink: &sink,
            adapters: &adapters,
            credentials: &credentials,
        },
        &frame,
        std::time::Instant::now(),
        tokio::sync::oneshot::channel().1,
        None,
    )
    .await;

    let added: Vec<_> = tree_stamps(&spool).difference(&before).cloned().collect();
    assert!(
        added.is_empty(),
        "the turn wrote under the worker's {}: {added:?}",
        spool.display()
    );
    let shells: Vec<_> = std::fs::read_dir(std::env::temp_dir())
        .expect("the worker's temp dir")
        .filter_map(|entry| entry.ok().map(|entry| entry.file_name()))
        .filter(|name| name.to_string_lossy().starts_with(&shell_root))
        .collect();
    assert!(
        shells.is_empty(),
        "a nanocode shell root on the worker: {shells:?}"
    );
    let completed =
        completed.unwrap_or_else(|refusal| panic!("the turn completes: {}", refusal.reason));
    assert!(
        matches!(completed, WorkerMessage::CompletedCapsule { .. }),
        "{completed:?}"
    );
    let requests = mock.requests();
    assert_eq!(
        requests.len(),
        2,
        "the code cell, then the model's last word"
    );
    let read = requests[1].to_string();
    assert!(
        read.contains("Successfully stopped task"),
        "the model read TaskStop's answer: {read}"
    );
    assert!(
        read.contains("running in background") && !read.contains(&spool.display().to_string()),
        "the background Bash result names no worker file: {read}"
    );
}

/// One `nanocode_openai` turn through the worker over the toolhost double,
/// under kata's Code Mode limits as the worker installs them, its model the
/// mock answering `replies` in order: the worker's own result, the record it
/// hands the main.
async fn a_nanocode_turn(
    replies: Vec<mock_provider::Reply>,
    seed: u8,
) -> Result<WorkerMessage, kata_worker::capsule_execution::CapsuleAttemptRefusal> {
    let mock = mock_provider::MockProvider::start(replies).await;
    let (result, _witness) = a_nanocode_turn_on(NanocodeTurn {
        mock: &mock,
        seed,
        double: toolhost_double::DoubleConfig::default(),
        wall_time_ms: 30_000,
        stop: tokio::sync::oneshot::channel().1,
    })
    .await;
    result
}

/// One `nanocode_openai` turn through the worker: its model `mock`, its
/// toolhost the double `double` configures, its wall budget `wall_time_ms`,
/// and `stop` the attempt's fenced stop (the operator's cancel).
struct NanocodeTurn<'a> {
    mock: &'a mock_provider::MockProvider,
    seed: u8,
    double: toolhost_double::DoubleConfig,
    wall_time_ms: u64,
    stop: tokio::sync::oneshot::Receiver<String>,
}

/// Run `turn` under kata's Code Mode limits as the worker installs them (each
/// cell in an interpreter process): the worker's own result, and the toolhost
/// double's witness.
async fn a_nanocode_turn_on(
    turn: NanocodeTurn<'_>,
) -> (
    Result<WorkerMessage, kata_worker::capsule_execution::CapsuleAttemptRefusal>,
    toolhost_double::DoubleWitness,
) {
    const TOKEN: &str = "sk-nanocode-live-workers-7c2b";
    kata_agent_nanocode::install_code_mode_limits();
    let NanocodeTurn {
        mock,
        seed,
        double,
        wall_time_ms,
        stop,
    } = turn;
    let rig = rig();
    let mut env = std::collections::BTreeMap::new();
    env.insert("KATA_FIXTURE_TOKEN".to_string(), TOKEN.to_string());
    let credentials = kata_worker::agent_credential::AgentCredentialSource::for_test(env);
    let (tree, tree_ref) = empty_tree(&rig);
    let (environment, claim) = publish_manifest(&rig);
    let prompt = rig.publish_prompt("sort");
    let occurrence = OccurrenceId(FixedBytes([seed; 32]));
    let capsule = agent_capsule_budgeted(
        occurrence,
        environment,
        tree,
        prompt,
        kata_types::agent::AdapterKind::NanocodeOpenai,
        Some(credential_ref(
            kata_types::metering::CredentialMode::ApiKey,
            kata_types::execution_contract::CredentialSource::EnvVar {
                var: smol_str::SmolStr::new("KATA_FIXTURE_TOKEN"),
            },
        )),
        Some("gpt-6-luna".into()),
        wall_time_ms,
    );
    let frame = frame_for(publish_capsule(&rig, &capsule), occurrence);
    let source = rig.reader();
    let refs = vec![(prompt, prompt_ref(&rig, prompt)), (tree, tree_ref)];
    let trees = FixtureTrees { tree, refs };
    let driver = ToolhostDriver {
        attempt_root: rig.dir.path().join("attempt"),
        config: double,
        witness: std::sync::Mutex::new(None),
    };
    let sink = CasBlobSink(&rig.cas);
    let adapters = kata_agent::adapter::capsule_registry::StaticAgentAdapterRegistry::new([
        std::sync::Arc::new(
            kata_agent_nanocode::NanocodeAdapter::openai().with_endpoint(
                kata_agent_nanocode::adapter::TestEndpoint {
                    url: mock.url.clone(),
                    websocket_url: None,
                },
            ),
        ) as std::sync::Arc<dyn kata_agent::adapter::AgentAdapter>,
    ]);
    let result = execute_capsule_frame(
        &CapsuleExecution {
            driver: &driver,
            environments: &FixedIndex(Some(claim)),
            trees: &trees,
            source: &source,
            probe: &FixedProbe(true),
            sink: &sink,
            adapters: &adapters,
            credentials: &credentials,
        },
        &frame,
        std::time::Instant::now(),
        stop,
        None,
    )
    .await;
    let witness = driver
        .witness
        .lock()
        .expect("the witness slot")
        .take()
        .expect("the toolhost double was started");
    (result, witness)
}

/// What the kernel charged over one second after a turn: the CPU time, in
/// clock ticks, of this process's Code Mode interpreter processes listed at
/// its start, and of this process itself (every thread of it; a child's time
/// is not this process's own).
struct TicksOverASecond {
    interpreters: std::collections::BTreeSet<u32>,
    interpreters_burned: u64,
    this_process_burned: u64,
}

/// [`TicksOverASecond`], read now.
async fn ticks_over_a_second() -> TicksOverASecond {
    let interpreters = quickjs_threads::interpreters();
    let in_interpreters = || {
        interpreters
            .iter()
            .copied()
            .filter_map(quickjs_threads::process_cpu_ticks)
            .sum::<u64>()
    };
    let this_process = || quickjs_threads::process_cpu_ticks(std::process::id()).unwrap_or(0);
    let before = (in_interpreters(), this_process());
    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    TicksOverASecond {
        interpreters_burned: in_interpreters().saturating_sub(before.0),
        this_process_burned: this_process().saturating_sub(before.1),
        interpreters,
    }
}

/// The CPU time a cell spinning in this process for the whole of a
/// [`ticks_over_a_second`] second is charged at least half of: 50 ticks of
/// the 100 the kernel counts a second in (`/proc`'s `USER_HZ`, 100 on Linux).
/// An idle test process is charged a few; a cell spinning in one of its
/// threads, a whole second's worth.
const SPIN_IN_THIS_PROCESS_TICKS: u64 = 50;

/// The attempts kata's wire lets one model call fail before it refuses the
/// next (`kata_agent_nanocode`'s `adapter::wire::ATTEMPTS`), written out: a
/// call that fails transiently on either kind is sent exactly this many times.
const WIRE_ATTEMPTS: usize = 5;

/// The mock's answers to a Responses call that fails transiently while a cell
/// runs: its connection dropped 500 ms after it arrives, and each of its
/// re-sends, to kata's attempt budget ([`WIRE_ATTEMPTS`]), dropped at once.
/// The turn ends about 16 s after the call (nanocode's 1, 2, 4 and 8 s of
/// backoff), its transient failure past them.
fn a_call_its_connection_drops() -> impl Iterator<Item = mock_provider::Reply> {
    std::iter::once(mock_provider::Reply::DropAfter(
        std::time::Duration::from_millis(500),
    ))
    .chain(std::iter::repeat_n(
        mock_provider::Reply::Drop,
        WIRE_ATTEMPTS - 1,
    ))
}

/// **No nanocode Code Mode cell outlives the harness's shutdown, one inside a
/// long native step included, and the refusal names no live worker.** The
/// worker publishes a turn's session evidence only when the turn completes,
/// and a cell could outlive the shutdown only on a turn that does not:
/// nanocode detaches a failed turn's cells. Two turns, each a cell that yields
/// at 100 ms and waits 100 ms on a timer, and a next model request whose
/// connection drops 500 ms after it arrives, as do nanocode's re-sends of it
/// ([`a_call_its_connection_drops`]), so each turn ends a transient provider
/// failure about 7 s in with its cell running:
///
/// * the cell then spins in JavaScript;
/// * the cell then runs one long default-comparator sort, a native step no
///   interrupt reaches ([`quickjs_threads::A_LONG_NATIVE_STEP`]; MEASURED at
///   8ec3b215 on djs, 1.1 s for 8,000 references, so about 35 s for its
///   200,000, past the turn's end, the shutdown's grace and the witness's
///   second).
///
/// Either way the shutdown's terminate kills the cell's interpreter process
/// and reaps it before the live-worker count is read: the refusal names no
/// live Code Mode worker, the kernel lists no interpreter process of this one
/// once the worker returned, so none burns CPU, and this process itself is
/// charged under half a second of CPU over the next second, so no cell spins
/// in it either.
///
/// Each refusal is read as the main stores it: its `worker_reason` off the
/// acceptance transition, through the real accept path and a second raw
/// handle ([`durable_worker_reason`]).
///
/// **Would red if:** the cells ran in this process (with kata's backend not
/// installed, nanocode's embedded host runs a cell inline on a tokio runtime
/// thread of this one, which the spin or the sort holds past the turn: this
/// process is charged that second), or the supervisor released the
/// live-worker count before the reap (the refusal names a live worker), or the
/// shutdown left an interpreter running (one is listed).
#[tokio::test]
async fn no_nanocode_cell_outlives_the_shutdown_a_native_step_included() {
    let turn = |tail: &str, seed: u8| {
        a_nanocode_turn(
            std::iter::once(mock_provider::code_reply(
                "r1",
                &format!(
                    "// @exec: {{\"yield_time_ms\": 100}}\n\
                     await new Promise((resolve) => setTimeout(resolve, 100));\n{tail}"
                ),
                mock_provider::usage(1, 0, 1),
            ))
            .chain(a_call_its_connection_drops())
            .collect(),
            seed,
        )
    };
    for (tail, seed) in [
        ("while (true) {}", 0x7a),
        (quickjs_threads::A_LONG_NATIVE_STEP, 0x7b),
    ] {
        let refused = turn(tail, seed)
            .await
            .expect_err("a turn whose model request failed is a refusal");
        let ticks = ticks_over_a_second().await;
        assert!(
            ticks.interpreters.is_empty() && ticks.interpreters_burned == 0,
            "{tail}: interpreter processes {:?} burned {} ticks after the turn",
            ticks.interpreters,
            ticks.interpreters_burned
        );
        assert!(
            ticks.this_process_burned < SPIN_IN_THIS_PROCESS_TICKS,
            "{tail}: this process burned {} ticks in the second after the turn: a cell runs in it",
            ticks.this_process_burned
        );
        let reason = durable_worker_reason(&refused);
        assert!(
            reason.contains("the model provider failed the turn (transient)"),
            "{tail}: the turn is a transient provider failure: {reason}"
        );
        assert!(
            !reason.contains("code_mode_workers_live"),
            "{tail}: the refusal names a live worker: {reason}"
        );
    }
}

/// The double's witness that the worker's `KillAll` frames went unanswered:
/// its own log holds exactly `sent` of them (a cancel sends its own before
/// the turn end's), and its own record of the worker closing its stdin, the
/// turn end's fallback.
fn assert_the_kill_all_went_unanswered(witness: &toolhost_double::DoubleWitness, sent: usize) {
    let kinds = witness.kinds();
    assert_eq!(
        kinds.iter().filter(|kind| **kind == "kill_all").count(),
        sent,
        "{kinds:?}"
    );
    assert!(
        witness.stdin_closed(),
        "the unanswered KillAll closed the toolhost's stdin: {kinds:?}"
    );
}

/// **A failed nanocode turn whose `KillAll` went unanswered names it in the
/// refusal the main stores, and its cell does not outlive the turn.** The
/// model's first request starts a cell that yields at 100 ms, waits 100 ms on a
/// timer and then runs one long native sort
/// ([`quickjs_threads::A_LONG_NATIVE_STEP`]); the next request's connection
/// drops 500 ms after it arrives, as do nanocode's re-sends of it
/// ([`a_call_its_connection_drops`]), so the turn ends a transient provider
/// failure with the sort running, and the
/// toolhost double never answers the turn end's `KillAll`. The `worker_reason`
/// read off the acceptance transition through a second raw handle
/// ([`durable_worker_reason`]) names `kill_all: unconfirmed` and no live Code
/// Mode worker: the harness's shutdown, after the unanswered `KillAll`'s grace,
/// kills and reaps the sort's interpreter process, and the kernel lists no
/// interpreter process of this one once the worker returned. The double's own
/// log holds the one `KillAll` and its stdin's close.
///
/// **Would red if:** the worker folded no `TurnEnd` into a refusal's reason
/// (watched: the reason names no `kill_all`).
#[tokio::test]
async fn a_failed_nanocode_turn_names_its_unanswered_kill_all_in_the_refusal() {
    let mock = mock_provider::MockProvider::start(
        vec![mock_provider::code_reply(
            "r1",
            &format!(
                "// @exec: {{\"yield_time_ms\": 100}}\n\
                 await new Promise((resolve) => setTimeout(resolve, 100));\n{}",
                quickjs_threads::A_LONG_NATIVE_STEP
            ),
            mock_provider::usage(1, 0, 1),
        )]
        .into_iter()
        .chain(a_call_its_connection_drops())
        .collect(),
    )
    .await;
    let (result, witness) = a_nanocode_turn_on(NanocodeTurn {
        mock: &mock,
        seed: 0x7c,
        double: toolhost_double::DoubleConfig {
            swallow_kill_all: true,
            ..toolhost_double::DoubleConfig::default()
        },
        wall_time_ms: 30_000,
        stop: tokio::sync::oneshot::channel().1,
    })
    .await;
    let refusal = result.expect_err("a turn whose model request failed is a refusal");
    let ticks = ticks_over_a_second().await;
    assert!(
        ticks.interpreters.is_empty() && ticks.interpreters_burned == 0,
        "interpreter processes {:?} burned {} ticks after the turn",
        ticks.interpreters,
        ticks.interpreters_burned
    );
    assert_the_kill_all_went_unanswered(&witness, 1);
    let stored = durable_worker_reason(&refusal);
    assert!(
        stored.contains("the model provider failed the turn (transient)"),
        "the failed turn is a transient provider failure: {stored}"
    );
    assert!(stored.contains("kill_all: unconfirmed"), "{stored}");
    assert!(
        !stored.contains("code_mode_workers_live"),
        "the shutdown reaped the sort's interpreter: {stored}"
    );
}

/// **A cancelled nanocode turn whose `KillAll` went unanswered names it in the
/// refusal the main stores.** The model's one request stalls; the operator's
/// fenced stop goes out once the mock has it, nanocode confirms the cancel,
/// and neither the cancel's `KillAll` nor the turn end's gets an answer from
/// the toolhost double, so `prompt` hands back `Cancelled` after the turn
/// end's 5 s grace and the stdin's close.
/// The stored `worker_reason` ([`durable_worker_reason`]) is the confirmed
/// cancel's and names `kill_all: unconfirmed`; no cell ran, so it names no
/// live Code Mode worker (behind kata's backend even a cell inside a native
/// step leaves nanocode able to confirm: the cancel kills its interpreter,
/// `nanocode_qualification::a_cancel_during_a_native_step_is_confirmed_behind_kata_backend`).
///
/// **Would red if:** the worker folded no `TurnEnd` into a refusal's reason
/// (watched: the reason names no `kill_all`).
#[tokio::test]
async fn a_cancelled_nanocode_turn_names_its_unanswered_kill_all_in_the_refusal() {
    let mock = mock_provider::MockProvider::start(vec![mock_provider::Reply::Stall]).await;
    let (stop, stopped) = tokio::sync::oneshot::channel();
    let ((result, witness), ()) = tokio::join!(
        a_nanocode_turn_on(NanocodeTurn {
            mock: &mock,
            seed: 0x7d,
            double: toolhost_double::DoubleConfig {
                swallow_kill_all: true,
                ..toolhost_double::DoubleConfig::default()
            },
            wall_time_ms: 30_000,
            stop: stopped,
        }),
        async {
            mock.wait_for_requests(1).await;
            stop.send("the operator's stop".to_owned())
                .expect("the worker still awaits its stop");
        }
    );
    let refusal = result.expect_err("a cancelled turn is a refusal");
    assert_eq!(mock.requests().len(), 1, "the one model request stalled");
    assert_the_kill_all_went_unanswered(&witness, 2);
    let stored = durable_worker_reason(&refusal);
    assert!(
        stored.contains("the fenced stop cancelled the turn"),
        "nanocode confirmed the operator's cancel: {stored}"
    );
    assert!(stored.contains("kill_all: unconfirmed"), "{stored}");
    assert!(
        !stored.contains("code_mode_workers_live"),
        "no cell ran: {stored}"
    );
}

/// A session standing in for the embedded harness's two `Cancelled` rows
/// nobody confirmed (`kata_agent_nanocode`'s outcome map: a stop on a clean
/// watermark nanocode never confirmed, and kata's own gate refusal on one):
/// `prompt` waits for the cancel token when `asked`, else returns at once, and
/// answers `Cancelled` with no usage; `close` reports the teardown confirmed
/// and NO acknowledged cancel. The real harness reaches these rows only on a
/// race (MEASURED: an operator stop out before the turn starts is confirmed by
/// nanocode at once), so the fixture states them.
struct UnconfirmedStopAdapter {
    asked: bool,
}

struct UnconfirmedStopSession {
    id: kata_agent::adapter::SessionId,
    asked: bool,
    _process: Box<dyn InteractiveProcess>,
}

impl kata_agent::adapter::AgentAdapter for UnconfirmedStopAdapter {
    fn kind(&self) -> kata_types::agent::AdapterKind {
        kata_types::agent::AdapterKind::NanocodeOpenai
    }

    fn open(
        &self,
        _scope: kata_agent::adapter::AttemptScope,
        process: Box<dyn InteractiveProcess>,
    ) -> Result<Box<dyn kata_agent::adapter::AgentSession>, kata_agent::adapter::OpenRefusal> {
        Ok(Box::new(UnconfirmedStopSession {
            id: kata_agent::adapter::SessionId::new("unconfirmed-stop"),
            asked: self.asked,
            _process: process,
        }))
    }
}

#[async_trait::async_trait]
impl kata_agent::adapter::AgentSession for UnconfirmedStopSession {
    fn session_id(&self) -> &kata_agent::adapter::SessionId {
        &self.id
    }

    async fn prompt(
        &mut self,
        _prompt: &kata_types::agent::Prompt,
        cancel: &kata_agent::adapter::session::CancelToken,
    ) -> kata_agent::adapter::TurnOutcome {
        while self.asked && !cancel.is_cancelled() {
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        kata_agent::adapter::TurnOutcome::Cancelled { usage: None }
    }

    fn issuance(&self) -> Option<kata_agent::adapter::MayHaveIssued> {
        None
    }

    fn take_evidence(&mut self) -> kata_types::agent::SessionEvidence {
        kata_types::agent::SessionEvidence {
            events: Vec::new(),
            events_dropped: 0,
            scratch_commits: Vec::new(),
        }
    }

    async fn close(self: Box<Self>) -> kata_agent::adapter::CleanupReport {
        kata_agent::adapter::CleanupReport::new(
            TeardownOutcome::Confirmed {
                probe: kata_agent::resource_bounds::TeardownProbe::SignalProbe,
                elapsed_ms: 0,
            },
            false,
        )
    }
}

/// The stored `worker_reason` ([`durable_worker_reason`]) of one turn of
/// [`UnconfirmedStopAdapter`] through the worker, the operator's fenced stop
/// sent once the turn is in flight when `asked`.
async fn an_unconfirmed_stop_turn(asked: bool, seed: u8) -> String {
    const TOKEN: &str = "sk-unconfirmed-stop-4e1d";
    let rig = rig();
    let mut env = std::collections::BTreeMap::new();
    env.insert("KATA_FIXTURE_TOKEN".to_string(), TOKEN.to_string());
    let credentials = kata_worker::agent_credential::AgentCredentialSource::for_test(env);
    let (tree, tree_ref) = empty_tree(&rig);
    let (environment, claim) = publish_manifest(&rig);
    let prompt = rig.publish_prompt("go");
    let occurrence = OccurrenceId(FixedBytes([seed; 32]));
    let capsule = agent_capsule_budgeted(
        occurrence,
        environment,
        tree,
        prompt,
        kata_types::agent::AdapterKind::NanocodeOpenai,
        Some(credential_ref(
            kata_types::metering::CredentialMode::ApiKey,
            kata_types::execution_contract::CredentialSource::EnvVar {
                var: smol_str::SmolStr::new("KATA_FIXTURE_TOKEN"),
            },
        )),
        Some("gpt-6-luna".into()),
        30_000,
    );
    let frame = frame_for(publish_capsule(&rig, &capsule), occurrence);
    let source = rig.reader();
    let refs = vec![(prompt, prompt_ref(&rig, prompt)), (tree, tree_ref)];
    let trees = FixtureTrees { tree, refs };
    let driver = ToolhostDriver {
        attempt_root: rig.dir.path().join("attempt"),
        config: toolhost_double::DoubleConfig::default(),
        witness: std::sync::Mutex::new(None),
    };
    let sink = CasBlobSink(&rig.cas);
    let adapters = kata_agent::adapter::capsule_registry::StaticAgentAdapterRegistry::new([
        std::sync::Arc::new(UnconfirmedStopAdapter { asked })
            as std::sync::Arc<dyn kata_agent::adapter::AgentAdapter>,
    ]);
    let (stop, stopped) = tokio::sync::oneshot::channel();
    let execution = CapsuleExecution {
        driver: &driver,
        environments: &FixedIndex(Some(claim)),
        trees: &trees,
        source: &source,
        probe: &FixedProbe(true),
        sink: &sink,
        adapters: &adapters,
        credentials: &credentials,
    };
    let turn = execute_capsule_frame(&execution, &frame, std::time::Instant::now(), stopped, None);
    let result = if asked {
        stop.send("the operator's stop".to_owned())
            .expect("the worker still awaits its stop");
        turn.await
    } else {
        let result = turn.await;
        drop(stop);
        result
    };
    durable_worker_reason(&result.expect_err("a cancelled turn is a refusal"))
}

/// **A `Cancelled` nobody confirmed is never worded as confirmed.** The
/// session answers `Cancelled` and its close report records no acknowledged
/// cancel ([`UnconfirmedStopAdapter`]). With the operator's fenced stop sent,
/// the stored `worker_reason` ([`durable_worker_reason`]) says the stop went
/// out, the turn stopped before it issued anything, and the harness did not
/// confirm; with no stop sent, it says kata never asked for the stop. Neither
/// says a confirmation happened.
///
/// **Would red if:** the worker worded every `Cancelled` as a confirmed cancel
/// (watched: the reason said "the harness confirmed the cancel").
#[tokio::test]
async fn a_cancel_nobody_confirmed_is_never_worded_as_confirmed() {
    let stored = an_unconfirmed_stop_turn(true, 0x80).await;
    assert!(
        stored.contains("the fenced stop cancelled the turn")
            && stored.contains("before it issued anything")
            && stored.contains("did not confirm the stop"),
        "the operator's stop is worded as kata observed it: {stored}"
    );
    assert!(!stored.contains("confirmed the"), "{stored}");

    let stored = an_unconfirmed_stop_turn(false, 0x81).await;
    assert!(
        stored.contains("before it issued anything")
            && stored.contains("kata never asked for")
            && !stored.contains("fenced stop"),
        "a stop nobody asked for is worded as such: {stored}"
    );
    assert!(!stored.contains("confirmed the"), "{stored}");
}

/// **A nanocode turn the worker abandons past its stop grace names the
/// unanswered `KillAll` its `close` found.** The toolhost double answers no
/// `ReadFile`, so `prompt` holds at its read of `/work/AGENTS.md`, before
/// nanocode's agent is built and before any model request; the 1.5 s wall
/// expires, the session's stop grace passes, and the worker drops the turn's
/// future and drains its evidence. Only then does `close` run the turn's end:
/// its `KillAll` gets no answer, and the stdin is closed. The stored
/// `worker_reason` ([`durable_worker_reason`]) is the timed-out refusal of a
/// turn whose watermark was never crossed and names `kill_all: unconfirmed`,
/// which only `close`'s report (`CleanupReport::turn_end`) carried. No agent
/// was built, so no count is named: `close` reporting the turn end it ran for a
/// dropped turn, its count included, is pinned on the session,
/// `nanocode_qualification::close_reports_the_turn_end_it_ran_for_a_dropped_future`,
/// and the worker reads `close`'s records as it reads the evidence's.
///
/// **Would red if:** the worker dropped `close`'s turn-end records (watched:
/// the reason names no `kill_all`).
#[tokio::test]
async fn a_nanocode_turn_abandoned_past_its_stop_grace_names_closes_kill_all_in_the_refusal() {
    let mock = mock_provider::MockProvider::start(Vec::new()).await;
    let (result, witness) = a_nanocode_turn_on(NanocodeTurn {
        mock: &mock,
        seed: 0x7e,
        double: toolhost_double::DoubleConfig {
            swallow_kill_all: true,
            reads: toolhost_double::ReadMode::Hold,
            ..toolhost_double::DoubleConfig::default()
        },
        wall_time_ms: 1_500,
        stop: tokio::sync::oneshot::channel().1,
    })
    .await;
    let refusal = result.expect_err("a turn the wall stopped is a refusal");
    assert!(mock.requests().is_empty(), "no model request left");
    assert_eq!(
        witness.kinds()[0],
        "read_file",
        "the turn held at its first read: {:?}",
        witness.kinds()
    );
    assert_the_kill_all_went_unanswered(&witness, 1);
    let stored = durable_worker_reason(&refusal);
    assert!(
        stored.contains("agent_turn_timed_out") && stored.contains("never crossed"),
        "the abandoned turn is the timed-out refusal of a clean watermark: {stored}"
    );
    assert!(stored.contains("kill_all: unconfirmed"), "{stored}");
    assert!(
        !stored.contains("code_mode_workers_live"),
        "no agent was built: {stored}"
    );
}

/// The `worker_reason` the main stores for `refusal`: the refusal fed through
/// its real accept path, read off the acceptance transition by a second raw
/// handle ([`durable_failure_transition`]), not off the refusal itself.
fn durable_worker_reason(
    refusal: &kata_worker::capsule_execution::CapsuleAttemptRefusal,
) -> String {
    let dir = tempfile::tempdir().expect("an operational db directory");
    let payload: serde_json::Value =
        serde_json::from_str(&durable_failure_transition(dir.path(), refusal))
            .expect("the transition payload is JSON");
    payload["worker_reason"]
        .as_str()
        .expect("the transition carries the worker's reason")
        .to_owned()
}

// ---------------------------------------------------------------------------
// The wall clock at its declared-bound ceiling
// ---------------------------------------------------------------------------

/// **`Instant` arithmetic at the declared-bound ceiling.** `u64::MAX` ms of
/// wall budget is a legal declaration: `checked_add` overflows, and the
/// fallback must land the deadline in the future, never subtract it into the
/// past (a deadline that fires before the prompt is not a budget) or panic on
/// the underflow the `Instant` API can raise.
#[tokio::test]
async fn an_astronomical_wall_budget_completes_instead_of_wedging_on_the_deadline() {
    let mock = mock_provider::MockProvider::start(vec![mock_provider::message_reply(
        "r1",
        "done",
        mock_provider::usage(10, 0, 2),
    )])
    .await;
    let (reported, _witness) = a_nanocode_turn_on(NanocodeTurn {
        mock: &mock,
        seed: 0x7B,
        double: toolhost_double::DoubleConfig::default(),
        wall_time_ms: u64::MAX,
        stop: tokio::sync::oneshot::channel().1,
    })
    .await;
    let reported = reported.unwrap_or_else(|refusal| {
        panic!(
            "a legal `u64::MAX` wall budget completes; the fallback deadline \
             lives in the future, not a subtraction into the past: {refusal}"
        )
    });
    assert!(
        matches!(reported, WorkerMessage::CompletedCapsule { .. }),
        "the largest legal budget is still a turn, not a refusal"
    );
}

// ---------------------------------------------------------------------------
// A turn its model provider failed — the class the worker settles from
// nanocode's typed error, read through the real accept path
// ---------------------------------------------------------------------------

/// A nanocode kind, for the provider-failure cells that run once per kind; the
/// Responses kind over HTTPS ([`Self::OpenAi`]) or over its production
/// transport, the WebSocket ([`Self::OpenAiWebSocket`]).
#[derive(Clone, Copy, Debug)]
enum NanocodeKind {
    OpenAi,
    OpenAiWebSocket,
    Anthropic,
}

const NANOCODE_KINDS: [NanocodeKind; 2] = [NanocodeKind::OpenAi, NanocodeKind::Anthropic];

/// The Anthropic API's own words for an account without credit (N6, 2026-11-04).
const CREDIT_REFUSAL: &str = "Your credit balance is too low to access the Anthropic API. \
     Please go to Plans & Billing to upgrade or purchase credits.";

impl NanocodeKind {
    const fn adapter_kind(self) -> kata_types::agent::AdapterKind {
        match self {
            Self::OpenAi | Self::OpenAiWebSocket => kata_types::agent::AdapterKind::NanocodeOpenai,
            Self::Anthropic => kata_types::agent::AdapterKind::NanocodeAnthropic,
        }
    }

    const fn model(self) -> &'static str {
        match self {
            Self::OpenAi | Self::OpenAiWebSocket => "gpt-6-luna",
            Self::Anthropic => "claude-sonnet-5-5",
        }
    }

    /// The kind's adapter pointed at `mock`.
    fn adapter(self, mock: &mock_provider::MockProvider) -> kata_agent_nanocode::NanocodeAdapter {
        match self {
            Self::OpenAi | Self::OpenAiWebSocket => kata_agent_nanocode::NanocodeAdapter::openai()
                .with_endpoint(kata_agent_nanocode::adapter::TestEndpoint {
                    url: mock.url.clone(),
                    websocket_url: matches!(self, Self::OpenAiWebSocket)
                        .then(|| mock.ws_url.clone()),
                }),
            Self::Anthropic => kata_agent_nanocode::NanocodeAdapter::anthropic().with_endpoint(
                kata_agent_nanocode::adapter::TestEndpoint {
                    url: format!("{}/messages", mock.url),
                    websocket_url: None,
                },
            ),
        }
    }

    /// A 400 refusing the request for credit, in the kind's error shape: over
    /// the WebSocket, the `error` event stating the status.
    fn credit_refusal(self) -> mock_provider::Reply {
        let body = match self {
            Self::OpenAiWebSocket => {
                return mock_provider::Reply::Events(vec![serde_json::json!({
                    "type": "error", "status": 400, "error": {
                        "message": CREDIT_REFUSAL, "type": "invalid_request_error",
                        "param": null, "code": null,
                    },
                })]);
            }
            Self::OpenAi => serde_json::json!({"error": {
                "message": CREDIT_REFUSAL, "type": "invalid_request_error", "param": null, "code": null,
            }}),
            Self::Anthropic => serde_json::json!({"type": "error", "error": {
                "type": "invalid_request_error", "message": CREDIT_REFUSAL,
            }}),
        };
        mock_provider::Reply::Status(400, body)
    }

    /// A 500 server error, in the kind's error shape: transient to both
    /// clients, and not a status either waits out.
    fn server_error(self) -> mock_provider::Reply {
        match self {
            Self::OpenAi | Self::OpenAiWebSocket => mock_provider::Reply::Status(
                500,
                serde_json::json!({"error": {
                    "message": "mock server error", "type": "server_error", "param": null,
                    "code": null,
                }}),
            ),
            Self::Anthropic => mock_provider::Reply::Status(
                500,
                serde_json::json!({"type": "error", "error": {
                    "type": "api_error", "message": "mock server error",
                }}),
            ),
        }
    }

    /// A reply whose Code Mode cell runs `true` in the capsule.
    fn runs_true(self) -> mock_provider::Reply {
        match self {
            Self::OpenAi | Self::OpenAiWebSocket => mock_provider::exec_command_reply(
                "r1",
                &serde_json::json!({"cmd": "true", "yield_time_ms": 30_000}),
                mock_provider::usage(1, 0, 1),
            ),
            Self::Anthropic => mock_provider::claude_code_reply(
                "r1",
                "const result = await tools.Bash({\"command\": \"true\"});\ntext(JSON.stringify(result));",
            ),
        }
    }

    /// A reply that ends the turn with `done`.
    fn answers(self) -> mock_provider::Reply {
        match self {
            Self::OpenAi | Self::OpenAiWebSocket => {
                mock_provider::message_reply("r9", "done", mock_provider::usage(1, 0, 1))
            }
            Self::Anthropic => mock_provider::claude_text_reply("done"),
        }
    }
}

/// One `kind` turn through the worker against `mock`, in a capsule on
/// `network`, over the toolhost double, under kata's Code Mode limits: the
/// worker's own result and the double's witness. `attempt` names the attempt
/// root, so two attempts of one cell never share one.
async fn a_provider_turn(
    kind: NanocodeKind,
    mock: &mock_provider::MockProvider,
    network: CapsuleNetwork,
    attempt: &str,
) -> (
    Result<WorkerMessage, kata_worker::capsule_execution::CapsuleAttemptRefusal>,
    toolhost_double::DoubleWitness,
) {
    const TOKEN: &str = "sk-nanocode-provider-failure-5e1a";
    kata_agent_nanocode::install_code_mode_limits();
    let rig = rig();
    let mut env = std::collections::BTreeMap::new();
    env.insert("KATA_FIXTURE_TOKEN".to_string(), TOKEN.to_string());
    let credentials = kata_worker::agent_credential::AgentCredentialSource::for_test(env);
    let (tree, tree_ref) = empty_tree(&rig);
    let (environment, claim) = publish_manifest(&rig);
    let prompt = rig.publish_prompt("go");
    let occurrence = OccurrenceId(FixedBytes([0x5e; 32]));
    let template = agent_capsule_with(
        occurrence,
        environment,
        tree,
        prompt,
        kind.adapter_kind(),
        Some(credential_ref(
            kata_types::metering::CredentialMode::ApiKey,
            kata_types::execution_contract::CredentialSource::EnvVar {
                var: smol_str::SmolStr::new("KATA_FIXTURE_TOKEN"),
            },
        )),
        Some(kind.model().into()),
    );
    let capsule = Capsule::new(
        template.occurrence(),
        template.action(),
        template.environment(),
        template.platform(),
        template.inputs().to_vec(),
        template.process().clone(),
        network,
        None,
        template.budgets(),
        None,
    )
    .expect("the capsule is well formed");
    let frame = frame_for(publish_capsule(&rig, &capsule), occurrence);
    let source = rig.reader();
    let refs = vec![(prompt, prompt_ref(&rig, prompt)), (tree, tree_ref)];
    let trees = FixtureTrees { tree, refs };
    let driver = ToolhostDriver {
        attempt_root: rig.dir.path().join(attempt),
        config: toolhost_double::DoubleConfig::default(),
        witness: std::sync::Mutex::new(None),
    };
    let sink = CasBlobSink(&rig.cas);
    let adapters = kata_agent::adapter::capsule_registry::StaticAgentAdapterRegistry::new([
        std::sync::Arc::new(kind.adapter(mock))
            as std::sync::Arc<dyn kata_agent::adapter::AgentAdapter>,
    ]);
    let result = execute_capsule_frame(
        &CapsuleExecution {
            driver: &driver,
            environments: &FixedIndex(Some(claim)),
            trees: &trees,
            source: &source,
            probe: &FixedProbe(true),
            sink: &sink,
            adapters: &adapters,
            credentials: &credentials,
        },
        &frame,
        std::time::Instant::now(),
        tokio::sync::oneshot::channel().1,
        None,
    )
    .await;
    let witness = driver
        .witness
        .lock()
        .expect("the witness slot")
        .take()
        .expect("the toolhost double was started");
    (result, witness)
}

/// The accepting transition the real accept path writes for `refusal`, read
/// back through a second raw handle, as JSON.
fn durable_payload(
    refusal: &kata_worker::capsule_execution::CapsuleAttemptRefusal,
) -> serde_json::Value {
    let dir = tempfile::tempdir().expect("an operational db directory");
    serde_json::from_str(&durable_failure_transition(dir.path(), refusal))
        .expect("the transition payload is JSON")
}

/// The provider's words for an account past its quota, in the Responses
/// error shape: `insufficient_quota`, a code nanocode reads as terminal.
const QUOTA_REFUSAL: &str =
    "You exceeded your current quota, please check your plan and billing details.";

/// **A nanocode turn its provider REFUSED is PROVEN NOT PERFORMED, names the
/// provider's reason, and is charged NOTHING, on either kind and on both
/// Responses transports.** The mock answers the turn's request refusing it: a
/// 400 for credit over HTTP on either kind; over the WebSocket, an `error`
/// event stating a 400 for credit, which nanocode would re-send on a new
/// socket (MEASURED at 8ec3b215: five times, its `reconnectable` reading every
/// `error` event without a terminal code so) and kata's wire does not, and one
/// stating a 429 `insufficient_quota`. Through the real accept path and a
/// second raw handle, the attempt's durable record holds the verdict
/// `proven_not_performed`, the class `refused`, the authoritative `0` charge
/// (a 4xx answer promises no processing), and the provider's status, error
/// type and message in the worker's reason; the mock's own log holds the one
/// request.
///
/// **Would red if:** the turn were classified by the bytes that left (watched,
/// with the adapter's provider-failure arm removed — the earlier
/// classification: `proven_ambiguous`, no class, an `Unavailable` charge), or a
/// refusal of the one request were charged as unknown (watched, with
/// `Wire::failed_turn_charge`'s `Nothing` arm removed: an `Unavailable`
/// charge), or the WebSocket's error event went unread (the WebSocket rows
/// `proven_ambiguous`), or kata's wire re-sent the WebSocket's refusal
/// (watched before the wire: six requests, an `unavailable` charge).
#[tokio::test]
async fn a_provider_refused_nanocode_turn_is_proven_not_performed_and_charged_nothing() {
    let quota = serde_json::json!({"type": "error", "status": 429, "error": {
        "type": "insufficient_quota", "code": "insufficient_quota", "param": null,
        "message": QUOTA_REFUSAL,
    }});
    for (kind, replies, reason, charged) in [
        (
            NanocodeKind::OpenAi,
            vec![NanocodeKind::OpenAi.credit_refusal()],
            format!("HTTP 400 invalid_request_error: {CREDIT_REFUSAL}"),
            serde_json::json!({"quality": "authoritative", "micro_usd": 0}),
        ),
        (
            NanocodeKind::OpenAiWebSocket,
            vec![NanocodeKind::OpenAiWebSocket.credit_refusal(); WIRE_ATTEMPTS],
            format!("HTTP 400 invalid_request_error: {CREDIT_REFUSAL}"),
            serde_json::json!({"quality": "authoritative", "micro_usd": 0}),
        ),
        (
            NanocodeKind::OpenAiWebSocket,
            vec![mock_provider::Reply::Events(vec![quota])],
            format!("HTTP 429 insufficient_quota (insufficient_quota): {QUOTA_REFUSAL}"),
            serde_json::json!({"quality": "authoritative", "micro_usd": 0}),
        ),
        (
            NanocodeKind::Anthropic,
            vec![NanocodeKind::Anthropic.credit_refusal()],
            format!("HTTP 400 invalid_request_error: {CREDIT_REFUSAL}"),
            serde_json::json!({"quality": "authoritative", "micro_usd": 0}),
        ),
    ] {
        let mock = mock_provider::MockProvider::start(replies).await;
        let (result, _witness) = a_provider_turn(kind, &mock, CapsuleNetwork::Offline, "a").await;
        let refusal = result.expect_err("a refused turn is a refusal");
        let payload = durable_payload(&refusal);
        assert_eq!(
            payload["verdict"], "proven_not_performed",
            "{kind:?}: {payload}"
        );
        assert_eq!(
            payload["provider_failure"], "refused",
            "{kind:?}: {payload}"
        );
        assert_eq!(
            payload["terminal_charge"]["token_usage"]["cost"], charged,
            "{kind:?}: {payload}"
        );
        let stored = payload["worker_reason"]
            .as_str()
            .expect("the worker's reason");
        assert!(
            stored.contains(&reason),
            "{kind:?}: the provider's own status, type and message: {stored}"
        );
        assert_eq!(mock.requests().len(), 1, "{kind:?}: the one request");
    }
}

/// **A TRANSIENT provider failure past the harness's retries is PROVEN NOT
/// PERFORMED, its charge unknown, and a fresh attempt takes the provider's
/// next answer, on either kind.** The first call is answered 500, a status
/// nanocode does not wait out (MEASURED at 8ec3b215: a 429, 502, 503, 504 or
/// 529 each client retries for up to 600 s, `nanocode_http`'s `PATIENCE`), every
/// time it is sent, to kata's attempt budget ([`WIRE_ATTEMPTS`]). The
/// first attempt's durable record holds `proven_not_performed`, the class
/// `transient` and an `Unavailable` charge (no call completed, and a transient
/// failure is no proof that nothing billed). A second attempt — a fresh
/// capsule from the same base, as the stage's failure retry dispatches
/// (`failure_retry_oci::
/// a_transient_provider_failure_is_rerun_on_the_same_agent_and_completes`) —
/// against the same mock completes on its next answer.
///
/// **Would red if:** the turn were classified by the bytes that left (watched,
/// with the adapter's provider-failure arm removed — the earlier
/// classification: `proven_ambiguous`, which the main never re-runs).
#[tokio::test]
async fn a_transient_nanocode_failure_is_not_performed_and_a_fresh_attempt_completes() {
    for kind in NANOCODE_KINDS {
        let attempts = WIRE_ATTEMPTS;
        let mut script = vec![kind.server_error(); attempts];
        script.push(kind.answers());
        let mock = mock_provider::MockProvider::start(script).await;
        let (first, _witness) = a_provider_turn(kind, &mock, CapsuleNetwork::Offline, "a").await;
        assert_eq!(
            mock.requests().len(),
            attempts,
            "{kind:?}: the call's attempts, to kata's budget"
        );
        let refusal = first.expect_err("a transient failure is a refusal");
        let payload = durable_payload(&refusal);
        assert_eq!(
            payload["verdict"], "proven_not_performed",
            "{kind:?}: {payload}"
        );
        assert_eq!(
            payload["provider_failure"], "transient",
            "{kind:?}: {payload}"
        );
        assert_eq!(
            payload["terminal_charge"]["token_usage"]["cost"]["quality"], "unavailable",
            "{kind:?}: an unknown charge, never zero: {payload}"
        );
        assert!(
            payload["worker_reason"]
                .as_str()
                .is_some_and(|reason| reason.contains("HTTP 500")),
            "{kind:?}: {payload}"
        );
        let (second, _witness) = a_provider_turn(kind, &mock, CapsuleNetwork::Offline, "b").await;
        let completed = second.unwrap_or_else(|refusal| {
            panic!("{kind:?}: the fresh attempt completes: {}", refusal.reason)
        });
        assert!(
            matches!(completed, WorkerMessage::CompletedCapsule { .. }),
            "{kind:?}: {completed:?}"
        );
        assert_eq!(mock.requests().len(), attempts + 1, "{kind:?}");
    }
}

/// **A provider failure stays AMBIGUOUS exactly when a tool call ran in a
/// capsule that can reach the network**, on either kind. The same script — the
/// first call's cell runs `true` in the capsule (the double's own log holds the
/// `exec`), the provider refuses the second request — settles PROVEN NOT
/// PERFORMED in an offline capsule (its effects are capsule-local and nothing
/// is published) and PROVEN AMBIGUOUS, with no class, in a capsule declaring
/// egress; a refusal with no tool call is PROVEN NOT PERFORMED in the
/// networked capsule too.
///
/// **Would red if:** the worker ignored the capsule's network (watched, with
/// `reached_beyond`'s network test removed: the networked capsule's tool-call
/// turn `proven_not_performed`), or the tool call (watched, with its tool-call
/// test removed: the networked capsule's turn with no tool call
/// `proven_ambiguous`), or the gate lost the tool call (watched, with
/// `TurnGate::mark_while_open`'s `tool_called` line removed:
/// `proven_not_performed`).
#[tokio::test]
async fn a_provider_failure_is_ambiguous_only_after_a_tool_call_in_a_networked_capsule() {
    let networked = || CapsuleNetwork::Egress {
        allowlist: std::collections::BTreeSet::from([
            kata_types::execution_contract::EgressAuthority::new("example.com", 443)
                .expect("an authority"),
        ]),
    };
    for kind in NANOCODE_KINDS {
        for (network, label, tool, verdict, class) in [
            (
                CapsuleNetwork::Offline,
                "offline",
                true,
                "proven_not_performed",
                "refused",
            ),
            (networked(), "networked", true, "proven_ambiguous", ""),
            (
                networked(),
                "networked, no tool",
                false,
                "proven_not_performed",
                "refused",
            ),
        ] {
            let mut script = Vec::new();
            if tool {
                script.push(kind.runs_true());
            }
            script.push(kind.credit_refusal());
            let mock = mock_provider::MockProvider::start(script).await;
            let (result, witness) = a_provider_turn(kind, &mock, network, "a").await;
            let refusal = result.expect_err("a failed turn is a refusal");
            assert_eq!(
                witness.kinds().contains(&"exec"),
                tool,
                "{kind:?} {label}: the double's own log of the exec: {:?}",
                witness.kinds()
            );
            let payload = durable_payload(&refusal);
            assert_eq!(payload["verdict"], verdict, "{kind:?} {label}: {payload}");
            assert_eq!(
                payload["provider_failure"].as_str().unwrap_or(""),
                class,
                "{kind:?} {label}: {payload}"
            );
            if verdict == "proven_ambiguous" {
                let reason = payload["worker_reason"].as_str().unwrap_or("");
                assert!(
                    reason.contains("issued=ToolCall")
                        && reason
                            .contains("a tool call ran in a capsule that can reach the network"),
                    "{kind:?} {label}: {reason}"
                );
            }
        }
    }
}

/// **A provider failure whose teardown could not confirm the container's
/// subtree empty is PROVEN AMBIGUOUS**, on either kind, as a completed turn's
/// is. The provider refuses the turn's one request in an offline capsule, no
/// tool ran — a refusal the worker otherwise settles PROVEN NOT PERFORMED — but
/// the placement's teardown reports `Ambiguous`. Through the real accept path
/// and a second raw handle, the durable record holds `proven_ambiguous`, no
/// class, and a worker reason naming the unconfirmed teardown.
///
/// **Would red if:** the worker settled a provider failure without its teardown
/// (watched, with the `ProviderFailed` arm's `|| !teardown_confirmed` removed:
/// `proven_not_performed`).
#[tokio::test]
async fn a_provider_failure_with_an_unconfirmed_teardown_is_proven_ambiguous() {
    for kind in NANOCODE_KINDS {
        *INJECTED_TEARDOWN
            .lock()
            .expect("the teardown injector is unpoisoned") = Some(TeardownOutcome::Ambiguous {
            reason: kata_agent::resource_bounds::AmbiguousTeardown::StillPresentAtDeadline {
                observed: "the fixture's subtree, still populated".to_owned(),
            },
            elapsed_ms: 0,
        });
        let mock = mock_provider::MockProvider::start(vec![kind.credit_refusal()]).await;
        let (result, witness) = a_provider_turn(kind, &mock, CapsuleNetwork::Offline, "a").await;
        assert!(!witness.kinds().contains(&"exec"), "{kind:?}: no tool ran");
        let refusal = result.expect_err("a failed turn is a refusal");
        let payload = durable_payload(&refusal);
        assert_eq!(
            payload["verdict"], "proven_ambiguous",
            "{kind:?}: {payload}"
        );
        assert!(payload["provider_failure"].is_null(), "{kind:?}: {payload}");
        let reason = payload["worker_reason"].as_str().unwrap_or("");
        assert!(
            reason.contains("the model provider failed the turn (refused)")
                && reason.contains("teardown could not confirm the container's subtree empty"),
            "{kind:?}: {reason}"
        );
    }
}
