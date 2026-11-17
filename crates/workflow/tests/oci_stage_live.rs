//! **The live OCI proof** — one real capsule runs in one real
//! rootless container, driven through the production driver, with every verdict read
//! back from the HOST.
//!
//! # Why this file lives in `kata-workflow` and not beside its OCI siblings
//!
//! It exercises THREE planes at once and needs all three crates in one process:
//! the environment plane (`kata_core::environment::declare_environment` roots
//! the busybox closure so nothing hand-realises it), the capsule plane
//! (`kata_workflow::capsule_assembly::assemble_capsule` over a shell stage compiled
//! from the shipped pack's own shape, plus a tree artifact published through
//! `CasStore::put_durable`), and the driver
//! (`kata_worker::oci_driver::OciStageDriver`). `kata-workflow` already
//! dev-depends on `kata-worker` and depends on `kata-core`, so this is the one
//! crate where that composition compiles without a new edge.
//!
//! # What is asserted against something that does not share the code under test
//!
//! * `/out/hi`'s BYTES are read with `cat` from the host after the container is
//!   gone — the file the guest's `sh` redirected into a directory kata bind-mounted;
//! * the stage's stdout arrives as a `completed` FRAME the provider wrote and this
//!   process decoded, and it carries the content of `/work/src/a.txt`, which only a
//!   container that really bound the materialized `/work` could have read;
//! * `youki --root <state> list` is run against the provider's OWN state root, so
//!   *"the runtime holds no container"* is the runtime's answer;
//! * the container's cgroup DIRECTORY is looked for on the filesystem after the
//!   drive returns, so *"the tree is gone"* is the kernel's answer;
//! * the closure's gc root is read with `nix-store --query --roots`, so *"the
//!   environment plane rooted it"* is nix's answer rather than kata's.
//!
//! # IT REFUSES ON A HOST WITH A STALE PROFILE, and the refusal is the pin's own mechanism
//!
//! When the youki pin moves its store path, `/etc/apparmor.d/youki` names the OLD
//! path until an operator runs, as root:
//!
//! ```text
//! sudo kata host apparmor-install
//! ```
//!
//! Until then `certify_youki` refuses `profile_file_differs` and this test FAILS
//! naming it — never skips. That is stated in the `#[ignore]` reason and in the
//! panic.
//!
//! # Every test RE-EXECS ITSELF inside a delegated user scope
//!
//! `certify_youki`'s delegation arm measures the CALLING process's own cgroup, and a
//! login session's cgroup is not delegated on this class of host — so without a
//! scope there is no measured basis and the provider has nothing admissible to
//! announce. `systemd-run --user --scope -p Delegate=yes` supplies one at zero
//! privilege, the same mechanism the three sibling OCI live files re-exec through.

#![cfg(target_os = "linux")]

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use kata_core::OperationalDb;
use kata_core::environment::{DeclarationInput, DeclarationSource, NixStore, declare_environment};
use kata_core::store::cas::CasStore;
use kata_program::execution_program::{compile_starlark_execution_program, lower_stage_operation};
use kata_test_utils::git::{hermetic_git_in, init_git_repo_at, run_git};
use kata_test_utils::youki_registry::youki_list;
use kata_types::execution_contract::{
    ArtifactId, ArtifactPrivacy, ArtifactRef, Capsule, CapsuleNetwork, CapsuleProcess,
    EgressAuthority, EnvironmentId, GuestPath, PlatformRef,
};
use kata_types::nix_environment::{
    IntegrityPolicy, NarVerification, NixEnvironmentManifest, RetentionClass, RetentionIntent,
    StorePath,
};
use kata_types::primitives::{FixedBytes, ObjectId};
use kata_types::sandbox::{ExecBackend, FsPolicy, NetPolicy, SandboxDirective, SandboxImage};
use kata_types::tree_artifact::{
    TreeEntry, TreeEntryMode, TreeManifest, TreeNode, TreePath, WorkTreeInputBounds,
};
use kata_types::workflow::StageId;
use kata_types::youki_pin::YoukiPin;
use kata_vcs::{JjBackend, VcsBackend};
use kata_worker::execution_route::{ExternalProviderAddress, OciRoute};
use kata_worker::materialize::{DeclaredTreeResolver, LocalCasBlobSource, LocalStorePathProbe};
use kata_worker::oci_driver::{
    OCI_PROVIDER_NAME, OciProviderInstallation, OciStageDriver, OciStageRequest,
};
use kata_worker::oci_runtime::certify_youki;
use kata_workflow::capsule_assembly::{
    NodeBudgetDefaults, RenderedCommand, assemble_capsule, empty_tree_artifact,
};
use smol_str::SmolStr;

// The production registry installs kata's Code Mode limits, which run each
// cell of a nanocode turn in an interpreter process: this binary, re-executed.
kata_code_mode_host::interpreter_entry!();

/// The real store path the OCI goldens and the three sibling live files name. One
/// statically linked busybox is the whole closure, and it is realised on the
/// reference host.
const BUSYBOX: &str =
    "/nix/store/qddzvnv6b0805nkvbqddbswddcfhx814-busybox-static-x86_64-unknown-linux-musl-1.37.0";

/// The bytes the guest reads out of `/work` — the proof that the materialized tree
/// really is what the container bound.
const SOURCE_PAYLOAD: &str = "capsule-work-tree\n";

/// What the guest writes into `/out` — read back off the host with `cat`.
const OUT_PAYLOAD: &str = "hi\n";

/// The stage the capsule is assembled from: the shipped
/// `workflows/smoke/sandbox-smoke-shell-offline.star`'s own shape — a `shell` stage in
/// an `offline`, `workspace = "rw"` profile — with a SHORT `timeout_ms` of its own.
///
/// # Why the shipped pack is not loaded verbatim, stated rather than hidden
///
/// It does not HAVE to be a reduction: through the authoring default, the
/// smoke rig carries `DEFAULT_STAGE_TIMEOUT_MS` and assembles — which is what
/// [`every_shipped_shell_stage_assembles`] asserts by name. This local pack survives
/// because a live container test wants a 30-second wall-time bound rather than an
/// hour: a wedged guest here should fail the run in half a minute, not hold a
/// delegated scope open until the nextest slow-timeout reaps it.
const PACK: &str = "probe = stage(\n\
     \x20   id = \"probe\",\n\
     \x20   agent = \"shell\",\n\
     \x20   sandbox = \"iso\",\n\
     \x20   timeout_ms = 30000,\n\
     \x20   prompt = \"echo hi > /out/hi; cat /work/src/a.txt\",\n\
     )\n\
     workflow(\n\
     \x20   \"oci-stage-live\",\n\
     \x20   root = [probe],\n\
     \x20   sandbox_profiles = {\"iso\": sandbox_profile(workspace = \"rw\", net = \"offline\")},\n\
     )\n";

/// The shipped shell smokes, read from the checkout so the family cannot drift away
/// from packs that no longer exist (an unreadable path panics rather than skipping).
const SHIPPED_SHELL_SMOKES: &[&str] = &[
    "workflows/smoke/sandbox-smoke-shell-offline.star",
    "workflows/smoke/sandbox-smoke-shell-workspace-ro.star",
    "workflows/smoke/sandbox-smoke-shell-write-closure.star",
];

// ---------------------------------------------------------------------------
// Rig
// ---------------------------------------------------------------------------

/// Marks the re-exec'd inner run, carrying the NAME of the test that asked for it, so
/// the child can never run a different body than the parent selected.
const INNER_ENV: &str = "KATA_OCI_STAGE_LIVE_INNER";

/// Run an async `body` inside a delegated user scope, re-exec'ing this binary if
/// needed. The sibling spelling in `crates/worker/tests/oci_provider_live.rs` carries
/// the reasoning; what must not be duplicated — what a delegated scope IS — is one
/// `systemd-run` argv in both, and `_containment-preconditions` blocks the run on
/// the same fact.
/// The production kind→adapter registry every `CapsuleExecution` carries —
/// the fixture sees what the route sees.
static AGENT_ADAPTERS: std::sync::LazyLock<
    kata_agent::adapter::capsule_registry::StaticAgentAdapterRegistry,
> = std::sync::LazyLock::new(kata_worker::adapter_registry::production);

static AMBIENT_CREDENTIALS: std::sync::LazyLock<
    kata_worker::agent_credential::AgentCredentialSource,
> = std::sync::LazyLock::new(kata_worker::agent_credential::AgentCredentialSource::ambient);

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
            return candidate;
        }
        if dir.file_name().and_then(|n| n.to_str()) == Some("target") {
            break;
        }
        cur = dir.parent();
    }
    panic!(
        "`{name}` is not next to the test binary, and it IS the instrument of this proof. `cargo \
         nextest run -p kata-workflow` does NOT build it. Run `cargo build -p kata-provider-youki \
         --bin kata-provider-youki` in the same command, which is also what keeps a STALE one from \
         being driven."
    );
}

/// The repository root, from this test binary's own location, so the shipped pack is
/// read from the checkout under test rather than from a cwd nobody set.
fn repo_root() -> PathBuf {
    let mut dir = std::env::current_exe().expect("the test binary has a path");
    while dir.pop() {
        if dir.join("workflows/std").is_dir() && dir.join("Cargo.toml").is_file() {
            return dir;
        }
    }
    panic!("could not find the repository root above this test binary");
}

/// Every plane one attempt needs, on disk, in one disposable directory.
struct Planes {
    dir: tempfile::TempDir,
    data_dir: PathBuf,
    op_path: PathBuf,
    cas_db: PathBuf,
    cas_blobs: PathBuf,
    db: std::sync::Arc<OperationalDb>,
    cas: std::sync::Arc<CasStore>,
}

/// The nucleus is opened WITH the content store bound, which is what
/// `OperationalDb::adopt_and_accept_capsule_completion` requires: it reads the node's ONE store off
/// the database rather than taking a handle, so the store the adoption verifies a
/// result against is the one the node's offloaded output already publishes into.
fn planes() -> Planes {
    let dir = tempfile::tempdir().expect("a tempdir");
    let data_dir = dir.path().join("data");
    std::fs::create_dir_all(&data_dir).expect("the data directory");
    let cas_db = data_dir.join("cas.db");
    let cas_blobs = data_dir.join("cas");
    let op_path = data_dir.join("operational.db");
    let cas = std::sync::Arc::new(CasStore::open(&cas_db, &cas_blobs).expect("a fresh CAS opens"));
    let db = std::sync::Arc::new(
        OperationalDb::open_with_cas(&op_path, std::sync::Arc::clone(&cas))
            .expect("an operational nucleus with its content store bound"),
    );
    Planes {
        dir,
        data_dir,
        op_path,
        cas_db,
        cas_blobs,
        db,
        cas,
    }
}

/// Publish a one-file tree artifact for `/work`, through the real CAS.
fn publish_work_tree(cas: &CasStore) -> ArtifactRef {
    let member = cas
        .put_durable(SOURCE_PAYLOAD.as_bytes())
        .expect("the member publishes");
    let manifest = TreeManifest::new(vec![TreeEntry {
        path: TreePath::new("src/a.txt").expect("an accepted tree path"),
        node: TreeNode::File {
            mode: TreeEntryMode::Regular,
            object: member.object_id(),
            size_bytes: member.size(),
        },
    }])
    .expect("a valid manifest");
    let bytes = manifest.manifest_bytes().expect("the manifest serializes");
    let receipt = cas.put_durable(&bytes).expect("the manifest publishes");
    ArtifactRef::new(receipt.object_id(), receipt.size(), ArtifactPrivacy::Public)
}

/// Publish the CANONICAL EMPTY TREE's bytes, which `assemble_capsule` maps `/out` and
/// `/tmp` to. `empty_tree_artifact()` derives the reference and deliberately does not
/// publish the bytes; making the reference resolvable is the issuing path's job, and
/// in this rig that is here.
fn publish_empty_tree(cas: &CasStore) -> ArtifactRef {
    let declared = empty_tree_artifact().expect("the canonical empty tree");
    let bytes = TreeManifest::new(Vec::new())
        .expect("an empty manifest is accepted")
        .manifest_bytes()
        .expect("the manifest serializes");
    let receipt = cas
        .put_durable(&bytes)
        .expect("the empty manifest publishes");
    let published = ArtifactRef::new(receipt.object_id(), receipt.size(), ArtifactPrivacy::Public);
    assert_eq!(
        published.id(),
        declared.id(),
        "the CAS must address the empty manifest exactly as `empty_tree_artifact` derives it, else \
         the capsule's /out and /tmp mappings name an artifact this rig did not publish"
    );
    published
}

/// ROOT the busybox closure through the environment plane, against the HOST's daemon
/// store, read-only.
///
/// The closure is not hand-realised and not hand-rooted. `declare_environment` verifies it, stages
/// an indirect gc root and promotes it, so `nix store gc` cannot take the bytes the container is
/// about to bind while the attempt runs.
///
/// `NarHashOnly` with no signature requirement, deliberately: this rig proves the OCI
/// ROUTE, and a signature policy would make it fail for a question about the binary
/// cache. The signature arms are `crates/core/tests/nix_environment_plane.rs`'s.
fn declare_busybox_environment(planes: &Planes) -> (EnvironmentId, NixEnvironmentManifest) {
    assert!(
        Path::new(BUSYBOX).join("bin/busybox").is_file(),
        "the closure's only store object is not realised at {BUSYBOX}. The container rbinds that \
         exact path and execs the binary inside it, so there is nothing to observe without it. \
         Realise it with `nix-store --realise {BUSYBOX}`."
    );
    let root = StorePath::new(BUSYBOX).expect("a real store path");
    let reference = declare_environment(
        &planes.db,
        &planes.cas,
        // The HOST's store, read-only: nothing here writes to it, and the bind the
        // container takes is of the host's own physical path.
        &NixStore::Daemon,
        &planes.data_dir,
        DeclarationInput {
            label: "capsule-busybox".to_owned(),
            platform: PlatformRef::new(
                "x86_64-linux",
                FixedBytes(*blake3::hash(b"capsule-platform").as_bytes()),
            ),
            source: DeclarationSource::StorePaths {
                nixpkgs_attribute: SmolStr::new("nixpkgs#pkgsStatic.busybox"),
                paths: vec![root.clone()],
            },
            path_prepend: vec![
                GuestPath::new(format!("{BUSYBOX}/bin")).expect("the closure's bin directory"),
            ],
            integrity_policy: IntegrityPolicy {
                verify: NarVerification::NarHashOnly,
                sigs_needed: 0,
                required_signers: Vec::new(),
                allow_unsigned_content_addressed: true,
                verify_contents_at_declare: false,
            },
            retention: RetentionIntent {
                class: RetentionClass::Authoritative,
            },
        },
    )
    .unwrap_or_else(|error| {
        panic!(
            "the environment plane refused to declare the busybox closure: {error}. This rig ROOTS \
             the closure through the environment plane rather than hand-realising it, so a refusal here is a \
             finding about that plane and not about the OCI route."
        )
    });

    // NIX itself says the closure is rooted — read before the container starts, since
    // that is the property the bind depends on.
    let registered = std::process::Command::new("nix-store")
        .args(["--query", "--roots", BUSYBOX])
        .output()
        .expect("nix-store --query --roots runs");
    let roots = String::from_utf8_lossy(&registered.stdout).into_owned();
    assert!(
        roots.contains(
            kata_core::environment::roots::environment_directory(
                &planes.data_dir,
                reference.id().0.0,
            )
            .to_str()
            .expect("the environment directory is UTF-8")
        ),
        "the environment plane must leave a REGISTERED gc root for the closure the container is \
         about to bind; `nix-store --query --roots {BUSYBOX}` says:\n{roots}"
    );

    // The manifest, read back out of the CAS by the row's own object id — never
    // rebuilt here, which would be a second answer to what was declared.
    let row = planes
        .db
        .environment(reference.id().0.0)
        .expect("the operational nucleus answers")
        .expect("the declared environment has a row");
    let bytes = planes
        .cas
        .get_verified_bounded(&ObjectId::from(row.manifest_object_id), 1 << 20)
        .expect("the manifest object is in the CAS");
    (
        reference.id(),
        serde_json::from_slice(&bytes).expect("the stored manifest decodes"),
    )
}

/// The assemblable directive for the smoke rig's own profile: `iso` is
/// `workspace = "rw"`, `net = "offline"`, and a shell stage takes the default
/// containment backend.
fn directive() -> SandboxDirective {
    SandboxDirective {
        exec: ExecBackend::Oci,
        fs: FsPolicy::WorkspaceRw,
        net: NetPolicy::Offline,
        env: BTreeMap::new(),
        secret_tokens: BTreeMap::new(),
        image: None::<SandboxImage>,
        confine_to_declared_inputs: true,
        content_cacheable: true,
        read_closure: Vec::new(),
        write_closure: Vec::new(),
        determinism_pinned: true,
    }
}

/// Assemble the capsule for `probe`, over the published work tree and the declared
/// environment.
fn assemble(environment: EnvironmentId, work_tree: ArtifactId) -> Capsule {
    assemble_running(environment, work_tree, None)
}

/// [`assemble`], with the rendered command REPLACED when `command` is given — the stop
/// cell needs a container that is still running when the stop arrives.
fn assemble_running(
    environment: EnvironmentId,
    work_tree: ArtifactId,
    command: Option<&str>,
) -> Capsule {
    assemble_from(PACK, environment, work_tree, command)
}

/// [`assemble_running`] over `pack` — the frame-budget cell's pack is [`PACK`] with a
/// shorter `timeout_ms`.
fn assemble_from(
    pack: &str,
    environment: EnvironmentId,
    work_tree: ArtifactId,
    command: Option<&str>,
) -> Capsule {
    let program = compile_starlark_execution_program(pack, "oci-stage-live.star", &[])
        .expect("the reduced pack compiles");
    let id = StageId(SmolStr::new("probe"));
    let stage = program
        .stages
        .iter()
        .find(|(stage_id, _)| *stage_id == &id)
        .map(|(_, stage)| stage)
        .expect("the probe stage is present");
    let lowered = lower_stage_operation(&program, &id).expect("the probe stage lowers");
    let platform = PlatformRef::new(
        "x86_64-linux",
        FixedBytes(*blake3::hash(b"capsule-platform").as_bytes()),
    );
    let (_action, capsule) = assemble_capsule(
        &lowered,
        kata_types::execution_contract::OccurrenceId(FixedBytes(
            *blake3::hash(b"capsule-platform-occurrence").as_bytes(),
        )),
        stage,
        &directive(),
        // EXPLICIT, which is what `RenderedCommand`'s one constructor is for: the reduced
        // pack's prompt carries no template expression, so the renderer would return these
        // bytes unchanged and this rig stands in for it rather than pretending to be it.
        &RenderedCommand::rendered(
            command.map_or_else(|| stage.op.prompt_template.clone(), str::to_owned),
        ),
        environment,
        platform.id(),
        work_tree,
        NodeBudgetDefaults {
            memory_bytes: 512 * 1024 * 1024,
            process_count: 64,
        },
        None,
        None,
    )
    .expect("the capsule assembles");
    capsule
}

/// Provision the freshly built `kata-provider-youki` into a by-hash provider store
/// this rig owns, exactly as an operator provisions the youki provider.
fn install_provider(root: &Path) -> OciProviderInstallation {
    let binary = workspace_bin("kata-provider-youki");
    let source = root.join("provider-src");
    std::fs::create_dir_all(&source).expect("the provider source directory");
    let destination = source.join(format!("kata-provider-{OCI_PROVIDER_NAME}"));
    std::fs::copy(&binary, &destination).expect("the provider bytes copy");
    let store_root = root.join("provider-store");
    let store = kata_worker::ProviderStore::new(&store_root);
    let provisioned = store
        .provision(OCI_PROVIDER_NAME, &source)
        .expect("the provider provisions into a by-hash store");
    let address = ExternalProviderAddress::parse(&provisioned.address.to_string())
        .expect("a minted address parses");
    OciProviderInstallation::new(store_root, address)
}

/// [`install_provider`], plus the two members an `Egress` capsule's provider
/// entry must carry — `kata-oci-hook` (the `loopback-up` / `hand-listener`
/// hooks) and `ip` (the host's iproute2 the loopback hook execs). An entry
/// provisioned without them refuses `provider_unresolved` before the container
/// starts — the egress live cell provisions all three, mirroring
/// `crates/worker/tests/egress_oci_live.rs`'s install.
fn install_egress_provider(root: &Path) -> OciProviderInstallation {
    let provider = workspace_bin("kata-provider-youki");
    let hook = workspace_bin("kata-oci-hook");
    let source = root.join("provider-src");
    std::fs::create_dir_all(&source).expect("the provider source directory");
    std::fs::copy(
        &provider,
        source.join(format!("kata-provider-{OCI_PROVIDER_NAME}")),
    )
    .expect("the provider bytes copy");
    std::fs::copy(&hook, source.join("kata-oci-hook")).expect("the hook bytes copy");
    std::fs::copy(host_ip(), source.join("ip")).expect("the iproute2 member copies");
    let store_root = root.join("provider-store");
    let store = kata_worker::ProviderStore::new(&store_root);
    let provisioned = store
        .provision(OCI_PROVIDER_NAME, &source)
        .expect("the provider provisions into a by-hash store");
    let address = ExternalProviderAddress::parse(&provisioned.address.to_string())
        .expect("a minted address parses");
    OciProviderInstallation::new(store_root, address)
}

/// The host's `ip` — the `loopback-up` hook execs it by absolute path on the
/// HOST rootfs (a createContainer hook sees the host's mounts inside the
/// guest's netns), so a real iproute2 binary is the member the provider entry
/// carries. Same lookup `egress_oci_live.rs` performs.
fn host_ip() -> PathBuf {
    for candidate in ["/usr/bin/ip", "/usr/sbin/ip", "/bin/ip", "/sbin/ip"] {
        let path = Path::new(candidate);
        if path.is_file() {
            return path.to_path_buf();
        }
    }
    panic!("no iproute2 `ip` on this host — the `loopback-up` hook execs it by absolute path")
}

/// How many upstream dials the egress seam performed — a DELTA never an
/// absolute (`fn` pointers cannot capture). Same construction as
/// `egress_oci_live.rs`'s.
static UPSTREAM_DIALS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

/// The live-cell dial: every allowlisted authority maps to the loopback
/// listener this cell owns — the ONE substituted edge in an otherwise all-real
/// path, because the production `connect_checked` refuses every local address
/// class by design and a live cell's upstream can only be local. The CONNECT
/// parse, the allowlist, the 200/403 answers and the relayed bytes are all the
/// production proxy's.
fn loopback_dial(
    _host: &str,
    port: u16,
) -> std::pin::Pin<
    Box<
        dyn std::future::Future<
                Output = Result<tokio::net::TcpStream, kata_worker::egress_proxy::EgressRefusal>,
            > + Send
            + '_,
    >,
> {
    UPSTREAM_DIALS.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    Box::pin(async move {
        tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .map_err(
                |error| kata_worker::egress_proxy::EgressRefusal::UpstreamUnreachable {
                    authority: format!("127.0.0.1:{port}"),
                    error: error.to_string(),
                },
            )
    })
}

// ---------------------------------------------------------------------------
// The exit criterion
// ---------------------------------------------------------------------------

/// The pids matching `pattern` that live in the named CONTAINER's cgroup —
/// the container-scoped answer to "did the guest's process survive". The
/// defect this replaces: `pgrep -f` alone is a HOST-WIDE oracle — any process
/// on the box whose argv matches (another project's `sleep 60` loop supplied
/// ~400 of them once) reads as a survivor, which is a guarantee wider than
/// the mechanism. `/proc/<pid>/cgroup` is the kernel's own statement of which
/// cgroup holds a pid — the same containment check `attempt_root`'s
/// `names_container_cgroup` writes — and a pid that exits between the listing
/// and the read is not a survivor.
fn container_processes(pattern: &str, container_id: &str) -> Vec<u32> {
    let listed = std::process::Command::new("pgrep")
        .args(["-f", pattern])
        .output()
        .expect("pgrep runs");
    let parent = format!("/kata.oci.{container_id}");
    String::from_utf8_lossy(&listed.stdout)
        .split_whitespace()
        .filter_map(|pid| pid.parse::<u32>().ok())
        .filter(|pid| {
            std::fs::read_to_string(format!("/proc/{pid}/cgroup")).is_ok_and(|cgroups| {
                cgroups
                    .lines()
                    .any(|line| line.ends_with(&parent) || line.contains(&format!("{parent}/")))
            })
        })
        .collect()
}

/// Any `kata.oci.<container_id>` cgroup directory the kernel still holds, via
/// the `find` both cells below run — one spelling, in one place.
fn surviving_cgroups(container_id: &str) -> String {
    let found = std::process::Command::new("find")
        .arg("/sys/fs/cgroup")
        .args(["-maxdepth", "6", "-type", "d", "-name"])
        .arg(format!("kata.oci.{container_id}"))
        .output()
        .expect("find runs");
    String::from_utf8_lossy(&found.stdout).trim().to_owned()
}

/// A HOST process the cell spawns itself, with the same argv the guest runs —
/// the decoy that proves the oracle above ran on a box carrying a matching
/// argv OUTSIDE the container, so an empty [`container_processes`] is a claim
/// about the container and not about the host being clean. Killed and reaped
/// on drop; a leaked decoy is exactly the residue a host-wide oracle would read
/// as a kata survivor.
struct HostDecoy(std::process::Child);

impl HostDecoy {
    fn spawn(argv: &[&str]) -> Self {
        Self(
            std::process::Command::new(argv[0])
                .args(&argv[1..])
                .spawn()
                .expect("the decoy spawns"),
        )
    }

    fn still_running(&mut self) -> bool {
        matches!(self.0.try_wait(), Ok(None))
    }
}

impl Drop for HostDecoy {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// **One capsule, one container, every verdict from the host.**
///
/// **Would red if:** the driver bound a `/work` that did not hold the materialized
/// tree (the `cat` would print nothing and stdout would not carry the payload), bound
/// an `/out` the host cannot see (the `cat` on the host side would fail), left the
/// container registered (the runtime's own `list` would name it), left the cgroup
/// tree behind (the directory would still be there), or reported a provenance that
/// was not this route's.
#[test]
#[ignore = "HOST-DEPENDENT (pinned youki, its INSTALLED AppArmor profile, a \
            delegated user scope, a nix daemon, the fixture closure's store path realised) AND \
            instrument-dependent (`cargo build -p kata-provider-youki`). On a host where the \
            pinned youki's AppArmor profile has not been installed this FAILS with \
            `profile_file_differs` — run `sudo kata host \
            apparmor-install` first. `just gate` is host-independent by design, so this rides the \
            containment side like its three OCI siblings; the containment lane's `oci-live-smoke` step runs it. Run it now with `cargo build -p \
            kata-provider-youki --bin kata-provider-youki && cargo nextest run -p kata-workflow -P live-smoke -E \
            'binary(oci_stage_live)' --run-ignored all`."]
fn a_real_capsule_runs_in_a_real_container_and_the_host_says_so_live() {
    delegated(
        "a_real_capsule_runs_in_a_real_container_and_the_host_says_so_live",
        a_real_capsule_body(),
    );
}

async fn a_real_capsule_body() {
    let test = "a_real_capsule_runs_in_a_real_container_and_the_host_says_so_live";
    let planes = planes();
    // Declared AFTER the tempdir so it drops BEFORE it: `ProviderStore::provision`
    // seals its entry and `TempDir`'s `Drop` cannot remove a sealed tree.
    let unseal = kata_worker::UnsealOnDrop::new(planes.dir.path());

    // KATA'S OWN MEASUREMENT, the real thing. A host that cannot certify fails HERE,
    // naming the refusal — there is no skip on purpose.
    let certification = certify_youki(YoukiPin::embedded()).unwrap_or_else(|refusal| {
        panic!(
            "{test}: this host cannot deliver the rootless-OCI prerequisite ({token}): {refusal}. \
             When the youki pin has moved its store path this is `profile_file_differs` until \
             `/etc/apparmor.d/youki` names the new one — run `sudo kata host apparmor-install` as \
             root. `just \
             _containment-preconditions` gives the one-line diagnosis.",
            token = refusal.token(),
        )
    });

    let work_tree = publish_work_tree(&planes.cas);
    let empty = publish_empty_tree(&planes.cas);
    let (environment_id, environment) = declare_busybox_environment(&planes);
    let capsule = assemble(environment_id, work_tree.id());

    let installation = install_provider(planes.dir.path());
    let worker_state = planes.dir.path().join("worker-state");
    let driver = OciStageDriver::new(
        OciRoute::new(certification.clone()),
        &worker_state,
        installation,
    );
    let provenance = kata_types::execution_provenance::ExecutionProvenance::local_oci_runtime(
        "read off the route below",
    );
    assert_eq!(
        provenance.label(),
        "local_oci_runtime",
        "{test}: the provenance arm this route records must be the OCI one"
    );

    let source = LocalCasBlobSource::open(&planes.cas_db, &planes.cas_blobs)
        .expect("the CAS opens read-only");
    let trees = DeclaredTreeResolver::new(vec![work_tree, empty], &source);
    // THE ARGV IS NOT HAND-BUILT HERE: a vector spelled in this file could name a
    // command the pack did not contain, so the container would run bytes no capsule
    // committed to. The capsule contract folds the vector into `CapsuleId`,
    // `assemble_capsule` derives it as `["sh", "-c", <the pack's own command>]`, and
    // the assertion below reads it back off the capsule so the shape is pinned
    // rather than assumed.
    assert_eq!(
        capsule.process(),
        &CapsuleProcess::Command {
            argv: [
                SmolStr::new("sh"),
                SmolStr::new("-c"),
                SmolStr::new("echo hi > /out/hi; cat /work/src/a.txt"),
            ]
            .to_vec(),
        },
        "{test}: the capsule's argv must be the shell form derived from the PACK's command. \
         `argv[0]` is a program NAME resolved against the PATH the environment's path_prepend \
         renders — a store path here would fold this host's realisation into the capsule id"
    );
    let attempt_tag = "capsule-attempt";
    let output = driver
        .drive(
            attempt_tag,
            &OciStageRequest {
                capsule: &capsule,
                environment: &environment,
                network: NetPolicy::Offline,
                trees: &trees,
                source: &source,
                probe: &LocalStorePathProbe,
                execution_id: ulid::Ulid::new(),
            },
        )
        .await
        .unwrap_or_else(|refusal| {
            panic!(
                "{test}: the OCI stage driver refused ({label}): {refusal}",
                label = refusal.label(),
            )
        });

    // v6: the frame carries SIZES; the stage's bytes are the spool files the
    // provider wrote under `<attempt root>/capture`, read off the root the
    // output still owns.
    let spool = output.attempt_root.join("capture");
    let output_stdout =
        std::fs::read_to_string(spool.join("stdout")).expect("the provider spooled stdout");
    let output_stderr =
        std::fs::read_to_string(spool.join("stderr")).expect("the provider spooled stderr");
    assert_eq!(
        output.exit_code,
        Some(0),
        "{test}: the container's exit status arrives as a `completed` frame the provider wrote and \
         this process decoded.\nstdout: {output_stdout}\nstderr: {output_stderr}",
    );
    assert!(
        output_stdout.contains(SOURCE_PAYLOAD.trim()),
        "{test}: the stage's stdout must carry the bytes of /work/src/a.txt, which only a container \
         that really bound the MATERIALIZED /work could have read.\nstdout: {output_stdout}",
    );
    assert!(
        output.teardown.is_confirmed(),
        "{test}: the driver refuses an unconfirmed teardown, so reaching here with an ambiguous \
         one would mean the refusal is not wired: {:?}",
        output.teardown
    );

    // `/out/hi`'s BYTES, read with `cat` off the host after the container is gone.
    let out_file = output.attempt_root.join("out/hi");
    let written = std::process::Command::new("cat")
        .arg(&out_file)
        .output()
        .expect("cat runs");
    assert!(
        written.status.success(),
        "{test}: the guest's redirect into /out did not land on the host at {path}. That bind is \
         how a stage's RESULT leaves the container, so an absent file here is the whole route \
         failing quietly. cat said: {err}",
        path = out_file.display(),
        err = String::from_utf8_lossy(&written.stderr),
    );
    assert_eq!(
        String::from_utf8_lossy(&written.stdout),
        OUT_PAYLOAD,
        "{test}: /out/hi must hold exactly what the guest wrote"
    );

    // The materializer's `/tmp` is GONE: the guest's /tmp is a tmpfs and nothing on
    // the host backs it.
    assert!(
        !output.attempt_root.join("tmp").exists(),
        "{test}: the attempt root still holds a `tmp` directory. The guest's /tmp is a tmpfs with \
         no host path behind it — a host directory there is a stage's scratch left where a later \
         attempt could read it"
    );

    // THE RUNTIME's own answer: it holds no container under this id. The state root is
    // the provider's `<attempt>/oci/<container>/state`; it must EXIST before it is
    // listed, because `youki --root <dir> list` creates a missing root and answers an
    // empty list for it — a wrong path would pass by listing nothing.
    let state = worker_state
        .join("attempts")
        .join(attempt_tag)
        .join("oci")
        .join(&output.container_id)
        .join("state");
    assert!(
        state.is_dir(),
        "{test}: the provider's youki state root {} is absent, so the listing below would \
         prove nothing",
        state.display()
    );
    let listing = youki_list(&state);
    assert!(
        !listing.contains(&output.container_id),
        "{test}: the runtime still holds `{id}` after a clean exit; `youki delete --force` is the \
         provider's unconditional finally.\n{listing}",
        id = output.container_id,
    );

    // THE KERNEL's answer: the cgroup tree kata created is gone.
    let leaf = PathBuf::from("/sys/fs/cgroup");
    let survivors = std::process::Command::new("find")
        .arg(&leaf)
        .args(["-maxdepth", "6", "-type", "d", "-name"])
        .arg(format!("kata.oci.{}", output.container_id))
        .output()
        .expect("find runs");
    assert!(
        String::from_utf8_lossy(&survivors.stdout).trim().is_empty(),
        "{test}: a `kata.oci.{id}` cgroup directory survived the drive. The parent kata creates is \
         rmdir'd by its own guard after the teardown verdict is read, so residue here is the \
         teardown claim being wider than its mechanism.\nfind said: {found}",
        id = output.container_id,
        found = String::from_utf8_lossy(&survivors.stdout),
    );

    println!(
        "live-stage container={id} exit=0 out-bytes={bytes} teardown={teardown} \
         provenance=local_oci_runtime capsule={capsule} youki={youki}",
        id = output.container_id,
        bytes = OUT_PAYLOAD.len(),
        teardown = output.teardown.label(),
        capsule = capsule.id().0,
        youki = certification.sha256,
    );
    drop(unseal);
}

/// **A FENCED STOP KILLS THE RUNNING CONTAINER.** A capsule that would sleep for five
/// minutes is driven through `drive_cancellable`; a stop is sent three seconds in. The
/// verdict is read off the host: the drive ends `stopped` within the teardown budget (not
/// after 297 s), no process in the container's own `kata.oci.<id>` cgroup survives (a
/// host-wide `pgrep` is not the oracle — a decoy `sleep 297` runs on the host the whole
/// drive, so the empty scoped answer is a claim about the container), and no
/// `kata.oci.<id>` cgroup survives.
/// This is the driver half of the worker loop's capsule-arm stop race; the loop's own
/// half (the fence and its handler) is the worker crate's, host-free.
#[test]
#[ignore = "HOST-DEPENDENT like its siblings (pinned youki with its INSTALLED AppArmor profile, a \
            delegated user scope, the busybox closure realised) and instrument-dependent (`cargo \
            build -p kata-provider-youki --bin kata-provider-youki`). Run with `cargo nextest run \
            -p kata-workflow -E 'binary(oci_stage_live)' --run-ignored all`."]
fn a_fenced_stop_kills_the_running_container_live() {
    delegated(
        "a_fenced_stop_kills_the_running_container_live",
        a_fenced_stop_body(),
    );
}

async fn a_fenced_stop_body() {
    let test = "a_fenced_stop_kills_the_running_container_live";
    let planes = planes();
    let unseal = kata_worker::UnsealOnDrop::new(planes.dir.path());
    let certification = certify_youki(YoukiPin::embedded()).unwrap_or_else(|refusal| {
        panic!(
            "{test}: this host cannot deliver the rootless-OCI prerequisite ({token}): {refusal}",
            token = refusal.token(),
        )
    });
    let work_tree = publish_work_tree(&planes.cas);
    let empty = publish_empty_tree(&planes.cas);
    let (environment_id, environment) = declare_busybox_environment(&planes);
    let capsule = assemble_running(environment_id, work_tree.id(), Some("sleep 297"));
    let driver = OciStageDriver::new(
        OciRoute::new(certification),
        planes.dir.path().join("worker-state"),
        install_provider(planes.dir.path()),
    );
    let source = LocalCasBlobSource::open(&planes.cas_db, &planes.cas_blobs)
        .expect("the CAS opens read-only");
    let trees = DeclaredTreeResolver::new(vec![work_tree, empty], &source);
    // THE DECOY — a host `sleep 297` OUTSIDE the container, held across the
    // drive: when the scoped oracle below reports empty, this one's survival
    // is the proof the host carried a matching argv and the scope — not the
    // silence — is what cleared it.
    let mut decoy = HostDecoy::spawn(&["sleep", "297"]);
    let (stop, cancel) = tokio::sync::oneshot::channel::<String>();
    tokio::spawn(async move {
        tokio::time::sleep(std::time::Duration::from_secs(3)).await;
        let _ = stop.send("operator stop (live cell)".to_owned());
    });
    let started = std::time::Instant::now();
    let refusal = driver
        .drive_cancellable(
            "stop-attempt",
            &OciStageRequest {
                capsule: &capsule,
                environment: &environment,
                network: NetPolicy::Offline,
                trees: &trees,
                source: &source,
                probe: &LocalStorePathProbe,
                execution_id: ulid::Ulid::new(),
            },
            started + kata_worker::oci_driver::CAPSULE_PREPARE_BUDGET,
            cancel,
        )
        .await
        .err()
        .unwrap_or_else(|| panic!("{test}: a stopped container is never a completed stage"));
    let elapsed = started.elapsed();
    assert_eq!(refusal.label(), "stopped", "{test}: {refusal}");
    assert!(
        elapsed < std::time::Duration::from_secs(120),
        "{test}: the stop must END the container, not wait out its 297 s sleep (took {elapsed:?})"
    );
    let container_id = format!("kata-{}", capsule.id().0);
    // THE KERNEL's answer, scoped to the container's own cgroup: no `sleep 297`
    // IN `kata.oci.<id>` survives the stop — while the host's own decoy, which
    // shares the argv and none of the cgroup, runs on.
    assert!(
        decoy.still_running(),
        "{test}: the host decoy must outlive the drive — an empty scoped oracle \
         is only a claim if the host carried the argv"
    );
    let survivors = container_processes("^sleep 297$", &container_id);
    assert!(
        survivors.is_empty(),
        "{test}: the container's `sleep 297` survived the stop: pids {survivors:?}"
    );
    let cgroups = surviving_cgroups(&container_id);
    assert!(
        cgroups.is_empty(),
        "{test}: a `kata.oci.{container_id}` cgroup survived the stop: {cgroups}"
    );
    println!("live-stop container={container_id} stopped_after={elapsed:?}");
    drop(unseal);
}

/// **A capsule that outlives its wall clock is STOPPED by the provider budget the worker
/// launched it under — about `timeout_ms` + `PROVIDER_FRAME_MARGIN`, not whenever its
/// process gets round to exiting.**
///
/// The capsule's stage declares `timeout_ms = 5000` and runs `sleep 60`; no stop is ever
/// sent, so the one thing that can end it early is the frame budget the drive handed the
/// provider supervisor (5 s + 30 s). The verdict is read off the host: the drive ends in
/// well under the sixty seconds the guest asked for, and no process in the container's
/// own `kata.oci.<id>` cgroup survives — a host-wide `pgrep` is not the oracle (another
/// project's `sleep 60` loop once supplied ~400 of them and redded this cell for a full
/// L2); a decoy `sleep 60` runs on the host the whole drive, so the scoped-empty answer
/// is a claim about the container, not about a clean box. The main's own wall-time leg
/// is not in this loop — this is the WORKER's half of the bound, the half that still
/// holds after the main has settled an attempt.
///
/// **Would red if:** the drive launched the provider with any budget longer than the
/// guest's sleep (the one-hour default) — the container would run to
/// completion and the drive would return a finished stage.
#[test]
#[ignore = "HOST-DEPENDENT like its siblings (pinned youki with its INSTALLED AppArmor profile, a \
            delegated user scope, the busybox closure realised) and instrument-dependent (`cargo \
            build -p kata-provider-youki --bin kata-provider-youki`). About 40 s. Run with `cargo \
            nextest run -p kata-workflow -P live-smoke -E 'binary(oci_stage_live)' --run-ignored \
            all`."]
fn a_capsule_past_its_wall_clock_is_stopped_by_its_provider_budget_live() {
    delegated(
        "a_capsule_past_its_wall_clock_is_stopped_by_its_provider_budget_live",
        a_capsule_past_its_wall_clock_body(),
    );
}

async fn a_capsule_past_its_wall_clock_body() {
    let test = "a_capsule_past_its_wall_clock_is_stopped_by_its_provider_budget_live";
    let planes = planes();
    let unseal = kata_worker::UnsealOnDrop::new(planes.dir.path());
    let certification = certify_youki(YoukiPin::embedded()).unwrap_or_else(|refusal| {
        panic!(
            "{test}: this host cannot deliver the rootless-OCI prerequisite ({token}): {refusal}",
            token = refusal.token(),
        )
    });
    let work_tree = publish_work_tree(&planes.cas);
    let empty = publish_empty_tree(&planes.cas);
    let (environment_id, environment) = declare_busybox_environment(&planes);
    let short = PACK.replace("timeout_ms = 30000", "timeout_ms = 5000");
    assert_ne!(
        short, PACK,
        "{test}: the premise: the pack's timeout was rewritten"
    );
    let capsule = assemble_from(&short, environment_id, work_tree.id(), Some("sleep 60"));
    assert_eq!(capsule.budgets().wall_time_ms, 5_000, "{test}: the premise");
    let driver = OciStageDriver::new(
        OciRoute::new(certification),
        planes.dir.path().join("worker-state"),
        install_provider(planes.dir.path()),
    );
    let source = LocalCasBlobSource::open(&planes.cas_db, &planes.cas_blobs)
        .expect("the CAS opens read-only");
    let trees = DeclaredTreeResolver::new(vec![work_tree, empty], &source);
    // HELD, never sent: a closed channel would read as "no stop requested" too, but a live
    // sender makes it certain nothing but the budget can end this drive.
    let (_stop, cancel) = tokio::sync::oneshot::channel::<String>();
    // THE DECOY — a host `sleep 60` OUTSIDE the container, held across the
    // drive, so the scoped oracle's empty answer below cannot owe anything to
    // the host happening to be clean.
    let mut decoy = HostDecoy::spawn(&["sleep", "60"]);
    let started = std::time::Instant::now();
    let refusal = driver
        .drive_cancellable(
            "wall-clock-attempt",
            &OciStageRequest {
                capsule: &capsule,
                environment: &environment,
                network: NetPolicy::Offline,
                trees: &trees,
                source: &source,
                probe: &LocalStorePathProbe,
                execution_id: ulid::Ulid::new(),
            },
            started + kata_worker::oci_driver::CAPSULE_PREPARE_BUDGET,
            cancel,
        )
        .await
        .err()
        .unwrap_or_else(|| {
            panic!(
                "{test}: the guest slept its full 60 s and the drive returned a FINISHED stage \
                 after {:?}: nothing held it to its 5 s wall clock",
                started.elapsed()
            )
        });
    let elapsed = started.elapsed();
    let budget = std::time::Duration::from_millis(5_000)
        + kata_worker::provider_supervisor::PROVIDER_FRAME_MARGIN;
    assert_eq!(
        refusal.label(),
        "provider_refused_stage",
        "{test}: the provider stopped answering within its budget and was killed and contained: \
         {refusal}"
    );
    assert!(
        refusal
            .to_string()
            .contains(&format!("no frame before its {budget:?} budget ran out")),
        "{test}: the refusal names the budget it was held to: {refusal}"
    );
    assert!(
        elapsed >= budget && elapsed < std::time::Duration::from_secs(60),
        "{test}: stopped at the {budget:?} budget, before the guest's 60 s sleep ended (took \
         {elapsed:?})"
    );
    // THE KERNEL's answer, scoped to the container's own cgroup — the driver
    // names it `kata-{capsule id}` (`OciStageDriver`'s drive) inside the
    // `kata.oci.<id>` parent kata owns. The host's own decoy `sleep 60` shares
    // the argv and none of the cgroup, and must still be running.
    let container_id = format!("kata-{}", capsule.id().0);
    assert!(
        decoy.still_running(),
        "{test}: the host decoy must outlive the drive — an empty scoped oracle \
         is only a claim if the host carried the argv"
    );
    let survivors = container_processes("^sleep 60$", &container_id);
    assert!(
        survivors.is_empty(),
        "{test}: the container's `sleep 60` survived its budget: pids {survivors:?}"
    );
    let cgroups = surviving_cgroups(&container_id);
    assert!(
        cgroups.is_empty(),
        "{test}: a `kata.oci.{container_id}` cgroup survived the drive: {cgroups}"
    );
    println!("live-wall-clock budget={budget:?} stopped_after={elapsed:?}");
    drop(unseal);
}

/// **Every shipped shell smoke ASSEMBLES.**
///
/// `assemble_capsule` refuses a stage with no `timeout_ms`; `stage()` resolves an
/// undeclared `timeout_ms=` to `kata_types::workflow::DEFAULT_STAGE_TIMEOUT_MS` at
/// the AUTHORING layer, so every shipped shell smoke carries a wall-time bound and
/// there is no stage a capsule could be refused for. This test fails if that is
/// forgotten.
///
/// The assertion is over the WHOLE `workflows/smoke` shell-smoke family, not one pack, and it
/// checks the assembled capsule's `wall_time_ms` IS the stage's `timeout_ms` — an
/// assembly that succeeded while committing to some other number would be the
/// interesting defect here, and "it returned `Ok`" would not catch it.
///
/// Host-free, so it rides `just gate` even though its sibling above cannot.
#[test]
fn every_shipped_shell_stage_assembles() {
    let mut checked = 0usize;
    for pack in SHIPPED_SHELL_SMOKES {
        let path = repo_root().join(pack);
        let text = std::fs::read_to_string(&path).unwrap_or_else(|e| {
            panic!("the shipped pack {} must be readable: {e}", path.display())
        });
        let program = compile_starlark_execution_program(&text, pack, &[])
            .expect("the shipped pack compiles — it ships and `just workflows-check-all` loads it");
        for (stage_id, stage) in &program.stages {
            if stage.op.agent_label.as_deref() != Some("shell") {
                continue;
            }
            assert!(
                stage.policies.timeout_ms > 0,
                "{pack}::{} must carry a positive wall-time bound in the checked IR",
                stage_id.0
            );
            let lowered = lower_stage_operation(&program, stage_id)
                .unwrap_or_else(|e| panic!("{pack}::{} lowers: {e:?}", stage_id.0));
            let (_, capsule) = assemble_capsule(
                &lowered,
                kata_types::execution_contract::OccurrenceId(FixedBytes([7; 32])),
                stage,
                &directive(),
                // EXPLICIT, which is what `RenderedCommand`'s one constructor is for: the
                // smoke rigs' prompts carry no template expression, so the renderer would
                // return these bytes unchanged and this rig stands in for it rather than
                // pretending to be it.
                &RenderedCommand::rendered(stage.op.prompt_template.clone()),
                kata_types::execution_contract::EnvironmentId(FixedBytes([3; 32])),
                PlatformRef::new("x86_64-linux", FixedBytes([11; 32])).id(),
                ArtifactId(FixedBytes([20; 32])),
                NodeBudgetDefaults {
                    memory_bytes: 512 * 1024 * 1024,
                    process_count: 64,
                },
                None,
                None,
            )
            .unwrap_or_else(|e| {
                panic!(
                    "{pack}::{} must assemble now that every checked stage carries a wall-time \
                     bound; got: {e}",
                    stage_id.0
                )
            });
            assert_eq!(
                capsule.budgets().wall_time_ms,
                stage.policies.timeout_ms,
                "{pack}::{} assembled a capsule committing to a wall-time bound that is not the \
                 stage's own",
                stage_id.0
            );
            checked += 1;
        }
    }
    assert!(
        checked > 0,
        "no shipped shell stage was reached — SHIPPED_SHELL_SMOKES names packs that no longer \
         hold a shell stage, so this test proves nothing"
    );
    println!("shipped-shell-stages-assembled={checked}");
}

/// **A refusal AFTER the provider launched tears the provider — and its cgroup —
/// down.**
///
/// The only two ways a launched provider goes away in order (`shutdown` and
/// `kill_and_contain`) both consume `self`, and only they run `contain`, which removes
/// the SWEEP ROOT directory the launch created under the delegated parent.
/// `ProviderSupervisor`'s `Drop` only KILLS (one `cgroup.kill` write) and leaves the
/// directory for the worker's next launch to reclaim. So a `?` between the launch and
/// the assignment that merely dropped the supervisor would leave a
/// `kata.provider.<name>.<pid>.<sequence>` tree behind for a stage that never started —
/// residue an operator reads as a live stage — the leak `launch` closes inside
/// itself, re-created one layer up by the caller.
///
/// The refusal used is `plan_refused`, forced by a `NetPolicy::Host` request that
/// `oci_bundle::spec_for` refuses BY NAME. It is reached after the provider is
/// launched and after the parent cgroup is created, and it needs no certified youki:
/// no container is ever planned, so nothing execs the runtime.
///
/// **Would red if:** the driver dropped the supervisor on that path. WATCHED RED with
/// the `shutdown` replaced by a bare `drop`: a `kata.provider.*` directory survived
/// under the delegated parent, counted with `find`.
#[test]
#[ignore = "Instrument-dependent (`cargo build -p kata-provider-youki`) and \
            host-dependent (a delegated user scope, a nix daemon, the fixture closure realised) — \
            it launches the real provider. It needs NO certified youki, because the refusal under \
            test happens before any container is planned. Run it with `cargo build -p \
            kata-provider-youki --bin kata-provider-youki && cargo nextest run -p kata-workflow -P live-smoke -E \
            'binary(oci_stage_live)' --run-ignored all`."]
fn a_refusal_after_the_provider_launched_leaves_no_provider_cgroup() {
    delegated(
        "a_refusal_after_the_provider_launched_leaves_no_provider_cgroup",
        a_refusal_after_launch_body(),
    );
}

async fn a_refusal_after_launch_body() {
    let test = "a_refusal_after_the_provider_launched_leaves_no_provider_cgroup";
    let planes = planes();
    let unseal = kata_worker::UnsealOnDrop::new(planes.dir.path());
    let parent = kata_worker::sandbox_bounds::cgroup_delegation()
        .usable_parent
        .clone()
        .unwrap_or_else(|| {
            panic!(
                "{test}: this process measured NO usable delegated cgroup parent, so the launch creates no sweep root and there is no residue for this test to be about. The `delegated` wrapper re-execs inside `systemd-run --user --scope -p Delegate=yes` precisely to supply one — see `just _containment-preconditions`."
            )
        });
    let before = provider_cgroups(&parent);

    let work_tree = publish_work_tree(&planes.cas);
    let empty = publish_empty_tree(&planes.cas);
    let (environment_id, environment) = declare_busybox_environment(&planes);
    let capsule = assemble(environment_id, work_tree.id());
    let installation = install_provider(planes.dir.path());
    let driver = OciStageDriver::new(
        OciRoute::new(fixture_certification()),
        planes.dir.path().join("worker-state"),
        installation,
    );
    let source = LocalCasBlobSource::open(&planes.cas_db, &planes.cas_blobs)
        .expect("the CAS opens read-only");
    let trees = DeclaredTreeResolver::new(vec![work_tree, empty], &source);
    let refusal = driver
        .drive(
            "plan-refused-attempt",
            &OciStageRequest {
                capsule: &capsule,
                environment: &environment,
                // THE FORCED REFUSAL: `spec_for` admits only `Offline` on this route,
                // and refuses `Host` by name because there is no egress arm.
                network: NetPolicy::Host,
                trees: &trees,
                source: &source,
                probe: &LocalStorePathProbe,
                execution_id: ulid::Ulid::new(),
            },
        )
        .await
        .err()
        .unwrap_or_else(|| {
            panic!(
                "{test}: `NetPolicy::Host` has no form on the rootless-OCI route and must be refused; a drive that succeeded means the plan stopped refusing it."
            )
        });
    assert_eq!(
        refusal.label(),
        "plan_refused",
        "{test}: the refusal under test is the plan's; got {refusal}"
    );
    // The PER-CONTAINER parent is not created at all on this path: `plan_under`
    // derives its path purely, renders the plan, and only then
    // calls `establish`. So there is no `kata.oci.*` directory to look for, and the
    // residue this test is about is the SWEEP ROOT the launch made — which only
    // `shutdown`/`kill_and_contain` removes.
    assert!(
        provider_cgroups(&parent)
            .iter()
            .all(|dir| !std::path::Path::new(dir)
                .join(format!("kata.oci.kata-{}", capsule.id().0))
                .exists()),
        "{test}: a per-container parent cgroup exists for a capsule whose PLAN was refused. \
         `plan_under` derives the parent's path purely and creates it only after `spec_for` \
         succeeds, so a refused plan must leave the hierarchy untouched."
    );

    // THE PROPERTY, read with `find`: no new `kata.provider.*` tree under the
    // delegated parent. Polled, because `contain` observes the subtree's emptiness
    // before it removes it.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(15);
    loop {
        let now = provider_cgroups(&parent);
        let leaked: Vec<&String> = now.iter().filter(|dir| !before.contains(*dir)).collect();
        if leaked.is_empty() {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "{test}: {leaked:?} survived under {parent} fifteen seconds after a refusal that \
             happened AFTER the provider launched. A refusal that only DROPPED the supervisor \
             never runs `contain`, and leaves a sweep root an operator reads as a live stage \
             until the next launch on this worker reclaims it.",
            parent = parent.display(),
        );
        tokio::time::sleep(std::time::Duration::from_millis(250)).await;
    }
    println!("post-launch-refusal label=plan_refused provider-cgroups-leaked=0");
    drop(unseal);
}

/// The `kata.provider.*` directories under the delegated parent, listed with `find` —
/// a tool that shares no code with the supervisor. A DELTA is what the assertion
/// reads, because another concurrent run on the host may legitimately hold one.
fn provider_cgroups(parent: &Path) -> Vec<String> {
    let output = std::process::Command::new("find")
        .arg(parent)
        .args(["-mindepth", "1", "-maxdepth", "1", "-type", "d", "-name"])
        .arg(format!(
            "{}*",
            kata_worker::provider_supervisor::PROVIDER_CGROUP_PREFIX
        ))
        .output()
        .expect("find runs");
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .map(str::to_owned)
        .collect()
}

/// A `YoukiCertification` over the REAL PINNED RUNTIME, with the pin's own path and
/// sha256, for the arms that refuse BEFORE any container is planned.
///
/// The path and digest must be real, and the driver is what makes them so: it
/// re-derives the pinned binary's sha256 immediately before every launch and refuses
/// `runtime_changed` on a mismatch, so a fictional path here would refuse before the
/// arm under test was reached. Taking them from `YoukiPin::embedded()` means the
/// per-stage verification in these tests exercises the production comparison against
/// the production bytes.
///
/// The rest of the fields are FIXTURE values and are never consulted by a test that
/// uses this: the profile, the seccomp witness and the functional probe matter only
/// when a container is started, and the exit-criterion test above certifies for real.
/// That is also why these arms run on a host whose AppArmor profile is not installed.
fn fixture_certification() -> kata_worker::oci_runtime::YoukiCertification {
    let pin = YoukiPin::embedded();
    kata_worker::oci_runtime::YoukiCertification {
        store_path: PathBuf::from(pin.store_path()),
        sha256: pin.sha256().to_owned(),
        version: (0, 7, 0),
        spec_version: (1, 0, 2),
        libseccomp_version: "2.6.1".to_owned(),
        profile: kata_worker::oci_runtime::ApparmorProfile::Loaded,
        installed_profile_sha256: "e".repeat(64),
        userns_restriction: kata_worker::oci_runtime::UsernsRestriction::Restricted,
        delegation: kata_worker::sandbox_bounds::cgroup_delegation().clone(),
        functional_probe_id: "kata-oci-stage-live-fixture".to_owned(),
    }
}

// ---------------------------------------------------------------------------
// THE WHOLE CAPSULE PATH
// ---------------------------------------------------------------------------

/// The production driver, plus ONE host-side reading taken at the only instant it can be:
/// `sha256sum` of the guest's `/out/hi` after the container is torn down and BEFORE
/// `execute_capsule_frame` publishes `/out` and removes the attempt root. Nothing about the
/// drive is changed; the digest is an observation of bytes kata did not write.
struct GuestDigestingDriver<'a> {
    inner: &'a OciStageDriver,
    guest_digest: std::sync::Mutex<Option<String>>,
}

#[async_trait::async_trait]
impl kata_worker::oci_driver::CapsuleDriver for GuestDigestingDriver<'_> {
    async fn drive_capsule(
        &self,
        attempt_tag: &str,
        request: &kata_worker::oci_driver::OciStageRequest<'_>,
        assign_by: std::time::Instant,
        cancel: tokio::sync::oneshot::Receiver<String>,
    ) -> Result<kata_worker::oci_driver::OciStageOutput, kata_worker::oci_driver::OciDriveRefusal>
    {
        let output = self
            .inner
            .drive_capsule(attempt_tag, request, assign_by, cancel)
            .await?;
        let guest_file = output.attempt_root.join("out").join("hi");
        *self.guest_digest.lock().expect("the digest latch") = Some(sha256_of(&guest_file));
        Ok(output)
    }

    fn attempt_root(&self, attempt_tag: &str) -> std::path::PathBuf {
        self.inner.attempt_root(attempt_tag)
    }

    fn describe_driver(&self) -> String {
        self.inner.describe_driver()
    }
}

/// The worker these cells PLACE the attempt on. One name, used by the authorization's
/// dispatch and echoed on the reported fence, because the main compares the frame's
/// claim against `attempts.worker_id`.
const CAPSULE_WORKER: &str = "worker-capsule-1";

/// **THE VERTICAL SLICE: lowering → assembly → authorization → the worker executes the
/// durable frame → `/out` published as a tree → the main adopts and accepts, once.**
///
/// # What makes this the exit criterion rather than a longer version of its sibling
///
/// The sibling above drives `OciStageDriver::drive` with a capsule a rig assembled and
/// asserts what the container did. This one never constructs a frame: it reads the
/// `DispatchFrame::Capsule` out of `attempt_commands.command_json`, which is the byte
/// sequence `authorize_attempt` wrote, and hands THAT to
/// `kata_worker::capsule_execution::execute_capsule_frame`. So the capsule the container
/// runs is the capsule the authorization declared, by construction and not by agreement
/// between two spellings.
///
/// # What is asserted against something that does not share the code under test
///
/// * `/out/hi`'s bytes are read out of the CAS's own BLOB FILE with `sha256sum`, and the
///   digest is compared against `sha256sum` of a file this test writes with the expected
///   payload — two independent runs of a program kata does not link;
/// * the occurrence, its `accepted_attempt_id` and the result's `artifacts` row are read
///   through a SECOND raw rusqlite handle;
/// * the container's exit code and `/work` payload arrive as a provider-written frame,
///   exactly as the sibling asserts.
///
/// # WHAT IS NOT IN THE LOOP, and it is stated rather than implied
///
/// The frame does not travel a transport: this test reads the durable command row and
/// hands it to the worker's executor directly — the same bytes, one hop
/// earlier — so `worker_loop`'s capsule arm, `CapsuleRoute`, the transport and the
/// reactor's `CompletedCapsule` arm are not in it. The reactor's one main-side step, the
/// production door `OperationalDb::adopt_and_accept_capsule_completion`, is driven here
/// directly. The whole product path (a durable main, its worker, the transport and the
/// reactor) is `bin/kata/tests/oci_main_live.rs`'s.
#[test]
#[ignore = "HOST-DEPENDENT for its sibling's reasons (pinned youki, its \
            INSTALLED AppArmor profile, a delegated user scope, a nix daemon, the fixture \
            closure's store path realised) AND instrument-dependent (`cargo build -p \
            kata-provider-youki`). On a host where the pinned youki's AppArmor profile has \
            not been installed this FAILS with `profile_file_differs` — run `sudo kata host \
            apparmor-install` first. Passes live on a host with the \
            profile installed. Run it with `cargo build -p kata-provider-youki --bin \
            kata-provider-youki && cargo nextest run -p kata-workflow -P live-smoke -E 'binary(oci_stage_live)' \
            --run-ignored all`."]
fn the_whole_capsule_slice_runs_and_the_plane_records_one_accepted_outcome_live() {
    delegated(
        "the_whole_capsule_slice_runs_and_the_plane_records_one_accepted_outcome_live",
        the_whole_slice_body(),
    );
}

async fn the_whole_slice_body() {
    let test = "the_whole_capsule_slice_runs_and_the_plane_records_one_accepted_outcome_live";
    let planes = planes();
    let unseal = kata_worker::UnsealOnDrop::new(planes.dir.path());

    // KATA'S OWN MEASUREMENT. A host that cannot certify fails HERE, by name.
    let certification = certify_youki(YoukiPin::embedded()).unwrap_or_else(|refusal| {
        panic!(
            "{test}: this host cannot deliver the rootless-OCI prerequisite ({token}): {refusal}. \
             Run `sudo kata host apparmor-install` as root; `just \
             _containment-preconditions` gives the one-line diagnosis.",
            token = refusal.token(),
        )
    });

    // -- the MAIN's side: lower, declare, assemble, authorize -----------------
    let execution_id = ulid::Ulid::new();
    let program_hash = kata_types::primitives::ContentHash::new([7u8; 32]);
    assert!(matches!(
        planes
            .db
            .submit_execution(
                execution_id,
                &kata_core::ProgramRecord {
                    program_hash,
                    schema_version: 4,
                    program_json: b"{\"program\":1}".to_vec(),
                },
                &slice_invocation(),
            )
            .expect("the execution admits"),
        kata_core::SubmitOutcome::Submitted { .. }
    ));

    // The manifest itself is not handed to the worker — the worker RESOLVES it from
    // the capsule's id through the plane — so only the id is bound here.
    let (environment_id, _environment) = declare_busybox_environment(&planes);
    // PROMOTED, because the authorization gate refuses an unpromoted root by name
    // ("promoted at AUTHORIZE").
    planes
        .db
        .promote_environment_root(environment_id.0.0, chrono::Utc::now().timestamp_millis())
        .expect("the declared closure's root promotes");

    let program = compile_starlark_execution_program(PACK, "oci-stage-live.star", &[])
        .expect("the reduced pack compiles");
    let stage_id = StageId(SmolStr::new("probe"));
    let stage = program
        .stages
        .iter()
        .find(|(id, _)| *id == &stage_id)
        .map(|(_, stage)| stage)
        .expect("the probe stage is present");
    let lowered = lower_stage_operation(&program, &stage_id).expect("the probe stage lowers");
    let occurrence = kata_types::execution_contract::OccurrenceRef::new(
        kata_types::workflow::ExecutionId(execution_id),
        program_hash,
        lowered.contract.id(),
        lowered.path.clone(),
    );
    // THE PRODUCTION SEED: the scratch workspace's ONE admission walk, published
    // and recorded as the execution's durable /work head — the row is what
    // authorization accepts as this attempt's /work.
    let workspace = planes.dir.path().join("slice-workspace");
    std::fs::create_dir_all(workspace.join("src")).expect("the workspace directory");
    std::fs::write(workspace.join("src/a.txt"), SOURCE_PAYLOAD).expect("the source file");
    let head = kata_core::work_tree::publish_scratch_tree_head(
        &planes.db,
        &planes.cas,
        execution_id,
        &workspace,
    )
    .expect("the scratch seed publishes and records the head");
    let head_row = planes
        .db
        .artifact(head.work_tree_artifact_id)
        .unwrap()
        .expect("the head's artifact row");
    let work_tree = kata_types::execution_contract::ArtifactRef::new(
        kata_types::primitives::ObjectId::new(head_row.object_id),
        head_row.size_bytes,
        head_row.privacy,
    );
    kata_core::work_tree::declare_empty_tree(&planes.db, &planes.cas, execution_id)
        .expect("the empty tree declares");
    let (prepared, capsule) = assemble_capsule(
        &lowered,
        occurrence.id(),
        stage,
        &directive(),
        // EXPLICIT, which is what `RenderedCommand`'s one constructor is for: the reduced
        // pack's prompt carries no template expression, so the renderer would return these
        // bytes unchanged and this rig stands in for it rather than pretending to be it.
        &RenderedCommand::rendered(stage.op.prompt_template.clone()),
        environment_id,
        PlatformRef::new(
            "x86_64-linux",
            FixedBytes(*blake3::hash(b"capsule-platform").as_bytes()),
        )
        .id(),
        work_tree.id(),
        NodeBudgetDefaults {
            memory_bytes: 512 * 1024 * 1024,
            process_count: 64,
        },
        None,
        None,
    )
    .expect("the capsule assembles");

    let authorized = kata_workflow::authorization::authorize_attempt(
        &planes.db,
        &planes.cas,
        kata_workflow::authorization::AuthorizeInput {
            execution: kata_types::workflow::ExecutionId(execution_id),
            program_hash,
            lowered: &lowered,
            occurrence: occurrence.clone(),
            prepared,
            capsule: capsule.clone(),
            environment: environment_id,
            work_head: Some(&head),
            programs: &kata_workflow::authorization::HostProgramProbe,
            checked_stage: stage,
            place: &|| Ok(CAPSULE_WORKER.into()),
            approval_bypass_reason: None,
        },
    )
    .unwrap_or_else(|error| panic!("{test}: the authorization refused: {error}"))
    .dispatched()
    .unwrap_or_else(|| panic!("{test}: an ungated stage dispatches"));

    // -- THE FRAME, read out of the durable command rather than constructed --
    let mut frame = command_capsule_frame(&planes.op_path);
    assert_eq!(
        frame.attempt_id, authorized.attempt_id,
        "{test}: the frame the command row holds must be this authorization's"
    );
    assert_eq!(frame.capsule.id, capsule.id());
    // AT REST THE EPOCH IS NOT STAMPED, and this is the first host to have executed far
    // enough to observe it. The durable command deliberately does not restate the lease
    // epoch — `attempt_commands` is filed under `(attempt, lease_epoch)` and a payload copy
    // could disagree with its own row after the next dispatch — so the stored frame carries
    // `0`, the "not stamped" value, while `attempts.lease_epoch` is the authority.
    assert_eq!(
        frame.lease_epoch, 0,
        "{test}: the at-rest frame carries no generation; the row is the authority"
    );
    // THE DELIVERY STAMP, which in production is `Dispatcher::frame_for_dispatch` reading
    // the row at the send boundary. This rig performs it explicitly because it hands the
    // frame to the worker without a transport in between, and the worker ECHOES whatever
    // the frame carried onto its completion fence — so a rig that skipped the stamp would
    // be asserting about a fence the main's ingress would refuse.
    frame.lease_epoch = authorized.lease_epoch;
    frame.placed_on = SmolStr::new(CAPSULE_WORKER);

    // -- the WORKER's side: resolve, drive, publish --------------------------
    let installation = install_provider(planes.dir.path());
    let worker_state = planes.dir.path().join("worker-state");
    let driver = OciStageDriver::new(
        OciRoute::new(certification.clone()),
        &worker_state,
        installation,
    );
    // THE PRODUCTION RESOLVERS. The worker resolves the
    // environment AND every mapped artifact through `LocalPlaneIndex`: `operational.db`
    // and `cas.db` opened read-only by path, each id recomputed from the bytes the row
    // points at. No manifest or reference list is handed in beside the capsule (a
    // pairing nobody would check); the id in the capsule is what finds the bytes, and
    // a row that disagrees is refused by name.
    let planes_index = kata_worker::plane_index::LocalPlaneIndex::open(&planes.data_dir)
        .expect("the worker opens the node's planes read-only");
    let digesting = GuestDigestingDriver {
        inner: &driver,
        guest_digest: std::sync::Mutex::new(None),
    };
    let reported = {
        let sink = kata_worker::result_publication::CasBlobSink(&planes.cas);
        kata_worker::capsule_execution::execute_capsule_frame(
            &kata_worker::capsule_execution::CapsuleExecution {
                driver: &digesting,
                environments: &planes_index,
                trees: &planes_index,
                source: &planes_index,
                probe: &LocalStorePathProbe,
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
        .unwrap_or_else(|error| panic!("{test}: the capsule execution refused: {error}"))
    };

    // -- THE ATTEMPT ROOT IS GONE, read off the filesystem with `find` ----------
    // `/out` is an artifact now, so the materialized `/work`, the bundle and the runtime
    // state under `<worker_state>/attempts/<attempt>` have no reader, and no successful
    // stage leaves that tree behind.
    let attempt_root = driver.attempt_root(&authorized.attempt_id.to_string());
    let listing = std::process::Command::new("find")
        .arg(worker_state.join("attempts"))
        .output()
        .expect("`find` runs");
    let listing = String::from_utf8_lossy(&listing.stdout);
    assert!(
        !attempt_root.exists() && listing.lines().count() <= 1,
        "{test}: a PUBLISHED attempt's root {} must be removed; the attempts directory still \
         holds:\n{listing}",
        attempt_root.display()
    );

    let kata_transport::types::WorkerMessage::CompletedCapsule {
        attempt_id,
        fence,
        result,
        work_delta,
        exit_code,
        stdout,
        stderr,
        capture_exceeded,
        provenance,
        agent,
        ..
    } = reported
    else {
        panic!("{test}: a capsule execution reports the capsule terminal and nothing else");
    };
    assert_eq!(attempt_id, authorized.attempt_id);
    assert_eq!(fence.lease_epoch, authorized.lease_epoch);
    assert_eq!(fence.worker_id.as_str(), CAPSULE_WORKER);
    assert!(
        agent.is_none(),
        "a Command capsule's completed frame carries NO agent report — the band is the Agent \
         turn's alone"
    );
    assert_eq!(
        provenance.label(),
        "local_oci_runtime",
        "{test}: the arm this route's facts carry"
    );
    // The refs name CAS blobs — read them verified, which is what the frame
    // promises a reader.
    let capture_bytes = |reference: &kata_types::execution_contract::ArtifactRef| {
        String::from_utf8(
            planes
                .cas
                .get_verified(
                    &reference.object_id(),
                    reference.size_bytes(),
                    reference.size_bytes().max(1),
                )
                .expect("the reported capture is held and verified"),
        )
        .expect("the capture is UTF-8")
    };
    let stdout_text = capture_bytes(&stdout);
    let stderr_text = capture_bytes(&stderr);
    assert_eq!(
        exit_code,
        Some(0),
        "{test}: the container's exit status arrives as a provider-written frame.\nstdout: \
         {stdout_text}\nstderr: {stderr_text}"
    );
    assert!(
        stdout_text.contains(SOURCE_PAYLOAD.trim()),
        "{test}: the stage's stdout must carry the bytes of /work/src/a.txt, which only a container \
         that really bound the MATERIALIZED /work could have read.\nstdout: {stdout_text}"
    );
    assert!(
        !capture_exceeded,
        "{test}: a three-byte result hits no capture bound"
    );

    // -- the MAIN's side: adopt AND accept, once, in the production door ------
    let attempt = planes
        .db
        .attempt(authorized.attempt_id)
        .expect("the attempts row is readable")
        .expect("the authorization wrote it");
    let (adopted, verdict) = planes
        .db
        .adopt_and_accept_capsule_completion(
            &kata_core::operational::CapsuleResultAdoption {
                execution_id,
                occurrence_id: occurrence.id(),
                result: result.clone(),
                stdout: stdout.clone(),
                stderr: stderr.clone(),
                work_delta,
                capture_exceeded,
                agent: None,
                egress_refusals: vec![],
            },
            |adopted| kata_core::operational::WorkerCompletionInput {
                execution_id,
                attempt_id: authorized.attempt_id,
                attempt_ordinal: attempt.attempt_ordinal,
                lease_epoch: authorized.lease_epoch,
                worker_id: CAPSULE_WORKER.to_owned(),
                output: kata_core::operational::capsule_result_output(
                    adopted,
                    &result,
                    exit_code,
                    &stdout,
                    &stderr,
                    capture_exceeded,
                    Some(kata_workflow::test_harness::oci_rig_executor_term().digest()),
                ),
            },
        )
        .unwrap_or_else(|error| panic!("{test}: the main refused the result tree: {error}"));
    assert_eq!(
        adopted.manifest.entries().len(),
        1,
        "{test}: the stage wrote exactly `/out/hi`"
    );
    assert!(
        matches!(
            verdict,
            kata_core::operational::CompletionVerdict::Accepted { .. }
        ),
        "{test}: exactly one acceptance — the frame satisfies the worker fence, whose epoch \
         and placement are the authorization's own: {verdict:?}"
    );

    // -- RAW SQLITE: one occurrence, one accepted attempt, one result row ----
    let conn = rusqlite::Connection::open_with_flags(
        &planes.op_path,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .expect("a second raw handle onto operational.db");
    let (occurrences, accepted): (i64, Option<Vec<u8>>) = conn
        .query_row(
            "SELECT count(*), (SELECT accepted_attempt_id FROM occurrences) FROM occurrences",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .expect("the occurrences table is readable");
    assert_eq!(occurrences, 1, "{test}: exactly ONE occurrence");
    assert_eq!(
        accepted,
        Some(authorized.attempt_id.to_bytes().to_vec()),
        "{test}: and its accepted outcome is this attempt's"
    );
    // The `artifacts` row carries the CONTENT CLAIM and no owner (schema 20), so the row
    // and the retaining ROOT are read separately. The query is a RUNTIME string, so a
    // dropped column would leave the compile green and panic `no such column` the
    // first time this test could actually run.
    let (kind, object): (String, Vec<u8>) = conn
        .query_row(
            "SELECT kind, object_id FROM artifacts WHERE artifact_id = ?1",
            rusqlite::params![adopted.artifact_id.as_slice()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .expect("the result's artifacts row is readable");
    assert_eq!(kind, "tree", "{test}: a result is a tree");
    assert_eq!(object, result.object_id().0.to_vec());
    let root_owner: Option<Vec<u8>> = conn
        .query_row(
            "SELECT owner_execution_id FROM cas_roots
              WHERE purpose = 'artifact_object' AND object_digest = ?1
                AND released_at_ms IS NULL",
            rusqlite::params![result.object_id().0.as_slice()],
            |row| row.get(0),
        )
        .expect("the result's retaining root is readable");
    assert_eq!(
        root_owner,
        Some(execution_id.to_bytes().to_vec()),
        "{test}: the retaining ROOT belongs to this execution, and since schema 20 it is \
         the only place ownership is recorded"
    );

    // -- SHA256SUM: the file the GUEST wrote, and the bytes the store kept ---------
    //
    // The instrument is `sha256sum`, which kata does not link, and the FIRST digest is
    // taken from the container's own output file on the host — the bytes a process inside
    // the container redirected into a directory kata bind-mounted, which nothing in kata
    // wrote. That is the independent reading.
    //
    // Not `__test_blob_path(&member.object)`: a `CasStore` keeps an object under
    // `INLINE_THRESHOLD` as a COLUMN in `cas.db`, `/out/hi` is three bytes, and so no
    // blob file exists.
    let member = &adopted.manifest.entries()[0];
    assert_eq!(member.path.as_str(), "hi");
    let TreeNode::File {
        object: member_object,
        size_bytes: member_size,
        ..
    } = &member.node
    else {
        panic!("the adopted `hi` entry is a file")
    };
    let from_guest = digesting
        .guest_digest
        .lock()
        .expect("the digest latch")
        .take()
        .expect("the guest's /out/hi was digested between the teardown and the publish");
    let expected_file = planes.dir.path().join("expected-out-hi");
    std::fs::write(&expected_file, OUT_PAYLOAD).expect("writing the expected payload");
    assert_eq!(
        from_guest,
        sha256_of(&expected_file),
        "{test}: the file the guest wrote into the bound `/out` must hold the expected payload, \
         digested by a program kata does not link"
    );
    // And the STORE kept those same bytes: read back through the store's own verified read
    // (which is address-checked and inline/file agnostic), written to a host file, and
    // digested by the same external program. The comparison is against the GUEST's digest,
    // so the claim is "what the store retained is what the container produced" rather than
    // kata agreeing with itself.
    let from_store = planes
        .cas
        .get_verified(member_object, *member_size, 64 * 1024)
        .expect("the published member reads back at its own address");
    let store_file = planes.dir.path().join("store-out-hi");
    std::fs::write(&store_file, &from_store).expect("writing the store's bytes");
    let from_cas = sha256_of(&store_file);
    assert_eq!(
        from_cas, from_guest,
        "{test}: the bytes the CAS retained for `/out/hi` must be the bytes the guest wrote"
    );

    println!(
        "live-capsule occurrence={occurrence} attempt={attempt} capsule={capsule} \
         result={result} out-sha256={from_cas} youki={youki}",
        occurrence = occurrence.id().0,
        attempt = authorized.attempt_id,
        capsule = capsule.id().0,
        result = result.id().0,
        youki = certification.sha256,
    );
    drop(unseal);
}

/// **The committed-base live cell**: the `/work` an isolated `oci` capsule
/// binds is the execution's COMMITTED base tree — the artifact admission
/// published into CAS and recorded as the work-tree head — not a scratch walk
/// of the operator's checkout.
///
/// **Would red if:** the container's `/work` lacked a committed file, lost the
/// committed executable bit, dropped or de-referenced a committed symlink, or
/// materialized bytes that exist only in the operator's dirty working copy.
/// Every one of those is checked by the GUEST's own `test`/`cat`, which exits
/// non-zero on the first miss — the verdict arrives as the provider-written
/// completion frame, and the committed payload in stdout is bytes only a real
/// bind of the materialized head could have produced.
#[test]
#[ignore = "HOST-DEPENDENT for its siblings' reasons (pinned youki, its INSTALLED AppArmor \
            profile, a delegated user scope, a nix daemon, the fixture closure's store path \
            realised) AND instrument-dependent (`cargo build -p kata-provider-youki`). On a \
            host where the profile has not been installed this FAILS with \
            `profile_file_differs` — run `sudo kata host \
            apparmor-install` first. Run it with `cargo build -p kata-provider-youki --bin \
            kata-provider-youki && cargo nextest run -p kata-workflow -P live-smoke -E \
            'binary(oci_stage_live)' --run-ignored all`."]
fn the_committed_base_head_is_what_the_container_sees_live() {
    delegated(
        "the_committed_base_head_is_what_the_container_sees_live",
        the_committed_base_body(),
    );
}

async fn the_committed_base_body() {
    let test = "the_committed_base_head_is_what_the_container_sees_live";
    let planes = planes();
    let unseal = kata_worker::UnsealOnDrop::new(planes.dir.path());
    let certification = certify_youki(YoukiPin::embedded()).unwrap_or_else(|refusal| {
        panic!(
            "{test}: this host cannot deliver the rootless-OCI prerequisite ({token}): {refusal}. \
             Run `sudo kata host apparmor-install` as root; `just \
             _containment-preconditions` gives the one-line diagnosis.",
            token = refusal.token(),
        )
    });

    // -- THE COMMITTED BASE, built by git itself ------------------------------
    // The fixture is a REAL repository: git records the executable bit and the
    // symlink, jj adopts the colocated repo, and `dirty.txt` stays UNCOMMITTED
    // in the operator working copy — the exact shape an execution's committed
    // base must never carry into `/work`.
    let repo = planes.dir.path().join("repo");
    std::fs::create_dir_all(&repo).expect("the repo directory");
    init_git_repo_at(&repo);
    std::fs::create_dir_all(repo.join("src")).expect("src/");
    std::fs::create_dir_all(repo.join("bin")).expect("bin/");
    std::fs::write(repo.join("src/a.txt"), SOURCE_PAYLOAD).expect("the committed file");
    std::fs::write(repo.join("bin/run.sh"), "#!/bin/sh\necho tool\n").expect("the executable");
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(
            repo.join("bin/run.sh"),
            std::fs::Permissions::from_mode(0o755),
        )
        .expect("the executable bit");
    }
    std::os::unix::fs::symlink("src/a.txt", repo.join("latest")).expect("the committed symlink");
    run_git(&repo, &["add", "-A"]);
    run_git(&repo, &["commit", "-q", "-m", "the committed base"]);
    // THE OPERATOR'S DIRTY FILE — committed to nothing, present on disk.
    std::fs::write(repo.join("dirty.txt"), "uncommitted\n").expect("the uncommitted edit");
    // Ground truth from git itself: the commit's tree holds the executable and
    // the symlink and does NOT hold the dirty file.
    let listing = hermetic_git_in(&repo)
        .args(["ls-tree", "-r", "HEAD"])
        .output()
        .unwrap();
    let listing = String::from_utf8_lossy(&listing.stdout).into_owned();
    assert!(
        listing.contains("100755") && listing.contains("120000") && !listing.contains("dirty.txt"),
        "{test}: the fixture's committed tree must hold an executable and a symlink and no \
         dirty.txt: {listing}"
    );

    // -- the EXECUTION's admission-time publication, main's side --------------
    let execution_id = ulid::Ulid::new();
    let program_hash = kata_types::primitives::ContentHash::new([9u8; 32]);
    planes
        .db
        .submit_execution(
            execution_id,
            &kata_core::ProgramRecord {
                program_hash,
                schema_version: 4,
                program_json: b"{\"program\":1}".to_vec(),
            },
            &slice_invocation(),
        )
        .expect("the execution admits");

    // THE PRODUCTION PATH: JjBackend::open adopts the repo, the execution
    // workspace bases on trunk, and `publish_base_tree_head` streams the
    // committed members into CAS and records the durable head — the same three
    // calls kata-api's isolated-`oci` admission makes.
    let backend = JjBackend::open(&repo).expect("adopt the fixture repository");
    let key = kata_effects_contract::ExecutionWorkspaceKey::execution(ulid::Ulid::new());
    let handle = kata_vcs::test_support::create_trunk_workspace(&backend, &key).expect("workspace");
    let head = kata_core::work_tree::publish_base_tree_head(
        &planes.db,
        &planes.cas,
        execution_id,
        |put| {
            kata_effects_contract::ExecutionWorkspaceProvider::committed_base_tree(
                &backend,
                &handle,
                WorkTreeInputBounds::default(),
                put,
            )
        },
    )
    .unwrap_or_else(|error| panic!("{test}: the committed base publishes: {error}"));
    kata_effects_contract::ExecutionWorkspaceProvider::remove_workspace(&backend, &key)
        .expect("the execution workspace removes");

    let (environment_id, _environment) = declare_busybox_environment(&planes);
    planes
        .db
        .promote_environment_root(environment_id.0.0, chrono::Utc::now().timestamp_millis())
        .expect("the declared closure's root promotes");

    let program = compile_starlark_execution_program(PACK, "oci-stage-live.star", &[])
        .expect("the reduced pack compiles");
    let stage_id = StageId(SmolStr::new("probe"));
    let stage = program
        .stages
        .iter()
        .find(|(id, _)| *id == &stage_id)
        .map(|(_, stage)| stage)
        .expect("the probe stage is present");
    let lowered = lower_stage_operation(&program, &stage_id).expect("the probe stage lowers");
    let occurrence = kata_types::execution_contract::OccurrenceRef::new(
        kata_types::workflow::ExecutionId(execution_id),
        program_hash,
        lowered.contract.id(),
        lowered.path.clone(),
    );
    kata_core::work_tree::declare_empty_tree(&planes.db, &planes.cas, execution_id)
        .expect("the empty tree declares");
    // The GUEST checks all four facts itself and exits non-zero on the first
    // miss: the committed file exists, the committed executable keeps its bit,
    // the committed symlink resolves, and the uncommitted edit is ABSENT.
    let (prepared, capsule) = assemble_capsule(
        &lowered,
        occurrence.id(),
        stage,
        &directive(),
        &RenderedCommand::rendered(
            "echo hi > /out/hi; \
             test -f /work/src/a.txt && test -x /work/bin/run.sh && test -L /work/latest && \
             ! test -e /work/dirty.txt && cat /work/src/a.txt && cat /work/latest"
                .to_owned(),
        ),
        environment_id,
        PlatformRef::new(
            "x86_64-linux",
            FixedBytes(*blake3::hash(b"workspace-platform-live").as_bytes()),
        )
        .id(),
        ArtifactId(FixedBytes(head.work_tree_artifact_id)),
        NodeBudgetDefaults {
            memory_bytes: 512 * 1024 * 1024,
            process_count: 64,
        },
        None,
        None,
    )
    .expect("the capsule assembles");

    // COMMITTED-BASE authorization: the durable head row, re-read inside the
    // gate, is what the capsule's `/work` mapping must equal.
    let authorized = kata_workflow::authorization::authorize_attempt(
        &planes.db,
        &planes.cas,
        kata_workflow::authorization::AuthorizeInput {
            execution: kata_types::workflow::ExecutionId(execution_id),
            program_hash,
            lowered: &lowered,
            occurrence: occurrence.clone(),
            prepared,
            capsule: capsule.clone(),
            environment: environment_id,
            work_head: Some(&head),
            programs: &kata_workflow::authorization::HostProgramProbe,
            checked_stage: stage,
            place: &|| Ok(CAPSULE_WORKER.into()),
            approval_bypass_reason: None,
        },
    )
    .unwrap_or_else(|error| panic!("{test}: the authorization refused: {error}"))
    .dispatched()
    .unwrap_or_else(|| panic!("{test}: an ungated stage dispatches"));

    let mut frame = command_capsule_frame(&planes.op_path);
    assert_eq!(frame.attempt_id, authorized.attempt_id);
    assert_eq!(frame.capsule.id, capsule.id());
    frame.lease_epoch = authorized.lease_epoch;
    frame.placed_on = SmolStr::new(CAPSULE_WORKER);

    // -- the WORKER's side: the same resolvers and driver as the sibling cell --
    let installation = install_provider(planes.dir.path());
    let worker_state = planes.dir.path().join("worker-state");
    let driver = OciStageDriver::new(
        OciRoute::new(certification.clone()),
        &worker_state,
        installation,
    );
    let planes_index = kata_worker::plane_index::LocalPlaneIndex::open(&planes.data_dir)
        .expect("the worker opens the node's planes read-only");
    let reported = {
        let sink = kata_worker::result_publication::CasBlobSink(&planes.cas);
        kata_worker::capsule_execution::execute_capsule_frame(
            &kata_worker::capsule_execution::CapsuleExecution {
                driver: &driver,
                environments: &planes_index,
                trees: &planes_index,
                source: &planes_index,
                probe: &LocalStorePathProbe,
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
        .unwrap_or_else(|error| panic!("{test}: the capsule execution refused: {error}"))
    };

    let kata_transport::types::WorkerMessage::CompletedCapsule {
        attempt_id,
        result,
        work_delta,
        exit_code,
        stdout,
        stderr,
        capture_exceeded,
        ..
    } = reported
    else {
        panic!("{test}: a capsule execution reports the capsule terminal and nothing else");
    };
    assert_eq!(attempt_id, authorized.attempt_id);
    // v6: the refs name CAS blobs — read them verified, which is the frame's promise.
    let capture_text = |reference: &kata_types::execution_contract::ArtifactRef| {
        String::from_utf8(
            planes
                .cas
                .get_verified(
                    &reference.object_id(),
                    reference.size_bytes(),
                    reference.size_bytes().max(1),
                )
                .expect("the reported capture is held and verified"),
        )
        .expect("the capture is UTF-8")
    };
    let stdout_text = capture_text(&stdout);
    let stderr_text = capture_text(&stderr);
    assert!(
        !capture_exceeded,
        "{test}: a four-byte payload hits no capture bound"
    );
    assert_eq!(
        exit_code,
        Some(0),
        "{test}: the guest's /work checks must ALL hold — a missing committed file, a lost \
         executable bit, a dropped symlink, or a leaked dirty.txt exits non-zero.\nstdout: \
         {stdout_text}\nstderr: {stderr_text}"
    );
    // TWO sightings of the payload: once through the committed file's own path
    // and once through the committed symlink — the symlink resolving inside the
    // container is the only way the second `cat` produces it.
    assert_eq!(
        stdout_text.matches(SOURCE_PAYLOAD.trim()).count(),
        2,
        "{test}: stdout must carry the committed bytes twice — /work/src/a.txt and \
         /work/latest the symlink resolves to.\nstdout: {stdout_text}"
    );

    // -- the MAIN's side: adopt and accept through the production door --------
    let attempt = planes
        .db
        .attempt(authorized.attempt_id)
        .expect("the attempts row is readable")
        .expect("the authorization wrote it");
    let (_adopted, verdict) = planes
        .db
        .adopt_and_accept_capsule_completion(
            &kata_core::operational::CapsuleResultAdoption {
                execution_id,
                occurrence_id: occurrence.id(),
                result: result.clone(),
                stdout: stdout.clone(),
                stderr: stderr.clone(),
                work_delta,
                capture_exceeded,
                agent: None,
                egress_refusals: vec![],
            },
            |adopted| kata_core::operational::WorkerCompletionInput {
                execution_id,
                attempt_id: authorized.attempt_id,
                attempt_ordinal: attempt.attempt_ordinal,
                lease_epoch: authorized.lease_epoch,
                worker_id: CAPSULE_WORKER.to_owned(),
                output: kata_core::operational::capsule_result_output(
                    adopted,
                    &result,
                    exit_code,
                    &stdout,
                    &stderr,
                    false,
                    Some(kata_workflow::test_harness::oci_rig_executor_term().digest()),
                ),
            },
        )
        .unwrap_or_else(|error| panic!("{test}: the main refused the result tree: {error}"));
    assert!(
        matches!(
            verdict,
            kata_core::operational::CompletionVerdict::Accepted { .. }
        ),
        "{test}: exactly one acceptance: {verdict:?}"
    );

    // -- RAW SQLITE: the recorded head IS the artifact the capsule mapped -----
    let conn = rusqlite::Connection::open_with_flags(
        &planes.op_path,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .expect("a second raw handle onto operational.db");
    let recorded_head: Vec<u8> = conn
        .query_row(
            "SELECT work_tree_artifact_id FROM execution_work_tree_heads \
              WHERE execution_id = ?1",
            rusqlite::params![execution_id.to_bytes().as_slice()],
            |row| row.get(0),
        )
        .expect("the recorded head row is readable");
    assert_eq!(
        recorded_head.as_slice(),
        head.work_tree_artifact_id.as_slice(),
        "{test}: the durable head is the artifact this capsule's /work bound"
    );

    println!(
        "committed-base live occurrence={occurrence} attempt={attempt} capsule={capsule} \
         head={head} base={base} youki={youki}",
        occurrence = occurrence.id().0,
        attempt = authorized.attempt_id,
        capsule = capsule.id().0,
        head = kata_types::primitives::ContentHash::new(head.work_tree_artifact_id),
        base = head.base_commit,
        youki = certification.sha256,
    );
    drop(unseal);
}

/// The invocation record these cells admit their execution with.
fn slice_invocation() -> kata_core::InvocationRecord {
    let bytes =
        kata_types::idempotency::canonicalize_args(&serde_json::json!({"schema_version": 1}));
    let digest = *blake3::hash(&bytes).as_bytes();
    kata_core::InvocationRecord {
        schema_version: 1,
        kind: kata_core::InvocationKind::Workflow,
        admission_digest: kata_types::identity_algebra::AdmissionDigest(
            kata_types::primitives::ContentHash::new(digest),
        ),
        invocation_json: bytes,
    }
}

/// The `DispatchFrame::Capsule` the dispatch command holds, decoded off a raw handle.
///
/// Read from `attempt_commands.command_json`, so the bytes are the ones
/// `authorize_attempt` wrote and the decode is the transport's own.
fn command_capsule_frame(op_path: &Path) -> kata_transport::types::CapsuleAssignment {
    let frames = command_capsule_frames(op_path);
    assert_eq!(frames.len(), 1, "exactly one dispatch command is written");
    frames.into_iter().next().expect("the one frame")
}

/// Every written capsule frame, in row order — the multi-attempt sibling of
/// [`command_capsule_frame`], for cells that authorize twice against one
/// plane.
fn command_capsule_frames(op_path: &Path) -> Vec<kata_transport::types::CapsuleAssignment> {
    let conn = rusqlite::Connection::open_with_flags(
        op_path,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .expect("a raw handle onto operational.db");
    let mut statement = conn
        .prepare("SELECT command_json FROM attempt_commands ORDER BY rowid")
        .expect("the command table reads");
    statement
        .query_map([], |row| row.get::<_, Vec<u8>>(0))
        .expect("the command table lists")
        .map(|payload| {
            let payload = payload.expect("a payload row");
            let command: serde_json::Value =
                serde_json::from_slice(&payload).expect("the command payload is JSON");
            let frame: kata_transport::types::DispatchFrame =
                serde_json::from_value(command["frame"].clone())
                    .expect("the command payload's frame decodes as a DispatchFrame");
            let kata_transport::types::DispatchFrame::Capsule(capsule) = frame;
            *capsule
        })
        .collect()
}

/// `sha256sum <path>`, first field. The instrument is a program kata does not link, so
/// the digest is not kata's own answer about kata's own bytes.
fn sha256_of(path: &Path) -> String {
    let output = std::process::Command::new("sha256sum")
        .arg(path)
        .output()
        .expect("sha256sum runs");
    assert!(
        output.status.success(),
        "sha256sum failed on {}: {}",
        path.display(),
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout)
        .split_whitespace()
        .next()
        .expect("sha256sum prints a digest")
        .to_owned()
}

// ---------------------------------------------------------------------------
// The LIVE progress cell
// ---------------------------------------------------------------------------

/// A `WorkerSideTransport` that records every result frame — the main-side
/// half of the wire, in-process, so the live cell reads the frames the
/// emitter sent without standing a reactor up.
#[derive(Default, Debug)]
struct RecordingWire {
    sent: std::sync::Mutex<Vec<kata_transport::types::WorkerMessage>>,
}

#[async_trait::async_trait]
impl kata_transport::transport::WorkerSideTransport for RecordingWire {
    async fn recv_frame(
        &self,
    ) -> kata_types::error::KataResult<kata_transport::types::DispatchFrame> {
        std::future::pending().await
    }
    async fn recv_control(
        &self,
    ) -> kata_types::error::KataResult<kata_transport::types::WorkerControl> {
        std::future::pending().await
    }
    async fn send_result(
        &self,
        message: kata_transport::types::WorkerMessage,
    ) -> kata_types::error::KataResult<()> {
        self.sent.lock().expect("the wire's record").push(message);
        Ok(())
    }
    async fn shutdown(&self) -> kata_types::error::KataResult<()> {
        Ok(())
    }
    fn is_alive(&self) -> bool {
        true
    }
}

const PROGRESS_PACK: &str = "probe = stage(\n\
     \x20   id = \"probe\",\n\
     \x20   agent = \"shell\",\n\
     \x20   sandbox = \"iso\",\n\
     \x20   timeout_ms = 30000,\n\
     \x20   progress_visibility = \"full\",\n\
     \x20   prompt = \"echo first-marker; sleep 0.6; echo second-marker; echo sealed > /out/hi\",\n\
     )\n\
     workflow(\n\
     \x20   \"oci-progress-live\",\n\
     \x20   root = [probe],\n\
     \x20   sandbox_profiles = {\"iso\": sandbox_profile(workspace = \"rw\", net = \"offline\")},\n\
     )\n";

/// **The live progress cell: a running OCI shell capsule streams its spooled stdout
/// as `CapsuleProgress` frames on the wire — authored `progress_visibility =
/// "full"` reaching the tailer through the stamped frame.**
///
/// Same production shape as the vertical cell above: the frame is the bytes
/// `authorize_attempt` enqueued, the driver is the real `OciStageDriver`, the
/// container is real youki. What the cell adds is the worker loop's one line
/// of progress wiring — `CapsuleProgress::start(&frame, transport)` handed
/// into `execute_capsule_frame` — which is exactly how `worker_loop` calls
/// it, minus the loop itself.
///
/// # What is asserted against something that does not share the code under test
///
/// * The frame's `progress_visibility` is read off the durable command
///   payload — the authored knob's arrival is the authorization's own bytes,
///   not a field this rig set;
/// * the progress frames are read off the recording transport — the wire
///   itself, carrying `"first-marker"`/`"second-marker"` the container really
///   printed, attributed to the attempt the authorization minted, strictly
///   monotonic in `byte_offset`;
/// * the terminal `CompletedCapsule` still reports the published captures —
///   progress was a parallel stream, not a mutation of the result.
#[test]
#[ignore = "Same host prerequisites as \
            the_whole_capsule_slice_runs_and_the_plane_records_one_accepted_outcome_live \
            (pinned youki, installed AppArmor profile, delegated user scope, nix daemon). \
            Run with `cargo build -p kata-provider-youki --bin kata-provider-youki && \
            cargo nextest run -p kata-workflow -P live-smoke -E 'binary(oci_stage_live)' \
            --run-ignored all`."]
fn a_running_oci_shell_capsule_streams_progress_live() {
    delegated(
        "a_running_oci_shell_capsule_streams_progress_live",
        the_progress_slice_body(),
    );
}

async fn the_progress_slice_body() {
    use kata_worker::capsule_progress::CapsuleProgress;

    let test = "a_running_oci_shell_capsule_streams_progress_live";
    let planes = planes();
    let unseal = kata_worker::UnsealOnDrop::new(planes.dir.path());
    let certification = certify_youki(YoukiPin::embedded()).unwrap_or_else(|refusal| {
        panic!(
            "{test}: this host cannot deliver the rootless-OCI prerequisite ({token}): {refusal}",
            token = refusal.token(),
        )
    });

    let execution_id = ulid::Ulid::new();
    let program_hash = kata_types::primitives::ContentHash::new([8u8; 32]);
    assert!(matches!(
        planes
            .db
            .submit_execution(
                execution_id,
                &kata_core::ProgramRecord {
                    program_hash,
                    schema_version: 4,
                    program_json: b"{\"program\":1}".to_vec(),
                },
                &slice_invocation(),
            )
            .expect("the execution admits"),
        kata_core::SubmitOutcome::Submitted { .. }
    ));
    let (environment_id, _environment) = declare_busybox_environment(&planes);
    planes
        .db
        .promote_environment_root(environment_id.0.0, chrono::Utc::now().timestamp_millis())
        .expect("the declared closure's root promotes");

    let program = compile_starlark_execution_program(PROGRESS_PACK, "oci-progress-live.star", &[])
        .expect("the progress pack compiles");
    let stage_id = StageId(SmolStr::new("probe"));
    let stage = program
        .stages
        .iter()
        .find(|(id, _)| *id == &stage_id)
        .map(|(_, stage)| stage)
        .expect("the probe stage is present");
    let lowered = lower_stage_operation(&program, &stage_id).expect("the probe stage lowers");
    let occurrence = kata_types::execution_contract::OccurrenceRef::new(
        kata_types::workflow::ExecutionId(execution_id),
        program_hash,
        lowered.contract.id(),
        lowered.path.clone(),
    );
    let workspace = planes.dir.path().join("progress-workspace");
    std::fs::create_dir_all(&workspace).expect("the workspace directory");
    let head = kata_core::work_tree::publish_scratch_tree_head(
        &planes.db,
        &planes.cas,
        execution_id,
        &workspace,
    )
    .expect("the scratch seed publishes and records the head");
    let head_row = planes
        .db
        .artifact(head.work_tree_artifact_id)
        .unwrap()
        .expect("the head's artifact row");
    let work_tree = kata_types::execution_contract::ArtifactRef::new(
        kata_types::primitives::ObjectId::new(head_row.object_id),
        head_row.size_bytes,
        head_row.privacy,
    );
    kata_core::work_tree::declare_empty_tree(&planes.db, &planes.cas, execution_id)
        .expect("the empty tree declares");
    let (prepared, capsule) = assemble_capsule(
        &lowered,
        occurrence.id(),
        stage,
        &directive(),
        &RenderedCommand::rendered(stage.op.prompt_template.clone()),
        environment_id,
        PlatformRef::new(
            "x86_64-linux",
            FixedBytes(*blake3::hash(b"progress-platform-live").as_bytes()),
        )
        .id(),
        work_tree.id(),
        NodeBudgetDefaults {
            memory_bytes: 512 * 1024 * 1024,
            process_count: 64,
        },
        None,
        None,
    )
    .expect("the capsule assembles");

    let authorized = kata_workflow::authorization::authorize_attempt(
        &planes.db,
        &planes.cas,
        kata_workflow::authorization::AuthorizeInput {
            execution: kata_types::workflow::ExecutionId(execution_id),
            program_hash,
            lowered: &lowered,
            occurrence: occurrence.clone(),
            prepared,
            capsule: capsule.clone(),
            environment: environment_id,
            work_head: Some(&head),
            programs: &kata_workflow::authorization::HostProgramProbe,
            checked_stage: stage,
            place: &|| Ok(CAPSULE_WORKER.into()),
            approval_bypass_reason: None,
        },
    )
    .unwrap_or_else(|error| panic!("{test}: the authorization refused: {error}"))
    .dispatched()
    .unwrap_or_else(|| panic!("{test}: an ungated stage dispatches"));

    let mut frame = command_capsule_frame(&planes.op_path);
    assert_eq!(frame.attempt_id, authorized.attempt_id);
    // THE AUTHORED KNOB, read off the durable command's own bytes — the
    // authorization stamped the checked stage's `progress_visibility` onto
    // the at-rest frame, so this rig sets nothing.
    assert_eq!(
        frame.progress_visibility,
        kata_types::workflow::ProgressVisibility::Full,
        "{test}: the authored visibility must ride the at-rest frame"
    );
    frame.lease_epoch = authorized.lease_epoch;
    frame.placed_on = SmolStr::new(CAPSULE_WORKER);

    let installation = install_provider(planes.dir.path());
    let worker_state = planes.dir.path().join("worker-state");
    let driver = OciStageDriver::new(
        OciRoute::new(certification.clone()),
        &worker_state,
        installation,
    );
    let planes_index = kata_worker::plane_index::LocalPlaneIndex::open(&planes.data_dir)
        .expect("the worker opens the node's planes read-only");

    // The wire the emitter drains onto, and the emitter exactly as
    // `worker_loop` constructs it — the stage authored `full`, so `start`
    // returns one.
    let wire = std::sync::Arc::new(RecordingWire::default());
    let progress = CapsuleProgress::start(
        &frame,
        std::sync::Arc::clone(&wire)
            as std::sync::Arc<dyn kata_transport::transport::WorkerSideTransport>,
    )
    .expect("a `full` stage builds an emitter");

    let reported = {
        let sink = kata_worker::result_publication::CasBlobSink(&planes.cas);
        kata_worker::capsule_execution::execute_capsule_frame(
            &kata_worker::capsule_execution::CapsuleExecution {
                driver: &driver,
                environments: &planes_index,
                trees: &planes_index,
                source: &planes_index,
                probe: &LocalStorePathProbe,
                sink: &sink,
                adapters: &*AGENT_ADAPTERS,
                credentials: &AMBIENT_CREDENTIALS,
            },
            &frame,
            std::time::Instant::now(),
            tokio::sync::oneshot::channel().1,
            Some(&progress),
        )
        .await
        .unwrap_or_else(|error| panic!("{test}: the capsule execution refused: {error}"))
    };
    // The loop's own ordering rule: the drain is flushed before the terminal
    // would be sent — here, before the frames are read.
    progress.finish().await;

    let kata_transport::types::WorkerMessage::CompletedCapsule {
        attempt_id, stdout, ..
    } = reported
    else {
        panic!("{test}: a capsule execution reports the capsule terminal");
    };
    assert_eq!(attempt_id, authorized.attempt_id);

    let frames: Vec<kata_transport::types::WorkerMessage> =
        wire.sent.lock().expect("the wire's record").clone();
    let progress_frames: Vec<_> = frames
        .iter()
        .map(|message| match message {
            kata_transport::types::WorkerMessage::CapsuleProgress {
                attempt_id,
                byte_offset,
                preview,
                dropped,
                fence,
            } => (
                *attempt_id,
                *byte_offset,
                preview.clone(),
                *dropped,
                fence.clone(),
            ),
            other => panic!("{test}: the wire carried a non-progress frame: {other:?}"),
        })
        .collect();
    assert!(
        !progress_frames.is_empty(),
        "{test}: a `full` shell capsule's spool was tailed — the wire carried progress"
    );
    let previews: Vec<&str> = progress_frames
        .iter()
        .map(|(_, _, preview, _, _)| preview.as_str())
        .collect();
    assert!(
        previews
            .iter()
            .any(|preview| preview.contains("first-marker")),
        "{test}: the first echo reached the wire while the capsule slept: {previews:?}"
    );
    assert!(
        previews
            .iter()
            .any(|preview| preview.contains("second-marker")),
        "{test}: the second echo reached the wire: {previews:?}"
    );
    for (id, _, _, _, fence) in &progress_frames {
        assert_eq!(*id, authorized.attempt_id, "{test}: attribution");
        assert_eq!(fence.lease_epoch, authorized.lease_epoch);
        assert_eq!(fence.worker_id.as_str(), CAPSULE_WORKER);
    }
    let mut offsets = progress_frames.iter().map(|(_, offset, ..)| *offset);
    assert!(
        offsets.clone().is_sorted() && offsets.next() != Some(0),
        "{test}: byte offsets are strictly monotonic: {progress_frames:?}"
    );
    // The terminal still reports the published captures — the progress
    // stream was parallel to the result, never a part of it.
    let published = planes
        .cas
        .get_verified(
            &stdout.object_id(),
            stdout.size_bytes(),
            stdout.size_bytes().max(1),
        )
        .expect("the reported capture is held and verified");
    let stdout_text = String::from_utf8_lossy(&published);
    assert!(
        stdout_text.contains("first-marker") && stdout_text.contains("second-marker"),
        "{test}: the full capture published whole beside the progress stream: {stdout_text}"
    );

    drop(unseal);
    drop(planes);
}

// ---------------------------------------------------------------------------
// An AUTHORED `net = "host"` shell stage, egress live
// ---------------------------------------------------------------------------

/// The pack this cell compiles: a shell stage authored `net = "host"` over a
/// scratch `/work` — the authored shape whose whole route out is the node's
/// `[node] egress_allow` through the worker-owned CONNECT proxy.
const EGRESS_PACK: &str = "probe = stage(\n\
     \x20   id = \"probe\",\n\
     \x20   agent = \"shell\",\n\
     \x20   sandbox = \"eg\",\n\
     \x20   timeout_ms = 60000,\n\
     \x20   prompt = \"true\",\n\
     )\n\
     workflow(\n\
     \x20   \"oci-egress-live\",\n\
     \x20   root = [probe],\n\
     \x20   sandbox_profiles = {\"eg\": sandbox_profile(workspace = \"scratch\", net = \"host\")},\n\
     )\n";

/// **An authored `net = "host"` shell stage reaches exactly the node's
/// `[node] egress_allow` — through the worker's CONNECT proxy, inside a real
/// container — and a host the allowlist does not name is refused, the refusal
/// read off the PROXY's record rather than kata's report.**
///
/// `crates/worker/tests/egress_oci_live.rs` proves the proxy mechanism against
/// a hand-built `CapsuleNetwork::Egress` capsule. What this cell adds is the
/// AUTHORED path: a pack's `sandbox_profile(net = "host")` stage, CHECKed
/// under `oci` against the node's installed `egress_allow`, assembled to
/// `CapsuleNetwork::Egress` over exactly that set, authorized, read out of the
/// durable command frame, and driven on real youki. The one substituted edge is
/// the upstream dial (`loopback_dial`, the same seam `egress_oci_live` uses —
/// `connect_checked` refuses every local address class by design, so a live
/// cell's upstream can only be loopback). The CONNECT parse, the allowlist,
/// the 200/403 answers, the handed-over fd and the refusal record are all the
/// production proxy's.
///
/// # What is asserted against something that does not share the code under test
///
/// * the tunnel's bytes are the LOOPBACK echo's derived answer — `KATA-PONG:`
///   prefixed by a listener kata does not run inside;
/// * the refusal is read off the completion's `egress_refusals` (the proxy's
///   own record, shipped on the frame) and then off the durable
///   `execution_evidence` row the accepting transaction wrote — raw sqlite,
///   second handle;
/// * `youki list` against the provider state root says the runtime holds no
///   container.
#[test]
#[ignore = "HOST-DEPENDENT for its siblings' reasons (pinned youki, its INSTALLED \
            AppArmor profile, a delegated user scope, a nix daemon, the fixture closure's store \
            path realised) AND instrument-dependent (`cargo build -p kata-provider-youki -p \
            kata-oci-hook`). Run it with `cargo build -p kata-provider-youki -p kata-oci-hook && \
            cargo nextest run -p kata-workflow -P live-smoke -E 'binary(oci_stage_live)' \
            --run-ignored all`."]
fn a_host_net_shell_stage_reaches_only_the_declared_allowlist_live() {
    delegated(
        "a_host_net_shell_stage_reaches_only_the_declared_allowlist_live",
        a_host_net_egress_body(),
    );
}

async fn a_host_net_egress_body() {
    let test = "a_host_net_shell_stage_reaches_only_the_declared_allowlist_live";
    let planes = planes();
    let unseal = kata_worker::UnsealOnDrop::new(planes.dir.path());
    let certification = certify_youki(YoukiPin::embedded()).unwrap_or_else(|refusal| {
        panic!(
            "{test}: this host cannot deliver the rootless-OCI prerequisite ({token}): {refusal}. \
             Run `sudo kata host apparmor-install` as root.",
            token = refusal.token(),
        )
    });

    // THE UPSTREAM — a loopback listener that answers the guest's KATA-PING
    // with the DERIVED KATA-PONG:KATA-PING: a pipe that echoed the request
    // itself could not produce the prefix.
    let upstream = tokio::net::TcpListener::bind(("127.0.0.1", 0))
        .await
        .expect("the upstream binds");
    let port = upstream.local_addr().expect("its port").port();
    let server = tokio::spawn(async move {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let (mut socket, _) = upstream.accept().await.expect("one accepted tunnel");
        let mut buf = vec![0_u8; 64];
        let n = tokio::time::timeout(std::time::Duration::from_secs(20), socket.read(&mut buf))
            .await
            .expect("the upstream read inside the tunnel's idle window")
            .expect("a read");
        assert_eq!(
            &buf[..n],
            b"KATA-PING",
            "the upstream saw the guest's bytes"
        );
        socket
            .write_all(b"KATA-PONG:KATA-PING")
            .await
            .expect("the derived answer writes back");
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    });

    // THE NODE FACTS — `oci` profile and exactly one declared authority, the
    // upstream's `host:port`: the CHECK door opens on the installed set, and
    // the capsule mints it verbatim.
    kata_types::node_profile::mark_node_installed();
    kata_types::node_profile::install_node_egress_allow(std::collections::BTreeSet::from([
        EgressAuthority::from_authority_str(&format!("upstream.test:{port}"))
            .expect("an authority parses"),
    ]));

    // The MAIN's side — submit, declare the environment, publish the canonical
    // empty tree (the scratch /work's only artifact — there is no head), then
    // compile the authored pack THROUGH CHECK: the installed `egress_allow` is
    // what admits `net = "host"`.
    let execution_id = ulid::Ulid::new();
    let program_hash = kata_types::primitives::ContentHash::new([0xe5; 32]);
    assert!(matches!(
        planes
            .db
            .submit_execution(
                execution_id,
                &kata_core::ProgramRecord {
                    program_hash,
                    schema_version: 4,
                    program_json: b"{\"program\":1}".to_vec(),
                },
                &slice_invocation(),
            )
            .expect("the execution admits"),
        kata_core::SubmitOutcome::Submitted { .. }
    ));
    let (environment_id, _environment) = declare_busybox_environment(&planes);
    planes
        .db
        .promote_environment_root(environment_id.0.0, chrono::Utc::now().timestamp_millis())
        .expect("the declared closure's root promotes");
    kata_core::work_tree::declare_empty_tree(&planes.db, &planes.cas, execution_id)
        .expect("the canonical empty tree declares");

    let program = compile_starlark_execution_program(EGRESS_PACK, "oci-egress-live.star", &[])
        .expect("the egress pack CHECKs under `oci` — egress_allow is declared");
    let stage_id = StageId(SmolStr::new("probe"));
    let stage = program
        .stages
        .iter()
        .find(|(id, _)| *id == &stage_id)
        .map(|(_, stage)| stage)
        .expect("the probe stage is present");
    let lowered = lower_stage_operation(&program, &stage_id).expect("the probe stage lowers");
    let occurrence = kata_types::execution_contract::OccurrenceRef::new(
        kata_types::workflow::ExecutionId(execution_id),
        program_hash,
        lowered.contract.id(),
        lowered.path.clone(),
    );

    // The guest script: CONNECT the ALLOWLISTED authority (the seam dials the
    // loopback echo), then CONNECT a host the allowlist does not name — the
    // proxy's 403 and its refusal record are the second half of the proof.
    let script = format!(
        "{{ printf 'CONNECT upstream.test:{port} HTTP/1.1\\r\\n\\r\\n'; sleep 1; \
         printf 'KATA-PING'; sleep 2; }} | nc -w 6 127.0.0.1 19200 > /out/proxy.out \
         2>/out/proxy.err; \
         {{ printf 'CONNECT disallowed.test:443 HTTP/1.1\\r\\n\\r\\n'; sleep 1; }} | \
         nc -w 4 127.0.0.1 19200 > /out/refused.out 2>/out/refused.err; true",
    );
    let mut directive = directive();
    directive.fs = FsPolicy::Scratch;
    directive.net = NetPolicy::Host;
    let (prepared, capsule) = assemble_capsule(
        &lowered,
        occurrence.id(),
        stage,
        &directive,
        &RenderedCommand::rendered(script),
        environment_id,
        PlatformRef::new(
            "x86_64-linux",
            FixedBytes(*blake3::hash(b"egress-platform").as_bytes()),
        )
        .id(),
        empty_tree_artifact()
            .expect("the canonical empty tree")
            .id(),
        NodeBudgetDefaults {
            memory_bytes: 512 * 1024 * 1024,
            process_count: 64,
        },
        None,
        None,
    )
    .expect("the egress capsule assembles");
    // THE AUTHORED-PATH CLAIM: the capsule's only route out is `Egress` over
    // EXACTLY the installed `[node] egress_allow` — minted into the capsule's
    // identity, not conferred at launch.
    assert_eq!(
        capsule.network(),
        &CapsuleNetwork::Egress {
            allowlist: std::collections::BTreeSet::from([EgressAuthority::from_authority_str(
                &format!("upstream.test:{port}")
            )
            .unwrap(),]),
        },
        "{test}: the authored `net = \"host\"` mints the node's declared set verbatim"
    );

    let authorized = kata_workflow::authorization::authorize_attempt(
        &planes.db,
        &planes.cas,
        kata_workflow::authorization::AuthorizeInput {
            execution: kata_types::workflow::ExecutionId(execution_id),
            program_hash,
            lowered: &lowered,
            occurrence: occurrence.clone(),
            prepared,
            capsule: capsule.clone(),
            environment: environment_id,
            work_head: None,
            programs: &kata_workflow::authorization::HostProgramProbe,
            checked_stage: stage,
            place: &|| Ok(CAPSULE_WORKER.into()),
            approval_bypass_reason: None,
        },
    )
    .unwrap_or_else(|error| panic!("{test}: the authorization refused: {error}"))
    .dispatched()
    .unwrap_or_else(|| panic!("{test}: an ungated stage dispatches"));
    let mut frame = command_capsule_frame(&planes.op_path);
    assert_eq!(frame.attempt_id, authorized.attempt_id);
    frame.lease_epoch = authorized.lease_epoch;
    frame.placed_on = SmolStr::new(CAPSULE_WORKER);

    // The WORKER's side — the egress provider (hook + ip members), the dial
    // seam, the production resolvers.
    let installation = install_egress_provider(planes.dir.path());
    let worker_state = planes.dir.path().join("worker-state");
    let driver = OciStageDriver::new(
        OciRoute::new(certification.clone()),
        &worker_state,
        installation,
    )
    .with_upstream_dial(loopback_dial);
    let planes_index = kata_worker::plane_index::LocalPlaneIndex::open(&planes.data_dir)
        .expect("the worker opens the node's planes read-only");
    let reported = {
        let sink = kata_worker::result_publication::CasBlobSink(&planes.cas);
        kata_worker::capsule_execution::execute_capsule_frame(
            &kata_worker::capsule_execution::CapsuleExecution {
                driver: &driver,
                environments: &planes_index,
                trees: &planes_index,
                source: &planes_index,
                probe: &LocalStorePathProbe,
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
        .unwrap_or_else(|error| panic!("{test}: the capsule execution refused: {error}"))
    };
    let kata_transport::types::WorkerMessage::CompletedCapsule {
        attempt_id,
        result,
        work_delta,
        exit_code,
        stdout,
        stderr,
        capture_exceeded,
        egress_refusals,
        ..
    } = reported
    else {
        panic!("{test}: a capsule execution reports the capsule terminal and nothing else");
    };
    assert_eq!(attempt_id, authorized.attempt_id);
    assert_eq!(
        exit_code,
        Some(0),
        "{test}: the guest script ran to its end"
    );
    assert!(!capture_exceeded);

    // THE PROXY'S OWN RECORD — the refusal rides the completion frame, and its
    // KIND is the allowlist's answer rather than a dial error.
    assert!(
        egress_refusals.iter().any(|refusal| {
            refusal.kind == kata_types::egress_refusal::EgressRefusalKind::HostNotAllowed
                && refusal.authority == "disallowed.test"
                && refusal.port == 443
        }),
        "{test}: the proxy recorded `host_not_allowed` for the unlisted authority, verbatim: \
         {egress_refusals:?}"
    );

    // THE GUEST-SIDE ANSWERS, read out of the adopted result tree's CAS
    // bytes — the 200 the proxy produced and the echo's derived PONG for the
    // allowlisted connect, the 403 for the refused one.
    let attempt = planes
        .db
        .attempt(authorized.attempt_id)
        .expect("the attempts row is readable")
        .expect("the authorization wrote it");
    let (adopted, verdict) = planes
        .db
        .adopt_and_accept_capsule_completion(
            &kata_core::operational::CapsuleResultAdoption {
                execution_id,
                occurrence_id: occurrence.id(),
                result: result.clone(),
                stdout: stdout.clone(),
                stderr: stderr.clone(),
                work_delta,
                capture_exceeded,
                agent: None,
                egress_refusals: egress_refusals.clone(),
            },
            |adopted| kata_core::operational::WorkerCompletionInput {
                execution_id,
                attempt_id: authorized.attempt_id,
                attempt_ordinal: attempt.attempt_ordinal,
                lease_epoch: authorized.lease_epoch,
                worker_id: CAPSULE_WORKER.to_owned(),
                output: kata_core::operational::capsule_result_output(
                    adopted,
                    &result,
                    exit_code,
                    &stdout,
                    &stderr,
                    capture_exceeded,
                    Some(kata_workflow::test_harness::oci_rig_executor_term().digest()),
                ),
            },
        )
        .unwrap_or_else(|error| panic!("{test}: the main refused the result tree: {error}"));
    assert!(
        matches!(
            verdict,
            kata_core::operational::CompletionVerdict::Accepted { .. }
        ),
        "{test}: the completion accepts: {verdict:?}"
    );
    let member_text = |name: &str| {
        let member = adopted
            .manifest
            .entries()
            .iter()
            .find(|entry| entry.path.as_str() == name)
            .unwrap_or_else(|| panic!("{test}: /out/{name} is in the adopted result"));
        let TreeNode::File {
            object, size_bytes, ..
        } = &member.node
        else {
            panic!("{test}: /out/{name} is a file")
        };
        String::from_utf8(
            planes
                .cas
                .get_verified(object, *size_bytes, 1 << 16)
                .expect("the member reads back verified"),
        )
        .expect("the member is UTF-8")
    };
    let allowed = member_text("proxy.out");
    assert!(
        allowed.contains("200") && allowed.contains("KATA-PONG:KATA-PING"),
        "{test}: the allowlisted CONNECT got the proxy's 200 AND the loopback echo's derived \
         answer — bytes no mis-wired pipe produces: {allowed:?}"
    );
    let refused = member_text("refused.out");
    assert!(
        refused.contains("403"),
        "{test}: the unlisted CONNECT was answered 403 by the proxy: {refused:?}"
    );

    // THE DURABLE EVIDENCE — the accepting transaction's `execution_evidence`
    // row, read off a SECOND raw handle: the proxy's record is durable, not a
    // log line.
    let conn = rusqlite::Connection::open_with_flags(
        &planes.op_path,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .expect("a second raw handle onto operational.db");
    let evidence_json: String = conn
        .query_row(
            "SELECT CAST(evidence_json AS TEXT) FROM execution_evidence WHERE execution_id = ?1",
            [execution_id.to_bytes().as_slice()],
            |row| row.get(0),
        )
        .expect("exactly one evidence row — the refusal record");
    assert!(
        evidence_json.contains("host_not_allowed") && evidence_json.contains("disallowed.test"),
        "{test}: the durable evidence names the proxy's refusal and its authority: {evidence_json}"
    );
    server.await.expect("the upstream saw its read");
    drop(unseal);
}

// ---------------------------------------------------------------------------
// `workspace = "scratch"`, live
// ---------------------------------------------------------------------------

/// The pack this cell compiles: a shell stage authored `workspace = "scratch"`
/// — the confined writable-root spelling whose guest writes are evidence,
/// never a durable mutation.
const SCRATCH_PACK: &str = "probe = stage(\n\
     \x20   id = \"probe\",\n\
     \x20   agent = \"shell\",\n\
     \x20   sandbox = \"sc\",\n\
     \x20   timeout_ms = 30000,\n\
     \x20   prompt = \"true\",\n\
     )\n\
     workflow(\n\
     \x20   \"oci-scratch-live\",\n\
     \x20   root = [probe],\n\
     \x20   sandbox_profiles = {\"sc\": sandbox_profile(workspace = \"scratch\", net = \"offline\")},\n\
     )\n";

/// The guest's marker, written inside the container's ephemeral `/work`.
const SCRATCH_MARKER: &str = "scratch-evidence\n";

/// **A `workspace = "scratch"` capsule's guest writes into a writable `/work`
/// — and the bytes land NOWHERE durable: the delta rides the completion as
/// EVIDENCE (`scratch_delta_*`), the execution records no `/work` head, and
/// the apply sweep never schedules it.** Live, on real youki, through the
/// same authorized frame the workspace cell drives.
///
/// # What is asserted against something that does not share the code under test
///
/// * the WRITE happened inside the container: the published delta artifact —
///   decoded out of CAS by its own reference — names `scratch-marker.txt`
///   with the payload only the guest's `echo` could have produced;
/// * the write landed nowhere durable: `execution_work_tree_heads` holds NO
///   row for this execution — raw sqlite, second handle — and
///   `pending_work_apply_for_stage` answers `false` because the accepted
///   outcome carries `scratch_delta_*`, not `work_delta_*`;
/// * the adopted result's disposition is `Scratch`, read off the adoption's
///   own record.
///
/// **Would red if:** the adoption bound the delta under `work_delta_*` (the
/// sweep would answer `true`), or the capsule mapped the execution's head
/// instead of the canonical empty tree (the role check would have refused
/// `work_tree_not_role_bound` before the container ran).
#[test]
#[ignore = "HOST-DEPENDENT for its siblings' reasons (pinned youki, its INSTALLED \
            AppArmor profile, a delegated user scope, a nix daemon, the fixture closure's store \
            path realised) AND instrument-dependent (`cargo build -p kata-provider-youki`). Run it \
            with `cargo build -p kata-provider-youki --bin kata-provider-youki && cargo nextest \
            run -p kata-workflow -P live-smoke -E 'binary(oci_stage_live)' --run-ignored all`."]
fn a_scratch_work_writes_nowhere_durable_and_the_delta_is_evidence_live() {
    delegated(
        "a_scratch_work_writes_nowhere_durable_and_the_delta_is_evidence_live",
        a_scratch_work_body(),
    );
}

async fn a_scratch_work_body() {
    let test = "a_scratch_work_writes_nowhere_durable_and_the_delta_is_evidence_live";
    let planes = planes();
    let unseal = kata_worker::UnsealOnDrop::new(planes.dir.path());
    let certification = certify_youki(YoukiPin::embedded()).unwrap_or_else(|refusal| {
        panic!(
            "{test}: this host cannot deliver the rootless-OCI prerequisite ({token}): {refusal}. \
             Run `sudo kata host apparmor-install` as root.",
            token = refusal.token(),
        )
    });
    kata_types::node_profile::mark_node_installed();

    let execution_id = ulid::Ulid::new();
    let program_hash = kata_types::primitives::ContentHash::new([0x5c; 32]);
    assert!(matches!(
        planes
            .db
            .submit_execution(
                execution_id,
                &kata_core::ProgramRecord {
                    program_hash,
                    schema_version: 4,
                    program_json: b"{\"program\":1}".to_vec(),
                },
                &slice_invocation(),
            )
            .expect("the execution admits"),
        kata_core::SubmitOutcome::Submitted { .. }
    ));
    let (environment_id, _environment) = declare_busybox_environment(&planes);
    planes
        .db
        .promote_environment_root(environment_id.0.0, chrono::Utc::now().timestamp_millis())
        .expect("the declared closure's root promotes");
    // The scratch /work's ONE artifact — declared (its CAS object is what the
    // worker's plane index resolves), never a HEAD row: a scratch stage has
    // no durable workspace to advance.
    let empty = kata_core::work_tree::declare_empty_tree(&planes.db, &planes.cas, execution_id)
        .expect("the canonical empty tree declares");

    let program = compile_starlark_execution_program(SCRATCH_PACK, "oci-scratch-live.star", &[])
        .expect("the scratch pack CHECKs under `oci` — the /work door's Scratch arm admits");
    let stage_id = StageId(SmolStr::new("probe"));
    let stage = program
        .stages
        .iter()
        .find(|(id, _)| *id == &stage_id)
        .map(|(_, stage)| stage)
        .expect("the probe stage is present");
    let lowered = lower_stage_operation(&program, &stage_id).expect("the probe stage lowers");
    let occurrence = kata_types::execution_contract::OccurrenceRef::new(
        kata_types::workflow::ExecutionId(execution_id),
        program_hash,
        lowered.contract.id(),
        lowered.path.clone(),
    );

    let mut directive = directive();
    directive.fs = FsPolicy::Scratch;
    let (prepared, capsule) = assemble_capsule(
        &lowered,
        occurrence.id(),
        stage,
        &directive,
        &RenderedCommand::rendered(format!(
            "printf '{SCRATCH_MARKER}' > /work/scratch-marker.txt; \
             printf 'hi\\n' > /out/hi; cat /work/scratch-marker.txt"
        )),
        environment_id,
        PlatformRef::new(
            "x86_64-linux",
            FixedBytes(*blake3::hash(b"scratch-platform").as_bytes()),
        )
        .id(),
        empty.id(),
        NodeBudgetDefaults {
            memory_bytes: 512 * 1024 * 1024,
            process_count: 64,
        },
        None,
        None,
    )
    .expect("the scratch capsule assembles");
    // The /work claim, before any container runs: the canonical empty tree,
    // `ReadWriteScratch` — the access tag every main-side door keys on.
    let work = capsule
        .inputs()
        .iter()
        .find(|mapping| mapping.guest_path.as_str() == "/work")
        .expect("/work is mapped");
    assert_eq!(
        work.access,
        kata_types::execution_contract::GuestAccess::ReadWriteScratch,
        "{test}: a scratch /work carries its own access tag"
    );
    assert_eq!(
        work.artifact,
        empty.id(),
        "{test}: a scratch /work IS the canonical empty tree"
    );

    let authorized = kata_workflow::authorization::authorize_attempt(
        &planes.db,
        &planes.cas,
        kata_workflow::authorization::AuthorizeInput {
            execution: kata_types::workflow::ExecutionId(execution_id),
            program_hash,
            lowered: &lowered,
            occurrence: occurrence.clone(),
            prepared,
            capsule: capsule.clone(),
            environment: environment_id,
            work_head: None,
            programs: &kata_workflow::authorization::HostProgramProbe,
            checked_stage: stage,
            place: &|| Ok(CAPSULE_WORKER.into()),
            approval_bypass_reason: None,
        },
    )
    .unwrap_or_else(|error| panic!("{test}: the authorization refused: {error}"))
    .dispatched()
    .unwrap_or_else(|| panic!("{test}: an ungated stage dispatches"));
    let mut frame = command_capsule_frame(&planes.op_path);
    frame.lease_epoch = authorized.lease_epoch;
    frame.placed_on = SmolStr::new(CAPSULE_WORKER);

    let installation = install_provider(planes.dir.path());
    let worker_state = planes.dir.path().join("worker-state");
    let driver = OciStageDriver::new(
        OciRoute::new(certification.clone()),
        &worker_state,
        installation,
    );
    let planes_index = kata_worker::plane_index::LocalPlaneIndex::open(&planes.data_dir)
        .expect("the worker opens the node's planes read-only");
    let reported = {
        let sink = kata_worker::result_publication::CasBlobSink(&planes.cas);
        kata_worker::capsule_execution::execute_capsule_frame(
            &kata_worker::capsule_execution::CapsuleExecution {
                driver: &driver,
                environments: &planes_index,
                trees: &planes_index,
                source: &planes_index,
                probe: &LocalStorePathProbe,
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
        .unwrap_or_else(|error| panic!("{test}: the capsule execution refused: {error}"))
    };
    let kata_transport::types::WorkerMessage::CompletedCapsule {
        attempt_id,
        result,
        work_delta,
        exit_code,
        stdout,
        stderr,
        capture_exceeded,
        ..
    } = reported
    else {
        panic!("{test}: a capsule execution reports the capsule terminal and nothing else");
    };
    assert_eq!(attempt_id, authorized.attempt_id);
    assert_eq!(
        exit_code,
        Some(0),
        "{test}: the guest script ran to its end"
    );
    assert!(!capture_exceeded);
    // The DELTA rides the completion — the write it records is real evidence,
    // present BECAUSE the scratch /work is writable.
    let delta = work_delta.expect("{test}: a writable scratch /work reports its delta");

    let attempt = planes
        .db
        .attempt(authorized.attempt_id)
        .expect("the attempts row is readable")
        .expect("the authorization wrote it");
    let (adopted, verdict) = planes
        .db
        .adopt_and_accept_capsule_completion(
            &kata_core::operational::CapsuleResultAdoption {
                execution_id,
                occurrence_id: occurrence.id(),
                result: result.clone(),
                stdout: stdout.clone(),
                stderr: stderr.clone(),
                work_delta: Some(delta.clone()),
                capture_exceeded,
                agent: None,
                egress_refusals: vec![],
            },
            |adopted| kata_core::operational::WorkerCompletionInput {
                execution_id,
                attempt_id: authorized.attempt_id,
                attempt_ordinal: attempt.attempt_ordinal,
                lease_epoch: authorized.lease_epoch,
                worker_id: CAPSULE_WORKER.to_owned(),
                output: kata_core::operational::capsule_result_output(
                    adopted,
                    &result,
                    exit_code,
                    &stdout,
                    &stderr,
                    capture_exceeded,
                    Some(kata_workflow::test_harness::oci_rig_executor_term().digest()),
                ),
            },
        )
        .unwrap_or_else(|error| panic!("{test}: the main refused the result tree: {error}"));
    assert!(
        matches!(
            verdict,
            kata_core::operational::CompletionVerdict::Accepted { .. }
        ),
        "{test}: the completion accepts: {verdict:?}"
    );

    // THE DISPOSITION — evidence, not a workspace mutation.
    let adopted_delta = adopted
        .work_delta
        .as_ref()
        .expect("{test}: the adopted result carries the delta it verified");
    assert_eq!(
        adopted_delta.disposition,
        kata_core::operational::WorkDeltaDisposition::Scratch,
        "{test}: the scratch /work binds its delta as scratch evidence"
    );
    let output = kata_core::operational::capsule_result_output(
        &adopted,
        &result,
        exit_code,
        &stdout,
        &stderr,
        capture_exceeded,
        Some(kata_workflow::test_harness::oci_rig_executor_term().digest()),
    );
    assert!(
        output["scratch_delta_artifact_id"].is_string()
            && output["work_delta_artifact_id"].is_null(),
        "{test}: the accepted outcome records `scratch_delta_*`, never `work_delta_*`: {output}"
    );

    // THE WRITE, proven from the delta's own bytes — decoded out of CAS at
    // the completion's reference, naming the marker the guest wrote.
    let delta_bytes = planes
        .cas
        .get_verified(
            &delta.object_id(),
            delta.size_bytes(),
            delta.size_bytes().max(1 << 20),
        )
        .expect("the published delta reads back verified");
    let delta_decoded: kata_types::tree_delta::TreeDelta =
        serde_json::from_slice(&delta_bytes).expect("the delta decodes");
    assert!(
        delta_decoded.changes().iter().any(|change| {
            change.path.as_str() == "scratch-marker.txt"
                && matches!(
                    change.change,
                    kata_types::tree_delta::TreeChangeKind::Write { .. }
                )
        }),
        "{test}: the delta names the guest's write — the container really ran with a writable \
         scratch /work: {:?}",
        delta_decoded.changes()
    );

    // NOWHERE DURABLE — the execution's head table stays empty (a scratch
    // stage has no head to advance) and the apply sweep answers `false`,
    // both off the durable rows.
    let conn = rusqlite::Connection::open_with_flags(
        &planes.op_path,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .expect("a second raw handle onto operational.db");
    let heads: i64 = conn
        .query_row(
            "SELECT count(*) FROM execution_work_tree_heads WHERE execution_id = ?1",
            [execution_id.to_bytes().as_slice()],
            |row| row.get(0),
        )
        .expect("the head table is readable");
    assert_eq!(
        heads, 0,
        "{test}: a scratch stage's execution records no /work head — there is no durable tree \
         the delta could have landed on"
    );
    assert!(
        !planes
            .db
            .pending_work_apply_for_stage(execution_id, "probe")
            .unwrap(),
        "{test}: the apply sweep never schedules a scratch delta"
    );
    drop(unseal);
}

/// **A `reads=`-confined stage sees exactly its declared closure under `oci` —
/// enforced at MATERIALIZATION, and the rest of the head is never a deletion.**
/// The head carries `src/a.txt` AND `docs/b.md`; the stage declares
/// `reads = ["src"]` and `produces_files = ["src/out.txt"]`. The guest itself
/// runs `! test -e /work/docs/b.md && cat /work/src/a.txt > /work/src/out.txt`
/// — a leaked `docs/` would fail the guest's own check, and a lost `src/`
/// would fail the cat. Afterwards the published delta, read back out of the
/// CAS and applied to the published base OUTSIDE kata, is exactly
/// `{src/a.txt, docs/b.md, src/out.txt}` with `docs/b.md`'s node untouched —
/// an unmaterialized base member is UNCHANGED, never a delete. The twin —
/// the same confined stage running `cat /work/docs/b.md` — must exit
/// non-zero: the file is not there to read.
///
/// **Would red if:** the materializer ignored the view (`docs/b.md` exists in
/// the container and `test -e` fails), the delta folded an unmaterialized
/// member as deleted (`docs/b.md` vanishes from the applied head), or the
/// confinement were advisory (`cat /work/docs/b.md` exits 0).
#[test]
#[ignore = "HOST-DEPENDENT like its siblings (pinned youki with its INSTALLED AppArmor profile, a \
            delegated user scope, the busybox closure realised) and instrument-dependent (`cargo \
            build -p kata-provider-youki --bin kata-provider-youki`). Run with `cargo nextest run \
            -p kata-workflow -P live-smoke -E 'binary(oci_stage_live)' --run-ignored all`."]
fn a_confined_stage_reads_only_its_declared_view_live() {
    delegated(
        "a_confined_stage_reads_only_its_declared_view_live",
        a_confined_stage_reads_only_body(),
    );
}

async fn a_confined_stage_reads_only_body() {
    let test = "a_confined_stage_reads_only_its_declared_view_live";
    let planes = planes();
    let unseal = kata_worker::UnsealOnDrop::new(planes.dir.path());
    let certification = certify_youki(YoukiPin::embedded()).unwrap_or_else(|refusal| {
        panic!(
            "{test}: this host cannot deliver the rootless-OCI prerequisite ({token}): {refusal}",
            token = refusal.token(),
        )
    });

    // THE BASE — two members, one inside the declared closure and one outside
    // it, held by the rig's own CAS. The manifest is kept beside the
    // reference: it is the outside-kata statement of the base the delta is
    // applied to below.
    let member_a = planes
        .cas
        .put_durable(b"alpha payload\n")
        .expect("the covered member publishes");
    let member_b = planes
        .cas
        .put_durable(b"beta payload\n")
        .expect("the confined member publishes");
    let base_manifest = TreeManifest::new(vec![
        TreeEntry {
            path: TreePath::new("src/a.txt").expect("an accepted tree path"),
            node: TreeNode::File {
                mode: TreeEntryMode::Regular,
                object: member_a.object_id(),
                size_bytes: member_a.size(),
            },
        },
        TreeEntry {
            path: TreePath::new("docs/b.md").expect("an accepted tree path"),
            node: TreeNode::File {
                mode: TreeEntryMode::Regular,
                object: member_b.object_id(),
                size_bytes: member_b.size(),
            },
        },
    ])
    .expect("a valid manifest");
    let base_bytes = base_manifest
        .manifest_bytes()
        .expect("the manifest serializes");
    let base_receipt = planes
        .cas
        .put_durable(&base_bytes)
        .expect("the base manifest publishes");
    let (environment_id, _environment) = declare_busybox_environment(&planes);

    // THE PACK — a deterministic shell stage confined to `reads = ["src"]`
    // with `src/out.txt` declared writable. `produces_files` keeps the delta
    // fence honest: an out-of-closure WRITE would be the observed path it
    // refuses.
    const CONFINED_PACK: &str = "probe = stage(\n\
         \x20   id = \"probe\",\n\
         \x20   agent = \"shell\",\n\
         \x20   sandbox = \"iso\",\n\
         \x20   reads = [\"src\"],\n\
         \x20   produces_files = [\"src/out.txt\"],\n\
         \x20   timeout_ms = 30000,\n\
         \x20   prompt = \"true\",\n\
         )\n\
         workflow(\n\
         \x20   \"oci-confined-live\",\n\
         \x20   root = [probe],\n\
         \x20   sandbox_profiles = {\"iso\": sandbox_profile(workspace = \"rw\", net = \"offline\")},\n\
         )\n";
    let program = compile_starlark_execution_program(CONFINED_PACK, "confined.star", &[])
        .expect("the confined pack compiles");
    let stage_id = StageId(SmolStr::new("probe"));
    let stage = program
        .stages
        .iter()
        .find(|(id, _)| *id == &stage_id)
        .map(|(_, stage)| stage)
        .expect("the probe stage is present");
    let lowered = lower_stage_operation(&program, &stage_id).expect("the probe stage lowers");

    let installation = install_provider(planes.dir.path());
    let worker_state = planes.dir.path().join("worker-state");
    let driver = OciStageDriver::new(
        OciRoute::new(certification.clone()),
        &worker_state,
        installation,
    );
    let planes_index = kata_worker::plane_index::LocalPlaneIndex::open(&planes.data_dir)
        .expect("the worker opens the node's planes read-only");

    // THE FIRST DRIVE — the confined stage writes its declared output, having
    // proven docs/ absent and src/ present through the guest's own test.
    let execution_id = ulid::Ulid::new();
    let program_hash = kata_types::primitives::ContentHash::new([0x5Au8; 32]);
    planes
        .db
        .submit_execution(
            execution_id,
            &kata_core::ProgramRecord {
                program_hash,
                schema_version: 4,
                program_json: b"{\"program\":1}".to_vec(),
            },
            &slice_invocation(),
        )
        .expect("the execution admits");
    // The DECLARED reference is the capsule's `/work` — its privacy is
    // `declare_work_tree`'s own answer, not a spelling this rig invents.
    let head_ref = kata_core::work_tree::declare_work_tree(
        &planes.db,
        &planes.cas,
        execution_id,
        &base_manifest,
        &base_receipt,
    )
    .expect("the base manifest declares for the execution");
    kata_core::work_tree::declare_empty_tree(&planes.db, &planes.cas, execution_id)
        .expect("the /out and /tmp empty tree declares");
    let head = planes
        .db
        .record_work_tree_head(execution_id, "", head_ref.id().0.0, "")
        .expect("the head row records");
    let occurrence = kata_types::execution_contract::OccurrenceRef::new(
        kata_types::workflow::ExecutionId(execution_id),
        program_hash,
        lowered.contract.id(),
        lowered.path.clone(),
    );
    let (prepared, capsule) = assemble_capsule(
        &lowered,
        occurrence.id(),
        stage,
        &directive(),
        &RenderedCommand::rendered(
            "test ! -e /work/docs/b.md && cat /work/src/a.txt > /work/src/out.txt".to_owned(),
        ),
        environment_id,
        PlatformRef::new(
            "x86_64-linux",
            FixedBytes(*blake3::hash(b"confined-platform").as_bytes()),
        )
        .id(),
        head_ref.id(),
        NodeBudgetDefaults {
            memory_bytes: 512 * 1024 * 1024,
            process_count: 64,
        },
        None,
        None,
    )
    .expect("the confined capsule assembles");
    let view = capsule
        .work_view()
        .expect("a confined stage's capsule carries the work view");
    assert_eq!(
        view.include,
        [
            smol_str::SmolStr::new("src"),
            smol_str::SmolStr::new("src/out.txt")
        ],
        "{test}: the minted include is the declared union, mint-sorted"
    );

    let authorized = kata_workflow::authorization::authorize_attempt(
        &planes.db,
        &planes.cas,
        kata_workflow::authorization::AuthorizeInput {
            execution: kata_types::workflow::ExecutionId(execution_id),
            program_hash,
            lowered: &lowered,
            occurrence: occurrence.clone(),
            prepared,
            capsule: capsule.clone(),
            environment: environment_id,
            work_head: Some(&head),
            programs: &kata_workflow::authorization::HostProgramProbe,
            checked_stage: stage,
            place: &|| Ok(CAPSULE_WORKER.into()),
            approval_bypass_reason: None,
        },
    )
    .unwrap_or_else(|error| panic!("{test}: the authorization refused: {error}"))
    .dispatched()
    .unwrap_or_else(|| panic!("{test}: an ungated stage dispatches"));
    let mut frame = command_capsule_frame(&planes.op_path);
    assert_eq!(frame.attempt_id, authorized.attempt_id);
    assert_eq!(frame.capsule.id, capsule.id());
    frame.lease_epoch = authorized.lease_epoch;
    frame.placed_on = SmolStr::new(CAPSULE_WORKER);
    let reported = {
        let sink = kata_worker::result_publication::CasBlobSink(&planes.cas);
        kata_worker::capsule_execution::execute_capsule_frame(
            &kata_worker::capsule_execution::CapsuleExecution {
                driver: &driver,
                environments: &planes_index,
                trees: &planes_index,
                source: &planes_index,
                probe: &LocalStorePathProbe,
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
        .unwrap_or_else(|error| panic!("{test}: the capsule execution refused: {error}"))
    };
    let kata_transport::types::WorkerMessage::CompletedCapsule {
        attempt_id,
        work_delta,
        exit_code,
        stderr,
        ..
    } = reported
    else {
        panic!("{test}: a capsule execution reports the capsule terminal and nothing else");
    };
    assert_eq!(attempt_id, authorized.attempt_id);
    assert_eq!(
        exit_code,
        Some(0),
        "{test}: the guest's own confinement check must hold — `docs/` materialized and the \
         leak it is, or `src/` is missing and the cat failed.\nstderr: {}",
        String::from_utf8_lossy(
            &planes
                .cas
                .get_verified(
                    &stderr.object_id(),
                    stderr.size_bytes(),
                    stderr.size_bytes().max(1),
                )
                .unwrap_or_default()
        )
    );

    // THE LANDED HEAD, read outside kata: the published delta applied to the
    // published base. `docs/b.md` must be byte-identical — an unmaterialized
    // base member is UNCHANGED, never a delete — and `src/out.txt` must carry
    // `src/a.txt`'s bytes, because the guest's `cat` produced it.
    let work_delta = work_delta.expect("a /work-bearing capsule emits a delta");
    let delta_bytes = planes
        .cas
        .get_verified(
            &work_delta.object_id(),
            work_delta.size_bytes(),
            work_delta.size_bytes().max(1),
        )
        .expect("the delta artifact reads verified");
    let delta = serde_json::from_slice::<kata_types::tree_delta::TreeDelta>(&delta_bytes)
        .expect("the delta decodes");
    let landed = delta
        .apply(&base_manifest)
        .expect("the delta applies to the published base");
    let node_at = |path: &str| -> &TreeNode {
        &landed
            .entries()
            .iter()
            .find(|entry| entry.path.as_str() == path)
            .unwrap_or_else(|| panic!("{test}: {path} must land in the head"))
            .node
    };
    let paths: Vec<&str> = landed
        .entries()
        .iter()
        .map(|entry| entry.path.as_str())
        .collect();
    assert_eq!(
        paths,
        ["docs/b.md", "src/a.txt", "src/out.txt"],
        "{test}: the landed head is the base plus exactly the declared output"
    );
    assert_eq!(
        node_at("docs/b.md"),
        &TreeNode::File {
            mode: TreeEntryMode::Regular,
            object: member_b.object_id(),
            size_bytes: member_b.size(),
        },
        "{test}: an unmaterialized base member lands UNCHANGED, never a delete"
    );
    let TreeNode::File {
        object: out_object,
        size_bytes: out_size,
        ..
    } = node_at("src/out.txt")
    else {
        panic!("{test}: the declared output is a file member");
    };
    let out_bytes = planes
        .cas
        .get_verified(out_object, *out_size, (*out_size).max(1))
        .expect("the output member's bytes read verified");
    assert_eq!(
        out_bytes,
        planes
            .cas
            .get_verified(
                &member_a.object_id(),
                member_a.size(),
                member_a.size().max(1),
            )
            .unwrap()
            .as_slice(),
        "{test}: src/out.txt carries src/a.txt's bytes — the guest's cat produced it"
    );

    // THE TWIN — the same confined stage, and the read the container must
    // refuse: `cat /work/docs/b.md` exits non-zero because the file was never
    // materialized.
    let execution2 = ulid::Ulid::new();
    planes
        .db
        .submit_execution(
            execution2,
            &kata_core::ProgramRecord {
                program_hash,
                schema_version: 4,
                program_json: b"{\"program\":1}".to_vec(),
            },
            &slice_invocation(),
        )
        .expect("the twin execution admits");
    kata_core::work_tree::declare_work_tree(
        &planes.db,
        &planes.cas,
        execution2,
        &base_manifest,
        &base_receipt,
    )
    .expect("the base manifest declares for the twin");
    kata_core::work_tree::declare_empty_tree(&planes.db, &planes.cas, execution2)
        .expect("the twin /out and /tmp empty tree declares");
    let twin_head = planes
        .db
        .record_work_tree_head(execution2, "", head_ref.id().0.0, "")
        .expect("the twin head row records");
    let occurrence2 = kata_types::execution_contract::OccurrenceRef::new(
        kata_types::workflow::ExecutionId(execution2),
        program_hash,
        lowered.contract.id(),
        lowered.path.clone(),
    );
    let (prepared2, capsule2) = assemble_capsule(
        &lowered,
        occurrence2.id(),
        stage,
        &directive(),
        &RenderedCommand::rendered("cat /work/docs/b.md".to_owned()),
        environment_id,
        PlatformRef::new(
            "x86_64-linux",
            FixedBytes(*blake3::hash(b"confined-platform-twin").as_bytes()),
        )
        .id(),
        head_ref.id(),
        NodeBudgetDefaults {
            memory_bytes: 512 * 1024 * 1024,
            process_count: 64,
        },
        None,
        None,
    )
    .expect("the twin capsule assembles");
    let authorized2 = kata_workflow::authorization::authorize_attempt(
        &planes.db,
        &planes.cas,
        kata_workflow::authorization::AuthorizeInput {
            execution: kata_types::workflow::ExecutionId(execution2),
            program_hash,
            lowered: &lowered,
            occurrence: occurrence2.clone(),
            prepared: prepared2,
            capsule: capsule2.clone(),
            environment: environment_id,
            work_head: Some(&twin_head),
            programs: &kata_workflow::authorization::HostProgramProbe,
            checked_stage: stage,
            place: &|| Ok(CAPSULE_WORKER.into()),
            approval_bypass_reason: None,
        },
    )
    .unwrap_or_else(|error| panic!("{test}: the twin authorization refused: {error}"))
    .dispatched()
    .unwrap_or_else(|| panic!("{test}: an ungated stage dispatches"));
    let mut frame2 = command_capsule_frames(&planes.op_path)
        .into_iter()
        .find(|frame| frame.attempt_id == authorized2.attempt_id)
        .expect("the twin's dispatch is enqueued beside the first drive's");
    assert_eq!(frame2.capsule.id, capsule2.id());
    frame2.lease_epoch = authorized2.lease_epoch;
    frame2.placed_on = SmolStr::new(CAPSULE_WORKER);
    let reported2 = {
        let sink = kata_worker::result_publication::CasBlobSink(&planes.cas);
        kata_worker::capsule_execution::execute_capsule_frame(
            &kata_worker::capsule_execution::CapsuleExecution {
                driver: &driver,
                environments: &planes_index,
                trees: &planes_index,
                source: &planes_index,
                probe: &LocalStorePathProbe,
                sink: &sink,
                adapters: &*AGENT_ADAPTERS,
                credentials: &AMBIENT_CREDENTIALS,
            },
            &frame2,
            std::time::Instant::now(),
            tokio::sync::oneshot::channel().1,
            None,
        )
        .await
        .unwrap_or_else(|error| panic!("{test}: the twin capsule execution refused: {error}"))
    };
    let kata_transport::types::WorkerMessage::CompletedCapsule {
        exit_code: twin_exit,
        ..
    } = reported2
    else {
        panic!("{test}: the twin reports a capsule terminal");
    };
    assert_ne!(
        twin_exit,
        Some(0),
        "{test}: `cat /work/docs/b.md` must exit non-zero — the unmaterialized \
         member is not there to read"
    );
    println!("confined-view exit={exit_code:?} twin-exit={twin_exit:?} landed={paths:?}");
    drop(unseal);
}
