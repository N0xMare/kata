//! The ADVERSARIAL KERNEL SUITE on the rootless-OCI route.
//!
//! This file asks the attacker's question — the rows of the [`ATTACKS`] table
//! in `common::adversarial` — of a rootless OCI container `kata_worker::oci_driver`
//! planned, started through `kata-provider-youki`, and owns the cgroup of.
//!
//! # The probes are argv INSIDE a container
//!
//! There is no `CommandPrefix` here to re-host. On this route what a stage
//! may read is decided by a capsule's guest MAPPINGS and by the `config.json`
//! `oci_bundle::spec_for` renders from it — there is no `fs` policy enum, no
//! `--ro-bind` of a host path, and no host `$HOME`. Translating a prefix into a
//! capsule inside a test would invent a SECOND producer of this route's
//! mount set, which is exactly the defect consolidating `MATERIALIZED_ROOTS`
//! removed one plane over.
//!
//! `common::adversarial::COVERAGE` states one cell per (driver, attack) so the
//! coverage is auditable. Three rows are `NotExpressible` here and one (A1) is
//! `NotDemonstrable` on the reference host, each saying why in the table; the
//! other NINE run, and the FLOORS they must meet are this column's own — a
//! capsule declares guest mappings, not an fs policy.
//!
//! # The four rules, unchanged
//!
//! **1. Every containment assertion carries a NON-VACUITY CONTROL.**
//! [`Ledger::contained`] panics unless a [`Ledger::control`] for the same probe
//! already recorded that the attack SUCCEEDS with the relevant containment
//! relaxed. On this route "relaxed" has two honest forms and both are used:
//! for the rows whose containment IS a capsule declaration (A7's budgets, A9's
//! mappings) the control is ANOTHER CONTAINER RUN with that declaration widened,
//! so it is tagged `via=oci` and is a driver observation; for the rows whose
//! containment is the container itself (A1, A1', A3, A4, A8, A10) the only
//! counterfactual that is not a construction is the same busybox argv on the
//! HOST, tagged `via=host`.
//!
//! **2. The rig PRINTS its assertion count** — the `ADVERSARIAL-KERNEL-SUITE
//! attack=… containment-assertions=N` line, from the shared [`Ledger`], so a
//! log says how many assertions each row actually made.
//!
//! **3. A capability SKIP is a FAILURE.** There is no capability gate in this
//! file at all: `certify_youki` is called and a refusal PANICS naming the
//! refusal's own token — on a host whose AppArmor profile for the pinned youki is
//! missing or stale, `profile_file_differs`, whose recourse is `sudo python3 -B
//! kata host apparmor-install`. So a host that cannot certify
//! FAILS every row rather than skipping it.
//!
//! **4. The container must be shown to WORK before it is shown to refuse.** Every
//! row calls [`Rig::require_viable`] first, which runs `echo` in a container of
//! the same shape and requires the sentinel on stdout. Without it a driver that
//! failed to start anything would satisfy every containment assertion in this
//! file at once — the attack "failed" because nothing ran. That is the
//! anti-stub control, and it is why a broken rig reds here instead of certifying.

#![cfg(target_os = "linux")]

mod common;

use common::adversarial::{
    A1P_CONSTRUCTION_RESIDUE, A2_FS_ESCAPE, A3_PROCESS_MEMORY, A4_NET_EGRESS,
    A6_DESCENDANT_TEARDOWN, A7_DECLARED_BOUNDS, A8_NAMESPACE_IDENTITY, A9_UNDECLARED_WRITE,
    A10_CLEARED_ENV, DRIVER_SPAWNS, ExecutionDriver, Ledger, driver,
};
use common::static_probe;

use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::Output;
use std::sync::atomic::{AtomicUsize, Ordering};

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
use kata_types::youki_pin::YoukiPin;
use kata_worker::execution_route::{ExternalProviderAddress, OciRoute};
use kata_worker::materialize::{BlobSource, StorePathProbe, TreeResolver};
use kata_worker::oci_driver::{
    OCI_PROVIDER_NAME, OciProviderInstallation, OciStageDriver, OciStageRequest,
};
use kata_worker::oci_runtime::certify_youki;
use smol_str::SmolStr;

/// The same real store path every OCI live file in this workspace names. One
/// statically linked busybox IS the whole closure, which is what lets a capsule
/// here be a fixture rather than a nix build.
const BUSYBOX: &str =
    "/nix/store/qddzvnv6b0805nkvbqddbswddcfhx814-busybox-static-x86_64-unknown-linux-musl-1.37.0";
const BUSYBOX_NAR_HASH: &str = "sha256-d7JNm1d4Wo1oSA2pvoRLt1vqyAhSlIsjE0GckcLiSeA=";
const BUSYBOX_NAR_SIZE: u64 = 1_495_056;

/// The marker `Rig::require_viable` demands on stdout. Distinctive, so a match
/// cannot be something else's output.
const VIABLE: &str = "kata-oci-adversarial-viable";

/// The sentinel this rig's OWN process carries in its environment, set on the
/// delegated re-exec below.
///
/// A10 needs a variable that is genuinely in the spawning process's environment
/// and that nothing declared to the capsule. `std::env::set_var` is `unsafe` in a
/// multi-threaded process and this workspace denies `unsafe_code`, so the
/// variable is planted on the `systemd-run` child's `Command` — which is the
/// process every row actually runs in.
const ENV_SENTINEL_KEY: &str = "KATA_OCI_ADVERSARIAL_SECRET";
const ENV_SENTINEL_VALUE: &str = "a-secret-no-capsule-declared";

/// Re-exec marker for the delegated scope.
const INNER_ENV: &str = "KATA_OCI_ADVERSARIAL_DELEGATED_INNER";

/// One attempt tag per drive. The driver refuses a pre-existing attempt root by
/// name, which is right, so the rig mints a fresh one rather than reusing one.
static ATTEMPTS: AtomicUsize = AtomicUsize::new(0);

fn hash(byte: u8) -> ContentHash {
    ContentHash::new([byte; 32])
}

// ---------------------------------------------------------------------------
// The fixture planes
// ---------------------------------------------------------------------------

fn environment() -> NixEnvironmentManifest {
    NixEnvironmentManifest::new(
        "adversarial-busybox",
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

fn mapping(path: &str, artifact: u8, access: GuestAccess) -> GuestMapping {
    GuestMapping {
        artifact: ArtifactId(hash(artifact)),
        guest_path: GuestPath::new(path.to_owned()).expect("a guest path"),
        access,
    }
}

/// The three materializable roots. The environment closure is BOUND at its own
/// store paths by the runtime, so a `/nix/store` mapping is not a tree the
/// materializer places (it refuses one by name).
fn default_mappings() -> Vec<GuestMapping> {
    vec![
        mapping("/work", 20, GuestAccess::ReadWrite),
        mapping("/out", 21, GuestAccess::ReadWrite),
        mapping("/tmp", 22, GuestAccess::ReadWrite),
    ]
}

/// Budgets generous enough that no row trips one by accident. A7 narrows them on
/// purpose and says so at its own call site.
fn default_budgets() -> CapsuleBudgets {
    CapsuleBudgets {
        wall_time_ms: 60_000,
        output_bytes: 1 << 20,
        memory_bytes: 512 * 1024 * 1024,
        process_count: 64,
        result_bytes: 4 * 1024 * 1024,
        result_entries: 128,
        work_delta_bytes: kata_types::execution_contract::CAPSULE_WORK_DELTA_BYTES,
        work_delta_entries: kata_types::execution_contract::CAPSULE_WORK_DELTA_ENTRIES,
    }
}

/// Every mapped tree is EMPTY: these rows are about what a container can REACH,
/// and a file in `/work` would be a second thing to be wrong.
struct EmptyTrees;

impl TreeResolver for EmptyTrees {
    fn tree_manifest(&self, _artifact: ArtifactId) -> KataResult<TreeManifest> {
        TreeManifest::new(vec![])
    }

    fn tree_reference(
        &self,
        artifact: ArtifactId,
    ) -> KataResult<kata_types::execution_contract::ArtifactRef> {
        panic!(
            "the driver looked up the reference for tree artifact {artifact:?}. The fixture \
             resolves MANIFESTS for the materializer — nothing below execute_capsule_frame asks \
             for a reference"
        );
    }
}

/// Reached for no member, because every tree is empty. PANICS rather than
/// returning bytes, so a fixture that grew a member fails loudly instead of
/// materializing something this file never described.
struct BytesForbidden;

impl BlobSource for BytesForbidden {
    fn read_verified(
        &self,
        object: ObjectId,
        _expected: u64,
        _maximum: u64,
    ) -> KataResult<Vec<u8>> {
        panic!("no member's bytes should be read: every mapped tree here is empty ({object:?})")
    }
}

/// The real host's store, because the container rbinds the closure at its own
/// store path and a fabricated `true` here would bind a directory that is not
/// there.
struct RealStore;

impl StorePathProbe for RealStore {
    fn present(&self, path: &StorePath) -> KataResult<bool> {
        Ok(Path::new(path.as_str()).is_dir())
    }
}

// ---------------------------------------------------------------------------
// The rig
// ---------------------------------------------------------------------------

/// What one container run did, reduced to what these rows read.
struct Drive {
    exit_code: Option<i32>,
    stdout: String,
    stderr: String,
    attempt_root: PathBuf,
}

impl Drive {
    fn ok(&self) -> bool {
        self.exit_code == Some(0)
    }

    /// stdout and stderr together. Several probes print their verdict to one or
    /// the other depending on which busybox applet answered, and a row that
    /// scored only stdout would read a refusal as silence.
    fn text(&self) -> String {
        format!("{}{}", self.stdout, self.stderr)
    }
}

/// How one container run differs from the default shape.
struct Plan {
    mappings: Vec<GuestMapping>,
    budgets: CapsuleBudgets,
}

impl Default for Plan {
    fn default() -> Self {
        Self {
            mappings: default_mappings(),
            budgets: default_budgets(),
        }
    }
}

/// The node-scoped facts, built once per row.
struct Rig {
    dir: tempfile::TempDir,
    /// Un-seals the provisioned provider store so `TempDir::drop` can remove it.
    /// Declared after `dir` so it drops BEFORE it.
    _unseal: kata_worker::UnsealOnDrop,
    driver: OciStageDriver,
    environment: NixEnvironmentManifest,
}

impl Rig {
    /// Certify, provision, and build the production driver — or PANIC naming the
    /// prerequisite. There is no skip: see rule 3 in this file's header.
    fn build(test: &str) -> Self {
        assert!(
            Path::new(BUSYBOX).join("bin/busybox").is_file(),
            "{test}: the closure's only store object is not realised at {BUSYBOX}. Every probe \
             in this file execs a binary inside that exact path, so there is nothing to observe \
             without it. Realise it with `nix-store --realise {BUSYBOX}`."
        );
        let certification = certify_youki(YoukiPin::embedded()).unwrap_or_else(|refusal| {
            panic!(
                "{test}: this host cannot deliver the rootless-OCI prerequisite ({token}): \
                 {refusal}. For `profile_file_differs` — the AppArmor profile at \
                 `/etc/apparmor.d/youki` does not name the pinned store path — run `sudo \
                 kata host apparmor-install` as root. `just \
                 _containment-preconditions` gives the one-line diagnosis. This is a FAILURE \
                 and not a skip on purpose: a containment claim nobody measured must not read \
                 as green.",
                token = refusal.token(),
            )
        });
        let dir = tempfile::tempdir().expect("a temporary root for this row");
        let unseal = kata_worker::UnsealOnDrop::new(dir.path());
        let installation = install_provider(dir.path());
        let driver = OciStageDriver::new(
            OciRoute::new(certification),
            dir.path().join("worker-state"),
            installation,
        );
        Self {
            dir,
            _unseal: unseal,
            driver,
            environment: environment(),
        }
    }

    /// A host directory no capsule mapping names. The target of A2's read and
    /// A9's write, and read back from OUTSIDE with `std::fs` in both cases.
    fn host_only_dir(&self) -> PathBuf {
        let dir = self.dir.path().join("host-only");
        std::fs::create_dir_all(&dir).expect("the host-only directory");
        dir
    }

    /// Run `script` as `busybox sh -c` inside a real rootless container.
    ///
    /// Every probe in this file goes through here, so the driver is consumed once
    /// per observation and [`DRIVER_SPAWNS`] — which is what makes a verdict's
    /// `via=oci` attribution true — is incremented in exactly one place.
    async fn run(&self, script: &str, plan: &Plan) -> Result<Drive, String> {
        DRIVER_SPAWNS.fetch_add(1, Ordering::Relaxed);
        let tag = format!("adv-{}", ATTEMPTS.fetch_add(1, Ordering::Relaxed));
        let capsule = Capsule::new(
            OccurrenceId(hash(0x5a)),
            PreparedActionId(hash(2)),
            EnvironmentId(hash(3)),
            PlatformRef::new("x86_64-linux", hash(11)).id(),
            plan.mappings.clone(),
            CapsuleProcess::Command {
                argv: vec![
                    SmolStr::new(format!("{BUSYBOX}/bin/busybox")),
                    SmolStr::new("sh"),
                    SmolStr::new("-c"),
                    SmolStr::new(script),
                ],
            },
            CapsuleNetwork::Offline,
            None,
            plan.budgets,
            None,
        )
        .map_err(|e| format!("the capsule is not well formed: {e}"))?;
        let trees = EmptyTrees;
        let source = BytesForbidden;
        let probe = RealStore;
        let request = OciStageRequest {
            capsule: &capsule,
            environment: &self.environment,
            network: NetPolicy::Offline,
            trees: &trees,
            source: &source,
            probe: &probe,
            execution_id: ulid::Ulid::new(),
        };
        match self.driver.drive(&tag, &request).await {
            Ok(output) => {
                // v6: the frame reports SIZES; the bytes are the spool files the
                // provider wrote under the attempt root's `capture/`, and this
                // rig holds the owned root so they are still there.
                let spool = output.attempt_root.join("capture");
                let read = |stream: &str| {
                    std::fs::read_to_string(spool.join(stream))
                        .expect("the provider spooled the stream")
                };
                Ok(Drive {
                    exit_code: output.exit_code,
                    stdout: read("stdout"),
                    stderr: read("stderr"),
                    // The rig reads the tree after the drive; dropping the owned root
                    // releases its lock and keeps the bytes.
                    attempt_root: output.attempt_root.to_path_buf(),
                })
            }
            // A REFUSAL is not a contained attack and must never be scored as
            // one: the refusal's own label is returned so the caller can say
            // which step of the route declined, and every caller that expects a
            // container asserts on it.
            Err(refusal) => Err(format!("{}: {refusal}", refusal.label())),
        }
    }

    /// THE ANTI-STUB CONTROL. A container of this shape starts, execs, prints and
    /// exits 0 — asserted before any row claims a refusal.
    async fn require_viable(&self, test: &str, plan: &Plan) {
        let out = self
            .run(&format!("echo {VIABLE}"), plan)
            .await
            .unwrap_or_else(|refusal| {
                panic!(
                    "{test}: VIABILITY: the route refused before any probe ran ({refusal}). Every \
                     containment assertion below would then be satisfied by an attack that never \
                     ran, which is the tautology this suite exists to eliminate."
                )
            });
        assert!(
            out.ok() && out.stdout.contains(VIABLE),
            "{test}: VIABILITY: a container of this exact shape did not exec busybox and print \
             its sentinel (exit {:?}). Nothing below is a measurement of containment until it \
             does.\nstdout: {}\nstderr: {}",
            out.exit_code,
            out.stdout,
            out.stderr,
        );
    }
}

/// The SAME busybox argv, on the host, with no container at all.
///
/// The honest unconstrained arm for a row whose containment IS the container:
/// there is no authorable capsule with "no container", so the only
/// counterfactual that is not itself a construction is this.
///
/// # It takes the ledger, and that is the fix for a measured over-count
///
/// [`Ledger::via`] credits a verdict to the driver when a spawn happened since
/// the previous verdict. Every row here starts with `Rig::require_viable`, which
/// starts a container — so the first HOST observation after it inherited that
/// spawn and printed `via=oci CONTROL=succeeded` for a control that ran no
/// container (measured, on A3). Over-counting is the
/// one direction a non-vacuity control may not err in, because the comparator
/// requires each pair's driver-observed subset to hold a control.
///
/// So this helper settles the watermark first, and it is the ONLY way this file
/// runs anything on the host — a host probe that forgot to settle would have to
/// not use the helper, which `no_host_probe_bypasses_the_ledger_settle` forbids
/// by scanning this file's own source.
fn on_host(led: &mut Ledger, script: &str) -> Output {
    led.settle();
    std::process::Command::new(format!("{BUSYBOX}/bin/busybox"))
        .args(["sh", "-c", script])
        .output()
        .expect("the host control runs busybox")
}

/// `busybox`, as an absolute path both arms resolve identically.
///
/// The closure is rbound into the container at its own store path, so this exact
/// string names the same bytes inside and outside. Every probe that must not
/// depend on `PATH` spells its applets through it — which the A1' `unshare` probe
/// does, because the whole point of that row is which syscall was refused and not
/// which binary was found.
fn bb() -> String {
    format!("{BUSYBOX}/bin/busybox")
}

/// The evidence for a containment verdict, worded by the verdict.
///
/// `Ledger::contained` prints its evidence on a PASS and embeds it in the panic on a
/// BREACH, so evidence written as the contained reading would announce success in the
/// very message reporting a breach — A1' saying "was REFUSED (the probe printed
/// \"residue-ok\")". Every containment site here words both outcomes.
fn verdict(held: bool, if_held: &str, if_breached: &str) -> String {
    if held {
        if_held.to_owned()
    } else {
        format!("BREACH: {if_breached}")
    }
}

fn host_text(out: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

/// Provision the freshly built `kata-provider-youki` into a by-hash provider
/// store this rig owns, exactly as an operator provisions the youki provider.
fn install_provider(root: &Path) -> OciProviderInstallation {
    let binary = workspace_bin("kata-provider-youki");
    let source = root.join("provider-src");
    std::fs::create_dir_all(&source).expect("the provider source directory");
    std::fs::copy(
        &binary,
        source.join(format!("kata-provider-{OCI_PROVIDER_NAME}")),
    )
    .expect("the provider bytes copy");
    let store_root = root.join("provider-store");
    let provisioned = kata_worker::ProviderStore::new(&store_root)
        .provision(OCI_PROVIDER_NAME, &source)
        .expect("the provider provisions into a by-hash store");
    OciProviderInstallation::new(
        store_root,
        ExternalProviderAddress::parse(&provisioned.address.to_string())
            .expect("a minted address parses"),
    )
}

/// Locate a workspace binary next to the current test binary.
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
        "`{name}` is not next to the test binary, and it IS the instrument of every row here. \
         `cargo nextest run -p kata-worker` does NOT build it. Run `cargo build -p \
         kata-provider-youki --bin kata-provider-youki` in the same command, which is also what \
         keeps a STALE one from being driven."
    );
}

/// Run an async `body` inside a delegated user scope, re-exec'ing this binary if
/// needed.
///
/// The same shape `oci_provider_live.rs`, `oci_stage_live.rs` and
/// `interactive_capsule_live.rs` use, and re-spelled for their stated reason: what must
/// not be duplicated is WHAT a delegated scope is, which is one `systemd-run` argv
/// and the fact `just _containment-preconditions` blocks its lane on.
///
/// This copy plants [`ENV_SENTINEL_KEY`] on the child, which A10 needs and which
/// `std::env::set_var` cannot provide in a multi-threaded process without
/// `unsafe`.
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
        .env(ENV_SENTINEL_KEY, ENV_SENTINEL_VALUE)
        .output()
        .unwrap_or_else(|error| {
            panic!(
                "re-exec of `{test}` inside `systemd-run --user --scope -p Delegate=yes` could \
                 not be spawned ({error}). A delegated scope is what lets an unprivileged \
                 process write a cgroup limit, and without one this host cannot certify the \
                 rootless-OCI prerequisite at all — see `just _containment-preconditions`."
            )
        });
    // Forwarded VERBATIM, because the inner run is where every
    // `ADVERSARIAL-KERNEL-SUITE` line is printed and the comparator parses those
    // lines out of this recipe's captured log.
    eprintln!(
        "--- delegated inner run of `{test}` stdout ---\n{}\n--- stderr ---\n{}\n---",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    print!("{}", String::from_utf8_lossy(&output.stdout));
    kata_test_utils::delegated_scope::assert_inner_ran_the_one_test(test, &output);
}

/// The `#[ignore]` text every row in this file carries, spelled once.
macro_rules! oci_live_row {
    ($name:ident, $body:ident) => {
        #[test]
        #[ignore = "HOST-DEPENDENT (pinned youki, its INSTALLED AppArmor \
                    profile, a delegated user scope, the fixture closure's store path realised) \
                    AND instrument-dependent (`cargo build -p kata-provider-youki`). On a host \
                    whose profile for the pinned youki is not installed this FAILS with \
                    `profile_file_differs` — run `sudo kata host \
                    apparmor-install` first. `just gate` is \
                    host-independent by design, so this rides the containment lane's \
                    `oci-live-smoke` (the containment lane's step 1). Run it with `cargo build -p \
                    kata-provider-youki --bin kata-provider-youki && cargo nextest run -p \
                    kata-worker -P live-smoke -E 'binary(oci_adversarial_live)' --run-ignored \
                    all` — `-P live-smoke` is NOT optional: the default profile kills a test at \
                    60 s, before the supervisor's own budget, and a SIGTERM there is the \
                    orphan path."]
        fn $name() {
            common::adversarial::bind_driver(ExecutionDriver::OciRuntime);
            delegated(stringify!($name), $body());
        }
    };
}

// ---------------------------------------------------------------------------
// The manifest — host-independent, and the one place declarations are printed
// ---------------------------------------------------------------------------

/// Host-independent. Prints THIS driver's floors, asserts `COVERAGE` is total,
/// and emits one `NOT-RUN` line per row this column declines.
///
/// Deliberately not `#[ignore]`d: it needs no youki, so it rides `just test-crate
/// kata-worker` and a new attack or driver reds in milliseconds. It is also what
/// puts the OCI column's declarations into `just test`'s log — the `#[ignore]`d
/// rows below cannot do that, because a declaration is needed exactly when its row
/// did not run.
#[test]
fn the_oci_column_declares_its_floors_and_what_it_cannot_express() {
    // BOUND, not read: this binary IS the OCI column. `bind_driver` refuses a
    // `DRIVER_ENV` that names a different driver rather than honouring it, so a
    // lane that sets `=oci` and a developer who sets nothing get the same answer
    // and `=linked` against this file is a named failure.
    common::adversarial::bind_driver(ExecutionDriver::OciRuntime);
    assert_eq!(driver(), ExecutionDriver::OciRuntime);
    common::adversarial::print_manifest_and_check_coverage(
        common::adversarial::ProbeVocabulary::CapsuleArgv,
    );
}

/// No host probe in this file may bypass [`on_host`], and so the ledger settle.
///
/// # THE DEFECT THIS PINS, and it was measured
///
/// `Ledger::via` credits a verdict to the driver when a spawn happened since the
/// previous verdict. Every row here starts with a viability container, so the
/// first HOST observation after it inherited that spawn and printed
/// `via=oci CONTROL=succeeded` for a control that ran nothing — measured on
/// A3. Over-counting is the one direction a non-vacuity control
/// may not err in: the comparator requires each pair's driver-observed subset to
/// hold BOTH a containment and a control, and a mislabelled host control satisfies
/// that without measuring it.
///
/// [`on_host`] settles the watermark, so the fix holds for every probe that goes
/// through it — and this check is what says every probe does. It scans this file's
/// own source for a second spawner, because a row that called
/// `std::process::Command` directly would be correct-looking and silently
/// mis-attributed.
///
/// COUNTERFACTUAL: add a bare `std::process::Command::new(bb())` to any row and
/// this names the line.
///
/// Host-independent, and deliberately not `#[ignore]`d.
#[test]
fn no_host_probe_bypasses_the_ledger_settle() {
    let source = include_str!("oci_adversarial_live.rs");
    let mut offenders = Vec::new();
    for (n, line) in source.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.starts_with("//") || trimmed.starts_with("///") || trimmed.starts_with("//!") {
            continue;
        }
        // Assembled from two halves so THIS line does not contain the literal it
        // looks for — a source scan is code the scan can see, and a literal here
        // would convict this check of itself.
        let needle = concat!("std::process::", "Command::new");
        if !trimmed.contains(needle) {
            continue;
        }
        // The four sanctioned spawners: the host-probe helper, the delegated
        // re-exec, the runtime's own `list`, and this scan's own mention.
        let sanctioned = ["/bin/busybox\"))", "systemd-run"];
        if sanctioned.iter().any(|ok| line.contains(ok)) {
            continue;
        }
        offenders.push(format!("  line {}: {trimmed}", n + 1));
    }
    // NON-VACUITY: the scan must be reading the file, or an empty offender list is
    // the list of a scan that found nothing at all.
    assert!(
        source.contains("fn on_host(led: &mut Ledger"),
        "the scan is not reading this file's source"
    );
    assert!(
        offenders.is_empty(),
        "{} host spawn(s) in this file do not go through `on_host`, which is what settles the \
         ledger's spawn watermark. A verdict made from one would be credited to the execution \
         driver though no container ran, which is the over-count `Ledger::settle` exists to \
         close:\n{}",
        offenders.len(),
        offenders.join("\n"),
    );
}

// ---------------------------------------------------------------------------
// A1 — capability regain: NOT DEMONSTRABLE on this host, and that is measured
// ---------------------------------------------------------------------------
//
// There is no row here, and the absence is a MEASUREMENT rather than an
// omission. A1 asks whether a stage can regain the capabilities it was stripped
// of and so reach `chroot`/`pivot_root`/`mount`. Its non-vacuity control must
// show that chain SUCCEEDING with the container absent, and on the reference host
// it cannot succeed anywhere:
//
//   kernel.apparmor_restrict_unprivileged_userns = 1
//   $ unshare -Ur /bin/true
//   unshare: write failed /proc/self/uid_map: Operation not permitted
//   $ busybox unshare -U busybox sh -c 'id -u; grep CapEff /proc/self/status'
//   65534
//   CapEff:  0000000000000000          (CapBnd: 000001ffffffffff)
//   $ busybox unshare -U -m busybox mount -t tmpfs none /tmp/x
//   Permission denied
//
// So an unconfined unprivileged process on this host may CREATE a user namespace
// and may not write its `uid_map`, which is what would grant capabilities in it.
// `Ledger::control` refuses to count a containment assertion whose control did
// not succeed, and it is right to: "the chroot failed inside" would be
// indistinguishable from "the chroot could not have worked anywhere".
//
// `COVERAGE` therefore carries
// `DriverCoverage::NotDemonstrable("uid_map_write_is_apparmor_restricted_on_this_host")`
// for (OciRuntime, A1), the manifest test prints it as a `NOT-RUN` row with that
// token, and the comparator excludes A1 from every pair this column is in rather
// than treating the silence as agreement. A host without the restriction must
// promote the cell back to `Runs` and write the row.
//
// A1' below carries the one residue syscall this host CAN demonstrate.

// ---------------------------------------------------------------------------
// A1' — the CONSTRUCTION RESIDUE, which only this route can be asked about
// ---------------------------------------------------------------------------

oci_live_row!(
    attack_oci_construction_residue_is_refused_by_the_kernel_live,
    a1p_body
);

/// **A1'.** `OciMeasuredBasis::residue_denied` says kata's own OCI deny list
/// NAMES all thirteen `ConstructionResidue` syscalls. It says nothing about what
/// the kernel does with them, and its own documentation is explicit about that.
/// This row is the other half, inside a real container.
///
/// # FOUR counted doors to a user namespace, and two measured-and-noted syscalls
///
/// `unshare`, `mount` and `setns` are all attempted. Of the three only `unshare` is
/// COUNTED, because only `unshare` can be made to succeed with the containment
/// relaxed on the reference host — and [`Ledger::control`] is right to refuse the other
/// two rather than let "it failed inside" stand for "it could not have worked
/// anywhere". The other doors to the same user namespace are counted beside it, each
/// a static probe busybox `printf`s on both arms (`common::static_probe`):
/// `clone(CLONE_NEWUSER)` must read EPERM and `clone3(CLONE_NEWUSER)` ENOSYS — the
/// errnos their deny-list entries declare — and an i386-ABI `unshare(CLONE_NEWUSER)`
/// must be KILLED by SIGSYS, the foreign architecture being a way round every
/// `x86_64` rule at once. MEASURED before `clone`/`clone3` joined the fence: both
/// created a nested user namespace inside the container in which a
/// capability-gated `clone(CLONE_NEWNET)` also succeeded (`probe-rc=100`), where the
/// same bytes on the host got the namespace without the capability (`probe-rc=101`):
/// the container inherits the pinned youki's AppArmor `userns` grant. MEASURED:
///
/// ```text
/// $ busybox unshare -U busybox true            -> exit 0        (COUNTABLE)
/// $ busybox unshare -U -m busybox mount …      -> Permission denied
/// $ unshare -Urm …                             -> write failed /proc/self/uid_map: EPERM
/// ```
///
/// `mount` and `setns` need capabilities in a namespace whose `uid_map` something
/// already wrote, and `kernel.apparmor_restrict_unprivileged_userns=1` refuses an
/// unconfined process that write. **And the fence cannot be relaxed instead:**
/// there is no `KATA_DISABLE_SECCOMP` for a rendered `config.json`, and adding one
/// to make a test scoreable would weaken production. So both are run, their
/// in-container result is recorded as a [`Ledger::note`], and neither is counted —
/// this suite's own convention for an attack it cannot demonstrate.
///
/// The PLAN-side half is asserted first and unconditionally: kata's fence must
/// still NAME all three, whatever the kernel is asked: measure the mechanism's
/// presence before the behaviour, so a refusal cannot be credited to a fence that
/// is not there.
async fn a1p_body() {
    let test = "attack_oci_construction_residue_is_refused_by_the_kernel_live";
    let rig = Rig::build(test);
    let mut led = Ledger::new(A1P_CONSTRUCTION_RESIDUE);
    let plan = Plan::default();
    rig.require_viable(test, &plan).await;

    // `residue_denied` is a fact about the PLAN, and it is asserted before the
    // kernel is asked anything: if kata's own list stopped naming these syscalls,
    // every refusal below would be attributable to something else and this row
    // would be measuring the wrong mechanism.
    let rules = kata_types::sandbox_seccomp::oci_seccomp_rules()
        .expect("the OCI fence renders for a fixture plan");
    let named: std::collections::BTreeSet<&str> = rules
        .syscalls
        .iter()
        .flat_map(|rule| rule.names.iter().copied())
        .collect();
    for syscall in ["unshare", "mount", "setns"] {
        assert!(
            named.contains(syscall),
            "{test}: kata's OCI fence does not name `{syscall}`, so a refusal observed below \
             would not be attributable to the fence this row is about. This is the same \
             assertion `OciMeasuredBasis::residue_denied` reads, made BEFORE the behaviour \
             under test."
        );
    }

    // THE COUNTED PROBE. Byte-identical on both arms: `busybox` is rbound into the
    // container at its own store path, so this exact string names the same bytes
    // inside and outside and the only difference between the arms is the container.
    let bb = bb();
    let unshare_probe = format!("{bb} unshare -U {bb} true && echo residue-ok || echo refused");
    let control = on_host(&mut led, &unshare_probe);
    let control_text = host_text(&control);
    led.control(
        "unshare",
        control_text.contains("residue-ok"),
        &format!(
            "UNCONSTRAINED (no container): `unshare -U` created a user namespace on the host — \
             {}",
            control_text.trim()
        ),
    );
    let inside = rig
        .run(&unshare_probe, &plan)
        .await
        .unwrap_or_else(|refusal| {
            panic!("{test}: the route refused instead of running the `unshare` probe: {refusal}")
        });
    // The DISCRIMINATOR IS THE PRINTED WORD, not the exit code: the probe is
    // `<syscall> && echo residue-ok || echo refused`, so the shell exits 0 on both
    // arms by design and a message that quoted the exit code would read as a
    // contradiction. `unshare -U` needs no capability at all, which is what makes the
    // refusal attributable to the FENCE rather than to the container's empty
    // capability set: the identical argv on the same bytes succeeded on the host.
    let held = !inside.text().contains("residue-ok") && inside.text().contains("refused");
    led.contained(
        "unshare",
        held,
        &verdict(
            held,
            &format!(
                "INSIDE the planned container `unshare` was REFUSED (the probe printed {:?}, not \
             `residue-ok`) — and `unshare -U` requires no capability, so this is the fence kata \
             rendered being enforced by the kernel and not the container's empty capability set. \
             The same argv, the same busybox bytes, succeeded on the host above.",
                inside.text().trim(),
            ),
            &format!(
                "INSIDE the planned container `unshare` was NOT refused — the probe printed {:?}",
                inside.text().trim(),
            ),
        ),
    );

    // THE OTHER DOORS TO A USER NAMESPACE. `unshare` is not the only call that makes
    // one: `clone` and `clone3` take the same CLONE_NEWUSER flag, and busybox has no
    // applet for either, so each is a static probe `busybox printf` writes on both
    // arms (`common::static_probe`). The fence denies `clone` only WITH that flag, so
    // the plan-side half reads the errno the entry declares and the kernel half
    // compares against it — `clone3` answers ENOSYS so a libc falls back to `clone`,
    // whose flags a filter can read.
    let host_dir = rig.dir.path().join("probe-host");
    std::fs::create_dir_all(&host_dir).expect("the host arm's probe directory");
    let host_dir = host_dir.display().to_string();
    for (probe, name, door) in [
        ("clone_newuser", "clone", static_probe::CLONE_NEWUSER),
        ("clone3_newuser", "clone3", static_probe::CLONE3_NEWUSER),
    ] {
        let entry = kata_types::sandbox_seccomp::DENIED_SYSCALLS
            .iter()
            .find(|entry| entry.name == name)
            .unwrap_or_else(|| {
                panic!(
                    "{test}: kata's deny-list has no `{name}` entry, so a refusal observed below \
                     would not be attributable to the fence this probe is about"
                )
            });
        assert!(
            named.contains(name),
            "{test}: kata's OCI fence does not name `{name}`, though the deny-list does"
        );
        let refused_with = i32::try_from(entry.errno).expect("an errno fits i32");
        let program = static_probe::static_elf(&[door, static_probe::NAMESPACE_REPORT].concat());
        let control = on_host(
            &mut led,
            &static_probe::write_and_run(&bb, &host_dir, &program),
        );
        let control_text = host_text(&control);
        let control_exit = static_probe::probe_exit(&control_text);
        led.control(
            probe,
            control_exit.is_some_and(static_probe::ProbeExit::created),
            &format!(
                "UNCONSTRAINED (no container): `{name}(CLONE_NEWUSER)` created a user namespace \
                 on the host — {control_exit:?} ({})",
                control_text.trim()
            ),
        );
        let inside = rig
            .run(&static_probe::write_and_run(&bb, "/tmp", &program), &plan)
            .await
            .unwrap_or_else(|refusal| {
                panic!(
                    "{test}: the route refused instead of running the `{probe}` probe: {refusal}"
                )
            });
        let inside_exit = static_probe::probe_exit(&inside.text());
        let held = inside_exit == Some(static_probe::ProbeExit::Errno(refused_with));
        led.contained(
            probe,
            held,
            &verdict(
                held,
                &format!(
                    "INSIDE the planned container `{name}(CLONE_NEWUSER)` failed with errno \
                     {refused_with}, the errno its deny-list entry declares — the same bytes \
                     created a user namespace on the host above ({control_exit:?})."
                ),
                &format!(
                    "INSIDE the planned container `{name}(CLONE_NEWUSER)` read {inside_exit:?}, \
                     not errno {refused_with} (`Succeeded` is a nested user namespace in which a \
                     capability-gated `clone(CLONE_NEWNET)` also succeeded) — {}",
                    inside.text().trim(),
                ),
            ),
        );
    }

    // THE ARCHITECTURE AXIS. The fence's rules are numbers in the `x86_64` table;
    // an i386-ABI call (`int 0x80`) reaches seccomp as `AUDIT_ARCH_I386` with the
    // i386 table's numbers, so it asks what the capsule's filters do with a
    // foreign architecture. The probe is `unshare(CLONE_NEWUSER)` — denied by
    // name on `x86_64` — through that ABI.
    let program = static_probe::static_elf(
        &[
            static_probe::I386_UNSHARE_NEWUSER,
            static_probe::I386_REPORT,
        ]
        .concat(),
    );
    let control = on_host(
        &mut led,
        &static_probe::write_and_run(&bb, &host_dir, &program),
    );
    let control_text = host_text(&control);
    let control_exit = static_probe::probe_exit(&control_text);
    led.control(
        "i386_unshare_newuser",
        control_exit == Some(static_probe::ProbeExit::Succeeded),
        &format!(
            "UNCONSTRAINED (no container): an i386-ABI `unshare(CLONE_NEWUSER)` succeeded on the \
             host — {control_exit:?} ({})",
            control_text.trim()
        ),
    );
    let inside = rig
        .run(&static_probe::write_and_run(&bb, "/tmp", &program), &plan)
        .await
        .unwrap_or_else(|refusal| {
            panic!(
                "{test}: the route refused instead of running the `i386_unshare_newuser` probe: \
                 {refusal}"
            )
        });
    let inside_exit = static_probe::probe_exit(&inside.text());
    let held = inside_exit == Some(static_probe::ProbeExit::KilledBySigsys);
    led.contained(
        "i386_unshare_newuser",
        held,
        &verdict(
            held,
            "INSIDE the planned container an i386-ABI `unshare(CLONE_NEWUSER)` KILLED the probe \
             by SIGSYS — both of the container's filters kill a foreign architecture (the stage \
             fence by the runtime's bad-arch action, the inherited kata floor by its arch guard), \
             and the same bytes created a user namespace on the host above.",
            &format!(
                "INSIDE the planned container an i386-ABI `unshare(CLONE_NEWUSER)` read \
                 {inside_exit:?}, not a SIGSYS kill — {}",
                inside.text().trim(),
            ),
        ),
    );

    // THE TWO NOTED PROBES. Run, recorded, NOT counted — their controls are not
    // constructible on this host and the fence is not relaxable on this route.
    for (probe, script) in [
        (
            "mount",
            format!(
                "{bb} mkdir -p /tmp/m && {bb} mount -t tmpfs none /tmp/m && echo residue-ok || echo refused"
            ),
        ),
        (
            "setns",
            format!(
                "{bb} nsenter --mount=/proc/1/ns/mnt {bb} true && echo residue-ok || echo refused"
            ),
        ),
    ] {
        let control = on_host(&mut led, &script);
        let control_text = host_text(&control);
        let inside = rig.run(&script, &plan).await.unwrap_or_else(|refusal| {
            panic!("{test}: the route refused instead of running the `{probe}` probe: {refusal}")
        });
        led.note(&format!(
            "`{probe}` is MEASURED AND NOT COUNTED. Unconstrained on this host it also fails \
             ({}), because it needs capabilities in a namespace whose uid_map something already \
             wrote and `kernel.apparmor_restrict_unprivileged_userns=1` refuses an unconfined \
             process that write; and the fence is not relaxable on this route, so no other \
             counterfactual exists. INSIDE the container (exit {:?}): {}. Raise this row's \
             floor to 3 on a host that permits a mapped-root userns.",
            control_text.trim(),
            inside.exit_code,
            inside.text().trim(),
        ));
    }
    led.finish();
}

// ---------------------------------------------------------------------------
// A2 — an undeclared host path
// ---------------------------------------------------------------------------

oci_live_row!(attack_oci_cannot_read_an_undeclared_host_path_live, a2_body);

/// **A2.** TWO observations, and the reason is in `COVERAGE`: this route has no
/// fs policy enum. The two shapes that DO exist here are a host absolute path
/// under no mapping at all, and the worker's own state tree — the directory
/// holding the provider's runtime state and this attempt's own inputs.
async fn a2_body() {
    let test = "attack_oci_cannot_read_an_undeclared_host_path_live";
    let rig = Rig::build(test);
    let mut led = Ledger::new(A2_FS_ESCAPE);
    let plan = Plan::default();
    rig.require_viable(test, &plan).await;

    let secret_dir = rig.host_only_dir();
    let secret = secret_dir.join("operator-secret");
    std::fs::write(&secret, "SECRET-BYTES-NO-CAPSULE-DECLARED\n").expect("the host secret");

    for (probe, target) in [
        ("undeclared_host_file", secret.clone()),
        (
            "worker_state_tree",
            rig.dir.path().join("worker-state").join("attempts"),
        ),
    ] {
        let script = format!(
            "cat {}/* 2>&1 || ls {} 2>&1",
            target.display(),
            target.display()
        );
        let control = on_host(&mut led, &script);
        let control_text = host_text(&control);
        led.control(
            probe,
            control.status.success() && !control_text.trim().is_empty(),
            &format!(
                "UNCONSTRAINED (no container): the same read of `{}` succeeded on the host, so \
                 the path exists and is readable by this uid",
                target.display()
            ),
        );
        let inside = rig.run(&script, &plan).await.unwrap_or_else(|refusal| {
            panic!("{test}: the route refused instead of running the `{probe}` probe: {refusal}")
        });
        let observed = inside.text();
        let held = !observed.contains("SECRET-BYTES-NO-CAPSULE-DECLARED") && !inside.ok();
        led.contained(
            probe,
            held,
            &verdict(
                held,
                &format!(
                    "INSIDE the planned container `{}` is not reachable (exit {:?}) — a capsule \
                 declares guest MAPPINGS and `spec_for` refuses one outside /work, /out and the \
                 tmpfs /tmp, so no host path arrives by accident — {}",
                    target.display(),
                    inside.exit_code,
                    observed.trim(),
                ),
                &format!(
                    "INSIDE the planned container `{}` WAS reachable (exit {:?}) — {}",
                    target.display(),
                    inside.exit_code,
                    observed.trim(),
                ),
            ),
        );
    }
    led.finish();
}

// ---------------------------------------------------------------------------
// A3 — another process's memory, and a host pid
// ---------------------------------------------------------------------------

oci_live_row!(attack_oci_cannot_address_a_host_pid_live, a3_body);

/// **A3.** The container's own pid namespace is what makes a host pid
/// unaddressable, and the probe is the cheapest possible one that a busybox
/// closure can express: signal 0 to the pid of the process that STARTED the
/// container. On the host that succeeds (it is this very process); inside, the
/// pid does not exist.
async fn a3_body() {
    let test = "attack_oci_cannot_address_a_host_pid_live";
    let rig = Rig::build(test);
    let mut led = Ledger::new(A3_PROCESS_MEMORY);
    let plan = Plan::default();
    rig.require_viable(test, &plan).await;

    let host_pid = std::process::id();
    let script = format!("kill -0 {host_pid} 2>&1 && echo addressed || echo unreachable");
    let control = on_host(&mut led, &script);
    let control_text = host_text(&control);
    led.control(
        "host_pid_is_addressable",
        control_text.contains("addressed"),
        &format!(
            "UNCONSTRAINED (no container): pid {host_pid} — this rig's own process — is \
             addressable from a host child: {}",
            control_text.trim()
        ),
    );

    let inside = rig.run(&script, &plan).await.unwrap_or_else(|refusal| {
        panic!("{test}: the route refused instead of running: {refusal}")
    });
    let observed = inside.text();
    let held = observed.contains("unreachable") && !observed.contains("addressed");
    led.contained(
        "host_pid_is_addressable",
        held,
        &verdict(
            held,
            &format!(
            "INSIDE the planned container pid {host_pid} does not exist — the container has its \
             own pid namespace, so the number names nothing — {}",
            observed.trim()
        ),
            &format!(
                "INSIDE the planned container host pid {host_pid} WAS addressable — {}",
            observed.trim()
            ),
        ),
    );
    led.finish();
}

// ---------------------------------------------------------------------------
// A4 — network egress under the only posture this route admits
// ---------------------------------------------------------------------------

oci_live_row!(
    attack_oci_offline_container_cannot_reach_a_host_address_live,
    a4_body
);

/// **A4.** `spec_for` admits ONLY [`NetPolicy::Offline`] on this route, so there
/// is no in-container relaxed arm to build and the control is the host. The
/// sentinel is a real listener this rig opened on loopback, which is what makes
/// "could not connect" mean the network and not a closed port.
async fn a4_body() {
    let test = "attack_oci_offline_container_cannot_reach_a_host_address_live";
    let rig = Rig::build(test);
    let mut led = Ledger::new(A4_NET_EGRESS);
    let plan = Plan::default();
    rig.require_viable(test, &plan).await;

    let listener = TcpListener::bind("127.0.0.1:0").expect("a host-only sentinel listener");
    let port = listener
        .local_addr()
        .expect("the sentinel's address")
        .port();
    // Answer every connection for the life of this row, so the control's success
    // is the connection and not a race with an unaccepted backlog.
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            drop(stream);
        }
    });

    let script = format!("nc -w 2 127.0.0.1 {port} < /dev/null && echo reached || echo refused");
    let control = on_host(&mut led, &script);
    let control_text = host_text(&control);
    led.control(
        "host_only_tcp_address",
        control_text.contains("reached"),
        &format!(
            "UNCONSTRAINED (no container): 127.0.0.1:{port} is reachable from a host child: {}",
            control_text.trim()
        ),
    );

    // The INTERFACES the guest's kernel lists, read in the same container: a loopback
    // connect failing says nothing about a second interface with a route off the box,
    // so the offline claim also needs `/proc/net/dev` to name `lo` and nothing else.
    let inside_script = format!(
        "{script}; echo \"IFACES $(tail -n +3 /proc/net/dev | cut -d: -f1 | tr -d ' ' | tr '\\n' ,)\""
    );
    let inside = rig
        .run(&inside_script, &plan)
        .await
        .unwrap_or_else(|refusal| {
            panic!("{test}: the route refused instead of running: {refusal}")
        });
    let observed = inside.text();
    let interfaces = observed
        .lines()
        .find_map(|line| line.strip_prefix("IFACES "))
        .unwrap_or_else(|| panic!("{test}: the guest listed no interfaces: {observed}"));
    assert_eq!(
        interfaces.trim(),
        "lo,",
        "{test}: the offline container's kernel lists interfaces other than `lo` in \
         /proc/net/dev: {interfaces:?}"
    );
    led.note(&format!(
        "INSIDE /proc/net/dev lists exactly `lo` ({})",
        interfaces.trim()
    ));
    let held = !observed.contains("reached");
    led.contained(
        "host_only_tcp_address",
        held,
        &verdict(
            held,
            &format!(
                "INSIDE the planned container 127.0.0.1:{port} is not reachable — the only network \
             posture this route admits is offline, and the container's loopback is its own — {}",
                observed.trim()
            ),
            &format!(
                "INSIDE the planned container 127.0.0.1:{port} WAS reached — {}",
                observed.trim()
            ),
        ),
    );
    led.finish();
}

// ---------------------------------------------------------------------------
// A6 — a descendant that tries to outlive the container
// ---------------------------------------------------------------------------

oci_live_row!(
    attack_oci_descendant_cannot_outlive_the_container_live,
    a6_body
);

/// **A6.** A stage that backgrounds a long-lived process COMPLETES, and within 5 s of
/// its completion nothing of it — nor of kata's — survives in the cgroup hierarchy.
///
/// # What is measured
///
/// The probe backgrounds `sleep 300 &` with its stdio inherited. On the captured
/// arm the container's stdout and stderr are FILES (`connect_stdio`), not pipes,
/// so no descendant can hold a pipe open. youki 0.7.0 has a lost-SIGCHLD race (an
/// init that exits before `handle_foreground` blocks signals strands the client —
/// this probe's init forks and exits at once), which the pin carries a patch for;
/// under the patched pin this form completed 5 of 5 in 3.6–4.4 s (measured). What
/// the row asserts does not depend on it: completion, then the hierarchy read from
/// OUTSIDE.
///
/// # The cgroup path is MEASURED, not composed
///
/// `/sys/fs/cgroup/kata.oci.<id>` does not exist. The real shape, read off the
/// host while a container ran:
///
/// ```text
/// <this process's own cgroup dir>/../kata.provider.youki.<pid>/kata.oci.<container id>
/// ```
///
/// so the scan is rooted at the parent of THIS process's own cgroup — taken from
/// `/proc/self/cgroup`, which is a host read and not a second producer of the
/// driver's layout. Rooting it there also makes the row immune to another run's
/// residue: a failed earlier run left `kata.provider.youki.*` directories under
/// three OTHER `run-u*.scope`s, and a scan of all of `/sys/fs/cgroup` would have
/// found them and failed this row for somebody else's mess.
///
async fn a6_body() {
    let test = "attack_oci_descendant_cannot_outlive_the_container_live";
    let rig = Rig::build(test);
    let mut led = Ledger::new(A6_DESCENDANT_TEARDOWN);

    // Non-vacuity for the cgroup scan itself, before anything else: a viability
    // container of the same shape must make a `kata.oci.*` directory APPEAR under
    // our own scope while it runs. Without this, "no directory afterwards" is
    // satisfied by a scan that never finds anything at all.
    let plan = Plan::default();
    let sighted = std::sync::Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
    let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    {
        let sighted = std::sync::Arc::clone(&sighted);
        let stop = std::sync::Arc::clone(&stop);
        let root = own_cgroup_scope();
        std::thread::spawn(move || {
            while !stop.load(Ordering::Relaxed) {
                for found in kata_cgroup_dirs(&root) {
                    sighted.lock().expect("the sighting list").push(found);
                }
                std::thread::sleep(std::time::Duration::from_millis(25));
            }
        });
    }
    // Long enough for the poller to see it, short enough to cost nothing.
    let viable = rig
        .run(&format!("{} sleep 2; echo {VIABLE}", bb()), &plan)
        .await
        .unwrap_or_else(|refusal| {
            panic!("{test}: VIABILITY: the route refused before any probe ran ({refusal})")
        });
    stop.store(true, Ordering::Relaxed);
    assert!(
        viable.ok() && viable.stdout.contains(VIABLE),
        "{test}: VIABILITY: a container of this shape did not run (exit {:?}): {}",
        viable.exit_code,
        viable.text(),
    );
    let seen = sighted.lock().expect("the sighting list").clone();
    assert!(
        seen.iter().any(|d| d.contains("kata.oci.")),
        "{test}: NON-VACUITY: no `kata.oci.*` cgroup directory was ever observed under {} \
         while a container was RUNNING, so the absence asserted below is the absence of \
         something this scan cannot see. Saw: {seen:?}",
        own_cgroup_scope().display(),
    );

    // THE CONTROL: on the host, an orphaned `sleep` DOES outlive the shell that
    // started it. Without it the containment assertion is satisfied by a probe
    // that never managed to background anything.
    let marker = rig.host_only_dir().join("orphan.pid");
    let bb = bb();
    let control = on_host(
        &mut led,
        &format!(
            "{bb} sh -c '{bb} sleep 30 >/dev/null 2>&1 & echo $! > {m}' ; {bb} sleep 1; \
             {bb} kill -0 \"$({bb} cat {m})\" && echo survived || echo gone",
            m = marker.display(),
        ),
    );
    let control_text = host_text(&control);
    let orphan_pid = std::fs::read_to_string(&marker)
        .map(|s| s.trim().to_owned())
        .unwrap_or_default();
    led.control(
        "backgrounded_descendant",
        control_text.contains("survived"),
        &format!(
            "UNCONSTRAINED (no container): a backgrounded `sleep` (pid {orphan_pid}) outlived \
             the shell that started it: {}",
            control_text.trim()
        ),
    );
    if !orphan_pid.is_empty() {
        // The rig's own residue, and the lane's `pgrep-stale` step is right to care.
        let _ = on_host(
            &mut led,
            &format!("{bb} kill {orphan_pid} 2>/dev/null; true"),
        );
    }

    // THE PROPERTY, and the mechanism it rests on is the KERNEL's, not kata's.
    //
    // A 45 s descendant is backgrounded and the init exits at once. When a pid
    // namespace's init exits the kernel kills every other process in that namespace,
    // and a cgroup directory cannot be removed while it still has members — so the
    // absence of `kata.oci.<id>` within 5 s (a ninth of the descendant's remaining
    // life) is the kernel's own attestation that nothing of that container is left
    // running. It is not kata reporting on itself, which is what `Ledger::contained`
    // needs and what a `TeardownOutcome::Confirmed` read off the driver would not
    // have been.
    let after = rig
        .run(
            &format!("{bb} sleep 45 >/dev/null 2>&1 & echo backgrounded $!"),
            &plan,
        )
        .await
        .unwrap_or_else(|refusal| {
            panic!(
                "{test}: the route refused instead of running the descendant probe ({refusal}). \
                 This drive is expected to COMPLETE; a refusal here is a different experiment."
            )
        });
    assert!(
        after.ok() && after.stdout.contains("backgrounded"),
        "{test}: the probe did not report backgrounding anything (exit {:?}), so there is no \
         descendant for this row to be about: {}",
        after.exit_code,
        after.text(),
    );

    // Poll: kata's teardown and the kernel's cgroup release are not the same
    // instant, and a single sample would make this row's verdict a race. Bounded at
    // 5 s, which is a tenth of the descendant's own remaining life — so a pass
    // cannot be the descendant simply having finished.
    let root = own_cgroup_scope();
    let mut residue = kata_cgroup_dirs(&root);
    for _ in 0..100 {
        if residue.is_empty() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
        residue = kata_cgroup_dirs(&root);
    }
    let held = residue.is_empty();
    led.contained(
        "backgrounded_descendant",
        held,
        &verdict(
            held,
            &format!(
            "the stage COMPLETED and within 5s NO `kata.provider.youki.*` or `kata.oci.*` cgroup \
             directory survives under {} — while the descendant it backgrounded had ~40s left to \
             run. A cgroup directory cannot be rmdir'd while it has members, so this absence is \
             the KERNEL attesting the descendant is gone, read from the host filesystem and not \
             from the driver's own teardown verdict. Non-vacuous because the viability container \
             above made such a directory appear in this same place.",
            root.display(),
        ),
            &format!(
                "{} kata cgroup director(ies) SURVIVE under {} 5s after the stage completed: {:?}",
            residue.len(),
            root.display(),
            residue,
            ),
        ),
    );
    led.finish();
}

/// The cgroup directory this process's own cgroup lives in.
///
/// Read from `/proc/self/cgroup` — a host fact — so the scan below is rooted where
/// THIS delegated scope's containers go and nowhere else. Scoping it matters: a
/// failed earlier run left `kata.provider.youki.*` directories under other
/// `run-u*.scope`s, and a hierarchy-wide scan would fail this row for them.
fn own_cgroup_scope() -> PathBuf {
    let raw = std::fs::read_to_string("/proc/self/cgroup").unwrap_or_default();
    // cgroup v2: a single `0::<path>` line.
    let rel = raw
        .lines()
        .find_map(|line| line.strip_prefix("0::"))
        .unwrap_or("/")
        .trim()
        .to_owned();
    let mut dir = PathBuf::from("/sys/fs/cgroup");
    dir.push(rel.trim_start_matches('/'));
    // Our own cgroup is `<scope>/kata.supervisor` once a supervisor has run, so the
    // scope is its parent. Taking the parent unconditionally is wrong; take it only
    // when we are inside a kata-made leaf.
    if dir
        .file_name()
        .and_then(|n| n.to_str())
        .is_some_and(|n| n.starts_with("kata."))
        && let Some(parent) = dir.parent()
    {
        return parent.to_path_buf();
    }
    dir
}

/// Every `kata.provider.*` / `kata.oci.*` directory under `root`, as host paths.
fn kata_cgroup_dirs(root: &Path) -> Vec<String> {
    let mut found = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir).into_iter().flatten().flatten() {
            let path = entry.path();
            if !path.is_dir() {
                continue;
            }
            let name = entry.file_name().to_string_lossy().into_owned();
            if name.starts_with("kata.provider.") || name.starts_with("kata.oci.") {
                found.push(path.display().to_string());
            }
            stack.push(path);
        }
    }
    found.sort_unstable();
    found
}

// ---------------------------------------------------------------------------
// A7 — a bound the capsule declared
// ---------------------------------------------------------------------------

oci_live_row!(attack_oci_declared_process_bound_is_enforced_live, a7_body);

/// **A7.** The one row whose control is ANOTHER CONTAINER RUN, and so the one
/// whose control is a DRIVER observation (`via=oci`): the containment being
/// relaxed is a number the capsule declared, and widening it is authorable.
///
/// # It measures PIDS, and a MEMORY probe is wrong twice over
///
/// Filling `/dev/shm` with 96 MiB and expecting a 512 MiB budget to allow it
/// does not work. MEASURED from inside a real container:
///
/// ```text
/// shm   on /dev/shm type tmpfs (rw,nosuid,nodev,noexec,size=65536k,uid=1000,…)
/// tmpfs on /tmp     type tmpfs (rw,nosuid,nodev,relatime,size=524288k,uid=1000,…)
/// ```
///
/// So `/dev/shm` is a fixed 64 MiB and the 96 MiB write could never succeed — the
/// CONTROL failed, exactly as `Ledger::control` is built to notice. Worse, the
/// obvious repair was wrong too: `/tmp` is sized **at the capsule's
/// `memory_bytes`** (524288k = the 512 MiB this rig declared), so a `/tmp` fill
/// that "respects the bound" would be measuring the tmpfs's own `size=` and
/// reporting it as a cgroup enforcement — a guarantee attributed to the wrong
/// mechanism, which is this codebase's costliest recurring defect.
///
/// `process_count` has no such second enforcer. It becomes `pids.max` on the
/// cgroup kata created, so a fork count is attributable to that and to nothing
/// else, and the observation is a NUMBER read out of the container's own `/proc`
/// rather than an exit code.
///
/// `min_pinned` is zero in this column: the bound is a cgroup kata created and
/// wrote, so there is no accepted-then-dropped bound to pin, and carrying such a
/// pin here unmeasured would report a hole on a mechanism that does not have it.
async fn a7_body() {
    let test = "attack_oci_declared_process_bound_is_enforced_live";
    let rig = Rig::build(test);
    let mut led = Ledger::new(A7_DECLARED_BOUNDS);

    let bb = bb();
    // Sixty OVERLAPPING children, each of which appends one line to `/out` — and
    // the count is read off the HOST from the attempt root afterwards, not out of
    // `/proc` during the storm.
    //
    // Counting `/proc` entries with `ls | grep -c` as the last act of the bounded
    // container produces no parseable output at all (MEASURED): under
    // `pids.max = 16` the sixty children still hold every slot
    // when the pipeline runs, so the count itself cannot fork and the probe reports
    // nothing. A probe whose own measurement needs the resource it is exhausting
    // cannot measure it. So the children write, `wait` (a builtin — no fork) lets
    // them drain, and the verdict is a line count in a file kata's own driver
    // published, read with `std::fs`.
    let fork_probe = format!(
        "for i in $({bb} seq 1 60); do ( {bb} sleep 1; {bb} echo x >> /out/forks ) & done; \
         wait; {bb} echo storm-done"
    );

    let generous = Plan {
        budgets: CapsuleBudgets {
            process_count: 512,
            ..default_budgets()
        },
        ..Plan::default()
    };
    rig.require_viable(test, &generous).await;
    let relaxed = rig
        .run(&fork_probe, &generous)
        .await
        .unwrap_or_else(|refusal| {
            panic!("{test}: the route refused instead of running the relaxed arm: {refusal}")
        });
    let relaxed_forks = forks_recorded(&relaxed.attempt_root);
    led.control(
        "declared_process_bound",
        relaxed_forks > 40,
        &format!(
            "BOUND RELAXED (the capsule declares process_count = {}): {relaxed_forks} of 60 \
             overlapping children ran, counted on the HOST in {}",
            generous.budgets.process_count,
            relaxed.attempt_root.display(),
        ),
    );

    let narrow = Plan {
        budgets: CapsuleBudgets {
            process_count: 16,
            ..default_budgets()
        },
        ..Plan::default()
    };
    let bounded = rig
        .run(&fork_probe, &narrow)
        .await
        .unwrap_or_else(|refusal| {
            panic!("{test}: the route refused instead of running the bounded arm: {refusal}")
        });
    let bounded_forks = forks_recorded(&bounded.attempt_root);
    let held =
        bounded_forks < relaxed_forks && bounded_forks <= narrow.budgets.process_count as usize;
    led.contained(
        "declared_process_bound",
        held,
        &verdict(
            held,
            &format!(
            "BOUND DECLARED (process_count = {}): the IDENTICAL probe got only {bounded_forks} of \
             60 children through against {relaxed_forks} under the wide bound — the number rode \
             the capsule into `linux.resources` and became `pids.max` on a cgroup kata created. \
             Counted on the HOST, in {}. Container said: {}",
            narrow.budgets.process_count,
            bounded.attempt_root.display(),
            bounded.text().trim(),
        ),
            &format!(
                "BOUND DECLARED (process_count = {}) did NOT hold: {bounded_forks} of 60 children ran against {relaxed_forks} under the wide bound",
            narrow.budgets.process_count,
            ),
        ),
    );
    led.finish();
}

/// How many lines the container's children appended to `/out/forks`, read from the
/// HOST.
///
/// `find_under` rather than a composed path: `/out`'s host-side location beneath
/// the attempt root is the driver's layout, and a second spelling of it here would
/// be a second producer of a fact the driver already returns.
fn forks_recorded(attempt_root: &Path) -> usize {
    find_under(attempt_root, "forks")
        .and_then(|p| std::fs::read_to_string(p).ok())
        .map_or(0, |text| {
            text.lines().filter(|l| !l.trim().is_empty()).count()
        })
}

// ---------------------------------------------------------------------------
// A8 — naming a namespace outside the container's own
// ---------------------------------------------------------------------------

oci_live_row!(
    attack_oci_cannot_name_a_namespace_outside_the_container_live,
    a8_body
);

/// **A8.** Two observations: the container's own pid namespace is NOT the host's
/// (read as an inode from `/proc/self/ns/pid` on both sides), and `/proc` inside
/// lists only the container's processes rather than the host's.
async fn a8_body() {
    let test = "attack_oci_cannot_name_a_namespace_outside_the_container_live";
    let rig = Rig::build(test);
    let mut led = Ledger::new(A8_NAMESPACE_IDENTITY);
    let plan = Plan::default();
    rig.require_viable(test, &plan).await;

    // 1. The namespace identity itself, written into `/out` and read on the HOST for
    //    the reason probe 2 below spells out: nothing in this row needs the
    //    container's stdout, and a probe that does not use it cannot be wedged by it.
    let ns_script = format!("{} readlink /proc/self/ns/pid > /out/ns", bb());
    let control = on_host(&mut led, "readlink /proc/self/ns/pid");
    let host_ns = host_text(&control).trim().to_owned();
    led.control(
        "pid_namespace_identity",
        !host_ns.is_empty(),
        &format!("UNCONSTRAINED (no container): the host's pid namespace reads as {host_ns}"),
    );
    let inside = rig.run(&ns_script, &plan).await.unwrap_or_else(|refusal| {
        panic!("{test}: the route refused instead of running: {refusal}")
    });
    let inside_ns = find_under(&inside.attempt_root, "ns")
        .and_then(|p| std::fs::read_to_string(p).ok())
        .unwrap_or_default()
        .trim()
        .to_owned();
    let held = !inside_ns.is_empty() && inside_ns != host_ns;
    led.contained(
        "pid_namespace_identity",
        held,
        &verdict(
            held,
            &format!(
            "INSIDE the planned container the pid namespace reads as {inside_ns}, which is not \
             the host's {host_ns} — so there is no host namespace here to name"
        ),
            &format!(
                "INSIDE the planned container the pid namespace reads {inside_ns:?}, which is EMPTY or the host's own {host_ns}"
            ),
        ),
    );

    // 2. And the consequence: `/proc` holds the container's processes, not the
    //    host's. A count, because the host's exact pid set is not stable.
    //
    // Written to `/out` and counted on the HOST. This probe was `ls -1 /proc | grep
    // -c …` and one full-suite run stranded it at the provider's 120 s budget; the
    // explanation recorded then (a pipeline stage holding the container's stdout)
    // is contradicted by the provider's captured arm writing stdout to a FILE, and
    // the stranding matches youki 0.7.0's lost-SIGCHLD race, which the pin now
    // patches. Counting on the host is kept because it is the better oracle — the
    // container's own output is not trusted to report on the container.
    //
    // The HOST control first and the container second, so the containment verdict
    // below is made immediately after the container run it reads and `via=oci` is
    // true of it. The previous order (container, then the settling host probe, then
    // the verdict) tagged this row's containment `via=host` by `Ledger::via`'s own
    // construction — a container observation credited to the host — which the
    // comparator's per-attack check for an `attribution=exact` rig now refuses.
    let bb = bb();
    // The control below reads busybox's own report of an entry gone before its
    // `lstat`; the pinned busybox's report, off a `/proc` entry past `pid_max`
    // (at most 2^22, so no process holds it), must be exactly the one it reads.
    let gone = on_host(&mut led, &format!("{bb} ls -1 /proc/4194305"));
    assert!(
        gone.status.code() == Some(1) && listed_but_for_exited_processes(&gone),
        "{test}: the pinned busybox's report of a vanished /proc entry is not the one the host \
         control reads as a listing: {:?}, {}",
        gone.status,
        host_text(&gone)
    );
    let host_list = rig.host_only_dir().join("proc-entries");
    let control = on_host(
        &mut led,
        &format!("{bb} ls -1 /proc > {}", host_list.display()),
    );
    assert!(
        listed_but_for_exited_processes(&control),
        "{test}: the host control could not list /proc: {}",
        host_text(&control)
    );
    let host_count = count_numeric_lines(&host_list);
    let exited = String::from_utf8_lossy(&control.stderr).lines().count();
    led.control(
        "host_process_table",
        host_count > 20,
        &format!(
            "UNCONSTRAINED (no container): /proc lists {host_count} host processes ({exited} more \
             exited mid-listing), so the table this attack wants is large and present"
        ),
    );
    let list_script = format!("{bb} ls -1 /proc > /out/proc-entries");
    let inside = rig
        .run(&list_script, &plan)
        .await
        .unwrap_or_else(|refusal| {
            panic!("{test}: the route refused instead of running: {refusal}")
        });
    let inside_count = numeric_entries(&inside.attempt_root, "proc-entries");
    let held = inside_count > 0 && inside_count < 10;
    led.contained(
        "host_process_table",
        held,
        &verdict(
            held,
            &format!(
            "INSIDE the planned container /proc lists {inside_count} process(es) against the \
             host's {host_count} — the container's `/proc` is mounted in its own pid namespace, \
             so the host's table is not there to read. Both counts are taken on the HOST from \
             files the two arms wrote."
        ),
            &format!(
                "INSIDE the planned container /proc lists {inside_count} process(es) against the host's {host_count} — zero means the probe read nothing, many means the host table is visible"
            ),
        ),
    );
    led.finish();
}

/// Whether a host `ls -1 /proc` listed the table: it exited 0, or it exited 1
/// and every line of its standard error is busybox's report of an entry that
/// was gone by the time it read it (`ls: /proc/<pid>: No such file or
/// directory`). busybox's `ls` reads the directory, then `lstat`s each entry
/// (MEASURED: one `lstat` per entry, and no option of the pinned busybox skips
/// it), so a host process that exits between the two is reported and left
/// out, and the listing is the rest of the table. Any other failure is no
/// listing.
fn listed_but_for_exited_processes(out: &Output) -> bool {
    if out.status.success() {
        return true;
    }
    let stderr = String::from_utf8_lossy(&out.stderr);
    out.status.code() == Some(1)
        && !stderr.trim().is_empty()
        && stderr.lines().all(|line| {
            line.strip_prefix("ls: /proc/")
                .and_then(|rest| rest.strip_suffix(": No such file or directory"))
                .is_some_and(|pid| !pid.is_empty() && pid.bytes().all(|b| b.is_ascii_digit()))
        })
}

/// **The host `/proc` control reads a pid that exited mid-listing as a
/// listing, and nothing else that fails as one.** Exit 0 is a listing, and so
/// is exit 1 whose every standard-error line is busybox's report of a numeric
/// `/proc` entry gone; an empty report, a non-numeric or empty entry, another
/// directory, another error beside the reports, another exit status and a
/// signal are not.
///
/// Every output here is built, not run, so this cell needs no busybox and no
/// host capability. That the pinned busybox prints exactly the report this
/// predicate reads is checked where busybox is a precondition: by the live A8
/// row, which lists a `/proc` entry past `pid_max` before its host control.
#[test]
fn a_host_process_that_exits_mid_listing_leaves_the_proc_control_a_listing() {
    use std::os::unix::process::ExitStatusExt as _;
    let ls = |status: i32, stderr: &str| Output {
        status: std::process::ExitStatus::from_raw(status),
        stdout: b"1\n2\n".to_vec(),
        stderr: stderr.as_bytes().to_vec(),
    };
    let exited = |code: i32| code << 8;
    let gone = "ls: /proc/4194305: No such file or directory\n";
    for listed in [
        ls(exited(0), ""),
        ls(exited(1), gone),
        ls(
            exited(1),
            "ls: /proc/41: No such file or directory\nls: /proc/4194305: No such file or directory\n",
        ),
    ] {
        assert!(listed_but_for_exited_processes(&listed), "{listed:?}");
    }
    for refused in [
        ls(exited(1), ""),
        ls(
            exited(1),
            "ls: /no-such-proc/4194305: No such file or directory\n",
        ),
        ls(
            exited(1),
            "ls: /proc/no-such-entry: No such file or directory\n",
        ),
        ls(exited(1), "ls: /proc/: No such file or directory\n"),
        ls(
            exited(1),
            "ls: /proc/41: No such file or directory\nls: /proc/42: Permission denied\n",
        ),
        ls(exited(2), gone),
        // The wait status of a process SIGKILL ended.
        ls(9, ""),
    ] {
        assert!(!listed_but_for_exited_processes(&refused), "{refused:?}");
    }
}

/// Lines that are entirely digits, in a file the container wrote into `/out`.
fn numeric_entries(attempt_root: &Path, name: &str) -> usize {
    find_under(attempt_root, name).map_or(0, |p| count_numeric_lines(&p))
}

/// Lines that are entirely digits, in a host file.
fn count_numeric_lines(path: &Path) -> usize {
    std::fs::read_to_string(path).map_or(0, |text| {
        text.lines()
            .filter(|line| !line.is_empty() && line.chars().all(|c| c.is_ascii_digit()))
            .count()
    })
}

// ---------------------------------------------------------------------------
// A9 — writing outside the declared surface
// ---------------------------------------------------------------------------

oci_live_row!(
    attack_oci_cannot_write_outside_the_declared_mappings_live,
    a9_body
);

/// **A9.** TWO observations, for A2's reason. The control is a DRIVER observation
/// (`via=oci`) rather than a host run, because on this route the relaxed arm is
/// authorable: a write into a DECLARED mapping is a write the capsule asked for,
/// and the host reads its bytes back out of the attempt root the driver returned.
async fn a9_body() {
    let test = "attack_oci_cannot_write_outside_the_declared_mappings_live";
    let rig = Rig::build(test);
    let mut led = Ledger::new(A9_UNDECLARED_WRITE);
    let plan = Plan::default();
    rig.require_viable(test, &plan).await;

    // A write into `/out`, which the capsule declares read-write, lands and the HOST
    // can read it: the probe's write mechanism works inside a container at all, so
    // "the write failed" below is not a probe that could write nowhere. A CONTROL of
    // its own probe — it demonstrates the tool, not the attack.
    let declared = rig
        .run("echo declared-bytes > /out/declared && echo wrote", &plan)
        .await
        .unwrap_or_else(|refusal| {
            panic!("{test}: the route refused instead of running the declared arm: {refusal}")
        });
    let landed = find_under(&declared.attempt_root, "declared")
        .and_then(|p| std::fs::read_to_string(p).ok())
        .unwrap_or_default();
    led.control(
        "declared_mapping_write_lands",
        declared.ok() && landed.contains("declared-bytes"),
        &format!(
            "MAPPING DECLARED (`/out`, read-write): the container's write landed and the HOST \
             read the bytes back out of {} — {:?}",
            declared.attempt_root.display(),
            landed.trim(),
        ),
    );

    // 1. A path under NO mapping. The ATTACK — write wherever the stage likes —
    //    succeeds unconstrained: the same shell line on the host creates and writes
    //    a path nothing declared. The `/out` control above proves the tool and not
    //    this attack; this control proves the attack.
    let bb = bb();
    let loose = rig.host_only_dir().join("undeclared");
    let control = on_host(
        &mut led,
        &format!(
            "{bb} mkdir -p {d} && echo escaped > {d}/x && echo wrote || echo refused",
            d = loose.display()
        ),
    );
    let loose_bytes = std::fs::read_to_string(loose.join("x")).unwrap_or_default();
    led.control(
        "undeclared_path_write",
        host_text(&control).contains("wrote") && loose_bytes == "escaped\n",
        &format!(
            "UNCONSTRAINED (no container): a write to a path nothing declared ({}) landed — \
             read back with `std::fs`: {loose_bytes:?}",
            loose.join("x").display(),
        ),
    );
    let undeclared = rig
        .run(
            "echo escaped > /undeclared/x 2>&1 && echo wrote || echo refused",
            &plan,
        )
        .await
        .unwrap_or_else(|refusal| {
            panic!("{test}: the route refused instead of running: {refusal}")
        });
    let held = !undeclared.text().contains("wrote");
    led.contained(
        "undeclared_path_write",
        held,
        &verdict(
            held,
            &format!(
                "`/undeclared/x` is under no mapping the capsule declared and the write did not \
                 happen (exit {:?}) — {}",
                undeclared.exit_code,
                undeclared.text().trim(),
            ),
            &format!(
                "the container WROTE `/undeclared/x`, a path under no declared mapping — {}",
                undeclared.text().trim(),
            ),
        ),
    );

    // 2. A HOST absolute path, scored by reading the host with `std::fs` rather than
    //    by believing the container's exit code. The control writes the same path
    //    from the host and is read back the same way, then the original bytes are
    //    restored so the containment arm starts from them.
    let target = rig.host_only_dir().join("must-not-move");
    std::fs::write(&target, "ORIGINAL\n").expect("the host file this write must not reach");
    let control = on_host(
        &mut led,
        &format!(
            "echo escaped > {} && echo wrote || echo refused",
            target.display()
        ),
    );
    let moved = std::fs::read_to_string(&target).unwrap_or_default();
    led.control(
        "host_absolute_path_write",
        host_text(&control).contains("wrote") && moved == "escaped\n",
        &format!(
            "UNCONSTRAINED (no container): the same write to {} changed its bytes to {moved:?}",
            target.display(),
        ),
    );
    std::fs::write(&target, "ORIGINAL\n").expect("the host file is restored");
    let host_write = rig
        .run(
            &format!(
                "echo escaped > {} 2>&1 && echo wrote || echo refused",
                target.display()
            ),
            &plan,
        )
        .await
        .unwrap_or_else(|refusal| {
            panic!("{test}: the route refused instead of running: {refusal}")
        });
    let after = std::fs::read_to_string(&target).expect("the host file is still readable");
    let held = after == "ORIGINAL\n";
    led.contained(
        "host_absolute_path_write",
        held,
        &verdict(
            held,
            &format!(
                "a write to the HOST absolute path {} left its bytes unchanged, read back from \
                 OUTSIDE the container with `std::fs` — container said: {}",
                target.display(),
                host_write.text().trim(),
            ),
            &format!(
                "the container CHANGED the host file {} to {after:?} — container said: {}",
                target.display(),
                host_write.text().trim(),
            ),
        ),
    );
    led.finish();
}

/// The first entry named `name` anywhere under `root`.
///
/// `/out`'s host-side location is the driver's business and not this rig's — it
/// returns the attempt root and owns the layout beneath it — so the file is found
/// rather than composed from a path this file would then be a second producer of.
fn find_under(root: &Path, name: &str) -> Option<PathBuf> {
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir).into_iter().flatten().flatten() {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
            } else if path.file_name().and_then(|n| n.to_str()) == Some(name) {
                return Some(path);
            }
        }
    }
    None
}

// ---------------------------------------------------------------------------
// A10 — environment nobody declared
// ---------------------------------------------------------------------------

oci_live_row!(
    attack_oci_stage_reads_no_undeclared_environment_live,
    a10_body
);

/// **A10.** The sentinel is in THIS process's environment — planted on the
/// delegated re-exec, because `set_var` is `unsafe` in a multi-threaded process
/// and this workspace denies `unsafe_code`. A host child inherits it; the
/// container's init must not, because a capsule declares its environment and
/// nothing else reaches the container.
async fn a10_body() {
    let test = "attack_oci_stage_reads_no_undeclared_environment_live";
    let rig = Rig::build(test);
    let mut led = Ledger::new(A10_CLEARED_ENV);
    let plan = Plan::default();
    rig.require_viable(test, &plan).await;

    assert_eq!(
        std::env::var(ENV_SENTINEL_KEY).ok().as_deref(),
        Some(ENV_SENTINEL_VALUE),
        "{test}: this process does not carry {ENV_SENTINEL_KEY}, so there is no undeclared \
         variable for a container to fail to see. It is planted on the `systemd-run` child in \
         `delegated`; a row reached without that re-exec cannot make this observation."
    );

    let script = "env";
    let control = on_host(&mut led, script);
    let control_text = host_text(&control);
    led.control(
        "worker_process_environment",
        control_text.contains(ENV_SENTINEL_VALUE),
        &format!(
            "UNCONSTRAINED (no container): a plain host child inherited {ENV_SENTINEL_KEY} \
             wholesale — {} variables, the sentinel among them",
            control_text.lines().count()
        ),
    );

    let inside = rig.run(script, &plan).await.unwrap_or_else(|refusal| {
        panic!("{test}: the route refused instead of running: {refusal}")
    });
    let observed = inside.text();
    let held = !observed.contains(ENV_SENTINEL_VALUE) && !observed.contains(ENV_SENTINEL_KEY);
    led.contained(
        "worker_process_environment",
        held,
        &verdict(
            held,
            &format!(
            "INSIDE the planned container the environment holds {} variable(s) and neither \
             {ENV_SENTINEL_KEY} nor its value is among them — a capsule's environment is what \
             `spec_for` renders, and the kata process's own is not an input to it",
            observed.lines().count()
        ),
            &format!(
                "INSIDE the planned container {ENV_SENTINEL_KEY} or its value IS visible — a variable no capsule declared reached the stage"
            ),
        ),
    );
    led.finish();
}

/// The certification this rig drove, echoed so a reader of the log can tell WHICH
/// runtime produced these verdicts.
///
/// Not a row and not counted: it makes no containment claim. It exists because
/// every verdict above is about a container started by one specific pinned
/// binary, and a log that did not say which one could be quoted against a
/// different host's.
#[test]
#[ignore = "needs a certifiable pinned youki (see any row's ignore text) AND \
            a delegated user scope — `certify_youki` measures cgroup delegation where a STAGE \
            cgroup would be created, and a login session's scope is not delegated on the reference host \
            (measured: `mkdir …/session-NNNN.scope/.kata-bounds-probe-… : Permission denied`), so \
            this runs inside `systemd-run --user --scope -p Delegate=yes` like every row above. \
            Prints the measured basis these verdicts were produced under."]
fn the_oci_column_names_the_runtime_it_measured_live() {
    common::adversarial::bind_driver(ExecutionDriver::OciRuntime);
    delegated(
        "the_oci_column_names_the_runtime_it_measured_live",
        basis_body(),
    );
}

// `async` with nothing to await, because `delegated` takes a future — the row runs
// inside a delegated scope for the reason its `#[ignore]` text gives, and the one
// shape that re-execs into one is the future-taking helper every other row uses.
#[allow(clippy::unused_async)]
async fn basis_body() {
    let certification = certify_youki(YoukiPin::embedded())
        .unwrap_or_else(|refusal| panic!("this host cannot certify the pinned youki: {refusal}"));
    let basis = kata_worker::provider_supervisor::measured_basis_from_certification(&certification);
    println!(
        "ADVERSARIAL-KERNEL-SUITE BASIS driver=oci_runtime youki={} sha256={} version={} \
         residue-denied={}",
        basis.youki.store_path, basis.youki.sha256, basis.youki_version, basis.residue_denied,
    );
    assert!(
        basis.residue_denied,
        "kata's OCI fence does not name every `ConstructionResidue` syscall, so A1' above is not \
         measuring the mechanism it claims to"
    );
}
