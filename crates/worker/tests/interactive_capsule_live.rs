//! A REAL long-lived process inside a REAL rootless
//! container, spoken to over live stdio, and torn down with the attempt.
//!
//! # The one property this file exists for
//!
//! *An agent's process can run inside the capsule and kata can talk to it while it
//! runs.* Every layer under that has been proven separately — the runtime is
//! certified, the bundle is planned, the provider starts it, the driver composes them
//! — and all of it is for a ONE-SHOT: start, print, exit, read the capture. An agent
//! is the opposite shape, and this file establishes that the shape is reachable at
//! all.
//!
//! # The mechanism, MEASURED before it was designed (reference host)
//!
//! A throwaway rootless bundle running `busybox cat`, started with
//! `youki run --bundle … ` and `process.terminal = false`, echoed `hello-from-host`
//! back on the RUNTIME CLIENT's own stdout after the host wrote that line to the
//! client's stdin; closing the client's stdin gave `cat` its EOF and a clean exit
//! `0`. So a container's init inherits the client's three descriptors, and the whole
//! of the stdio bridge is three FIFOs kata names and the provider opens.
//!
//! The alternative measured in the same session and REJECTED: `youki exec` into the
//! running container fails `EPERM` (`failed to set namespace … typ: Pid`) under
//! rootless on the reference host, so no SECOND process can be added to a container this route
//! started — which is why terminal callbacks are refused by name rather than served
//! (the measurement is recorded on `kata_provider_protocol::OciStdio`).
//!
//! # Every verdict is read off the HOST
//!
//! The echo is read off the pipe, and everything after it is read off something that
//! does not share the code under test: `youki --root <state> list` for the
//! container's registration and its absence, and the filesystem for the kata-owned
//! cgroup directory. A rig that asked [`InteractiveCapsule::teardown`] whether it
//! had torn anything down would be asking kata whether kata worked — which is the
//! false `Confirmed` the kata-owned parent exists to close, re-created in a test.
//!
//! # It REFUSES on this host until the profile is installed
//!
//! `certify_youki` refuses `profile_file_differs` until the pinned runtime's
//! AppArmor profile is loaded (`sudo kata host apparmor-install`), and this file FAILS naming it rather than skipping. That is the
//! no-skip rule working: the claim above is made nowhere until this has run green.

#![cfg(target_os = "linux")]

mod common;

use std::os::unix::process::ExitStatusExt as _;
use std::path::{Path, PathBuf};
use std::time::Duration;

use kata_agent::adapter::Signal;
use kata_test_utils::youki_registry::youki_list;
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
use kata_worker::interactive_capsule::InteractiveCapsule;
use kata_worker::materialize::{BlobSource, StorePathProbe, TreeResolver};
use kata_worker::oci_driver::{
    OCI_PROVIDER_NAME, OciProviderInstallation, OciStageDriver, OciStageRequest,
};
use kata_worker::oci_runtime::certify_youki;
use kata_worker::provider_supervisor::{ProviderLaunchSpec, ProviderSupervisor};
use tokio::io::{AsyncBufReadExt as _, AsyncWriteExt as _};

/// The same real store path every OCI live file names. One statically linked busybox
/// is the whole closure.
const BUSYBOX: &str =
    "/nix/store/qddzvnv6b0805nkvbqddbswddcfhx814-busybox-static-x86_64-unknown-linux-musl-1.37.0";
const BUSYBOX_NAR_HASH: &str = "sha256-d7JNm1d4Wo1oSA2pvoRLt1vqyAhSlIsjE0GckcLiSeA=";
const BUSYBOX_NAR_SIZE: u64 = 1_495_056;

/// The line the host writes into the init's stdin and must read back on its
/// stdout. Distinctive, so a match cannot be something else's output.
const PROMPT: &str = "kata-live-prompt";

/// What the busybox init's `SIGTERM` handler prints before it exits.
const TRAPPED: &str = "trapped:TERM";

fn hash(byte: u8) -> ContentHash {
    ContentHash::new([byte; 32])
}

fn environment() -> NixEnvironmentManifest {
    NixEnvironmentManifest::new(
        "interactive-capsule-busybox",
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

fn mapping(path: &str, artifact: u8) -> GuestMapping {
    GuestMapping {
        artifact: ArtifactId(hash(artifact)),
        guest_path: GuestPath::new(path.to_owned()).expect("a guest path"),
        access: GuestAccess::ReadWrite,
    }
}

/// The three materializable roots and nothing else: the environment closure is BOUND
/// at its own store paths by the runtime, so a `/nix/store` mapping is not a tree the
/// materializer places (it refuses one by name).
fn capsule(argv: Vec<smol_str::SmolStr>) -> Capsule {
    Capsule::new(
        OccurrenceId(hash(0x5a)),
        PreparedActionId(hash(2)),
        EnvironmentId(hash(3)),
        PlatformRef::new("x86_64-linux", hash(11)).id(),
        vec![
            mapping("/work", 20),
            mapping("/out", 21),
            mapping("/tmp", 22),
        ],
        CapsuleProcess::Command { argv },
        CapsuleNetwork::Offline,
        None,
        CapsuleBudgets {
            // The init is spoken to for the whole attempt, and this is the budget
            // the supervisor reads the terminal frame under — so it bounds the LIVE
            // conversation, not one command.
            wall_time_ms: 90_000,
            output_bytes: 1 << 20,
            memory_bytes: 512 * 1024 * 1024,
            // MEASURED: codex's tokio runtime scales workers to the
            // host's core count (128 on the reference host) plus a blocking pool — 64 tasks
            // exactly filled pids.max and the starved init hung silent for the
            // full deadline. 512 is the same generous bound
            // `oci_adversarial_live`'s pids cell relaxes to, and it is exactly
            // the number an operator's `NodeBudgetDefaults` must clear for
            // this init.
            process_count: 512,
            result_bytes: 4 * 1024 * 1024,
            result_entries: 128,
            work_delta_bytes: kata_types::execution_contract::CAPSULE_WORK_DELTA_BYTES,
            work_delta_entries: kata_types::execution_contract::CAPSULE_WORK_DELTA_ENTRIES,
        },
        None,
    )
    .expect("the fixture capsule is well formed")
}

/// Every mapped tree is EMPTY: this proof is about the process and its stdio, and a
/// file in `/work` would be a second thing to be wrong.
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
             for a reference, and answering would be a second, invented claim about the id"
        );
    }
}

/// Reached for no member, because every tree is empty. It PANICS rather than
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
        panic!(
            "no member's bytes should be read: every mapped tree in this fixture is empty ({object:?})"
        )
    }
}

/// The real host's store, because the container rbinds the closure at its own store
/// path and a fabricated `true` here would bind a directory that is not there.
struct RealStore;

impl StorePathProbe for RealStore {
    fn present(&self, path: &StorePath) -> KataResult<bool> {
        Ok(Path::new(path.as_str()).is_dir())
    }
}

const INNER_ENV: &str = "KATA_A3_INTERACTIVE_DELEGATED_INNER";

/// Run an async `body` inside a delegated user scope, re-exec'ing this binary if
/// needed — the same shape `oci_provider_live.rs` and `oci_stage_live.rs` use, and
/// re-spelled for their stated reason: what must not be duplicated is WHAT a
/// delegated scope is, which is one `systemd-run` argv here and there and the fact
/// `just _containment-preconditions` blocks its lane on.
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
        "`{name}` is not next to the test binary, and it IS the instrument of this proof. `cargo \
         nextest run -p kata-worker` does NOT build it. Run `cargo build -p kata-provider-youki \
         --bin kata-provider-youki` in the same command, which is also what keeps a STALE one \
         from being driven."
    );
}

/// Provision the freshly built `kata-provider-youki` into a by-hash provider store
/// this rig owns, exactly as an operator provisions the youki provider.
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

// ---------------------------------------------------------------------------
// The exit criterion
// ---------------------------------------------------------------------------

/// **A long-lived process inside a real container, spoken to, signalled, and gone.**
///
/// **Would red if:** the container's stdin were `/dev/null` (the echo would never
/// arrive and the read would time out), its stdout went to a file (same), the FIFOs
/// were opened in the wrong order (both processes would block before the container
/// started), `signal` did not reach the init inside its own pid namespace (the wait
/// would not return), or the teardown left the container registered or its cgroup
/// directory behind (the runtime's own `list` and the filesystem would say so).
#[test]
#[ignore = "HOST-DEPENDENT (pinned youki, its INSTALLED AppArmor profile, a \
            delegated user scope, the fixture closure's store path realised) AND \
            instrument-dependent (`cargo build -p kata-provider-youki`). On a host where the \
            pinned runtime's profile has not been installed this FAILS with \
            `profile_file_differs` — run `sudo kata host \
            apparmor-install` first. `just gate` is host-independent by design, so this rides the \
            containment side like its four OCI siblings. Run it now with `cargo build -p \
            kata-provider-youki --bin kata-provider-youki && cargo nextest run -p kata-worker -P live-smoke -E \
            'binary(interactive_capsule_live)' --run-ignored all`."]
fn an_interactive_capsule_talks_over_live_stdio_and_is_torn_down_live() {
    delegated(
        "an_interactive_capsule_talks_over_live_stdio_and_is_torn_down_live",
        an_interactive_capsule_body(StateFileAtSignal::AsTheRuntimeLeftIt),
    );
}

/// **A signal sent while the runtime's state file is unreadable still reaches the
/// init.**
///
/// Upstream youki 0.7.0's `State::save` opened `state.json` with `O_TRUNC` and only
/// then wrote it, so a reader between the two saw an EMPTY file, and a `youki kill`
/// there failed `EOF while parsing a value at line 1 column 0`. MEASURED on the
/// unpatched build by delaying that `write(2)` with strace fault injection
/// (`write:delay_enter`): the user process had printed, the file was 0 bytes, and
/// `youki kill` failed with exactly that error. The pinned build saves by temporary
/// file and rename (`nix/youki-0.7.0-atomic-state-save.patch`), so no runtime
/// writer leaves that file now; this cell pins the other half — `signal`'s wait
/// reads an unreadable state as "not running yet" rather than signalling into it.
///
/// It holds the window open deterministically: it empties the state file once the
/// start has completed and restores the runtime's own bytes [`TORN_STATE_HOLD`]
/// later, from another thread, while `signal` runs.
///
/// **Would red if:** `signal` ran `youki kill` without first waiting for the
/// runtime to report the container `running` — the kill would read the empty file.
#[test]
#[ignore = "same host contract as `an_interactive_capsule_talks_over_live_stdio_and_is_torn_down_live`."]
fn a_signal_inside_the_runtimes_state_write_reaches_the_init_live() {
    delegated(
        "a_signal_inside_the_runtimes_state_write_reaches_the_init_live",
        an_interactive_capsule_body(StateFileAtSignal::TornByAnInFlightSave),
    );
}

/// What the busybox body does to the runtime's `state.json` as it signals.
#[derive(Clone, Copy)]
enum StateFileAtSignal {
    /// Nothing.
    AsTheRuntimeLeftIt,
    /// Empty it for [`TORN_STATE_HOLD`], then restore the runtime's own bytes —
    /// what upstream youki 0.7.0's in-place `State::save` left between its
    /// `O_TRUNC` open and its `write`.
    TornByAnInFlightSave,
}

/// How long [`StateFileAtSignal::TornByAnInFlightSave`] keeps the state file empty.
/// Far longer than any `youki kill` takes on an idle host, so an unguarded kill
/// lands inside it every time.
const TORN_STATE_HOLD: Duration = Duration::from_millis(750);

/// Empty `<state>/<container>/state.json` now and restore it after
/// [`TORN_STATE_HOLD`] on another thread. Waits first for the file to hold the
/// runtime's completed `running` save, so what is restored is exactly what the
/// runtime wrote.
fn tear_state_file(state: &Path, container: &str) -> std::thread::JoinHandle<()> {
    let path = state.join(container).join("state.json");
    let mut saved = None;
    for _ in 0..200 {
        let bytes = std::fs::read(&path).expect("the runtime's state file is readable");
        let running = serde_json::from_slice::<serde_json::Value>(&bytes)
            .is_ok_and(|state| state["status"] == "running");
        if running {
            saved = Some(bytes);
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    let saved = saved.unwrap_or_else(|| {
        panic!(
            "{path} never held a completed `running` state within 2s, so there is no start \
             for this cell to tear",
            path = path.display(),
        )
    });
    std::fs::File::create(&path)
        .expect("the state file is truncated, as upstream `State::save` did");
    std::thread::spawn(move || {
        std::thread::sleep(TORN_STATE_HOLD);
        std::fs::write(&path, saved).expect("the runtime's own state bytes are restored");
    })
}

async fn an_interactive_capsule_body(state_file: StateFileAtSignal) {
    assert!(
        Path::new(BUSYBOX).join("bin/busybox").is_file(),
        "the closure's only store object is not realised at {BUSYBOX}. The container rbinds that \
         exact path and execs the binary inside it, so there is nothing to observe without it. \
         Realise it with `nix-store --realise {BUSYBOX}`."
    );

    // KATA'S OWN MEASUREMENT. A host that cannot certify fails HERE, naming the
    // refusal — there is no skip on purpose.
    let certification = certify_youki(YoukiPin::embedded()).unwrap_or_else(|refusal| {
        panic!(
            "this host cannot deliver the rootless-OCI prerequisite, so there is no container to \
             put an interactive process in: {refusal}. `just _containment-preconditions` gives the \
             one-line diagnosis."
        )
    });

    let root = tempfile::tempdir().expect("a temporary worker state root");
    // Declared AFTER the `TempDir` so it drops BEFORE it: the by-hash provider store is
    // sealed `0500`, which `TempDir`'s own removal cannot get through. See
    // `kata_worker::UnsealOnDrop`.
    let _unseal = kata_worker::UnsealOnDrop::new(root.path());
    let driver = OciStageDriver::new(
        OciRoute::new(certification),
        root.path().join("worker-state"),
        install_provider(root.path()),
    );

    // `sh -c 'trap …; while read line; do echo "got:$line"; done'` — a process that
    // stays alive, answers on demand, and is therefore an agent's shape rather than a
    // stage's. `busybox sh` and not `cat`, so the answer is DERIVED from the prompt:
    // a `cat` would echo bytes a mis-wired pipe could also have echoed.
    //
    // # THE `trap` IS LOAD-BEARING, and the reason is a KERNEL RULE
    //
    // MEASURED on a host with the pinned youki's AppArmor profile installed:
    // without the trap, `signal(Terminate)` ->
    // `youki kill --signal TERM` is DELIVERED AND IGNORED, and `wait()` times out at
    // 30 s. That is not a defect in the signal path — it is `kernel/signal.c`'s rule
    // for a process that is PID 1 IN ITS OWN PID NAMESPACE: a signal from outside the
    // namespace is discarded unless the init has installed a handler for it, with
    // SIGKILL and SIGSTOP the only exceptions. A container init with no `SIGTERM`
    // handler cannot be politely stopped BY ANYTHING, so a rig that expected it to be
    // was asking the kernel for something it does not do.
    //
    // Installing the handler is the right repair rather than switching the test to
    // `Kill`, and it makes the claim STRONGER: the trap firing is positive evidence
    // that the signal arrived and was acted on, where a container that merely died
    // could have died of anything. It is also an ordinary agent shape — a process
    // catching `SIGTERM` to flush a session file is ordinary — so the fixture models
    // the process the bounded-`close()` design was written for instead of one no
    // polite signal can reach.
    //
    // The handler ANSWERS before it exits: [`TRAPPED`] on the init's stdout is
    // that positive evidence, read off the conversation itself. It then exits
    // 143 = 128 + SIGTERM, a non-zero status — but the status alone cannot carry the
    // proof; see the assertion after `wait()`.
    //
    // As of execution contract v5 this vector is a field of the CAPSULE (folded into
    // `CapsuleId`) rather than of `OciStageRequest`, so it is handed to the fixture
    // instead of to the request.
    let environment = environment();
    let capsule = capsule(vec![
        smol_str::SmolStr::new(format!("{BUSYBOX}/bin/busybox")),
        smol_str::SmolStr::new("sh"),
        smol_str::SmolStr::new("-c"),
        smol_str::SmolStr::new(format!(
            "trap 'echo {TRAPPED}; exit 143' TERM; while read line; do echo \"got:$line\"; done"
        )),
    ]);
    let trees = EmptyTrees;
    let source = BytesForbidden;
    let probe = RealStore;
    let request = OciStageRequest {
        capsule: &capsule,
        environment: &environment,
        network: NetPolicy::Offline,
        trees: &trees,
        source: &source,
        probe: &probe,
        execution_id: ulid::Ulid::new(),
    };

    // `vendor-live`: the tag the verbatim `youki kill` reports
    // `interactive_capsule::tests` pins were captured under.
    let capsule = InteractiveCapsule::launch(&driver, "vendor-live", &request)
        .await
        .unwrap_or_else(|refusal| panic!("the interactive container did not start: {refusal}"));

    // Read from the HOST before anything else: the runtime's own registry names the
    // container, which is what makes every later assertion about its ABSENCE mean
    // something.
    let state = capsule.runtime_state().to_path_buf();
    let container = capsule.container_id().to_owned();
    // POLLED, not sampled once. MEASURED: the
    // provider's `accepted` frame and youki's own state file are not the same instant,
    // so roughly one launch in three listed nothing here while the container was
    // starting normally. A single sample would make this assertion a coin flip about a
    // property that is not in doubt — the registry is the BASELINE for the absence
    // asserted after teardown, and 2 s is far inside the 90 s attempt budget.
    let mut listed = youki_list(&state);
    for _ in 0..40 {
        if listed.contains(&container) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
        listed = youki_list(&state);
    }
    assert!(
        listed.contains(&container),
        "the pinned runtime's own `list` does not name container `{container}` within 2s of the \
         provider accepting it, so there is no live container for this proof to be \
         about:\n{listed}"
    );

    // THE SPLIT, before the conversation: the session's process half (stdio,
    // signal, wait) and the container's teardown half, as the composition
    // holds them.
    let (mut process, placement) =
        kata_worker::interactive_capsule::InteractivePlacement::into_halves(Box::new(capsule));

    // THE PROPERTY. Write a line into the init's stdin and read its answer off the
    // init's stdout, while the container runs.
    let mut stdin = process.take_stdin().expect("the init's stdin");
    let mut lines =
        tokio::io::BufReader::new(process.take_stdout().expect("the init's stdout")).lines();
    stdin
        .write_all(format!("{PROMPT}\n").as_bytes())
        .await
        .expect("the prompt is written into the init's stdin");
    stdin.flush().await.expect("the prompt is flushed");

    let answer = tokio::time::timeout(Duration::from_secs(30), lines.next_line())
        .await
        .unwrap_or_else(|_| {
            panic!(
                "no line arrived on the init's stdout within 30s. The container's stdio is \
                 either not connected to kata's FIFOs at all, or connected in the wrong \
                 direction; container `{container}` state root {state}",
                state = state.display(),
            )
        })
        .expect("the init's stdout reads as UTF-8 lines")
        .expect("the init answered before EOF");
    assert_eq!(
        answer,
        format!("got:{PROMPT}"),
        "the init did not answer the prompt it was given, so the two FIFOs are not one live \
         conversation"
    );

    // Where kata created the cgroup, read as a HOST path WHILE THE CONTAINER IS
    // PROVABLY ALIVE — it has just answered on its own stdout — so the absence
    // asserted after the teardown is about a directory that existed.
    //
    // MEASURED: this read cannot sit AFTER `wait()` — by the time the init's exit
    // has been reported the kernel may already have released its cgroup, so the "it
    // existed" half would race the very teardown it is the baseline for. Ordering it here
    // costs nothing and removes the race: the conversation above is the proof the
    // container is running.
    let cgroup = common::cgroup_leaf(&container);
    assert!(
        cgroup.as_ref().is_some_and(|leaf| leaf.is_dir()),
        "kata's own parent cgroup for container `{container}` is not a directory while the \
         container is still answering on its stdout, so there is nothing for the sweep to \
         confirm the absence of: {cgroup:?}"
    );

    // Signal the INIT, through `youki kill`. `Terminate` and not `Kill`, so what is
    // proven is that a POLITE signal reaches a process kata is not the parent of —
    // which is only observable because the fixture installs a `SIGTERM` trap; see the
    // capsule argv above for the kernel rule that makes the handler mandatory.
    let torn = match state_file {
        StateFileAtSignal::AsTheRuntimeLeftIt => None,
        StateFileAtSignal::TornByAnInFlightSave => Some(tear_state_file(&state, &container)),
    };
    process
        .signal(Signal::Terminate)
        .await
        .expect("SIGTERM is delivered to the container's init");
    if let Some(restorer) = torn {
        restorer.join().expect("the state file restorer finished");
    }
    let trapped = tokio::time::timeout(Duration::from_secs(30), lines.next_line())
        .await
        .unwrap_or_else(|_| {
            panic!(
                "the init's TERM handler printed nothing within 30s of a SIGTERM `signal` \
                 reported delivered; container `{container}`"
            )
        })
        .expect("the handler's line reads as UTF-8")
        .expect("the TERM handler answered before EOF");
    assert_eq!(
        trapped, TRAPPED,
        "the init's next line after the signal is not its TERM handler's, so nothing shows \
         the signal reached the handler"
    );
    let status = tokio::time::timeout(Duration::from_secs(30), process.wait())
        .await
        .expect("the provider reports the container's exit within 30s")
        .expect("the terminal frame decodes");
    // The handler's 143, or no exit status at all — never youki's own 255. When
    // `youki kill`'s `stopped` save lands inside the foreground `youki run`'s delete
    // of the container directory, that delete fails `ENOTEMPTY` and the client exits
    // 255, the init's 143 discarded (MEASURED on the pinned binary; see
    // `InteractiveCapsuleHandle::signal`). The provider then finds the directory that
    // delete left and reports no exit status, which `wait` returns as a `SIGKILL`
    // status. The handler's line above is the proof the signal landed, and the
    // teardown below still finds nothing left.
    assert!(
        status.code() == Some(143) || status.signal() == Some(9),
        "a container whose init trapped SIGTERM and exited 143 reports that, or no exit status \
         when the runtime client failed after it; got {status}"
    );

    let teardown = kata_worker::interactive_capsule::InteractiveTeardown::teardown(placement).await;
    assert!(
        teardown.is_confirmed(),
        "the teardown must be CONFIRMED by a probe and not merely attempted: {teardown:?}"
    );

    // THE HOST'S OWN ANSWERS, after the fact.
    let listed = youki_list(&state);
    assert!(
        !listed.contains(&container),
        "container `{container}` is still registered with the runtime after teardown:\n{listed}"
    );
    if let Some(leaf) = cgroup {
        assert!(
            !leaf.exists(),
            "the kata-owned cgroup directory {leaf} survived the teardown, so the container's \
             residue is unaccounted for",
            leaf = leaf.display(),
        );
    }
}

// ---------------------------------------------------------------------------
// The FRAME ORDERING on the interactive arm — no youki, no cgroup, no container
// ---------------------------------------------------------------------------

/// **On an `interactive` plan the provider REFUSES without accepting first; on a
/// `captured` plan it accepts first, exactly as it always did.**
///
/// # Why this ordering is a correctness property and not a style
///
/// Kata opens its end of the three FIFOs before it assigns and reads as soon as it has
/// an `accepted`. A read-only FIFO whose writer has not opened yet reads `Ok(0)` at the
/// syscall — MEASURED, and pinned by
/// `kata_worker::interactive_capsule`'s `an_output_fifo_with_no_writer_yet_reads_as_eof_at_the_syscall`
/// — so an acceptance sent before the provider had opened the two write ends would let
/// a codec see the init's stream end before its first byte and latch the turn
/// AMBIGUOUS on a container that was starting normally. Deferring acceptance until
/// after the spawn is what closes that, and the observable consequence is exactly this
/// frame order.
///
/// # It needs no certified youki, which is why it is the one case here that RUNS
///
/// Nothing is started: the plan's `cgroup_parent` is a directory that does not exist,
/// which `verify_cgroup_parent` refuses before a bundle is written, before the runtime
/// is digested and before anything is spawned. The measured basis is a FIXTURE — the
/// provider echoes whatever `--measured-basis` it is handed, so admission needs no
/// measurement — and it is never used by a case that starts a container.
///
/// **Would red if:** the provider answered `accepted` before `start_container` on the
/// interactive arm (the first assertion sees an acceptance), or if deferring leaked
/// onto the captured arm (the second sees a refusal where an acceptance belongs).
#[test]
#[ignore = "instrument-dependent — it drives the real `kata-provider-youki`, which `cargo nextest run -p kata-worker` does NOT build. It needs NO youki, no AppArmor profile, no cgroup delegation and no container: the plan it sends is refused before anything is written. Run it with `cargo build -p kata-provider-youki --bin kata-provider-youki && cargo nextest run -p kata-worker -P live-smoke -E             'binary(interactive_capsule_live)' --run-ignored all`."]
fn the_interactive_arm_refuses_before_accepting_and_the_captured_arm_after() {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("a tokio runtime")
        .block_on(frame_ordering_body());
}

async fn frame_ordering_body() {
    let binary = workspace_bin("kata-provider-youki");
    let root = tempfile::tempdir().expect("a temporary attempt root");
    // A parent cgroup that does not exist: `verify_cgroup_parent` refuses it, which is
    // the FIRST check in `start_container` and therefore the one that reaches the
    // fewest side effects.
    let absent_parent = root.path().join("no-such-cgroup");

    for interactive in [true, false] {
        let mut spec = ProviderLaunchSpec::production(
            binary.clone(),
            OCI_PROVIDER_NAME,
            Duration::from_secs(30),
        );
        spec.measured_basis = Some(fixture_basis());
        spec.handshake_timeout = Duration::from_secs(30);
        spec.stage_timeout = Duration::from_secs(30);
        let mut supervisor = ProviderSupervisor::launch(&spec)
            .await
            .expect("the freshly built provider launches and is admitted on the fixture basis");

        let plan = kata_provider_protocol::OciBundlePlan {
            config_json: r#"{"ociVersion":"1.1.0"}"#.to_owned(),
            rootfs_mountpoints: vec!["/work".to_owned()],
            container_id: "kata-frame-ordering-probe".to_owned(),
            youki: kata_provider_protocol::PinnedRuntime {
                store_path: "/nix/store/0000000000000000000000000000000f-youki/bin/youki"
                    .to_owned(),
                sha256: "f".repeat(64),
            },
            cgroup_parent: Some(absent_parent.display().to_string()),
            state_root: root.path().join("oci").display().to_string(),
            stdio: if interactive {
                kata_provider_protocol::OciStdio::Interactive(
                    kata_provider_protocol::InteractiveStdio {
                        stdin_fifo: root.path().join("io/stdin").display().to_string(),
                        stdout_fifo: root.path().join("io/stdout").display().to_string(),
                        stderr_fifo: root.path().join("io/stderr").display().to_string(),
                    },
                )
            } else {
                kata_provider_protocol::OciStdio::Captured
            },
            egress_hook: None,
        };
        // A FRESH spool dir per arm: the supervisor must create it itself (v6's
        // contract is "created EMPTY by the supervisor"), and the first arm's run
        // leaves its `capture/` behind — sharing one path would fail the second
        // arm's existence check for a reason that is not the check under test.
        let capture = kata_provider_protocol::CaptureSpec {
            spool_dir: root
                .path()
                .join(format!("capture-{interactive}"))
                .to_string_lossy()
                .into_owned(),
            limit_bytes: 64 * 1024 * 1024,
        };
        let assignment = kata_worker::provider_supervisor::StageAssignment {
            assignment_id: "frame-ordering",
            capture: &capture,
        };

        let accepted = supervisor.assign_stage(assignment, plan).await;
        let refusal = supervisor
            .stage_refusal()
            .map(|refused| refused.reason.clone());

        if interactive {
            assert!(
                accepted.is_err(),
                "on an INTERACTIVE plan the provider must refuse WITHOUT accepting first: kata reads as soon as it has an acceptance, and a FIFO with no writer yet reads as EOF. It accepted instead."
            );
            let reason = refusal.expect(
                "the refusal must arrive as a typed `refused` frame about this assignment, not only as an error string",
            );
            assert!(
                reason.contains("parent cgroup"),
                "the pre-acceptance refusal must be the cgroup-parent check, which is the first thing `start_container` does; got: {reason}"
            );
        } else {
            let accepted = accepted.expect(
                "on a CAPTURED plan the provider must accept FIRST — the abrupt-teardown crash proof builds its kill on that acceptance being observable early",
            );
            assert_eq!(accepted.assignment_id, "frame-ordering");
            let completed = supervisor.await_stage_completion("frame-ordering").await;
            assert!(
                completed.is_err(),
                "the same plan must still be refused on the captured arm, just AFTER the acceptance"
            );
            assert!(
                supervisor
                    .stage_refusal()
                    .is_some_and(|refused| refused.reason.contains("parent cgroup")),
                "and for the same reason"
            );
        }
        let _ = supervisor.shutdown().await;
    }
}

/// A measured basis by field literal, for the case that refuses before a container is
/// planned. A FIXTURE and not a measurement: the provider echoes whatever
/// `--measured-basis` it is handed, so admission needs no certified youki, and no case
/// that starts a container uses this.
fn fixture_basis() -> kata_provider_protocol::OciMeasuredBasis {
    kata_provider_protocol::OciMeasuredBasis {
        youki: kata_provider_protocol::PinnedRuntime {
            store_path: "/nix/store/0000000000000000000000000000000f-youki/bin/youki".to_owned(),
            sha256: "f".repeat(64),
        },
        youki_version: "0.7.0".to_owned(),
        libseccomp_version: "2.6.1".to_owned(),
        apparmor_profile_name: "youki".to_owned(),
        apparmor_profile_sha256: "e".repeat(64),
        userns_restriction: kata_provider_protocol::MeasuredUsernsRestriction::Restricted,
        delegated_cgroup_parent: None,
        functional_probe_id: "kata-frame-ordering-fixture".to_owned(),
        residue_denied: false,
    }
}
