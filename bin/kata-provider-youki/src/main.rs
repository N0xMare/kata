//! `kata-provider-youki` — the out-of-process provider that STARTS the
//! rootless OCI container kata already described in full.
//!
//! # What it applies, and what it decides: nothing
//!
//! It re-hosts kata's certified `config.json`. [`OciBundlePlan::config_json`] is written into the
//! bundle BYTE FOR BYTE — never parsed, never re-serialized, never merged with a
//! default — and the runtime that reads it is the exact store path kata pinned,
//! whose digest this process re-derives before `execve`ing it. So every
//! containment property of the resulting container is kata's:
//! `kata_worker::oci_bundle::spec_for` chose the namespaces, the mounts, the
//! bounds and the whole deny-list's `linux.seccomp`, and this process chose the order of
//! four subprocess calls.
//!
//! # Its certificate says `provider_enforced`
//!
//! The containment around the stage is not an argv kata composed — it is the
//! rootless OCI runtime this process `execve`s, which unshares the namespaces,
//! loads the fence and applies the bounds. A claim to enforce it is admissible
//! only beside kata's own measurement of it:
//! `kata_worker::oci_runtime::certify_youki` is that measurement, and the
//! supervisor hands it to this process as `--measured-basis <json>` —
//! `kata_provider_protocol::OciMeasuredBasis`, which the certificate ECHOES
//! unchanged. `admit` admits the claim only when the echo is byte-equal to what
//! kata measured in this process, so nothing here can invent, improve, or carry
//! forward a basis.
//!
//! **The basis is REQUIRED.** Without it this binary has no admissible thing to
//! say: `provider_enforced` is the protocol's only containment claim, and there
//! is no measurement for it to rest on. It exits 2 before writing a frame, which
//! is the fail-closed direction — a supervisor that could not certify the host
//! must not get a running container out of this process.
//!
//! # The five refusals of a plan
//!
//! Each one is a thing kata said that this process cannot honour exactly, and in
//! every case the alternative is a container that ran somewhere other than where
//! kata said, or under something other than what kata pinned:
//!
//! * a `state_root` that is relative, or that carries a `..` component — see
//!   [`attempt_state_root`]. There is no directory this process may choose instead;
//! * a digest mismatch at [`PinnedRuntime::store_path`];
//! * NO `cgroup_parent`; a `cgroup_parent` that is not a cgroup v2 directory this
//!   process can see; and a `config.json` whose `linux.cgroupsPath` is absent, not
//!   absolute, or does not resolve to a CHILD of that parent — see
//!   [`verify_cgroup_parent`]. Kata owns the parent, the runtime creates its leaf
//!   inside it, only the config places anything, and a plan whose two halves
//!   disagreed would have this process verify a directory the container never
//!   enters;
//! * a rootfs mount point that is not an absolute, `..`-free guest path;
//! * a BUNDLE directory that already exists, which means this container id has been
//!   run beneath this attempt state root before. Not the state root, which the
//!   runtime creates for any `--root` invocation — see [`materialize`].
//!
//! # Teardown: TWO units, and the ORDER is measured
//!
//! `kata_worker::oci_runtime::spawn_with_timeout` holds the same lesson, and it
//! holds here with one process fewer. The container's init and the `youki run`
//! client are DIFFERENT units of teardown: the client lives in this provider's own
//! cgroup and the init lives where `linux.cgroupsPath` put it — a leaf inside the
//! parent kata owns. MEASURED on the reference host, with and without that
//! placement: `SIGKILL` on the client alone leaves `youki list`
//! reporting the container `Running` and the init alive. So a cancellation kills the
//! CONTAINER first (`youki kill <id> KILL`, which lets the still-live client observe
//! the exit), then the client, then `youki delete --force <id>` to clear the state
//! directory. `delete --force` also runs after an ordinary exit, unconditionally: a
//! container left registered makes the NEXT run on this host fail on a name collision
//! rather than on the fact it measures.
//!
//! # What a `SIGKILL` on THIS process leaves behind, and who reaps it
//!
//! A cancellation reaches this provider as stdin EOF or `SIGTERM`, and both are
//! handled. A `SIGKILL` is not handleable — and it does not have to be. The plan's
//! `cgroup_parent` is a cgroup KATA created and owns, and
//! `linux.cgroupsPath` puts the container's own leaf inside it, so the container is
//! in the subtree `ProviderSupervisor::contain` already sweeps with `cgroup.kill` and
//! already reads `TeardownProbe::CgroupPopulation` from. **MEASURED on the reference
//! host, both halves:** a `SIGKILL` on the runtime client leaves the container's init
//! ALIVE and `youki list` reporting `Running` (so this binary is not what reaps it),
//! and one write of `1` to the sweep root's `cgroup.kill` empties the whole subtree.
//! `crates/worker/tests/oci_provider_live.rs`'s supervisor-abrupt arm is that
//! proof, watched red first with the placement removed.
//!
//! # How it ships
//!
//! The flake installs this binary with `kata-oci-hook` as a provider-source
//! member under `share/kata/provider-source` (`providerSourceBins`), and
//! `kata host setup` provisions it into the by-hash provider store, which is the
//! only path kata executes it from. `just oci-live-smoke` and the other OCI live
//! recipes build it from source.

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::time::Duration;

use kata_provider_protocol::{
    AssignStage, AssignmentAccepted, AssignmentRefused, CERTIFICATE_VERSION, FrameError,
    OciBundlePlan, OciMeasuredBasis, OciStdio, PROTOCOL_VERSION, PinnedRuntime,
    ProviderCertificate, ProviderFrame, ProviderHello, StageCompleted, SupervisorFrame,
    capture::CaptureSpool, measured_certificate, read_frame, write_frame,
};
use sha2::{Digest as _, Sha256};
use std::os::unix::fs::FileTypeExt as _;
use std::os::unix::fs::OpenOptionsExt as _;

/// The name this provider answers to, and the name an operator would write in
/// `KATA_EXTERNAL_EXECUTION_PROVIDER`. The supervisor resolves it to
/// `kata-provider-youki`, so the two halves are one fact spelled once.
const PROVIDER_NAME: &str = "youki";

/// How often the assignment loop looks at the container and at the supervisor.
///
/// A poll rather than an event loop because this process has exactly two things
/// to watch and no reason to link an async runtime to watch them; 50 ms is far
/// below any teardown budget a supervisor holds and far above the cost of two
/// non-blocking checks.
const WATCH_INTERVAL: Duration = Duration::from_millis(50);

/// How many [`WATCH_INTERVAL`] steps a cancellation spends trying to reach the
/// container before it gives up and `SIGKILL`s the runtime client anyway.
///
/// 100 × 50 ms = five seconds, which is an order of magnitude more than a rootless
/// container takes to register on the reference host (observed well under 500 ms)
/// and well inside a supervisor's own teardown budget — so the bound is a wedged
/// RUNTIME detector, not an acceptance window. See [`cancel`] for why it is a loop
/// at all.
const CANCEL_KILL_ATTEMPTS: u32 = 100;

/// `eprintln!` that cannot panic — the ONLY way this process writes stderr.
///
/// `eprintln!` PANICS when the write fails, and the write fails with `EPIPE` exactly
/// when it matters most: a supervisor that was `SIGTERM`ed with its whole process
/// group has lost the reader of this process's stderr, and the teardown path then
/// announces itself on stderr before doing the teardown. Measured: the
/// cancellation's `eprintln!` panicked mid-`cancel`, the provider
/// died with its container still running, and with that one write made
/// non-panicking nothing leaked. A diagnostic line is worth writing and never worth
/// dying for, so every stderr line here goes through this and drops its verdict.
macro_rules! note {
    ($($arg:tt)*) => {{
        use std::io::Write as _;
        let _ = writeln!(std::io::stderr(), $($arg)*);
    }};
}

/// Set by the `SIGTERM` handler, read by the assignment loop.
///
/// A supervisor's `SIGTERM` is a CANCELLATION, and the one thing this process must
/// not do on it is die with a container still running: that is the residue nobody
/// looks at. The default disposition would do exactly that, so the signal is
/// caught and folded into the same cancellation path an EOF takes.
static TERMINATED: AtomicBool = AtomicBool::new(false);

fn main() -> std::process::ExitCode {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    let certificate = match parse_measured_basis(&argv) {
        Ok(basis) => measured_certificate(PROVIDER_NAME, basis),
        Err(message) => {
            note!("kata-provider-youki: {message}");
            return std::process::ExitCode::from(2);
        }
    };
    install_sigterm_handler();
    match serve(&certificate) {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(e) => {
            // stderr, never stdout: stdout carries frames and one stray line on
            // it would desynchronise the length prefix for every frame after it.
            note!("kata-provider-youki: {e}");
            std::process::ExitCode::from(1)
        }
    }
}

/// Catch `SIGTERM` so a cancellation reaches the assignment loop.
fn install_sigterm_handler() {
    extern "C" fn handle(_signal: libc::c_int) {
        TERMINATED.store(true, Ordering::SeqCst);
    }
    // SAFETY: `signal(2)` with a handler that performs one `SeqCst` atomic store on
    // a `static AtomicBool` and returns. `AtomicBool` is lock-free on every target
    // this workspace builds for, so the handler is async-signal-safe whatever the
    // ordering: it allocates nothing, takes no lock, and calls no library function.
    // `SeqCst` rather than `Relaxed` because the flag is read on another path that
    // also reads the child's state, and the strongest ordering costs one fence on a
    // signal that arrives at most once per assignment.
    #[allow(unsafe_code)]
    unsafe {
        libc::signal(libc::SIGTERM, handle as *const () as libc::sighandler_t);
    }
}

/// Parse argv: the MEASURED BASIS, the one argument this provider takes.
///
/// It is argv rather than an environment variable because it is the channel kata
/// delivers a MEASUREMENT on, and an environment variable would be a channel an
/// operator could write to.
fn parse_measured_basis(argv: &[String]) -> Result<OciMeasuredBasis, String> {
    let mut basis: Option<OciMeasuredBasis> = None;
    let mut i = 0;
    while i < argv.len() {
        match argv[i].as_str() {
            "--measured-basis" => {
                let raw = argv
                    .get(i + 1)
                    .ok_or_else(|| "`--measured-basis` needs a value".to_owned())?;
                basis = Some(serde_json::from_str(raw).map_err(|e| {
                    format!(
                        "`--measured-basis` is not this build's `OciMeasuredBasis` JSON ({e}). \
                         Kata produces it from `certify_youki`; a hand-written one is refused \
                         rather than half-read."
                    )
                })?);
                i += 2;
            }
            other => return Err(format!("unknown flag `{other}`")),
        }
    }

    basis.ok_or_else(|| {
        "`--measured-basis <json>` is REQUIRED and this process was launched without it. \
         `provider_enforced`, the provider protocol's only containment claim, is admissible only \
         as an echo of what kata measured (`kata_worker::oci_runtime::certify_youki`). With no \
         measurement to quote there is nothing admissible to announce, so no frame is written \
         and no container is started."
            .to_owned()
    })
}

/// What the supervisor's end of the pipe has done.
enum FromSupervisor {
    /// A frame arrived. BOXED: an assignment carries a whole `config.json`, and an
    /// enum whose smallest variant paid for its largest would make every channel
    /// slot the size of a bundle plan.
    Frame(Box<SupervisorFrame>),
    /// The supervisor closed the pipe: it is done with this provider, which is a
    /// CANCELLATION for anything in flight.
    Closed,
    /// The stream could not be read as this protocol.
    Broken(String),
}

/// Say hello, then serve assignments until the supervisor closes stdin.
///
/// # Why stdin is read on its OWN THREAD
///
/// A cancellation is an EOF on this pipe, and an EOF that arrives while a
/// container is running must be noticed WHILE it is running — a provider that only
/// looked at its stdin between assignments would hold the container until it
/// finished and then discover it was never wanted. One reader thread owns the
/// descriptor for the whole process lifetime and forwards what it sees, so the
/// assignment loop can watch the container and the supervisor at once without two
/// readers of one descriptor.
fn serve(certificate: &ProviderCertificate) -> Result<(), FrameError> {
    let stdout = std::io::stdout();
    let mut output = stdout.lock();

    write_frame(
        &mut output,
        &ProviderFrame::Hello(ProviderHello {
            protocol_version: PROTOCOL_VERSION,
            certificate_version: CERTIFICATE_VERSION,
            certificate: certificate.clone(),
        }),
    )?;

    let (frames, incoming) = mpsc::channel::<FromSupervisor>();
    std::thread::spawn(move || {
        let stdin = std::io::stdin();
        let mut input = stdin.lock();
        loop {
            let message = match read_frame::<_, SupervisorFrame>(&mut input) {
                Ok(frame) => FromSupervisor::Frame(Box::new(frame)),
                Err(FrameError::PeerClosed) => FromSupervisor::Closed,
                Err(e) => FromSupervisor::Broken(e.to_string()),
            };
            let terminal = !matches!(message, FromSupervisor::Frame(_));
            if frames.send(message).is_err() || terminal {
                return;
            }
        }
    });

    loop {
        // `recv_timeout` rather than `recv`, so a `SIGTERM` arriving between
        // assignments is noticed: the handler sets a flag and wakes nothing, and a
        // provider blocked forever on a channel would sit there holding a supervisor's
        // teardown grace open for no reason. There is nothing to clean up on this
        // path — no container is in flight — so the exit is the orderly one.
        let frame = match incoming.recv_timeout(WATCH_INTERVAL) {
            Ok(FromSupervisor::Frame(frame)) => frame,
            Err(mpsc::RecvTimeoutError::Timeout) => {
                if TERMINATED.load(Ordering::SeqCst) {
                    return Ok(());
                }
                continue;
            }
            // The reader thread is gone and said nothing: treat it as the peer
            // closing, which is the same orderly exit.
            Ok(FromSupervisor::Closed) | Err(mpsc::RecvTimeoutError::Disconnected) => {
                return Ok(());
            }
            Ok(FromSupervisor::Broken(message)) => return Err(FrameError::Malformed(message)),
        };
        let SupervisorFrame::Assign(assign) = *frame;
        // EXHAUSTIVE DESTRUCTURE. A field added to `AssignStage`
        // is `E0027` here, so this provider cannot silently ignore an instruction
        // a newer supervisor considered load-bearing.
        let AssignStage {
            protocol_version: _,
            assignment_id,
            plan,
            capture,
        } = assign;

        // **WHEN ACCEPTANCE GOES OUT, and why it is not unconditional.**
        //
        // On every stdio arm but the interactive one, `accepted` is the first thing
        // this provider says.
        // A provider-crash check can only build its crash arm on *the provider
        // accepted work* being an OBSERVATION, and the sooner it is observable the
        // more of this process's life such a check covers.
        //
        // An `interactive` OCI plan is the exception, and it is a CORRECTNESS
        // exception rather than a preference. Kata opens its end of the three FIFOs
        // before it writes the assignment and then waits for `accepted`; the moment
        // it has one it may read. If this provider answered `accepted` before it had
        // OPENED the two output FIFOs for writing, kata's first `read` would find a
        // pipe with a reader and NO WRITER — which is not `EAGAIN`, it is a clean
        // end-of-file. A codec would see the init's stream end before its first
        // byte and latch the turn AMBIGUOUS on a container that was starting
        // normally. So on that arm acceptance waits until the container's stdio is
        // connected and the runtime client is spawned: after that the write ends are
        // held by the child, and an EOF kata reads means the init really is gone.
        //
        // The cost is stated: a failure before the spawn is then a `refused` with no
        // `accepted` in front of it, which is `AssignmentRefused`'s other documented
        // shape (the provider declined, so nothing ran) and which
        // `ProviderSupervisor::assign_stage` already records as a stage refusal.
        let defer_acceptance = matches!(plan.stdio, OciStdio::Interactive(_));
        if !defer_acceptance {
            announce_acceptance(&mut output, &assignment_id)?;
        }

        let answer = match start_container(&assignment_id, &plan, &capture) {
            // Nothing started, so nothing has to be torn down — and on
            // the deferred arm nothing has been accepted either, which
            // is what makes this refusal honest rather than a
            // retraction.
            Err(refusal) => *refusal,
            Ok(started) => {
                if defer_acceptance {
                    announce_acceptance(&mut output, &assignment_id)?;
                }
                finish_container(&assignment_id, &plan, started, &incoming)
            }
        };
        write_frame(&mut output, &answer)?;
    }
}

/// Write the `accepted` frame for `assignment_id`.
///
/// A function rather than an inline `write_frame` because it now has TWO call sites
/// on two different orderings — see [`serve`]'s `defer_acceptance` — and an
/// acceptance spelled twice is an acceptance that comes to differ.
///
/// # Errors
///
/// Whatever writing the frame to the supervisor fails with.
fn announce_acceptance(
    output: &mut impl std::io::Write,
    assignment_id: &str,
) -> Result<(), FrameError> {
    write_frame(
        output,
        &ProviderFrame::Accepted(AssignmentAccepted {
            assignment_id: assignment_id.to_owned(),
        }),
    )
}

fn refuse(assignment_id: &str, reason: &str) -> ProviderFrame {
    ProviderFrame::Refused(AssignmentRefused {
        assignment_id: assignment_id.to_owned(),
        reason: reason.to_owned(),
    })
}

/// The attempt-local directory this assignment's bundle and runtime state go
/// under, or the refusal it earns.
///
/// # Why [`OciBundlePlan::state_root`] and why a refusal rather than a default
///
/// This provider writes a rootfs, a `config.json`, two capture files and a runtime
/// state tree. Every directory it could choose for them on its own — a tempdir,
/// `/tmp`, its own working directory, anything derived from `/var/lib/kata` — is a
/// path from MAIN that this process invented, and a container whose state lives
/// where kata does not know to look is not a container kata can tear down, bound,
/// or read back. So the root is kata's to name and this function only checks that
/// what kata named is a path with one meaning.
///
/// **It is not the stage's working directory**, which is `process.cwd` inside
/// `config.json`. One field answering *"which directory"* for the stage and for this
/// provider's scratch would overload it; the state root is a property of the OCI
/// plan, so it is a field of the OCI plan.
///
/// # Refused set
///
/// A relative path (it would resolve against wherever this process was started) and
/// a path with a `..` component (which can name a directory outside the attempt the
/// worker owns while every character of it looks ordinary). Not refused: a state
/// root that already EXISTS — `youki --root <dir> <anything>` creates that
/// directory, a read-only `youki state` from a host observer included, so its
/// presence is not evidence of a previous run. The freshness check is on the bundle
/// ([`materialize`]).
fn attempt_state_root(state_root: &str) -> Result<&Path, String> {
    let path = Path::new(state_root);
    if !path.is_absolute() {
        return Err(format!(
            "the plan's state root `{state_root}` is RELATIVE, so it names a different directory \
             depending on where this process was started. An attempt-local state root is an \
             absolute path kata resolved or it is nothing."
        ));
    }
    if path
        .components()
        .any(|component| matches!(component, std::path::Component::ParentDir))
    {
        return Err(format!(
            "the plan's state root `{state_root}` contains a `..` component, which can name a \
             directory outside the attempt the worker owns while every character of the path looks \
             ordinary. Nothing is written beneath it."
        ));
    }
    Ok(path)
}

/// The cgroup v2 unified-hierarchy mount point.
///
/// A literal here and not a measurement: the OCI runtime spec defines
/// `linux.cgroupsPath` as a path FROM this mount point, so a provider checking that
/// the plan's leaf is beneath the plan's parent has to name it. This route is
/// Linux-only (the plan's namespaces and id mappings have no other spelling), and a
/// host that mounts the unified hierarchy elsewhere is one where kata's own
/// `sandbox_bounds` measurement would not find a delegated parent either.
const CGROUP_ROOT: &str = "/sys/fs/cgroup";

/// The kata-owned parent cgroup the container's leaf must be created beneath, or
/// the refusal it earns.
///
/// # Why a `None` is refused, and it is the whole point of the parent cgroup
///
/// `linux.cgroupsPath` inside the plan's `config.json` names a leaf beneath this
/// directory. **MEASURED on the reference host:** with that field unset youki 0.7.0
/// asks the user manager for its own transient `youki-<id>.scope`, the container's
/// init lands outside every subtree kata owns, and a `SIGKILL` on this process
/// leaves the container `Running` while kata's teardown probe reads an empty
/// provider subtree and scores `confirmed`. So a plan with no parent is a plan for a
/// container nothing can tear down, and starting it would make the placement a claim
/// nobody could check. Refusing keeps the rule that a bound kata planned is never
/// silently lost at the boundary.
///
/// # And why the PLAN'S OWN TWO HALVES are checked against each other
///
/// The placement is carried twice: as `cgroup_parent` on the plan, which this
/// process can see, and as `linux.cgroupsPath` inside `config_json`, which is what
/// the RUNTIME acts on. Only the second one places anything. A plan whose halves
/// disagreed would have this provider verify a directory the container never enters
/// — the exact shape of check this repository calls a guarantee wider than its
/// mechanism — so the field is read out of the config and required to be an absolute
/// path whose PARENT is `cgroup_parent`.
///
/// Reading one field is not the parsing this provider refuses to do: the bytes it
/// WRITES are still `config_json` verbatim ([`materialize`]), never a re-serialized
/// form of anything parsed here.
///
/// # The rest of the refused set
///
/// A parent that is not absolute or carries `..` (a cgroup directory is named from
/// the hierarchy's mount point or it names nothing this process can check); a parent
/// that is not a cgroup v2 directory this process can see (no `cgroup.procs` in it).
/// The runtime creates the leaf, so an absent parent would otherwise surface as a
/// container failing a `cgroup.procs` write AFTER a bundle had been written — a worse
/// message for the same fact.
///
/// This provider does NOT create the parent, populate it, or read its knobs back.
/// Kata owns it — that is what "kata-owned" means — and a provider that could create
/// a cgroup could place a container somewhere kata never planned.
fn verify_cgroup_parent(
    cgroup_parent: Option<&str>,
    config_json: &str,
    container_id: &str,
) -> Result<(), String> {
    let parent = cgroup_parent.ok_or_else(|| {
        format!(
            "the plan names NO parent cgroup, so `linux.cgroupsPath` is unset and this container \
             would be placed by the runtime rather than by kata. Measured on the reference host: \
             youki then takes its own transient `youki-{container_id}.scope` from the user \
             manager, which is outside the subtree kata sweeps — a `SIGKILL` on this provider \
             leaves the container running while kata's teardown probe reports it gone. Refusing \
             rather than starting a container nothing can tear down."
        )
    })?;
    let path = Path::new(parent);
    if !path.is_absolute()
        || path
            .components()
            .any(|component| matches!(component, std::path::Component::ParentDir))
    {
        return Err(format!(
            "the plan's parent cgroup `{parent}` is not an absolute, `..`-free path. A cgroup \
             directory is named from the hierarchy's mount point or it names nothing this process \
             can check."
        ));
    }
    if !path.join("cgroup.procs").is_file() {
        return Err(format!(
            "the plan's parent cgroup `{parent}` is not a cgroup v2 directory this process can \
             see (no `cgroup.procs` in it). Kata creates and populates that parent before it \
             assigns; the container's leaf is created INSIDE it by the runtime, so an absent \
             parent would surface as a runtime failing a `cgroup.procs` write after a bundle had \
             already been written. Nothing is written."
        ));
    }

    let spec: serde_json::Value = serde_json::from_str(config_json).map_err(|e| {
        format!(
            "the plan's `config.json` does not parse as JSON ({e}), so the placement the RUNTIME \
             will act on cannot be read and cannot be checked against the parent kata named. The \
             bytes are still written verbatim when they are accepted; this read is a check, not a \
             re-serialization."
        )
    })?;
    let placed = spec
        .get("linux")
        .and_then(|linux| linux.get("cgroupsPath"))
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| {
            format!(
                "the plan names the parent cgroup `{parent}` and its `config.json` carries NO \
                 `linux.cgroupsPath`. Only that field places the container: the runtime would \
                 take its own transient scope outside `{parent}`, and this process would have \
                 verified a directory the container never enters."
            )
        })?;
    let placed_path = Path::new(placed);
    if !placed_path.is_absolute() {
        return Err(format!(
            "the plan's `linux.cgroupsPath` is `{placed}`, which is not absolute. Measured on the \
             reference host: youki routes a non-absolute path to its systemd manager, which \
             refuses it as malformed and starts no container at all — so this would fail after a \
             bundle had been written, with the runtime's words instead of kata's."
        ));
    }
    let resolved = Path::new(CGROUP_ROOT).join(placed.trim_start_matches('/'));
    if resolved.parent() != Some(path) {
        return Err(format!(
            "the plan's two halves DISAGREE about where this container goes: `cgroup_parent` is \
             `{parent}` and `linux.cgroupsPath` resolves to `{resolved}`, whose parent is not it. \
             The config is what the runtime acts on, so accepting this would place the container \
             outside the directory kata created, bounded and will sweep, while this process had \
             checked that directory and reported success.",
            resolved = resolved.display(),
        ));
    }
    Ok(())
}

/// Everything one container needs on disk, beneath the attempt-local state root.
struct Materialized {
    /// `<state root>/<container id>` is one directory per container — the
    /// bundle and runtime-state directories live beneath it, because the state
    /// root is per ATTEMPT and a container id is the runtime's namespace.
    /// The bundle directory youki reads `config.json` and `rootfs` from.
    bundle: PathBuf,
    /// The runtime's own state root — `youki --root <this>`.
    state: PathBuf,
}

/// Write the plan's bundle into a FRESH directory beneath the attempt state root.
///
/// The `config.json` is [`OciBundlePlan::config_json`]'s bytes and nothing else:
/// no parse, no re-serialize, no merge. A provider that round-tripped that text
/// through a JSON library could change key order, number formatting or an unknown
/// field and still answer `completed`, and the byte golden kata pins would then be
/// measuring a document no runtime ever read.
fn materialize(root: &Path, plan: &OciBundlePlan) -> Result<Materialized, String> {
    let home = root.join(&plan.container_id);
    let bundle = home.join("bundle");
    let state = home.join("state");
    // **The BUNDLE is what must be fresh, and the home directory is deliberately
    // not the subject.** A bundle left by an earlier run would put this container
    // on a rootfs and a `config.json` nobody wrote for it, and whatever it then
    // observed would be attributable to neither run. The runtime's STATE root is a
    // different matter: `youki --root <dir> <anything>` CREATES that directory,
    // including for a read-only `youki state` — MEASURED, by a host observer in
    // `crates/worker/tests/oci_provider_live.rs` that polled for the container's
    // init and thereby created the tree this provider was about to write, which
    // refused the assignment when the check was `home.exists()`. So an existing
    // state root is not evidence of a previous run, and refusing on it would refuse
    // for being watched.
    if bundle.exists() {
        return Err(format!(
            "{bundle} already exists, so this container id has been run beneath this attempt state \
             root before. The bundle must be FRESH: reusing one would run the container against a \
             rootfs and a `config.json` left by an earlier run, and whatever it then observed \
             would be attributable to neither.",
            bundle = bundle.display(),
        ));
    }
    let rootfs = bundle.join("rootfs");
    for directory in [&state, &rootfs] {
        std::fs::create_dir_all(directory)
            .map_err(|e| format!("creating {}: {e}", directory.display()))?;
    }
    for point in &plan.rootfs_mountpoints {
        let relative = point.strip_prefix('/').ok_or_else(|| {
            format!(
                "the plan's rootfs mount point `{point}` is not absolute, so it names no \
                 directory inside the rootfs"
            )
        })?;
        if Path::new(relative)
            .components()
            .any(|component| !matches!(component, std::path::Component::Normal(_)))
        {
            return Err(format!(
                "the plan's rootfs mount point `{point}` contains a `.` or `..` component. A \
                 mount point is a plain absolute guest path; anything else could name a directory \
                 outside the rootfs this provider is creating."
            ));
        }
        let directory = rootfs.join(relative);
        std::fs::create_dir_all(&directory)
            .map_err(|e| format!("creating the mount point {point}: {e}"))?;
    }
    // THE IDENTITY FILES — `/etc/passwd`, `/etc/group` and `nsswitch.conf`.
    // No nix mount provides them (the environment is a store-path mount set,
    // not an image), and a guest process's `getpwuid(0)` fails outright on
    // their absence.
    // Every capsule on this provider runs uid 0 inside its own user namespace;
    // the single `root` entry is the only honest answer a user namespace of
    // one has. `/tmp` is root's `home` because it is the capsule's writable
    // tmpfs, and `/bin/sh` root's shell because the environment promises a
    // `sh` on PATH there.
    let etc = rootfs.join("etc");
    std::fs::create_dir_all(&etc).map_err(|e| format!("creating {}: {e}", etc.display()))?;
    for (name, bytes) in [
        ("passwd", b"root:x:0:0:root:/tmp:/bin/sh\n" as &[u8]),
        ("group", b"root:x:0:\n" as &[u8]),
        (
            "nsswitch.conf",
            b"passwd: files\ngroup: files\nshadow: files\n" as &[u8],
        ),
    ] {
        std::fs::write(etc.join(name), bytes).map_err(|e| format!("writing /etc/{name}: {e}"))?;
    }
    std::fs::write(bundle.join("config.json"), plan.config_json.as_bytes())
        .map_err(|e| format!("writing config.json: {e}"))?;
    Ok(Materialized { bundle, state })
}

/// Re-derive the digest of the pinned runtime and refuse a mismatch.
///
/// The plan carries a path AND a digest because either alone is a weaker claim
/// ([`PinnedRuntime`]): this is the check that makes the pair mean something on
/// this side of the wire. A provider that execed the path without reading the
/// bytes would be trusting whatever is at a filesystem location at exec time,
/// which is the substitution class kata refuses everywhere it can observe one.
fn verify_pinned_runtime(youki: &PinnedRuntime) -> Result<(), String> {
    let bytes = std::fs::read(&youki.store_path).map_err(|e| {
        format!(
            "the plan pins the runtime at `{path}` and its bytes could not be read ({e}). \
             Nothing is started: a runtime this provider cannot hash is one it cannot prove is \
             the pinned one.",
            path = youki.store_path,
        )
    })?;
    let observed = format!("{:x}", Sha256::digest(&bytes));
    if observed == youki.sha256 {
        return Ok(());
    }
    Err(format!(
        "the runtime at `{path}` hashes to {observed} and the plan pins {pinned}. Refusing to \
         exec it: a store path is immutable, so a digest that moved means the pin was re-realized \
         or the store was damaged under a running worker — and a container started by an \
         unpinned runtime has none of the properties kata certified.",
        path = youki.store_path,
        pinned = youki.sha256,
    ))
}

/// Re-derive the digest of the pinned EGRESS HOOK and refuse a mismatch — plus
/// the halves-agreement checks that make the pair mean something.
///
/// Same mechanism as [`verify_pinned_runtime`], same reason, worse blast
/// radius: a `createContainer` hook runs as the runtime's child inside the
/// container's network namespace on the HOST's mount namespace, so an
/// unverified path there is code execution outside every bound the capsule's
/// `CapEff=0` init is under. The plan's [`OciBundlePlan::egress_hook`] and the
/// `hooks` object inside [`OciBundlePlan::config_json`] are the two halves of
/// one claim — kata renders them from the same `EgressHookInputs` — and this
/// process refuses each way they can disagree, because a create that proceeds
/// on one half only is a container kata described incompletely:
///
/// * the plan says `None` and the config carries ANY hook entry — a create the
///   plan never described;
/// * the plan says `Some` and the config registers no `createContainer`
///   entries — the egress plumbing kata pinned has nowhere to run;
/// * a `createContainer` `path` differs from `store_path` — the bytes being
///   exec'd are not the bytes being pinned;
/// * an entry appears on a phase kata does not render (`prestart`,
///   `createRuntime`, `startContainer`, `poststart`, `poststop`) — kata's
///   render produces `createContainer` only, so a foreign phase is a hook kata
///   never described;
/// * `store_path` exists but does not hash to `sha256` —
///   **`hook_digest_mismatch`**.
///
/// `OciBundlePlan::egress_hook`'s doc is the contract; this is the mechanism.
fn verify_egress_hooks(
    egress_hook: Option<&PinnedRuntime>,
    config_json: &str,
) -> Result<(), String> {
    const PHASES: [&str; 6] = [
        "prestart",
        "createRuntime",
        "createContainer",
        "startContainer",
        "poststart",
        "poststop",
    ];
    let spec: serde_json::Value = serde_json::from_str(config_json).map_err(|e| {
        format!(
            "the plan's `config.json` does not parse as JSON ({e}), so the hooks the RUNTIME \
             will exec cannot be read and cannot be checked against the program kata pinned. The \
             bytes are still written verbatim when they are accepted; this read is a check, not \
             a re-serialization."
        )
    })?;
    // Every (phase, path) the config registers, in phase order.
    let hooks = spec.get("hooks");
    let mut declared: Vec<(&str, &str)> = Vec::new();
    for phase in PHASES {
        if let Some(entries) = hooks
            .and_then(|hooks| hooks.get(phase))
            .and_then(serde_json::Value::as_array)
        {
            for entry in entries {
                declared.push((
                    phase,
                    entry
                        .get("path")
                        .and_then(serde_json::Value::as_str)
                        .unwrap_or("<a createContainer entry without a string `path`>"),
                ));
            }
        }
    }
    let Some(pinned) = egress_hook else {
        if declared.is_empty() {
            return Ok(());
        }
        return Err(format!(
            "the plan names NO egress hook program and its `config.json` registers {} hook \
             entr{} — the two halves DISAGREE about whether a `createContainer` phase exists at \
             all, and a hook the plan never pinned would run as the runtime's child with no \
             digest check standing anywhere",
            declared.len(),
            if declared.len() == 1 { "y" } else { "ies" },
        ));
    };
    if declared.is_empty() {
        return Err(format!(
            "the plan pins the egress hook `{path}` and its `config.json` registers NO hooks, \
             so the plumbing kata described has no phase to run in — a capsule whose declared \
             egress silently resolves to no proxy. Refusing rather than starting a container \
             whose network posture neither half describes",
            path = pinned.store_path,
        ));
    }
    for (phase, path) in &declared {
        if *phase != "createContainer" {
            return Err(format!(
                "the `config.json` registers a hook on `{phase}`, a phase kata's egress render \
                 never emits — `createContainer` is the only phase the pair is allowed to \
                 occupy, and a foreign phase is a hook kata never described running as the \
                 runtime's child"
            ));
        }
        if *path != pinned.store_path {
            return Err(format!(
                "the plan's two halves DISAGREE about which hook program runs: `egress_hook` \
                 pins `{pinned}` and the `createContainer` entry names `{path}`. Refusing \
                 rather than exec'ing bytes the digest check never saw",
                pinned = pinned.store_path,
            ));
        }
    }
    let bytes = std::fs::read(&pinned.store_path).map_err(|e| {
        format!(
            "the plan pins the egress hook at `{path}` and its bytes could not be read ({e}). \
             Nothing is started: a hook this provider cannot hash is one it cannot prove is \
             the pinned one.",
            path = pinned.store_path,
        )
    })?;
    let observed = format!("{:x}", Sha256::digest(&bytes));
    if observed == pinned.sha256 {
        return Ok(());
    }
    Err(format!(
        "hook_digest_mismatch: the egress hook at `{path}` hashes to {observed} and the plan \
         pins {pinned_sha}. Refusing to let the runtime exec it: a store path is immutable, so \
         a digest that moved means the entry was re-provisioned or the store was damaged under \
         a running worker — and a createContainer hook runs with capabilities the container's \
         own init never holds.",
        path = pinned.store_path,
        pinned_sha = pinned.sha256,
    ))
}

/// A container that is RUNNING: everything [`finish_container`] needs to watch it,
/// tear it down and report what it did.
struct Started {
    /// The runtime client. Its exit is the container's exit.
    child: Child,
    /// Where this container's bundle, state tree and captures live.
    staged: Materialized,
    /// `Some` on [`OciStdio::Captured`]; `None` on [`OciStdio::Interactive`],
    /// where kata read every byte as it was produced and there is no file to
    /// size or read back.
    captures: Option<CaptureFiles>,
}

/// Check the plan, write the bundle, connect the stdio and SPAWN the runtime client
/// — everything up to and including the moment the container exists.
///
/// # Why this is a phase of its own
///
/// Because on an `interactive` plan the ACCEPTANCE has to come after it. Kata may
/// read the output FIFOs as soon as it has an `accepted`, and a FIFO whose only
/// writer has not opened it yet reads as a clean end-of-file rather than as
/// `EAGAIN` — so an acceptance sent before this function returned would let kata
/// observe the init's stream ending before its first byte. [`serve`]'s
/// `defer_acceptance` is the other half of that ordering.
///
/// # Errors
///
/// A `refused` frame, on every check made before the container starts: the
/// cgroup parent, the state root, the pinned runtime's digest, the bundle's
/// freshness and the stdio. Nothing is running when one is returned, so the caller
/// has nothing to tear down.
///
/// BOXED, because `ProviderFrame`'s largest variant carries a whole `config.json`'s
/// worth of reason text and `clippy::result_large_err` is right that every `Ok` on
/// this path should not pay for it.
fn start_container(
    assignment_id: &str,
    plan: &OciBundlePlan,
    capture: &kata_provider_protocol::CaptureSpec,
) -> Result<Started, Box<ProviderFrame>> {
    // EXHAUSTIVE DESTRUCTURE — a field added to `OciBundlePlan` is `E0027` here,
    // so a newly-carried piece of the container's description cannot be dropped
    // by the one process whose job is to apply all of it.
    let OciBundlePlan {
        config_json,
        rootfs_mountpoints: _,
        container_id,
        youki,
        cgroup_parent,
        state_root,
        stdio,
        egress_hook,
    } = plan;

    if let Err(reason) = verify_cgroup_parent(cgroup_parent.as_deref(), config_json, container_id) {
        return Err(Box::new(refuse(assignment_id, &reason)));
    }
    let root = attempt_state_root(state_root)
        .map_err(|reason| Box::new(refuse(assignment_id, &reason)))?;
    if let Err(reason) = verify_pinned_runtime(youki) {
        return Err(Box::new(refuse(assignment_id, &reason)));
    }
    if let Err(reason) = verify_egress_hooks(egress_hook.as_ref(), config_json) {
        return Err(Box::new(refuse(assignment_id, &reason)));
    }
    let staged =
        materialize(root, plan).map_err(|reason| Box::new(refuse(assignment_id, &reason)))?;
    let plumbing =
        connect_stdio(stdio, capture).map_err(|reason| Box::new(refuse(assignment_id, &reason)))?;
    let Plumbing {
        stdin,
        stdout,
        stderr,
        captures,
    } = plumbing;

    let child = match runtime_command(youki)
        .arg("--root")
        .arg(&staged.state)
        .arg("run")
        .arg("--bundle")
        .arg(&staged.bundle)
        .arg(container_id)
        // Whatever `connect_stdio` resolved. On the `captured` arm this is
        // `/dev/null` and two files; on the `interactive` arm it is the three FIFOs
        // kata named. What it is NEVER is this process's own descriptors: the
        // container must not read the protocol stream this provider is still
        // serving on its stdin, nor write onto the frame stream.
        .stdin(stdin)
        .stdout(stdout)
        .stderr(stderr)
        .spawn()
    {
        Ok(child) => child,
        Err(e) => {
            return Err(Box::new(refuse(
                assignment_id,
                &format!(
                    "the pinned runtime `{path}` could not be spawned: {e}",
                    path = youki.store_path,
                ),
            )));
        }
    };

    Ok(Started {
        child,
        staged,
        captures,
    })
}

/// Watch the running container, tear it down, and report what it did.
///
/// The second phase of a container's run: see [`start_container`] for why the
/// two phases are split. By the time this is called the container exists and the
/// supervisor has been told so, so every path from here MUST reach
/// [`delete_force`].
fn finish_container(
    assignment_id: &str,
    plan: &OciBundlePlan,
    started: Started,
    incoming: &mpsc::Receiver<FromSupervisor>,
) -> ProviderFrame {
    let Started {
        mut child,
        staged,
        captures: capture_paths,
    } = started;
    let youki = &plan.youki;
    let container_id = &plan.container_id;

    let outcome = watch(
        &mut child,
        youki,
        &staged,
        container_id,
        capture_paths.as_ref(),
        incoming,
    );
    // THE FINALLY, on every path including a cancellation: a container left
    // registered makes the NEXT run on this host fail on a name collision rather
    // than on the fact it measures.
    delete_force(youki, &staged, container_id);

    // The capture SIZES are read BEFORE the outcome is folded into a frame,
    // because a file that cannot be `stat`ed makes every `completed` frame below
    // a claim about bytes nobody counted: it is its own refusal, and it names
    // the path. The BYTES stay in the spool — the supervisor reads them back
    // itself; this frame must never carry them.
    //
    // On the INTERACTIVE arm there is nothing to size: kata consumed every byte
    // off the FIFOs as it was produced, so the two sizes are `0` and
    // `capture_exceeded` is `false`. Reporting anything else would be claiming
    // bytes this process never had.
    let sizes = match &capture_paths {
        None => Ok((0, 0)),
        Some(files) => files
            .stdout
            .metadata()
            .and_then(|o| files.stderr.metadata().map(|e| (o.len(), e.len())))
            .map_err(|e| {
                format!(
                    "stat of the capture spool ({}, {}): {e}",
                    files.stdout.display(),
                    files.stderr.display()
                )
            }),
    };
    let (mut stdout_bytes, mut stderr_bytes) = match sizes {
        Ok(sizes) => sizes,
        Err(message) => {
            return refuse(
                assignment_id,
                &format!(
                    "the container ran and its output could not be sized ({message}), so this \
                     provider cannot say what the stage printed. The container was killed and \
                     deleted before this answer. Refusing rather than reporting zero capture, \
                     which is a claim about the stage rather than about this failure."
                ),
            );
        }
    };
    // THE SPOOL'S CEILING HOLDS ON THE FILE, not only on the kill: the watch
    // is a poll, so a fast writer can overshoot between intervals — on the
    // exceed arm, truncate each file to what the bound permits (stdout first,
    // then whatever room remains for stderr) BEFORE the sizes are folded into
    // the frame, keeping "the spool never holds more than `limit_bytes`" a fact
    // rather than a claim the poll's timing makes false.
    if matches!(outcome, Watched::CaptureExceeded)
        && let Some(files) = &capture_paths
    {
        let limit = files.limit_bytes;
        let keep_out = files.stdout.metadata().map_or(0, |m| m.len()).min(limit);
        let keep_err = files
            .stderr
            .metadata()
            .map_or(0, |m| m.len())
            .min(limit.saturating_sub(keep_out));
        for (path, keep) in [(&files.stdout, keep_out), (&files.stderr, keep_err)] {
            if let Ok(file) = std::fs::OpenOptions::new().write(true).open(path) {
                let _ = file.set_len(keep);
            }
        }
        stdout_bytes = keep_out;
        stderr_bytes = keep_err;
    }
    // One frame builder: `Exited` reports what the client reported; `Cancelled`
    // and `CaptureExceeded` report `None`, because on those paths the stage did
    // not exit — this provider killed it (through the one `cancel` path both
    // take). See `cancel` for why the client's own number must not be forwarded.
    // `ClientFailed` reports `None` too: the client did not finish its own delete,
    // so the number it exited with is youki's own — whether or not the stage ran
    // (see `client_exit`).
    let completed = |exit_code: Option<i32>, capture_exceeded: bool| {
        ProviderFrame::Completed(StageCompleted {
            assignment_id: assignment_id.to_owned(),
            // `None` for a signal death, a cancellation or a capture kill, which
            // are different facts from exiting 0 and are carried as one word.
            exit_code,
            stdout_bytes,
            stderr_bytes,
            capture_exceeded,
        })
    };
    match outcome {
        Watched::Exited(code) => completed(code, false),
        Watched::ClientFailed | Watched::Cancelled => completed(None, false),
        Watched::CaptureExceeded => completed(None, true),
        Watched::Unreadable(message) => refuse(
            assignment_id,
            &format!(
                "the container was started and this provider then lost track of it ({message}). \
                 The container was killed and deleted before this answer."
            ),
        ),
    }
}

/// The two spool files a `captured` assignment writes, and the bound over them.
///
/// Paths, not handles: the descriptors went to the runtime client, and the bound
/// is enforced by [`watch`] polling `metadata` on these paths — a size read, not
/// a write — each [`WATCH_INTERVAL`]. Breaching [`Self::limit_bytes`] kills the
/// container through the same [`cancel`] a supervisor EOF takes.
struct CaptureFiles {
    /// `<spool_dir>/stdout`.
    stdout: PathBuf,
    /// `<spool_dir>/stderr`.
    stderr: PathBuf,
    /// [`kata_provider_protocol::CaptureSpec::limit_bytes`] — COMBINED over both
    /// files.
    limit_bytes: u64,
}

/// The three descriptors the runtime client is spawned with, plus the two capture
/// files to read back afterwards when there are any.
struct Plumbing {
    stdin: Stdio,
    stdout: Stdio,
    stderr: Stdio,
    /// `Some` on [`OciStdio::Captured`]; `None` on [`OciStdio::Interactive`],
    /// where kata read every byte as it was produced and there is no file to
    /// size or read back.
    captures: Option<CaptureFiles>,
}

/// Resolve the container init's three descriptors from the plan's [`OciStdio`].
///
/// # The `captured` arm: FILES, never pipes
///
/// That is a measured lesson rather than a preference: a piped
/// descriptor is inherited by the container's init, so a read-to-EOF on this side
/// blocks until that process closes it — which a hung container never does — and the
/// teardown after the read never runs. Files hold no descriptor open here.
///
/// # The `interactive` arm: three FIFOs KATA created, which this process only OPENS
///
/// It does not create a missing one and does not accept anything that is not already
/// a FIFO. A provider that could create the thing kata planned could put it
/// somewhere kata never planned. Concretely, a provider that created a missing
/// FIFO would be choosing where a container's output goes, and one that opened a
/// REGULAR FILE at that path would connect the container to bytes on disk while kata
/// waited forever on a pipe — a container answering `completed` with a session that
/// never spoke.
///
/// Neither open can block, and that is kata's ordering rather than this function's
/// luck: kata opens its own end of each FIFO before it writes the assignment (the
/// stdin it writes `O_RDWR`, so this `O_RDONLY` has a peer; the two it reads
/// `O_RDONLY | O_NONBLOCK`, so this `O_WRONLY` has one too). If that ordering were
/// ever broken the symptom is an open that blocks here, before the container starts,
/// which the supervisor's stage budget ends — not a started container nobody reads.
///
/// # Refused set
///
/// For each of the three paths: not absolute; carrying a `..` component; not a FIFO
/// (including absent, which `symlink_metadata` reports as the same refusal with the
/// OS error named); a symlink AT the named path, which `O_NOFOLLOW` refuses on the
/// open even if the `symlink_metadata` above somehow saw a FIFO; and an `open` that
/// fails. Plus, on the captured arm, either capture file that cannot be created.
///
/// # What is NOT checked here, stated rather than implied
///
/// That the three paths lie beneath [`OciBundlePlan::state_root`], or anywhere in
/// particular. They are absolute and `..`-free and nothing more, so kata may put the
/// FIFOs where it likes (today `<attempt>/io`, a sibling of the state root) — and a
/// supervisor that named `/tmp/x` would be obeyed. That is the same trust this
/// provider already extends to `state_root` and `cgroup_parent`: kata names the
/// directories, this process checks only that each name has ONE meaning. Nor is the
/// MODE checked: kata creates them `0o600` and this provider does not verify it, so a
/// world-readable FIFO would be opened without complaint. Both are kata's to get
/// right, and neither is a claim this provider makes.
///
/// NOT refused either: the two capture files already existing — the bundle's
/// freshness is [`materialize`]'s check and the same directory cannot be reused
/// without tripping it.
fn connect_stdio(
    plan: &OciStdio,
    capture: &kata_provider_protocol::CaptureSpec,
) -> Result<Plumbing, String> {
    match plan {
        OciStdio::Captured => {
            // The spool the SUPERVISOR named (`AssignStage::capture`), never a
            // directory this process chose: `CaptureSpool::create` owns the
            // absolute/`..`-free/existing-dir checks and the `O_EXCL` creation
            // of both files, so a staged or hostile name refuses rather than
            // writing over bytes that are not this stage's.
            let spool = CaptureSpool::create(capture)?;
            let out_path = spool.stdout_path().to_path_buf();
            let err_path = spool.stderr_path().to_path_buf();
            let (stdout, stderr) = spool.into_files();
            Ok(Plumbing {
                stdin: Stdio::null(),
                stdout: Stdio::from(stdout),
                stderr: Stdio::from(stderr),
                captures: Some(CaptureFiles {
                    stdout: out_path,
                    stderr: err_path,
                    limit_bytes: capture.limit_bytes,
                }),
            })
        }
        OciStdio::Interactive(io) => {
            // EXHAUSTIVE DESTRUCTURE. A fourth descriptor added to
            // the wire is `E0027` here rather than a channel this provider silently
            // leaves unconnected.
            let kata_provider_protocol::InteractiveStdio {
                stdin_fifo,
                stdout_fifo,
                stderr_fifo,
            } = io;
            let stdin = open_fifo(stdin_fifo, FifoEnd::Read)?;
            let stdout = open_fifo(stdout_fifo, FifoEnd::Write)?;
            let stderr = open_fifo(stderr_fifo, FifoEnd::Write)?;
            Ok(Plumbing {
                stdin: Stdio::from(stdin),
                stdout: Stdio::from(stdout),
                stderr: Stdio::from(stderr),
                captures: None,
            })
        }
    }
}

/// Which end of a FIFO this provider opens — the container's side of it.
#[derive(Clone, Copy)]
enum FifoEnd {
    /// The container init READS this one as its `stdin`.
    Read,
    /// The container init WRITES this one as its `stdout` or `stderr`.
    Write,
}

impl FifoEnd {
    const fn label(self) -> &'static str {
        match self {
            Self::Read => "read",
            Self::Write => "write",
        }
    }
}

/// Open one of kata's FIFOs for the container init, or say why not.
///
/// See [`connect_stdio`] for the refused set and for why neither open blocks.
fn open_fifo(path: &str, end: FifoEnd) -> Result<std::fs::File, String> {
    let fifo = Path::new(path);
    if !fifo.is_absolute()
        || fifo
            .components()
            .any(|component| matches!(component, std::path::Component::ParentDir))
    {
        return Err(format!(
            "the plan's interactive stdio names `{path}`, which is not an absolute, `..`-free \
             path. A relative path resolves against wherever this process was started and a `..` \
             can name a file outside the attempt the worker owns, so the container's live stdio \
             would be connected to something kata did not name. Nothing is started."
        ));
    }
    // `symlink_metadata`, so a SYMLINK to a FIFO is refused as not-a-FIFO rather
    // than followed: kata created these three by name, and a link at one of those
    // names means something other than kata put it there.
    let kind = std::fs::symlink_metadata(fifo).map_err(|e| {
        format!(
            "the plan's interactive stdio names `{path}` and this process cannot stat it ({e}). \
             Kata creates all three FIFOs before it assigns, so an absent one means the \
             assignment and the attempt directory disagree — and a provider that CREATED the \
             missing one would be choosing where a container's live stdio goes. Nothing is started."
        )
    })?;
    if !kind.file_type().is_fifo() {
        return Err(format!(
            "the plan's interactive stdio names `{path}`, which is not a FIFO ({kind:?}). Opening \
             a regular file there would connect the container to bytes on disk while kata waited \
             on a pipe — a container that runs, answers `completed`, and never speaks to the \
             session kata opened for it. Nothing is started.",
            kind = kind.file_type(),
        ));
    }
    // `O_NOFOLLOW`, so the `symlink_metadata` above is not a check with a window after
    // it: if the name became a symlink between the stat and this open, the open fails
    // rather than following it to whatever the link now points at.
    let opened = match end {
        FifoEnd::Read => std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(fifo),
        FifoEnd::Write => std::fs::OpenOptions::new()
            .write(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(fifo),
    };
    opened.map_err(|e| {
        format!(
            "the plan's interactive stdio FIFO `{path}` could not be opened for {end} ({e}). Kata \
             opens its own end of each FIFO before it writes the assignment, so this open has a \
             peer and cannot block; a failure here is the attempt directory being gone or \
             unreadable. Nothing is started.",
            end = end.label(),
        )
    })
}

/// What the watch loop ended on.
enum Watched {
    /// The client exited on its own with no container directory left — its own
    /// delete finished, so its status is the init's, apart from the client errors
    /// [`client_exit`] names as not caught; `None` means a signal killed the client.
    Exited(Option<i32>),
    /// The client exited on its own WITHOUT finishing its own delete: the container
    /// directory was still there when it was reaped, so its status is youki's report
    /// of its own error and not the init's. See [`client_exit`].
    ClientFailed,
    /// This provider CANCELLED the assignment and tore the container down.
    Cancelled,
    /// The spool files together passed the assignment's combined bound and the
    /// container was killed for it — through [`cancel`], the same teardown a
    /// cancellation takes.
    CaptureExceeded,
    /// Waiting on the client itself failed.
    Unreadable(String),
}

/// Watch the container and the supervisor at the same time.
///
/// Three things end this loop, and only the first is the ordinary one: the client
/// exits, the supervisor closes the pipe (an EOF is a cancellation), or a
/// `SIGTERM` arrives. The last two go through [`cancel`], which is where the
/// two-unit ordering lives.
fn watch(
    child: &mut Child,
    youki: &PinnedRuntime,
    staged: &Materialized,
    container_id: &str,
    captures: Option<&CaptureFiles>,
    incoming: &mpsc::Receiver<FromSupervisor>,
) -> Watched {
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                // An exited client CAN still be over-bound: a stage that bursts
                // past the combined bound and exits between two polls wrote the
                // bytes and was never killed — but `capture_exceeded` is what the
                // bound MEANS, so the size check runs on the exit path too. A
                // dead container needs no kill; the flag alone marks the stage
                // performed-but-over-its-promise.
                if let Some(files) = captures
                    && let (Ok(o), Ok(e)) = (files.stdout.metadata(), files.stderr.metadata())
                {
                    let total = o.len() + e.len();
                    if total > files.limit_bytes {
                        note!(
                            "kata-provider-youki: container {container_id}'s capture passed the \
                             combined bound ({total} > {} bytes spooled) before it exited",
                            files.limit_bytes
                        );
                        return Watched::CaptureExceeded;
                    }
                }
                return client_exit(status.code(), &staged.state.join(container_id));
            }
            // A wait that FAILS is not a reason to walk away from a container: this
            // process has lost track of the client, the container may well be
            // running, and only the teardown below can reach it. So the fault goes
            // through the same cancellation the other arms take, and the message is
            // carried into the answer afterwards.
            Err(e) => {
                let message = format!("waiting on the runtime client: {e}");
                let _ = cancel(child, youki, staged, container_id);
                return Watched::Unreadable(message);
            }
            Ok(None) => {}
        }
        // THE COMBINED CAPTURE BOUND, polled in the same watch that owns the
        // other endings. `try_wait` first: an exited client cannot be
        // over-bound by files it no longer writes, and the ordering keeps an
        // EXCEED arm from naming a kill this loop did not do. A poll, not a
        // per-byte gate — the descriptors are the runtime's — so a fast writer
        // can overshoot between intervals; the bound is then about what the
        // record may call complete, and the kill is what keeps the sum there.
        if let Some(files) = captures {
            let total = match (files.stdout.metadata(), files.stderr.metadata()) {
                (Ok(o), Ok(e)) => Some(o.len() + e.len()),
                // A stat fault is NOT the exceed path: the completion arm's own
                // size read reports it as the refusal it is, and killing on a
                // `stat` error would fail a stage on this process's I/O, not on
                // the bound.
                _ => None,
            };
            if let Some(total) = total
                && total > files.limit_bytes
            {
                note!(
                    "kata-provider-youki: container {container_id} breached its combined capture \
                     bound ({total} > {} bytes spooled): killing the container itself first, \
                     then the runtime client",
                    files.limit_bytes
                );
                return match cancel(child, youki, staged, container_id) {
                    Cancellation::TornDown => Watched::CaptureExceeded,
                    Cancellation::Unreaped(message) => Watched::Unreadable(message),
                };
            }
        }
        let cancelled = match incoming.try_recv() {
            Ok(FromSupervisor::Closed) | Err(mpsc::TryRecvError::Disconnected) => {
                Some("the supervisor closed the frame stream".to_owned())
            }
            Ok(FromSupervisor::Broken(message)) => {
                Some(format!("the frame stream could not be read: {message}"))
            }
            // A frame arriving while an assignment is in flight is a protocol
            // violation — the supervisor writes one assignment and reads its
            // answer — and it is treated as a cancellation rather than queued,
            // because this provider cannot tell which of the two assignments the
            // container it is holding belongs to.
            Ok(FromSupervisor::Frame(_)) => {
                Some("a second frame arrived while this assignment was in flight".to_owned())
            }
            Err(mpsc::TryRecvError::Empty) => None,
        };
        let cancelled = cancelled.or_else(|| {
            TERMINATED
                .load(Ordering::SeqCst)
                .then(|| "SIGTERM".to_owned())
        });
        if let Some(reason) = cancelled {
            note!(
                "kata-provider-youki: cancelling container {container_id} ({reason}): killing the \
                 container itself first, then the runtime client"
            );
            return match cancel(child, youki, staged, container_id) {
                Cancellation::TornDown => Watched::Cancelled,
                Cancellation::Unreaped(message) => Watched::Unreadable(message),
            };
        }
        std::thread::sleep(WATCH_INTERVAL);
    }
}

/// What a `youki run` client that exited on its own says about the stage.
///
/// # The client's status is the init's only once its own delete is SEEN finished
///
/// youki 0.7.0's `run` (`crates/youki/src/commands/run.rs`) waits for the init,
/// then calls `container.delete(true)?`, and only after that returns the init's
/// status for `main` to exit with. Any error on that path — the start, the
/// foreground wait, or the delete — is returned instead, and `main` exits `-1`,
/// which is `255`, with the init's status discarded. `Container::delete` ends in
/// `remove_dir_all` of the container directory, `<--root>/<id>`
/// (`crates/libcontainer/src/container/container_delete.rs`), so a client that
/// returned the init's status has removed it. A container directory still present
/// when the client is reaped therefore means the client failed — and the number
/// it exited with is youki's own.
///
/// The case that reaches it in production is
/// `kata_worker::interactive_capsule::InteractiveCapsuleHandle::signal`'s third outcome: a
/// concurrent `youki kill`'s `stopped` save creates its temporary file after the
/// client's delete listed the directory, the final `rmdir` fails `ENOTEMPTY`, and
/// the client exits `255` over an init that exited `143` on its `SIGTERM`.
///
/// The check runs BEFORE [`delete_force`], which removes what the failed client
/// left. Once the create has made the directory, nothing but that client's own
/// delete removes it, and nothing recreates it: a save that opens its temporary
/// file after the `rmdir` fails `ENOENT` (the `failed to open container state
/// file` outcome). So an absent directory is a delete the client finished — or a
/// client that failed with no directory left, the set below.
///
/// # Refused set — the client statuses NOT forwarded as the stage's
///
/// Every one whose container directory is present at the reap, or whose absence
/// cannot be confirmed (a `stat` that fails other than `ENOENT`): those are
/// [`Watched::ClientFailed`], reported as `exit_code: None` and named on this
/// process's stderr. That covers the delete race above, a delete that failed
/// removing the cgroup or running a `poststop` hook, a foreground wait that
/// failed before a delete that then failed too, a start that failed after the
/// create succeeded (`run` returns before its delete), and an id already present
/// (`InitContainerBuilder::create_container_dir` refuses `Exist` and leaves the
/// directory it found — which only an outside writer makes, as `materialize`
/// refuses an existing bundle). The last two may not have run the stage at all:
/// `None` here says the client did not finish its own delete, so no exit status of
/// the stage's own reached this provider — never that the stage ran or exited.
///
/// NOT caught, stated: a client error that leaves no directory — one before the
/// directory exists (loading or validating the spec), a create that failed and
/// removed its own directory (`cleanup_container`), or a failed foreground wait
/// whose delete then succeeded. Each still exits `255` and
/// is forwarded as `Some(255)`; none is reached by a concurrent kill, and telling
/// them from a stage that exited `255` would need youki's own error report, which
/// goes to the stage's stderr with the stage's bytes.
fn client_exit(code: Option<i32>, container_dir: &Path) -> Watched {
    let seen = match std::fs::symlink_metadata(container_dir) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Watched::Exited(code),
        Ok(_) => "is still present".to_owned(),
        Err(error) => format!("could not be confirmed absent ({error})"),
    };
    note!(
        "kata-provider-youki: the runtime client exited {code:?} and its container directory \
         {dir} {seen}, so the client did not finish its own delete and its status is not the \
         stage's: reporting no exit status",
        dir = container_dir.display(),
    );
    Watched::ClientFailed
}

/// Kill the CONTAINER, then the client. **The order is the measurement, and the
/// LOOP is the race.**
///
/// # Order
///
/// `youki kill <id> KILL` reaches the init inside `youki-<id>.scope`, which is a
/// cgroup the client does not live in: killing the client first leaves the
/// container `Running` (MEASURED on the reference host — see the module
/// docs, and `oci_provider_live.rs` reds on it).
///
/// # Why the kill is a BOUNDED LOOP and not one call
///
/// A cancellation can land in the window between `spawn` and the container being
/// REGISTERED — youki is still creating it. One `youki kill` there fails (there is
/// nothing to resolve yet), and a provider that then `SIGKILL`ed the client would
/// kill it MID-CREATE: `delete --force` finds no state to clear, and whatever the
/// runtime had already forked survives with nothing left watching it. That is the
/// same leak the wrong ORDER produces, reached through timing instead.
///
/// So the kill is retried every [`WATCH_INTERVAL`] until one SUCCEEDS — which is
/// only possible once the container exists, and means its init has been `SIGKILL`ed
/// — or until the client exits on its own, which is the other way there is nothing
/// left to create. [`CANCEL_KILL_ATTEMPTS`] bounds it: a runtime wedged in `Creating`
/// must not make a cancellation hang, so the last resort is still to `SIGKILL` the
/// client, and that case is REPORTED on stderr rather than passed off as a clean
/// teardown.
///
/// # Why the runtime's last write does not matter here
///
/// A `kill` that lands while the container is `Created` saves `stopped` while the
/// client's start saves `running`. The pinned youki renames each `state.json` into
/// place whole (`nix/youki-0.7.0-atomic-state-save.patch`), so no reader sees a torn
/// document, but the LAST rename wins and either order is possible. Neither changes
/// this teardown, read from youki 0.7.0's source:
///
/// * every `kill` and `delete` loads through `Container::refresh_status`, which
///   derives the status from the init pid: a dead or zombie init is `Stopped`
///   whatever the file says, and a live one keeps only a stored `Created`,
///   `Creating` or `Paused`. A `kill` that exited 0 has already delivered `SIGKILL`
///   before it saved, so both documents describe an init that is gone;
/// * `Container::delete` with `force` refuses no status — `Stopped` proceeds, every
///   other status `SIGKILL`s the container's cgroup first — so the status chooses
///   only whether that extra kill runs, never whether the container is removed;
/// * a kill that lands before the start releases the init either fails the start
///   (a `Stopped` refresh, or a refused notify socket), and the client exits without
///   its own delete, or lets the client reap the dead init and delete; whatever the
///   client leaves is [`delete_force`]'s, which runs only after this function has
///   reaped the client, so no youki writer is left to race it; and
/// * the outcome is this provider's (`Cancelled`, exit `None`), never the file's.
///
/// The one teardown the atomic save does change is the last resort above: a client
/// `SIGKILL`ed mid-save leaves the previous document rather than a truncated one,
/// which `delete --force` could not load.
fn cancel(
    child: &mut Child,
    youki: &PinnedRuntime,
    staged: &Materialized,
    container_id: &str,
) -> Cancellation {
    let mut reached = false;
    let mut client_exited = false;
    let mut attempts = 0u32;
    while attempts < CANCEL_KILL_ATTEMPTS {
        attempts += 1;
        if youki_command(youki, staged)
            .args(["kill", container_id, "KILL"])
            .status()
            .is_ok_and(|status| status.success())
        {
            reached = true;
            break;
        }
        // A `kill` that failed has two explanations and they need the same
        // treatment for opposite reasons: the container does not exist YET (keep
        // trying — this is the race), or it does not exist ANY MORE (the client is
        // about to exit and there is nothing to reach). `try_wait` tells them apart.
        match child.try_wait() {
            Ok(Some(_)) => {
                client_exited = true;
                break;
            }
            Ok(None) => {}
            Err(_) => break,
        }
        std::thread::sleep(WATCH_INTERVAL);
    }
    if !reached && !client_exited {
        note!(
            "kata-provider-youki: container {container_id} was never reachable by `youki kill` in \
             {attempts} attempt(s) and the runtime client had not exited; SIGKILLing the client as \
             a last resort. Anything the runtime forked before this point may SURVIVE — this is \
             the one teardown path this provider cannot make clean, and it says so rather than \
             reporting a sweep it did not perform."
        );
    }
    // The client is kata's own direct child; a kill that fails because it has
    // already exited is the success case, so the verdict is deliberately dropped.
    // It usually HAS already exited: the `youki kill` above ends the container and
    // the client observes that — MEASURED, with `youki run` exiting `9` for a
    // container killed by `SIGKILL`.
    child.kill().ok();
    match child.wait() {
        // **The client's status is deliberately DISCARDED here**, and reporting it
        // would be the defect: `youki run` encodes a signalled container as its
        // SIGNAL NUMBER in its own exit code, so a cancelled stage arrives as `9` —
        // indistinguishable on the wire from a stage that exited 9 by itself. The
        // stage did not exit at all; this provider killed it. `None` is the
        // protocol's word for exactly that (`StageCompleted::exit_code`), and it is
        // the one answer a supervisor can act on.
        Ok(_) => Cancellation::TornDown,
        Err(e) => Cancellation::Unreaped(format!("reaping the killed runtime client: {e}")),
    }
}

/// What [`cancel`] observed. Two arms, because a teardown that could not reap its
/// own child is not a teardown that worked.
///
/// Whether the `youki kill` really LANDED (as against the last-resort path) is not
/// an arm here: it is not a different answer to the supervisor — the stage is gone
/// or unaccounted for either way, and the frame says `None` — so it is reported
/// where it is observed, on stderr inside [`cancel`], rather than folded into a
/// value a caller would have to interpret.
enum Cancellation {
    /// The container was killed (or was already gone) and the client is reaped.
    TornDown,
    /// Waiting on the killed client failed, so this process cannot say the subtree
    /// is gone.
    Unreaped(String),
}

/// `youki delete --force <id>`, unconditionally and ignoring its own verdict.
///
/// This is a teardown and not a measurement: a `delete` of a container that is
/// already gone exits non-zero, and treating that as a failure would turn every
/// clean run into one.
fn delete_force(youki: &PinnedRuntime, staged: &Materialized, container_id: &str) {
    youki_command(youki, staged)
        .args(["delete", "--force", container_id])
        .status()
        .ok();
}

/// The pinned runtime with an EMPTY environment — every `youki` this provider
/// spawns is built here.
///
/// The runtime needs nothing from it (the pin is an absolute path, the state root
/// rides `--root`, the container's environment is the bundle's `process.env`), and
/// whatever this process was started with is not this provider's to pass on: kata
/// launches it with none, and a launcher that did not would otherwise hand the
/// runtime its whole environment.
fn runtime_command(youki: &PinnedRuntime) -> Command {
    let mut command = Command::new(&youki.store_path);
    command.env_clear();
    command
}

/// One runtime invocation against THIS assignment's state root.
///
/// `--root` is the whole reason `youki kill` and `youki delete` can reach the
/// container at all: with the runtime's default state root, a `kill` issued from
/// outside the client's own context fails to resolve the container. The state root
/// is attempt-local, so two assignments cannot see each other's containers.
fn youki_command(youki: &PinnedRuntime, staged: &Materialized) -> Command {
    let mut command = runtime_command(youki);
    command
        .arg("--root")
        .arg(&staged.state)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    command
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt as _;

    /// A file on disk standing in for the `kata-oci-hook` member, with its real
    /// sha256 — the pin and the path are the two halves the check holds apart.
    fn hook_file(bytes: &[u8]) -> (PathBuf, String) {
        let path = std::env::temp_dir().join(format!(
            "kata-youki-hook-test-{}-{}",
            std::process::id(),
            bytes.len()
        ));
        std::fs::write(&path, bytes).expect("the fixture hook is written");
        let sha256 = format!("{:x}", Sha256::digest(bytes));
        (path, sha256)
    }

    /// The `config.json` hooks block exactly as `oci_bundle`'s render emits it:
    /// two `createContainer` entries on the ONE pinned path.
    fn config_with_hooks(hook_path: &str) -> String {
        serde_json::json!({
            "process": {},
            "hooks": {
                "createContainer": [
                    {"path": hook_path, "args": [hook_path, "loopback-up", "--ip", "/ip"]},
                    {"path": hook_path, "args": [hook_path, "hand-listener", "--port", "19200", "--to", "/s"]}
                ]
            }
        })
        .to_string()
    }

    /// **A hook whose bytes do not match the pin refuses as `hook_digest_mismatch`
    /// — by name, before any `execve`.**
    ///
    /// The refused set's sharpest arm: the path is right, the phase is right, and
    /// only the digest can say the bytes are not the pinned ones.
    #[test]
    fn a_hook_whose_bytes_moved_is_refused_by_name() {
        let (path, _real_sha) = hook_file(b"not the pinned hook");
        let pinned = PinnedRuntime {
            store_path: path.to_string_lossy().into_owned(),
            sha256: "0".repeat(64),
        };
        let refusal = verify_egress_hooks(Some(&pinned), &config_with_hooks(&pinned.store_path))
            .expect_err("a digest that moved is refused");
        assert!(
            refusal.starts_with("hook_digest_mismatch:"),
            "refused BY NAME: {refusal}"
        );
    }

    /// **The measured basis is the one argument this provider takes**: any other
    /// flag is refused by name before a frame is written, and so is a launch with
    /// no basis at all.
    #[test]
    fn every_argument_but_the_measured_basis_is_refused() {
        for flag in [
            "--announce-protocol",
            "--announce-containment",
            "--anything",
        ] {
            let argv = vec![flag.to_owned(), "nothing_enforced".to_owned()];
            let refusal = parse_measured_basis(&argv).expect_err("an unknown flag is refused");
            assert_eq!(refusal, format!("unknown flag `{flag}`"));
        }
        let refusal = parse_measured_basis(&[]).expect_err("a launch with no basis is refused");
        assert!(
            refusal.starts_with("`--measured-basis <json>` is REQUIRED"),
            "{refusal}"
        );
    }

    /// **Every way the two halves can disagree is refused before the digest is
    /// even consulted**: a pin with no hooks, hooks with no pin, a hook on a
    /// phase kata's render never emits, and a `createContainer` path that is not
    /// the pinned program.
    #[test]
    fn the_two_halves_must_agree_before_the_digest_is_consulted() {
        let (path, sha256) = hook_file(b"an honest hook");
        let hook = path.to_string_lossy().into_owned();
        let pinned = PinnedRuntime {
            store_path: hook.clone(),
            sha256,
        };
        let ok = config_with_hooks(&hook);
        assert!(
            verify_egress_hooks(Some(&pinned), &ok).is_ok(),
            "the honest pair passes"
        );

        // A pin, no hooks in the spec.
        let no_hooks = serde_json::json!({"process": {}}).to_string();
        assert!(
            verify_egress_hooks(Some(&pinned), &no_hooks).is_err(),
            "a pinned hook the spec never registers"
        );
        // Hooks in the spec, no pin.
        assert!(
            verify_egress_hooks(None, &ok).is_err(),
            "a spec that registers hooks the plan never pinned"
        );
        // A foreign phase — kata renders createContainer only.
        let foreign = serde_json::json!({
            "process": {},
            "hooks": {"prestart": [{"path": hook, "args": [hook]}]}
        })
        .to_string();
        let refusal =
            verify_egress_hooks(Some(&pinned), &foreign).expect_err("a phase kata never renders");
        assert!(refusal.contains("prestart"), "named: {refusal}");
        // A createContainer entry for a DIFFERENT program.
        let stranger = serde_json::json!({
            "process": {},
            "hooks": {"createContainer": [{"path": "/usr/bin/curl", "args": []}]}
        })
        .to_string();
        assert!(
            verify_egress_hooks(Some(&pinned), &stranger).is_err(),
            "a hook path the plan did not pin"
        );
        std::fs::remove_file(&path).ok();
    }

    /// A runtime CLIENT scripted by `script` (`sh -c`, with the container directory
    /// youki 0.7.0 keeps at `<--root>/<id>` as `$1`), handed to [`finish_container`]
    /// as if [`start_container`] had spawned it, and the frame that comes back.
    ///
    /// The plan's runtime is `true`, so the unconditional [`delete_force`] runs and
    /// touches nothing: what is left in the scratch root afterwards is what the
    /// script left.
    fn finish_a_scripted_client(test: &str, script: &str) -> (ProviderFrame, bool) {
        let root = std::env::temp_dir().join(format!(
            "kata-youki-scripted-client-{test}-{}",
            std::process::id()
        ));
        std::fs::remove_dir_all(&root).ok();
        let container_id = "scripted";
        let staged = Materialized {
            bundle: root.join(container_id).join("bundle"),
            state: root.join(container_id).join("state"),
        };
        std::fs::create_dir_all(&staged.state).expect("a scratch runtime state root");
        let state_root = staged.state.clone();
        let container_dir = staged.state.join(container_id);
        let plan = OciBundlePlan {
            config_json: "{}".to_string(),
            rootfs_mountpoints: Vec::new(),
            container_id: container_id.to_string(),
            youki: PinnedRuntime {
                store_path: "true".to_string(),
                sha256: "0".repeat(64),
            },
            cgroup_parent: None,
            state_root: root.to_string_lossy().into_owned(),
            stdio: OciStdio::Captured,
            egress_hook: None,
        };
        let child = Command::new("sh")
            .arg("-c")
            .arg(script)
            .arg("sh")
            .arg(&container_dir)
            .stdin(Stdio::null())
            .spawn()
            .expect("the scripted client spawns");
        // The sender is held for the whole call: a dropped one is a supervisor EOF,
        // which is a cancellation and not the exit under test.
        let (_frames, incoming) = mpsc::channel::<FromSupervisor>();
        let frame = finish_container(
            "scripted-assignment",
            &plan,
            Started {
                child,
                staged,
                captures: None,
            },
            &incoming,
        );
        // A script may have taken the state root's permissions away; give them back
        // so the residue can be read and the scratch root removed.
        std::fs::set_permissions(&state_root, std::fs::Permissions::from_mode(0o755))
            .expect("the state root's permissions restored");
        let residue = container_dir.exists();
        std::fs::remove_dir_all(&root).ok();
        (frame, residue)
    }

    /// **A client that exits 255 and leaves its container directory behind did
    /// not report the stage's exit: the frame says `None`, not `Some(255)`.**
    ///
    /// The scripted client is youki 0.7.0's `run` failing in its own delete — the
    /// concurrent `youki kill`'s `stopped` save creating its temporary file after
    /// the delete listed the directory, so the final `rmdir` fails `ENOTEMPTY`
    /// (`interactive_capsule::InteractiveCapsuleHandle::signal`'s third outcome): the
    /// directory survives and `main` exits `-1`.
    ///
    /// **Would red if:** the provider forwarded the client's status without
    /// looking for the directory its own delete removes.
    #[test]
    fn a_client_that_exits_255_leaving_its_container_directory_reports_no_exit_status() {
        let (frame, residue) = finish_a_scripted_client(
            "residue",
            r#"mkdir -p "$1" && : > "$1/state.json.1.tmp" && exit 255"#,
        );
        assert!(residue, "the scripted client left its container directory");
        let ProviderFrame::Completed(completed) = frame else {
            panic!("the stage ran, so the answer is a completion: {frame:?}");
        };
        assert_eq!(
            completed.exit_code, None,
            "youki's own 255, with its delete unfinished, is not the stage's exit status"
        );
        assert!(!completed.capture_exceeded);
    }

    /// **A client that exits 255 with its delete FINISHED is a stage that exited
    /// 255: the frame says `Some(255)`.** The twin of the cell above — youki's
    /// `run` returns the init's status only after its delete removed the
    /// directory, so a 255 with no directory is the stage's own.
    ///
    /// **Would red if:** the provider read any 255 as the client's, or looked for
    /// residue somewhere that is present on every run (the state root itself).
    #[test]
    fn a_client_that_exits_255_with_its_delete_finished_reports_the_stages_255() {
        let (frame, residue) = finish_a_scripted_client("clean", "exit 255");
        assert!(!residue, "the scripted client left no container directory");
        let ProviderFrame::Completed(completed) = frame else {
            panic!("the stage ran, so the answer is a completion: {frame:?}");
        };
        assert_eq!(completed.exit_code, Some(255));
    }

    /// **A client that exits 255 when its container directory's absence cannot be
    /// CONFIRMED reports no exit status: the frame says `None`, not `Some(255)`.**
    /// The scripted client takes every permission off the state root before it
    /// exits, so the provider's `stat` of `<root>/<id>` fails `EACCES` rather than
    /// `ENOENT` — the arm of [`client_exit`]'s refused set that is not a directory
    /// seen present.
    ///
    /// **Would red if:** the provider read a `stat` that failed other than
    /// `ENOENT` as a delete the client finished, and forwarded its 255.
    #[test]
    fn a_client_that_exits_255_with_its_container_directory_unconfirmed_reports_no_exit_status() {
        // The arm needs a `stat` that fails other than `ENOENT`; a process that
        // bypasses directory permissions (root, `CAP_DAC_OVERRIDE`) cannot drive
        // it, and this cell refuses rather than passes on such a host.
        let probe = std::env::temp_dir().join(format!(
            "kata-youki-scripted-client-probe-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&probe).expect("a scratch probe directory");
        std::fs::set_permissions(&probe, std::fs::Permissions::from_mode(0o000))
            .expect("the probe's permissions taken away");
        let probed = std::fs::symlink_metadata(probe.join("child")).map(|_| ());
        std::fs::set_permissions(&probe, std::fs::Permissions::from_mode(0o755))
            .expect("the probe's permissions restored");
        std::fs::remove_dir_all(&probe).ok();
        assert_eq!(
            probed.map_err(|error| error.kind()),
            Err(std::io::ErrorKind::PermissionDenied),
            "this host's stat under a 000 directory must fail EACCES for the cell to reach the arm"
        );

        let (frame, residue) =
            finish_a_scripted_client("unconfirmed", r#"chmod 000 "${1%/*}" && exit 255"#);
        assert!(!residue, "the scripted client made no container directory");
        let ProviderFrame::Completed(completed) = frame else {
            panic!("the stage ran, so the answer is a completion: {frame:?}");
        };
        assert_eq!(
            completed.exit_code, None,
            "a 255 whose container directory could not be confirmed absent is not the stage's"
        );
        assert!(!completed.capture_exceeded);
    }

    /// **The rootfs's passwd entry gives root a shell whose TYPE is `sh`** —
    /// read back off the filesystem from a materialized bundle. The rootfs has
    /// no `/bin`, so a process that resolves its login shell from this entry
    /// finds it by that name on `PATH`.
    ///
    /// **Would red if:** the entry named another shell, or none.
    #[test]
    fn the_capsule_root_login_shell_is_sh() {
        let root = std::env::temp_dir().join(format!(
            "kata-youki-login-shell-test-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&root).expect("a scratch state root");
        let plan = OciBundlePlan {
            config_json: "{}".to_string(),
            rootfs_mountpoints: Vec::new(),
            container_id: "login-shell".to_string(),
            youki: PinnedRuntime {
                store_path: "/nonexistent".to_string(),
                sha256: "0".repeat(64),
            },
            cgroup_parent: None,
            state_root: root.to_string_lossy().into_owned(),
            stdio: OciStdio::Captured,
            egress_hook: None,
        };
        let materialized = materialize(&root, &plan).expect("the bundle materializes");
        let passwd = std::fs::read_to_string(materialized.bundle.join("rootfs/etc/passwd"))
            .expect("the provider wrote /etc/passwd");
        std::fs::remove_dir_all(&root).ok();
        let fields: Vec<&str> = passwd.trim_end().split(':').collect();
        assert_eq!(fields.len(), 7, "one passwd entry: {passwd:?}");
        assert_eq!(fields[..3], ["root", "x", "0"], "{passwd:?}");
        assert_eq!(
            Path::new(fields[6])
                .file_name()
                .and_then(|name| name.to_str()),
            Some("sh"),
            "root's login shell type is `sh`: {passwd:?}"
        );
    }

    /// **Every runtime invocation this provider makes starts with an EMPTY
    /// environment, whatever this process holds.**
    ///
    /// The runtime is a script that writes the kernel's copy of the environment it
    /// was started with (`/proc/$$/environ`) to a file; this test process holds
    /// cargo's variables, so an inherited environment is non-empty. Read from
    /// `/proc`, not from the command under test.
    ///
    /// **Would red if:** [`runtime_command`], which [`youki_command`] and the `run`
    /// spawn both build on, stopped clearing the environment (measured: with the
    /// clear absent, the record holds cargo's variables).
    #[test]
    fn the_runtime_is_spawned_with_an_empty_environment() {
        let root =
            std::env::temp_dir().join(format!("kata-youki-runtime-environ-{}", std::process::id()));
        std::fs::remove_dir_all(&root).ok();
        std::fs::create_dir_all(&root).expect("a scratch root");
        let record = root.join("environ");
        let script = root.join("youki");
        std::fs::write(
            &script,
            format!(
                "#!/bin/sh\n/bin/cat /proc/$$/environ > {}\n",
                record.display()
            ),
        )
        .expect("the recording runtime is written");
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755))
            .expect("the recording runtime is executable");
        let own = std::fs::read("/proc/self/environ").expect("this process's environment");
        assert!(
            !own.is_empty(),
            "this process holds no environment, so an empty record would prove nothing"
        );
        let youki = PinnedRuntime {
            store_path: script.to_string_lossy().into_owned(),
            sha256: "0".repeat(64),
        };
        let staged = Materialized {
            bundle: root.join("bundle"),
            state: root.join("state"),
        };
        let status = youki_command(&youki, &staged)
            .arg("state")
            .status()
            .expect("the recording runtime runs");
        let recorded = std::fs::read(&record).expect("the runtime recorded its environment");
        std::fs::remove_dir_all(&root).ok();
        assert!(status.success(), "the recording runtime exited {status}");
        assert!(
            recorded.is_empty(),
            "the runtime was started with an environment: {:?}",
            String::from_utf8_lossy(&recorded)
                .split('\0')
                .filter_map(|entry| entry.split('=').next())
                .collect::<Vec<_>>(),
        );
    }
}
