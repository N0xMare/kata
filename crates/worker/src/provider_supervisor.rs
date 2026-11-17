//! The **`ProviderSupervisor`**: kata's side of one external provider process.
//!
//! # What this is, in kata's four-word vocabulary
//!
//! A **route** ([`crate::execution_route`]) decides that a stage goes to a
//! provider. A **provider** is the process kata does not link. A **supervisor**
//! is this: the thing that installs kata's seccomp floor, spawns the provider
//! through the ONE production spawn path, admits or refuses its handshake,
//! assigns it work, and tears it down. A **runtime** is none of those — it is
//! the OCI runtime (the pinned youki) a provider drives, and nothing in this
//! file is one.
//!
//! # This is the ONLY production install site of the floor
//!
//! No other production code puts `kata_floor_bpf()` on a `CommandPrefix`. Here
//! the floored child is a process kata does not link, which then forks a stage —
//! so the floor's three properties (installed by kata, inherited across `fork`,
//! preserved across `execve`) are all exercised on the path the proof is about.
//!
//! `ProviderFloor::Installed` is the only value any production caller can reach.
//!
//! # Teardown is scored from the kernel
//!
//! A provider teardown is scored from `TeardownProbe::CgroupPopulation` and
//! from nothing else. The producer
//! ([`crate::process::observe_cgroup_empty`]) is reached here on every path a
//! provider can leave by: an orderly [`ProviderSupervisor::shutdown`], an abrupt
//! [`ProviderSupervisor::kill_and_contain`], and a REFUSED handshake — which
//! must not merely `start_kill` and return, or whatever the peer had already
//! forked would go unwatched and the outer cgroup directory would stay behind.
//!
//! A login session's cgroup is not delegated, but `systemd-run --user --scope
//! -p Delegate=yes` supplies one at zero privilege. So `Confirmed` is reachable
//! on an ordinary host, and `crates/worker/tests/oci_provider_live.rs` reaches
//! it.
//!
//! # The supervisor is USED, not merely working
//!
//! *A mechanism that works is not a mechanism that is used.* For this module
//! the answer is BOTH: [`crate::oci_driver::OciStageDriver`] is the one
//! production caller, driving the capsule route's own provider.

use std::path::{Path, PathBuf};
use std::time::Duration;

use kata_agent::CommandPrefix;
use kata_agent::resource_bounds::{
    AmbiguousTeardown, CgroupPlan, ResourceBounds, TeardownOutcome, TeardownProbe,
};
use kata_provider_protocol::{
    AdmittedProvider, AssignStage, AssignmentAccepted, AssignmentRefused, CaptureSpec,
    FRAME_HEADER_BYTES, MeasuredUsernsRestriction, OciBundlePlan, OciMeasuredBasis,
    OpeningFrameError, PROTOCOL_VERSION, PinnedRuntime, ProviderFrame, ProviderRefusal,
    StageCompleted, SupervisorFrame, admit, body_len, decode_frame, decode_opening_frame,
    encode_frame,
};
use kata_types::error::{KataError, KataResult};
use tokio::io::{AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::process::{Child, ChildStdin, ChildStdout};

use crate::execution_route::EXTERNAL_PROVIDER_ENV;
use crate::sandbox_bounds::CgroupDelegation;

/// A provider named `x` is the executable `kata-provider-x` **inside its store
/// entry**.
///
/// # There is no `PATH` lookup
///
/// `PATH` lookup is non-hermetic: it reads the environment of whatever process
/// the worker happens to be, so one node resolves different bytes as its
/// environment changes — and the environment of a worker loop embedded in
/// the main is not the environment of the standalone `kata-worker`. Resolution
/// by filesystem LOCATION ("next to the kata binary") is refused with it: a path
/// is still a NAME for whatever bytes currently sit there.
///
/// A provider is identified by CONTENT ([`crate::provider_store`]): node
/// configuration names a content address, kata resolves it through a by-hash
/// store to a HOST path, and this prefix is what picks the executable INSIDE the
/// resolved entry.
///
/// # Why the name prefix is enough
///
/// A `KATA_EXTERNAL_EXECUTION_PROVIDER_BIN` path variable would let the NAME an
/// operator declares and the BINARY that answers disagree with nothing
/// observing the difference. That is true of a path — and it is not true of a
/// digest, because the name IS the contents.
/// The convention survives because it is what lets one store entry answer for a
/// NAMED provider without a second knob pointing at a file, and the handshake
/// still checks the announced name against the declared one
/// (`ProviderRefusal::ProviderIdentityMismatch`), so the convention is not the
/// only thing binding the two.
pub const PROVIDER_BINARY_PREFIX: &str = "kata-provider-";

/// The default budget for the provider's opening frame.
///
/// A provider that has not said hello in this long is a provider that will never
/// say hello, and a supervisor holds bounds rather than blocking forever on a
/// peer it does not trust.
pub const DEFAULT_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(30);

/// The slack a provider's frame budget carries PAST the stage's own wall clock: the
/// provider's own work around the stage — planning and launching the container before
/// it runs, killing and deleting it after — which the stage's clock does not include.
///
/// # There is no default stage budget
///
/// A stage's own hashed `timeout_ms` (a capsule's `wall_time_ms`, which is folded from
/// it) is the ONLY wall clock: a cap outside the program's hash is a cap the program
/// never agreed to — a constant 120 s would SIGKILL a capsule that asked for three
/// minutes at two. [`ProviderLaunchSpec::production`] therefore TAKES the stage's budget, and this
/// margin is the only number the supervisor adds to it, measured from the ASSIGNMENT.
///
/// On the capsule route the worker's kill is therefore issued at the latest
/// `wall_time_ms` + this past the assignment — ONE deadline, taken before the `Assign`
/// frame is written and bounding the write, the acceptance and the terminal frame together
/// ([`ProviderSupervisor::assign_stage`]) — and the assignment is refused once
/// `kata_types::capsule_timing::CAPSULE_PREPARE_BUDGET_MS` has passed since the worker's
/// start anchor (`crate::oci_driver`'s `PrepareBudgetElapsed`). The main's
/// `CAPSULE_WALL_TIME_GRACE_MS` is DEFINED as the sum of the two plus a report slack,
/// measured from a fold that follows that anchor, so the kill is issued at least that
/// slack before the main may settle the attempt as lost. `kata_types::capsule_timing`
/// states the inequality and what it does not order: a successful stage's publication
/// and teardown, which fit only the report slack, and a suspend of the worker's host or a
/// step of the main's wall clock.
pub const PROVIDER_FRAME_MARGIN: Duration =
    Duration::from_millis(kata_types::capsule_timing::PROVIDER_FRAME_MARGIN_MS);

/// How long an orderly teardown (close stdin, let the provider exit) may take
/// before the supervisor stops asking and SIGKILLs.
pub const DEFAULT_TEARDOWN_GRACE: Duration = Duration::from_secs(5);

/// Whether this launch installs kata's seccomp floor on the provider.
///
/// # There are two variants and only one of them is reachable from production
///
/// *An operator must not be able to ask for an unfloored external provider.*
/// [`Self::AbsentForProofControl`] exists because the floor proof's
/// non-vacuity control is *the same provider, the same argv, the same
/// certificate, with the floor absent* — and a proof whose control cannot be
/// expressed is a proof that measured nothing.
///
/// The adversarial suite's controls use it too: they are arms with *the
/// relevant containment relaxed*, and under an external provider the relevant
/// containment includes the floor the provider carries, so a control that
/// relaxed only the stage fence would still be denied `ptrace` and
/// `process_vm_readv` by the floor and `Ledger::control` would fail on an
/// attack that could not be demonstrated. The suite DERIVES this arm from the
/// prefix it was handed rather than from a flag, which is why no knob appears
/// anywhere.
///
/// It is a Rust value in a
/// `#[doc(hidden)]` position, reachable only by a caller that names it in
/// source; no environment variable, config key or `ContainmentLever` produces
/// it, and `no_containment_lever_can_null_the_provider_floor`
/// (`crates/worker/tests/provider_supervisor.rs`) is the measurement
/// that says so rather than the claim.
/// `manual_non_exhaustive` fires on the `#[doc(hidden)]` last variant and its
/// suggestion — `#[non_exhaustive]`, or delete the variant — is wrong in both
/// directions here. The world is EXACTLY two arms and a third would be a review
/// event: `the_proof_control_arm_is_the_only_route_to_a_floorless_provider_prefix`
/// carries a dummy exhaustive match over both, which `#[non_exhaustive]` would
/// silently turn into a wildcard. And the hidden variant is the floor proof's
/// control, which is the opposite of dead.
#[allow(clippy::manual_non_exhaustive)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProviderFloor {
    /// PRODUCTION. `Some(kata_floor_bpf())` on the provider's `CommandPrefix`.
    Installed,
    /// **The floor proof's CONTROL ARM ONLY.** Never an operator
    /// knob; see the type's documentation.
    #[doc(hidden)]
    AbsentForProofControl,
}

impl ProviderFloor {
    /// The bytes this arm puts on the prefix.
    #[must_use]
    pub fn bytes(self) -> Option<Vec<u8>> {
        match self {
            ProviderFloor::Installed => Some(kata_types::sandbox_seccomp::kata_floor_bpf()),
            ProviderFloor::AbsentForProofControl => None,
        }
    }

    /// Stable token for the evidence line.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            ProviderFloor::Installed => "installed",
            ProviderFloor::AbsentForProofControl => "absent_for_proof_control",
        }
    }
}

/// Everything a launch needs, decided before a process exists.
#[derive(Clone, Debug)]
pub struct ProviderLaunchSpec {
    /// The resolved provider executable.
    pub binary: PathBuf,
    /// The name the operator declared, checked against what the binary
    /// announces.
    pub provider_name: String,
    /// Whether the floor is installed. Production: [`ProviderFloor::Installed`].
    pub floor: ProviderFloor,
    /// The rootless-OCI mechanism KATA MEASURED on this host, when it measured
    /// one.
    ///
    /// Two uses, and they are the same fact read from both sides of the wire:
    /// [`provider_command_prefix`] puts it on the provider's argv as
    /// `--measured-basis <json>`, and [`ProviderSupervisor::launch`] hands the
    /// same value to [`admit`] as the thing the provider's certificate must
    /// restate byte for byte. A provider can therefore only ECHO it, which is what
    /// makes `ClaimedContainment::ProviderEnforced` admissible at all.
    ///
    /// `None` on every host where this process has not certified the prerequisite,
    /// and `None` is not a relaxation: with it, `admit` refuses an enforcement
    /// claim as unmeasured. Production fills it from
    /// [`measured_basis_from_certification`]; see
    /// [`crate::oci_runtime::certified_oci_route`] for when a certification
    /// exists.
    pub measured_basis: Option<OciMeasuredBasis>,
    /// Budget for the opening frame.
    pub handshake_timeout: Duration,
    /// Budget for one assignment, from just before the `Assign` frame is written to the
    /// terminal frame — ONE deadline bounding the write, the acceptance and the
    /// completion together: the stage's own wall clock plus [`PROVIDER_FRAME_MARGIN`] on
    /// every production path.
    pub stage_timeout: Duration,
    /// Budget for an orderly teardown before SIGKILL.
    pub teardown_grace: Duration,
}

impl ProviderLaunchSpec {
    /// The PRODUCTION spec: floored, and the assignment's frame budget DERIVED from
    /// `stage_wall_clock` — the stage's own hashed `timeout_ms`, or a capsule's
    /// `wall_time_ms` — plus [`PROVIDER_FRAME_MARGIN`]. There is no default to fall
    /// back on; see [`PROVIDER_FRAME_MARGIN`] for why.
    #[must_use]
    pub fn production(
        binary: PathBuf,
        provider_name: impl Into<String>,
        stage_wall_clock: Duration,
    ) -> Self {
        Self {
            binary,
            provider_name: provider_name.into(),
            floor: ProviderFloor::Installed,
            // No basis by default, and the default is the fail-closed one: a
            // supervisor that has certified nothing admits no enforcement claim.
            // A caller holding a `YoukiCertification` sets it.
            measured_basis: None,
            handshake_timeout: DEFAULT_HANDSHAKE_TIMEOUT,
            stage_timeout: stage_wall_clock.saturating_add(PROVIDER_FRAME_MARGIN),
            teardown_grace: DEFAULT_TEARDOWN_GRACE,
        }
    }
}

/// **PURE** — the `CommandPrefix` a launch spawns through.
///
/// Pure over the spec and the bounds so a test can read back exactly what
/// production would spawn without spawning it — which is how
/// `the_production_provider_prefix_always_carries_the_shipped_floor` observes the field
/// rather than trusting the call graph.
///
/// The literal is EXHAUSTIVE, with no `..Default::default()`, and that is
/// deliberate: a new `CommandPrefix` field must be re-decided at every site that
/// builds a floored prefix rather than absorbed silently.
#[must_use]
pub fn provider_command_prefix(spec: &ProviderLaunchSpec, bounds: ResourceBounds) -> CommandPrefix {
    // The MEASURED BASIS rides ARGV and nothing else — it is the provider's only
    // argument. Not the environment, which an operator can set, and an instruction
    // to a provider that must not be operator-reachable is an argument; and not a
    // frame, because a provider writes its hello BEFORE it reads anything — that ordering is what lets a supervisor learn what it is
    // talking to before it hands over work, and a basis delivered as a frame would
    // have to be read first, inverting it.
    //
    // Serialized with `serde_json::to_string`, which cannot fail for this type
    // (`String`s, an `Option<String>`, a bool and a unit enum): the `map_or_else`
    // is there so an impossible failure is a MISSING BASIS — and therefore an
    // enforcement claim kata refuses — rather than a panic or an empty argument
    // the provider would read as a basis.
    let mut args: Vec<std::ffi::OsString> = Vec::new();
    if let Some(basis) = spec.measured_basis.as_ref()
        && let Ok(json) = serde_json::to_string(basis)
    {
        args.push("--measured-basis".into());
        args.push(json.into());
    }
    CommandPrefix {
        program: spec.binary.clone().into_os_string(),
        args,
        kata_floor_bpf: spec.floor.bytes(),
        resource_bounds: bounds,
    }
}

/// **PURE** — read kata's own rootless-OCI certification onto the wire, so a
/// provider can be held to restating it.
///
/// # This is the kata side of the measured basis's whole argument
///
/// This function is where kata's measurement becomes something a certificate can
/// be compared against. It is the ONLY producer of an
/// [`OciMeasuredBasis`] in this workspace, so *"what kata measured"* has one
/// spelling on both sides of [`admit`]'s equality.
///
/// The conversion is an **exhaustive destructure** of [`YoukiCertification`]
/// an axis added to the certification is `E0027` here rather than
/// a measured fact silently left out of the basis a provider quotes.
///
/// # What is dropped, deliberately, and why it is not a loss
///
/// * `spec_version` — the OCI spec version youki reports. It is a FLOOR check
///   (`>= 1.0`) that `certify_youki` already applied, and a basis is compared for
///   byte-equality rather than ordered; carrying it would add an axis whose only
///   meaning is a comparison that already happened.
/// * the delegation's `evidence` and its controller set. The basis carries the
///   PARENT directory, which is the fact a provider could be placed under; the
///   evidence is prose for an operator and would make two hosts that measured the
///   same delegation with different wording disagree on a certificate.
///
/// # `residue_denied` is a fact about KATA's deny list
///
/// True when the fence this route plans names every one of the 13
/// `ConstructionResidue` syscalls — read out of
/// [`kata_types::sandbox_seccomp::oci_seccomp_rules`] and the shipped partition,
/// so editing `DENIED_SYSCALLS` moves it. It is NOT an observation from inside a
/// container: that the kernel returns `EPERM` for each of them is the
/// adversarial A1' row. And it does not touch
/// `ProviderCertificate::declares_construction_residue_unverified`, which stays
/// `true` on every certificate — that declaration is about kata never verifying
/// the PROVIDER's residue handling, and a rule in kata's own spec is not that
/// verification.
#[must_use]
pub fn measured_basis_from_certification(
    certification: &crate::oci_runtime::YoukiCertification,
) -> OciMeasuredBasis {
    // EXHAUSTIVE DESTRUCTURE, applied to the type on kata's side of the
    // boundary.
    let crate::oci_runtime::YoukiCertification {
        store_path,
        sha256,
        version,
        // See the doc comment: a floor already applied, not an identity.
        spec_version: _,
        libseccomp_version,
        // The loaded-profile axis is `Loaded` or `Unknown`, and `Unknown` is an
        // unreadable kernel list rather than a fact about the profile. What binds
        // the profile NAME to the pinned path is the installed TEXT, whose digest
        // is the next field, so the basis carries that and not this.
        profile: _,
        installed_profile_sha256,
        userns_restriction,
        delegation,
        functional_probe_id,
    } = certification;
    let (major, minor, patch) = *version;
    OciMeasuredBasis {
        youki: PinnedRuntime {
            store_path: store_path.display().to_string(),
            sha256: sha256.clone(),
        },
        youki_version: format!("{major}.{minor}.{patch}"),
        // Carried THROUGH, not re-derived and not folded to a boolean: the
        // certification read this line out of the binary's own identification and
        // a basis is a measurement, so the value the runtime printed is what the
        // provider gets to echo.
        libseccomp_version: libseccomp_version.clone(),
        // From the PIN, because the pin is what the certification checked the
        // kernel's loaded list and `/etc/apparmor.d/<name>` against — the
        // certification carries no name of its own, and a name read from anywhere
        // else would be a name nothing verified.
        apparmor_profile_name: kata_types::youki_pin::YoukiPin::embedded()
            .profile_name()
            .to_owned(),
        apparmor_profile_sha256: installed_profile_sha256.clone(),
        userns_restriction: match userns_restriction {
            crate::oci_runtime::UsernsRestriction::Restricted => {
                MeasuredUsernsRestriction::Restricted
            }
            crate::oci_runtime::UsernsRestriction::Unrestricted => {
                MeasuredUsernsRestriction::Unrestricted
            }
            crate::oci_runtime::UsernsRestriction::Unknown => MeasuredUsernsRestriction::Unknown,
        },
        delegated_cgroup_parent: delegation
            .usable_parent
            .as_ref()
            .map(|parent| parent.display().to_string()),
        functional_probe_id: functional_probe_id.clone(),
        residue_denied: oci_fence_denies_the_construction_residue(),
    }
}

/// Does the fence this route plans name every `ConstructionResidue` syscall?
///
/// Read out of the two producers rather than counted by hand: a hand-counted
/// partition can sum to 28 against a 29-entry list, and this is the same
/// arithmetic one plane over.
fn oci_fence_denies_the_construction_residue() -> bool {
    let Ok(rules) = kata_types::sandbox_seccomp::oci_seccomp_rules() else {
        return false;
    };
    let named: std::collections::BTreeSet<&str> = rules
        .syscalls
        .iter()
        .flat_map(|rule| rule.names.iter().copied())
        .collect();
    kata_types::sandbox_seccomp::shipped_partition()
        .residue_names()
        .iter()
        .all(|name| named.contains(name))
}

/// **PURE** — the provider's outer cgroup, from a MEASURED delegation.
///
/// A `ProviderSupervisor` owns the provider process under an outer cgroup, so
/// the provider and everything it spawns are inside one kernel-accounted
/// subtree that kata created and the provider cannot leave. This reuses the
/// per-stage cgroup mechanism — `CommandPrefix::resource_bounds`, whose
/// `pre_exec` hook has the child place ITSELF into the cgroup with one
/// `write(2)` — rather than minting a second way to create a cgroup. A second
/// spelling of "put this child in a cgroup" is how two answers get minted.
///
/// **The parent comes from `measure_cgroup_delegation`, never from a directory
/// existing.** A `stat` read as "cgroup delegation: present" can be wrong in
/// either direction. `usable_parent` is `None` unless the probe really created,
/// wrote and removed a child there.
///
/// # TWO LEVELS, and a MEASUREMENT is why
///
/// The plan places the provider in `<sweep root>/provider` rather than in the
/// sweep root itself, so the swept cgroup has NO member processes of its own.
/// That is not tidiness: cgroup v2's no-internal-processes rule makes a cgroup
/// with both a member process and controllers enabled a `domain invalid` parent,
/// and **MEASURED on the reference host**, a container leaf nested under
/// such a cgroup cannot be populated at all — youki fails the container with
/// `EOPNOTSUPP` writing the init's pid to the leaf's `cgroup.procs`. The rootless
/// OCI route needs its own bounded parent INSIDE the swept subtree
/// ([`crate::oci_cgroup`]), so the provider sits one level down for that
/// subtree to exist.
///
/// The SWEEP ROOT is therefore [`CgroupPlan::parent`] and not
/// [`CgroupPlan::path`]: it is what [`ProviderSupervisor::kill_and_contain`]
/// sweeps and reads its verdict from, and it covers the provider's own leaf, the
/// per-container parents beside it, and anything either of them forked.
///
/// # ONE ROOT PER LAUNCH: `kata.provider.<name>.<pid>.<sequence>`
///
/// `sequence` is [`next_sweep_root_sequence`]'s process-local counter, so two launches
/// in one worker never name one directory. A name that stopped at the pid would be a
/// WEDGE: a supervisor dropped mid-stage kills its subtree through `cgroup.kill`
/// but cannot observe it empty, so it leaves the directory — and every later launch on
/// that worker would refuse `already exists` until restart, while the boot sweep (which
/// skips live pids) never clears it. The leftover root is reclaimed by the NEXT
/// launch instead ([`reclaim_orphaned_sweep_roots`]).
///
/// No knobs are applied at either level. This cgroup is for MEMBERSHIP
/// ACCOUNTING, not for a ceiling: teardown is scored from the subtree's
/// population, and a `memory.max` here would be a resource decision nobody asked
/// for — and would additionally bound the PROVIDER with a stage's budget, which
/// is not a bound anyone declared. The stage's bounds go on the per-container
/// parent, where they reach the stage and nothing else.
#[must_use]
pub fn outer_cgroup_bounds(
    delegation: &CgroupDelegation,
    provider_name: &str,
    sequence: u64,
) -> ResourceBounds {
    let Some(parent) = delegation.usable_parent.as_ref() else {
        return ResourceBounds::default();
    };
    ResourceBounds {
        cgroup: Some(CgroupPlan {
            // `kata.provider.` distinguishes an OUTER provider subtree from
            // the per-stage cgroups at a glance in `systemd-cgls`, which is
            // the only place an operator meets both.
            parent: parent.join(format!(
                "{PROVIDER_CGROUP_PREFIX}{provider_name}.{}.{sequence}",
                std::process::id()
            )),
            name: PROVIDER_CGROUP_LEAF.to_owned(),
        }),
    }
}

/// The prefix every provider sweep root's basename carries, so
/// [`sweep_stale_provider_cgroups`] recognizes one and an operator recognizes it in
/// `systemd-cgls`. The full name is `kata.provider.<provider name>.<pid>.<sequence>`.
pub const PROVIDER_CGROUP_PREFIX: &str = "kata.provider.";

/// The next per-launch sequence for [`outer_cgroup_bounds`]. Process-local and
/// monotonic: the pid in the name already separates processes.
#[must_use]
fn next_sweep_root_sequence() -> u64 {
    static SEQUENCE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    SEQUENCE.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
}

/// The owning worker pid a sweep root's basename carries, or `None` for a name that
/// is not `kata.provider.<name>.<pid>.<sequence>`. A provider name may itself contain
/// a dot, so the pid and the sequence are the LAST two fields.
fn sweep_root_owner(basename: &str) -> Option<u32> {
    let suffix = basename.strip_prefix(PROVIDER_CGROUP_PREFIX)?;
    let (rest, sequence) = suffix.rsplit_once('.')?;
    sequence.parse::<u64>().ok()?;
    let (name, pid) = rest.rsplit_once('.')?;
    if name.is_empty() {
        return None;
    }
    pid.parse::<u32>().ok()
}

/// The sweep roots a live [`SweepRoot`] or [`ProviderSupervisor`] in THIS process owns.
///
/// What lets [`reclaim_orphaned_sweep_roots`] tell a sibling stage's root — one a
/// concurrent launch in this worker holds, possibly still empty between its `mkdir` and
/// its spawn — from one a dropped supervisor abandoned. Both carry this pid; only the
/// registry distinguishes them.
fn owned_sweep_roots() -> &'static std::sync::Mutex<std::collections::BTreeSet<PathBuf>> {
    static OWNED: std::sync::OnceLock<std::sync::Mutex<std::collections::BTreeSet<PathBuf>>> =
        std::sync::OnceLock::new();
    OWNED.get_or_init(Default::default)
}

fn register_sweep_root(path: &Path) {
    owned_sweep_roots()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .insert(path.to_path_buf());
}

fn release_sweep_root(path: &Path) {
    owned_sweep_roots()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .remove(path);
}

/// Reclaim every sweep root under `parent` that names THIS process and that no live
/// supervisor in this process owns — the directory a dropped supervisor left, or one a
/// terminal path could not confirm empty.
///
/// Its members are killed (`cgroup.kill`: whatever is in an unowned root of this pid is
/// residue of this process's own abandoned stage, and nothing else will ever reap it),
/// the subtree is observed empty within `budget`, and only then removed depth-first.
/// A root that does not empty in time is LEFT and returned in the second list, for the
/// next launch or the next boot — never removed while it may still hold a member.
///
/// Runs at the start of every [`ProviderSupervisor::launch`], so the residue of one
/// cancelled or panicked stage is bounded by the next launch rather than by a restart.
///
/// Returns `(removed, left)`.
#[must_use]
fn reclaim_orphaned_sweep_roots(parent: &Path, budget: Duration) -> (Vec<PathBuf>, Vec<PathBuf>) {
    let me = std::process::id();
    let Ok(entries) = std::fs::read_dir(parent) else {
        return (Vec::new(), Vec::new());
    };
    let orphaned: Vec<PathBuf> = {
        let owned = owned_sweep_roots()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        entries
            .flatten()
            .filter(|entry| entry.file_type().is_ok_and(|t| t.is_dir()))
            .filter(|entry| {
                entry
                    .file_name()
                    .to_str()
                    .and_then(sweep_root_owner)
                    .is_some_and(|pid| pid == me)
            })
            .map(|entry| entry.path())
            .filter(|path| !owned.contains(path))
            .collect()
    };
    let mut removed = Vec::new();
    let mut left = Vec::new();
    for root in orphaned {
        let _ = crate::process::kill_cgroup_subtree(&root);
        let emptied = crate::process::observe_cgroup_empty(&root, budget);
        if emptied.is_confirmed() {
            remove_cgroup_tree(&root);
        }
        if root.exists() {
            left.push(root);
        } else {
            removed.push(root);
        }
    }
    (removed, left)
}

/// The basename of the provider's OWN cgroup inside the sweep root.
///
/// A leaf and not the sweep root itself, so the sweep root stays process-free and
/// can distribute controllers to the per-container parents beside it — see
/// [`outer_cgroup_bounds`] for the measurement that forces it.
pub const PROVIDER_CGROUP_LEAF: &str = "provider";

/// The sweep root, OWNED until a supervisor exists to own it.
///
/// # Why a guard and not a `PathBuf`
///
/// `ProviderSupervisor::launch` creates this directory BEFORE it spawns, and then
/// has six ways to fail: the spawn itself, either pipe missing, a hello frame that
/// is not a hello, an unreadable hello, and a refused certificate. Each of those
/// routes through [`contain`], which removes the tree only when the teardown is
/// `Confirmed` — so on an `Ambiguous` verdict, and on the spawn arm where there is
/// no child to contain at all, the directory survived the process that made it. An
/// empty cgroup nobody owns is residue an operator reads as a stage that is still
/// somewhere.
///
/// So the directory is owned here and the ownership is MOVED into the supervisor on
/// success by [`Self::into_established`]. Every failure path drops this value
/// instead, and `Drop` removes the tree — after `contain` has swept it, so the
/// removal is of an empty subtree or of nothing.
#[derive(Debug)]
struct SweepRoot {
    /// `None` once ownership has moved to the supervisor, or when this host
    /// delegates no cgroup and there was nothing to create.
    path: Option<PathBuf>,
}

impl SweepRoot {
    /// Create the sweep root `bounds` names, and enable the controllers its
    /// per-container children will need.
    ///
    /// `stage_cgroup` (the spawn-site consumer of [`CgroupPlan`]) creates the plan's
    /// own directory with a non-recursive `create_dir`, so the sweep root has to
    /// exist before the provider is spawned; and `cgroup.subtree_control` can only be
    /// written while the cgroup has no member processes, which is true exactly here —
    /// before the provider exists.
    ///
    /// # `AlreadyExists` is a REFUSAL, not an adoption
    ///
    /// The name carries this process's pid and a sequence this process never repeats,
    /// and [`reclaim_orphaned_sweep_roots`] has just removed every unowned root of this
    /// pid it could observe empty — so an existing directory is residue of a DEAD
    /// worker whose pid this kernel reused, with the same sequence, that would not
    /// empty. Adopting it would put this worker's providers and containers inside a
    /// subtree that may still hold the dead worker's descendants, and the first
    /// `contain` would then sweep processes this supervisor never launched — or score
    /// `Confirmed` over them. The next launch takes the next sequence, so this refuses
    /// one launch, not the worker.
    ///
    /// # Errors
    /// The OS text of the `mkdir`, naming the path. A `subtree_control` write that
    /// fails is NOT an error: it means the leaf beneath this root will carry no knob
    /// for that controller, which
    /// [`crate::oci_cgroup::OciParentCgroup::establish`] refuses BY NAME with the
    /// path in hand. Failing the whole launch here would refuse a provider over a
    /// controller no assignment may even ask for.
    fn establish(bounds: &ResourceBounds, delegation: &CgroupDelegation) -> Result<Self, String> {
        let Some(plan) = bounds.cgroup.as_ref() else {
            return Ok(Self { path: None });
        };
        let root = plan.parent.clone();
        // REGISTERED BEFORE the `mkdir`, so a concurrent launch's reclaimer can never
        // see this root existing and unowned in the instant between the two.
        register_sweep_root(&root);
        std::fs::create_dir(&root).map_err(|e| {
            release_sweep_root(&root);
            if e.kind() == std::io::ErrorKind::AlreadyExists {
                format!(
                    "{root} already exists and would not empty when this launch tried to reclaim \
                     it. Its name carries this process's pid and a per-launch sequence, so it is \
                     residue of a dead worker whose pid this kernel reused — never a subtree this \
                     process may adopt, because the first sweep would then reach descendants this \
                     supervisor never launched. The next launch takes a new sequence; remove the \
                     directory by hand once its `cgroup.procs` is empty.",
                    root = root.display(),
                )
            } else {
                format!("mkdir {}: {e}", root.display())
            }
        })?;
        let established = Self { path: Some(root) };
        let subtree = established
            .path
            .as_ref()
            .expect("just established")
            .join("cgroup.subtree_control");
        for controller in crate::sandbox_bounds::capsule_subtree_controllers(delegation) {
            if let Err(e) = std::fs::write(&subtree, format!("+{}", controller.token())) {
                // WARN and not debug: it is the difference between a host that can
                // bound a container and one that cannot, and the refusal an
                // assignment then earns is easier to read with the cause above it.
                tracing::warn!(
                    path = %subtree.display(),
                    controller = controller.token(),
                    cause = %e,
                    "the provider sweep root did not take a subtree controller, so a container \
                     placed beneath it will have no knob for that axis and the assignment will be \
                     refused"
                );
            }
        }
        Ok(established)
    }

    /// The directory, while this value still owns it.
    fn established(&self) -> Option<&Path> {
        self.path.as_deref()
    }

    /// Hand the directory to the caller and DISARM the guard.
    fn into_established(mut self) -> Option<PathBuf> {
        self.path.take()
    }
}

impl Drop for SweepRoot {
    fn drop(&mut self) {
        if let Some(path) = self.path.take() {
            remove_cgroup_tree(&path);
            // Released AFTER the removal: a root that would not go becomes reclaimable
            // by the next launch rather than owned by nobody.
            release_sweep_root(&path);
        }
    }
}

/// Remove every `kata.provider.*` subtree under the delegated parent whose worker
/// process is GONE — the crash-window residue a killed worker leaves.
///
/// # Why this exists and why it is a boot action
///
/// A worker that dies between [`SweepRoot::establish`] and its `Drop` — `SIGKILL`,
/// a panic in a thread that aborts, a power loss — leaves the directory, and
/// possibly the provider and container processes inside it. Nothing else reclaims it:
/// the supervisor that owned it is gone, and the next worker's sweep root has a
/// different pid in its name, so [`reclaim_orphaned_sweep_roots`] never looks there.
/// The residue then shows an operator a cgroup that looks like a live stage.
///
/// Residue of a LIVE worker — a supervisor dropped mid-stage — is not this function's:
/// that worker's own next launch reclaims it ([`reclaim_orphaned_sweep_roots`]).
///
/// # What it refuses to touch, and why that direction
///
/// A directory whose trailing pid is still a LIVE process is skipped: two workers
/// can share one uid and one delegated parent, and sweeping a live sibling's subtree
/// would kill its provider and its container. Pid reuse can therefore make this skip
/// residue that is really dead — which leaves a directory for an operator to see,
/// the safe direction — and can never make it kill a live one.
///
/// Returns what it removed, for the boot line. Best effort per entry: one unreadable
/// directory must not stop the rest, and the caller is a boot that has to come up.
pub fn sweep_stale_provider_cgroups(delegation: &CgroupDelegation) -> Vec<PathBuf> {
    let Some(parent) = delegation.usable_parent.as_ref() else {
        return Vec::new();
    };
    let Ok(entries) = std::fs::read_dir(parent) else {
        return Vec::new();
    };
    let mut removed = Vec::new();
    for entry in entries.flatten() {
        if !entry.file_type().is_ok_and(|t| t.is_dir()) {
            continue;
        }
        let Some(pid) = entry.file_name().to_str().and_then(sweep_root_owner) else {
            continue;
        };
        if std::path::Path::new(&format!("/proc/{pid}")).exists() {
            continue;
        }
        let path = entry.path();
        // The processes FIRST: `rmdir` on a populated cgroup is `EBUSY`, and a
        // directory removed without its members killed would be a leak wearing a
        // cleanup's name.
        let _ = crate::process::kill_cgroup_subtree(&path);
        remove_cgroup_tree(&path);
        if !path.exists() {
            removed.push(path);
        }
    }
    removed
}

// ---------------------------------------------------------------------------
// Containment of a provider that is going away, however it goes
// ---------------------------------------------------------------------------

/// What kata DID about a provider process and its subtree, and what it OBSERVED
/// afterwards.
///
/// The two are separate fields on purpose (the claimed/measured cut, applied to
/// a teardown): *kata SIGKILLed three descendants* is an action kata took, and
/// *the subtree is empty* is a fact the kernel reported. Folding them would let
/// "we did the kill" be read as "the residue is gone".
#[derive(Clone, Debug)]
pub struct ContainedResidue {
    /// The kernel's own word on the provider process itself.
    pub reaped: String,
    /// The subtree sweep: how many LIVE descendants were still in the outer
    /// cgroup after the provider was gone and were SIGKILLed, or why no sweep
    /// could be performed. `Ok(0)` and `Err(_)` are different facts and must not
    /// collapse: the first says there was no residue, the second says kata could
    /// not look.
    pub swept: Result<usize, String>,
    /// The teardown verdict, scored from [`TeardownProbe::CgroupPopulation`]
    /// and from nothing else.
    pub teardown: TeardownOutcome,
    /// The outer cgroup the verdict was read from, when one existed.
    pub outer_cgroup: Option<PathBuf>,
}

impl ContainedResidue {
    /// Whether the subtree's absence was OBSERVED — never merely requested.
    #[must_use]
    pub fn is_contained(&self) -> bool {
        matches!(
            &self.teardown,
            TeardownOutcome::Confirmed {
                probe: TeardownProbe::CgroupPopulation,
                ..
            }
        )
    }

    /// One line an operator can read: what kata did, what it saw, and — when the
    /// answer is not "gone" — what they can do about it.
    ///
    /// Every recourse named here is one that exists in this build and reaches
    /// this path: [`EXTERNAL_PROVIDER_ENV`] is read by
    /// [`crate::execution_route::declared_external_provider`], and the delegation
    /// remediation is QUOTED from `measure_cgroup_delegation`'s own measurement
    /// rather than composed here, so a host where the advice would be wrong
    /// produces different advice instead of the same sentence.
    #[must_use]
    pub fn operator_line(&self) -> String {
        let swept = match &self.swept {
            Ok(0) => {
                "the outer cgroup held no surviving descendant, so there was no residue to kill"
                    .to_owned()
            }
            Ok(n) => format!(
                "{n} descendant process(es) OUTLIVED the provider inside its outer cgroup and were \
                 SIGKILLed by kata — a process reparented to init is unreachable from any handle \
                 kata holds, and the cgroup is what made it reachable anyway"
            ),
            Err(why) => format!("no subtree sweep could be performed: {why}"),
        };
        match &self.teardown {
            TeardownOutcome::Confirmed { probe, elapsed_ms } => format!(
                "{reaped}. {swept}. The subtree's absence was CONFIRMED by `{probe}` after \
                 {elapsed_ms}ms — the kernel's own membership accounting, which covers a \
                 descendant that called setsid(2).",
                reaped = self.reaped,
                probe = probe.label(),
            ),
            TeardownOutcome::Ambiguous {
                reason: AmbiguousTeardown::StillPresentAtDeadline { observed },
                elapsed_ms,
            } => format!(
                "{reaped}. {swept}. After {elapsed_ms}ms the subtree was STILL POPULATED: \
                 {observed}. Nothing is claimed about it. Raise `{budget_env}` if this host is \
                 slow to reap, and inspect the cgroup directly ({cgroup}); the provider's own \
                 stderr is inherited by kata and is in this process's stderr.",
                reaped = self.reaped,
                budget_env = crate::process::TEARDOWN_CONFIRM_BUDGET_ENV,
                cgroup = self
                    .outer_cgroup
                    .as_ref()
                    .map_or_else(|| "none".to_owned(), |p| p.display().to_string()),
            ),
            TeardownOutcome::Ambiguous { reason, elapsed_ms } => format!(
                "{reaped}. {swept}. After {elapsed_ms}ms the teardown is AMBIGUOUS, which is \
                 kata's answer when it cannot look, rather than a clean success: \
                 {reason}. {recourse}",
                reaped = self.reaped,
                recourse = delegation_recourse(),
            ),
        }
    }
}

/// The recourse for a host that delegates no cgroup — QUOTED from the
/// measurement, never composed here.
///
/// `fold_cgroup_delegation` builds a `remediation` from what it actually
/// observed (which cgroup this process sits in, which step was refused), so the
/// advice names this host's own paths. A sentence written here would be the same
/// sentence on every host, including the ones where it is wrong — a recourse
/// nobody can invoke, in the message whose whole job is to name one that works.
fn delegation_recourse() -> String {
    match crate::sandbox_bounds::cgroup_delegation()
        .remediation
        .as_ref()
    {
        Some(remediation) => format!(
            "Kata scores this from the outer cgroup alone, and this host gave kata none. \
             Recourse: {remediation}"
        ),
        None => format!(
            "This host DOES delegate a cgroup, so the outer cgroup was not the missing piece — \
             read the observation above rather than changing the host. To stop routing this node \
             to an external provider entirely, unset `{env}`.",
            env = EXTERNAL_PROVIDER_ENV,
        ),
    }
}

/// Kill a provider process and CONTAIN whatever it left behind.
///
/// The ladder is `SIGKILL` on the direct child, reap, then sweep the outer cgroup
/// and read its population. Reaping the direct child says the direct child is
/// gone; it says NOTHING about a descendant the provider forked — which is the
/// entire reason the supervisor needs the cgroup and refuses `SignalProbe` here.
async fn contain(
    child: &mut Child,
    outer_cgroup: Option<&Path>,
    budget: Duration,
) -> ContainedResidue {
    let _ = child.start_kill();
    let reaped = match child.wait().await {
        Ok(status) => format!("the provider process reaped as {status}"),
        Err(e) => format!("the provider process could not be reaped: {e}"),
    };

    let Some(cgroup) = outer_cgroup.map(Path::to_path_buf) else {
        return ContainedResidue {
            reaped,
            swept: Err(
                "no outer cgroup was established — `measure_cgroup_delegation` reports this host \
                 does not delegate one, so the provider's subtree has no kernel-side membership \
                 accounting kata may read or sweep"
                    .to_owned(),
            ),
            teardown: TeardownOutcome::Ambiguous {
                reason: AmbiguousTeardown::Unobservable(
                    "kata scores a provider teardown from `TeardownProbe::CgroupPopulation` \
                     alone, and no outer cgroup exists on this host to read one from"
                        .to_owned(),
                ),
                elapsed_ms: 0,
            },
            outer_cgroup: None,
        };
    };

    let swept_cgroup = cgroup.clone();
    let (swept, teardown) = tokio::task::spawn_blocking(move || {
        // The sweep first, then the observation. The other order would read a
        // population kata was about to change and report it as the verdict.
        let swept = crate::process::kill_cgroup_subtree(&swept_cgroup);
        let teardown = crate::process::observe_cgroup_empty(&swept_cgroup, budget);
        (swept, teardown)
    })
    .await
    .unwrap_or_else(|e| {
        (
            Err(format!("the subtree sweep task did not complete: {e}")),
            TeardownOutcome::Ambiguous {
                reason: AmbiguousTeardown::Unobservable(format!(
                    "the blocking observation task did not complete: {e}"
                )),
                elapsed_ms: 0,
            },
        )
    });

    // Remove the directory only once its absence has been OBSERVED. `rmdir` on a
    // populated cgroup is `EBUSY`, so removing it early is impossible; removing
    // it on an AMBIGUOUS verdict would destroy the one surface an operator has
    // left to look at.
    //
    // DEPTH-FIRST, because the sweep root is a subtree:
    // the provider's own leaf, the per-container parents beside it, and the leaf a
    // runtime created inside one of those. A single `rmdir` on the root would be
    // `ENOTEMPTY` and would leave the whole tree behind — empty cgroup directories
    // an operator would read as a stage that is still somewhere.
    if matches!(teardown, TeardownOutcome::Confirmed { .. }) {
        remove_cgroup_tree(&cgroup);
    }

    ContainedResidue {
        reaped,
        swept,
        teardown,
        outer_cgroup: Some(cgroup),
    }
}

/// `rmdir` every cgroup in `root`'s subtree, children before parents.
///
/// Best effort and silent on failure, for the reason `contain` removes the tree at
/// all only after `Confirmed`: a directory that will not go is a populated cgroup,
/// which is a TEARDOWN fact the verdict above already carries, and a second error
/// channel for it would report the same thing twice in different words.
///
/// Not `remove_dir_all`: a cgroup directory's contents are kernel files that cannot
/// be unlinked, so the recursive helper would fail on the first knob. Only the
/// DIRECTORIES come out, and only bottom-up.
fn remove_cgroup_tree(root: &Path) {
    if let Ok(entries) = std::fs::read_dir(root) {
        for entry in entries.flatten() {
            if entry.file_type().is_ok_and(|t| t.is_dir()) {
                remove_cgroup_tree(&entry.path());
            }
        }
    }
    if let Err(e) = std::fs::remove_dir(root)
        && e.kind() != std::io::ErrorKind::NotFound
    {
        tracing::debug!(path = %root.display(), %e, "provider cgroup not removed");
    }
}

/// Whether a crashed provider had been OBSERVED to take work before it died.
///
/// **This type exists because of one trap**: *"the provider died and kata
/// coped"* is satisfiable by a provider
/// that never started*. A crash report that could not distinguish the two would
/// let the vacuous case be read as the proof. The distinction is derived from
/// what kata READ off the wire — the acceptance frame it holds and the number of
/// frames it decoded — never from what the rig believes it arranged.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CrashPrecondition {
    /// The provider ACCEPTED an assignment and produced its acceptance frame
    /// before it died. This is the crash proof's bar and the only value under
    /// which a crash arm proves anything.
    AcceptedAndFramed {
        /// The assignment the provider echoed back in its acceptance frame.
        assignment_id: String,
        /// How many frames kata decoded from this provider, hello included.
        frames_read: u32,
    },
    /// The provider died without ever accepting work. A crash arm that reaches
    /// this state has measured kata's error handling and NOTHING about a running
    /// provider.
    NeverAccepted {
        /// How many frames kata decoded from this provider, hello included.
        frames_read: u32,
    },
}

impl CrashPrecondition {
    /// Stable snake_case label — the metric dimension and the log field.
    #[must_use]
    pub const fn label(&self) -> &'static str {
        match self {
            CrashPrecondition::AcceptedAndFramed { .. } => "accepted_and_framed",
            CrashPrecondition::NeverAccepted { .. } => "never_accepted",
        }
    }

    /// Whether the crash proof's non-vacuity precondition is met.
    #[must_use]
    pub const fn satisfies_crash_proof_precondition(&self) -> bool {
        matches!(self, CrashPrecondition::AcceptedAndFramed { .. })
    }

    /// Frames kata decoded from this provider, hello included.
    #[must_use]
    pub const fn frames_read(&self) -> u32 {
        match self {
            CrashPrecondition::AcceptedAndFramed { frames_read, .. }
            | CrashPrecondition::NeverAccepted { frames_read } => *frames_read,
        }
    }
}

/// **The operator-facing record of a provider that stopped answering.**
///
/// A provider crash must be *contained AND explicit*.
/// Containment is [`ContainedResidue`]; explicitness is this type's
/// [`Display`](std::fmt::Display), which names the provider, what kata observed,
/// whether the provider had taken work, what happened to its descendants, and
/// what an operator can do — with every named recourse being one that exists in
/// this build.
#[derive(Clone, Debug)]
pub struct ProviderCrashReport {
    provider: String,
    provider_pid: Option<u32>,
    precondition: CrashPrecondition,
    loss: String,
    residue: ContainedResidue,
}

impl ProviderCrashReport {
    /// Stable snake_case label. THREE arms, because they are three different
    /// operational situations and an operator acts differently on each: the
    /// residue is provably gone, the residue is provably still there, or kata
    /// could not look.
    #[must_use]
    pub fn label(&self) -> &'static str {
        match &self.residue.teardown {
            TeardownOutcome::Confirmed { .. } => "provider_crash_contained",
            TeardownOutcome::Ambiguous {
                reason: AmbiguousTeardown::StillPresentAtDeadline { .. },
                ..
            } => "provider_crash_residue_survived",
            TeardownOutcome::Ambiguous { .. } => "provider_crash_residue_unobservable",
        }
    }

    /// Whether the crash proof's non-vacuity precondition was met.
    #[must_use]
    pub const fn precondition(&self) -> &CrashPrecondition {
        &self.precondition
    }

    /// What kata did about the process and its subtree, and what it observed.
    #[must_use]
    pub const fn residue(&self) -> &ContainedResidue {
        &self.residue
    }

    /// The pid KATA read off the spawned child, never one the provider reported.
    #[must_use]
    pub const fn provider_pid(&self) -> Option<u32> {
        self.provider_pid
    }
}

#[cfg(test)]
impl ProviderCrashReport {
    /// A fabricated report for the CONSUMERS' tests — a refusal's provenance
    /// mapping, a retained root's marker text — so they assert against the
    /// verdict vocabulary itself rather than against a spawned provider.
    /// `ContainedResidue`'s fields are public for exactly this construction.
    pub(crate) fn fabricated(precondition: CrashPrecondition, teardown: TeardownOutcome) -> Self {
        Self {
            provider: "fabricated-provider".to_owned(),
            provider_pid: None,
            precondition,
            loss: "a fabricated loss".to_owned(),
            residue: ContainedResidue {
                reaped: "a fabricated reap".to_owned(),
                swept: Ok(0),
                teardown,
                outer_cgroup: None,
            },
        }
    }
}

impl std::fmt::Display for ProviderCrashReport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let took_work = match &self.precondition {
            CrashPrecondition::AcceptedAndFramed {
                assignment_id,
                frames_read,
            } => format!(
                "It had ACCEPTED assignment `{assignment_id}` and produced {frames_read} frame(s) \
                 before it died, so work was in flight and that stage did not complete"
            ),
            CrashPrecondition::NeverAccepted { frames_read } => format!(
                "It had accepted NO assignment (kata decoded {frames_read} frame(s) from it), so \
                 nothing was in flight and no stage was lost"
            ),
        };
        write!(
            f,
            "sandbox: the external provider `{provider}` (pid {pid}) stopped answering \
             [{label}]: {loss} {took_work}. {residue} To stop routing this node to an external \
             provider, unset `{env}`; the provider's own stderr is inherited by this process and \
             is the only place its side of the story is written.",
            provider = self.provider,
            pid = self
                .provider_pid
                .map_or_else(|| "unknown".to_owned(), |p| p.to_string()),
            label = self.label(),
            loss = self.loss,
            residue = self.residue.operator_line(),
            env = EXTERNAL_PROVIDER_ENV,
        )
    }
}

/// What ONE assignment says beside its [`OciBundlePlan`].
///
/// Borrowed rather than owned: every caller already holds these, and the
/// [`AssignStage`] frame they become is built inside
/// [`ProviderSupervisor::assign_stage`], which takes the plan by value.
#[derive(Clone, Copy, Debug)]
pub struct StageAssignment<'a> {
    /// Kata's id for this stage, echoed by the provider on every answer.
    pub assignment_id: &'a str,
    /// Where the stage's captured output is spooled, and the COMBINED bound over
    /// it — [`CaptureSpec`]'s contract verbatim: the supervisor creates the
    /// directory empty (below), the provider writes `<dir>/stdout` and
    /// `<dir>/stderr`, and a stage whose two files sum past `limit_bytes` is
    /// KILLED by the provider and reported `capture_exceeded`.
    pub capture: &'a CaptureSpec,
}

/// One assignment's answer, with the ACCEPTANCE that preceded it.
///
/// The `accepted` frame is carried rather than checked-and-dropped because a
/// crash arm may only kill a provider that has been OBSERVED to accept an
/// assignment and produce at least one frame, else *"the provider died and kata
/// coped"* is satisfiable by a provider that never started. This type makes the
/// fact the arm needs available and observed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StageOutcome {
    /// The provider's acceptance frame.
    pub accepted: AssignmentAccepted,
    /// The provider's terminal frame.
    pub completed: StageCompleted,
}

/// Kata's side of one live provider process.
///
/// Holds the child, the two pipe ends, and the two facts that matter about the
/// launch: what the provider CLAIMED (its admitted certificate) and what kata
/// MEASURED (how many bytes of floor the prefix really carried). The
/// claimed/measured distinction is kept by keeping them in separate fields with separate
/// accessors, never folded into one "provider status".
pub struct ProviderSupervisor {
    child: Child,
    stdin: Option<ChildStdin>,
    stdout: BufReader<ChildStdout>,
    admitted: AdmittedProvider,
    provider_name: String,
    provider_pid: Option<u32>,
    floor_bytes: usize,
    outer_cgroup: Option<PathBuf>,
    stage_timeout: Duration,
    teardown_grace: Duration,
    /// The ONE deadline of the assignment in flight: [`Self::assign_stage`]'s start plus
    /// `stage_timeout`, taken before the `Assign` frame is written. The write, the
    /// acceptance and the terminal frame are all bounded by it — never a fresh budget per
    /// read, which let an assignment run to twice its budget.
    assignment_deadline: Option<tokio::time::Instant>,
    /// How many frames kata has DECODED from this provider, hello included.
    ///
    /// The crash proof's precondition is *the provider produced at least one
    /// frame*, and this is the counter that makes it an observation. It is
    /// incremented where a frame is decoded, so a provider that wrote nothing
    /// cannot reach a non-zero value by any path.
    frames_read: u32,
    /// The acceptance frame of the assignment currently in flight.
    ///
    /// Carried on the supervisor rather than returned-and-forgotten so a crash
    /// arm cannot be handed an acceptance the rig constructed: the only writer is
    /// [`Self::assign_stage`], and it writes what it decoded off the wire.
    accepted_in_flight: Option<AssignmentAccepted>,
    /// The `refused` FRAME this provider answered the last assignment with, when
    /// it answered with one. See [`Self::stage_refusal`] for why the frame is
    /// kept as a value.
    stage_refusal: Option<AssignmentRefused>,
    /// Set by the two terminal paths once `contain` has run, so [`Drop`] knows the
    /// subtree was already accounted for.
    contained: bool,
}

impl Drop for ProviderSupervisor {
    /// **The synchronous last resort: one write of `1` to the outer cgroup's
    /// `cgroup.kill`.**
    ///
    /// # The leak this closes
    ///
    /// `shutdown` and `kill_and_contain` are async and consume `self`, and nothing
    /// forces either to run: a stage task that PANICS, or a future that is
    /// dropped mid-`run_stage`, drops the supervisor with a container running.
    /// Tokio's `kill_on_drop` alone would `SIGKILL` the provider — the ONE process that
    /// tears the container down — and leave `youki run` reparented to init with the
    /// container alive beneath it, in a `kata.provider.youki.<pid>` subtree whose
    /// pid names a LIVE worker, so the boot sweep (which only adopts dead owners'
    /// subtrees) skips it. In production that is a running stage nothing will ever
    /// reap.
    ///
    /// # Why one write is correct here and a teardown is not
    ///
    /// A `Drop` cannot await `contain`, and blocking on a runtime from inside a
    /// drop that runs on a runtime thread panics. But the kill that matters is not
    /// async: `cgroup.kill` is the kernel killing every member of the subtree —
    /// provider, runtime client, container init and anything it forked, including a
    /// descendant that called `setsid` — in one synchronous write, the same write
    /// `contain` makes first. What a `Drop` cannot do is OBSERVE the subtree empty
    /// and remove its directories. The Drop releases the root from this process's
    /// registry, so the NEXT launch on this worker reclaims it
    /// ([`reclaim_orphaned_sweep_roots`]) — the boot sweep never would, because this
    /// worker's pid is live.
    ///
    /// With no delegated outer cgroup there is no subtree to kill and nothing more a
    /// synchronous drop can reach than `kill_on_drop` already does; that is said
    /// loudly rather than passed off as a teardown.
    fn drop(&mut self) {
        // Whatever happened below, no live supervisor owns this root any more: a
        // directory left behind is the next launch's to reclaim.
        if let Some(cgroup) = &self.outer_cgroup {
            release_sweep_root(cgroup);
        }
        if self.contained {
            return;
        }
        if let Some(cgroup) = &self.outer_cgroup {
            let written = std::fs::write(cgroup.join("cgroup.kill"), "1");
            tracing::error!(
                provider = %self.provider_name,
                provider_pid = ?self.provider_pid,
                outer_cgroup = %cgroup.display(),
                cgroup_kill = ?written,
                "provider supervisor DROPPED without `shutdown`/`kill_and_contain` (a \
                 panicking or cancelled stage task): wrote `1` to the outer cgroup's \
                 `cgroup.kill`, killing the provider, its runtime client and any container \
                 beneath it. The subtree's emptiness is NOT confirmed here; its \
                 directories are reclaimed by this worker's next provider launch."
            );
        } else {
            tracing::error!(
                provider = %self.provider_name,
                provider_pid = ?self.provider_pid,
                "provider supervisor DROPPED without `shutdown`/`kill_and_contain` and this host \
                 delegates no outer cgroup: only the provider itself is killed (`kill_on_drop`); \
                 anything it forked, a container included, is unaccounted for."
            );
        }
    }
}

/// Every `(provider_name, stage_timeout)` [`ProviderSupervisor::launch`] was handed in
/// this process, in order — recorded at the top of the launch, before anything can refuse.
#[cfg(any(test, feature = "test-support"))]
static LAUNCHED_FRAME_BUDGETS: std::sync::Mutex<Vec<(String, Duration)>> =
    std::sync::Mutex::new(Vec::new());

/// The frame budget of every provider launch this process attempted: a rig's view of the
/// spec a production path actually LAUNCHED with, rather than of a spec it rebuilt.
///
/// The budget bounds a LIVE provider, and nothing a host-free rig can start answers an
/// assignment — so without this, a path that launched with an hour where the stage agreed
/// to five seconds is indistinguishable from a correct one until a wedged provider
/// outlives its stage.
#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
#[must_use]
pub fn launched_frame_budgets_for_test() -> Vec<(String, Duration)> {
    LAUNCHED_FRAME_BUDGETS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone()
}

impl ProviderSupervisor {
    /// Spawn a provider, install the floor, and admit or refuse its handshake.
    ///
    /// The spawn goes through `crate::process::command_with_prefix` —
    /// the ONE production function that turns a `CommandPrefix` into a child —
    /// because a supervisor that built its own `Command` would be installing a
    /// COPY of the floor hook rather than the hook, and the copy is what would
    /// silently stop matching.
    ///
    /// # Errors
    /// * [`KataError::Io`] if the spawn itself fails — which, for a `Some(_)`
    ///   floor, INCLUDES the kernel refusing the filter, because
    ///   `attach_kata_floor` fails that spawn closed rather than execing the
    ///   provider unfloored.
    /// * [`KataError::Protocol`] for a handshake that timed out, arrived
    ///   malformed, arrived out of order, or was REFUSED by
    ///   [`kata_provider_protocol::admit`] — the message quotes the refusal and
    ///   its stable label.
    pub async fn launch(spec: &ProviderLaunchSpec) -> KataResult<Self> {
        #[cfg(any(test, feature = "test-support"))]
        LAUNCHED_FRAME_BUDGETS
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push((spec.provider_name.clone(), spec.stage_timeout));
        // ONE read of the measured delegation, passed to both producers. Two reads
        // of an `OnceLock` cannot disagree today, and a function that reaches for a
        // global rather than taking what its caller already holds is how a test ends
        // up unable to drive it.
        let delegation = crate::sandbox_bounds::cgroup_delegation();
        // RECLAIM before establishing: a root an earlier stage in this worker abandoned
        // (a dropped supervisor, an unconfirmed teardown) is killed, observed empty and
        // removed here, so one cancelled stage costs one directory until the next launch
        // and never wedges the worker.
        if let Some(parent) = delegation.usable_parent.clone() {
            let budget = crate::process::teardown_confirm_budget();
            let (reclaimed, left) =
                tokio::task::spawn_blocking(move || reclaim_orphaned_sweep_roots(&parent, budget))
                    .await
                    .unwrap_or_default();
            if !reclaimed.is_empty() || !left.is_empty() {
                tracing::warn!(
                    reclaimed = ?reclaimed,
                    left = ?left,
                    "provider launch reclaimed sweep roots an earlier stage in this worker \
                     abandoned; any that would not empty are left for the next launch"
                );
            }
        }
        let bounds =
            outer_cgroup_bounds(delegation, &spec.provider_name, next_sweep_root_sequence());
        // The SWEEP ROOT, created before the provider exists — see
        // `SweepRoot::establish`. It is `CgroupPlan::parent` and not
        // `CgroupPlan::path`: the provider goes in a leaf beneath it so the root
        // itself stays process-free and can hold the per-container parents the
        // rootless-OCI route needs.
        let sweep = SweepRoot::establish(&bounds, delegation).map_err(|e| {
            KataError::Io(std::io::Error::other(format!(
                "sandbox: the provider's outer cgroup could not be created ({e}), \
                 so nothing would account for what the external provider `{name}` spawns and no \
                 teardown of it could be observed. Refusing to launch rather than running a peer \
                 kata cannot sweep.",
                name = spec.provider_name,
            )))
        })?;
        let prefix = provider_command_prefix(spec, bounds);
        // Read the floor length off the PREFIX, not off the spec. A spawn path
        // that grew an environment read and nulled the field would still have been
        // HANDED the shipped floor, so a count taken from the argument would
        // report 184 while the provider ran unfloored.
        let floor_bytes = prefix.kata_floor_bpf.as_ref().map_or(0, Vec::len);

        let mut command = crate::process::command_with_prefix(&prefix);
        command
            // An EMPTY environment: the provider reads none (its basis rides argv, its
            // work arrives as frames), and the worker's holds what must stay in the
            // worker — an `env:` credential above all.
            .env_clear()
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            // The provider's stderr is DIAGNOSTIC and is deliberately inherited
            // rather than piped: a piped stream nobody drains is a provider that
            // blocks on a full pipe, which would look exactly like a hang.
            .stderr(std::process::Stdio::inherit())
            .kill_on_drop(true);

        let mut child = command.spawn().map_err(|e| {
            KataError::Io(std::io::Error::new(
                e.kind(),
                format!(
                    "sandbox: could not spawn the external provider `{name}` at {binary} with the \
                     kata seccomp floor {floor}: {e}",
                    name = spec.provider_name,
                    binary = spec.binary.display(),
                    floor = spec.floor.label(),
                ),
            ))
        })?;
        let provider_pid = child.id();
        let stdin = child.stdin.take().ok_or_else(|| {
            KataError::Protocol("sandbox: the provider child has no stdin pipe".to_owned())
        })?;
        let stdout = child.stdout.take().ok_or_else(|| {
            KataError::Protocol("sandbox: the provider child has no stdout pipe".to_owned())
        })?;
        let mut stdout = BufReader::new(stdout);

        // A refused or unreadable handshake is a provider that must GO, and
        // "go" means the same thing here as it does after a crash: the process
        // and everything under it. `start_kill` alone would leave a peer that had
        // already forked something running unwatched, and the outer cgroup
        // directory behind — the residue nobody looked at. Every early return
        // below therefore routes through `contain`, and says what it found.
        let contain_budget = crate::process::teardown_confirm_budget();
        let handshake_deadline = tokio::time::Instant::now() + spec.handshake_timeout;
        // The OPENING frame is decoded numbers-first (`decode_opening_frame`): a
        // provider speaking another certificate vocabulary is a body this build's
        // types cannot decode, and it is refused by name rather than as garbled.
        let opening = read_frame_with(
            &mut stdout,
            handshake_deadline,
            spec.handshake_timeout,
            |body| Ok(decode_opening_frame(body)),
        )
        .await;
        let hello = match opening {
            Ok(Ok(ProviderFrame::Hello(hello))) => hello,
            Ok(Err(OpeningFrameError::Refused(refusal))) => {
                let residue = contain(&mut child, sweep.established(), contain_budget).await;
                return Err(refused_at_handshake(
                    &spec.provider_name,
                    &refusal,
                    &residue.operator_line(),
                ));
            }
            Ok(Err(OpeningFrameError::Malformed(e))) => {
                let residue = contain(&mut child, sweep.established(), contain_budget).await;
                return Err(malformed_opening_fault(&e, &residue.operator_line()));
            }
            Ok(Ok(other)) => {
                let residue = contain(&mut child, sweep.established(), contain_budget).await;
                return Err(KataError::Protocol(format!(
                    "sandbox: the external provider `{name}` opened with `{got}` instead of its \
                     hello frame. A provider announces its protocol and certificate BEFORE it is \
                     handed work, so a supervisor never assigns to a peer it has not read. \
                     {residue}",
                    name = spec.provider_name,
                    got = frame_kind(&other),
                    residue = residue.operator_line(),
                )));
            }
            Err(e) => {
                let residue = contain(&mut child, sweep.established(), contain_budget).await;
                return Err(KataError::Protocol(format!(
                    "{e} {}",
                    residue.operator_line()
                )));
            }
        };

        let admitted = match admit(&hello, &spec.provider_name, spec.measured_basis.as_ref()) {
            Ok(admitted) => admitted,
            Err(refusal) => {
                let residue = contain(&mut child, sweep.established(), contain_budget).await;
                return Err(refused_at_handshake(
                    &spec.provider_name,
                    &refusal,
                    &residue.operator_line(),
                ));
            }
        };

        Ok(Self {
            child,
            stdin: Some(stdin),
            stdout,
            admitted,
            provider_name: spec.provider_name.clone(),
            provider_pid,
            floor_bytes,
            outer_cgroup: sweep.into_established(),
            stage_timeout: spec.stage_timeout,
            teardown_grace: spec.teardown_grace,
            assignment_deadline: None,
            // The hello frame. Read, decoded and admitted — so a peer that wrote
            // nothing can never present as having produced one.
            frames_read: 1,
            accepted_in_flight: None,
            stage_refusal: None,
            contained: false,
        })
    }

    /// The provider process's pid, as KATA observed it — never as the provider
    /// reported it.
    ///
    /// The claimed/measured distinction is load-bearing for the floor proof:
    /// the proof asserts that the STAGE's `PPid` is this number, which
    /// establishes that the stage really is the provider's child. A pid the
    /// provider told kata about would let a provider that ran the stage itself
    /// satisfy the same assertion.
    #[must_use]
    pub const fn provider_pid(&self) -> Option<u32> {
        self.provider_pid
    }

    /// How many bytes of kata seccomp floor the spawned prefix REALLY carried.
    #[must_use]
    pub const fn floor_bytes(&self) -> usize {
        self.floor_bytes
    }

    /// The certificate this provider was admitted on. A CLAIM, never a
    /// measurement.
    #[must_use]
    pub const fn admitted(&self) -> &AdmittedProvider {
        &self.admitted
    }

    /// The outer cgroup this provider was placed in, when this host delegates
    /// one. `None` means the host does not, which is a MEASURED fact from
    /// `measure_cgroup_delegation` and not an unattempted one.
    #[must_use]
    pub fn outer_cgroup(&self) -> Option<&Path> {
        self.outer_cgroup.as_deref()
    }

    /// The `refused` FRAME the provider answered the LAST assignment with —
    /// `None` when it answered with anything else, including when it never
    /// reached an assignment at all.
    ///
    /// # Why a decoded frame is kept as a VALUE and not only as a message
    ///
    /// A refusal is the one answer a provider gives that is neither a success
    /// nor a fault: *"I was asked, I understood, and I will not"*. Both paths
    /// that can receive one — [`Self::assign_stage`], for a provider that
    /// refuses before accepting (the shipped third-party candidate fixture
    /// does), and [`Self::await_stage_completion`], for one that accepts first
    /// — fold it into
    /// a [`KataError::Protocol`] message, which is right for an operator and
    /// leaves a PROGRAM with nothing but substring matching.
    ///
    /// Substring matching is forgeable: a check scored with
    /// `err.contains("refused")` is greened by a candidate whose FIRST frame
    /// was a `refused` — one that never sent a hello, was never admitted, and
    /// was therefore never assigned anything — because kata's own honest report
    /// of that fault contains the word. The frame cannot be forged the same
    /// way: it is recorded only where a
    /// `ProviderFrame::Refused` was decoded as the answer to an assignment kata
    /// had already written, and [`AssignmentRefused::assignment_id`] says which
    /// one, so a caller can require the refusal to be about the work it sent.
    ///
    /// Reset at the top of every [`Self::assign_stage`], so this is the current
    /// assignment's answer and never a previous one's.
    #[must_use]
    pub const fn stage_refusal(&self) -> Option<&AssignmentRefused> {
        self.stage_refusal.as_ref()
    }

    /// Assign one stage and read the provider's answer.
    ///
    /// # `plan` is a plan the provider must APPLY or REFUSE
    ///
    /// [`OciBundlePlan`] hands the provider a rootless container kata
    /// described in full. A provider that cannot honour the plan
    /// answers `Refused` and this call returns an error — the plan is never
    /// degraded to a weaker one, because a stage that ran with less containment
    /// than kata planned while kata reported success is the whole failure class
    /// external providers must not open.
    ///
    /// # Errors
    /// [`KataError::Protocol`] for a budget overrun, a malformed or out-of-order
    /// frame, an answer about a different assignment, or the provider's own
    /// `Refused`. A dead provider surfaces here as an explicit protocol error
    /// rather than as a hang — which is the containment half the crash proof
    /// builds its crash arm on.
    pub async fn run_stage(
        &mut self,
        stage: StageAssignment<'_>,
        plan: OciBundlePlan,
    ) -> KataResult<StageOutcome> {
        let accepted = self.assign_stage(stage, plan).await?;
        let completed = self.await_stage_completion(stage.assignment_id).await?;
        Ok(StageOutcome {
            accepted,
            completed,
        })
    }

    /// Assign one stage and read the provider's ACCEPTANCE, without waiting for
    /// the stage to finish.
    ///
    /// # Why this is a separate call and not an implementation detail of
    /// [`Self::run_stage`]
    ///
    /// The crash proof's crash arm may only kill a provider that has
    /// been OBSERVED to accept an assignment and produce at least one frame. A
    /// rig built on `run_stage` alone cannot reach that moment: `run_stage`
    /// returns only after the terminal frame, so by the time the caller holds an
    /// acceptance the stage is already over and there is nothing left to crash
    /// mid-flight. Splitting the two is what makes the proof's precondition an
    /// observable state rather than a sentence in a comment.
    ///
    /// # Errors
    /// [`KataError::Protocol`] for a budget overrun, a malformed or out-of-order
    /// frame, or an acceptance naming a different assignment.
    pub async fn assign_stage(
        &mut self,
        stage: StageAssignment<'_>,
        plan: OciBundlePlan,
    ) -> KataResult<AssignmentAccepted> {
        let StageAssignment {
            assignment_id,
            capture,
        } = stage;
        // A previous assignment's refusal is not this one's answer. Cleared
        // BEFORE the frame goes out, so [`Self::stage_refusal`] is `None` for
        // every window in which no answer has been read.
        self.stage_refusal = None;
        // THE ASSIGNMENT'S ONE DEADLINE, taken before a byte of it is written. Everything
        // from here to the terminal frame — the write, the acceptance, the completion — is
        // bounded by this instant, so the provider's kill fires at the latest
        // `stage_timeout` after this line (plus the kill itself), however the time is split.
        let deadline = tokio::time::Instant::now() + self.stage_timeout;
        self.assignment_deadline = Some(deadline);
        // THE SPOOL DIRECTORY is the supervisor's to create — the spec's words are
        // "created empty by the supervisor", and a provider that could create it
        // would be choosing where a stage's bytes land. `create_dir`, deliberately
        // strict: a directory that already exists is reused state at a name this
        // caller computed fresh, which is what the refusal below is for.
        std::fs::create_dir(&capture.spool_dir).map_err(|e| {
            KataError::Storage(format!(
                "sandbox: the capture spool directory `{}` could not be created EMPTY ({e}); \
                 nothing is assigned.",
                capture.spool_dir
            ))
        })?;
        let assign = SupervisorFrame::Assign(AssignStage {
            protocol_version: PROTOCOL_VERSION,
            assignment_id: assignment_id.to_owned(),
            plan,
            capture: capture.clone(),
        });
        let bytes = encode_frame(&assign).map_err(|e| frame_fault(&e))?;
        let stdin = self.stdin.as_mut().ok_or_else(|| {
            KataError::Protocol(
                "sandbox: this provider's stdin is already closed; it cannot be assigned more work"
                    .to_owned(),
            )
        })?;
        // BOUNDED: a provider that stops reading its stdin would otherwise hold this write
        // forever once the pipe fills.
        let budget = self.stage_timeout;
        let written = tokio::time::timeout_at(deadline, async {
            stdin.write_all(&bytes).await?;
            stdin.flush().await
        })
        .await
        .map_err(|_| {
            KataError::Protocol(format!(
                "sandbox: the external provider did not read its assignment within the \
                 assignment's {budget:?} budget."
            ))
        })?;
        written?;

        let accepted = match self.read_frame(deadline).await? {
            ProviderFrame::Accepted(accepted) => accepted,
            other => {
                // A REFUSAL is kept as a frame before it becomes a message. A
                // provider is permitted to decline without accepting first —
                // a `refused` frame means *"the provider declined; nothing
                // ran"*, with no acceptance in the ordering — and this is the
                // arm such a provider arrives on. See [`Self::stage_refusal`].
                if let ProviderFrame::Refused(refused) = &other {
                    self.stage_refusal = Some(refused.clone());
                }
                return Err(KataError::Protocol(format!(
                    "sandbox: the external provider answered an assignment with `{got}` before \
                     accepting it. Acceptance is a frame in its own right because a crash \
                     proof needs *the provider accepted work* to be an OBSERVATION.",
                    got = frame_kind(&other),
                )));
            }
        };
        // EXHAUSTIVE DESTRUCTURE.
        let AssignmentAccepted {
            assignment_id: accepted_id,
        } = &accepted;
        if accepted_id != assignment_id {
            return Err(KataError::Protocol(format!(
                "sandbox: the external provider accepted assignment `{accepted_id}` and was given \
                 `{assignment_id}`. An answer about a different assignment is refused rather than \
                 attributed to this one."
            )));
        }
        self.accepted_in_flight = Some(accepted.clone());
        Ok(accepted)
    }

    /// Read the terminal frame of an assignment already accepted — by the SAME deadline
    /// [`Self::assign_stage`] took, not a fresh budget: the time the provider spent before
    /// accepting is spent from the one budget the assignment has.
    ///
    /// # Errors
    /// [`KataError::Protocol`] for a budget overrun, the provider's own
    /// `Refused`, a terminal frame about a different assignment, the stream
    /// ending — which is a CRASH and is reported as one — or no assignment in flight.
    pub async fn await_stage_completion(
        &mut self,
        assignment_id: &str,
    ) -> KataResult<StageCompleted> {
        let deadline = self.assignment_deadline.ok_or_else(|| {
            KataError::Protocol(
                "sandbox: no assignment is in flight on this provider, so there is no terminal \
                 frame to wait for"
                    .to_owned(),
            )
        })?;
        match self.read_frame(deadline).await? {
            ProviderFrame::Completed(completed) => {
                if completed.assignment_id != assignment_id {
                    return Err(KataError::Protocol(format!(
                        "sandbox: the external provider completed assignment `{got}` and was given \
                         `{assignment_id}`.",
                        got = completed.assignment_id,
                    )));
                }
                self.accepted_in_flight = None;
                self.assignment_deadline = None;
                Ok(completed)
            }
            ProviderFrame::Refused(refused) => {
                // Kept as a frame before it becomes a message — see
                // [`Self::stage_refusal`].
                self.stage_refusal = Some(refused.clone());
                Err(KataError::Protocol(format!(
                    "sandbox: the external provider REFUSED assignment `{id}` and nothing ran: \
                     {reason}",
                    id = refused.assignment_id,
                    reason = refused.reason,
                )))
            }
            other => Err(KataError::Protocol(format!(
                "sandbox: the external provider followed its acceptance with `{got}` rather than a \
                 terminal frame.",
                got = frame_kind(&other),
            ))),
        }
    }

    /// Read one frame and COUNT it.
    ///
    /// The counter is incremented here and nowhere else, so *the provider
    /// produced at least one frame* — the crash proof's second precondition — is
    /// a fact about bytes this build decoded rather than about what a caller
    /// arranged.
    async fn read_frame(&mut self, deadline: tokio::time::Instant) -> KataResult<ProviderFrame> {
        let frame = read_frame_async(&mut self.stdout, deadline, self.stage_timeout).await?;
        self.frames_read = self.frames_read.saturating_add(1);
        Ok(frame)
    }

    /// Tear the provider down and say what was OBSERVED — never a clean `Ok(())`.
    ///
    /// The ladder is stdin-EOF, then grace, then [`Self::kill_and_contain`].
    /// `SIGTERM`-then-grace is deliberately absent: an orderly signal here would
    /// give a provider a chance to tidy up before being "killed" and make the
    /// crash arm vacuous.
    ///
    /// # Scored from `TeardownProbe::CgroupPopulation` alone
    ///
    /// Where this host delegates a cgroup the
    /// outcome is [`TeardownOutcome::Confirmed`] with that probe, read from the
    /// outer cgroup's own membership after the subtree is swept. Where it does
    /// not, the outcome is [`TeardownOutcome::Ambiguous`] — an unobservable
    /// teardown is `AmbiguousTeardown`, never a clean
    /// success, because reaping the direct child says the direct child is gone
    /// and says NOTHING about a descendant the provider forked.
    pub async fn shutdown(mut self) -> TeardownOutcome {
        // Closing stdin is the provider's EOF, which is its orderly exit signal.
        drop(self.stdin.take());
        let orderly = tokio::time::timeout(self.teardown_grace, self.child.wait()).await;
        let grace = self.teardown_grace;
        let exited_within_grace = match orderly {
            Ok(Ok(status)) => Some(format!(
                "the provider exited {status} within its {grace:?} grace window"
            )),
            Ok(Err(e)) => Some(format!("waiting on the provider failed: {e}")),
            Err(_) => None,
        };

        let budget = crate::process::teardown_confirm_budget();
        let mut residue = contain(&mut self.child, self.outer_cgroup.as_deref(), budget).await;
        self.contained = true;
        if let Some(orderly) = exited_within_grace {
            // The process was already gone before `contain` signalled it; say so
            // rather than reporting a SIGKILL that landed on nothing. The SUBTREE
            // half of `contain` is still what produced the verdict, which is the
            // whole point of the cgroup probe: an orderly provider exit is not evidence
            // about what it left behind.
            residue.reaped = orderly;
        }
        residue.teardown
    }

    /// **SIGKILL the provider and CONTAIN its subtree — the crash proof's crash
    /// arm.**
    ///
    /// # It DOES reach a rootless OCI container the provider was holding
    ///
    /// The subtree
    /// this sweeps is the provider's sweep root, and `oci_bundle::spec_for` sets
    /// `linux.cgroupsPath` to a leaf beneath the per-container parent kata created
    /// inside that same root ([`crate::oci_cgroup`]), so the container's init is a
    /// member of this subtree. `kill_cgroup_subtree` writes `cgroup.kill`, which the
    /// kernel applies recursively, and `live_cgroup_members` recurses — so the
    /// PLACEMENT is what makes the sweep and the probe reach the container.
    ///
    /// **MEASURED on the reference host, both halves:** a `SIGKILL` on the
    /// runtime client alone leaves the container's init alive and `youki list`
    /// reporting `Running`, and one write of `1` to the sweep root's `cgroup.kill`
    /// then leaves the whole subtree empty.
    /// `crates/worker/tests/oci_provider_live.rs`'s
    /// `the_supervisors_abrupt_teardown_reaps_the_container_live` is that proof from
    /// the host, watched red first with the placement removed.
    ///
    /// With `linux.cgroupsPath` unset youki puts the init in its own transient
    /// `youki-<id>.scope`, outside this subtree, and
    /// [`TeardownProbe::CgroupPopulation`] would answer about a subtree the stage was
    /// never in — `Confirmed` over a running container. A plan with no
    /// `cgroup_parent` is refused by the provider, so that shape cannot be
    /// assigned.
    ///
    /// No stdin EOF and no grace window: this is the abrupt path, and giving a
    /// provider either would be an orderly shutdown wearing a crash's name.
    /// Callers use it to tear down a provider that has already died on its own,
    /// too — `start_kill` on a dead child is harmless, and the work that matters
    /// happens afterwards, in the outer cgroup.
    ///
    /// The `loss` string is what kata OBSERVED about the provider going away, in
    /// the words of whatever noticed (a protocol error, a budget expiring). It is
    /// carried rather than re-derived so the operator-facing line names the real
    /// symptom instead of a category.
    pub async fn kill_and_contain(mut self, loss: impl Into<String>) -> ProviderCrashReport {
        let budget = crate::process::teardown_confirm_budget();
        let residue = contain(&mut self.child, self.outer_cgroup.as_deref(), budget).await;
        self.contained = true;
        let precondition = match self.accepted_in_flight.take() {
            Some(AssignmentAccepted { assignment_id }) => CrashPrecondition::AcceptedAndFramed {
                assignment_id,
                frames_read: self.frames_read,
            },
            None => CrashPrecondition::NeverAccepted {
                frames_read: self.frames_read,
            },
        };
        ProviderCrashReport {
            provider: self.provider_name.clone(),
            provider_pid: self.provider_pid,
            precondition,
            loss: loss.into(),
            residue,
        }
    }
}

/// The stable token for a frame, for a message that has to name what arrived.
fn frame_kind(frame: &ProviderFrame) -> &'static str {
    match frame {
        ProviderFrame::Hello(_) => "hello",
        ProviderFrame::Accepted(_) => "accepted",
        ProviderFrame::Completed(_) => "completed",
        ProviderFrame::Refused(_) => "refused",
    }
}

/// The supervisor's words for a frame the codec refused. `FrameError`'s
/// `Display` already opens with `provider protocol:`, so the protocol is named
/// there and only the `sandbox:` scope is added here — composed once, for every
/// call site: the header's length ([`read_frame_with`]), the body's decode
/// ([`read_frame_async`]), the opening frame ([`malformed_opening_fault`]) and
/// the `Assign` frame's encode ([`ProviderSupervisor::assign_stage`]).
fn frame_fault_text(e: &kata_provider_protocol::FrameError) -> String {
    format!("sandbox: {e}")
}

fn frame_fault(e: &kata_provider_protocol::FrameError) -> KataError {
    KataError::Protocol(frame_fault_text(e))
}

/// An opening frame the codec could not read at all, after the provider was
/// contained: the codec's words, then what containing it found.
fn malformed_opening_fault(e: &kata_provider_protocol::FrameError, residue: &str) -> KataError {
    KataError::Protocol(format!("{} {residue}", frame_fault_text(e)))
}

/// Read one provider frame by `deadline` — the end of a `budget` the caller started
/// earlier, which is named in the refusal.
///
/// The two BOUNDS live in `kata_provider_protocol::body_len`, shared with the
/// blocking reader the provider uses, so the ceiling cannot be one number here
/// and another there.
async fn read_frame_async(
    stdout: &mut BufReader<ChildStdout>,
    deadline: tokio::time::Instant,
    budget: Duration,
) -> KataResult<ProviderFrame> {
    read_frame_with(stdout, deadline, budget, |body| {
        decode_frame::<ProviderFrame>(body).map_err(|e| frame_fault(&e))
    })
    .await
}

/// A handshake refusal, worded once for both doors that reach one: the opening
/// frame's numbers ([`decode_opening_frame`]) and the full [`admit`].
fn refused_at_handshake(name: &str, refusal: &ProviderRefusal, residue: &str) -> KataError {
    KataError::Protocol(format!(
        "sandbox: the external provider `{name}` was REFUSED at the handshake [{label}]: \
         {refusal} Nothing was assigned to it. {residue}",
        label = refusal.label(),
    ))
}

/// [`read_frame_async`] with the body's decode supplied, so the opening frame
/// can be judged by [`decode_opening_frame`] under the same bounds and budget.
async fn read_frame_with<T>(
    stdout: &mut BufReader<ChildStdout>,
    deadline: tokio::time::Instant,
    budget: Duration,
    decode: impl FnOnce(&[u8]) -> KataResult<T>,
) -> KataResult<T> {
    let read = async {
        let mut header = [0u8; FRAME_HEADER_BYTES];
        stdout.read_exact(&mut header).await.map_err(|e| {
            if e.kind() == std::io::ErrorKind::UnexpectedEof {
                KataError::Protocol(
                    "sandbox: the external provider closed its stream where a frame was expected. \
                     A provider that exits instead of answering is a CRASH, and it is reported as \
                     one rather than as an empty answer."
                        .to_owned(),
                )
            } else {
                KataError::Protocol(format!(
                    "sandbox: reading the external provider's frame header failed: {e}"
                ))
            }
        })?;
        let len = body_len(header).map_err(|e| frame_fault(&e))?;
        let mut body = vec![0u8; len];
        stdout.read_exact(&mut body).await.map_err(|e| {
            KataError::Protocol(format!(
                "sandbox: the external provider declared a {len}-byte frame and did not deliver \
                 one: {e}"
            ))
        })?;
        decode(&body)
    };

    match tokio::time::timeout_at(deadline, read).await {
        Ok(result) => result,
        Err(_) => Err(KataError::Protocol(format!(
            "sandbox: the external provider produced no frame before its {budget:?} budget ran \
             out. A supervisor holds a budget rather than blocking forever on a peer kata does \
             not link."
        ))),
    }
}

#[cfg(test)]
mod sweep_root_name_tests {
    use super::sweep_root_owner;

    /// The owner pid is the second-to-last field of the per-launch name, a provider
    /// name may carry dots, and the pre-sequence shape is not a sweep root at all.
    #[test]
    fn the_owner_pid_is_read_off_the_per_launch_name() {
        assert_eq!(sweep_root_owner("kata.provider.youki.4242.0"), Some(4242));
        assert_eq!(sweep_root_owner("kata.provider.a.b.4242.17"), Some(4242));
        assert_eq!(sweep_root_owner("kata.provider.youki.4242"), None);
        assert_eq!(sweep_root_owner("kata.provider..4242.1"), None);
        assert_eq!(sweep_root_owner("kata.oci.kata-x.4242.1"), None);
    }
}

#[cfg(test)]
mod frame_fault_tests {
    use std::process::Stdio;
    use std::time::Duration;

    use tokio::io::BufReader;

    use kata_provider_protocol::{OpeningFrameError, decode_opening_frame};

    use super::{malformed_opening_fault, read_frame_async};

    /// The refusal `read_frame_async` gives for what a real child process writes
    /// to its stdout — `printf` escapes, so the bytes are the shell's, not a codec's.
    async fn refusal_for(printf: &str) -> String {
        let mut child = tokio::process::Command::new("sh")
            .args(["-c", &format!("printf '{printf}'")])
            .stdout(Stdio::piped())
            .spawn()
            .expect("spawn sh");
        let mut stdout = BufReader::new(child.stdout.take().expect("piped stdout"));
        let budget = Duration::from_secs(10);
        let refusal = read_frame_async(&mut stdout, tokio::time::Instant::now() + budget, budget)
            .await
            .expect_err("the frame is refused")
            .to_string();
        let _ = child.wait().await;
        refusal
    }

    fn names_the_protocol_once(site: &str, refusal: &str, codec_words: &str) {
        assert!(
            refusal.contains(codec_words),
            "{site}: the refusal is the frame codec's: {refusal}"
        );
        assert_eq!(
            refusal.matches("provider protocol:").count(),
            1,
            "{site}: the protocol is named once: {refusal}"
        );
    }

    /// A frame the codec refuses is refused with the protocol's own words, once,
    /// at each of the three supervisor sites that word one: the header's length
    /// (an empty body), the body's decode (one byte that is not JSON), and the
    /// handshake's opening frame (the same byte, through `decode_opening_frame`
    /// and the words the `Malformed` arm returns). `FrameError`'s `Display`
    /// already opens with `provider protocol:`, so a site that prefixes it again
    /// doubles it.
    ///
    /// **Would red if:** any of the three sites composed `provider protocol:` in
    /// front of a `FrameError` again. The fourth site, the `Assign` frame's
    /// encode, needs a launched supervisor and is pinned by
    /// `an_unframeable_assignment_names_the_provider_protocol_once`.
    #[tokio::test]
    async fn a_malformed_frame_names_the_provider_protocol_once() {
        names_the_protocol_once(
            "header length",
            &refusal_for(r"\000\000\000\000").await,
            "ZERO-byte frame body",
        );
        names_the_protocol_once(
            "body decode",
            &refusal_for(r"\000\000\000\001x").await,
            "was not this protocol version's JSON",
        );
        let Err(OpeningFrameError::Malformed(e)) = decode_opening_frame(b"x") else {
            panic!("one byte that is not JSON is a malformed opening frame");
        };
        names_the_protocol_once(
            "opening frame",
            &malformed_opening_fault(&e, "residue: none").to_string(),
            "was not this protocol version's JSON",
        );
    }
}
