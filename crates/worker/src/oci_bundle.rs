//! The rootless OCI `config.json` kata PLANS for a
//! capsule, and the refusals that keep it from describing anything else.
//!
//! # What this module is, and what it deliberately is not
//!
//! [`spec_for`] takes a [`Capsule`], the [`NixEnvironmentManifest`] whose closure
//! that capsule binds, the host roots a stage's `/work` and `/out` were
//! materialized into, the argv, and the network posture — and produces the BYTES
//! of one OCI runtime spec, wrapped in the [`OciBundlePlan`] a provider needs to
//! start it. It executes nothing, creates no directory, and touches no cgroup.
//!
//! It is here because kata decides containment and a provider applies it. A provider that built a spec from a policy description
//! would be a second implementation of kata's containment, and any comparison
//! against it would then be measuring that implementation instead of the wire.
//!
//! # Why the OCI spec is built as a VALUE and not as JSON
//!
//! `oci_spec::runtime::Spec` is the typed form of `config.json`. Hand-assembling
//! the JSON — which the certification's throwaway `write_bundle_config` does, because
//! its whole subject is *"does youki start a container at all"* — makes every
//! field a string literal nobody type-checks, so an OCI field that was renamed or
//! retyped produces a container the runtime starts DIFFERENTLY rather than a
//! build failure. A containment mechanism whose description can drift silently is
//! the defect class this repository pays for most often.
//!
//! # The two guards the OCI spec cannot express
//!
//! Kata's classic-BPF fence carries an arch guard and an x32 range guard, and
//! neither has an OCI spelling. `kata_types::sandbox_seccomp::oci_seccomp_rules`
//! is where that difference is stated and bounded; this module renders what that
//! producer returns and adds nothing to it.
//!
//! # The six device nodes kata does not plan, cannot omit, and therefore states
//!
//! MEASURED on the reference host: a container started from a spec this module
//! produced reports six mount points in `/proc/self/mountinfo` that appear
//! NOWHERE in the plan — `/dev/null`, `/dev/zero`, `/dev/full`, `/dev/tty`,
//! `/dev/random` and `/dev/urandom`, each a bind of the host's `devtmpfs` node
//! carrying `nosuid`. They are the OCI runtime spec's DEFAULT DEVICES: a runtime
//! MUST make them available, and a rootless runtime cannot `mknod`, so it binds
//! the host's. `linux.devices` is left unset here because restating the six would
//! be a second copy of the runtime's list that could drift from it, and because
//! the alternative — a container with no `/dev/null` — is broken rather than
//! hermetic.
//!
//! The consequence is stated and not claimed away: this route's mount table is
//! *the plan plus the spec's default devices plus the runtime's renderings of
//! `maskedPaths`/`readonlyPaths`*, and `crates/worker/tests/oci_bundle_live.rs`
//! asserts exactly that union against the guest's own `mountinfo` — including
//! that the six ARE present, so a runtime that stopped providing them is a
//! failure too. `/dev/tty` is the one an operator should notice: it is the
//! calling process's controlling terminal, and it is in the set because the spec
//! puts it there.
//!
//! # Its input is its own
//!
//! [`BundleMounts`] is this module's OWN input struct. `crate::oci_driver`
//! adapts the materializer's `MaterializedRoots` into it, so this module
//! depends on no materializer type.

use std::path::{Path, PathBuf};

use crate::egress_proxy::EgressPlumbing;
use crate::oci_cgroup::AttemptContainment;
use kata_provider_protocol::{OciBundlePlan, PinnedRuntime};
use kata_types::{
    KataError, KataResult,
    execution_contract::{Capsule, CapsuleNetwork, GuestAccess, GuestMapping, GuestPath},
    nix_environment::NixEnvironmentManifest,
    sandbox::NetPolicy,
    sandbox_seccomp::{OciFlagsSetArg, OciSeccompAction, oci_seccomp_rules},
    youki_pin::YoukiPin,
};
use oci_spec::runtime::{
    Arch, Capabilities, Hook, HookBuilder, Hooks, HooksBuilder, LinuxBuilder,
    LinuxCapabilitiesBuilder, LinuxIdMappingBuilder, LinuxMemoryBuilder, LinuxNamespace,
    LinuxNamespaceBuilder, LinuxNamespaceType, LinuxPidsBuilder, LinuxResourcesBuilder,
    LinuxSeccompAction, LinuxSeccompArg, LinuxSeccompArgBuilder, LinuxSeccompBuilder,
    LinuxSeccompOperator, LinuxSyscallBuilder, Mount, MountBuilder, PosixRlimitBuilder,
    PosixRlimitType, ProcessBuilder, RootBuilder, Spec, SpecBuilder, UserBuilder, VERSION,
};

/// The `/work` mount point inside the guest.
const GUEST_WORK: &str = "/work";
/// The `/out` mount point inside the guest.
const GUEST_OUT: &str = "/out";
/// The `/tmp` mount point inside the guest.
const GUEST_TMP: &str = "/tmp";
/// The `/proc` mount point inside the guest.
const GUEST_PROC: &str = "/proc";
/// The `/dev` mount point inside the guest.
const GUEST_DEV: &str = "/dev";
/// The git view's READ-ONLY history mount. Not a `GuestPath`
/// root (a capsule mapping can never address it — the view arrives through the
/// capsule's `git_view` field, never through an input), same class as `/proc`.
const GUEST_GIT_HISTORY: &str = "/git-history";
/// The git view's WRITABLE scratch gitdir mount — see [`GUEST_GIT_HISTORY`].
const GUEST_GIT: &str = "/git";
/// The tool host's READ-ONLY directory: the provider entry's `toolhost/`, bound
/// here for an agent capsule — every agent capsule's init is `kata-toolhost` —
/// and for nothing else. Runtime-owned like [`GUEST_GIT_HISTORY`]: not a
/// `GuestPath` root, so no capsule mapping can name, shadow or write it.
const GUEST_TOOLHOST: &str = "/.kata";
/// The tool host's program, the one file under [`GUEST_TOOLHOST`]
/// (`crate::provider_store::TOOLHOST_PROGRAM`): `process.args` of every capsule
/// [`GUEST_TOOLHOST`] is bound for. kata fixes it, so the capsule's own argv
/// is empty (`Capsule::new` refuses any other).
const TOOLHOST_GUEST_PROGRAM: &str = "/.kata/kata-toolhost";
/// The `HOME` a toolhost capsule's init and every tool process it starts see:
/// the capsule's `/tmp` tmpfs, the one writable scratch that is not the stage's
/// tree or its result. Kata renders it, so a declared `HOME` is refused
/// (`kata_types::execution_contract::kata_rendered_env`).
const TOOLHOST_HOME: &str = "HOME=/tmp";

/// `root.path`, relative to the bundle directory — the OCI spec's own convention.
const ROOTFS_DIRECTORY: &str = "rootfs";

/// The guest's hostname. FIXED, and that is the point: a hostname derived from
/// the host or from the attempt would be a machine fact reaching a stage, which
/// is the thing this whole plane exists to prevent.
const GUEST_HOSTNAME: &str = "kata";

/// `RLIMIT_NOFILE`, soft and hard. runc's rootless-spec default; the ONLY rlimit
/// on this route, because every other bound kata cares about is a cgroup bound
/// and setting the same limit twice by two mechanisms gives an operator two
/// places to read a different answer.
const NOFILE_LIMIT: u64 = 1024;

/// `/dev` and `/dev/shm` tmpfs size — runc's rootless-spec default, verbatim.
const DEV_TMPFS_SIZE: &str = "size=65536k";

/// runc 1.3.6's rootless `linux.maskedPaths`, verbatim.
///
/// # Why verbatim, and why `/sys/firmware` stays in a spec with no `/sys`
///
/// This list is the OCI ecosystem's accumulated answer to *"which `/proc` and
/// `/sys` entries leak the host"*, maintained by the reference runtime and
/// re-derived by nobody here — a second hand-maintained copy would drift from
/// runc's the first time runc added an entry. `/sys` is NOT a mount on this route
/// (see [`bundle_mounts`]), so masking `/sys/firmware` covers a path that does
/// not exist and a runtime skips it; dropping it would make this list a kata
/// EDIT of runc's rather than runc's, and the next reader would have to work out
/// which entries were dropped on purpose.
const MASKED_PATHS: &[&str] = &[
    "/proc/acpi",
    "/proc/asound",
    "/proc/kcore",
    "/proc/keys",
    "/proc/latency_stats",
    "/proc/timer_list",
    "/proc/timer_stats",
    "/proc/sched_debug",
    "/sys/firmware",
    "/proc/scsi",
];

/// runc 1.3.6's rootless `linux.readonlyPaths`, verbatim. See [`MASKED_PATHS`].
const READONLY_PATHS: &[&str] = &[
    "/proc/bus",
    "/proc/fs",
    "/proc/irq",
    "/proc/sys",
    "/proc/sysrq-trigger",
];

/// The host roots a stage's writable guest directories were materialized into.
///
/// Three fields and no more: `/work` and `/out` are real host directories a
/// stage's bytes come from and go to, and `/tmp` is a tmpfs whose only property
/// is its SIZE — there is no host directory behind it, and inventing one would
/// put a stage's scratch on the host's disk where a later attempt could read it.
///
/// # Every field is PRIVATE, and the only constructor derives two of them
///
/// Public fields made this type able to name ANY two absolute host paths, which
/// is not what a bundle's `/work` and `/out` are: they are the two subdirectories
/// of ONE attempt root, laid out exactly as the worker's materializer lays
/// them out. A caller that could pass two unrelated paths could bind a stage's
/// `/out` into another attempt's tree, and this module would have no way to tell.
/// [`Self::under`] takes the root and derives both names, so that assignment is
/// not a caller's to make.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BundleMounts {
    work: PathBuf,
    out: PathBuf,
    tmp_bytes: u64,
    /// The OPTIONAL egress environment. `None` from [`Self::under`], so a
    /// capsule without egress renders a `config.json` with no egress plumbing at
    /// all — which is what keeps the committed golden a test of production
    /// rather than of a default.
    egress: Option<EgressPlumbing>,
    /// The agent capsule's disposable git view: the materialized
    /// history tree (bound `ro` at `/git-history`) and the writable scratch
    /// gitdir (bound `rw` at `/git`). `None` from [`Self::under`] —
    /// [`Self::with_git_view`] sets it, and only a capsule that DECLARES
    /// `git_view` may arrive carrying one ([`spec_for`]'s agreement check, the
    /// egress pair's rule restated).
    git_view: Option<crate::git_view::GitViewLayout>,
    /// The provider entry's `toolhost/` directory, bound `ro` at `/.kata` for a
    /// capsule whose init is `kata-toolhost`. `None` from [`Self::under`];
    /// [`Self::with_toolhost`] sets it, and only such a capsule may arrive
    /// carrying one ([`spec_for`]'s agreement check).
    toolhost: Option<PathBuf>,
}

/// The worker-resolved halves of an `Egress` capsule's `hooks.createContainer`
/// render — inputs [`spec_for`] cannot invent because they are facts of the
/// PROVISIONED provider entry, not of the capsule.
///
/// `program` pins the `kata-oci-hook` binary by path AND sha256 — exactly the
/// `youki` pin's shape, for the same reason and a worse blast radius: a
/// `createContainer` hook runs as the runtime's child inside the guest's
/// network namespace on the host's mount namespace (measured), outside
/// every bound the capsule's `CapEff=0` init is under. The provider re-derives
/// the digest before the runtime may exec it (`hook_digest_mismatch`).
/// `ip` is the provider entry's iproute2 binary that `loopback-up` execs by
/// absolute path; it travels inside the hook's argv rather than as a second
/// pin because the entry is hash-verified as a whole at resolve — see
/// `crate::provider_store`.
#[derive(Clone, Debug)]
pub struct EgressHookInputs {
    /// `<provider entry>/kata-oci-hook`, pinned by path and sha256.
    pub program: PinnedRuntime,
    /// `<provider entry>/ip`, exec'd by the `loopback-up` hook.
    pub ip: PathBuf,
}

/// The subdirectory of an attempt root bound read-write at `/work`.
///
/// `pub(crate)` so the modules that must stay OUT of it — `interactive_capsule`'s `io/`,
/// `egress_proxy`'s `egress/` — compare against this constant rather than against a
/// literal `"work"` that would keep matching after this one moved.
pub(crate) const ATTEMPT_WORK_DIRECTORY: &str = "work";
/// The subdirectory of an attempt root bound read-write at `/out`. See
/// [`ATTEMPT_WORK_DIRECTORY`] for why it is `pub(crate)`.
pub(crate) const ATTEMPT_OUT_DIRECTORY: &str = "out";

impl BundleMounts {
    /// The two writable roots beneath `attempt_root`, plus the `/tmp` size.
    ///
    /// The layout is the worker materializer's: `<attempt_root>/work` and
    /// `<attempt_root>/out`. There is no `tmp` directory on the host — `/tmp` is a
    /// tmpfs in the container and nothing on this side backs it.
    ///
    /// Taking the ROOT rather than two paths is what keeps the materializer's
    /// layout and this plan's from drifting apart.
    ///
    /// # Refused set
    ///
    /// `attempt_root` that is not absolute (a relative mount source resolves
    /// against whatever directory the RUNTIME happens to be in, so the stage would
    /// read a different tree depending on who started it); `tmp_bytes` of 0 (a
    /// filesystem a stage cannot write one byte to is a broken mount, not a
    /// bound); and the two derived paths being EQUAL.
    ///
    /// That last one cannot happen while [`ATTEMPT_WORK_DIRECTORY`] and
    /// [`ATTEMPT_OUT_DIRECTORY`] are distinct literals, and it is checked anyway
    /// for one reason: the day either name becomes configurable, an aliasing pair
    /// would bind a stage's RESULT directory over its SOURCE tree, and the failure
    /// would look like a stage that overwrote its own inputs rather than like a
    /// layout bug. A refusal that costs one comparison is cheaper than that
    /// diagnosis.
    ///
    /// # Errors
    /// [`KataError::Validation`] naming which of the three refused.
    pub fn under(attempt_root: &Path, tmp_bytes: u64) -> KataResult<Self> {
        let refuse = |reason: String| {
            Err(KataError::Validation(format!(
                "oci bundle mounts refused: {reason}"
            )))
        };
        if !attempt_root.is_absolute() {
            return refuse(format!(
                "the attempt root {} is not absolute. A relative mount source resolves against \
                 whatever directory the RUNTIME happens to be in, so the stage would read a \
                 different tree depending on who started it",
                attempt_root.display()
            ));
        }
        if tmp_bytes == 0 {
            return refuse(
                "the /tmp tmpfs size is 0 bytes, which is a filesystem a stage cannot write one \
                 byte to. A scratch directory that refuses every write is not a bound, it is a \
                 broken mount"
                    .to_owned(),
            );
        }
        let work = attempt_root.join(ATTEMPT_WORK_DIRECTORY);
        let out = attempt_root.join(ATTEMPT_OUT_DIRECTORY);
        if work == out {
            return refuse(format!(
                "the derived /work and /out sources are the same host path ({}). A stage's RESULT \
                 directory bound over its SOURCE tree would look like a stage overwriting its own \
                 inputs rather than like a layout bug",
                work.display()
            ));
        }
        Ok(Self {
            work,
            out,
            tmp_bytes,
            egress: None,
            git_view: None,
            toolhost: None,
        })
    }

    /// Give this attempt's container the tool host: `dir` is the provider
    /// entry's `toolhost/` as `crate::provider_store::ResolvedProvider::toolhost_dir`
    /// proved it (a real directory holding exactly the one program), bound
    /// read-only at `/.kata`.
    ///
    /// # Errors
    /// [`KataError::Validation`] when `dir` is not absolute: a relative mount
    /// source resolves against whatever directory the runtime happens to be in.
    pub fn with_toolhost(mut self, dir: PathBuf) -> KataResult<Self> {
        if !dir.is_absolute() {
            return Err(KataError::Validation(format!(
                "oci bundle mounts refused: the toolhost directory {} is not absolute",
                dir.display()
            )));
        }
        self.toolhost = Some(dir);
        Ok(self)
    }

    /// The host directory bound read-only at `/.kata`, when this attempt's
    /// capsule's init is `kata-toolhost`.
    #[must_use]
    pub fn toolhost(&self) -> Option<&Path> {
        self.toolhost.as_deref()
    }

    /// Give this attempt's container the proxy variables for `plumbing`.
    ///
    /// # What this adds to `config.json`, and what it does NOT
    ///
    /// the `process.env` entries [`EgressPlumbing::guest_env`] declares — the
    /// `HTTP_PROXY`/`HTTPS_PROXY`/`ALL_PROXY` proxy names and the loopback
    /// `NO_PROXY` bypass, each in both casings, the proxy names all in the
    /// `http://127.0.0.1:<port>` form [`EgressPlumbing`] is the sole producer of. No
    /// mount, no namespace change, no capability: see [`crate::egress_proxy`]'s
    /// module doc for the measurement that rules out bind-mounting the proxy socket
    /// (no HTTP client in play can consume a `unix:` proxy URL, and one of the two
    /// IGNORES it and goes direct), and for the `createContainer` hook that raises the
    /// loopback the endpoint this renders is reached on.
    #[must_use]
    pub fn with_egress(mut self, plumbing: EgressPlumbing) -> Self {
        self.egress = Some(plumbing);
        self
    }

    /// The egress environment this attempt's container is given, if any.
    #[must_use]
    pub const fn egress(&self) -> Option<&EgressPlumbing> {
        self.egress.as_ref()
    }

    /// Give this attempt's container the git view's two mounts — the
    /// directories DERIVED from the same attempt root, for the reason
    /// [`Self::under`] derives `work`/`out`: a caller-supplied pair could bind
    /// one attempt's scratch into another's container. `adapt_roots` compares
    /// the derivation against the materializer's layout, the same
    /// two-producers check the work/out pair already gets.
    #[must_use]
    pub fn with_git_view(mut self) -> Self {
        let root = self
            .work
            .parent()
            .expect("`work` is `<attempt_root>/work` by construction");
        self.git_view = Some(crate::git_view::GitViewLayout {
            history: root.join(crate::git_view::HISTORY_ROOT_NAME),
            scratch: root.join(crate::git_view::SCRATCH_ROOT_NAME),
        });
        self
    }

    /// The git view's two host roots when this attempt's capsule declares one —
    /// `history` for the `ro` `/git-history` bind, `scratch` for the `rw` `/git`
    /// one.
    #[must_use]
    pub fn git_view(&self) -> Option<&crate::git_view::GitViewLayout> {
        self.git_view.as_ref()
    }

    /// The host path bound read-write at `/work`.
    #[must_use]
    pub fn work(&self) -> &Path {
        &self.work
    }

    /// The host path bound read-write at `/out`.
    #[must_use]
    pub fn out(&self) -> &Path {
        &self.out
    }

    /// The `/tmp` tmpfs size in bytes.
    #[must_use]
    pub const fn tmp_bytes(&self) -> u64 {
        self.tmp_bytes
    }

    /// Both host sources as UTF-8, or the refusal that names which one is not.
    ///
    /// `to_str`, never `to_string_lossy`: a lossy conversion replaces the
    /// offending byte with U+FFFD and produces a mount source that is a DIFFERENT
    /// path which probably does not exist — so youki refuses a path the operator
    /// cannot find in their own filesystem, or worse, one that does exist. The
    /// `config.json` is UTF-8 text by the OCI spec, so a non-UTF-8 host path has
    /// no representation in a bundle and is refused rather than approximated.
    ///
    /// `{:?}` and not `display()`, deliberately and against clippy's default
    /// advice: this message exists BECAUSE the value holds a byte that is not
    /// valid UTF-8, and `Display` renders exactly that byte as a replacement
    /// character — showing the operator a path that looks fine inside a message
    /// saying it is not.
    #[allow(clippy::unnecessary_debug_formatting)]
    fn sources(&self) -> KataResult<(&str, &str)> {
        Ok((
            utf8_source(&self.work, GUEST_WORK)?,
            utf8_source(&self.out, GUEST_OUT)?,
        ))
    }
}

/// One host mount source as the UTF-8 a `config.json` can hold — see
/// [`BundleMounts::sources`], whose doc carries the reasoning.
#[allow(clippy::unnecessary_debug_formatting)]
fn utf8_source<'a>(path: &'a Path, which: &str) -> KataResult<&'a str> {
    path.to_str().ok_or_else(|| {
        KataError::Validation(format!(
            "oci bundle refused: the host source for {which} is not valid UTF-8, and a \
             config.json is UTF-8 text. Refusing rather than converting it lossily: a path that \
             lost a byte names a DIFFERENT file, so the runtime would bind something other than \
             what kata materialized. Value: {path:?}"
        ))
    })
}

/// Plan the rootless OCI container for `capsule`.
///
/// # Refused set
///
/// Accepts if and only if ALL of the following hold; everything else is refused
/// with the offending value named:
///
/// * `network` is [`NetPolicy::Offline`]. [`NetPolicy::Host`] is refused BY NAME:
///   there is no egress arm on this route yet, and a container that quietly kept
///   the host's network because kata had nothing better to do would be the
///   silent downgrade this whole plane exists to prevent.
/// * both host sources are valid UTF-8 — see [`BundleMounts::sources`]. That they
///   are ABSOLUTE, distinct and paired with a non-zero `/tmp` size is
///   [`BundleMounts::under`]'s refused set, made unrepresentable before this
///   function is reached rather than re-checked here.
/// * `budgets.memory_bytes` and `budgets.process_count` are non-zero. A zero is
///   not "unbounded" — it is a bound nobody set, and this route's whole claim is
///   that a stage runs bounded.
/// * the environment's closure is non-empty and its `path_prepend` is non-empty.
///   An empty `path_prepend` would render `PATH=:/bin`, whose leading empty entry
///   the shell reads as the CURRENT DIRECTORY — a `PATH` that resolves out of
///   `/work` is worse than no `PATH`.
/// * every capsule input maps a guest path that is `/work`, `/out`, `/tmp`, or one
///   of the closure's own store paths; ALL THREE of `/work`, `/out` and `/tmp` are
///   present and writable — `/work` as [`GuestAccess::ReadWrite`] or
///   [`GuestAccess::ReadWriteScratch`], `/out` and `/tmp` as `ReadWrite` — and
///   no closure store path is mapped `ReadWrite` or `ReadWriteScratch`.
///   `/tmp` is required and not merely permitted because
///   `kata_workflow::capsule_assembly` always emits it — a capsule arriving
///   without one did not come from that assembler, and a bundle that mounted a
///   `/tmp` the capsule never asked for would be kata inventing an authority.
/// * an `Agent` capsule — whose init is `kata-toolhost` — arrives with the
///   mounts' toolhost directory, and no other capsule does. Its `process.args`
///   is `/.kata/kata-toolhost`, fixed by kata — the capsule's own argv is empty
///   by `Capsule::new` — and its env renders `HOME=/tmp`. The harness's
///   credential is carried to the harness in-process, so no bundle carries one.
/// * the fence has an OCI form — see
///   [`oci_seccomp_rules`](kata_types::sandbox_seccomp::oci_seccomp_rules)'s own
///   refused set.
/// * the pinned youki parses, and the rendered `Spec` round-trips through
///   `serde_json` unchanged.
///
/// # What it does NOT refuse, and must not be read as checking
///
/// * **That the capsule's `EnvironmentId` names THIS manifest.** That id is
///   `H(manifest artifact id, closure digest)` and this function is handed the
///   manifest, not its artifact id, so it cannot recompute it. Binding the pair is
///   the authorizing step's job, and a check here that compared the
///   closure digest alone would be a narrower test wearing the wider claim.
/// * **That any of these paths or bytes EXIST.** This is a plan; materialization
///   and digest verification live in the worker's materializer.
/// * **The two classic-BPF guards** the OCI spec cannot express (foreign `arch`,
///   the x32 number range). Stated, not refused — see the module docs.
///
/// # Errors
/// [`KataError::Validation`] for every item in the refused set, naming which.
pub fn spec_for(
    capsule: &Capsule,
    environment: &NixEnvironmentManifest,
    mounts: &BundleMounts,
    containment: &AttemptContainment,
    network: NetPolicy,
    egress: Option<&EgressHookInputs>,
) -> KataResult<OciBundlePlan> {
    spec_for_as(
        capsule,
        environment,
        mounts,
        containment,
        network,
        egress,
        nix::unistd::getuid().as_raw(),
        nix::unistd::getgid().as_raw(),
    )
}

/// [`spec_for`] with the host uid/gid the single rootless mapping points at taken
/// as parameters instead of read from the process.
///
/// `#[doc(hidden)] pub` for ONE reason, and it is the same reason
/// [`crate::oci_runtime::run_throwaway_container_with`] is: the produced
/// `config.json` is a committed byte golden, and a golden that embedded the
/// running uid would be re-baselined on every host instead of comparing. The
/// golden test drives this seam with fixed ids, and its sibling
/// `spec_for_reads_the_processs_own_uid_and_gid` asserts that [`spec_for`] passes
/// the PROCESS's own, so neither half is taken on trust.
///
/// # Errors
/// See [`spec_for`].
#[doc(hidden)]
pub fn spec_for_as(
    capsule: &Capsule,
    environment: &NixEnvironmentManifest,
    mounts: &BundleMounts,
    containment: &AttemptContainment,
    network: NetPolicy,
    egress: Option<&EgressHookInputs>,
    // `host_user` / `host_group` rather than `host_uid` / `host_gid`: clippy's
    // `similar_names` is right that a one-letter difference between two adjacent
    // `u32` parameters is a call site waiting to swap them.
    host_user: u32,
    host_group: u32,
) -> KataResult<OciBundlePlan> {
    // EXHAUSTIVE DESTRUCTURE 1/3 — the capsule. `Capsule::fields` exists for
    // this: a field added to the capsule is `E0027` here rather than a bundle
    // that silently ignores what the capsule says.
    let kata_types::execution_contract::CapsuleFields {
        // Read: the schema version is stamped and validated by `Capsule`'s own
        // decoder, so there is nothing left for this renderer to decide about it.
        schema_version: _,
        id,
        // The occurrence, the prepared action and the platform are the capsule's
        // PROVENANCE. None of them may reach the guest: an occurrence id in the
        // environment or in the hostname would make a stage's bytes depend on
        // which run produced them, which is the opposite of what a content-
        // addressed capsule is for. Named here so that stays a decision.
        occurrence: _,
        action: _,
        platform: _,
        // See the refused set: the pair cannot be verified from a manifest alone.
        environment: _,
        inputs,
        // `process.args`, taken FROM THE CAPSULE rather than from a parameter: the
        // bytes the container execs are the ones the capsule id
        // folds, so they are the authorization's answer and not the caller's. A
        // capsule cannot carry an empty argv (`Capsule::new` refuses one, with argv[0]
        // and the NUL case), so this renderer's old `argv is empty` refusal is
        // unrepresentable and is gone rather than kept as a second door.
        process,
        // The DECLARED network posture, planned from as of contract v8: an
        // `Egress` declaration drives the `createContainer` hooks render and
        // the proxy environment, and a disagreement between it, the mounts'
        // plumbing and the `egress` inputs is refused rather than resolved in
        // anybody's favour — the three are halves of one claim.
        network: declared_network,
        git_view,
        // The confinement view is the MATERIALIZER's input, not the renderer's:
        // what the container sees of /work is decided by which members are
        // written, and the bind is read-write either way. Named here so the
        // field is never silently unread.
        work_view: _,
        budgets,
    } = capsule.fields();

    // EXHAUSTIVE DESTRUCTURE 2/3 — the bounds.
    let kata_types::execution_contract::CapsuleBudgets {
        // Neither of these has an OCI spelling, and neither is dropped: the wall
        // clock is the provider supervisor's FRAME BUDGET on the worker
        // ([`crate::oci_driver::capsule_provider_spec`]: `wall_time_ms` plus
        // `PROVIDER_FRAME_MARGIN`, after which the provider and its container are
        // killed and contained) and, on the main, the capsule wall-time settlement
        // leg (`kata_workflow`'s `Dispatcher::sweep_capsule_wall_time`).
        // (`crate::oci_runtime::run_bundle`'s `timeout` is a live-test helper's
        // watchdog, not on the production route.) They are bounds on what KATA does
        // around the container, not on the container, so a `config.json` that
        // claimed them would be claiming an enforcement it has no mechanism for.
        // The output bound rides the ASSIGNMENT — `oci_driver`'s `CaptureSpec`
        // puts `output_bytes` on the spool as the provider's COMBINED kill bound.
        wall_time_ms: _,
        output_bytes: _,
        // The result-tree pair. Neither has an OCI
        // spelling either, and for a sharper reason than the two above: they bound
        // the RESULT TREE main adopts after the container has exited, so nothing
        // inside `config.json` could enforce them even in principle. They are the
        // adopting side's bound, checked where the result is adopted.
        result_bytes: _,
        result_entries: _,
        // Contract v7's `/work` delta pair — CARRIED on the capsule so the delta
        // budget the author promised travels in the capsule id; enforcement (the
        // `TreeDelta` comparison) is where the produced tree is accounted, and
        // no `config.json` field could state it either.
        work_delta_bytes: _,
        work_delta_entries: _,
        memory_bytes,
        process_count,
    } = budgets;

    let refuse = |reason: String| {
        Err(KataError::Validation(format!(
            "oci bundle refused: {reason}"
        )))
    };

    let toolhost_launch = vec![smol_str::SmolStr::new_static(TOOLHOST_GUEST_PROGRAM)];
    let toolhost_init = matches!(
        process,
        kata_types::execution_contract::CapsuleProcess::Agent(_)
    );
    let (argv, declared_env) = match process {
        kata_types::execution_contract::CapsuleProcess::Command { argv } => (argv, Vec::new()),
        // An `Agent` turn launches `kata-toolhost`, the one init an agent
        // capsule has: kata fixes `process.args` (the turn's own argv is empty
        // by `Capsule::new`) and renders its `HOME` ahead of the node's
        // declared NON-SECRET environment, all after `PATH` and the proxy pair.
        // The embedded harness that speaks to it runs in the worker.
        kata_types::execution_contract::CapsuleProcess::Agent(turn) => (
            &toolhost_launch,
            std::iter::once(TOOLHOST_HOME.to_owned())
                .chain(turn.env.iter().map(|(key, value)| format!("{key}={value}")))
                .collect::<Vec<String>>(),
        ),
    };

    // The network posture, BY NAME. No `_ =>` arm: a third variant must stop this
    // compiling, because that is the moment somebody has to decide what it means
    // for a container that has no egress mechanism.
    match network {
        // `Egress` capsules ALSO plan an `Offline` namespace posture — their
        // only reach is the loopback listener a `createContainer` hook hands
        // the worker, which is an empty namespace plus one socket, not a
        // second posture.
        NetPolicy::Offline => {}
        NetPolicy::Host => {
            return refuse(
                "network posture `host` has no form on the rootless-OCI route. Offline is \
                 implemented by giving the container its OWN empty network namespace, and the \
                 egress arm that exists (`crate::egress_proxy`) reaches the world through a \
                 worker-owned listener fd handed over by a createContainer hook — never through \
                 a shared namespace. A `host` posture would share the host's interfaces \
                 wholesale, so refusing rather than omitting the network namespace: a container \
                 that kept the host's network because kata had nothing better to offer is a \
                 containment plan silently degraded, and the frame would still say `completed`."
                    .to_owned(),
            );
        }
    }

    // The DECLARED posture, the plumbing env and the hook inputs are the THREE
    // halves of one claim, and they must agree exactly: `Offline` arrives with
    // no egress machinery, `Egress` arrives with all of it, and anything in
    // between is refused — a plan carrying only some of the halves would
    // describe a network posture nobody declared.
    let hook_inputs = match (declared_network, mounts.egress(), egress) {
        (CapsuleNetwork::Offline, None, None) => None,
        (CapsuleNetwork::Egress { .. }, Some(_), Some(inputs)) => Some(inputs),
        (CapsuleNetwork::Offline, plumbing, inputs) => {
            return refuse(format!(
                "the capsule declares `network: offline` but arrives with egress machinery \
                 (plumbing env: {}, hook inputs: {}). An Offline plan carries no egress \
                 anything — the declaration is the authority, not the supplies",
                plumbing.is_some(),
                inputs.is_some()
            ));
        }
        (CapsuleNetwork::Egress { allowlist }, plumbing, inputs) => {
            return refuse(format!(
                "the capsule declares an egress allowlist of {} entries but arrives short of \
                 its mechanism (plumbing env: {}, hook inputs: {}). A plan that rendered only \
                 part of an egress arm would describe a posture nobody declared",
                allowlist.len(),
                plumbing.is_some(),
                inputs.is_some()
            ));
        }
    };

    // Contract v10's GIT VIEW — the same agreement shape the egress check
    // states: the capsule's `git_view` field, the materialized mounts and the
    // rendered `config.json` are three halves of one claim, and they must agree
    // exactly. A capsule declaring the view whose materializer laid out none is
    // refused rather than planned — the gitfile `/work/.git` already written
    // would resolve to nothing; and mounts arriving on a capsule that never
    // declared one is machinery a guest was not granted, refused the same way.
    match (git_view, mounts.git_view()) {
        (None, None) | (Some(_), Some(_)) => {}
        (Some(_), None) => {
            return refuse(
                "the capsule declares a git view but the materializer laid out none — the \
                 attempt root holds no git-history/ or git/ to bind, and a plan that mounted \
                 neither would hand the container a /work whose .git file resolves to nothing"
                    .to_owned(),
            );
        }
        (None, Some(_)) => {
            return refuse(
                "the mounts carry a git view the capsule never declared — a scratch repository \
                 and a history the authorization does not name, which a bundle does not grant \
                 on a guest's behalf"
                    .to_owned(),
            );
        }
    }

    // THE TOOL HOST — the same agreement shape again: an agent capsule, whose
    // init is `kata-toolhost`, and the mounts' toolhost directory arrive
    // together or not at all. A toolhost capsule with no directory would exec a
    // program the rootfs does not hold; a directory on any other capsule is a
    // mount the capsule never declared.
    match (toolhost_init, mounts.toolhost()) {
        (true, Some(_)) | (false, None) => {}
        (true, None) => {
            return refuse(
                "the capsule's init is kata-toolhost, fixed for every agent capsule, but the mounts \
                 carry no toolhost directory to bind at /.kata — a plan without it would exec a \
                 program the rootfs does not hold"
                    .to_owned(),
            );
        }
        (false, Some(_)) => {
            return refuse(
                "the mounts carry a toolhost directory, but the capsule's init is not \
                 kata-toolhost — /.kata is bound only for an agent capsule, whose launch it is, \
                 never on a guest's behalf"
                    .to_owned(),
            );
        }
    }
    // The two host sources, as the UTF-8 a `config.json` can hold. Absolute,
    // distinct and non-zero-`/tmp` are `BundleMounts::under`'s refusals and are
    // already unrepresentable here.
    let sources = mounts.sources()?;
    if memory_bytes == 0 {
        return refuse(
            "the capsule's memory_bytes budget is 0. `memory.limit = 0` means UNLIMITED to the \
             kernel, so rendering it would turn a bound nobody set into no bound at all"
                .to_owned(),
        );
    }
    if process_count == 0 {
        return refuse(
            "the capsule's process_count budget is 0, which as `pids.limit` is a container that \
             cannot fork its own init. A zero here is a bound nobody set, never `unlimited`"
                .to_owned(),
        );
    }
    if environment.closure().is_empty() {
        return refuse(
            "the Nix environment binds an EMPTY closure, so the rootfs would hold nothing but \
             empty mount points and the argv could name no program that exists"
                .to_owned(),
        );
    }
    if environment.path_prepend().is_empty() {
        return refuse(
            "the Nix environment declares no path_prepend, so `PATH` would render as `:/bin` — \
             and a LEADING EMPTY entry is read by every shell as the current directory, which on \
             this route is /work. A PATH that resolves out of the stage's own writable tree is \
             worse than no PATH"
                .to_owned(),
        );
    }

    let store_paths: Vec<&str> = environment
        .closure()
        .iter()
        .map(|entry| entry.store_path.as_str())
        .collect();

    // EXHAUSTIVE DESTRUCTURE 3/3 — every mapping the capsule declares.
    let mut work_seen = false;
    let mut out_seen = false;
    let mut tmp_seen = false;
    for input in inputs {
        let GuestMapping {
            // The artifact names WHICH BYTES land at the guest path; verifying and
            // placing them is the materializer's job, and this plan carries a
            // mount source rather than a digest precisely so the two cannot both
            // claim to have checked it.
            artifact: _,
            guest_path,
            access,
        } = input;
        let path = guest_path.as_str();
        let in_closure = store_paths.contains(&path);
        match (path, access, in_closure) {
            (GUEST_WORK, GuestAccess::ReadWrite | GuestAccess::ReadWriteScratch, _) => {
                work_seen = true;
            }
            (GUEST_OUT, GuestAccess::ReadWrite, _) => out_seen = true,
            (GUEST_TMP, GuestAccess::ReadWrite, _) => tmp_seen = true,
            // A closure store path, read-only: the one ACCEPTED mapping no
            // presence flag tracks, because the closure's own entries are what
            // `bundle_mounts` iterates.
            (_, GuestAccess::ReadOnly, true) => {}
            (GUEST_WORK | GUEST_OUT | GUEST_TMP, GuestAccess::ReadOnly, _) => {
                return refuse(format!(
                    "the capsule maps {path} READ-ONLY, and this route mounts it read-write. A \
                     stage told it may write a directory the plan mounts `ro` fails at the first \
                     write with EROFS, which reads as the stage's bug"
                ));
            }
            // `read_write_scratch` is `/work`'s own access tag — the marker a
            // scratch `/work` carries so the main records its delta without
            // applying it. On any other path it is a mapping no assembler
            // mints: refused, never coerced to plain read-write.
            (other, GuestAccess::ReadWriteScratch, _) => {
                return refuse(format!(
                    "the capsule maps {other} read_write_scratch — the scratch tag is \
                     {GUEST_WORK}'s alone: it is the marker the main's adoption keys on, and a \
                     scratch {GUEST_OUT} or a scratch store path is a mapping kata does not mint"
                ));
            }
            (_, GuestAccess::ReadWrite, true) => {
                return refuse(format!(
                    "the capsule maps the Nix store path {path} READ-WRITE. A store object is \
                     content-addressed and shared by every capsule that binds the same closure, \
                     so a writable bind would let one stage change another's inputs"
                ));
            }
            (other, _, false) => {
                return refuse(format!(
                    "the capsule maps guest path {other}, which is neither {GUEST_WORK}, \
                     {GUEST_OUT} nor {GUEST_TMP} and is not one of the {} store paths in the \
                     authorized closure. A mount this plan cannot attribute to the capsule's own \
                     authority does not go in the bundle",
                    store_paths.len()
                ));
            }
        }
    }
    let missing: Vec<&str> = [
        (work_seen, GUEST_WORK),
        (out_seen, GUEST_OUT),
        (tmp_seen, GUEST_TMP),
    ]
    .into_iter()
    .filter_map(|(seen, path)| (!seen).then_some(path))
    .collect();
    if !missing.is_empty() {
        return refuse(format!(
            "the capsule declares no read-write mapping for {}. This route binds a stage's tree \
             at {GUEST_WORK}, gives it scratch at {GUEST_TMP} and collects its result from \
             {GUEST_OUT}; a bundle that mounted one the capsule never asked for would be kata \
             inventing an authority. `kata_workflow::capsule_assembly` emits all three, so a \
             capsule short of one did not come from it",
            missing.join(", ")
        ));
    }

    let pin = YoukiPin::embedded_result().map_err(|error| {
        KataError::Validation(format!(
            "oci bundle refused: the embedded youki pin does not parse, so the plan cannot name \
             the runtime it expects: {error}"
        ))
    })?;

    let spec = build_spec(
        environment,
        mounts,
        sources,
        containment,
        argv,
        &declared_env,
        hook_inputs.map(|inputs| {
            (inputs, mounts.egress().expect(
            "the agreement check above admits an Egress capsule only with its plumbing present",
        ))
        }),
        host_user,
        host_group,
        memory_bytes,
        process_count,
    )?;

    // PRETTY, and "canonical" means exactly one deterministic encoding rather
    // than the smallest one: these bytes are a committed golden a reviewer has to
    // read, and `serde_json` emits struct fields in declaration order and every
    // sequence in the order it was built, so the encoding is stable. The trailing
    // newline is what makes the fixture a text file `diff` and `git` handle.
    let mut config_json = serde_json::to_string_pretty(&spec).map_err(|error| {
        KataError::Validation(format!(
            "oci bundle refused: serializing the spec failed: {error}"
        ))
    })?;
    config_json.push('\n');

    // VALIDATION, and it is a round-trip because oci-spec 0.8.4 ships no
    // validator: `Spec` has no `validate`, and its builders enforce only that
    // required fields were set. What a round-trip does prove is that the bytes a
    // runtime will DESERIALIZE carry the same spec kata SERIALIZED — which is the
    // half a typo in a `size=` option or a lost `Option` would break.
    let decoded: Spec = serde_json::from_str(&config_json).map_err(|error| {
        KataError::Validation(format!(
            "oci bundle refused: the rendered config.json does not decode as an OCI runtime \
             spec, so a runtime would read something other than what kata planned: {error}"
        ))
    })?;
    if decoded != spec {
        return refuse(
            "the rendered config.json decodes to a DIFFERENT spec than kata built. The bytes are \
             what the runtime reads, so a plan whose bytes and value disagree describes two \
             containers"
                .to_owned(),
        );
    }

    Ok(OciBundlePlan {
        config_json,
        rootfs_mountpoints: rootfs_mountpoints(environment, mounts)?,
        // The capsule's own content address, hex, with a kata prefix so a
        // container on a shared host is attributable. Derived from the CAPSULE and
        // not from the attempt: two attempts of the same capsule describe the same
        // container, and a runtime that already has one registered under this name
        // is telling kata something true.
        container_id: format!("kata-{}", id.0),
        youki: PinnedRuntime {
            store_path: pin.store_path().to_owned(),
            sha256: pin.sha256().to_owned(),
        },
        // THE PLACEMENT, and it is kata's. `linux.cgroupsPath` inside
        // `config_json` names `<this>/container`, so the runtime's own leaf is
        // inside the subtree `ProviderSupervisor::contain` sweeps and
        // `TeardownProbe::CgroupPopulation` reads — see `crate::oci_cgroup` for the
        // five measured rows that force this shape, including what happens with the
        // field unset (the container lands in youki's own transient scope and
        // survives a `SIGKILL`ed provider while kata scores `Confirmed`).
        //
        // `Some` unconditionally: `AttemptContainment::new` refuses anything that
        // is not a real kata-owned directory beneath the cgroup v2 mount point, so
        // there is no arm here that could produce a `None`. A host with no
        // delegation has no `AttemptContainment` to hand this function, and
        // `kata-provider-youki` refuses a `None` for the same reason — on this
        // route an unplaced container is one nothing can tear down.
        cgroup_parent: Some(containment.cgroup_parent().display().to_string()),
        // The provider's own scratch root, worker-local — a property of this
        // containment, not the stage's working directory (`process.cwd` in
        // `config_json`).
        state_root: containment.state_root().display().to_string(),
        // CAPTURED, and the one field this function cannot decide from the capsule:
        // whether the container's stdio is read back after it exits or spoken to
        // while it runs is a property of the CALLER's intent, not of the capsule.
        // A shell stage is read back; an agent is spoken to. `crate::interactive_capsule`
        // is the sole producer of the `interactive` arm, and it replaces this field
        // on the plan this function returns rather than taking a parameter here —
        // the arm changes not one byte of `config_json` (`process.terminal` is
        // `false` either way, and the OCI spec says nothing about where a
        // non-terminal init's descriptors come from), so there is nothing about the
        // container's own description for it to participate in.
        stdio: kata_provider_protocol::OciStdio::Captured,
        // THE EGRESS HOOK PIN, the second half of the `hooks` claim the spec
        // just rendered: `config.json` names the hook's PATH and args and this
        // field pins its BYTES, and `kata-provider-youki::verify_egress_hooks`
        // refuses every disagreement between the two (a hook with no pin, a pin
        // with no hooks, a foreign phase, a path that is not this program, and
        // `hook_digest_mismatch`). `None` on an Offline plan, whose spec
        // carries no `hooks` object at all — the halves agree by absence.
        egress_hook: hook_inputs.map(|inputs| inputs.program.clone()),
    })
}

/// The store object the executor-term reference capsules bind. A well-formed path
/// that names nothing: a reference is rendered, never run.
const REFERENCE_STORE_OBJECT: &str =
    "/nix/store/00000000000000000000000000000000-kata-executor-term-reference";
/// The host uid/gid the references' rootless mapping points at — fixed, so the
/// rendered bytes are the same on every host.
const REFERENCE_HOST_ID: u32 = 1000;
/// The attempt root every reference is laid out under. Never created or read.
const REFERENCE_ATTEMPT_ROOT: &str = "/kata-executor-term/attempt";

/// The COMMAND bundle template: the `config.json` [`spec_for_as`] renders
/// for a fixed OFFLINE COMMAND reference capsule, which `crate::executor_term` folds
/// into the executor term.
///
/// The reference fixes every per-capsule input — the occurrence, the mappings, the
/// argv, the budgets, the closure, the host roots, the cgroup parent and the
/// uid/gid — so what can move these bytes is the renderer itself: its namespaces,
/// capabilities, masked and read-only paths, `/proc` and `/dev` mounts, mount
/// options, rlimits, id-mapping shape and the seccomp rules it embeds.
///
/// Pure: no path is read, created or checked, and `spec_for_as` reads no process
/// state, so every host renders the same bytes from one build.
///
/// # Errors
///
/// A build defect only — the renderer refusing its own reference.
pub(crate) fn reference_command_config() -> KataResult<String> {
    let mounts = BundleMounts::under(Path::new(REFERENCE_ATTEMPT_ROOT), 64 << 20)?;
    render_reference(
        kata_types::execution_contract::CapsuleProcess::Command {
            argv: vec![smol_str::SmolStr::new(format!(
                "{REFERENCE_STORE_OBJECT}/bin/true"
            ))],
        },
        CapsuleNetwork::Offline,
        None,
        &mounts,
        None,
    )
}

/// The TOOLHOST bundle template: the `config.json` [`spec_for_as`] renders for a
/// fixed AGENT reference capsule — every agent capsule's init is `kata-toolhost` —
/// taking every arm the command reference does not: the `/.kata` bind of a fixed
/// toolhost directory, the fixed `process.args`, the rendered `HOME`, a declared
/// env, an egress allowlist (the proxy env and the two `createContainer` hooks) and
/// a git view (the `/git-history` and `/git` binds). A change to any of those arms'
/// render moves these bytes.
///
/// Pure, as [`reference_command_config`]: the toolhost directory, the egress socket
/// and the hook binaries are named, never touched.
///
/// # Errors
///
/// A build defect only — the renderer refusing its own reference.
pub(crate) fn reference_toolhost_config() -> KataResult<String> {
    use kata_types::{
        execution_contract::{
            AgentTurnSpec, ArtifactId, ArtifactPrivacy, ArtifactRef, CapsuleGitView,
            CapsuleProcess, EgressAuthority, GitIdentity, GitViewRef,
        },
        primitives::ContentHash,
    };
    let fixed = |byte: u8| ContentHash::new([byte; 32]);
    let root = Path::new(REFERENCE_ATTEMPT_ROOT);
    let mounts = BundleMounts::under(root, 64 << 20)?
        .with_egress(EgressPlumbing::loopback(
            root.join("egress").join("proxy.sock"),
            18080,
        )?)
        .with_toolhost(PathBuf::from(format!(
            "{REFERENCE_ATTEMPT_ROOT}/provider/toolhost"
        )))?
        .with_git_view();
    let hook_inputs = EgressHookInputs {
        program: PinnedRuntime {
            store_path: format!("{REFERENCE_STORE_OBJECT}/bin/kata-oci-hook"),
            sha256: "0".repeat(64),
        },
        ip: PathBuf::from(format!("{REFERENCE_STORE_OBJECT}/bin/ip")),
    };
    render_reference(
        CapsuleProcess::Agent(AgentTurnSpec {
            adapter: kata_types::agent::AdapterKind::NanocodeOpenai,
            model: None,
            reasoning_effort: None,
            output_schema: None,
            prompt: ArtifactId(fixed(9)),
            credential: None,
            env: [(
                smol_str::SmolStr::new("TERM"),
                smol_str::SmolStr::new("dumb"),
            )]
            .into_iter()
            .collect(),
        }),
        CapsuleNetwork::Egress {
            allowlist: [EgressAuthority::new("kata-executor-term.invalid", 443)?]
                .into_iter()
                .collect(),
        },
        Some(CapsuleGitView {
            history: ArtifactRef::new(fixed(10), 1, ArtifactPrivacy::Private),
            base_commit: smol_str::SmolStr::new("0".repeat(40)),
            branch: Some(GitViewRef {
                name: smol_str::SmolStr::new("main"),
                commit: smol_str::SmolStr::new("0".repeat(40)),
            }),
            identity: GitIdentity {
                name: smol_str::SmolStr::new("kata"),
                email: smol_str::SmolStr::new("kata@kata-executor-term.invalid"),
            },
        }),
        &mounts,
        Some(&hook_inputs),
    )
}

/// One reference capsule's `config.json`: the closure, mappings, budgets and
/// containment every reference shares, around the arm-bearing inputs each passes.
fn render_reference(
    process: kata_types::execution_contract::CapsuleProcess,
    network: CapsuleNetwork,
    git_view: Option<kata_types::execution_contract::CapsuleGitView>,
    mounts: &BundleMounts,
    egress: Option<&EgressHookInputs>,
) -> KataResult<String> {
    use kata_types::{
        execution_contract::{
            ArtifactId, ArtifactPrivacy, CapsuleBudgets, EnvironmentId, OccurrenceId, PlatformRef,
            PreparedActionId,
        },
        nix_environment::{
            ClosureEntry, IntegrityPolicy, NarVerification, Provenance, RetentionClass,
            RetentionIntent, StorePath,
        },
        primitives::ContentHash,
    };
    let fixed = |byte: u8| ContentHash::new([byte; 32]);
    let platform = PlatformRef::new("x86_64-linux", fixed(1));
    let store_object = StorePath::new(REFERENCE_STORE_OBJECT)?;
    let environment = NixEnvironmentManifest::new(
        "kata-executor-term-reference",
        platform.clone(),
        Provenance::StorePaths {
            nixpkgs_attribute: "kata-executor-term-reference".into(),
        },
        vec![store_object.clone()],
        vec![ClosureEntry {
            store_path: store_object,
            nar_hash: "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".into(),
            nar_size: 1,
            references: vec![],
            ca: None,
        }],
        vec![GuestPath::new(format!("{REFERENCE_STORE_OBJECT}/bin"))?],
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
        "kata-executor-term-reference",
    )?;
    let mapping = |path: &str, access: GuestAccess, artifact: u8| -> KataResult<GuestMapping> {
        Ok(GuestMapping {
            artifact: ArtifactId(fixed(artifact)),
            guest_path: GuestPath::new(path.to_owned())?,
            access,
        })
    };
    let capsule = Capsule::new(
        OccurrenceId(fixed(2)),
        PreparedActionId(fixed(3)),
        EnvironmentId(fixed(4)),
        platform.id(),
        vec![
            mapping(GUEST_WORK, GuestAccess::ReadWrite, 5)?,
            mapping(GUEST_OUT, GuestAccess::ReadWrite, 6)?,
            mapping(GUEST_TMP, GuestAccess::ReadWrite, 7)?,
            mapping(REFERENCE_STORE_OBJECT, GuestAccess::ReadOnly, 8)?,
        ],
        process,
        network,
        git_view,
        CapsuleBudgets {
            wall_time_ms: 30_000,
            output_bytes: 1 << 20,
            memory_bytes: 512 << 20,
            process_count: 64,
            result_bytes: 4 << 20,
            result_entries: 128,
            work_delta_bytes: kata_types::execution_contract::CAPSULE_WORK_DELTA_BYTES,
            work_delta_entries: kata_types::execution_contract::CAPSULE_WORK_DELTA_ENTRIES,
        },
        None,
    )?;
    let containment = AttemptContainment::new(
        PathBuf::from("/sys/fs/cgroup/kata-executor-term"),
        PathBuf::from("/kata-executor-term/state"),
    )?;
    Ok(spec_for_as(
        &capsule,
        &environment,
        mounts,
        &containment,
        NetPolicy::Offline,
        egress,
        REFERENCE_HOST_ID,
        REFERENCE_HOST_ID,
    )?
    .config_json)
}

/// Guest directories a provider must create inside the rootfs before starting the
/// container.
///
/// # Why these are `String` and not [`GuestPath`]
///
/// `GuestPath`'s roots are `/work`, `/nix/store`, `/tmp` and `/out` — the four a
/// CAPSULE MAPPING may address — and `/proc` and `/dev` are under none of them,
/// deliberately: they are RUNTIME-owned mounts that no capsule declares, names or
/// can point an artifact at. So the four capsule-addressable points below go
/// through `GuestPath` (which is what makes their refused set the capsule's), and
/// the two runtime-owned ones are added afterwards as the literal constants this
/// module's own `spec.mounts` uses. Widening `GUEST_ROOTS` to accommodate them
/// would be the opposite trade: it would let a capsule map an artifact over
/// `/proc`.
///
/// `/dev/pts` and `/dev/shm` are deliberately ABSENT: both live inside the tmpfs
/// mounted at `/dev`, so a directory pre-created in the rootfs is shadowed the
/// moment that tmpfs lands and the runtime creates them itself.
fn rootfs_mountpoints(
    environment: &NixEnvironmentManifest,
    mounts: &BundleMounts,
) -> KataResult<Vec<String>> {
    let mut points: Vec<String> = Vec::new();
    for entry in environment.closure() {
        points.push(entry.store_path.as_guest_path().as_str().to_owned());
    }
    for capsule_addressable in [GUEST_WORK, GUEST_OUT, GUEST_TMP] {
        points.push(GuestPath::new(capsule_addressable)?.as_str().to_owned());
    }
    // The git view's two mount targets — present exactly when the bundle
    // carries the mounts (the `spec_for` agreement check has already refused
    // either half alone). Runtime-owned roots like `/proc`'s: no capsule
    // mapping can name them.
    if mounts.git_view().is_some() {
        points.push(GUEST_GIT_HISTORY.to_owned());
        points.push(GUEST_GIT.to_owned());
    }
    // The tool host's directory — present exactly when the bundle binds it
    // (the `spec_for` agreement check). A DIRECTORY point, which the provider
    // creates like every other: the bind is of the entry's `toolhost/`
    // directory, never of the program file, so the read-only rootfs needs no
    // file mount point.
    if mounts.toolhost().is_some() {
        points.push(GUEST_TOOLHOST.to_owned());
    }
    points.push(GUEST_PROC.to_owned());
    points.push(GUEST_DEV.to_owned());
    Ok(points)
}

/// `spec.mounts`, in the order the runtime must perform them.
///
/// # No `/sys`, and no `/sys/fs/cgroup`
///
/// runc's rootless spec rbinds the host's `/sys` read-only and mounts the cgroup
/// hierarchy under it. Neither is here. `/sys` is a window onto the HOST — its
/// devices, its firmware, its kernel tunables — and a hermetic stage has no
/// business reading any of it; the cgroup hierarchy is how a stage would see the
/// bounds kata placed on it and, on a delegated tree, potentially widen them. The
/// consequence is stated rather than hidden: a stage that needs `/sys` fails on
/// this route, and `linux.maskedPaths`' `/sys/firmware` entry covers a path that
/// is not mounted.
///
/// # `rprivate` on every rbind — necessary, and on its own NOT sufficient
///
/// An `rbind` copies a whole subtree, so the propagation option has to cover the
/// same scope: `private` applies to the TOP mount only and leaves every mount
/// already beneath the source in its peer group. That is why these say `rprivate`.
///
/// **But the per-mount option alone changed nothing, and the measurement is the
/// receipt.** With `linux.rootfsPropagation` unset, youki makes the rootfs
/// `rslave`; the container's `/` reported `master:1`, and every mount created
/// beneath an rslave tree inherited slave-ness — so the closure rbind came back
/// `master:1` EVEN WITH `rprivate` among its own options. A per-mount propagation
/// flag cannot override the propagation of the tree the mount is created in. The
/// lever that works is the tree-level one on [`build_spec`]'s `Linux`, and both are
/// kept: the tree is private, and `rprivate` keeps each rbind private across its
/// recursive copy. `crates/worker/tests/oci_bundle_live.rs` reads the absence of
/// every propagation tag out of the guest's own mountinfo, so neither half rests on
/// this argument.
///
/// # Errors
/// [`KataError::Validation`] if `oci-spec` refuses a `Mount` this function
/// assembles — which would mean the crate's required-field set moved, and is
/// reported rather than panicked on.
fn bundle_mounts(
    environment: &NixEnvironmentManifest,
    mounts: &BundleMounts,
    (work_source, out_source): (&str, &str),
) -> KataResult<Vec<Mount>> {
    let mount =
        |destination: &str, typ: &str, source: &str, options: &[&str]| -> KataResult<Mount> {
            MountBuilder::default()
                .destination(PathBuf::from(destination))
                .typ(typ.to_owned())
                .source(PathBuf::from(source))
                .options(options.iter().map(|o| (*o).to_owned()).collect::<Vec<_>>())
                .build()
                .map_err(|error| {
                    KataError::Validation(format!(
                        "oci bundle refused: building the {destination} mount failed: {error}"
                    ))
                })
        };

    let mut built: Vec<Mount> = Vec::with_capacity(environment.closure().len() + 7);
    for entry in environment.closure() {
        // source == destination, so a store path means the same thing inside the
        // container as it does in the manifest that authorized it. A relocated
        // store object would make every `/nix/store/...` string compiled into its
        // own binaries wrong.
        built.push(mount(
            entry.store_path.as_str(),
            "none",
            entry.store_path.as_str(),
            &["rbind", "ro", "nosuid", "nodev", "rprivate"],
        )?);
    }

    built.push(mount(
        GUEST_WORK,
        "none",
        work_source,
        &["rbind", "rw", "nosuid", "nodev", "rprivate"],
    )?);
    // `/out` also gets `noexec`, and `/work` cannot: `/out` is a RESULT directory
    // kata reads afterwards and nothing in it is ever meant to run, while a stage
    // legitimately builds and runs binaries inside its own tree.
    built.push(mount(
        GUEST_OUT,
        "none",
        out_source,
        &["rbind", "rw", "nosuid", "nodev", "noexec", "rprivate"],
    )?);
    built.push(mount(
        GUEST_TMP,
        "tmpfs",
        "tmpfs",
        &[
            "nosuid",
            "nodev",
            "mode=1777",
            &format!("size={}", mounts.tmp_bytes()),
        ],
    )?);
    // THE GIT VIEW'S PAIR, rendered exactly when `mounts` carries
    // it (`spec_for`'s agreement check has already refused either half alone).
    // `/git-history` is `ro`: the agent's commits can never touch the shipped
    // packs. `/git` is `rw` and deliberately NOT `noexec`: git executes hooks
    // out of a gitdir's `hooks/`, and a scratch repository whose hooks cannot
    // run is a repository that lies about being one.
    if let Some(layout) = mounts.git_view() {
        built.push(mount(
            GUEST_GIT_HISTORY,
            "none",
            utf8_source(&layout.history, GUEST_GIT_HISTORY)?,
            &["rbind", "ro", "nosuid", "nodev", "rprivate"],
        )?);
        built.push(mount(
            GUEST_GIT,
            "none",
            utf8_source(&layout.scratch, GUEST_GIT)?,
            &["rbind", "rw", "nosuid", "nodev", "rprivate"],
        )?);
    }
    // THE TOOL HOST'S DIRECTORY, rendered exactly when `mounts` carries it
    // (`spec_for`'s agreement check). `ro`: the guest can neither replace its
    // own init nor plant a file beside it. Deliberately NOT `noexec`: it holds
    // the init the runtime execs. A plain `bind`, because the directory holds
    // one regular file and no mount beneath it.
    if let Some(dir) = mounts.toolhost() {
        built.push(mount(
            GUEST_TOOLHOST,
            "none",
            utf8_source(dir, GUEST_TOOLHOST)?,
            &["bind", "ro", "nosuid", "nodev", "rprivate"],
        )?);
    }
    built.push(
        MountBuilder::default()
            .destination(PathBuf::from(GUEST_PROC))
            .typ("proc".to_owned())
            .source(PathBuf::from("proc"))
            .build()
            .map_err(|error| {
                KataError::Validation(format!(
                    "oci bundle refused: building the /proc mount failed: {error}"
                ))
            })?,
    );
    built.push(mount(
        GUEST_DEV,
        "tmpfs",
        "tmpfs",
        &["nosuid", "strictatime", "mode=755", DEV_TMPFS_SIZE],
    )?);
    built.push(mount(
        "/dev/pts",
        "devpts",
        "devpts",
        &[
            "nosuid",
            "noexec",
            "newinstance",
            "ptmxmode=0666",
            "mode=0620",
        ],
    )?);
    built.push(mount(
        "/dev/shm",
        "tmpfs",
        "shm",
        &["nosuid", "noexec", "nodev", "mode=1777", DEV_TMPFS_SIZE],
    )?);
    Ok(built)
}

/// The namespaces this route unshares.
///
/// Six always, plus `network` for [`NetPolicy::Offline`]. No `time`: a container
/// with its own clock offset would make a stage's timestamps disagree with the
/// host's for no benefit kata has asked for.
///
/// # Errors
/// [`KataError::Validation`] if `oci-spec` refuses a `LinuxNamespace`.
fn namespaces() -> KataResult<Vec<LinuxNamespace>> {
    [
        LinuxNamespaceType::User,
        LinuxNamespaceType::Pid,
        LinuxNamespaceType::Mount,
        LinuxNamespaceType::Uts,
        LinuxNamespaceType::Ipc,
        LinuxNamespaceType::Cgroup,
        // OFFLINE is this namespace with nothing in it. `linux.network` is
        // deliberately absent and so is any interface: the namespace has a loopback
        // DEVICE and no route off the box, and adding an interface would be the
        // egress arm an OFFLINE capsule does not have.
        //
        // MEASURED, because "has a loopback device" reads as "has working
        // loopback" and it is not: the PINNED youki leaves `lo` at `qdisc noop`, DOWN
        // and with no address, so a loopback TCP connect inside the guest FAILS. (The
        // same bundle under `crun` has `lo` up, so this is a runtime behaviour and
        // not a property of an empty namespace.) That is the fact
        // `crate::egress_proxy`'s guest-side mechanism turns on: for an `Egress`
        // capsule a `createContainer` hook raises `lo` INSIDE this new namespace,
        // so the namespace is never joined by `path` (the note just below) and a
        // capsule that declares no egress keeps `lo` down.
        LinuxNamespaceType::Network,
    ]
    .into_iter()
    .map(|typ| {
        LinuxNamespaceBuilder::default()
            .typ(typ)
            // No `path`: kata asks for a NEW namespace of each type. A `path`
            // would JOIN an existing one, which is the opposite request.
            .build()
            .map_err(|error| {
                KataError::Validation(format!(
                    "oci bundle refused: building the {typ:?} namespace failed: {error}"
                ))
            })
    })
    .collect()
}

/// Translate one `SCMP_ARCH_*` token into `oci-spec`'s enum.
///
/// # Refused set
///
/// Exactly the tokens `kata_types::sandbox_seccomp`'s producer does not emit.
/// Total over the two it does, and a refusal rather than a default for anything
/// else: a fence rendered for the wrong architecture applies to no syscall the
/// stage issues and is indistinguishable from no fence.
fn arch_for(token: &str) -> KataResult<Arch> {
    match token {
        "SCMP_ARCH_X86_64" => Ok(Arch::ScmpArchX86_64),
        "SCMP_ARCH_X32" => Ok(Arch::ScmpArchX32),
        other => Err(KataError::Validation(format!(
            "oci bundle refused: kata's seccomp producer named architecture {other:?}, which this \
             renderer has no `oci_spec::runtime::Arch` for. A fence rendered for the wrong \
             architecture matches nothing the stage issues and is indistinguishable from no fence"
        ))),
    }
}

/// Assemble the whole spec. One function, so the field set a reader has to check
/// against the OCI spec is in one place.
fn build_spec(
    environment: &NixEnvironmentManifest,
    mounts: &BundleMounts,
    sources: (&str, &str),
    containment: &AttemptContainment,
    argv: &[smol_str::SmolStr],
    declared_env: &[String],
    egress: Option<(&EgressHookInputs, &EgressPlumbing)>,
    host_user: u32,
    host_group: u32,
    memory_bytes: u64,
    process_count: u32,
) -> KataResult<Spec> {
    let build = |what: &str, error: oci_spec::OciSpecError| {
        KataError::Validation(format!(
            "oci bundle refused: building {what} failed: {error}"
        ))
    };

    // The SINGLE rootless mapping: container 0 is this process's own uid, and
    // nothing else is mapped. `size 1` is what makes `newuidmap`/`newgidmap`
    // unnecessary — a single-id mapping is the one an unprivileged process may
    // write to its own `/proc/self/uid_map`. A wider range would need a setuid
    // helper and a `/etc/subuid` grant, i.e. a host fact kata would have to
    // inherit and cannot refuse the absence of.
    let uid_mapping = LinuxIdMappingBuilder::default()
        .container_id(0_u32)
        .host_id(host_user)
        .size(1_u32)
        .build()
        .map_err(|e| build("the uid mapping", e))?;
    let gid_mapping = LinuxIdMappingBuilder::default()
        .container_id(0_u32)
        .host_id(host_group)
        .size(1_u32)
        .build()
        .map_err(|e| build("the gid mapping", e))?;

    let rules = oci_seccomp_rules().map_err(|refusal| {
        KataError::Validation(format!(
            "oci bundle refused: kata's syscall fence has no OCI form on this build, so the \
             bundle would either carry no fence or carry a different one: {refusal}"
        ))
    })?;
    let mut architectures = Vec::with_capacity(rules.architectures.len());
    for token in &rules.architectures {
        architectures.push(arch_for(token)?);
    }
    let mut syscalls = Vec::with_capacity(rules.syscalls.len());
    for rule in &rules.syscalls {
        let mut builder = LinuxSyscallBuilder::default()
            .names(
                rule.names
                    .iter()
                    .map(|name| (*name).to_owned())
                    .collect::<Vec<_>>(),
            )
            .action(seccomp_action(rule.action));
        if let Some(errno) = rule.errno_ret {
            builder = builder.errno_ret(errno);
        }
        if !rule.args.is_empty() {
            let mut conditions = Vec::with_capacity(rule.args.len());
            for arg in &rule.args {
                conditions
                    .push(seccomp_arg(*arg).map_err(|e| build("a seccomp rule's argument", e))?);
            }
            builder = builder.args(conditions);
        }
        syscalls.push(builder.build().map_err(|e| build("a seccomp rule", e))?);
    }
    let seccomp = LinuxSeccompBuilder::default()
        .default_action(seccomp_action(rules.default_action))
        .architectures(architectures)
        .syscalls(syscalls)
        .build()
        .map_err(|e| build("the seccomp fence", e))?;

    let resources = LinuxResourcesBuilder::default()
        .memory(
            LinuxMemoryBuilder::default()
                .limit(i64::try_from(memory_bytes).map_err(|_| {
                    KataError::Validation(format!(
                        "oci bundle refused: memory budget {memory_bytes} bytes does not fit the \
                         OCI spec's signed `memory.limit`"
                    ))
                })?)
                // swap == limit is how cgroup v2 says NO SWAP: `memory.swap.max`
                // is derived as `swap - limit` by the runtime, so an equal pair is
                // zero swap. Leaving it unset would let a stage over its memory
                // bound keep running out of the host's swap instead of being
                // killed, and the bound would then be a latency property rather
                // than a bound.
                .swap(i64::try_from(memory_bytes).map_err(|_| {
                    KataError::Validation(format!(
                        "oci bundle refused: memory budget {memory_bytes} bytes does not fit the \
                         OCI spec's signed `memory.swap`"
                    ))
                })?)
                .build()
                .map_err(|e| build("the memory bound", e))?,
        )
        .pids(
            LinuxPidsBuilder::default()
                .limit(i64::from(process_count))
                .build()
                .map_err(|e| build("the pids bound", e))?,
        )
        // NO `cpu`. The capsule has no CPU field, and a bound derived from
        // anything else would be kata inventing one — `CapsuleBudgets`'
        // exhaustive destructure above is what keeps that visible the day a CPU
        // field is added.
        .build()
        .map_err(|e| build("the resource bounds", e))?;

    let linux = LinuxBuilder::default()
        .namespaces(namespaces()?)
        // THE PLACEMENT. Absolute, and that is the one spelling youki 0.7.0
        // honours as a path: MEASURED, a relative `cgroupsPath` is routed to its
        // systemd manager and refused as malformed, and a `slice:prefix:name`
        // triple lands the container under `user@<uid>.service/<slice>` — outside
        // the subtree kata sweeps. `crate::oci_cgroup` carries the five rows.
        .cgroups_path(containment.cgroups_path())
        .uid_mappings(vec![uid_mapping])
        .gid_mappings(vec![gid_mapping])
        .resources(resources)
        .seccomp(seccomp)
        // TREE-LEVEL propagation, and it is the half that actually detaches the
        // container. Unset, youki makes the rootfs `rslave` and every mount created
        // beneath it inherits slave-ness, so the closure rbind reported `master:1`
        // even carrying `rprivate` itself — see [`bundle_mounts`] for the
        // measurement.
        //
        // `"private"` and not `"rprivate"`: youki 0.7.0 REFUSES the recursive
        // spelling here by name — `UnknownRootfsPropagation("rprivate")`, observed,
        // exit 255, no container — and applies `"private"` recursively to the whole
        // rootfs, which the guest's own mountinfo confirms by reporting no
        // propagation tag on `/` or on any planned mount. The two spellings are
        // therefore not interchangeable on this field even though they are on a
        // mount's `options`, and the OCI spec's own wording ("MUST be one of
        // `shared`, `slave`, `private`, `unbindable`") is why: the recursive forms
        // are a mount-option vocabulary, not this field's.
        .rootfs_propagation("private".to_owned())
        .masked_paths(
            MASKED_PATHS
                .iter()
                .map(|p| (*p).to_owned())
                .collect::<Vec<_>>(),
        )
        .readonly_paths(
            READONLY_PATHS
                .iter()
                .map(|p| (*p).to_owned())
                .collect::<Vec<_>>(),
        )
        .build()
        .map_err(|e| build("the linux section", e))?;

    // EVERY capability set EMPTY, all five of them. `bounding` empty is the one
    // that matters: it is the ceiling a process can never raise, so an empty
    // bounding set means no `execve` in this container can gain a capability even
    // if a file carried one. The other four are emptied too rather than left
    // unset, because an unset set is "whatever the runtime defaults to" and runc's
    // default is a non-empty list.
    let capabilities = LinuxCapabilitiesBuilder::default()
        .bounding(Capabilities::default())
        .effective(Capabilities::default())
        .inheritable(Capabilities::default())
        .permitted(Capabilities::default())
        .ambient(Capabilities::default())
        .build()
        .map_err(|e| build("the capability sets", e))?;

    let mut path = environment
        .path_prepend()
        .iter()
        .map(GuestPath::as_str)
        .collect::<Vec<_>>()
        .join(":");
    // `/bin` last, matching the throwaway bundle the certification runs. It
    // is NOT a mount on this route, and an absent directory on `PATH` is inert
    // rather than an error — it stays because a guest shell probes it and finding
    // nothing there is the honest answer, whereas removing it would make this
    // route's `PATH` differ from every other for no mechanism.
    path.push_str(":/bin");

    let process = ProcessBuilder::default()
        .args(
            argv.iter()
                .map(std::string::ToString::to_string)
                .collect::<Vec<_>>(),
        )
        .env({
            let mut env = vec![format!("PATH={path}")];
            // AFTER `PATH` and in `EgressPlumbing`'s own order, so the rendered
            // sequence is a pure function of the plan. `None` appends nothing, which
            // is what makes the no-egress bytes identical to the committed golden.
            if let Some(plumbing) = mounts.egress() {
                env.extend(plumbing.guest_env());
            }
            // THE DECLARED ENV — kata's `HOME=/tmp`, then `AgentTurnSpec.env` in
            // `BTreeMap` order, after the proxy pair: the node's own non-secret
            // variables (`TERM`, the CA-bundle paths). Empty on a Command capsule —
            // `spec_for` derives the list from the capsule's own arm.
            env.extend(declared_env.iter().cloned());
            env
        })
        .cwd(PathBuf::from(GUEST_WORK))
        // No terminal: nothing on this route is interactive, and a container with
        // `terminal: true` waits for a console socket the runtime's caller must
        // supply.
        .terminal(false)
        .user(
            UserBuilder::default()
                .uid(0_u32)
                .gid(0_u32)
                .build()
                .map_err(|e| build("the process user", e))?,
        )
        .capabilities(capabilities)
        .rlimits(vec![
            PosixRlimitBuilder::default()
                .typ(PosixRlimitType::RlimitNofile)
                .hard(NOFILE_LIMIT)
                .soft(NOFILE_LIMIT)
                .build()
                .map_err(|e| build("the NOFILE rlimit", e))?,
        ])
        .no_new_privileges(true)
        .build()
        .map_err(|e| build("the process section", e))?;

    // THE HOOKS, rendered only when the capsule declared `Egress`: two
    // `createContainer` entries — `loopback-up` then `hand-listener`, in that
    // order, because the listener cannot bind a loopback that is still down.
    // They run INSIDE the container's network namespace as the runtime's child
    // (measured): the first raises `lo`, the second binds
    // `127.0.0.1:<port>` there and passes the LISTENING descriptor to the
    // worker over `SCM_RIGHTS` on the host-side handoff socket — and waits for
    // the worker's ack, so a create cannot complete while the accept queue
    // belongs to a process about to die. An Offline capsule's spec carries no
    // `hooks` object at all, which is what keeps its bytes identical to the
    // committed golden.
    let hooks = egress
        .map(|(inputs, plumbing)| egress_hooks(inputs, plumbing))
        .transpose()?;
    let spec_builder = SpecBuilder::default()
        // oci-spec's own version constant, so the spec kata claims compliance with
        // is the one whose types it used. On oci-spec 0.8.4 that renders
        // `"ociVersion": "1.0.2"` — NOT the 1.2.1 runc 1.3.6 generates, and not a
        // ceiling on the runtime: the certification already requires
        // youki to report an OCI spec version at or above 1.0, and a 1.2 runtime
        // reading a 1.0.2 bundle is exactly the forward compatibility the spec's
        // own semver clause promises. It moves when the dependency moves, which is
        // the one way it should.
        .version(VERSION.to_owned())
        .root(
            RootBuilder::default()
                .path(PathBuf::from(ROOTFS_DIRECTORY))
                // The rootfs itself is READ-ONLY and holds only empty mount
                // points, so the only writable bytes in the container are the ones
                // a mount named above put there.
                .readonly(true)
                .build()
                .map_err(|e| build("the root section", e))?,
        )
        .mounts(bundle_mounts(environment, mounts, sources)?)
        .process(process)
        .hostname(GUEST_HOSTNAME.to_owned())
        .linux(linux);
    let spec_builder = match hooks {
        Some(hooks) => spec_builder.hooks(hooks),
        None => spec_builder,
    };
    spec_builder.build().map_err(|e| build("the spec", e))
}

/// The `createContainer` pair an `Egress` capsule's spec carries — the only
/// hooks kata renders, on the only phase that runs inside the guest's network
/// namespace with the host's mount namespace still visible (measured: the
/// hook resolves host-rootfs paths and holds the runtime's own capabilities).
///
/// `args[0]` is the program path — the OCI hook argv convention — so every
/// `createContainer` entry's argv leads with the pinned binary, and the two
/// subcommands are `kata-oci-hook`'s whole interface. No `env`: the hook's
/// whole input is its argv, and anything ambient the runtime would have
/// passed stays ambient rather than becoming a channel.
fn egress_hooks(inputs: &EgressHookInputs, plumbing: &EgressPlumbing) -> KataResult<Hooks> {
    let build = |error: oci_spec::OciSpecError| {
        KataError::Validation(format!(
            "oci bundle refused: building the createContainer hooks failed: {error}"
        ))
    };
    let hook = |args: Vec<String>| -> KataResult<Hook> {
        HookBuilder::default()
            .path(PathBuf::from(&inputs.program.store_path))
            .args(args)
            .build()
            .map_err(build)
    };
    let ip = utf8_source(inputs.ip.as_path(), "the egress hook's `ip` member")?;
    let handoff = utf8_source(plumbing.socket_path(), "the egress hook's handoff socket")?;
    HooksBuilder::default()
        .create_container(vec![
            hook(vec![
                inputs.program.store_path.clone(),
                "loopback-up".to_owned(),
                "--ip".to_owned(),
                ip.to_owned(),
            ])?,
            hook(vec![
                inputs.program.store_path.clone(),
                "hand-listener".to_owned(),
                "--port".to_owned(),
                plumbing.guest_port().to_string(),
                "--to".to_owned(),
                handoff.to_owned(),
            ])?,
        ])
        .build()
        .map_err(build)
}

/// One neutral action into `oci-spec`'s enum. Total, because
/// [`OciSeccompAction`]'s three variants are exactly the three the OCI spec has.
const fn seccomp_action(action: OciSeccompAction) -> LinuxSeccompAction {
    match action {
        OciSeccompAction::Allow => LinuxSeccompAction::ScmpActAllow,
        OciSeccompAction::Errno => LinuxSeccompAction::ScmpActErrno,
        OciSeccompAction::KillProcess => LinuxSeccompAction::ScmpActKillProcess,
    }
}

/// One neutral flags condition into `oci-spec`'s argument: `SCMP_CMP_MASKED_EQ`
/// with `value` and `valueTwo` both the flags, which reads the same whichever of
/// the two a runtime takes for the mask (see [`OciFlagsSetArg`]).
fn seccomp_arg(arg: OciFlagsSetArg) -> Result<LinuxSeccompArg, oci_spec::OciSpecError> {
    LinuxSeccompArgBuilder::default()
        .index(usize::from(arg.index))
        .value(arg.flags)
        .value_two(arg.flags)
        .op(LinuxSeccompOperator::ScmpCmpMaskedEq)
        .build()
}

/// Write `plan`'s bundle into `bundle`: the `config.json` bytes verbatim and the
/// rootfs mount points the plan names.
///
/// `#[doc(hidden)] pub` and NOT a production path: `bin/kata-provider-youki` is
/// the process whose job this is in production. It lives here rather than in a
/// test because the bytes must land
/// UNCHANGED — a test that re-serialized the plan would be running a container
/// built from its own JSON, and the golden would then be measuring nothing.
///
/// # Errors
/// [`KataError::Validation`] naming the path that could not be created or written,
/// and a `rootfs_mountpoints` entry that is not an absolute guest path.
#[doc(hidden)]
pub fn materialize_bundle(plan: &OciBundlePlan, bundle: &Path) -> KataResult<()> {
    let fail = |what: &str, error: std::io::Error| {
        KataError::Validation(format!("oci bundle: {what} failed: {error}"))
    };
    let rootfs = bundle.join(ROOTFS_DIRECTORY);
    std::fs::create_dir_all(&rootfs).map_err(|e| fail("creating the rootfs", e))?;
    for point in &plan.rootfs_mountpoints {
        let relative = point.strip_prefix('/').ok_or_else(|| {
            KataError::Validation(format!(
                "oci bundle: rootfs mount point {point:?} is not absolute, so it names no \
                 directory inside the rootfs"
            ))
        })?;
        std::fs::create_dir_all(rootfs.join(relative))
            .map_err(|e| fail(&format!("creating the mount point {point}"), e))?;
    }
    std::fs::write(bundle.join("config.json"), plan.config_json.as_bytes())
        .map_err(|e| fail("writing config.json", e))
}
