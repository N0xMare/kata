//! CERTIFY the rootless-OCI runtime, or refuse it BY NAME.
//!
//! # What this module proves, and what it deliberately does not
//!
//! It proves that THIS host can deliver the rootless-OCI prerequisite the
//! `oci` execution profile requires: the pinned youki bytes are at the pinned
//! path, that binary reports a version at or above the pin, an OCI spec
//! version at or above 1.0 and a libseccomp it was BUILT AGAINST, the
//! exact-path AppArmor profile that lets it unshare
//! a user namespace is installed and byte-identical to the render, the kernel's
//! `apparmor_restrict_unprivileged_userns` state is READ rather than assumed,
//! cgroup v2 delegation offers memory and pids where a stage cgroup would go,
//! and — the only arm no read can substitute for — a throwaway rootless bundle
//! ACTUALLY RUNS.
//!
//! It proves nothing about executing a kata stage. No `config.json` is generated
//! from a capsule, no closure is bound and no bounds are applied here — that is
//! [`crate::oci_driver`]'s job. This module is certification plus refusal; the
//! bundle it runs holds a static `/bin/true` and nothing else.
//!
//! # The shape: which binary, proven to be which version, with which bytes
//!
//! Enforce a floor, content-address, pin, and re-verify per use
//! ([`verify_pinned_youki_unchanged`] exists because a digest that is computed
//! and never compared is recorded substrate that enforces nothing). Two
//! properties follow from youki's pin being an operator-managed Nix store path
//! rather than a `$PATH` search:
//!
//! * There is NO resolution step and no `$PATH` fallback. The pin names one
//!   exact executable, because the AppArmor profile attaches to one exact path;
//!   a youki found anywhere else proves nothing about the pinned one. So a
//!   binary at some other path is not a degraded certification, it is
//!   [`OciPrerequisiteRefusal::BinaryAbsent`] for the path that matters.
//! * The digest is **sha256**, not blake3. `config/youki-pin.toml` states what
//!   `sha256sum` prints, and three other surfaces compare that exact string
//!   (`kata host apparmor-install`, `scripts/feasibility-probes.py`,
//!   `kata doctor`). A second algorithm here would produce a value none of them
//!   could check.
//!
//! # Every refusal is a NAMED variant, and the fold is pure
//!
//! [`OciPrerequisiteRefusal`] has one variant per check, so a caller branches on
//! the enum instead of string-matching a diagnostic — a diagnostic is a proxy
//! for the fact, and a proxy can be satisfied without it. The classification
//! functions ([`fold_digest`], [`fold_versions`], [`fold_loaded_profile`],
//! [`fold_installed_profile`] and the [`fold_apparmor_prerequisite`] composing
//! them, [`fold_userns_restriction`], [`fold_delegation`])
//! are pure and total, so every arm INCLUDING the ones this host cannot produce
//! on demand is reachable from a unit table. Only [`certify_youki`] touches the
//! host.
//!
//! # The AppArmor claim is two different claims, and they are kept apart
//!
//! The kernel's `/sys/kernel/security/apparmor/profiles` lists profile NAMES,
//! not attachment paths, and on a hardened host it needs `CAP_MAC_ADMIN` to
//! read at all — it is unreadable for an ordinary user on the reference host.
//! So:
//!
//! * the loaded-profile axis answers the NAME question only, and an unreadable
//!   list is [`ApparmorProfile::Unknown`] — never folded to loaded, and never a
//!   refusal, because refusing it would make this certification require root;
//! * the NAME-TO-PATH binding is proven separately and exactly, by comparing
//!   `/etc/apparmor.d/<profile_name>` byte for byte against
//!   [`render_apparmor_profile`]. A file that is absent, unreadable or different
//!   IS a refusal: that text is the only place the pinned path is bound to the
//!   profile name, so without it nothing establishes that the loaded profile (or
//!   the profile a reload would load) covers the pinned binary.
//!
//! A profile that is loaded under the pinned name but whose installed text names
//! a DIFFERENT path is therefore refused, which is the whole point of the byte
//! comparison.
//!
//! # The seccomp arm reads `youki --version`, NOT `youki features`
//!
//! A youki built without libseccomp silently drops `linux.seccomp` (measured):
//! `libcontainer`'s init gates every seccomp call behind
//! `#[cfg(feature = "libseccomp")]` and the `cfg(not(...))` arm only
//! `tracing::warn!`s, so a bundle carrying every deny-list entry ran with
//! `Seccomp_filters: 0` and no refusal. [`fold_seccomp_support`] is what turns
//! that from a silent hole into a named refusal.
//!
//! The obvious channel would be `youki features`, whose OCI-features document has
//! a `linux.seccomp` object. It cannot be used: youki 0.7.0's
//! `crates/youki/src/commands/features.rs` carries a literal
//! `// TODO: Expose seccomp support information` and never populates that field,
//! so it reports `"seccomp": null` on a libseccomp build and a non-libseccomp
//! build ALIKE (both measured on the reference host). A check reading it would
//! refuse every youki that exists — a guarantee wider than its mechanism in the
//! other direction.
//!
//! What DOES move with the build is `youki --version`'s `libseccomp: <version>`
//! line: `crates/youki/src/commands/info.rs::print_youki` prints it under
//! `#[cfg(feature = "seccomp")]`, from a `LIBSECCOMP_VERSION` the crate's
//! `build.rs` emits by `pkg_config::probe_library("libseccomp")` — which it only
//! does when `CARGO_FEATURE_SECCOMP` is set. Its presence is therefore a witness
//! of the very `cfg` that gates the enforcement, and it costs no extra exec: it
//! is folded out of the output [`fold_versions`] already reads.
//!
//! It is a witness of the BUILD, not an observation of a filter being installed
//! in a container. That observation is `oci_runtime_live.rs`'s
//! `the_stage_fence_reaches_the_container_live`, which reads
//! `/proc/self/status`' `Seccomp_filters` from inside one.

use std::{
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::mpsc,
    time::Duration,
};

use kata_types::youki_pin::YoukiPin;

use crate::sandbox_bounds::{CgroupController, CgroupDelegation};

/// The OCI Runtime Specification version floor the adapter needs.
///
/// A REFUSAL rather than a degradation: pre-1.0 drafts differ in field semantics
/// the generated `config.json` will depend on, so an unchecked older runtime would
/// honour a spec that is not the one kata wrote.
pub const YOUKI_SPEC_MIN_VERSION: (u64, u64) = (1, 0);

/// A parsed `(major, minor, patch)`. An alias rather than a newtype: every
/// producer and consumer here is a comparison against a floor, which is exactly
/// what a tuple's derived `Ord` already is.
pub type SemanticVersion = (u64, u64, u64);

/// Where the kernel lists LOADED AppArmor profiles, by NAME.
pub const APPARMOR_LOADED_PROFILES: &str = "/sys/kernel/security/apparmor/profiles";

/// Where an installed profile lives. `<dir>/<profile_name>` is what
/// `kata host apparmor-install` writes.
pub const APPARMOR_PROFILE_DIRECTORY: &str = "/etc/apparmor.d";

/// The knob deciding whether an UNPROFILED binary may unshare a user namespace.
pub const USERNS_RESTRICTION_KNOB: &str = "/proc/sys/kernel/apparmor_restrict_unprivileged_userns";

/// How long the functional arm gives one `/bin/true` container.
///
/// The same 30 s `probe_youki` uses, so the two observations of one fact cannot
/// disagree about whether a slow host is a failing host.
pub const FUNCTIONAL_TIMEOUT: Duration = Duration::from_secs(30);

/// A command for the pinned runtime with an EMPTY environment — every `youki` the
/// worker spawns (`--version`, `spec`, `delete`, and the interactive capsule's `state`
/// and `kill`) is built here.
///
/// youki reads nothing it needs from its environment: the pin is an absolute path, the
/// state root rides `--root`, the cgroup is the bundle's absolute `linux.cgroupsPath`
/// (the cgroupfs manager, no bus), the user namespace maps one id (no `newuidmap`
/// lookup), and the container's own environment is the bundle's `process.env`. The
/// worker's environment holds what must stay in the worker — an `env:` credential
/// above all — so none of it is passed. The one runtime spawn not built here is the
/// certification's `run` under `systemd-run` ([`run_bundle`]), which passes exactly
/// [`SYSTEMD_RUN_ENV`].
#[must_use]
pub(crate) fn runtime_command(store_path: impl AsRef<std::ffi::OsStr>) -> Command {
    let mut command = Command::new(store_path);
    command.env_clear();
    command
}

/// The variables the certification's `systemd-run --user --scope` keeps from the
/// worker's environment, and so the `youki run` it execs inherits: `PATH`, which
/// resolves `systemd-run` itself and which an `env:` credential may not name
/// (`CREDENTIAL_ENV_RESERVED`), and `XDG_RUNTIME_DIR` (`USER_MANAGER_ENV`, reserved
/// likewise), without which `systemd-run`
/// cannot reach the user manager (measured: `Failed to connect to bus: No medium
/// found`). `systemd-run` adds its own `INVOCATION_ID` (measured), never the worker's.
pub(crate) const SYSTEMD_RUN_ENV: [&str; 2] =
    ["PATH", kata_types::execution_contract::USER_MANAGER_ENV];

/// A client of the user manager — the certification's `systemd-run` and its watchdog's
/// `systemctl` — started with the worker's [`SYSTEMD_RUN_ENV`] and nothing else, so no
/// other variable the worker holds (an `env:` credential above all) reaches it.
fn user_manager_command(program: &str) -> Command {
    let mut command = Command::new(program);
    command.env_clear().envs(
        SYSTEMD_RUN_ENV
            .iter()
            .filter_map(|name| std::env::var_os(name).map(|value| (*name, value))),
    );
    command
}

/// The watchdog's `SIGKILL` of one unit, for [`spawn_with_timeout`].
fn unit_kill_command(unit: &str) -> Command {
    let mut command = user_manager_command("systemctl");
    command
        .args(["--user", "kill", "--signal=KILL", unit])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    command
}

/// The AppArmor profile text for a pin — the ONE producer.
///
/// This is what `kata host apparmor-install` writes to
/// `/etc/apparmor.d/<profile_name>` and what [`fold_installed_profile`]
/// compares the installed file against, byte for byte. `flags=(unconfined)`
/// plus `userns,` is what lets the pinned binary unshare a user namespace
/// under `kernel.apparmor_restrict_unprivileged_userns=1` while every other
/// unprofiled binary on the host still transitions into the kernel's denying
/// profile — a grant that ATTACHES by exact path, never a sysctl relaxation.
///
/// The grant does not stay at that path: an unconfined profile is inherited
/// across `execve`, so every process the pinned binary execs — the container's
/// whole process tree included — runs under it and never falls into the
/// `unprivileged_userns` profile. What refuses a nested user namespace inside a
/// capsule is kata's syscall fence, not AppArmor: the inherited floor and the
/// stage fence both answer `unshare` and `clone(CLONE_NEWUSER)` with `EPERM`
/// and `clone3` with `ENOSYS`. Measured by
/// `attack_oci_construction_residue_is_refused_by_the_kernel_live`: with the
/// fence's `clone` door re-opened, a capsule process created a nested user
/// namespace in which a capability-gated `clone(CLONE_NEWNET)` also succeeded.
///
/// Deliberately carries no generated-by comment: an exact comparison against
/// the installed file is worth more than provenance duplicated out of the
/// pin.
#[must_use]
pub fn render_apparmor_profile(pin: &YoukiPin) -> String {
    format!(
        "abi <abi/4.0>,\n\
         include <tunables/global>\n\
         \n\
         profile {name} {path} flags=(unconfined) {{\n\
         \x20 userns,\n\
         \x20 include if exists <local/{name}>\n\
         }}\n",
        name = pin.profile_name(),
        path = pin.store_path(),
    )
}

/// Whether a profile with the pinned NAME is in the kernel's loaded list.
///
/// Two variants, not three: `absent` is a refusal
/// ([`OciPrerequisiteRefusal::ProfileNotLoaded`]), so it never reaches a
/// certification, and [`Self::Unknown`] is what an unreadable list folds to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ApparmorProfile {
    /// The list was readable and names the pinned profile.
    Loaded,
    /// The list could not be read — `CAP_MAC_ADMIN` on a hardened host. NEVER
    /// treated as loaded, and never as absent: absent is a claim.
    Unknown,
}

impl ApparmorProfile {
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            ApparmorProfile::Loaded => "loaded",
            ApparmorProfile::Unknown => "unknown",
        }
    }
}

/// `kernel.apparmor_restrict_unprivileged_userns`, as READ.
///
/// Recorded, never refused on, and it does NOT relax the profile requirement:
/// with the restriction ON the installed profile is what makes rootless OCI
/// possible at all, and with it OFF the certification still requires the
/// installed profile byte-identical to the render ([`fold_apparmor_prerequisite`]
/// refuses without it on either kernel) — the profile's digest is part of the
/// measured basis a provider must restate, so a host without one has no basis to
/// certify. The functional arm is what decides whether this host actually works.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UsernsRestriction {
    /// Non-zero: an unprofiled binary transitions into `unprivileged_userns`,
    /// which denies `capability`.
    Restricted,
    /// Zero: the kernel needs no profile for the userns transition. The
    /// certification still requires the installed one (see the type's docs).
    Unrestricted,
    /// Unreadable or unparsable. Never reported as either answer.
    Unknown,
}

impl UsernsRestriction {
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            UsernsRestriction::Restricted => "restricted",
            UsernsRestriction::Unrestricted => "unrestricted",
            UsernsRestriction::Unknown => "unknown",
        }
    }
}

/// What this host delivers for the rootless-OCI prerequisite, once certified.
#[derive(Clone, Debug)]
pub struct YoukiCertification {
    /// The pinned path, verbatim. Not canonicalized: the pin already names the
    /// resolved store path AppArmor evaluates, and canonicalizing would let a
    /// symlink change which path this certification is about.
    pub store_path: PathBuf,
    /// sha256 of the bytes at [`Self::store_path`], re-derived here and equal to
    /// the pin's. [`verify_pinned_youki_unchanged`] compares it again per use.
    pub sha256: String,
    /// The binary's own reported `(major, minor, patch)`, at or above the pin's.
    pub version: (u64, u64, u64),
    /// The OCI spec version youki reports, at or above [`YOUKI_SPEC_MIN_VERSION`].
    pub spec_version: (u64, u64, u64),
    /// The libseccomp version the pinned binary REPORTED being built against,
    /// verbatim — the witness that it will honour `linux.seccomp` at all.
    ///
    /// A string rather than a `bool`, for [`Self::functional_probe_id`]'s reason:
    /// a `true` would be kata's own conclusion, and this is the value the binary
    /// printed. Never ordered and never compared against a floor — which
    /// libseccomp is new enough is a question nobody here has asked, and
    /// inventing a floor would be a check wider than its mechanism.
    pub libseccomp_version: String,
    /// The loaded-profile axis. See the module docs on why `Unknown` certifies.
    pub profile: ApparmorProfile,
    /// sha256 of the INSTALLED profile text at `/etc/apparmor.d/<name>`, taken
    /// from the bytes [`fold_installed_profile`] compared.
    ///
    /// Carried rather than re-derived from [`render_apparmor_profile`], even
    /// though certification refused unless the two were byte-identical: the
    /// certificate this feeds (`kata_provider_protocol::OciMeasuredBasis`) is a
    /// MEASUREMENT, and a value recomputed from the pin would be a claim about
    /// what the file should contain. One reader, one fact.
    pub installed_profile_sha256: String,
    /// The kernel restriction, as read.
    pub userns_restriction: UsernsRestriction,
    /// The measured cgroup v2 delegation, carrying memory and pids.
    pub delegation: CgroupDelegation,
    /// The container id of the throwaway rootless container the functional arm
    /// really RAN.
    ///
    /// The identity of the run rather than a boolean, because a boolean would be
    /// a claim: this names the container whose exit status was observed, and it is
    /// the string that was passed to [`run_throwaway_container_with`] rather than
    /// one rebuilt from the same recipe afterwards.
    pub functional_probe_id: String,
}

/// Why this host cannot deliver the rootless-OCI prerequisite.
///
/// One variant per check. A caller branches on the variant; the [`Display`] text
/// is what an operator reads.
///
/// [`Display`]: std::fmt::Display
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OciPrerequisiteRefusal {
    /// Nothing at the pinned path.
    BinaryAbsent {
        store_path: String,
        realised_by: String,
    },
    /// Something is there and could not be read to digest it.
    BinaryUnreadable { store_path: String, error: String },
    /// The pinned path holds bytes the pin does not name.
    DigestMismatch {
        store_path: String,
        pinned: String,
        observed: String,
    },
    /// `youki --version` could not be run, or exited non-zero.
    VersionUnobtainable { store_path: String, error: String },
    /// Its output carries no readable `x.y.z`.
    VersionUnreadable { reported: String },
    /// It reports a version below the pin's floor.
    VersionBelowFloor {
        have: (u64, u64, u64),
        want: (u64, u64, u64),
        reported: String,
    },
    /// Its output carries no readable `spec: x.y.z` line.
    SpecVersionUnreadable { reported: String },
    /// It implements an OCI spec below [`YOUKI_SPEC_MIN_VERSION`].
    SpecVersionBelowFloor {
        have: (u64, u64, u64),
        want: (u64, u64),
        reported: String,
    },
    /// `youki --version` carries no `libseccomp:` line with a non-empty value.
    ///
    /// # Refused set, exactly
    ///
    /// One thing: an identification with no line whose key, trimmed, is
    /// `libseccomp` and whose value, trimmed, is non-empty. Nothing else. A value
    /// of `unknown` is NOT refused — youki's `build.rs` emits it when
    /// `pkg_config::probe_library("libseccomp")` fails WITH the feature already
    /// on, so refusing it would refuse a runtime that does enforce the fence. No
    /// libseccomp version floor is applied.
    ///
    /// # What that line stands for, and what it does not
    ///
    /// Its PRESENCE is a witness of `#[cfg(feature = "seccomp")]`, which is the
    /// same `cfg` gating every seccomp call in `libcontainer`'s init — so a
    /// runtime missing it was built without `libcontainer/libseccomp` and will
    /// IGNORE `linux.seccomp` in silence, logging a warning no caller sees. It is
    /// NOT an observation that a filter was installed in a running container; see
    /// [`fold_seccomp_support`] and the module docs.
    ///
    /// `youki features` is NOT a witness and is deliberately not read: youki
    /// 0.7.0's `crates/youki/src/commands/features.rs` carries an upstream
    /// `// TODO: Expose seccomp support information` and never populates the
    /// OCI-features document's `linux.seccomp` field, so it reports `null` on a
    /// libseccomp build and a non-libseccomp build alike.
    ///
    /// # A future youki that changes the `--version` FORMAT reds certification
    ///
    /// It does not pass. This refusal is keyed on the line being THERE, so a
    /// release that renames the key, moves the value, or emits the features
    /// document instead makes `certify_youki` refuse `seccomp_unsupported` on a
    /// runtime that may well support seccomp. That direction is the intended one:
    /// the arm is re-read against the new format (and `youki features` adopted the
    /// day upstream closes its TODO) rather than a fence being reported present
    /// because a parser stopped finding the thing it checks.
    SeccompUnsupported {
        store_path: String,
        realised_by: String,
        reported: String,
    },
    /// The loaded-profile list was READABLE and holds no profile of that name.
    ProfileNotLoaded {
        profile_name: String,
        loaded_profiles: usize,
    },
    /// `/etc/apparmor.d/<profile_name>` does not exist.
    ProfileFileAbsent { path: String },
    /// It exists and could not be read.
    ProfileFileUnreadable { path: String, error: String },
    /// It exists and is not the render — so nothing binds the profile name to
    /// the pinned path.
    ProfileFileDiffers {
        path: String,
        expected: String,
        observed: String,
    },
    /// cgroup v2 delegation cannot carry a stage's memory or pids bound.
    DelegationIncomplete {
        missing: Vec<&'static str>,
        evidence: String,
    },
    /// The throwaway bundle could not be built or launched at all.
    FunctionalHarness { stage: String, error: String },
    /// `youki run` was launched and did not exit 0.
    FunctionalRunRefused {
        exit: String,
        stderr_tail: String,
        /// What the run's stderr names, read once here so the operator's note
        /// and a caller's branch (`kata host setup`'s AppArmor recourse) cannot
        /// disagree.
        denial: FunctionalDenial,
    },
}

/// What a refused functional run's stderr names.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FunctionalDenial {
    /// The stderr names AppArmor.
    AppArmorNamed,
    /// The stderr carries an EPERM — the shape an unprofiled binary takes on
    /// transitioning into the `unprivileged_userns` AppArmor profile, which
    /// denies capability.
    CapabilityDenied,
    /// Neither: nothing in the stderr reads as a denial.
    Unclassified,
}

impl FunctionalDenial {
    /// Read a refused run's stderr: `apparmor` first, then `operation not
    /// permitted` / `eperm`, case-insensitively.
    fn of(stderr: &str) -> Self {
        let lowered = stderr.to_lowercase();
        if lowered.contains("apparmor") {
            Self::AppArmorNamed
        } else if lowered.contains("operation not permitted") || lowered.contains("eperm") {
            Self::CapabilityDenied
        } else {
            Self::Unclassified
        }
    }

    /// The refusal's note, so an operator reads the most likely cause instead
    /// of only the exit code.
    #[must_use]
    pub const fn note(self) -> &'static str {
        match self {
            Self::AppArmorNamed => "; AppArmor denial named in stderr",
            Self::CapabilityDenied => {
                "; capability denial (EPERM) — consistent with an unprofiled binary \
                 transitioning into the unprivileged_userns AppArmor profile, which denies \
                 capability"
            }
            Self::Unclassified => "",
        }
    }
}

impl std::fmt::Display for OciPrerequisiteRefusal {
    #[allow(clippy::too_many_lines)]
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OciPrerequisiteRefusal::BinaryAbsent {
                store_path,
                realised_by,
            } => write!(
                f,
                "the pinned youki is absent: `{store_path}` is not a file. Realise it from \
                 the kata checkout with `{realised_by}`, then re-pin config/youki-pin.toml if \
                 the store path moved. \
                 There is no $PATH fallback: the exact-path AppArmor profile covers the pinned \
                 path only, so a youki found elsewhere proves nothing about it — and a `youki` \
                 from a plain `nixpkgs#youki` install would additionally be one built without \
                 libseccomp, which this certification refuses by name."
            ),
            OciPrerequisiteRefusal::BinaryUnreadable { store_path, error } => write!(
                f,
                "the pinned youki `{store_path}` could not be read to content-address it: {error}"
            ),
            OciPrerequisiteRefusal::DigestMismatch {
                store_path,
                pinned,
                observed,
            } => write!(
                f,
                "DIGEST MISMATCH at `{store_path}`: the pin says sha256 {pinned}, the bytes on \
                 disk are sha256 {observed}. A Nix store path is immutable, so the pin is stale \
                 or the store is damaged — refusing to treat these bytes as the pinned \
                 containment binary. Re-pin config/youki-pin.toml and re-render the profile."
            ),
            OciPrerequisiteRefusal::VersionUnobtainable { store_path, error } => write!(
                f,
                "could not identify `{store_path}`: {error}. Refusing to use an unidentifiable \
                 binary for containment."
            ),
            OciPrerequisiteRefusal::VersionUnreadable { reported } => write!(
                f,
                "could not read a version out of `youki --version` (got {reported:?}). An \
                 unreadable version is not a passing version — refusing."
            ),
            OciPrerequisiteRefusal::VersionBelowFloor {
                have,
                want,
                reported,
            } => write!(
                f,
                "the pinned youki is {have:?}, below the pinned floor {want:?} (observed: \
                 {reported:?}). This is a REFUSAL, not a degradation: config/youki-pin.toml \
                 names the version whose bytes the installed profile covers."
            ),
            OciPrerequisiteRefusal::SpecVersionUnreadable { reported } => write!(
                f,
                "`youki --version` carries no readable `spec:` line (got {reported:?}), so which \
                 OCI Runtime Specification it implements is unknown — refusing."
            ),
            OciPrerequisiteRefusal::SpecVersionBelowFloor {
                have,
                want,
                reported,
            } => write!(
                f,
                "the pinned youki implements OCI spec {have:?}, below the required {want:?} \
                 (observed: {reported:?}). A pre-1.0 draft differs in field semantics the \
                 generated config.json depends on, so the runtime would honour a spec kata did \
                 not write."
            ),
            OciPrerequisiteRefusal::SeccompUnsupported {
                store_path,
                realised_by,
                reported,
            } => write!(
                f,
                "the pinned youki `{store_path}` reports no `libseccomp:` line, so it was built \
                 without `libcontainer/libseccomp` and will DROP the `linux.seccomp` section of \
                 every bundle kata writes — silently, with a log warning the caller never sees \
                 (measured: `Seccomp_filters: 0` inside a container whose config.json carried every \
                 deny-list entry). The stage fence would be absent while every surface reported it \
                 present, so this is a REFUSAL rather than a degradation. Realise a runtime that \
                 has it, from the kata checkout, with `{realised_by}`, then re-pin \
                 config/youki-pin.toml and re-install the AppArmor profile with `sudo kata host \
                 apparmor-install`. Observed identification: {reported:?}"
            ),
            OciPrerequisiteRefusal::ProfileNotLoaded {
                profile_name,
                loaded_profiles,
            } => write!(
                f,
                "no AppArmor profile named `{profile_name}` is among the {loaded_profiles} the \
                 kernel has loaded. With the userns restriction on, an unprofiled youki \
                 transitions into the kernel's `unprivileged_userns` profile, which denies \
                 `capability`. Load it: `sudo kata host apparmor-install`."
            ),
            OciPrerequisiteRefusal::ProfileFileAbsent { path } => write!(
                f,
                "`{path}` does not exist, so nothing binds the profile NAME to the pinned \
                 executable's path — the kernel's loaded list is keyed by name alone. Install it \
                 with `sudo kata host apparmor-install`."
            ),
            OciPrerequisiteRefusal::ProfileFileUnreadable { path, error } => write!(
                f,
                "`{path}` could not be read ({error}), so the name-to-path binding cannot be \
                 checked and is not assumed."
            ),
            OciPrerequisiteRefusal::ProfileFileDiffers {
                path,
                expected,
                observed,
            } => write!(
                f,
                "`{path}` is not the profile this pin renders, so the loaded profile of that \
                 name may attach to a different executable. Expected:\n{expected}\nfound:\n\
                 {observed}\nRe-render and reload with `sudo kata host apparmor-install`."
            ),
            OciPrerequisiteRefusal::DelegationIncomplete { missing, evidence } => write!(
                f,
                "cgroup v2 delegation cannot carry a stage bound: controller(s) {missing} are \
                 not usable where a stage cgroup would be created. Observed: {evidence}",
                missing = missing.join(", "),
            ),
            OciPrerequisiteRefusal::FunctionalHarness { stage, error } => write!(
                f,
                "the throwaway rootless bundle could not be prepared ({stage}): {error}. No \
                 container was started, so this host's rootless-OCI capability is UNPROVEN — \
                 never assumed."
            ),
            OciPrerequisiteRefusal::FunctionalRunRefused {
                exit,
                stderr_tail,
                denial,
            } => write!(
                f,
                "the pinned youki ran and REFUSED a rootless `/bin/true` container: exit \
                 {exit}{note}. stderr tail: {stderr_tail}",
                note = denial.note()
            ),
        }
    }
}

impl OciPrerequisiteRefusal {
    /// A stable token per variant, for a report that groups refusals without
    /// matching on prose.
    #[must_use]
    pub fn token(&self) -> &'static str {
        match self {
            OciPrerequisiteRefusal::BinaryAbsent { .. } => "binary_absent",
            OciPrerequisiteRefusal::BinaryUnreadable { .. } => "binary_unreadable",
            OciPrerequisiteRefusal::DigestMismatch { .. } => "digest_mismatch",
            OciPrerequisiteRefusal::VersionUnobtainable { .. } => "version_unobtainable",
            OciPrerequisiteRefusal::VersionUnreadable { .. } => "version_unreadable",
            OciPrerequisiteRefusal::VersionBelowFloor { .. } => "version_below_floor",
            OciPrerequisiteRefusal::SpecVersionUnreadable { .. } => "spec_version_unreadable",
            OciPrerequisiteRefusal::SpecVersionBelowFloor { .. } => "spec_version_below_floor",
            OciPrerequisiteRefusal::SeccompUnsupported { .. } => "seccomp_unsupported",
            OciPrerequisiteRefusal::ProfileNotLoaded { .. } => "profile_not_loaded",
            OciPrerequisiteRefusal::ProfileFileAbsent { .. } => "profile_file_absent",
            OciPrerequisiteRefusal::ProfileFileUnreadable { .. } => "profile_file_unreadable",
            OciPrerequisiteRefusal::ProfileFileDiffers { .. } => "profile_file_differs",
            OciPrerequisiteRefusal::DelegationIncomplete { .. } => "delegation_incomplete",
            OciPrerequisiteRefusal::FunctionalHarness { .. } => "functional_harness",
            OciPrerequisiteRefusal::FunctionalRunRefused { .. } => "functional_run_refused",
        }
    }
}

// ---------------------------------------------------------------------------
// The PURE folds. Every arm is reachable from a table, including the ones this
// host cannot produce on demand.
// ---------------------------------------------------------------------------

/// sha256-hex of `bytes`.
#[must_use]
pub fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::Digest as _;
    hex::encode(sha2::Sha256::digest(bytes))
}

/// Compare an OBSERVED digest with the pin's.
pub fn fold_digest(pin: &YoukiPin, observed: &str) -> Result<String, OciPrerequisiteRefusal> {
    if observed == pin.sha256() {
        return Ok(observed.to_string());
    }
    Err(OciPrerequisiteRefusal::DigestMismatch {
        store_path: pin.store_path().to_string(),
        pinned: pin.sha256().to_string(),
        observed: observed.to_string(),
    })
}

/// Parse the first `x.y.z` out of `token`.
fn dotted_triple(token: &str) -> Option<SemanticVersion> {
    let mut parts = token.split('.');
    let major = parts.next()?.parse().ok()?;
    let minor = parts.next()?.parse().ok()?;
    let patch = parts
        .next()?
        .split(|c: char| !c.is_ascii_digit())
        .next()?
        .parse()
        .ok()?;
    Some((major, minor, patch))
}

/// Fold `youki --version`'s whole output into `(version, spec_version)`.
///
/// youki prints four lines: `youki version: 0.7.0`, `commit: …`, `spec: 1.1.0`,
/// `rustc: …`. The spec line is read by its OWN key rather than positionally —
/// the `commit:` line on the reference build is literally `0.7.0-VERGEN…`, so a
/// positional reader would happily certify the commit string as a spec version.
pub fn fold_versions(
    pin: &YoukiPin,
    reported: &str,
) -> Result<(SemanticVersion, SemanticVersion), OciPrerequisiteRefusal> {
    let line_value = |key: &str| {
        reported.lines().find_map(|line| {
            line.split_once(':')
                .filter(|(name, _)| name.trim() == key)
                .and_then(|(_, value)| dotted_triple(value.trim()))
        })
    };

    let Some(version) = line_value("youki version") else {
        return Err(OciPrerequisiteRefusal::VersionUnreadable {
            reported: reported.to_string(),
        });
    };
    if version < pin.version_tuple() {
        return Err(OciPrerequisiteRefusal::VersionBelowFloor {
            have: version,
            want: pin.version_tuple(),
            reported: reported.to_string(),
        });
    }
    let Some(spec) = line_value("spec") else {
        return Err(OciPrerequisiteRefusal::SpecVersionUnreadable {
            reported: reported.to_string(),
        });
    };
    if (spec.0, spec.1) < YOUKI_SPEC_MIN_VERSION {
        return Err(OciPrerequisiteRefusal::SpecVersionBelowFloor {
            have: spec,
            want: YOUKI_SPEC_MIN_VERSION,
            reported: reported.to_string(),
        });
    }
    Ok((version, spec))
}

/// Fold `youki --version`'s output for the SECCOMP-SUPPORT witness, returning
/// the libseccomp version the binary reported being built against.
///
/// # Refused set
///
/// Exactly one thing: an identification with no `libseccomp:` line whose value is
/// non-empty after trimming. That is [`OciPrerequisiteRefusal::SeccompUnsupported`],
/// and it is the whole refusal — this says nothing about WHICH libseccomp (see
/// [`YoukiCertification::libseccomp_version`] on why no floor is applied), and
/// nothing about whether a filter is actually installed in a running container.
///
/// # Why the line's PRESENCE is the mechanism
///
/// `crates/youki/src/commands/info.rs::print_youki` — the function
/// `youki --version` calls — prints the line under `#[cfg(feature = "seccomp")]`,
/// and that is the same `seccomp` feature whose only effect is to turn on
/// `libcontainer/libseccomp`, which is the `cfg` gating every seccomp call in
/// `libcontainer`'s init. So the line is present if and only if the code that
/// would honour `linux.seccomp` was compiled in. See the module docs on why
/// `youki features` cannot serve here.
///
/// A value of `unknown` is ACCEPTED, and deliberately: youki's `build.rs` emits
/// that when `pkg_config::probe_library("libseccomp")` fails, which it can only
/// reach with the feature already on. Refusing it would refuse a runtime that
/// does enforce the fence, over a fact about its build's pkg-config.
///
/// The FIRST `libseccomp:` line with a non-empty value wins, and youki prints
/// exactly one — a second would mean this is not the identification the arm is
/// about, and preferring a later line would be a guess about which of two
/// answers is the runtime's.
pub fn fold_seccomp_support(
    pin: &YoukiPin,
    reported: &str,
) -> Result<String, OciPrerequisiteRefusal> {
    let value = reported.lines().find_map(|line| {
        line.split_once(':')
            .filter(|(name, _)| name.trim() == "libseccomp")
            .map(|(_, value)| value.trim())
            .filter(|value| !value.is_empty())
    });
    match value {
        Some(version) => Ok(version.to_string()),
        None => Err(OciPrerequisiteRefusal::SeccompUnsupported {
            store_path: pin.store_path().to_string(),
            realised_by: pin.realised_by().to_string(),
            reported: reported.to_string(),
        }),
    }
}

/// Fold a read of the kernel's loaded-profile list.
///
/// `Err` from the read means UNREADABLE, which is [`ApparmorProfile::Unknown`].
/// A readable list without the name is a REFUSAL.
pub fn fold_loaded_profile(
    pin: &YoukiPin,
    list: Result<&str, String>,
) -> Result<ApparmorProfile, OciPrerequisiteRefusal> {
    let Ok(text) = list else {
        return Ok(ApparmorProfile::Unknown);
    };
    if text
        .lines()
        .any(|line| line.split_whitespace().next() == Some(pin.profile_name()))
    {
        return Ok(ApparmorProfile::Loaded);
    }
    Err(OciPrerequisiteRefusal::ProfileNotLoaded {
        profile_name: pin.profile_name().to_string(),
        loaded_profiles: text.lines().count(),
    })
}

/// How an attempt to read the installed profile file turned out.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum InstalledProfileRead {
    /// The file's text.
    Text(String),
    /// The path does not exist.
    Absent,
    /// It exists and could not be read.
    Unreadable(String),
}

/// Fold the installed profile file against the render, returning the sha256 of
/// the text it COMPARED. See the module docs on why this arm refuses where the
/// loaded-profile arm does not.
///
/// The digest is returned rather than recomputed by the caller because this is the
/// only function that holds those bytes: it feeds
/// [`YoukiCertification::installed_profile_sha256`], and a second reader of
/// `/etc/apparmor.d/<name>` could disagree with the one that certified.
pub fn fold_installed_profile(
    pin: &YoukiPin,
    path: &str,
    read: InstalledProfileRead,
) -> Result<String, OciPrerequisiteRefusal> {
    let expected = render_apparmor_profile(pin);
    match read {
        InstalledProfileRead::Text(text) if text == expected => Ok(sha256_hex(text.as_bytes())),
        InstalledProfileRead::Text(text) => Err(OciPrerequisiteRefusal::ProfileFileDiffers {
            path: path.to_string(),
            expected,
            observed: text,
        }),
        InstalledProfileRead::Absent => Err(OciPrerequisiteRefusal::ProfileFileAbsent {
            path: path.to_string(),
        }),
        InstalledProfileRead::Unreadable(error) => {
            Err(OciPrerequisiteRefusal::ProfileFileUnreadable {
                path: path.to_string(),
                error,
            })
        }
    }
}

/// The AppArmor arms of the certification, folded once: the loaded-profile axis
/// and the installed file's digest.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ApparmorPrerequisite {
    /// [`fold_loaded_profile`]'s answer.
    pub profile: ApparmorProfile,
    /// [`fold_installed_profile`]'s digest of the text it compared.
    pub installed_profile_sha256: String,
}

/// The certification's AppArmor arms as ONE fold — the loaded-profile list, then
/// the installed file against the render — in [`certify_youki`]'s order, with its
/// refusals.
///
/// One function because two surfaces answer this question: the certification
/// and `kata doctor`'s `containment_userns` row
/// (`crate::sandbox_posture::userns_fact`). With two folds they disagreed — the
/// row passed an unrestricted kernel with no installed profile while the
/// certification refused it `profile_file_absent`. The kernel's restriction is
/// deliberately NOT an input: it relaxes nothing here (see
/// [`UsernsRestriction`]).
///
/// # Errors
/// [`fold_loaded_profile`]'s `profile_not_loaded`, then
/// [`fold_installed_profile`]'s `profile_file_absent` / `profile_file_unreadable`
/// / `profile_file_differs`.
pub fn fold_apparmor_prerequisite(
    pin: &YoukiPin,
    loaded_list: Result<&str, String>,
    installed_path: &str,
    installed: InstalledProfileRead,
) -> Result<ApparmorPrerequisite, OciPrerequisiteRefusal> {
    let profile = fold_loaded_profile(pin, loaded_list)?;
    let installed_profile_sha256 = fold_installed_profile(pin, installed_path, installed)?;
    Ok(ApparmorPrerequisite {
        profile,
        installed_profile_sha256,
    })
}

/// Fold a read of `apparmor_restrict_unprivileged_userns`. Total; never refuses.
#[must_use]
pub fn fold_userns_restriction(read: Result<&str, String>) -> UsernsRestriction {
    match read {
        Err(_) => UsernsRestriction::Unknown,
        Ok(raw) => match raw.trim().parse::<i64>() {
            Ok(0) => UsernsRestriction::Unrestricted,
            Ok(_) => UsernsRestriction::Restricted,
            Err(_) => UsernsRestriction::Unknown,
        },
    }
}

/// The two controllers a bounded OCI stage's cgroup must carry.
///
/// `cpu` is deliberately NOT required: the OCI spec's CPU resource is a
/// quota/period pair kata does not author, so requiring it here would refuse a
/// host over a bound kata does not set. Memory and pids are the two the
/// generated `config.json` carries.
const REQUIRED_CONTROLLERS: [CgroupController; 2] =
    [CgroupController::Memory, CgroupController::Pids];

/// Fold the measured delegation: memory and pids must be PROVEN usable.
pub fn fold_delegation(delegation: &CgroupDelegation) -> Result<(), OciPrerequisiteRefusal> {
    let missing: Vec<&'static str> = REQUIRED_CONTROLLERS
        .into_iter()
        .filter(|controller| !delegation.has(*controller))
        .map(CgroupController::token)
        .collect();
    if missing.is_empty() {
        return Ok(());
    }
    Err(OciPrerequisiteRefusal::DelegationIncomplete {
        missing,
        evidence: delegation.evidence.clone(),
    })
}

// ---------------------------------------------------------------------------
// The impure certification.
// ---------------------------------------------------------------------------

/// Read a file, distinguishing "absent" from "unreadable".
fn read_installed_profile(path: &Path) -> InstalledProfileRead {
    match std::fs::read_to_string(path) {
        Ok(text) => InstalledProfileRead::Text(text),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => InstalledProfileRead::Absent,
        Err(error) => InstalledProfileRead::Unreadable(error.to_string()),
    }
}

/// [`fold_apparmor_prerequisite`] over THIS host's two reads — the kernel's
/// loaded-profile list and `/etc/apparmor.d/<profile_name>`. The one reader
/// [`certify_youki`] and `kata doctor` share.
///
/// # Errors
/// [`fold_apparmor_prerequisite`]'s refused set.
pub fn read_apparmor_prerequisite(
    pin: &YoukiPin,
) -> Result<ApparmorPrerequisite, OciPrerequisiteRefusal> {
    read_apparmor_prerequisite_at(
        pin,
        Path::new(APPARMOR_LOADED_PROFILES),
        Path::new(APPARMOR_PROFILE_DIRECTORY),
    )
}

/// [`read_apparmor_prerequisite`] with the two read locations named — so a host-free
/// cell can point `kata doctor`'s `containment_userns` row at a fixture and watch the
/// row read the certification's fold off THOSE files.
///
/// # Errors
/// [`fold_apparmor_prerequisite`]'s refused set.
pub(crate) fn read_apparmor_prerequisite_at(
    pin: &YoukiPin,
    loaded_profiles: &Path,
    profile_directory: &Path,
) -> Result<ApparmorPrerequisite, OciPrerequisiteRefusal> {
    let installed = profile_directory.join(pin.profile_name());
    fold_apparmor_prerequisite(
        pin,
        std::fs::read_to_string(loaded_profiles)
            .as_deref()
            .map_err(std::string::ToString::to_string),
        &installed.display().to_string(),
        read_installed_profile(&installed),
    )
}

/// The pin's binary arms as one measurement: the pinned path holds a readable
/// file whose sha256 is the pin's, or the named refusal.
///
/// Factored out of [`certify_youki`] because `kata host apparmor-install` asks
/// the same question before writing the profile — one producer, so the install
/// and the certification can never disagree about which bytes the pin names.
pub fn pinned_binary_sha256(pin: &YoukiPin) -> Result<String, OciPrerequisiteRefusal> {
    let store_path = PathBuf::from(pin.store_path());
    if !store_path.is_file() {
        return Err(OciPrerequisiteRefusal::BinaryAbsent {
            store_path: pin.store_path().to_string(),
            realised_by: pin.realised_by().to_string(),
        });
    }
    let bytes =
        std::fs::read(&store_path).map_err(|error| OciPrerequisiteRefusal::BinaryUnreadable {
            store_path: pin.store_path().to_string(),
            error: error.to_string(),
        })?;
    fold_digest(pin, &sha256_hex(&bytes))
}

/// CERTIFY the rootless-OCI prerequisite on this host, or refuse it by name.
///
/// Eight checks in order, each a refusal of its own: the pinned path holds a
/// file; its bytes hash to the pin; `youki --version` reports a version at or
/// above the pin, a spec at or above 1.0 and a `libseccomp:` line; a profile of the pinned name is
/// loaded (or the list is unreadable) AND the installed profile file is the
/// render byte for byte; the kernel restriction is read; cgroup delegation
/// carries memory and pids; and a throwaway rootless `/bin/true` container
/// actually runs.
///
/// The functional arm is last on purpose — it is the only one that forks, and
/// every read above it is a cheaper explanation for the same failure.
pub fn certify_youki(pin: &YoukiPin) -> Result<YoukiCertification, OciPrerequisiteRefusal> {
    let store_path = PathBuf::from(pin.store_path());
    let sha256 = pinned_binary_sha256(pin)?;

    let reported = youki_version_output(&store_path)?;
    let (version, spec_version) = fold_versions(pin, &reported)?;
    // The SAME output, folded a second time for a different fact. One exec, two
    // reads: a second `Command` here would be a second measurement of one
    // binary's self-description, able to disagree with the first.
    let libseccomp_version = fold_seccomp_support(pin, &reported)?;

    let ApparmorPrerequisite {
        profile,
        installed_profile_sha256,
    } = read_apparmor_prerequisite(pin)?;

    let userns_restriction = fold_userns_restriction(
        std::fs::read_to_string(USERNS_RESTRICTION_KNOB)
            .as_deref()
            .map_err(std::string::ToString::to_string),
    );

    // The CACHED accessor, not a second measurement. `measure_cgroup_delegation`
    // creates, writes and removes a scratch cgroup; taking it again here would be
    // a second reader of one fact able to disagree with the posture report that
    // already took it — and would pay the round trip twice per certification.
    let delegation = crate::sandbox_bounds::cgroup_delegation().clone();
    fold_delegation(&delegation)?;

    let functional_probe_id = run_functional_probe(pin)?;

    Ok(YoukiCertification {
        store_path,
        sha256,
        version,
        spec_version,
        libseccomp_version,
        profile,
        installed_profile_sha256,
        userns_restriction,
        delegation,
        functional_probe_id,
    })
}

/// The certification's FUNCTIONAL arm on its own: one throwaway rootless
/// `/bin/true` container of the pinned runtime, returning the id of the
/// container that really ran.
///
/// The id is MINTED HERE and both used and returned, so a caller recording it
/// ([`YoukiCertification::functional_probe_id`]) names the container that ran
/// rather than a string rebuilt from the same recipe — two spellings of one id
/// is how a basis would come to quote a probe nobody launched. `pub` for `kata
/// host setup`, whose re-run on a host whose loaded-profile list needs root to
/// read observes the profile the way the certification does: by a container
/// starting. It does not verify the pinned bytes; [`certify_youki`] does that
/// first, and so must any other caller.
///
/// # Errors
/// [`OciPrerequisiteRefusal::FunctionalHarness`] or
/// [`OciPrerequisiteRefusal::FunctionalRunRefused`].
pub fn run_functional_probe(pin: &YoukiPin) -> Result<String, OciPrerequisiteRefusal> {
    let id = functional_probe_id();
    run_throwaway_container(Path::new(pin.store_path()), &id)?;
    Ok(id)
}

/// Re-derive the pinned binary's sha256 and refuse if it changed.
///
/// Without it the certification's digest would be computed once and never
/// compared, which is recorded substrate that
/// enforces nothing. A store path is immutable, so a change here means the pin
/// was re-realized or the store damaged under a running worker.
pub fn verify_pinned_youki_unchanged(
    cert: &YoukiCertification,
) -> Result<(), OciPrerequisiteRefusal> {
    let bytes = std::fs::read(&cert.store_path).map_err(|error| {
        OciPrerequisiteRefusal::BinaryUnreadable {
            store_path: cert.store_path.display().to_string(),
            error: error.to_string(),
        }
    })?;
    let observed = sha256_hex(&bytes);
    if observed == cert.sha256 {
        return Ok(());
    }
    Err(OciPrerequisiteRefusal::DigestMismatch {
        store_path: cert.store_path.display().to_string(),
        pinned: cert.sha256.clone(),
        observed,
    })
}

/// Run `<pinned youki> --version` through the BOUNDED spawn and return its output.
///
/// Bounded rather than `Command::output()` for the reason the functional arm is:
/// a containment binary that hangs must produce a refusal, not a worker that
/// never finishes launching. It gets no systemd unit because it is not run in a
/// scope — the direct `SIGKILL` is the whole reaping story for a bare child.
pub(crate) fn youki_version_output(store_path: &Path) -> Result<String, OciPrerequisiteRefusal> {
    let unobtainable = |error: String| OciPrerequisiteRefusal::VersionUnobtainable {
        store_path: store_path.display().to_string(),
        error,
    };
    let capture = tempfile::Builder::new()
        .prefix("kata-youki-version-")
        .tempdir()
        .map_err(|error| unobtainable(format!("could not create a capture directory: {error}")))?;
    let run = spawn_with_timeout(
        runtime_command(store_path).arg("--version"),
        capture.path(),
        "version",
        &[],
        FUNCTIONAL_TIMEOUT,
    )
    .map_err(|error| unobtainable(format!("could not run `--version`: {error}")))?;
    match run.exit.as_deref() {
        Some("0") => {}
        None => {
            return Err(unobtainable(format!(
                "`--version` did not exit within {FUNCTIONAL_TIMEOUT:?} and was killed; a \
                 containment binary that does not identify itself promptly is refused"
            )));
        }
        Some(code) => {
            return Err(unobtainable(format!(
                "`--version` exited {code}; stderr: {stderr}",
                stderr = run.stderr.trim(),
            )));
        }
    }
    let reported = if run.stdout.trim().is_empty() {
        run.stderr.trim().to_string()
    } else {
        run.stdout.trim().to_string()
    };
    Ok(reported)
}

/// A statically-linked payload that runs in a rootfs holding nothing else.
///
/// The same candidate order `scripts/feasibility-probes.py::static_payload`
/// uses. Static is checked by reading the ELF's program headers for a
/// `PT_INTERP`, not by shelling `file(1)`: a certification taken where a stage
/// would be routed must not depend on a diagnostic tool being installed.
///
/// `#[doc(hidden)] pub` so the watchdog's live proof can assert WHICH payload this
/// host offers: its hang needs a multi-call busybox, and a host whose static
/// payload is a real `/bin/true` must say so rather than quietly prove nothing.
#[doc(hidden)]
#[must_use]
pub fn static_payload() -> Option<PathBuf> {
    for candidate in [
        "/bin/true",
        "/usr/bin/busybox-static",
        "/bin/busybox-static",
        "/usr/bin/busybox",
    ] {
        let path = Path::new(candidate);
        if path.is_file() && std::fs::read(path).is_ok_and(|bytes| is_static_elf(&bytes)) {
            return Some(path.to_path_buf());
        }
    }
    None
}

/// Is this a 64-bit little-endian ELF with no `PT_INTERP` program header?
///
/// Hand-parsed rather than via the `object` crate, which is a DEV-only
/// dependency of this crate — nothing in the worker's
/// production closure reads an ELF, and this keeps it that way.
fn is_static_elf(bytes: &[u8]) -> bool {
    /// `PT_INTERP`: the program header type naming a dynamic loader.
    const PT_INTERP: u32 = 3;
    // EVERY offset is `checked_add`ed. The input is a file this function does not
    // control, and `at + 2` on a header claiming a `usize::MAX`-adjacent program
    // header offset would panic in a debug build — a crafted ELF must make this
    // return `false`, never abort the worker that was asking whether it is static.
    let slice = |at: usize, len: usize| -> Option<&[u8]> { bytes.get(at..at.checked_add(len)?) };
    let read_u16 =
        |at: usize| -> Option<u16> { Some(u16::from_le_bytes(slice(at, 2)?.try_into().ok()?)) };
    let read_u32 =
        |at: usize| -> Option<u32> { Some(u32::from_le_bytes(slice(at, 4)?.try_into().ok()?)) };
    let read_u64 =
        |at: usize| -> Option<u64> { Some(u64::from_le_bytes(slice(at, 8)?.try_into().ok()?)) };
    let parsed = (|| -> Option<bool> {
        if bytes.get(..4)? != b"\x7fELF" || *bytes.get(4)? != 2 || *bytes.get(5)? != 1 {
            return None;
        }
        let program_header_offset = usize::try_from(read_u64(0x20)?).ok()?;
        let entry_size = usize::from(read_u16(0x36)?);
        let count = usize::from(read_u16(0x38)?);
        for index in 0..count {
            let at = program_header_offset.checked_add(index.checked_mul(entry_size)?)?;
            if read_u32(at)? == PT_INTERP {
                return Some(false);
            }
        }
        Some(true)
    })();
    parsed.unwrap_or(false)
}

/// Write a rootless OCI `config.json` whose only process is `args`.
///
/// The pinned youki's own `spec --rootless` generates it, so the spec is the one
/// the runtime under certification writes for itself, on every host: a host
/// without `runc` (a fresh Ubuntu 24.04) runs the same container as one with it.
/// A hand-written spec without a mount is refused by youki 0.7.0 for a user
/// namespace (`no mount in spec`). The `process` block is overwritten here. The
/// certification always passes `["/bin/true"]`; the argv is a parameter only so
/// the watchdog's own live proof can hand it something that hangs.
fn write_bundle_config(
    store_path: &Path,
    bundle: &Path,
    args: &[&str],
) -> Result<(), OciPrerequisiteRefusal> {
    let harness = |stage: &str, error: String| OciPrerequisiteRefusal::FunctionalHarness {
        stage: stage.to_string(),
        error,
    };
    // Bounded, as `youki_version_output` is: a containment binary that hangs
    // must produce a refusal, not a certification that never finishes.
    let capture = bundle.parent().unwrap_or(bundle);
    let generated = spawn_with_timeout(
        runtime_command(store_path)
            .args(["spec", "--rootless"])
            .current_dir(bundle),
        capture,
        "spec",
        &[],
        FUNCTIONAL_TIMEOUT,
    )
    .map_err(|error| harness("running `youki spec --rootless`", error))?;
    if generated.exit.as_deref() != Some("0") {
        return Err(harness(
            "running `youki spec --rootless`",
            format!(
                "exit {}; stderr: {}",
                generated
                    .exit
                    .as_deref()
                    .unwrap_or("none (killed at the deadline)"),
                generated.stderr.trim()
            ),
        ));
    }
    let text = std::fs::read_to_string(bundle.join("config.json"))
        .map_err(|e| harness("reading the youki-generated config.json", e.to_string()))?;
    let mut config: serde_json::Value = serde_json::from_str(&text)
        .map_err(|e| harness("parsing the youki-generated config.json", e.to_string()))?;
    config["process"] = serde_json::json!({
        "args": args,
        "cwd": "/",
        "terminal": false,
        "user": { "uid": 0, "gid": 0 },
        "env": ["PATH=/bin"],
    });
    let rendered = serde_json::to_string_pretty(&config)
        .map_err(|e| harness("serializing config.json", e.to_string()))?;
    std::fs::write(bundle.join("config.json"), rendered)
        .map_err(|e| harness("writing config.json", e.to_string()))
}

/// FUNCTIONAL: build a throwaway rootless bundle and run `/bin/true` in it.
///
/// This is the arm no read can substitute for, and the reason the certification
/// can claim the prerequisite at all. Ported from
/// `scripts/feasibility-probes.py::probe_youki`, including the delegated scope:
/// a login session's cgroup is not delegated on this class of host, so without
/// `systemd-run --user --scope -p Delegate=yes` youki cannot create the
/// container's cgroup. `--wait` is rejected alongside `--scope`; a scope already
/// runs synchronously and propagates the child's status.
fn run_throwaway_container(store_path: &Path, id: &str) -> Result<(), OciPrerequisiteRefusal> {
    run_throwaway_container_with(
        store_path,
        id,
        &["true"],
        &["/bin/true"],
        FUNCTIONAL_TIMEOUT,
    )
}

/// The container identity for one certification's functional arm.
///
/// Per-process, because two concurrent certifications on one host would otherwise
/// collide on the runtime's own namespace and the second `run` would fail on the
/// name rather than on the fact it measures.
fn functional_probe_id() -> String {
    format!("kata-oci-certify-{}", std::process::id())
}

/// [`run_throwaway_container`] with the container identity, the rootfs applet
/// names, the container's argv and the watchdog budget as parameters.
///
/// `#[doc(hidden)] pub` because the WATCHDOG is a production mechanism that only
/// a hanging container exercises, and no read can substitute for watching it
/// fire. `crates/worker/tests/oci_runtime_live.rs` drives THIS function with a
/// payload that sleeps for five minutes and a three-second budget, and then
/// observes — from `systemctl --user` and `youki list`, outside the code under
/// test — that the scope is gone and no container is left registered. A test that
/// re-implemented the launch could not have caught the pipe deadlock this
/// signature exists to have fixed: `stderr` was a `piped()` fd INHERITED by the
/// container's init, so `wait_with_output` blocked until that process closed it,
/// which a hung container never does — the watchdog killed the `systemd-run`
/// client and the read never returned, so `youki delete --force` never ran.
/// Output now goes to FILES in the bundle tempdir and the wait is `Child::wait`,
/// which holds no pipe open.
#[doc(hidden)]
pub fn run_throwaway_container_with(
    store_path: &Path,
    id: &str,
    applets: &[&str],
    args: &[&str],
    timeout: Duration,
) -> Result<(), OciPrerequisiteRefusal> {
    let harness = |stage: &str, error: String| OciPrerequisiteRefusal::FunctionalHarness {
        stage: stage.to_string(),
        error,
    };
    // Alive until AFTER the unit kill and the `youki delete --force` below: it
    // holds the bundle youki is reading and the capture files the refusal quotes,
    // and dropping it early would delete a rootfs out from under a container that
    // is still being torn down.
    let temporary = tempfile::Builder::new()
        .prefix("kata-youki-certify-")
        .tempdir()
        .map_err(|e| harness("creating the bundle tempdir", e.to_string()))?;
    let bundle = temporary.path().join("bundle");
    let bin = bundle.join("rootfs").join("bin");
    std::fs::create_dir_all(&bin)
        .map_err(|e| harness("creating the bundle rootfs", e.to_string()))?;
    let payload = static_payload().ok_or_else(|| {
        harness(
            "locating a statically linked payload",
            "none of /bin/true, /usr/bin/busybox-static, /bin/busybox-static, /usr/bin/busybox \
             is a statically linked ELF, so a rootfs holding nothing else cannot run one"
                .to_string(),
        )
    })?;
    for applet in applets {
        // busybox dispatches on argv[0], so a static busybox copied to `true` IS
        // `true` — which is also why the applet names are a parameter.
        let target = bin.join(applet);
        std::fs::copy(&payload, &target)
            .map_err(|e| harness("copying the static payload into the rootfs", e.to_string()))?;
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o755))
            .map_err(|e| harness("making the payload executable", e.to_string()))?;
    }
    write_bundle_config(store_path, &bundle, args)?;

    let outcome = run_bundle(store_path, &bundle, temporary.path(), id, timeout);

    match outcome {
        Err(error) => Err(harness("launching the delegated scope", error)),
        Ok(run) => throwaway_run_verdict(run, timeout),
    }
}

/// What a throwaway container's bounded run says: `Ok` on exit 0, else the
/// run refusal carrying the last ten lines of stderr (stdout when stderr is
/// empty) and the [`FunctionalDenial`] READ OFF THAT SAME TEXT — the reading
/// `kata host setup` routes the AppArmor install on.
fn throwaway_run_verdict(run: BoundedRun, timeout: Duration) -> Result<(), OciPrerequisiteRefusal> {
    if run.exit.as_deref() == Some("0") {
        return Ok(());
    }
    let stderr = if run.stderr.trim().is_empty() {
        run.stdout
    } else {
        run.stderr
    };
    let tail: Vec<&str> = stderr.lines().rev().take(10).collect();
    Err(OciPrerequisiteRefusal::FunctionalRunRefused {
        exit: run
            .exit
            .unwrap_or_else(|| format!("no exit within {timeout:?}; SIGKILLed")),
        stderr_tail: if tail.is_empty() {
            "no stderr".to_string()
        } else {
            tail.into_iter().rev().collect::<Vec<_>>().join(" / ")
        },
        denial: FunctionalDenial::of(&stderr),
    })
}

/// Launch an ALREADY-WRITTEN rootless bundle under a delegated user scope, tear
/// its container down whatever happens, and report what the run observed.
///
/// # Why this is a seam and not inlined
///
/// It is the one launch, and it has a SECOND caller: a bundle
/// `kata_worker::oci_bundle::spec_for` produced from a real `Capsule`, run by
/// `crates/worker/tests/oci_bundle_live.rs`. A test that re-implemented the
/// launch would be measuring its own `systemd-run` argv rather than kata's, and
/// the deadlock and the leaked-container bug this function's shape exists to have
/// fixed ([`spawn_with_timeout`]) would both be outside what it exercises.
///
/// The `delete --force` is the FINALLY and runs on every path, watchdog included.
/// A container left registered makes the NEXT run on this host fail on a name
/// collision rather than on the fact it measures.
///
/// # Errors
/// The `systemd-run` spawn or wait failing, as the message [`spawn_with_timeout`]
/// produced. A container that RAN and exited non-zero is `Ok`, with the code in
/// [`BoundedRun::exit`]: whether that is a failure is the caller's question.
#[doc(hidden)]
pub fn run_bundle(
    store_path: &Path,
    bundle: &Path,
    capture_dir: &Path,
    id: &str,
    timeout: Duration,
) -> Result<BoundedRun, String> {
    // The scope is NAMED so the watchdog can reach it, and the SECOND name is
    // youki's own: on a systemd host youki creates one transient scope per
    // container, `youki-<id>.scope`, and the container init lives there rather
    // than in kata's scope. Killing kata's scope alone reaps only the `youki run`
    // client and leaves the container Running — measured, see
    // [`spawn_with_timeout`]. Both go to the watchdog, youki's first.
    let unit = format!("{id}.scope");
    let teardown_units = vec![format!("youki-{id}.scope"), unit.clone()];
    let outcome = spawn_with_timeout(
        user_manager_command("systemd-run")
            .args(["--user", "--scope", "--unit", &unit, "--quiet", "--collect"])
            .args(["-p", "Delegate=yes"])
            .arg(store_path)
            .args(["run", "--bundle"])
            .arg(bundle)
            .arg(id),
        capture_dir,
        "run",
        &teardown_units,
        timeout,
    );
    let _ = spawn_with_timeout(
        runtime_command(store_path)
            .args(["delete", "--force"])
            .arg(id),
        capture_dir,
        "delete",
        &[],
        timeout,
    );
    outcome
}

/// What a bounded spawn observed.
#[derive(Clone, Debug)]
#[doc(hidden)]
pub struct BoundedRun {
    /// The exit code as a string, or `None` when the watchdog killed it.
    pub exit: Option<String>,
    /// Everything the child wrote to stdout, read from the capture file after it
    /// exited.
    pub stdout: String,
    /// Everything the child wrote to stderr, likewise.
    pub stderr: String,
}

/// Run `command` under `timeout`, capturing output to FILES rather than pipes.
///
/// # Why files, and why `Child::wait`
///
/// This is the fix for a deadlock that made the watchdog decorative. With
/// `Stdio::piped()` the write end is inherited by every descendant, container
/// init included, so `wait_with_output` reads until EOF — which a hung container
/// never gives. The watchdog would `SIGKILL` the `systemd-run` client, the read
/// would keep blocking on the surviving container's fd, and the
/// `youki delete --force` after it never ran: a refusal that hung instead of
/// refusing, and a leaked container. Files hold no fd open on this side, so
/// `Child::wait` returns as soon as the direct child is reaped and the capture is
/// read afterwards.
///
/// # Why UNIT NAMES and not just the pid
///
/// `nix::sys::signal::kill` reaches the direct child only, and the container's
/// init is not kata's child — nor is it even in kata's scope. MEASURED on the
/// reference host: with the container running under
/// `systemd-run --user --scope --unit <id>.scope`, the init's own cgroup is
/// `/user.slice/user-1000.slice/user@1000.service/user.slice/youki-<id>.scope`.
/// youki asks the user manager for its OWN transient scope per container (its
/// default cgroup naming, `:youki:<id>`), so killing kata's scope reaches the
/// `youki run` CLIENT and nothing else, and `youki kill`/`youki delete --force`
/// invoked from outside that context fail resolving
/// `/sys/fs/cgroup/:youki:<id>` — both verified by hand before this loop was
/// written.
///
/// So `units` is a LIST, killed in order: youki's container scope first (which
/// lets the still-live `youki run` client observe the exit and clean its own
/// state — observed to empty `youki list` on its own), then kata's scope, then a
/// direct `SIGKILL` of the child. `youki delete --force` afterwards clears any
/// state that survived. A unit that does not exist makes `systemctl` exit
/// non-zero, which is ignored: this is a teardown, not a measurement.
///
/// `nix` rather than `libc`: this workspace denies `unsafe_code`, and `nix`'s
/// `kill` is a safe wrapper.
fn spawn_with_timeout(
    command: &mut Command,
    capture_dir: &Path,
    tag: &str,
    units: &[String],
    timeout: Duration,
) -> Result<BoundedRun, String> {
    let out_path = capture_dir.join(format!("{tag}.out"));
    let err_path = capture_dir.join(format!("{tag}.err"));
    let create = |path: &Path| {
        std::fs::File::create(path).map_err(|error| format!("creating {}: {error}", path.display()))
    };
    let stdout = create(&out_path)?;
    let stderr = create(&err_path)?;
    let mut child = command
        .stdin(Stdio::null())
        .stdout(Stdio::from(stdout))
        .stderr(Stdio::from(stderr))
        .spawn()
        .map_err(|error| format!("spawning {}: {error}", command.get_program().display()))?;
    let pid = nix::unistd::Pid::from_raw(
        i32::try_from(child.id()).map_err(|_| "child pid does not fit in pid_t".to_string())?,
    );
    let units = units.to_vec();
    let (done, wait) = mpsc::channel::<()>();
    let watchdog = std::thread::spawn(move || {
        // `Timeout` ONLY. `Disconnected` is the wait finishing and dropping the
        // sender, which is the SUCCESS path — treating the two alike reported
        // every container as having timed out after 0.2 s, which is what this
        // arm looked like before the distinction was made.
        if wait.recv_timeout(timeout) != Err(mpsc::RecvTimeoutError::Timeout) {
            return false;
        }
        for unit in &units {
            let _ = unit_kill_command(unit).status();
        }
        let _ = nix::sys::signal::kill(pid, nix::sys::signal::Signal::SIGKILL);
        true
    });
    let waited = child.wait();
    drop(done);
    let timed_out = watchdog.join().unwrap_or(false);
    let status = waited.map_err(|error| format!("waiting for the child: {error}"))?;
    let read = |path: &Path| std::fs::read_to_string(path).unwrap_or_default();
    Ok(BoundedRun {
        exit: if timed_out {
            None
        } else {
            Some(
                status
                    .code()
                    .map_or_else(|| "signal".to_string(), |code| code.to_string()),
            )
        },
        stdout: read(&out_path),
        stderr: read(&err_path),
    })
}

// ---------------------------------------------------------------------------
// The one certification, taken for an `oci`-profile node.
// ---------------------------------------------------------------------------

/// The memo behind [`certified_oci_route`]. Module-level only so
/// [`oci_route_measured_for_test`] can observe it.
static MEASURED: std::sync::OnceLock<Result<YoukiCertification, OciPrerequisiteRefusal>> =
    std::sync::OnceLock::new();

/// Whether THIS process has taken the certification — successfully or not.
///
/// A rig's witness that a refusal it provoked came BEFORE the step that starts a
/// container: after a refused `CapsuleRoute::admit`, `false` proves nothing was measured,
/// on a host that could certify as much as on one that could not.
#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
#[must_use]
pub fn oci_route_measured_for_test() -> bool {
    MEASURED.get().is_some()
}

/// The ONE certification this process ever takes, memoized.
///
/// # Why a cache, and why it is not hidden state
///
/// [`certify_youki`] FORKS A CONTAINER: its functional arm runs a throwaway rootless
/// `/bin/true` and its `functional_probe_id` names that container. Calling it more
/// than once would mint a second, third and Nth answer to *"what did kata measure on
/// this host"*, each with a different probe id, each able to disagree with the one the
/// route was admitted on.
///
/// # Who asks, and why there is no switch
///
/// The one production caller is `crate::capsule_route::CapsuleRoute::admit`: every
/// stage runs as a capsule, so the rootless-OCI prerequisite is required at boot —
/// there is no second knob to consult.
///
/// # EXACTLY what is re-measured per stage, and what is not
///
/// This distinction is the whole of what a caller may rely on, so it is stated as a
/// list rather than left to *"a pinned path whose bytes are re-digested"*:
///
/// * **Re-measured on every stage:** the pinned binary's **sha256**, and nothing
///   else. [`crate::oci_driver::OciStageDriver::drive`] calls
///   [`verify_pinned_youki_unchanged`] immediately before it launches the provider and
///   refuses `runtime_changed` on a mismatch or an unreadable file. A store path is
///   immutable, so a change there means the pin was re-realised or the store damaged
///   under a running worker.
/// * **Boot-time only, never re-read while this process lives:** the installed
///   AppArmor profile's text and its digest, the loaded-profile list, the
///   `libseccomp:` witness from `youki --version`, the `apparmor_restrict_unprivileged_userns`
///   knob, the cgroup v2 delegation and its proven controllers, and the functional
///   probe that really ran a container. An operator who unloads the profile, flips the
///   knob or revokes delegation under a running worker is NOT refused until it
///   restarts — that is the honest limit of this cache, and it is the same limit
///   `sandbox_bounds::cgroup_delegation` has.
///
/// Why that split rather than re-measuring everything: the sha256 is one `read` of a
/// file kata is about to `execve`, while the profile check reads `/etc` and
/// `/sys/kernel/security`, the seccomp witness and the functional probe each fork,
/// and the delegation probe writes cgroup knobs. Paying those per stage would make
/// the certification's own cost proportional to the workload, and the functional arm
/// would mint a container per stage whose id nothing records. The one axis that
/// cannot be argued from immutability is the one that is checked.
///
/// The rest of what is cached is a measurement of THIS PROCESS's environment: the
/// delegation is a property of the cgroup this process was started in.
///
/// The `Err` arm is cached too, deliberately: a host that refused certification at
/// boot has no capsule route, so no stage runs on it — and a retry that could answer
/// differently would be exactly the "measure again and hope" the refusal exists to
/// prevent. There is no fallback: ADR-0001's initial profile says *"refusal before
/// issuance when required rootless OCI … containment cannot be installed. There is no
/// host-process or weaker-sandbox fallback."*
///
/// # Errors
///
/// [`certify_youki`]'s, cloned from the one measurement.
pub fn certified_oci_route() -> Result<&'static YoukiCertification, OciPrerequisiteRefusal> {
    MEASURED
        .get_or_init(|| certify_youki(YoukiPin::embedded()))
        .as_ref()
        .map_err(Clone::clone)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A refused run's stderr is read once, and the reading is what both the
    /// operator's note and `kata host setup`'s AppArmor recourse branch on:
    /// AppArmor named wins over an EPERM in the same stderr, case does not
    /// matter, and anything else is no denial at all.
    #[test]
    fn a_refused_runs_stderr_is_read_for_its_denial() {
        for (stderr, denial) in [
            (
                "apparmor=\"DENIED\" operation=\"capable\"",
                FunctionalDenial::AppArmorNamed,
            ),
            (
                "AppArmor: Operation not permitted",
                FunctionalDenial::AppArmorNamed,
            ),
            (
                "clone3: Operation not permitted",
                FunctionalDenial::CapabilityDenied,
            ),
            ("write uid_map: EPERM", FunctionalDenial::CapabilityDenied),
            (
                "rootfs: No such file or directory",
                FunctionalDenial::Unclassified,
            ),
            ("", FunctionalDenial::Unclassified),
        ] {
            assert_eq!(FunctionalDenial::of(stderr), denial, "{stderr:?}");
        }
        assert_eq!(FunctionalDenial::Unclassified.note(), "");
    }

    /// A refused throwaway run carries the denial read off the text it quotes:
    /// its stderr, or its stdout when the runtime wrote nothing to stderr — the
    /// refusal `kata host setup` routes the AppArmor install on. An exit 0 is
    /// no refusal, and a run the watchdog killed is named as killed.
    ///
    /// **Would red if:** the run refusal stopped reading its denial off the
    /// quoted text (a fixed denial, or the stderr read when stdout was quoted).
    #[test]
    fn a_refused_throwaway_run_carries_the_denial_its_output_names() {
        let run = |exit: Option<&str>, stdout: &str, stderr: &str| BoundedRun {
            exit: exit.map(str::to_string),
            stdout: stdout.to_string(),
            stderr: stderr.to_string(),
        };
        let timeout = Duration::from_secs(5);
        assert!(
            throwaway_run_verdict(run(Some("0"), "", "apparmor=\"DENIED\""), timeout).is_ok(),
            "an exit 0 is a container that ran, whatever it wrote"
        );
        for (exit, stdout, stderr, denial) in [
            (
                Some("1"),
                "",
                "apparmor=\"DENIED\" operation=\"capable\"",
                FunctionalDenial::AppArmorNamed,
            ),
            (
                Some("1"),
                "clone3: Operation not permitted",
                " \n",
                FunctionalDenial::CapabilityDenied,
            ),
            (
                None,
                "",
                "rootfs: No such file or directory",
                FunctionalDenial::Unclassified,
            ),
        ] {
            let refusal = throwaway_run_verdict(run(exit, stdout, stderr), timeout)
                .expect_err("a non-zero exit is refused");
            let OciPrerequisiteRefusal::FunctionalRunRefused {
                exit: said,
                stderr_tail,
                denial: read,
            } = refusal
            else {
                panic!("a run that started is a run refusal");
            };
            assert_eq!(read, denial, "{stdout:?} / {stderr:?}");
            let quoted = if stderr.trim().is_empty() {
                stdout
            } else {
                stderr
            };
            assert_eq!(
                stderr_tail,
                quoted.trim_end(),
                "the quoted text is the one read"
            );
            match exit {
                Some(code) => assert_eq!(said, code),
                None => assert!(said.contains("SIGKILLed"), "{said}"),
            }
        }
    }

    fn pin() -> &'static YoukiPin {
        YoukiPin::embedded()
    }

    /// The rendered profile is a LITERAL golden: every byte pinned, including
    /// the pinned executable's exact store path. A template change, a moved
    /// path, or a dropped `userns,` all red this — which is the whole guard a
    /// single-producer render needs: the installed file is compared against
    /// this text byte for byte.
    ///
    /// **Would red if:** anyone edited the template, or re-pinned
    /// `config/youki-pin.toml` without updating this literal (and the golden in
    /// `crates/types/src/youki_pin.rs`, which pins the fields the same edit
    /// moves).
    #[test]
    fn the_rendered_profile_is_the_literal_golden() {
        let rendered = render_apparmor_profile(pin());
        assert_eq!(
            rendered,
            "abi <abi/4.0>,\n\
             include <tunables/global>\n\
             \n\
             profile youki /nix/store/dwi0lfqpz41vv8sap08c2ykdga1970nl-youki-seccomp-0.7.0/bin/youki \
             flags=(unconfined) {\n  userns,\n  include if exists <local/youki>\n}\n"
        );
        // The load-bearing members, named so a re-pin that updates only the
        // literal above still reds on the properties that carry the mechanism.
        assert!(rendered.contains("flags=(unconfined)"));
        assert!(rendered.contains("  userns,\n"));
        assert!(rendered.contains(pin().store_path()));
        assert!(rendered.contains(&format!("profile {} ", pin().profile_name())));
    }

    /// Every pure fold, over a table that includes the arms this host cannot
    /// produce on demand.
    #[test]
    fn the_pure_folds_classify_every_arm() {
        // Digest.
        assert_eq!(
            fold_digest(pin(), pin().sha256()).as_deref(),
            Ok(pin().sha256())
        );
        assert_eq!(
            fold_digest(pin(), &"0".repeat(64))
                .expect_err("a wrong digest must refuse")
                .token(),
            "digest_mismatch"
        );

        // Versions. The reference build's `commit:` line is `0.7.0-VERGEN…`,
        // which is exactly why the spec line is read by its own key.
        let shipped = "youki version: 0.7.0\ncommit: 0.7.0-VERGEN_IDEMPOTENT_OUTPUT\nspec: \
                       1.1.0\nrustc: 1.98.1";
        assert_eq!(fold_versions(pin(), shipped), Ok(((0, 7, 0), (1, 1, 0))));
        for (reported, token) in [
            ("nothing useful", "version_unreadable"),
            ("youki version: 0.6.9\nspec: 1.1.0", "version_below_floor"),
            ("youki version: 0.7.0\ncommit: x", "spec_version_unreadable"),
            (
                "youki version: 0.7.0\nspec: 0.9.0",
                "spec_version_below_floor",
            ),
        ] {
            assert_eq!(
                fold_versions(pin(), reported)
                    .expect_err(&format!("{reported:?} must refuse"))
                    .token(),
                token,
                "for {reported:?}"
            );
        }

        // The SECCOMP-SUPPORT witness, over the two identifications measured on
        // the reference host: the re-pinned libseccomp build, and the
        // `nixpkgs#youki` build the pin moved AWAY from. The second is the one
        // that silently dropped `linux.seccomp`, so it must refuse BY NAME and
        // the refusal must name the pinned path an operator has to replace.
        let with_seccomp = "youki version: 0.7.0\ncommit: 0.7.0-VERGEN_IDEMPOTENT_OUTPUT\nspec: \
                            1.1.0\nrustc: 1.98.1\nlibseccomp: 2.6.1";
        assert_eq!(
            fold_seccomp_support(pin(), with_seccomp).as_deref(),
            Ok("2.6.1"),
            "the libseccomp version is carried VERBATIM; it is what the binary printed, not a \
             conclusion kata drew from it"
        );
        assert_eq!(
            fold_seccomp_support(pin(), "youki version: 0.7.0\nlibseccomp: unknown").as_deref(),
            Ok("unknown"),
            "`unknown` is what youki's build.rs emits when pkg-config fails WITH the feature \
             already on, so refusing it would refuse a runtime that does enforce the fence"
        );
        for reported in [
            // The measured `nixpkgs#youki` identification, verbatim.
            shipped,
            // A present-but-empty value is not a witness.
            "youki version: 0.7.0\nspec: 1.1.0\nlibseccomp:   ",
            // The word appearing somewhere other than as a line key.
            "youki version: 0.7.0\nspec: 1.1.0\nrustc: 1.98.1 libseccomp 2.6.1",
            "",
        ] {
            let refusal = fold_seccomp_support(pin(), reported)
                .expect_err(&format!("{reported:?} carries no libseccomp witness"));
            assert_eq!(refusal.token(), "seccomp_unsupported", "for {reported:?}");
            let rendered = refusal.to_string();
            assert!(
                rendered.contains(pin().store_path()) && rendered.contains(pin().realised_by()),
                "the refusal must name the pinned path AND the command that realises a runtime \
                 with the feature, because an operator's only recourse is to replace those \
                 bytes: {rendered}"
            );
        }

        // Loaded profiles: readable-and-present, readable-and-absent, unreadable.
        assert_eq!(
            fold_loaded_profile(pin(), Ok("unconfined (unconfined)\nyouki (unconfined)\n")),
            Ok(ApparmorProfile::Loaded)
        );
        assert_eq!(
            fold_loaded_profile(pin(), Ok("unconfined (unconfined)\n"))
                .expect_err("a readable list without the name must refuse")
                .token(),
            "profile_not_loaded"
        );
        assert_eq!(
            fold_loaded_profile(pin(), Err("Permission denied".to_string())),
            Ok(ApparmorProfile::Unknown),
            "an unreadable list is unknown — never loaded, and never a refusal that would make \
             this certification require root"
        );

        // The installed file, which is where the name-to-path binding lives.
        let expected = render_apparmor_profile(pin());
        assert_eq!(
            fold_installed_profile(
                pin(),
                "/etc/apparmor.d/youki",
                InstalledProfileRead::Text(expected.clone())
            ),
            Ok(sha256_hex(expected.as_bytes())),
            "a matching installed profile folds to the sha256 of the bytes it COMPARED, which is \
             what the measured basis a provider echoes carries — a second reader of the file could \
             disagree with the one that certified"
        );
        for (read, token) in [
            (InstalledProfileRead::Absent, "profile_file_absent"),
            (
                InstalledProfileRead::Unreadable("Permission denied".to_string()),
                "profile_file_unreadable",
            ),
            (
                // The path swapped for another store path: the name is still
                // `youki`, so the loaded-list axis could not catch this.
                InstalledProfileRead::Text(expected.replace(pin().store_path(), "/usr/bin/youki")),
                "profile_file_differs",
            ),
        ] {
            assert_eq!(
                fold_installed_profile(pin(), "/etc/apparmor.d/youki", read)
                    .expect_err("must refuse")
                    .token(),
                token
            );
        }

        // The restriction knob.
        for (read, want) in [
            (Ok("0\n"), UsernsRestriction::Unrestricted),
            (Ok("1\n"), UsernsRestriction::Restricted),
            (Ok("banana"), UsernsRestriction::Unknown),
            (Err("unreadable".to_string()), UsernsRestriction::Unknown),
        ] {
            assert_eq!(fold_userns_restriction(read), want);
        }
    }

    /// The delegation fold names the controller it is missing.
    #[test]
    fn the_delegation_fold_requires_memory_and_pids_by_name() {
        use crate::sandbox_bounds::{CgroupObservation, fold_cgroup_delegation};
        use std::collections::{BTreeMap, BTreeSet};

        let observation = CgroupObservation {
            unified_hierarchy: false,
            own_cgroup: Err("no v2".to_string()),
            offered: BTreeSet::new(),
            enabled_for_children: BTreeSet::new(),
            scratch_mkdir: Err("not attempted".to_string()),
            round_trips: BTreeMap::new(),
            relocated_self: false,
            subtree_enables: BTreeMap::new(),
            swap_cap: None,
        };
        let refusal = fold_delegation(&fold_cgroup_delegation(observation))
            .expect_err("a host with no unified hierarchy cannot carry a stage bound");
        assert_eq!(refusal.token(), "delegation_incomplete");
        let rendered = refusal.to_string();
        assert!(
            rendered.contains("memory") && rendered.contains("pids"),
            "the refusal must name the controllers: {rendered}"
        );
    }

    /// The static-ELF reader agrees with `file(1)` on this host's own payload.
    #[test]
    fn the_static_elf_reader_refuses_a_dynamic_binary() {
        let dynamic = std::fs::read("/proc/self/exe").expect("this test binary is readable");
        assert!(
            !is_static_elf(&dynamic),
            "the test binary is dynamically linked, so the reader must refuse it"
        );
        assert!(!is_static_elf(b"not an elf"));
    }

    /// **The certification watchdog's `systemctl --user kill` keeps only
    /// [`SYSTEMD_RUN_ENV`] of the worker's environment.**
    ///
    /// The command is read before it is spawned (a timeout is what spawns it, and
    /// `systemctl` is resolved off `PATH`, so no recording stand-in can take its
    /// place): its `Debug` form opens `env -i` only when the environment is
    /// cleared, and every variable it sets is named. This test process holds `HOME`
    /// and cargo's variables, so an inherited environment would carry them.
    ///
    /// **Would red if:** the watchdog's `systemctl` were built without clearing the
    /// environment (measured: with the clear absent, the `Debug` form has no
    /// `env -i`).
    #[test]
    fn the_watchdogs_unit_kill_keeps_only_the_user_manager_variables() {
        assert!(
            std::env::var_os("HOME").is_some(),
            "this process holds no HOME, so its absence would prove nothing"
        );
        let command = unit_kill_command("youki-probe.scope");
        assert_eq!(command.get_program(), "systemctl");
        assert_eq!(
            command.get_args().collect::<Vec<_>>(),
            ["--user", "kill", "--signal=KILL", "youki-probe.scope"]
        );
        let rendered = format!("{command:?}");
        assert!(
            rendered.starts_with("env -i "),
            "the watchdog's systemctl inherits the worker's environment: {rendered}"
        );
        for (name, value) in command.get_envs() {
            assert!(
                SYSTEMD_RUN_ENV.iter().any(|kept| name == *kept) && value.is_some(),
                "the watchdog's systemctl sets {name:?} beyond {SYSTEMD_RUN_ENV:?}"
            );
        }
        // What the user-manager clients keep can carry no key: an `env:` source
        // naming any of it is refused.
        for kept in SYSTEMD_RUN_ENV {
            assert!(
                kata_types::execution_contract::CREDENTIAL_ENV_RESERVED.contains(&kept),
                "`{kept}` reaches the user-manager clients but an `env:` source may name it"
            );
        }
    }

    /// **The worker's `youki --version` starts with an EMPTY environment, whatever
    /// the worker holds.**
    ///
    /// The runtime is a script that writes the kernel's copy of the environment it
    /// was started with (`/proc/$$/environ`) to a file and prints a version; this
    /// test process holds cargo's variables, so an inherited environment is
    /// non-empty. Read from `/proc`, not from the command under test.
    ///
    /// **Would red if:** [`runtime_command`], which every worker-side `youki` but the
    /// certification's `run` builds on, stopped clearing the environment (measured:
    /// with the clear absent, the record holds cargo's variables).
    #[test]
    fn the_runtime_version_read_starts_with_an_empty_environment() {
        use std::os::unix::fs::PermissionsExt as _;
        let root = tempfile::tempdir().expect("a scratch root");
        let record = root.path().join("environ");
        let script = root.path().join("youki");
        std::fs::write(
            &script,
            format!(
                "#!/bin/sh\n/bin/cat /proc/$$/environ > {}\necho 'youki version 0.7.0'\n",
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
        let reported = youki_version_output(&script).expect("the recording runtime answers");
        assert_eq!(reported, "youki version 0.7.0");
        let recorded = std::fs::read(&record).expect("the runtime recorded its environment");
        assert!(
            recorded.is_empty(),
            "`youki --version` was started with an environment: {:?}",
            String::from_utf8_lossy(&recorded)
                .split('\0')
                .filter_map(|entry| entry.split('=').next())
                .collect::<Vec<_>>(),
        );
    }
}
