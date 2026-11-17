//! `kata host` — preparing a host for kata's rootless-youki `oci` execution
//! profile.
//!
//! # `kata host apparmor-install` — the root-only verb
//!
//! The pinned youki needs an AppArmor profile on a host running
//! `kernel.apparmor_restrict_unprivileged_userns=1`: without one, the binary
//! transitions into the kernel's `unprivileged_userns` profile on
//! `unshare(CLONE_NEWUSER)`, which denies `capability`, and every rootless
//! container fails with EPERM. This verb writes the EXACT-PATH profile
//! [`kata_worker::oci_runtime::render_apparmor_profile`] renders for the
//! embedded pin to `/etc/apparmor.d/<profile_name>` and reloads it with
//! `apparmor_parser -r`.
//!
//! Its contract:
//!
//! * it runs as ROOT and never escalates itself — an operator supplies the
//!   privilege with `sudo kata host apparmor-install`, so a refusal before
//!   any write is the honest answer on a non-root invocation;
//! * exact path, never a glob, and never a sysctl relaxation: an upgrade
//!   changes the Nix store path, the profile stops attaching, and the
//!   certification refuses until an operator re-pins and re-installs — that
//!   refusal is the mechanism;
//! * it refuses to grant the profile to anything but the pinned bytes:
//!   [`kata_worker::oci_runtime::pinned_binary_sha256`] runs first, the same
//!   producer `certify_youki`'s first arms run, so the install and the
//!   certification cannot disagree about which bytes the pin names;
//! * and it never relaxes `kernel.apparmor_restrict_unprivileged_userns`.
//!
//! # `kata host setup` — the unprivileged verb
//!
//! Everything above the one root-owned fact, in one command an operator runs
//! on a fresh host: it measures the host answers the `oci` profile needs
//! (platform, Nix, cgroup v2 delegation, unprivileged userns, the pinned
//! youki, the AppArmor profile), provisions the shipped `kata-provider-youki`
//! — with a verbatim copy of the iproute2 `ip` the package declares by Nix
//! store path — into a by-hash store under `--config`'s directory, writes its
//! exports into
//! `.env`, merges the declared `[node]
//! environment` and an empty `egress_allow` into the config (scaffolding the
//! project the way `kata init` does when the file is absent), and finishes
//! with `kata doctor` as the verdict. The AppArmor profile is the one fact
//! that needs root; without `--install-apparmor` the run reports it deferred
//! and names `sudo kata host apparmor-install`, with the flag it execs that
//! exact command — privilege still supplied by the operator's sudo, never
//! escalated by kata itself.

use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::Context;
use kata_types::nix_environment::{NIX_STORE_DIRECTORY, StorePath};
use kata_types::youki_pin::YoukiPin;
use kata_worker::oci_runtime::{
    ApparmorProfile, FunctionalDenial, InstalledProfileRead, OciPrerequisiteRefusal,
    UsernsRestriction, pinned_binary_sha256, render_apparmor_profile, sha256_hex,
};
use serde::Serialize;

/// The recourse an operator types — the same spelling every `oci_runtime`
/// refusal that an uninstalled profile causes prints. Composed once here
/// rather than typed per call site.
pub const APPARMOR_INSTALL_COMMAND: &str = "sudo kata host apparmor-install";

/// Why `kata host apparmor-install` refused, or what went wrong mid-install.
///
/// One variant per named refusal: an operator branches on the token a
/// `Display` leads with, not on prose.
#[derive(Debug, PartialEq, Eq)]
pub enum ApparmorInstallError {
    /// euid was not 0. Written NOTHING — the privilege check is the first
    /// effect and precedes every filesystem mutation.
    RequiresRoot { euid: u32, target: String },
    /// The pinned path did not hold the pinned bytes, folded through the same
    /// producer the certification runs. Nothing was written: a profile
    /// granting `userns` to bytes that are not the pin is not this command's
    /// to install.
    PinnedBinary(OciPrerequisiteRefusal),
    /// The write (or the 0644 that makes it root-owned-but-readable) failed.
    WriteFailed { path: String, error: String },
    /// `apparmor_parser -r` could not be spawned or exited non-zero. The file
    /// stays — an unloaded file is not a policy in force, and the next run's
    /// file-compare names it drift.
    ReloadFailed { argv: String, error: String },
    /// The kernel's loaded-profile list was readable afterwards and did not
    /// name the profile — the reload reported success but the profile is not
    /// in force.
    NotLoaded { profile_name: String },
}

impl std::fmt::Display for ApparmorInstallError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::RequiresRoot { euid, target } => write!(
                f,
                "writing `{target}` and running `apparmor_parser -r` require root (euid 0; this \
                 process is euid {euid}). Re-run it as `{APPARMOR_INSTALL_COMMAND}` — this \
                 command never escalates."
            ),
            Self::PinnedBinary(refusal) => write!(f, "{refusal}"),
            Self::WriteFailed { path, error } => {
                write!(f, "could not write `{path}`: {error}")
            }
            Self::ReloadFailed { argv, error } => write!(
                f,
                "wrote the profile but `{argv}` failed: {error}. The file was left in place — an \
                 unloaded file is not a policy in force."
            ),
            Self::NotLoaded { profile_name } => write!(
                f,
                "`apparmor_parser -r` succeeded, but no profile named `{profile_name}` is in the \
                 kernel's loaded list — the reload reported success and the profile is not in \
                 force."
            ),
        }
    }
}

impl std::error::Error for ApparmorInstallError {}

/// What `kata host apparmor-install` did, in the shape `--format json` emits.
#[derive(Debug, Serialize)]
pub struct ApparmorInstallReport {
    /// Discriminates this payload for a machine reader without a schema
    /// version — the same `summary_kind` convention the sibling reports use.
    pub summary_kind: &'static str,
    /// `/etc/apparmor.d/<profile_name>` — what was written.
    pub profile_path: String,
    /// The profile name, from the embedded pin.
    pub profile_name: String,
    /// The pinned executable the profile attaches to.
    pub store_path: String,
    /// sha256 of the profile text written (== the render's digest).
    pub profile_sha256: String,
    /// The reload argv, verbatim — `apparmor_parser -r <path>`.
    pub reload: String,
    /// Whether the name was then OBSERVED in the kernel's loaded list:
    /// `verified`, or `unverifiable: <why>` — never a bare claim.
    pub loaded_check: String,
}

/// The reload argv — `apparmor_parser -r <profile path>` — spelled once so the
/// argv a test asserts and the argv the command runs are the same vector.
fn reload_argv(target: &Path) -> Vec<String> {
    vec![
        "apparmor_parser".to_string(),
        "-r".to_string(),
        target.display().to_string(),
    ]
}

/// Write `rendered` at `<dir>/<pin.profile_name()>` (0644) and reload it —
/// the impure half of the install with the two effects parameterized: the
/// privilege level and the `apparmor_parser` spawn. That is what makes every
/// refusal arm reachable without a kernel.
///
/// # Refused set — writes NOTHING until each is satisfied
///
/// 1. `euid != 0` → [`ApparmorInstallError::RequiresRoot`], before any write.
/// 2. The write or the chmod → [`ApparmorInstallError::WriteFailed`].
/// 3. `apparmor_parser -r` → [`ApparmorInstallError::ReloadFailed`]; the file
///    stays (an unloaded file is not a policy in force).
fn write_and_reload(
    pin: &YoukiPin,
    euid: u32,
    apparmor_dir: &Path,
    exec: &mut dyn FnMut(&[String]) -> Result<(), String>,
) -> Result<PathBuf, ApparmorInstallError> {
    let target = apparmor_dir.join(pin.profile_name());
    if euid != 0 {
        return Err(ApparmorInstallError::RequiresRoot {
            euid,
            target: target.display().to_string(),
        });
    }
    std::fs::write(&target, render_apparmor_profile(pin)).map_err(|error| {
        ApparmorInstallError::WriteFailed {
            path: target.display().to_string(),
            error: error.to_string(),
        }
    })?;
    // 0644 — root-owned policy, still readable by `apparmor_parser` and by the
    // non-root file-compare `certify_youki` runs.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o644)).map_err(
            |error| ApparmorInstallError::WriteFailed {
                path: target.display().to_string(),
                error: error.to_string(),
            },
        )?;
    }
    let argv = reload_argv(&target);
    exec(&argv).map_err(|error| ApparmorInstallError::ReloadFailed {
        argv: argv.join(" "),
        error,
    })?;
    Ok(target)
}

/// What the post-reload read of the kernel's loaded list established.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LoadedCheck {
    /// The list was readable and names the profile.
    Verified,
    /// The list could not be read — never reported as loaded, never as absent.
    Unverifiable,
}

/// The loaded-list fold as the report records it, through
/// [`kata_worker::oci_runtime::fold_loaded_profile`], the certification's own
/// arm, so install and certification cannot disagree about the list. A READABLE
/// list without the name is [`ApparmorInstallError::NotLoaded`]; an unreadable
/// one is [`LoadedCheck::Unverifiable`].
fn loaded_check(
    pin: &YoukiPin,
    read: Result<&str, String>,
) -> Result<LoadedCheck, ApparmorInstallError> {
    match kata_worker::oci_runtime::fold_loaded_profile(pin, read) {
        Ok(ApparmorProfile::Loaded) => Ok(LoadedCheck::Verified),
        Ok(ApparmorProfile::Unknown) => Ok(LoadedCheck::Unverifiable),
        Err(OciPrerequisiteRefusal::ProfileNotLoaded { .. }) => {
            Err(ApparmorInstallError::NotLoaded {
                profile_name: pin.profile_name().to_string(),
            })
        }
        Err(other) => Err(ApparmorInstallError::PinnedBinary(other)),
    }
}

impl From<OciPrerequisiteRefusal> for ApparmorInstallError {
    fn from(refusal: OciPrerequisiteRefusal) -> Self {
        Self::PinnedBinary(refusal)
    }
}

/// `kata host apparmor-install`, end to end.
///
/// # Errors
///
/// Anything [`ApparmorInstallError`] names (with `?` propagating
/// [`OciPrerequisiteRefusal`] through the `From` above), or a wrapped I/O
/// error from the loaded-list read's own context.
pub fn run_apparmor_install() -> anyhow::Result<ApparmorInstallReport> {
    let pin = YoukiPin::embedded();
    let euid = nix::unistd::geteuid().as_raw();
    let dir = Path::new(kata_worker::oci_runtime::APPARMOR_PROFILE_DIRECTORY);
    let mut exec = |argv: &[String]| -> Result<(), String> {
        let Some((program, args)) = argv.split_first() else {
            return Err("empty argv".to_string());
        };
        let output = Command::new(program)
            .args(args)
            .output()
            .map_err(|error| format!("could not spawn `{program}`: {error}"))?;
        if output.status.success() {
            Ok(())
        } else {
            Err(format!(
                "exited {code}: {stderr}",
                code = output
                    .status
                    .code()
                    .map_or_else(|| "signal".to_string(), |code| code.to_string()),
                stderr = String::from_utf8_lossy(&output.stderr).trim(),
            ))
        }
    };
    // The privilege check is FIRST — before the pin's binary check reads a byte
    // — because `RequiresRoot` must prove nothing was written, and a check that
    // runs after I/O cannot. The pin's binary check is SECOND and before the
    // write for its own reason: a profile granting `userns` to bytes that are
    // not the pin is not this command's to install.
    if euid != 0 {
        return Err(ApparmorInstallError::RequiresRoot {
            euid,
            target: dir.join(pin.profile_name()).display().to_string(),
        }
        .into());
    }
    pinned_binary_sha256(pin).map_err(ApparmorInstallError::from)?;
    let target = write_and_reload(pin, euid, dir, &mut exec)?;
    let rendered = render_apparmor_profile(pin);
    let loaded = loaded_check(
        pin,
        std::fs::read_to_string(kata_worker::oci_runtime::APPARMOR_LOADED_PROFILES)
            .as_deref()
            .map_err(std::string::ToString::to_string),
    )?;
    let loaded = match loaded {
        LoadedCheck::Verified => format!(
            "verified — `{name}` is in the kernel's loaded list",
            name = pin.profile_name()
        ),
        LoadedCheck::Unverifiable => format!(
            "unverifiable — {} could not be read; `certify_youki`'s functional arm is the next \
             observer",
            kata_worker::oci_runtime::APPARMOR_LOADED_PROFILES
        ),
    };
    Ok(ApparmorInstallReport {
        summary_kind: "kata host apparmor-install",
        profile_path: target.display().to_string(),
        profile_name: pin.profile_name().to_string(),
        store_path: pin.store_path().to_string(),
        profile_sha256: sha256_hex(rendered.as_bytes()),
        reload: reload_argv(&target).join(" "),
        loaded_check: loaded,
    })
}

/// The human-face rendering of an [`ApparmorInstallReport`].
#[must_use]
pub fn render_apparmor_install(report: &ApparmorInstallReport) -> String {
    use std::fmt::Write as _;
    let mut out = String::new();
    let _ = writeln!(out, "--- kata host apparmor-install ---");
    let _ = writeln!(out, "profile    {}", report.profile_path); // kata-spacing: intentional
    let _ = writeln!(out, "name       {}", report.profile_name); // kata-spacing: intentional
    let _ = writeln!(out, "attaches   {}", report.store_path); // kata-spacing: intentional
    let _ = writeln!(out, "sha256     {}", report.profile_sha256); // kata-spacing: intentional
    let _ = writeln!(out, "reload     {}", report.reload); // kata-spacing: intentional
    let _ = writeln!(out, "loaded     {}", report.loaded_check); // kata-spacing: intentional
    out
}

// ---------------------------------------------------------------------------
// `kata host setup` — preparing a host AND a project for the `oci` profile.
// ---------------------------------------------------------------------------
//
// The sequence mirrors the operator story: the host must deliver the
// rootless-OCI prerequisite (platform, Nix, cgroup v2 delegation, unprivileged
// user namespaces, the pinned youki, its AppArmor profile), then the project
// must declare the route (the provider's exports in `.env`, `[node]
// environment` + `egress_allow` in `--config`), and `kata
// doctor` is the verdict at the end. Every step is a named row in the report;
// a refusal aborts the run AT that row, because a precondition that refused
// makes the rows below it meaningless — there is no arm that proceeds on a
// weaker answer.
//
// What this command will never do: relax
// `kernel.apparmor_restrict_unprivileged_userns`, grant the AppArmor profile
// to a path that is not the pin's, overwrite an operator's declared value
// (a conflicting `environment` or `.env` key is a named refusal carrying the
// two values, not a silent edit), or pick the one
// container-runtime fact a host must answer for itself.

/// The packaged node-environment declaration, probed beside this binary.
const PACKAGED_NODE_ENVIRONMENT: &str = "share/kata/node-environment.toml";
/// The packaged provider bytes directory, probed beside this binary.
const PACKAGED_PROVIDER_SOURCE: &str = "share/kata/provider-source";

/// The packaged declaration of the provider-entry member kata does not build,
/// probed beside this binary: `ip = "<iproute2 store path>/bin/ip"`.
const PACKAGED_PROVIDER_MEMBERS: &str = "share/kata/provider-members.toml";

/// The members a provider-source directory holds — the ones kata builds: the
/// executable `provider_store`'s joint 1 requires (`kata-provider-<name>`), the
/// egress `createContainer` hook (`oci_driver`'s `OCI_HOOK_BINARY`), and the
/// static init of a nanocode agent capsule ([`PROVIDER_TOOLHOST_MEMBER`]). An
/// entry missing one provisions fine and then refuses the capsules that need it
/// at drive time — the earlier the naming, the better.
const PROVIDER_SOURCE_MEMBERS: [&str; 3] = [
    "kata-provider-youki",
    "kata-oci-hook",
    PROVIDER_TOOLHOST_MEMBER,
];

/// The capsule init's place in a provider entry: the one file of the
/// `toolhost/` directory `ResolvedProvider::toolhost_dir` binds at `/.kata`
/// (`kata_worker::provider_store::{TOOLHOST_DIRECTORY, TOOLHOST_PROGRAM}`).
const PROVIDER_TOOLHOST_MEMBER: &str = "toolhost/kata-toolhost";

/// The target a checkout builds the toolhost for: static musl, because a
/// capsule's root filesystem has no dynamic loader. Its build lands under the
/// Cargo target directory's `<this>/<profile>/`, not beside `kata`.
const TOOLHOST_TARGET: &str = "x86_64-unknown-linux-musl";

/// The iproute2 member `kata-oci-hook loopback-up` execs (`oci_driver`'s
/// `OCI_HOOK_IP`). kata neither builds nor ships it: the provider entry
/// receives a verbatim copy of the regular file a Nix store path declares.
const PROVIDER_IP_MEMBER: &str = "ip";

/// The packaged tree beside the binary, under its prefix (`<exe>/..`). When it
/// exists it is the only answer: a package never reads a checkout.
const PACKAGED_SHARE: &str = "share/kata";

/// The checkout's Nix expression for the two `share/kata` declarations — the
/// file the flake's package installs them from. A checkout build realises it
/// in place of a packaged tree.
const CHECKOUT_SHARE_EXPRESSION: &str = "nix/share.nix";

/// The checkout's youki expression: the pin's `realised_by` command builds it.
const CHECKOUT_YOUKI_EXPRESSION: &str = "nix/youki.nix";

/// The GC-root link name the checkout's `share/kata` build is rooted under.
const CHECKOUT_SHARE_ROOT: &str = "kata-share";

/// Where `kata host setup` finds what this binary does not carry: the provider
/// members kata builds, the two `share/kata` declarations, and the youki pin's
/// realisation.
#[derive(Debug)]
enum Companions {
    /// The flake package's layout, `<prefix>/share/kata/…` with `<prefix>` =
    /// `<exe>/..`. Also the answer when neither layout is present: the
    /// refusals then name these paths as probed.
    Packaged { prefix: Option<PathBuf> },
    /// A Cargo build inside a kata checkout's `target/`, with no packaged tree:
    /// the provider members are this binary's siblings (`cargo build
    /// --release` builds all four shipped binaries) and the musl toolhost of
    /// the same profile ([`checkout_member`]), and the declarations and the
    /// youki are built by `nix-build` from the checkout's own expressions.
    Checkout {
        /// The checkout root.
        root: PathBuf,
        /// The directory the running executable is in.
        bin_dir: PathBuf,
    },
}

impl Companions {
    fn of(exe_dir: &Path) -> Self {
        let prefix = exe_dir.parent().map(Path::to_path_buf);
        let packaged = prefix
            .as_ref()
            .is_some_and(|prefix| prefix.join(PACKAGED_SHARE).is_dir());
        if !packaged && let Some(root) = checkout_root(exe_dir) {
            return Self::Checkout {
                root,
                bin_dir: exe_dir.to_path_buf(),
            };
        }
        Self::Packaged { prefix }
    }
}

/// The kata checkout `exe_dir` is a Cargo build in: the nearest ancestor
/// holding a `Cargo.toml` and [`CHECKOUT_SHARE_EXPRESSION`], and only when
/// `exe_dir` lies under that ancestor's `target/`. A binary copied out of the
/// target tree — or built into a `CARGO_TARGET_DIR` elsewhere — is not a
/// checkout build, the same line the workflow library draws
/// (`kata_program::library::resolve_default_roots`). The running executable's
/// path is resolved (`/proc/self/exe`), so a link on `PATH` to
/// `target/release/kata` is a checkout build.
fn checkout_root(exe_dir: &Path) -> Option<PathBuf> {
    exe_dir
        .ancestors()
        .find(|ancestor| {
            ancestor.join("Cargo.toml").is_file()
                && ancestor.join(CHECKOUT_SHARE_EXPRESSION).is_file()
        })
        .filter(|root| exe_dir.starts_with(root.join("target")))
        .map(Path::to_path_buf)
}

/// `nix-build --out-link <link> <expression>`: builds (or substitutes) the
/// expression's derivation and roots the result at `link`, printing the store
/// path. The classic command, so a checkout build needs Nix installed and no
/// experimental feature enabled.
fn nix_build_argv(link: &Path, expression: &Path) -> Vec<String> {
    vec![
        "nix-build".to_string(),
        "--out-link".to_string(),
        link.display().to_string(),
        expression.display().to_string(),
    ]
}

/// The prefix the two `share/kata` declarations are read under, resolved at
/// most once per run and only when a step needs a declaration no flag
/// supplied: the package's own prefix, or — for a checkout build — the
/// `nix/share.nix` build, rooted under `.kata/nix-roots`.
struct Declarations<'a> {
    companions: &'a Companions,
    roots: PathBuf,
    built: Option<PathBuf>,
}

impl Declarations<'_> {
    fn prefix(
        &mut self,
        exec: &mut dyn FnMut(&[String]) -> Result<String, String>,
    ) -> Result<Option<PathBuf>, SetupRefusal> {
        let root = match self.companions {
            Companions::Packaged { prefix } => return Ok(prefix.clone()),
            Companions::Checkout { root, .. } => root,
        };
        if let Some(built) = &self.built {
            return Ok(Some(built.clone()));
        }
        let argv = nix_build_argv(
            &self.roots.join(CHECKOUT_SHARE_ROOT),
            &root.join(CHECKOUT_SHARE_EXPRESSION),
        );
        let refusal = |error: String| SetupRefusal::CheckoutBuild {
            argv: argv.join(" "),
            error,
        };
        std::fs::create_dir_all(&self.roots).map_err(|error| refusal(error.to_string()))?;
        let output = exec(&argv).map_err(refusal)?;
        let built = output
            .lines()
            .last()
            .map(PathBuf::from)
            .filter(|path| path.join(PACKAGED_SHARE).is_dir())
            .ok_or_else(|| {
                refusal(format!(
                    "it printed {output:?}, not a store path holding `{PACKAGED_SHARE}`"
                ))
            })?;
        self.built = Some(built.clone());
        Ok(Some(built))
    }
}

/// `kata host setup`'s arguments, lifted from the clap surface into one
/// struct so the injected rig and the CLI stay in lockstep.
#[derive(Debug)]
pub struct HostSetupArgs {
    /// The project config to write (`--config`, default `.kata/kata.toml`).
    pub config: PathBuf,
    /// Whether to run `sudo kata host apparmor-install` when the profile is
    /// not installed and loaded (`--install-apparmor`).
    pub install_apparmor: bool,
    /// An explicit `[node] environment` declaration file (`--environment-file`).
    pub environment_file: Option<PathBuf>,
    /// An explicit provider-source directory (`--provider-source`).
    pub provider_source: Option<PathBuf>,
    /// An explicit iproute2 `ip` under the Nix store (`--provider-ip`).
    pub provider_ip: Option<PathBuf>,
}

/// One step's disposition in the [`HostSetupReport`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StepStatus {
    /// The state the step wants was already true; nothing moved.
    InPlace,
    /// The step made its change.
    Changed,
    /// The step cannot complete without an operator action (root, or a
    /// declaration only the operator can place); the action is named in
    /// `actions`, and the run reports `incomplete` until it lands.
    Deferred,
    /// The step was already satisfied another way and did nothing.
    Skipped,
    /// The step refused; the run stopped at it.
    Refused,
}

/// One named step of the run, in the shape `--format json` emits.
#[derive(Debug, Clone, Serialize)]
pub struct SetupStep {
    /// The step's stable name (`platform`, `nix`, `youki`, …).
    pub name: &'static str,
    /// Its disposition.
    pub status: StepStatus,
    /// What was observed or done, in one line.
    pub detail: String,
}

/// What `kata host setup` did and observed, in the shape `--format json`
/// emits.
#[derive(Debug, Serialize)]
pub struct HostSetupReport {
    /// Discriminates this payload for a machine reader.
    pub summary_kind: &'static str,
    /// The `--config` path the run wrote or merged into.
    pub config: String,
    /// Every step that ran, in order — the last is `refused` when the run
    /// stopped early, or `doctor` when it reached the verdict.
    pub steps: Vec<SetupStep>,
    /// Operator actions the run could not perform itself (the root-only
    /// AppArmor install, spelled exactly).
    pub actions: Vec<String>,
    /// The doctor verdict, when the run reached it.
    pub doctor: Option<DoctorVerdict>,
    /// Whether ANY step moved a byte — the idempotence evidence a second run
    /// prints `false` for.
    pub changed: bool,
    /// Whether the run completed: no step refused, nothing deferred to the
    /// operator, and doctor passed.
    pub complete: bool,
}

/// The doctor verdict as the report records it — the counts, not the rows;
/// the human render prints the failing rows themselves.
#[derive(Debug, Serialize)]
pub struct DoctorVerdict {
    /// `kata doctor`'s `passed` — zero `[fail]` rows.
    pub passed: bool,
    /// Its `[fail]` count.
    pub failure_count: usize,
    /// Its `[warn]` count.
    pub warning_count: usize,
    /// The failing rows' names, for a machine reader.
    pub failed_checks: Vec<String>,
}

/// Why `kata host setup` stopped — one variant per named refusal, each
/// leading its `Display` with the token a script keys on.
#[derive(Debug)]
pub enum SetupRefusal {
    /// The build is not Linux x86-64 — the only platform the shipped
    /// containment plane targets.
    HostPlatform {
        /// `std::env::consts::OS`.
        os: &'static str,
        /// `std::env::consts::ARCH`.
        arch: &'static str,
    },
    /// `nix-store --version` could not be run — environment realisation and
    /// GC rooting need it.
    NixAbsent {
        /// The argv attempted.
        argv: String,
        /// Why it failed.
        error: String,
    },
    /// `nix store info` refused — the `nix` command the main runs at boot and for every
    /// declared environment (`nix store info`, `nix path-info`, `nix store verify`) needs
    /// Nix's `nix-command` feature and a reachable store, which `nix-store` does not.
    NixCommandUnavailable {
        /// The argv attempted.
        argv: String,
        /// Why it failed: nix's own text, which says which of the two it was.
        error: String,
    },
    /// `unprivileged_userns_clone` is 0 — a sysctl explicitly forbids what a
    /// rootless container needs, and this command never touches it.
    UsernsRefused {
        /// The knob read.
        knob: String,
    },
    /// The delegation probe could not prove memory+pids usable.
    Delegation {
        /// The folded refusal's own text.
        detail: String,
    },
    /// The pinned youki is absent and `nix-store --realise` could not deliver
    /// it — the cache miss leaves the operator's `realised_by` recourse.
    YoukiUnrealisable {
        /// The pinned path.
        store_path: String,
        /// The pin's `realised_by` text.
        realised_by: String,
        /// Why the realise failed.
        error: String,
    },
    /// `--install-apparmor` ran `sudo kata host apparmor-install` and the
    /// prerequisite still does not hold — the certification's fold still refuses,
    /// or, with the load unreadable, a rootless container still does not start.
    ApparmorInstall {
        /// The argv run.
        argv: String,
        /// What the post-install state still is.
        detail: String,
    },
    /// A rootless container of the pinned runtime did not start, and not for an
    /// AppArmor reason: the throwaway bundle could not be prepared, or the
    /// runtime's refusal names neither AppArmor nor a capability denial. No
    /// profile install changes that, so none is offered or run.
    ContainerStart {
        /// The certification's token (`functional_harness`,
        /// `functional_run_refused`).
        token: &'static str,
        /// The certification's refusal text.
        detail: String,
    },
    /// A checkout build's `nix-build` of the checkout's own expression failed
    /// — the youki pin's, or the `share/kata` declarations'.
    CheckoutBuild {
        /// The argv run.
        argv: String,
        /// Why it failed.
        error: String,
    },
    /// No provider-source directory was found — neither `--provider-source`,
    /// the packaged `share/kata/provider-source`, nor a checkout build's
    /// siblings.
    ProviderSourceAbsent {
        /// Every path probed.
        probed: Vec<String>,
    },
    /// The provider source lacks a member the provider's consumers resolve.
    ProviderSourceIncomplete {
        /// The directory read.
        source: String,
        /// The missing member names.
        missing: Vec<String>,
    },
    /// The provider source holds an `ip` of its own (the layout before `ip`
    /// was declared by store path). The entry's `ip` comes only from the
    /// declaration, so the source's is refused rather than used or ignored.
    ProviderSourceHoldsIp {
        /// The source's `ip`.
        path: String,
    },
    /// No iproute2 `ip` was declared — neither `--provider-ip` nor the
    /// packaged `share/kata/provider-members.toml`.
    ProviderIpAbsent {
        /// Every path probed.
        probed: Vec<String>,
    },
    /// The provider-member declaration file could not be read or parsed.
    ProviderIpDeclaration {
        /// The declaration file.
        path: String,
        /// What went wrong.
        error: String,
    },
    /// The declared `ip` is not a regular executable file under the Nix store.
    ProviderIpUnusable {
        /// The path as declared.
        declared: String,
        /// Why it cannot be the provider entry's `ip`.
        reason: String,
    },
    /// The environment kata was launched with — not a value `.env` supplied —
    /// already declares a DIFFERENT provider fact than the one this run
    /// provisioned: writing `.env` would be inert (dotenvy never overrides),
    /// so the two answers must be named instead.
    ProviderEnvConflict {
        /// The env key that differs.
        key: &'static str,
        /// The ambient value the node would actually use.
        ambient: String,
        /// The value this run provisioned.
        provisioned: String,
    },
    /// `ProviderStore::provision` refused, quoted.
    ProviderProvision {
        /// The source dir offered.
        source: String,
        /// The store's own text.
        error: String,
    },
    /// `.env` already declares a different value for a key this run must
    /// write — kata never overwrites an operator's declaration.
    EnvFileConflict {
        /// The `.env` path.
        path: String,
        /// The key.
        key: String,
        /// The declared value.
        existing: String,
        /// The required value.
        required: String,
    },
    /// The config declares no `[node] environment` and no declaration source
    /// exists — `--environment-file` was not passed and the packaged
    /// `share/kata/node-environment.toml` is absent.
    EnvironmentSourceAbsent {
        /// Every path probed.
        probed: Vec<String>,
    },
    /// The `--environment-file` given could not be read or parsed.
    EnvironmentFile {
        /// The path.
        path: String,
        /// What went wrong.
        error: String,
    },
    /// A declared environment store path could not be realised and rooted.
    EnvironmentRealise {
        /// The store path.
        store_path: String,
        /// Why it failed.
        error: String,
    },
    /// The existing config holds a value that conflicts with a declaration
    /// this run must make — the keyed diff is carried for the report.
    ConfigConflict {
        /// The config path.
        path: String,
        /// The rendered `required` vs `found` lines.
        diff: String,
    },
    /// The config file exists but does not parse.
    ConfigUnparseable {
        /// The config path.
        path: String,
        /// The parse error.
        error: String,
    },
    /// The init scaffold could not produce the project tree.
    Scaffold {
        /// The scaffold's own error text.
        error: String,
    },
    /// A filesystem write this run owns failed.
    Write {
        /// What was being written.
        path: String,
        /// The I/O error.
        error: String,
    },
}

impl std::fmt::Display for SetupRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::HostPlatform { os, arch } => write!(
                f,
                "host_platform: this build is {os}/{arch}; the shipped containment plane targets \
                 Linux x86-64 only."
            ),
            Self::NixAbsent { argv, error } => write!(
                f,
                "nix_absent: `{argv}` failed: {error}. Nix realises and GC-roots the pinned youki \
                 and the declared environment closure; install it and re-run."
            ),
            Self::NixCommandUnavailable { argv, error } => write!(
                f,
                "nix_command_unavailable: `{argv}` failed: {error}. kata's main runs the `nix` \
                 command at boot and for every declared environment, which needs Nix's \
                 `nix-command` feature (`experimental-features = nix-command` in nix.conf; \
                 `~/.config/nix/nix.conf` for your user) and a running Nix daemon. Enable the \
                 feature or start the daemon, whichever nix named, and re-run."
            ),
            Self::UsernsRefused { knob } => write!(
                f,
                "userns_refused: `{knob}` is 0 — this host explicitly forbids unprivileged user \
                 namespaces, which a rootless container cannot run without. That is a sysctl an \
                 operator sets, never one kata relaxes."
            ),
            Self::Delegation { detail } => {
                write!(f, "delegation_incomplete: {detail}")
            }
            Self::YoukiUnrealisable {
                store_path,
                realised_by,
                error,
            } => write!(
                f,
                "binary_absent: the pinned youki is not at `{store_path}` and `nix-store \
                 --realise` could not deliver it ({error}). Realise it from a kata checkout with \
                 `{realised_by}`, or install kata through its flake so the pin is part of the \
                 closure."
            ),
            Self::CheckoutBuild { argv, error } => write!(
                f,
                "checkout_build_failed: `{argv}` failed: {error}. A checkout build of kata \
                 realises the pinned youki and its `share/kata` declarations from the \
                 checkout's own Nix expressions. When `nix-build` ran, its log streamed to the \
                 terminal above this report; fix the build and re-run."
            ),
            Self::ApparmorInstall { argv, detail } => write!(
                f,
                "apparmor_install_failed: `{argv}` ran but the AppArmor prerequisite still does \
                 not hold: {detail}"
            ),
            Self::ContainerStart { token, detail } => write!(
                f,
                "{token}: a rootless container of the pinned youki did not start, and not for an \
                 AppArmor reason, so installing the AppArmor profile is not its recourse: \
                 {detail}"
            ),
            Self::ProviderSourceAbsent { probed } => write!(
                f,
                "provider_source_absent: no `kata-provider-youki` source directory found; probed \
                 {probed:?}. Run kata from a checkout build (`target/release/kata`, or a link \
                 to it, beside the provider members `cargo build --release` builds, with the \
                 static toolhost `cargo build --release --locked --target \
                 {TOOLHOST_TARGET} -p kata-toolhost` builds), install kata through its flake \
                 (which ships `share/kata/provider-source`), or pass `--provider-source`."
            ),
            Self::ProviderSourceIncomplete { source, missing } => write!(
                f,
                "provider_source_incomplete: `{source}` lacks {} — the `youki` provider's \
                 consumers resolve every member it ships.",
                missing.join(", ")
            ),
            Self::ProviderSourceHoldsIp { path } => write!(
                f,
                "provider_source_holds_ip: `{path}` is in the provider source, which holds only \
                 the members kata builds ({}). The provider entry's `ip` is copied from the Nix \
                 store path `share/kata/provider-members.toml` declares, or from \
                 `--provider-ip`; a source's own `ip` is not used. Remove it from the source \
                 directory.",
                PROVIDER_SOURCE_MEMBERS.join(", ")
            ),
            Self::ProviderIpAbsent { probed } => write!(
                f,
                "provider_ip_absent: no iproute2 `ip` is declared for the provider entry; probed \
                 {probed:?}. Run kata from a checkout build (which builds the declaration from \
                 `{CHECKOUT_SHARE_EXPRESSION}`), install kata through its flake (which ships \
                 `share/kata/provider-members.toml`), or pass `--provider-ip` naming an `ip` \
                 under `{NIX_STORE_DIRECTORY}`."
            ),
            Self::ProviderIpDeclaration { path, error } => write!(
                f,
                "provider_ip_declaration: `{path}` could not be used as the provider-member \
                 declaration: {error}"
            ),
            Self::ProviderIpUnusable { declared, reason } => write!(
                f,
                "provider_ip_unusable: the declared `ip` `{declared}` {reason}. The provider \
                 entry copies `ip` verbatim from a regular executable file under \
                 `{NIX_STORE_DIRECTORY}`."
            ),
            Self::ProviderEnvConflict {
                key,
                ambient,
                provisioned,
            } => write!(
                f,
                "provider_env_conflict: the environment kata was launched with declares \
                 `{key}={ambient}`, but this run provisioned `{provisioned}` — and `.env` never \
                 overrides a launch value, so writing it would be a lie. Unset it in the \
                 launching shell or re-run against its store."
            ),
            Self::ProviderProvision { source, error } => {
                write!(f, "provider_provision_failed: `{source}`: {error}")
            }
            Self::EnvFileConflict {
                path,
                key,
                existing,
                required,
            } => write!(
                f,
                "env_file_conflict: `{path}` already declares `{key}={existing}`; this run needs \
                 `{key}={required}`. kata never overwrites an operator's declaration — edit \
                 `{path}` or unset the key."
            ),
            Self::EnvironmentSourceAbsent { probed } => write!(
                f,
                "node_environment_source_absent: the config declares no `[node] environment` \
                 and no declaration source exists; probed {probed:?}. Run kata from a checkout \
                 build (which builds the declaration from `{CHECKOUT_SHARE_EXPRESSION}`), \
                 install kata through its flake (which ships \
                 `share/kata/node-environment.toml`), or pass `--environment-file` (`just \
                 node-environment` prints one)."
            ),
            Self::EnvironmentFile { path, error } => write!(
                f,
                "node_environment_file: `{path}` could not be used as an `[node] environment` \
                 declaration: {error}"
            ),
            Self::EnvironmentRealise { store_path, error } => write!(
                f,
                "node_environment_realise: `{store_path}` could not be realised and rooted: \
                 {error}"
            ),
            Self::ConfigConflict { path, diff } => write!(
                f,
                "config_conflict: `{path}` declares values this run must change, and kata never \
                 overwrites an operator's declaration:\n{diff}\nEdit the config or pass \
                 `--config` at a fresh one."
            ),
            Self::ConfigUnparseable { path, error } => {
                write!(
                    f,
                    "config_unparseable: `{path}` does not parse as TOML: {error}"
                )
            }
            Self::Scaffold { error } => {
                write!(
                    f,
                    "scaffold_failed: the project scaffold could not run: {error}"
                )
            }
            Self::Write { path, error } => {
                write!(f, "write_failed: could not write `{path}`: {error}")
            }
        }
    }
}

impl std::error::Error for SetupRefusal {}

/// The filesystem and executable seams the testable core reads through —
/// production values at construction, scratch values under test.
struct Probes {
    /// Debian/Ubuntu's `unprivileged_userns_clone` knob (absent means allowed).
    userns_clone_knob: PathBuf,
    /// `kernel.apparmor_restrict_unprivileged_userns` — recorded, never a refusal.
    userns_restriction_knob: PathBuf,
    /// The kernel's loaded-profile list.
    apparmor_loaded: PathBuf,
    /// The installed-profile directory.
    apparmor_dir: PathBuf,
    /// `current_exe()`'s parent — the packaged `../share/kata/…` anchors here.
    exe_dir: PathBuf,
    /// The Nix store directory a declared `ip` must resolve under.
    nix_store: PathBuf,
    /// The executable `sudo` re-invokes for `host apparmor-install`.
    exe: PathBuf,
    /// The certification's functional arm — one rootless `/bin/true` container
    /// of the pinned runtime — answering with the id of the container that ran.
    functional: fn(&YoukiPin) -> Result<String, OciPrerequisiteRefusal>,
}

impl Probes {
    fn production() -> anyhow::Result<Self> {
        let exe = std::env::current_exe().context("resolving this process's own path")?;
        let exe_dir = exe
            .parent()
            .map_or_else(|| PathBuf::from("."), Path::to_path_buf);
        Ok(Self {
            userns_clone_knob: PathBuf::from("/proc/sys/kernel/unprivileged_userns_clone"),
            userns_restriction_knob: PathBuf::from(
                kata_worker::oci_runtime::USERNS_RESTRICTION_KNOB,
            ),
            apparmor_loaded: PathBuf::from(kata_worker::oci_runtime::APPARMOR_LOADED_PROFILES),
            apparmor_dir: PathBuf::from(kata_worker::oci_runtime::APPARMOR_PROFILE_DIRECTORY),
            exe_dir,
            exe,
            nix_store: PathBuf::from(NIX_STORE_DIRECTORY),
            functional: kata_worker::oci_runtime::run_functional_probe,
        })
    }
}

/// Run a step, recording its row either way: the `refused` row is pushed
/// BEFORE the refusal propagates, so the report always ends on the step that
/// stopped the run.
fn run_step<T>(
    steps: &mut Vec<SetupStep>,
    name: &'static str,
    f: impl FnOnce() -> Result<(SetupStep, T), SetupRefusal>,
) -> Result<T, SetupRefusal> {
    match f() {
        Ok((step, value)) => {
            steps.push(step);
            Ok(value)
        }
        Err(refusal) => {
            steps.push(SetupStep {
                name,
                status: StepStatus::Refused,
                detail: refusal.to_string(),
            });
            Err(refusal)
        }
    }
}

fn step(name: &'static str, status: StepStatus, detail: String) -> SetupStep {
    SetupStep {
        name,
        status,
        detail,
    }
}

/// The AppArmor state a `host setup` run observes: the certification's own
/// AppArmor fold ([`kata_worker::oci_runtime::fold_apparmor_prerequisite`]) over
/// the same two reads — never a second detector.
enum ApparmorState {
    /// The fold admits, and the name is in the kernel's loaded list.
    Ready,
    /// The fold refuses — the name is not loaded, or the installed file is
    /// absent, unreadable or not the render — and the install verb fixes that.
    NeedsInstall(String),
    /// The fold admits with the loaded-profile list UNREADABLE (it needs root):
    /// the installed file is provably the render, and whether it is LOADED is
    /// not observable from this process's read of the list.
    InstalledLoadUnread,
}

/// What a rootless container of the pinned runtime STARTING shows about an
/// installed profile whose load this process cannot read — which depends on the
/// kernel. Under `apparmor_restrict_unprivileged_userns` the start is refused
/// unless a profile admitting the runtime is in force, so it observes one. On an
/// unrestricted (or unreadable) kernel the start succeeds with no profile loaded,
/// so it observes nothing about the load, and the text says so. Either way the
/// pair — an unknown load and a container that ran — is what `certify_youki`
/// admits.
fn unread_load_observed(probes: &Probes, container: &str) -> String {
    let restriction = kata_worker::oci_runtime::fold_userns_restriction(
        std::fs::read_to_string(&probes.userns_restriction_knob)
            .as_deref()
            .map_err(std::string::ToString::to_string),
    );
    match restriction {
        UsernsRestriction::Restricted => format!(
            "the kernel's loaded-profile list needs root to read, and this kernel restricts \
             unprivileged user namespaces, so the pinned runtime starting the rootless container \
             `{container}` shows a profile admitting it is in force — the certification's own \
             observation"
        ),
        UsernsRestriction::Unrestricted | UsernsRestriction::Unknown => format!(
            "the pinned runtime started the rootless container `{container}`, as the \
             certification requires; whether the profile is loaded needs root to read, and the \
             load is NOT observed: this kernel's user-namespace restriction reads `{}`, and a \
             kernel that does not restrict unprivileged user namespaces starts the container \
             with no profile loaded, so the start decides nothing about the load",
            restriction.label()
        ),
    }
}

/// The certification's functional arm refused, read for its recourse: an
/// AppArmor-shaped run refusal (stderr naming AppArmor, or the EPERM an
/// unprofiled runtime takes on a restricted kernel) is one the profile install
/// may fix, and is `Ok` for the caller to word. Every other refusal — a harness
/// that started no container, a run refused for an unclassified reason — is the
/// `ContainerStart` refusal, which offers no install.
fn apparmor_recourse(
    refusal: OciPrerequisiteRefusal,
) -> Result<OciPrerequisiteRefusal, SetupRefusal> {
    match refusal {
        OciPrerequisiteRefusal::FunctionalRunRefused {
            denial: FunctionalDenial::AppArmorNamed | FunctionalDenial::CapabilityDenied,
            ..
        } => Ok(refusal),
        other => Err(SetupRefusal::ContainerStart {
            token: other.token(),
            detail: other.to_string(),
        }),
    }
}

fn apparmor_state(pin: &YoukiPin, probes: &Probes) -> ApparmorState {
    let installed_path = probes.apparmor_dir.join(pin.profile_name());
    let read = match std::fs::read_to_string(&installed_path) {
        Ok(text) => InstalledProfileRead::Text(text),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => InstalledProfileRead::Absent,
        Err(error) => InstalledProfileRead::Unreadable(error.to_string()),
    };
    match kata_worker::oci_runtime::fold_apparmor_prerequisite(
        pin,
        std::fs::read_to_string(&probes.apparmor_loaded)
            .as_deref()
            .map_err(std::string::ToString::to_string),
        &installed_path.display().to_string(),
        read,
    ) {
        Ok(prerequisite) if prerequisite.profile == ApparmorProfile::Loaded => ApparmorState::Ready,
        Ok(_) => ApparmorState::InstalledLoadUnread,
        Err(refusal) => ApparmorState::NeedsInstall(refusal.to_string()),
    }
}

/// A `[node] environment` declaration, read out of a `node-environment.toml`
/// file's `[node]` table.
#[derive(Debug)]
struct EnvironmentDeclaration {
    /// The TOML item to merge under `[node] environment`.
    item: toml_edit::Item,
    /// The `store_paths` it declares — each must be realised and rooted.
    store_paths: Vec<String>,
}

/// The `store_paths` strings out of an `[node] environment` TOML item — the
/// reader for a declaration that came from the CONFIG rather than a file, so
/// its `store_paths` shape was never validated by [`parse_environment_file`].
fn env_item_store_paths(item: &toml_edit::Item) -> Vec<String> {
    item.get("store_paths")
        .and_then(toml_edit::Item::as_array)
        .map(|paths| {
            paths
                .iter()
                .filter_map(|p| p.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default()
}

fn parse_environment_file(path: &Path) -> Result<EnvironmentDeclaration, SetupRefusal> {
    let error = |error: String| SetupRefusal::EnvironmentFile {
        path: path.display().to_string(),
        error,
    };
    let text = std::fs::read_to_string(path).map_err(|e| error(e.to_string()))?;
    let document = text
        .parse::<toml_edit::DocumentMut>()
        .map_err(|e| error(format!("not valid TOML: {e}")))?;
    let item = document
        .get("node")
        .and_then(|node| node.get("environment"))
        .ok_or_else(|| error("no `[node] environment` key".to_string()))?;
    let store_paths = item
        .get("store_paths")
        .and_then(toml_edit::Item::as_array)
        .ok_or_else(|| error("`environment.store_paths` is not an array".to_string()))?
        .iter()
        .map(|value| {
            value
                .as_str()
                .map(str::to_string)
                .ok_or_else(|| error("a `store_paths` entry is not a string".to_string()))
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(EnvironmentDeclaration {
        item: item.clone(),
        store_paths,
    })
}

/// Which `[node] environment` declaration this run stands behind, and the
/// store paths that answer must realise.
///
/// The resolution is exact, never a silent pick:
///
/// * `--environment-file` is the one explicit second answer: passed against a
///   config that declares a DIFFERENT closure it is a `config_conflict`,
///   because rewriting the environment under a declared node is never
///   setup's call;
/// * the config's own declaration otherwise STANDS — including against the
///   packaged `share/kata/node-environment.toml`. That file is the default
///   for a node that declares nothing, not a truth an existing declaration
///   is compared against: an upgrade that moved the packaged closure, or an
///   operator's intentionally different declaration, must not deadlock the
///   setup command. It is not even read when a declaration exists, so a
///   malformed packaged file is irrelevant to a declared node;
/// * config silent + a source: that answer is merged;
/// * neither: `node_environment_source_absent`, naming every path probed.
///
/// `declarations` answers the prefix the default is read under (see
/// [`Declarations`]); it is asked only when the default is the answer, so a
/// checkout build builds nothing for a node that already declares one.
fn resolve_environment(
    args: &HostSetupArgs,
    declarations: &mut dyn FnMut() -> Result<Option<PathBuf>, SetupRefusal>,
    config: &Path,
    declared: Option<&toml_edit::Item>,
) -> Result<(Option<toml_edit::Item>, Vec<String>), SetupRefusal> {
    if let Some(path) = &args.environment_file {
        let file = parse_environment_file(path)?;
        if let Some(existing) = declared
            && !toml_items_equal(existing, &file.item)
        {
            return Err(SetupRefusal::ConfigConflict {
                path: config.display().to_string(),
                diff: format!(
                    "  environment: the config declares a different closure than \
                     `--environment-file` — found\n{existing}\n  required\n{}",
                    file.item
                ),
            });
        }
        return Ok((
            Some(declared.map_or_else(|| file.item.clone(), Clone::clone)),
            declared.map_or_else(|| file.store_paths.clone(), env_item_store_paths),
        ));
    }
    if let Some(existing) = declared {
        return Ok((Some(existing.clone()), env_item_store_paths(existing)));
    }
    let packaged = declarations()?.map(|prefix| prefix.join(PACKAGED_NODE_ENVIRONMENT));
    let Some(path) = packaged.as_ref().filter(|path| path.is_file()) else {
        return Err(SetupRefusal::EnvironmentSourceAbsent {
            probed: vec![
                "<--environment-file not passed>".to_string(),
                packaged.map_or_else(
                    || format!("<exe parent>/{PACKAGED_NODE_ENVIRONMENT}"),
                    |p| p.display().to_string(),
                ),
            ],
        });
    };
    let file = parse_environment_file(path)?;
    Ok((Some(file.item), file.store_paths))
}

/// The packaged provider-member declaration's shape: the one member kata does
/// not build, by the path its store object installs it at.
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct ProviderMembersDeclaration {
    ip: PathBuf,
}

/// The iproute2 `ip` this run copies into the provider entry, resolved to the
/// regular file it names.
///
/// `--provider-ip` is the explicit answer; otherwise the packaged
/// `share/kata/provider-members.toml` under the [`Declarations`] prefix
/// declares it (beside this binary, or built from a checkout), and neither is
/// `provider_ip_absent`. The declared path is resolved through
/// every link to the file it names, and that file must be a regular,
/// executable file under the Nix store — anything else is
/// `provider_ip_unusable`, naming the declared path and why. The RESOLVED
/// path is what the store copies, so a link (a profile's `bin/ip`) is never
/// what lands in the entry.
fn resolve_provider_ip(
    args: &HostSetupArgs,
    probes: &Probes,
    declarations: &mut dyn FnMut() -> Result<Option<PathBuf>, SetupRefusal>,
) -> Result<PathBuf, SetupRefusal> {
    let declared = if let Some(path) = &args.provider_ip {
        path.clone()
    } else {
        let packaged = declarations()?.map(|prefix| prefix.join(PACKAGED_PROVIDER_MEMBERS));
        let Some(path) = packaged.as_ref().filter(|path| path.is_file()) else {
            return Err(SetupRefusal::ProviderIpAbsent {
                probed: vec![
                    "<--provider-ip not passed>".to_string(),
                    packaged.map_or_else(
                        || format!("<exe parent>/{PACKAGED_PROVIDER_MEMBERS}"),
                        |p| p.display().to_string(),
                    ),
                ],
            });
        };
        let error = |error: String| SetupRefusal::ProviderIpDeclaration {
            path: path.display().to_string(),
            error,
        };
        let text = std::fs::read_to_string(path).map_err(|e| error(e.to_string()))?;
        toml::from_str::<ProviderMembersDeclaration>(&text)
            .map_err(|e| error(e.to_string()))?
            .ip
    };
    let unusable = |reason: String| SetupRefusal::ProviderIpUnusable {
        declared: declared.display().to_string(),
        reason,
    };
    let real = std::fs::canonicalize(&declared)
        .map_err(|e| unusable(format!("does not resolve to a file: {e}")))?;
    if !real.starts_with(&probes.nix_store) {
        return Err(unusable(format!(
            "resolves to `{}`, outside `{}`",
            real.display(),
            probes.nix_store.display()
        )));
    }
    let metadata = std::fs::metadata(&real)
        .map_err(|e| unusable(format!("resolves to `{}`: {e}", real.display())))?;
    if !metadata.is_file() {
        return Err(unusable(format!(
            "resolves to `{}`, which is not a regular file",
            real.display()
        )));
    }
    if std::os::unix::fs::PermissionsExt::mode(&metadata.permissions()) & 0o111 == 0 {
        return Err(unusable(format!(
            "resolves to `{}`, which is not executable",
            real.display()
        )));
    }
    Ok(real)
}

/// Compare two TOML items by VALUE, not by rendering: a `[node.environment]`
/// TABLE and an `environment = { … }` inline table carrying the same keys are
/// the same declaration, as is a key order difference — a byte compare could
/// never say so. Each item is inserted under a scratch key (a bare TOML value
/// — and a table item in particular, which renders as a `[header]` line, is
/// not a parseable value on its own), read back through the strict 1.0 parser,
/// and canonicalized to JSON so `toml`'s distinct `Table`/`InlineTable`
/// variants do not split the same answer into two.
fn toml_items_equal(a: &toml_edit::Item, b: &toml_edit::Item) -> bool {
    let canonical = |item: &toml_edit::Item| -> Option<serde_json::Value> {
        let mut doc = toml_edit::DocumentMut::new();
        doc["__v"] = item.clone();
        doc.to_string()
            .parse::<toml::Value>()
            .ok()
            .and_then(|parsed| parsed.get("__v").cloned())
            .and_then(|value| serde_json::to_value(value).ok())
    };
    match (canonical(a), canonical(b)) {
        (Some(left), Some(right)) => left == right,
        _ => a.to_string() == b.to_string(),
    }
}

/// The merge `kata host setup` performs on a `kata.toml`, expressed on its
/// TEXT so a test plants strings and never touches a path. Returns the new
/// document text and the applied-change lines; a conflict is the refusal.
///
/// `replace_template_defaults` distinguishes the two sources a differing
/// `environment` can have: when THIS run scaffolded the file a template
/// placeholder is kata's own, so replacing it is the point of the run; when
/// the file predates the run a differing value is an operator's declaration,
/// and kata refuses rather than overwrite it.
///
/// A `[node]` key the section does not declare (no row in
/// [`kata_types::config::node_knob_registry`]) is a conflict too: the loader
/// refuses it at the next start, so the merge refuses it before writing.
fn merge_oci_config(
    path: &Path,
    text: &str,
    environment: Option<&toml_edit::Item>,
    replace_template_defaults: bool,
) -> Result<(String, Vec<String>), SetupRefusal> {
    let mut document =
        text.parse::<toml_edit::DocumentMut>()
            .map_err(|e| SetupRefusal::ConfigUnparseable {
                path: path.display().to_string(),
                error: e.to_string(),
            })?;
    let node = document
        .get_mut("node")
        .and_then(toml_edit::Item::as_table_mut);
    let Some(node) = node else {
        return Err(SetupRefusal::ConfigConflict {
            path: path.display().to_string(),
            diff: "  [node]: the table does not exist or is not a table — a kata config owns it"
                .to_string(),
        });
    };

    let mut changes = Vec::new();
    let mut conflicts = Vec::new();

    // Refused set: every `[node]` key with no `node_knob_registry` row — the
    // registry is kept in lockstep with `NodeConfig`'s serde fields.
    let declared = kata_types::config::node_knob_registry();
    for (key, item) in node.iter() {
        if !declared.iter().any(|(name, _)| *name == key) {
            conflicts.push(format!(
                "  {key}: `[node]` declares no such key, found {item} — remove it"
            ));
        }
    }

    if let Some(declaration) = environment {
        match node.get("environment") {
            None => {
                node["environment"] = declaration.clone();
                changes.push("environment = <the declared closure>".to_string());
            }
            Some(existing) if toml_items_equal(existing, declaration) => {}
            Some(existing) => {
                let found = existing.to_string();
                if replace_template_defaults {
                    node["environment"] = declaration.clone();
                    changes.push("environment = <the declared closure>".to_string());
                } else {
                    conflicts.push(format!(
                        "  environment: a DIFFERENT closure is declared — required\n\
                         {declaration}\n  found\n{found}"
                    ));
                }
            }
        }
    }

    // `egress_allow`: write the empty declaration when absent so the knob an
    // operator adds `host:port` entries to is visible; never touch a set one.
    if node.get("egress_allow").is_none() {
        node["egress_allow"] = toml_edit::value(toml_edit::Array::new());
        changes.push("egress_allow = []".to_string());
    }

    if !conflicts.is_empty() {
        return Err(SetupRefusal::ConfigConflict {
            path: path.display().to_string(),
            diff: conflicts.join("\n"),
        });
    }
    let rendered = document.to_string();
    // The merge just built this text — a document the config parser itself
    // could not read is a defect in the merge, surfaced as a refusal rather
    // than a written file. `toml_edit` accepts TOML 1.1 constructs (a
    // multi-line inline table) that `toml`'s 1.0 grammar — the grammar the
    // loader uses — refuses, so a declaration source in the newer shape
    // would otherwise write a config that fails its own parse.
    rendered
        .parse::<toml::Value>()
        .map_err(|error| SetupRefusal::ConfigUnparseable {
            path: path.display().to_string(),
            error: format!("the merged document renders TOML the config parser refuses: {error}"),
        })?;
    Ok((rendered, changes))
}

/// Write `text` to `path` through a sibling temp + rename, preserving the
/// existing file's permissions — a config torn mid-write is worse than a
/// stale one.
fn write_config_atomically(path: &Path, text: &str) -> Result<(), String> {
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("kata.toml");
    let tmp = path.with_file_name(format!(".{file_name}.tmp"));
    // Read the permissions BEFORE the temp write — the file always exists at
    // this point (the scaffold just wrote it, or the operator did).
    let permissions = std::fs::metadata(path).ok().map(|meta| meta.permissions());
    std::fs::write(&tmp, text).map_err(|error| error.to_string())?;
    if let Some(permissions) = permissions {
        std::fs::set_permissions(&tmp, permissions).map_err(|error| error.to_string())?;
    }
    std::fs::rename(&tmp, path).map_err(|error| error.to_string())
}

/// The comment `kata host setup` writes above the exports it adds to `.env`.
/// The `KEY=value` lines that directly follow it are setup's own: a re-run
/// replaces a stale value there. Every other line is the operator's.
const ENV_BLOCK_HEADER: &str = "# kata host setup — the shipped youki provider's declared exports";

/// `KEY=value` (or `export KEY=value`) — `None` for anything else.
fn env_declaration(line: &str) -> Option<(&str, &str)> {
    let line = line.strip_prefix("export ").unwrap_or(line);
    let (key, value) = line.split_once('=')?;
    Some((key.trim(), value.trim()))
}

/// Merge the required `KEY=value` exports into `.env` text — the pure half of
/// the env step. Returns the new text when it differs. A differing value in
/// setup's own block (under [`ENV_BLOCK_HEADER`]) is replaced in place: a
/// rebuilt provider has a new address. A differing value anywhere else is the
/// operator's declaration, and the conflict the caller names.
fn merge_env_file(
    existing: &str,
    required: &[(&'static str, String)],
) -> Result<Option<String>, SetupRefusal> {
    let mut lines: Vec<String> = existing.lines().map(str::to_string).collect();
    let mut declared = std::collections::BTreeSet::new();
    let mut replaced = false;
    let mut in_block = false;
    for line in &mut lines {
        let trimmed = line.trim();
        if trimmed == ENV_BLOCK_HEADER {
            in_block = true;
            continue;
        }
        let declaration = (!trimmed.starts_with('#'))
            .then(|| env_declaration(trimmed))
            .flatten();
        let Some((key, value)) = declaration else {
            in_block = false;
            continue;
        };
        let Some((key, required_value)) = required.iter().find(|(name, _)| *name == key) else {
            continue;
        };
        declared.insert(*key);
        if value == required_value {
            continue;
        }
        if !in_block {
            return Err(SetupRefusal::EnvFileConflict {
                path: String::new(),
                key: (*key).to_string(),
                existing: value.to_string(),
                required: required_value.clone(),
            });
        }
        *line = format!("{key}={required_value}");
        replaced = true;
    }
    let additions: Vec<String> = required
        .iter()
        .filter(|(key, _)| !declared.contains(key))
        .map(|(key, value)| format!("{key}={value}"))
        .collect();
    if !replaced && additions.is_empty() {
        return Ok(None);
    }
    let mut text = if replaced {
        lines.join("\n") + "\n"
    } else {
        existing.to_string()
    };
    if additions.is_empty() {
        return Ok(Some(text));
    }
    if !text.is_empty() && !text.ends_with('\n') {
        text.push('\n');
    }
    if !text.is_empty() {
        text.push('\n');
    }
    text.push_str(ENV_BLOCK_HEADER);
    text.push('\n');
    for line in &additions {
        text.push_str(line);
        text.push('\n');
    }
    Ok(Some(text))
}

/// The `.env` `--config` implies — ONLY for the `.kata/kata.toml` layout,
/// where the project root (the config dir's parent) is where an operator's
/// commands run and so where dotenvy's cwd-ancestor search finds the file.
/// Any other `--config` shape returns `None`: writing a `.env` beside an
/// arbitrary config is a file nothing ever loads — an export that lies.
fn env_file_path(config_dir: &Path) -> Option<PathBuf> {
    match config_dir.file_name().and_then(|name| name.to_str()) {
        Some(".kata") => Some(config_dir.parent().unwrap_or(config_dir).join(".env")),
        _ => None,
    }
}

/// A directory `nix-store --realise` rooted this path under — one link per
/// store path, named for its basename, so a `nix store gc` cannot collect
/// what a running node still resolves.
fn nix_roots_dir(config_dir: &Path) -> PathBuf {
    config_dir.join("nix-roots")
}

/// `nix-store --realise --add-root <link> -- <path>` — the argv measured on
/// this host: realises the path and creates the indirect GC root atomically.
/// The operand sits after `--` so a value that slipped past validation can
/// still never be read as a flag.
fn realise_root_argv(link: &Path, store_path: &StorePath) -> Vec<String> {
    vec![
        "nix-store".to_string(),
        "--realise".to_string(),
        "--add-root".to_string(),
        link.display().to_string(),
        "--".to_string(),
        store_path.as_str().to_string(),
    ]
}

/// Realise one store path and root it under `roots/<basename>` — one link per
/// path, so `nix store gc` cannot collect what a running node still resolves.
/// The roots directory is created here because `--add-root` does not invent
/// parents. The value is validated as a store path FIRST: a declaration read
/// out of the operator's config never went through `parse_environment_file`'s
/// shape check, so the exec boundary is where every path is proven.
fn realise_and_root(
    exec: &mut dyn FnMut(&[String]) -> Result<String, String>,
    roots: &Path,
    store_path: &str,
) -> Result<(), String> {
    let store_path =
        kata_types::nix_environment::StorePath::new(store_path).map_err(|e| e.to_string())?;
    std::fs::create_dir_all(roots).map_err(|error| error.to_string())?;
    let link = roots.join(store_path.base_name());
    exec(&realise_root_argv(&link, &store_path)).map(|_| ())
}

/// Where a checkout build puts `member`. `cargo build --release` puts the
/// provider and the hook beside `kata` in `bin_dir`; the toolhost is a second
/// build, for [`TOOLHOST_TARGET`], under the same Cargo target directory's
/// `<TOOLHOST_TARGET>/<profile>/`. `bin_dir` is `<target dir>/<profile>`, so
/// the target directory is its parent (a `CARGO_TARGET_DIR` nested under the
/// checkout's `target/` included) and the profile its name: a release `kata`
/// stages a release toolhost.
fn checkout_member(bin_dir: &Path, member: &str) -> PathBuf {
    if member != PROVIDER_TOOLHOST_MEMBER {
        return bin_dir.join(member);
    }
    let profile = bin_dir.file_name().unwrap_or_default();
    bin_dir
        .parent()
        .unwrap_or(bin_dir)
        .join(TOOLHOST_TARGET)
        .join(profile)
        .join(kata_worker::provider_store::TOOLHOST_PROGRAM)
}

/// The cargo command that builds the toolhost for `bin_dir`'s profile.
fn toolhost_build(bin_dir: &Path) -> String {
    let profile = match bin_dir.file_name().and_then(|name| name.to_str()) {
        Some("release") => " --release".to_string(),
        Some("debug") | None => String::new(),
        Some(other) => format!(" --profile {other}"),
    };
    format!("cargo build{profile} --locked --target {TOOLHOST_TARGET} -p kata-toolhost")
}

/// Copy a checkout build's provider members ([`checkout_member`]) into a fresh
/// directory under `config_dir` (the store's filesystem), each at its place in
/// the entry, so the provider store provisions exactly them. A missing member
/// is `provider_source_incomplete`, naming `bin_dir` and, for the toolhost, the
/// path probed and the build that makes it. The directory is removed when the
/// returned handle drops.
fn stage_provider_members(
    bin_dir: &Path,
    config_dir: &Path,
) -> Result<tempfile::TempDir, SetupRefusal> {
    let missing: Vec<String> = PROVIDER_SOURCE_MEMBERS
        .iter()
        .filter_map(|member| {
            let built = checkout_member(bin_dir, member);
            if built.is_file() {
                None
            } else if *member == PROVIDER_TOOLHOST_MEMBER {
                Some(format!(
                    "`{member}` (`{}`, which `{}` builds)",
                    built.display(),
                    toolhost_build(bin_dir)
                ))
            } else {
                Some(format!("`{member}`"))
            }
        })
        .collect();
    if !missing.is_empty() {
        return Err(SetupRefusal::ProviderSourceIncomplete {
            source: bin_dir.display().to_string(),
            missing,
        });
    }
    let write = |error: std::io::Error| SetupRefusal::Write {
        path: config_dir.display().to_string(),
        error: error.to_string(),
    };
    std::fs::create_dir_all(config_dir).map_err(write)?;
    let staged = tempfile::Builder::new()
        .prefix(".provider-source-")
        .tempdir_in(config_dir)
        .map_err(write)?;
    for member in PROVIDER_SOURCE_MEMBERS {
        let to = staged.path().join(member);
        if let Some(parent) = to.parent() {
            std::fs::create_dir_all(parent).map_err(write)?;
        }
        std::fs::copy(checkout_member(bin_dir, member), to).map_err(write)?;
    }
    Ok(staged)
}

/// The one command `kata host setup` runs that can take minutes: a
/// checkout build's `nix-build`.
const STREAMED_PROGRAM: &str = "nix-build";

/// The production `exec`: runs `argv`, returning its trimmed stdout. A
/// [`STREAMED_PROGRAM`]'s stderr — its build log — goes straight to the
/// terminal as it runs, so a long first build is visible and a failing one's
/// log is above the refusal, which carries only the exit. Any other command's
/// stderr is captured into its failure.
fn run_command(argv: &[String]) -> Result<String, String> {
    let Some((program, argv_rest)) = argv.split_first() else {
        return Err("empty argv".to_string());
    };
    let streams = Path::new(program).file_name() == Some(STREAMED_PROGRAM.as_ref());
    let output = Command::new(program)
        .args(argv_rest)
        .stderr(if streams {
            std::process::Stdio::inherit()
        } else {
            std::process::Stdio::piped()
        })
        .output()
        .map_err(|error| format!("could not spawn `{program}`: {error}"))?;
    if output.status.success() {
        return Ok(String::from_utf8_lossy(&output.stdout).trim().to_string());
    }
    let code = output
        .status
        .code()
        .map_or_else(|| "signal".to_string(), |code| code.to_string());
    if streams {
        return Err(format!("exited {code}"));
    }
    Err(format!(
        "exited {code}: {stderr}",
        stderr = String::from_utf8_lossy(&output.stderr).trim(),
    ))
}

/// `kata host setup`, end to end — the impure rim. Every measurement and
/// effect the tests cannot own goes through [`run_setup_with`]'s injected
/// seams; this function is only the production bindings for them.
pub fn run_setup(args: &HostSetupArgs) -> anyhow::Result<HostSetupReport> {
    let probes = Probes::production()?;
    run_setup_with(
        args,
        &probes,
        &mut run_command,
        &pinned_binary_sha256,
        &|| {
            kata_worker::oci_runtime::fold_delegation(
                kata_worker::sandbox_bounds::cgroup_delegation(),
            )
        },
        &|key| crate::cli::launch_env_var(key),
        &|config| crate::cli::doctor::doctor_report_with_options(config, &[]),
    )
}

/// The testable core: every seam — subprocess exec, the pinned-binary digest,
/// the delegation probe and the doctor report — is injected, so a test plants
/// tempdirs and stubs and never reads `/etc`, `/proc`, or the pinned binary.
fn run_setup_with(
    args: &HostSetupArgs,
    probes: &Probes,
    exec: &mut dyn FnMut(&[String]) -> Result<String, String>,
    verify_pin: &dyn Fn(&YoukiPin) -> Result<String, OciPrerequisiteRefusal>,
    delegation: &dyn Fn() -> Result<(), OciPrerequisiteRefusal>,
    ambient: &dyn Fn(&'static str) -> Option<String>,
    doctor: &dyn Fn(&Path) -> crate::cli::doctor::DoctorReport,
) -> anyhow::Result<HostSetupReport> {
    let pin = YoukiPin::embedded();
    let config = args.config.clone();
    let config_dir = config
        .parent()
        .map_or_else(|| PathBuf::from("."), Path::to_path_buf);
    let config_dir_abs = std::env::current_dir()
        .context("resolving cwd for absolute store roots")?
        .join(&config_dir);
    let mut steps = Vec::new();
    let mut actions = Vec::new();
    let mut changed = false;
    let companions = Companions::of(&probes.exe_dir);
    let mut declarations = Declarations {
        companions: &companions,
        roots: nix_roots_dir(&config_dir_abs),
        built: None,
    };

    let outcome = (|| -> Result<(), SetupRefusal> {
        run_step(&mut steps, "platform", || {
            if std::env::consts::OS == "linux" && std::env::consts::ARCH == "x86_64" {
                Ok((
                    step("platform", StepStatus::InPlace, "linux/x86_64".to_string()),
                    (),
                ))
            } else {
                Err(SetupRefusal::HostPlatform {
                    os: std::env::consts::OS,
                    arch: std::env::consts::ARCH,
                })
            }
        })?;

        run_step(&mut steps, "nix", || {
            let invocation = vec!["nix-store".to_string(), "--version".to_string()];
            let version = exec(&invocation).map_err(|error| SetupRefusal::NixAbsent {
                argv: invocation.join(" "),
                error,
            })?;
            // The legacy `nix-store` needs no experimental feature; the `nix` command the
            // main runs at boot (`environment::nix::store_reachable`) does. Ask it the
            // same question boot asks, so a host without `nix-command` stops here.
            let store_info = vec!["nix".to_string(), "store".to_string(), "info".to_string()];
            exec(&store_info).map_err(|error| SetupRefusal::NixCommandUnavailable {
                argv: store_info.join(" "),
                error,
            })?;
            Ok((
                step(
                    "nix",
                    StepStatus::InPlace,
                    format!("`nix-store --version` → {version}; `nix store info` answers"),
                ),
                (),
            ))
        })?;

        run_step(&mut steps, "cgroup_v2", || {
            // The unified-hierarchy marker is the delegation probe's own
            // first read (`CgroupObservation::unified_hierarchy`) — stat-ing
            // `cgroup.controllers` a second time here asks the same fact
            // twice, so its absence surfaces through the fold's refusal text.
            delegation().map_err(|refusal| SetupRefusal::Delegation {
                detail: refusal.to_string(),
            })?;
            Ok((
                step(
                    "cgroup_v2",
                    StepStatus::InPlace,
                    "unified hierarchy; memory+pids delegation measured usable".to_string(),
                ),
                (),
            ))
        })?;

        run_step(&mut steps, "userns", || {
            match std::fs::read_to_string(&probes.userns_clone_knob) {
                Ok(raw) if raw.trim() == "0" => Err(SetupRefusal::UsernsRefused {
                    knob: probes.userns_clone_knob.display().to_string(),
                }),
                _ => {
                    let restriction = kata_worker::oci_runtime::fold_userns_restriction(
                        std::fs::read_to_string(&probes.userns_restriction_knob)
                            .as_deref()
                            .map_err(std::string::ToString::to_string),
                    );
                    Ok((
                        step(
                            "userns",
                            StepStatus::InPlace,
                            format!("unprivileged userns allowed; {}", restriction.label()),
                        ),
                        (),
                    ))
                }
            }
        })?;

        run_step(&mut steps, "youki", || {
            let unrealisable = |error: String| SetupRefusal::YoukiUnrealisable {
                store_path: pin.store_path().to_string(),
                realised_by: pin.realised_by().to_string(),
                error,
            };
            match verify_pin(pin) {
                Ok(sha256) => Ok((
                    step(
                        "youki",
                        StepStatus::InPlace,
                        format!(
                            "the pinned bytes are at `{}` (sha256 {sha256})",
                            pin.store_path()
                        ),
                    ),
                    (),
                )),
                Err(OciPrerequisiteRefusal::BinaryAbsent { .. }) => {
                    let roots = nix_roots_dir(&config_dir_abs);
                    // A package substitutes the pinned path; a checkout build
                    // runs the pin's own `realised_by` build from the checkout,
                    // which substitutes too when a cache holds it.
                    let how = match &companions {
                        Companions::Packaged { .. } => {
                            realise_and_root(&mut *exec, &roots, pin.store_object().as_str())
                                .map_err(unrealisable)?;
                            "realised and rooted the pinned youki".to_string()
                        }
                        Companions::Checkout { root, .. } => {
                            let expression = root.join(CHECKOUT_YOUKI_EXPRESSION);
                            let build = nix_build_argv(
                                &roots.join(pin.store_object().base_name()),
                                &expression,
                            );
                            std::fs::create_dir_all(&roots)
                                .map_err(|error| error.to_string())
                                .and_then(|()| exec(&build))
                                .map_err(|error| SetupRefusal::CheckoutBuild {
                                    argv: build.join(" "),
                                    error,
                                })?;
                            format!(
                                "built and rooted the pinned youki from `{}`",
                                expression.display()
                            )
                        }
                    };
                    let sha256 =
                        verify_pin(pin).map_err(|refusal| unrealisable(refusal.to_string()))?;
                    changed = true;
                    Ok((
                        step(
                            "youki",
                            StepStatus::Changed,
                            format!("{how} (sha256 {sha256})"),
                        ),
                        (),
                    ))
                }
                Err(refusal) => Err(unrealisable(refusal.to_string())),
            }
        })?;

        run_step(&mut steps, "apparmor", || {
            let reason = match apparmor_state(pin, probes) {
                ApparmorState::Ready => {
                    return Ok((
                        step(
                            "apparmor",
                            StepStatus::InPlace,
                            format!(
                                "profile `{}` is loaded and the installed file is the render",
                                pin.profile_name()
                            ),
                        ),
                        (),
                    ));
                }
                // The unprivileged RE-RUN's ordinary view: the installed file is the
                // render and the loaded list needs root to read. Reinstalling would
                // change nothing and demand sudo for it, and assuming the load would
                // claim what nothing observed — so the step takes the certification's
                // functional arm, a rootless container of the pinned runtime (verified
                // by the `youki` step above) actually starting, and says what that
                // start shows on THIS kernel (`unread_load_observed`).
                ApparmorState::InstalledLoadUnread => match (probes.functional)(pin) {
                    Ok(container) => {
                        return Ok((
                            step(
                                "apparmor",
                                StepStatus::InPlace,
                                format!(
                                    "profile `{}` is installed (the file is the render byte for \
                                     byte); {}",
                                    pin.profile_name(),
                                    unread_load_observed(probes, &container)
                                ),
                            ),
                            (),
                        ));
                    }
                    Err(refusal) => format!(
                        "profile `{}` is installed (the file is the render byte for byte), but \
                         its load state needs root to confirm — the loaded-profile list is \
                         unreadable without it — and a rootless container of the pinned \
                         runtime did not start: {}",
                        pin.profile_name(),
                        apparmor_recourse(refusal)?
                    ),
                },
                ApparmorState::NeedsInstall(reason) => reason,
            };
            if !args.install_apparmor {
                actions.push(APPARMOR_INSTALL_COMMAND.to_string());
                return Ok((
                    step(
                        "apparmor",
                        StepStatus::Deferred,
                        format!("{reason} — install it with `{APPARMOR_INSTALL_COMMAND}`"),
                    ),
                    (),
                ));
            }
            let invocation = vec![
                "sudo".to_string(),
                probes.exe.display().to_string(),
                "host".to_string(),
                "apparmor-install".to_string(),
            ];
            exec(&invocation).map_err(|error| SetupRefusal::ApparmorInstall {
                argv: invocation.join(" "),
                detail: format!("the command failed: {error}"),
            })?;
            changed = true;
            match apparmor_state(pin, probes) {
                ApparmorState::Ready => Ok((
                    step(
                        "apparmor",
                        StepStatus::Changed,
                        format!("installed and reloaded via `{}`", invocation.join(" ")),
                    ),
                    (),
                )),
                // The install ran privileged and its reload exited 0; this re-check
                // reads as the unprivileged caller, so the loaded list is still
                // unreadable. The reload's exit status observes nothing about the
                // load, so the step re-takes the certification's functional arm, as
                // the unprivileged re-run does: `changed` only when the container
                // starts, and refused — never `complete` — when it still does not.
                ApparmorState::InstalledLoadUnread => match (probes.functional)(pin) {
                    Ok(container) => Ok((
                        step(
                            "apparmor",
                            StepStatus::Changed,
                            format!(
                                "installed via `{}`; {}",
                                invocation.join(" "),
                                unread_load_observed(probes, &container)
                            ),
                        ),
                        (),
                    )),
                    Err(refusal) => Err(SetupRefusal::ApparmorInstall {
                        argv: invocation.join(" "),
                        detail: format!(
                            "the installed file is the render byte for byte, the loaded-profile \
                             list needs root to read, and a rootless container of the pinned \
                             runtime still did not start: {}",
                            apparmor_recourse(refusal)?
                        ),
                    }),
                },
                ApparmorState::NeedsInstall(reason) => Err(SetupRefusal::ApparmorInstall {
                    argv: invocation.join(" "),
                    detail: reason,
                }),
            }
        })?;

        let provider = run_step(&mut steps, "provider", || {
            // A checkout build's members are in the Cargo target directory,
            // which holds far more than the members: they are staged into a
            // directory of their own, which is what the store provisions (it
            // copies a source directory whole).
            let staged = match (&args.provider_source, &companions) {
                (None, Companions::Checkout { bin_dir, .. }) => {
                    Some(stage_provider_members(bin_dir, &config_dir_abs)?)
                }
                _ => None,
            };
            let source = match (&args.provider_source, &staged, &companions) {
                (Some(source), _, _) => Some(source.clone()),
                (None, Some(staged), _) => Some(staged.path().to_path_buf()),
                (None, None, Companions::Packaged { prefix }) => prefix
                    .as_ref()
                    .map(|prefix| prefix.join(PACKAGED_PROVIDER_SOURCE)),
                (None, None, Companions::Checkout { .. }) => None,
            };
            let Some(source) = source else {
                return Err(SetupRefusal::ProviderSourceAbsent {
                    probed: vec![
                        format!("<exe>/../{PACKAGED_PROVIDER_SOURCE}"),
                        "--provider-source <dir>".to_string(),
                    ],
                });
            };
            if !source.is_dir() {
                return Err(SetupRefusal::ProviderSourceAbsent {
                    probed: vec![source.display().to_string()],
                });
            }
            let missing: Vec<String> = PROVIDER_SOURCE_MEMBERS
                .iter()
                .filter(|member| !source.join(member).is_file())
                .map(|member| format!("`{member}`"))
                .collect();
            if !missing.is_empty() {
                return Err(SetupRefusal::ProviderSourceIncomplete {
                    source: source.display().to_string(),
                    missing,
                });
            }
            let source_ip = source.join(PROVIDER_IP_MEMBER);
            if source_ip.symlink_metadata().is_ok() {
                return Err(SetupRefusal::ProviderSourceHoldsIp {
                    path: source_ip.display().to_string(),
                });
            }
            let ip = resolve_provider_ip(args, probes, &mut || declarations.prefix(&mut *exec))?;
            let store_root = config_dir_abs.join("providers");
            let entries_before = store_root.read_dir().map_or(0, Iterator::count);
            let provisioned = kata_worker::ProviderStore::new(&store_root)
                .provision_with_members(
                    kata_worker::oci_driver::OCI_PROVIDER_NAME,
                    &source,
                    &[(PROVIDER_IP_MEMBER, &ip)],
                )
                .map_err(|error| SetupRefusal::ProviderProvision {
                    source: source.display().to_string(),
                    error: error.to_string(),
                })?;
            // The launch environment outranks `.env` (dotenvy never
            // overrides), so declaring a different answer through it would be
            // inert — that is a conflict, named before any write. A value
            // `.env` itself supplied is not ambient: the env step owns it.
            // `node_environment` keys off `NODE_PROVIDER_ENV_KEYS`, the list
            // `kata service install` copies into the installed main's snapshot.
            let required: Vec<(&'static str, String)> =
                provisioned.node_environment(&store_root).into();
            for &(key, ref required_value) in &required {
                if let Some(declared) = ambient(key)
                    && declared != *required_value
                {
                    return Err(SetupRefusal::ProviderEnvConflict {
                        key,
                        ambient: declared,
                        provisioned: required_value.clone(),
                    });
                }
            }
            let grew = store_root.read_dir().map_or(0, Iterator::count) > entries_before;
            if grew {
                changed = true;
            }
            Ok((
                step(
                    "provider",
                    if grew {
                        StepStatus::Changed
                    } else {
                        StepStatus::InPlace
                    },
                    format!(
                        "`kata-provider-youki` at `{}` in `{}` (members from `{}`, \
                         `{PROVIDER_IP_MEMBER}` copied from `{}`)",
                        provisioned.address,
                        store_root.display(),
                        match (&staged, &companions) {
                            (Some(_), Companions::Checkout { bin_dir, .. }) => bin_dir.display(),
                            _ => source.display(),
                        },
                        ip.display()
                    ),
                ),
                required,
            ))
        })?;

        run_step(&mut steps, "env_file", || {
            let all_ambient = provider
                .iter()
                .all(|(key, value)| ambient(key).is_some_and(|v| v == *value));
            if all_ambient {
                return Ok((
                    step(
                        "env_file",
                        StepStatus::Skipped,
                        "the three provider exports are already declared by the launch \
                         environment; nothing to write"
                            .to_string(),
                    ),
                    (),
                ));
            }
            let Some(env_path) = env_file_path(&config_dir_abs) else {
                // Only the `.kata/kata.toml` layout has a project root
                // dotenvy would search; an arbitrary `--config` shape has no
                // `.env` home, so the exports become the operator's declared
                // action — the run is incomplete until they are.
                for (key, value) in &provider {
                    actions.push(format!("export {key}={value}"));
                }
                return Ok((
                    step(
                        "env_file",
                        StepStatus::Deferred,
                        "`--config` is not the `.kata/kata.toml` layout, so no `.env` a worker \
                         would load can be written — declare the provider exports in the \
                         environment kata runs under (named in `actions`)"
                            .to_string(),
                    ),
                    (),
                ));
            };
            let existing = std::fs::read_to_string(&env_path).unwrap_or_default();
            let merged = merge_env_file(&existing, &provider).map_err(|mut refusal| {
                if let SetupRefusal::EnvFileConflict { path, .. } = &mut refusal {
                    *path = env_path.display().to_string();
                }
                refusal
            })?;
            match merged {
                None => Ok((
                    step(
                        "env_file",
                        StepStatus::InPlace,
                        format!("`{}` already declares all three", env_path.display()),
                    ),
                    (),
                )),
                Some(text) => {
                    std::fs::write(&env_path, text).map_err(|error| SetupRefusal::Write {
                        path: env_path.display().to_string(),
                        error: error.to_string(),
                    })?;
                    changed = true;
                    Ok((
                        step(
                            "env_file",
                            StepStatus::Changed,
                            format!("wrote the provider exports to `{}`", env_path.display()),
                        ),
                        (),
                    ))
                }
            }
        })?;

        run_step(&mut steps, "config", || {
            let mut detail = Vec::new();
            let mut config_changed = false;
            let just_scaffolded = !config.exists();
            if just_scaffolded {
                crate::cli::init::scaffold_project(&config, false).map_err(|error| {
                    SetupRefusal::Scaffold {
                        error: format!("{error:#}"),
                    }
                })?;
                changed = true;
                config_changed = true;
                detail.push("scaffolded the project (kata init's shape)".to_string());
            }
            let text = std::fs::read_to_string(&config).map_err(|error| SetupRefusal::Write {
                path: config.display().to_string(),
                error: error.to_string(),
            })?;
            // The environment declaration is needed only when the config does
            // not already declare one — resolve its source lazily so a node
            // already declared needs no `--environment-file`.
            let parsed = text.parse::<toml_edit::DocumentMut>().map_err(|e| {
                SetupRefusal::ConfigUnparseable {
                    path: config.display().to_string(),
                    error: e.to_string(),
                }
            })?;
            let declared = parsed
                .get("node")
                .and_then(|node| node.get("environment"))
                .cloned();
            let (declaration, store_paths) = resolve_environment(
                args,
                &mut || declarations.prefix(&mut *exec),
                &config,
                declared.as_ref(),
            )?;
            // Realise and root whichever declaration won — an environment the
            // store does not hold is a boot refusal, so this is owed whether
            // the decl came from the file or was already in the config.
            for store_path in &store_paths {
                realise_and_root(exec, &nix_roots_dir(&config_dir_abs), store_path).map_err(
                    |error| SetupRefusal::EnvironmentRealise {
                        store_path: store_path.clone(),
                        error,
                    },
                )?;
            }
            let (new_text, applied) =
                merge_oci_config(&config, &text, declaration.as_ref(), just_scaffolded)?;
            if new_text != text {
                write_config_atomically(&config, &new_text).map_err(|error| {
                    SetupRefusal::Write {
                        path: config.display().to_string(),
                        error,
                    }
                })?;
                changed = true;
                config_changed = true;
                detail.extend(applied.iter().map(|c| format!("declared {c}")));
            }
            if declared.is_some() {
                detail.push("the config's own environment declaration stands".to_string());
            }
            if detail.is_empty() {
                detail.push("already declares the oci profile and environment".to_string());
            }
            let status = if config_changed {
                StepStatus::Changed
            } else {
                StepStatus::InPlace
            };
            Ok((step("config", status, detail.join("; ")), ()))
        })?;

        Ok(())
    })();

    // A refused step already pushed its `refused` row — carrying the
    // refusal's own text as the detail — before the error propagated here.
    let complete_steps = outcome.is_ok();
    // A deferred step is work the run could not do itself (the root-owned
    // AppArmor install, exports a non-standard --config has no home for).
    // `doctor` warns on the AppArmor one rather than failing, so without this
    // conjunct a host where every capsule will EPERM could report `complete`
    // — the deferred action list is what the verdict waits on.
    let nothing_deferred =
        actions.is_empty() && !steps.iter().any(|row| row.status == StepStatus::Deferred);

    let doctor_verdict = if complete_steps {
        let report = doctor(&config);
        let verdict = DoctorVerdict {
            passed: report.passed,
            failure_count: report.failure_count,
            warning_count: report.warning_count,
            failed_checks: report
                .checks
                .iter()
                .filter(|check| check.status == crate::cli::doctor::DoctorStatus::Fail)
                .map(|check| check.name.to_string())
                .collect(),
        };
        steps.push(step(
            "doctor",
            if verdict.passed {
                StepStatus::InPlace
            } else {
                StepStatus::Refused
            },
            format!(
                "{} failed, {} warning(s)",
                verdict.failure_count, verdict.warning_count
            ),
        ));
        Some(verdict)
    } else {
        None
    };

    let complete = complete_steps
        && nothing_deferred
        && doctor_verdict
            .as_ref()
            .is_some_and(|verdict| verdict.passed);
    Ok(HostSetupReport {
        summary_kind: "kata host setup",
        config: config.display().to_string(),
        steps,
        actions,
        doctor: doctor_verdict,
        changed,
        complete,
    })
}

/// The human-face rendering of a [`HostSetupReport`].
#[must_use]
pub fn render_setup(report: &HostSetupReport) -> String {
    use std::fmt::Write as _;
    let mut out = String::new();
    let _ = writeln!(out, "--- kata host setup ---");
    let _ = writeln!(out, "config     {}", report.config); // kata-spacing: intentional
    for row in &report.steps {
        let status = match row.status {
            StepStatus::InPlace => "in_place",
            StepStatus::Changed => "changed",
            StepStatus::Deferred => "deferred",
            StepStatus::Skipped => "skipped",
            StepStatus::Refused => "refused",
        };
        let _ = writeln!(out, "  [{status}] {}", row.name);
        let _ = writeln!(out, "      {}", row.detail);
    }
    if !report.actions.is_empty() {
        let _ = writeln!(out, "actions required:");
        for action in &report.actions {
            let _ = writeln!(out, "  {action}");
        }
    }
    let _ = writeln!(
        out,
        "changed    {}", // kata-spacing: intentional
        if report.changed { "yes" } else { "no" }
    );
    let _ = writeln!(
        out,
        "status     {}", // kata-spacing: intentional
        if report.complete {
            "complete"
        } else {
            "incomplete"
        }
    );
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pin() -> &'static YoukiPin {
        YoukiPin::embedded()
    }

    /// A non-root invocation refuses BEFORE anything is written, proved
    /// against a scratch dir.
    #[test]
    fn a_non_root_install_refuses_and_writes_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let mut exec = |_: &[String]| -> Result<(), String> {
            panic!("a refused install must not reach the reload")
        };
        let error =
            write_and_reload(pin(), 1000, dir.path(), &mut exec).expect_err("non-root must refuse");
        assert!(
            matches!(error, ApparmorInstallError::RequiresRoot { euid: 1000, .. }),
            "the refusal must be `RequiresRoot`: {error:?}"
        );
        assert!(
            error.to_string().contains("euid 0"),
            "the refusal must name the required privilege: {error}"
        );
        assert!(
            std::fs::read_dir(dir.path()).unwrap().next().is_none(),
            "a refused install wrote a file into {:?}",
            dir.path()
        );
    }

    /// The happy path: the render lands at `<dir>/<name>` mode 0644 and the
    /// reload argv is exactly `apparmor_parser -r <that path>`.
    #[test]
    fn the_install_writes_the_render_and_reloads_it() {
        let dir = tempfile::tempdir().unwrap();
        let mut argv_seen = Vec::new();
        let mut exec = |argv: &[String]| -> Result<(), String> {
            argv_seen.push(argv.to_vec());
            Ok(())
        };
        let target = write_and_reload(pin(), 0, dir.path(), &mut exec).expect("install");
        assert_eq!(target, dir.path().join(pin().profile_name()));
        assert_eq!(
            std::fs::read_to_string(&target).unwrap(),
            render_apparmor_profile(pin()),
            "the written bytes are the render, byte for byte"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            assert_eq!(
                std::fs::metadata(&target).unwrap().permissions().mode() & 0o777,
                0o644,
                "the profile is root-owned policy, readable by the parser"
            );
        }
        assert_eq!(
            argv_seen,
            vec![vec![
                "apparmor_parser".to_string(),
                "-r".to_string(),
                target.display().to_string(),
            ]],
            "exactly one reload, with the profile path"
        );
    }

    /// A failed reload leaves the written file, because an unloaded file is
    /// not a policy in force.
    #[test]
    fn a_failed_reload_names_the_argv_and_leaves_the_file() {
        let dir = tempfile::tempdir().unwrap();
        let mut exec = |_: &[String]| -> Result<(), String> {
            Err("exited 1: AppArmor parser error".to_string())
        };
        let error =
            write_and_reload(pin(), 0, dir.path(), &mut exec).expect_err("the reload fails");
        assert!(
            matches!(error, ApparmorInstallError::ReloadFailed { .. }),
            "the refusal must be `ReloadFailed`: {error:?}"
        );
        assert!(
            error.to_string().contains("apparmor_parser -r"),
            "the refusal must name the reload argv: {error}"
        );
        assert!(
            dir.path().join(pin().profile_name()).is_file(),
            "a reload refusal leaves the file — the next file-compare names it drift"
        );
    }

    /// The loaded-list fold as the report records it: a readable list with the
    /// name is `verified`; a readable list without it is `not_loaded`; an
    /// unreadable list is `unverifiable` — never claimed either way.
    #[test]
    fn the_loaded_check_folds_the_kernels_list() {
        let pin = pin();
        assert_eq!(
            loaded_check(pin, Ok("unconfined (unconfined)\nyouki (unconfined)\n")),
            Ok(LoadedCheck::Verified)
        );
        assert!(
            matches!(
                loaded_check(pin, Ok("unconfined (unconfined)\n")),
                Err(ApparmorInstallError::NotLoaded { .. })
            ),
            "a readable list without the name is a refusal, not `unverifiable`"
        );
        assert_eq!(
            loaded_check(pin, Err("Permission denied".to_string())),
            Ok(LoadedCheck::Unverifiable),
            "an unreadable list is never reported as loaded — and never as absent"
        );
    }

    // ------------------------------------------------------------------
    // `kata host setup`
    // ------------------------------------------------------------------

    /// The `[node.environment]` TABLE shape `nix/node-environment-toml.nix`
    /// renders — the strict-TOML-1.0 form a merged config parses under.
    // The store paths are SHAPE-valid (`<32-char nix-base32 digest>-<name>`)
    // — `realise_and_root` runs `StorePath::new` on every value before exec,
    // so a fixture with a cosmetic path would refuse before nix-store ran.
    const NODE_ENVIRONMENT_TOML: &str = r#"
[node]
[node.environment]
label = "kata-node"
system = "x86_64-linux"
nixpkgs_attribute = "kata#nix/node-environment.nix"
store_paths = ["/nix/store/0123456789abcdfghijklmnpqrsvwxyz-env-a", "/nix/store/vwxyz0123456789abcdfghijklmnpqrs-env-b"]
path_prepend = ["/nix/store/0123456789abcdfghijklmnpqrsvwxyz-env-a/bin"]
integrity_policy = { verify = "nar_hash_only", sigs_needed = 0, required_signers = [], allow_unsigned_content_addressed = true, verify_contents_at_declare = true }
"#;

    /// A scratch `Probes` pointing every host read at `dir` — the tests plant
    /// the answers, never the host's.
    fn scratch_probes(dir: &Path) -> Probes {
        Probes {
            userns_clone_knob: dir.join("unprivileged_userns_clone"),
            userns_restriction_knob: dir.join("apparmor_restrict_unprivileged_userns"),
            apparmor_loaded: dir.join("apparmor-profiles"),
            apparmor_dir: dir.join("apparmor.d"),
            exe_dir: dir.join("prefix/bin"),
            exe: dir.join("prefix/bin/kata"),
            nix_store: dir.join("nix/store"),
            functional: functional_ok,
        }
    }

    /// The functional arm, stubbed to a container that ran.
    #[allow(clippy::unnecessary_wraps)]
    fn functional_ok(_pin: &YoukiPin) -> Result<String, OciPrerequisiteRefusal> {
        Ok("kata-oci-certify-test".to_string())
    }

    /// The functional arm, stubbed to the EPERM a restricted kernel gives an
    /// unprofiled runtime.
    fn functional_refused(_pin: &YoukiPin) -> Result<String, OciPrerequisiteRefusal> {
        Err(OciPrerequisiteRefusal::FunctionalRunRefused {
            exit: "1".to_string(),
            stderr_tail: "Operation not permitted".to_string(),
            denial: FunctionalDenial::CapabilityDenied,
        })
    }

    /// The functional arm, stubbed to a throwaway bundle that could not be
    /// prepared: no container started, and nothing about AppArmor was observed.
    fn functional_harness_failed(_pin: &YoukiPin) -> Result<String, OciPrerequisiteRefusal> {
        Err(OciPrerequisiteRefusal::FunctionalHarness {
            stage: "locating a statically linked payload".to_string(),
            error: "no statically linked payload on this host".to_string(),
        })
    }

    /// The functional arm, stubbed to a container the pinned runtime refused with
    /// stderr naming neither AppArmor nor a capability denial.
    fn functional_run_unclassified(_pin: &YoukiPin) -> Result<String, OciPrerequisiteRefusal> {
        Err(OciPrerequisiteRefusal::FunctionalRunRefused {
            exit: "1".to_string(),
            stderr_tail: "rootfs: No such file or directory".to_string(),
            denial: FunctionalDenial::Unclassified,
        })
    }

    std::thread_local! {
        /// How many times [`eperm_then`] has been asked on this thread.
        static FUNCTIONAL_CALLS: std::cell::Cell<u32> = const { std::cell::Cell::new(0) };
    }

    /// The functional arm, stubbed to the restricted kernel's EPERM on its FIRST
    /// call — the AppArmor-shaped refusal the pre-install check routes to the
    /// install — and to `after` on every later one: what the container says once
    /// the install ran.
    fn eperm_then(
        pin: &YoukiPin,
        after: fn(&YoukiPin) -> Result<String, OciPrerequisiteRefusal>,
    ) -> Result<String, OciPrerequisiteRefusal> {
        let call = FUNCTIONAL_CALLS.with(|calls| {
            let call = calls.get();
            calls.set(call + 1);
            call
        });
        if call == 0 {
            functional_refused(pin)
        } else {
            after(pin)
        }
    }

    fn eperm_then_harness_failed(pin: &YoukiPin) -> Result<String, OciPrerequisiteRefusal> {
        eperm_then(pin, functional_harness_failed)
    }

    fn eperm_then_run_unclassified(pin: &YoukiPin) -> Result<String, OciPrerequisiteRefusal> {
        eperm_then(pin, functional_run_unclassified)
    }

    /// A provider-source dir holding the kata-built members the packaged
    /// `share/kata/provider-source` holds.
    fn provider_source(dir: &Path) -> PathBuf {
        let source = dir.join("provider-source");
        for member in PROVIDER_SOURCE_MEMBERS {
            let path = source.join(member);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, format!("#!/{member}\n")).unwrap();
        }
        source
    }

    /// The bytes [`store_ip`] plants.
    const IP_BYTES: &[u8] = b"#!/iproute2/ip\n";

    /// An iproute2-shaped object in the scratch Nix store [`scratch_probes`]
    /// names, holding a regular executable `bin/ip`; returns that file.
    fn store_ip(dir: &Path) -> PathBuf {
        use std::os::unix::fs::PermissionsExt;
        let ip = dir.join("nix/store/0123456789abcdfghijklmnpqrsvwxyz-iproute2-7.1.0/bin/ip");
        if !ip.exists() {
            std::fs::create_dir_all(ip.parent().unwrap()).unwrap();
            std::fs::write(&ip, IP_BYTES).unwrap();
            std::fs::set_permissions(&ip, std::fs::Permissions::from_mode(0o555)).unwrap();
        }
        ip
    }

    fn environment_file(dir: &Path) -> PathBuf {
        let path = dir.join("node-environment.toml");
        std::fs::write(&path, NODE_ENVIRONMENT_TOML).unwrap();
        path
    }

    /// A `Probes` where every host answer is the good one: userns allowed,
    /// the restriction recorded-unrestricted, the profile loaded and
    /// installed byte-for-byte.
    fn green_probes(dir: &Path) -> Probes {
        let probes = scratch_probes(dir);
        std::fs::write(&probes.userns_restriction_knob, "0\n").unwrap();
        std::fs::create_dir_all(&probes.apparmor_dir).unwrap();
        std::fs::write(
            probes.apparmor_dir.join(pin().profile_name()),
            render_apparmor_profile(pin()),
        )
        .unwrap();
        std::fs::write(&probes.apparmor_loaded, "youki (enforce)\n").unwrap();
        std::fs::create_dir_all(probes.exe_dir.parent().unwrap()).unwrap();
        probes
    }

    fn passing_doctor(_config: &Path) -> crate::cli::doctor::DoctorReport {
        crate::cli::doctor::DoctorReport {
            summary_kind: "kata doctor",
            config: String::new(),
            online_checked: false,
            passed: true,
            failure_count: 0,
            warning_count: 0,
            checks: Vec::new(),
            next_commands: Vec::new(),
        }
    }

    fn failing_doctor(_config: &Path) -> crate::cli::doctor::DoctorReport {
        crate::cli::doctor::DoctorReport {
            summary_kind: "kata doctor",
            config: String::new(),
            online_checked: false,
            passed: false,
            failure_count: 1,
            warning_count: 0,
            checks: vec![crate::cli::doctor::DoctorCheck {
                name: "oci_containment",
                status: crate::cli::doctor::DoctorStatus::Fail,
                message: "the pinned youki is not certified".to_string(),
                details: std::collections::BTreeMap::new(),
                diagnostic: Vec::new(),
            }],
            next_commands: Vec::new(),
        }
    }

    // The `Result` is the injected seam's signature, not this stub's choice —
    // a green-arm double still must answer in the fallible shape.
    #[allow(clippy::unnecessary_wraps)]
    fn verify_ok(_pin: &YoukiPin) -> Result<String, OciPrerequisiteRefusal> {
        Ok("deadbeef".to_string())
    }

    #[allow(clippy::unnecessary_wraps)]
    fn delegation_ok() -> Result<(), OciPrerequisiteRefusal> {
        Ok(())
    }

    /// The `nix` step's two probes, `nix-store --version` and `nix store info`: a fake
    /// `exec` answers both for a host whose Nix is usable.
    fn answers_nix_probe(argv: &[String]) -> bool {
        (argv.len() == 2 && argv[1] == "--version") || argv == ["nix", "store", "info"]
    }

    /// No ambient declarations — the default test environment.
    fn no_ambient(_key: &'static str) -> Option<String> {
        None
    }

    /// The full rig: a green host, the packaged-shape files under a scratch
    /// prefix, an `exec` that records every argv and answers the `nix` step's
    /// probes, `--realise`, and the sudo re-exec.
    struct SetupRig {
        /// BEFORE `dir`, so it drops first: the `provider` step provisions a sealed
        /// (`0500`) by-hash store under `.kata/providers`, which `dir`'s own removal
        /// cannot get through. See `kata_worker::UnsealOnDrop`.
        _unseal: kata_worker::UnsealOnDrop,
        dir: tempfile::TempDir,
        args: HostSetupArgs,
        probes: Probes,
        execs: std::cell::RefCell<Vec<String>>,
    }

    impl SetupRig {
        fn new() -> Self {
            let dir = tempfile::tempdir().unwrap();
            let config_dir = dir.path().join(".kata");
            std::fs::create_dir_all(&config_dir).unwrap();
            let probes = green_probes(dir.path());
            let args = HostSetupArgs {
                config: config_dir.join("kata.toml"),
                install_apparmor: false,
                environment_file: Some(environment_file(dir.path())),
                provider_source: Some(provider_source(dir.path())),
                provider_ip: Some(store_ip(dir.path())),
            };
            Self {
                _unseal: kata_worker::UnsealOnDrop::new(dir.path()),
                dir,
                args,
                probes,
                execs: std::cell::RefCell::new(Vec::new()),
            }
        }

        fn run(&self) -> HostSetupReport {
            let mut exec = |argv: &[String]| -> Result<String, String> {
                self.execs.borrow_mut().push(argv.join(" "));
                if answers_nix_probe(argv) {
                    return Ok("nix-store (Nix) 2.34.8".to_string());
                }
                if argv.iter().any(|a| a == "--realise") {
                    return Ok(argv[2].clone());
                }
                if argv[0] == "sudo" {
                    return Ok(String::new());
                }
                Err(format!("unexpected argv: {}", argv.join(" ")))
            };
            run_setup_with(
                &self.args,
                &self.probes,
                &mut exec,
                &verify_ok,
                &delegation_ok,
                &no_ambient,
                &passing_doctor,
            )
            .unwrap()
        }

        fn execs(&self) -> Vec<String> {
            self.execs.borrow().clone()
        }
    }

    #[test]
    fn merge_env_file_appends_only_the_missing_and_refuses_a_conflict() {
        let required: Vec<(&'static str, String)> = vec![
            ("KATA_EXTERNAL_PROVIDER_STORE", "/store".to_string()),
            ("KATA_EXTERNAL_EXECUTION_PROVIDER", "youki".to_string()),
        ];
        // An existing, unrelated declaration is preserved; missing keys append.
        let merged = merge_env_file("FOO=bar\n", &required).unwrap().unwrap();
        assert!(
            merged.starts_with("FOO=bar\n"),
            "existing lines stay: {merged}"
        );
        assert!(merged.contains("KATA_EXTERNAL_PROVIDER_STORE=/store"));
        assert!(merged.contains("KATA_EXTERNAL_EXECUTION_PROVIDER=youki"));
        // All keys present and equal → nothing to write.
        let declared = "KATA_EXTERNAL_PROVIDER_STORE=/store\n\
                        KATA_EXTERNAL_EXECUTION_PROVIDER=youki\n";
        assert_eq!(merge_env_file(declared, &required).unwrap(), None);
        // A DIFFERENT declared value is the refusal, naming both answers.
        let error = merge_env_file("KATA_EXTERNAL_EXECUTION_PROVIDER=podman\n", &required)
            .expect_err("a conflicting declaration must refuse");
        let text = format!("{error}");
        assert!(text.starts_with("env_file_conflict"), "{text}");
        assert!(text.contains("podman") && text.contains("youki"), "{text}");
    }

    /// The exports under setup's own header are setup's: a stale value there
    /// (a rebuilt provider has a new address) is replaced in place, and every
    /// other line is kept byte for byte. The same key declared OUTSIDE that
    /// block is the operator's, and a different value there still refuses.
    #[test]
    fn merge_env_file_replaces_a_stale_value_only_in_its_own_block() {
        let required: Vec<(&'static str, String)> = vec![
            ("KATA_EXTERNAL_PROVIDER_STORE", "/store".to_string()),
            (
                "KATA_EXTERNAL_EXECUTION_PROVIDER_ADDRESS",
                "store:new".to_string(),
            ),
        ];
        let written = merge_env_file(
            "FOO=bar\n",
            &[
                ("KATA_EXTERNAL_PROVIDER_STORE", "/store".to_string()),
                (
                    "KATA_EXTERNAL_EXECUTION_PROVIDER_ADDRESS",
                    "store:old".to_string(),
                ),
            ],
        )
        .unwrap()
        .unwrap();
        let operator_after = format!("{written}\n# mine\nBAR=baz\n");
        let merged = merge_env_file(&operator_after, &required)
            .expect("a stale value in setup's own block is setup's to replace")
            .expect("the stale value changes the file");
        assert_eq!(
            merged,
            operator_after.replace("store:old", "store:new"),
            "only the stale value moves"
        );
        assert_eq!(merge_env_file(&merged, &required).unwrap(), None);

        let operator =
            format!("KATA_EXTERNAL_EXECUTION_PROVIDER_ADDRESS=store:operator\n\n{written}");
        let error = merge_env_file(&operator, &required)
            .expect_err("the operator's own declaration is never overwritten");
        let text = format!("{error}");
        assert!(text.starts_with("env_file_conflict"), "{text}");
        assert!(text.contains("store:operator"), "{text}");
    }

    #[test]
    fn merge_oci_config_declares_replaces_template_and_refuses_conflicts() {
        let scratch = tempfile::tempdir().unwrap();
        let declaration = parse_environment_file(&environment_file(scratch.path()))
            .unwrap()
            .item;
        let config = Path::new(".kata/kata.toml");
        let scaffolded = "[node]\nid = \"x\"\n# a scaffold comment to preserve\n\
                          \n[api]\nbind = \"127.0.0.1:8400\"\n";
        let (text, changes) =
            merge_oci_config(config, scaffolded, Some(&declaration), true).unwrap();
        assert!(
            text.contains("store_paths = [\"/nix/store/0123456789abcdfghijklmnpqrsvwxyz-env-a\""),
            "{text}"
        );
        assert!(text.contains("egress_allow = []"), "{text}");
        assert!(
            !text.contains("host_logins") && !changes.iter().any(|c| c.contains("host_logins")),
            "no `[node] host_logins` is written: the config load refuses the key: {text}"
        );
        assert!(
            text.contains("# a scaffold comment to preserve"),
            "the merge must not drop the operator-visible comments: {text}"
        );
        assert!(
            changes.iter().any(|c| c.contains("environment")),
            "the scaffolded environment placeholder was replaced: {changes:?}"
        );
        // A `[node]` key the section does not declare refuses — scaffolded or
        // pre-existing — naming the key, before anything is written.
        for scaffold in [true, false] {
            for key in ["execution_profile", "enviroment"] {
                let error = merge_oci_config(
                    config,
                    &format!("[node]\nid = \"x\"\n{key} = \"oci\"\n"),
                    Some(&declaration),
                    scaffold,
                )
                .expect_err("an undeclared [node] key must refuse");
                let error = format!("{error}");
                assert!(
                    error.starts_with("config_conflict")
                        && error.contains(&format!("{key}: `[node]` declares no such key")),
                    "{error}"
                );
            }
        }
        // The merged document must parse under the strict TOML 1.0 grammar the
        // loader uses — not only the 1.1 superset `toml_edit` accepts.
        text.parse::<toml::Value>()
            .expect("the merged text parses under strict TOML 1.0");
        // Idempotent: the merged output merges again with zero changes.
        let (again, changes_again) =
            merge_oci_config(config, &text, Some(&declaration), false).unwrap();
        assert_eq!(again, text);
        assert!(changes_again.is_empty());
        // A different declared environment is refused the same way.
        let other_environment = "{ store_paths = [\"/nix/store/different\"] }";
        let error = merge_oci_config(
            config,
            &format!("[node]\nenvironment = {other_environment}\n"),
            Some(&declaration),
            false,
        )
        .expect_err("a different declared environment must refuse");
        assert!(format!("{error}").starts_with("config_conflict"));
        // No [node] table at all refuses — a kata config owns it.
        assert!(matches!(
            merge_oci_config(config, "[api]\nbind = \"x\"\n", Some(&declaration), false),
            Err(SetupRefusal::ConfigConflict { .. })
        ));
    }

    /// A declaration authored in the TOML-1.1-only shape — a multi-line
    /// inline table, which `toml_edit` accepts and the strict 1.0 loader
    /// refuses — must never land in a written config: the merge refuses with
    /// `config_unparseable` rather than author a file that fails its own
    /// parse.
    #[test]
    fn a_toml11_only_environment_is_refused_instead_of_written_unparseable() {
        let scratch = tempfile::tempdir().unwrap();
        let path = scratch.path().join("node-environment.toml");
        std::fs::write(
            &path,
            "[node]\nenvironment = { label = \"x\", system = \"x86_64-linux\",\n  \
             nixpkgs_attribute = \"a\", store_paths = [\"/s\"],\n  \
             path_prepend = [], integrity_policy = { verify = \"nar_hash_only\", \
             sigs_needed = 0, required_signers = [], \
             allow_unsigned_content_addressed = true, verify_contents_at_declare = true } }\n",
        )
        .unwrap();
        let declaration = parse_environment_file(&path)
            .expect("toml_edit parses the 1.1 shape")
            .item;
        let error = merge_oci_config(
            Path::new(".kata/kata.toml"),
            "[node]\nid = \"x\"\n",
            Some(&declaration),
            true,
        )
        .expect_err("the 1.1-only declaration must refuse");
        assert!(
            format!("{error}").starts_with("config_unparseable"),
            "{error}"
        );
    }

    #[test]
    fn parse_environment_file_names_the_missing_and_malformed() {
        let dir = tempfile::tempdir().unwrap();
        let good = environment_file(dir.path());
        let decl = parse_environment_file(&good).unwrap();
        assert_eq!(
            decl.store_paths,
            vec![
                "/nix/store/0123456789abcdfghijklmnpqrsvwxyz-env-a",
                "/nix/store/vwxyz0123456789abcdfghijklmnpqrs-env-b"
            ]
        );
        let missing = dir.path().join("missing.toml");
        std::fs::write(&missing, "[node]\nid = \"x\"\n").unwrap();
        let error = parse_environment_file(&missing).expect_err("no environment key");
        assert!(format!("{error}").starts_with("node_environment_file"));
        let malformed = dir.path().join("malformed.toml");
        std::fs::write(&malformed, "[node]\nenvironment = {\n").unwrap();
        assert!(parse_environment_file(&malformed).is_err());
        let not_array = dir.path().join("not-array.toml");
        std::fs::write(
            &not_array,
            "[node]\nenvironment = { store_paths = \"x\" }\n",
        )
        .unwrap();
        assert!(parse_environment_file(&not_array).is_err());
    }

    #[test]
    fn toml_items_equal_compares_values_not_key_order() {
        let a: toml_edit::Item = "{ label = \"x\", store_paths = [\"/a\"] }"
            .parse::<toml_edit::Item>()
            .unwrap();
        let b: toml_edit::Item = "{ store_paths = [\"/a\"], label = \"x\" }"
            .parse::<toml_edit::Item>()
            .unwrap();
        let c: toml_edit::Item = "{ label = \"x\", store_paths = [\"/b\"] }"
            .parse::<toml_edit::Item>()
            .unwrap();
        assert!(toml_items_equal(&a, &b), "key order is not a difference");
        assert!(
            !toml_items_equal(&a, &c),
            "a differing path IS a difference"
        );
    }

    #[test]
    fn apparmor_state_folds_the_two_reads() {
        let dir = tempfile::tempdir().unwrap();
        let mut probes = scratch_probes(dir.path());
        std::fs::create_dir_all(&probes.apparmor_dir).unwrap();
        let profile_path = probes.apparmor_dir.join(pin().profile_name());
        // Ready: name loaded + file is the render.
        std::fs::write(&probes.apparmor_loaded, "youki (enforce)\n").unwrap();
        std::fs::write(&profile_path, render_apparmor_profile(pin())).unwrap();
        assert!(matches!(
            apparmor_state(pin(), &probes),
            ApparmorState::Ready
        ));
        // Name absent from a readable list → needs install.
        std::fs::write(&probes.apparmor_loaded, "unconfined (unconfined)\n").unwrap();
        assert!(matches!(
            apparmor_state(pin(), &probes),
            ApparmorState::NeedsInstall(_)
        ));
        // Unreadable list + installed file the render → the certification's
        // fold admits, and the load is unread from here.
        probes.apparmor_loaded = dir.path().join("no-such-list");
        assert!(matches!(
            apparmor_state(pin(), &probes),
            ApparmorState::InstalledLoadUnread
        ));
        // Unreadable list + no installed file → the fold refuses
        // `profile_file_absent`, which the install verb fixes.
        std::fs::remove_file(&profile_path).unwrap();
        assert!(matches!(
            apparmor_state(pin(), &probes),
            ApparmorState::NeedsInstall(reason) if reason.contains("does not exist")
        ));
        // Name loaded but the FILE differs → needs install (rebind name→path).
        std::fs::write(&probes.apparmor_loaded, "youki (enforce)\n").unwrap();
        std::fs::write(&profile_path, "profile youki /other/path {}\n").unwrap();
        assert!(matches!(
            apparmor_state(pin(), &probes),
            ApparmorState::NeedsInstall(_)
        ));
    }

    #[test]
    fn a_green_run_provisions_writes_env_merges_config_and_reports_changed() {
        let rig = SetupRig::new();
        let report = rig.run();
        assert!(report.complete, "a green rig must complete: {report:?}");
        assert!(report.changed, "a first run changes things");
        // The provider entry landed in the by-hash store under .kata/providers.
        let store_entries = std::fs::read_dir(rig.dir.path().join(".kata/providers"))
            .unwrap()
            .count();
        assert_eq!(store_entries, 1, "one by-hash entry");
        // .env holds the three exports at the project root.
        let env = std::fs::read_to_string(rig.dir.path().join(".env")).unwrap();
        assert!(env.contains("KATA_EXTERNAL_PROVIDER_STORE="));
        assert!(env.contains("KATA_EXTERNAL_EXECUTION_PROVIDER=youki"));
        assert!(env.contains("KATA_EXTERNAL_EXECUTION_PROVIDER_ADDRESS="));
        // The config was scaffolded then merged — and it parses under the
        // strict TOML 1.0 grammar the config loader uses, not only the 1.1
        // superset `toml_edit` accepts.
        let config = std::fs::read_to_string(&rig.args.config).unwrap();
        config
            .parse::<toml::Value>()
            .expect("a merged config parses under strict TOML 1.0");
        kata_types::config::parse_kata_config(&config, &rig.args.config)
            .expect("the merged config is one the loader's typed parse admits");
        assert!(
            config.contains("store_paths = [\"/nix/store/0123456789abcdfghijklmnpqrsvwxyz-env-a\""),
            "{config}"
        );
        // The scaffold seeds the same starters under every run — the factory
        // packs compile under `oci` since their stages were re-authored.
        let workflows_dir = rig.dir.path().join(".kata/workflows");
        assert!(
            workflows_dir.join("std.hello.star").is_file(),
            "the always-green starter is seeded"
        );
        for factory in [
            "std.software_factory.kata_self_improve.star",
            "std.software_factory.kata_self_improve_preflight.star",
        ] {
            assert!(
                workflows_dir.join(factory).is_file(),
                "the factory starters seed under oci — they compile: {factory}"
            );
        }
        // The environment's store paths were realised and rooted — each as
        // the operand AFTER `--`, so no value can ever be read as a flag.
        let execs = rig.execs();
        assert!(
            execs
                .iter()
                .any(|a| a.contains("-- /nix/store/0123456789abcdfghijklmnpqrsvwxyz-env-a")),
            "{execs:?}"
        );
        assert!(
            execs
                .iter()
                .any(|a| a.contains("-- /nix/store/vwxyz0123456789abcdfghijklmnpqrs-env-b")),
            "{execs:?}"
        );
        assert!(
            rig.dir.path().join(".kata/nix-roots").is_dir()
                || execs.iter().any(|a| a.contains("--add-root")),
            "every realise names a GC root link"
        );
    }

    #[test]
    fn a_second_run_changes_nothing() {
        let rig = SetupRig::new();
        let first = rig.run();
        assert!(first.complete && first.changed);
        let second = rig.run();
        assert!(second.complete, "{second:?}");
        assert!(
            !second.changed,
            "the second run must report no change: {second:?}"
        );
    }

    /// **An UNPRIVILEGED re-run on a host whose profile is installed changes
    /// nothing and demands no reinstall.** After a completed run the loaded-profile
    /// list becomes unreadable — the ordinary non-root view of
    /// `/sys/kernel/security/apparmor/profiles` — while the installed file is still
    /// the render byte for byte. The re-run must not re-install it (no `sudo` is
    /// exec'd, even under `--install-apparmor`), must not defer an action for it,
    /// and moves no byte.
    #[test]
    fn an_unprivileged_rerun_over_an_installed_profile_demands_no_reinstall() {
        let mut rig = SetupRig::new();
        assert!(rig.run().complete, "the first run completes");
        std::fs::remove_file(&rig.probes.apparmor_loaded).unwrap();
        for install_apparmor in [false, true] {
            rig.args.install_apparmor = install_apparmor;
            rig.execs.borrow_mut().clear();
            let rerun = rig.run();
            let apparmor = rerun.steps.iter().find(|s| s.name == "apparmor").unwrap();
            assert_eq!(
                apparmor.status,
                StepStatus::InPlace,
                "--install-apparmor={install_apparmor}: {apparmor:?}"
            );
            assert!(rerun.actions.is_empty(), "no action demanded: {rerun:?}");
            assert!(!rerun.changed, "a re-run moves no byte: {rerun:?}");
            assert!(
                !rig.execs().iter().any(|argv| argv.starts_with("sudo")),
                "no reinstall was exec'd: {:?}",
                rig.execs()
            );
            assert!(
                apparmor.detail.contains("kata-oci-certify-test"),
                "the step names what observed the profile — the container that ran: {}",
                apparmor.detail
            );
            assert!(rerun.complete, "observed, nothing deferred: {rerun:?}");
        }
    }

    /// The twin: the same re-run where the functional arm REFUSES — a rootless
    /// container of the pinned runtime does not start. Nothing observed the load,
    /// so nothing claims it: the step defers with the install action, says the
    /// load state needs root to confirm, and the run is `incomplete`.
    #[test]
    fn an_unprivileged_rerun_whose_container_does_not_start_claims_nothing() {
        let mut rig = SetupRig::new();
        assert!(rig.run().complete, "the first run completes");
        std::fs::remove_file(&rig.probes.apparmor_loaded).unwrap();
        rig.probes.functional = functional_refused;
        let rerun = rig.run();
        let apparmor = rerun.steps.iter().find(|s| s.name == "apparmor").unwrap();
        assert_eq!(apparmor.status, StepStatus::Deferred, "{apparmor:?}");
        assert!(
            apparmor.detail.contains("needs root to confirm")
                && apparmor.detail.contains("Operation not permitted"),
            "{}",
            apparmor.detail
        );
        assert_eq!(rerun.actions, vec![APPARMOR_INSTALL_COMMAND.to_string()]);
        assert!(
            !rerun.complete,
            "an unobserved load is never complete: {rerun:?}"
        );
        assert!(!rerun.changed, "{rerun:?}");
    }

    /// **What the container start observes is the kernel's to say.** The same
    /// unprivileged re-run, once per restriction state. On a kernel that RESTRICTS
    /// unprivileged user namespaces, the pinned runtime's rootless container starts
    /// only under a profile that admits it, so the step may say one is in force. On
    /// an unrestricted (or unreadable) kernel the container starts with no profile
    /// loaded at all, so the start says nothing about the load — the step must say
    /// the load is NOT observed, and must not claim it was. Both are `complete`: the
    /// certification admits exactly this pair (an unknown load, a container that ran).
    #[test]
    fn an_unprivileged_rerun_words_the_observation_by_the_kernel() {
        for (knob, in_force) in [(Some("1\n"), true), (Some("0\n"), false), (None, false)] {
            let rig = SetupRig::new();
            assert!(rig.run().complete, "the first run completes");
            std::fs::remove_file(&rig.probes.apparmor_loaded).unwrap();
            match knob {
                Some(value) => std::fs::write(&rig.probes.userns_restriction_knob, value).unwrap(),
                None => std::fs::remove_file(&rig.probes.userns_restriction_knob).unwrap(),
            }
            let rerun = rig.run();
            let apparmor = rerun.steps.iter().find(|s| s.name == "apparmor").unwrap();
            assert_eq!(
                apparmor.status,
                StepStatus::InPlace,
                "{knob:?}: {apparmor:?}"
            );
            assert!(rerun.complete, "{knob:?}: {rerun:?}");
            assert!(
                apparmor.detail.contains("kata-oci-certify-test"),
                "{knob:?}: names the container that ran: {}",
                apparmor.detail
            );
            if in_force {
                assert!(
                    apparmor
                        .detail
                        .contains("restricts unprivileged user namespaces")
                        && apparmor.detail.contains("in force"),
                    "{knob:?}: {}",
                    apparmor.detail
                );
            } else {
                assert!(
                    apparmor.detail.contains("load is NOT observed")
                        && !apparmor.detail.contains("in force")
                        && !apparmor.detail.contains("was observed"),
                    "{knob:?}: an unrestricted kernel's start decides nothing about the load: {}",
                    apparmor.detail
                );
            }
        }
    }

    /// **`--install-apparmor` re-observes what it installed.** The unprivileged
    /// re-run whose container does not start, with the install requested: the
    /// privileged verb exits 0, the loaded list is still unreadable, and the
    /// container still does not start. Nothing observed the install taking effect,
    /// so the step is refused with the functional refusal and the run is not
    /// `complete` — the reload's exit status is not an observation of the load.
    #[test]
    fn an_install_whose_container_still_does_not_start_is_not_complete() {
        let mut rig = SetupRig::new();
        assert!(rig.run().complete, "the first run completes");
        std::fs::remove_file(&rig.probes.apparmor_loaded).unwrap();
        rig.probes.functional = functional_refused;
        rig.args.install_apparmor = true;
        rig.execs.borrow_mut().clear();
        let rerun = rig.run();
        assert!(
            rig.execs().iter().any(|argv| argv.starts_with("sudo")),
            "the requested install ran: {:?}",
            rig.execs()
        );
        let apparmor = rerun.steps.iter().find(|s| s.name == "apparmor").unwrap();
        assert_eq!(apparmor.status, StepStatus::Refused, "{apparmor:?}");
        assert!(
            apparmor.detail.contains("Operation not permitted"),
            "the refusal carries what the container start said: {}",
            apparmor.detail
        );
        assert!(
            !rerun.complete,
            "an unobserved load is never complete: {rerun:?}"
        );
    }

    /// **A container start that fails for a reason that is not AppArmor's is
    /// not sent to the AppArmor install.** The throwaway bundle could not be
    /// prepared (`functional_harness`: no container started), or the pinned
    /// runtime refused the container with stderr naming neither AppArmor nor a
    /// capability denial (`functional_run_refused` with no denial read). Installing
    /// the profile changes neither, so the step must not defer that install as its
    /// action, must not exec it under `--install-apparmor`, and refuses with the
    /// certification's own token — the run is not `complete`.
    #[test]
    fn a_container_start_failure_that_is_not_apparmor_is_not_sent_to_the_apparmor_install() {
        for token in ["functional_harness", "functional_run_refused"] {
            for install_apparmor in [false, true] {
                let mut rig = SetupRig::new();
                assert!(rig.run().complete, "the first run completes");
                std::fs::remove_file(&rig.probes.apparmor_loaded).unwrap();
                rig.probes.functional = if token == "functional_harness" {
                    functional_harness_failed
                } else {
                    functional_run_unclassified
                };
                rig.args.install_apparmor = install_apparmor;
                rig.execs.borrow_mut().clear();
                let rerun = rig.run();
                let case = format!("{token} --install-apparmor={install_apparmor}");
                let apparmor = rerun.steps.iter().find(|s| s.name == "apparmor").unwrap();
                assert_eq!(apparmor.status, StepStatus::Refused, "{case}: {apparmor:?}");
                assert!(
                    apparmor.detail.contains(token),
                    "{case}: the refusal carries the certification's token: {}",
                    apparmor.detail
                );
                assert!(
                    rerun.actions.is_empty(),
                    "{case}: no AppArmor install is demanded: {rerun:?}"
                );
                assert!(
                    !rig.execs().iter().any(|argv| argv.starts_with("sudo")),
                    "{case}: no AppArmor install was exec'd: {:?}",
                    rig.execs()
                );
                assert!(!rerun.complete, "{case}: {rerun:?}");
            }
        }
    }

    /// **The post-install re-check routes a non-AppArmor failure the same way.**
    /// The container start is AppArmor-shaped BEFORE the install (EPERM), so
    /// `--install-apparmor` runs it; AFTER it, the start fails for a reason that
    /// is not AppArmor's. The install did run and the profile is in place, so
    /// that failure is not the install's: the step refuses with the
    /// certification's token, never `apparmor_install_failed`, and the run is not
    /// `complete`.
    #[test]
    fn a_non_apparmor_failure_after_the_install_is_not_the_installs() {
        for (token, functional) in [
            (
                "functional_harness",
                eperm_then_harness_failed as fn(&YoukiPin) -> _,
            ),
            ("functional_run_refused", eperm_then_run_unclassified),
        ] {
            let mut rig = SetupRig::new();
            assert!(rig.run().complete, "{token}: the first run completes");
            std::fs::remove_file(&rig.probes.apparmor_loaded).unwrap();
            FUNCTIONAL_CALLS.with(|calls| calls.set(0));
            rig.probes.functional = functional;
            rig.args.install_apparmor = true;
            rig.execs.borrow_mut().clear();
            let rerun = rig.run();
            assert_eq!(
                FUNCTIONAL_CALLS.with(std::cell::Cell::get),
                2,
                "{token}: the container start was taken before AND after the install"
            );
            assert_eq!(
                rig.execs()
                    .iter()
                    .filter(|argv| argv.starts_with("sudo"))
                    .count(),
                1,
                "{token}: the AppArmor-shaped first start ran the install: {:?}",
                rig.execs()
            );
            let apparmor = rerun.steps.iter().find(|s| s.name == "apparmor").unwrap();
            assert_eq!(
                apparmor.status,
                StepStatus::Refused,
                "{token}: {apparmor:?}"
            );
            assert!(
                apparmor.detail.starts_with(token),
                "{token}: refused with the certification's token: {}",
                apparmor.detail
            );
            assert!(
                !apparmor.detail.contains("apparmor_install_failed"),
                "{token}: a failure that is not AppArmor's is not the install's: {}",
                apparmor.detail
            );
            assert!(!rerun.complete, "{token}: {rerun:?}");
        }
    }

    #[test]
    fn the_apparmor_deferral_names_the_exact_sudo_command() {
        let rig = SetupRig::new();
        // Uninstalled: readable list without the name, no installed file.
        std::fs::write(&rig.probes.apparmor_loaded, "unconfined (unconfined)\n").unwrap();
        std::fs::remove_file(rig.probes.apparmor_dir.join(pin().profile_name())).unwrap();
        let report = rig.run();
        let apparmor = report.steps.iter().find(|s| s.name == "apparmor").unwrap();
        assert_eq!(apparmor.status, StepStatus::Deferred);
        assert_eq!(report.actions, vec![APPARMOR_INSTALL_COMMAND.to_string()]);
        // The doctor verdict still runs — the deferred step does not stop it.
        assert!(report.doctor.is_some());
        // But a run that left operator actions outstanding is NOT complete:
        // on a restricted host every capsule would EPERM until the deferred
        // install lands, and `complete` must not claim otherwise.
        assert!(
            !report.complete,
            "a deferred action holds the verdict at incomplete: {report:?}"
        );
        let rendered = render_setup(&report);
        assert!(rendered.contains("actions required:"), "{rendered}");
        assert!(rendered.contains(APPARMOR_INSTALL_COMMAND), "{rendered}");
        // The column-aligned `status     incomplete` row the renderer emits.
        // kata-spacing: intentional
        assert!(rendered.contains("status     incomplete"), "{rendered}");
    }

    /// The composed verdict against the REAL doctor, not a stub — a
    /// tempdir project scaffolded by the run itself, AppArmor deferred (the
    /// scratch probes name paths that were never planted), and the report
    /// must be `incomplete` naming the deferred action regardless of the
    /// doctor verdict the host happens to deliver.
    #[test]
    fn the_real_doctor_compose_reports_incomplete_while_apparmor_is_deferred() {
        let dir = tempfile::tempdir().unwrap();
        // The `provider` step seals a by-hash store under `.kata/providers`;
        // declared AFTER `dir` so it drops BEFORE it. See `kata_worker::UnsealOnDrop`.
        let _unseal = kata_worker::UnsealOnDrop::new(dir.path());
        let config_dir = dir.path().join(".kata");
        std::fs::create_dir_all(&config_dir).unwrap();
        // Deliberately NOT green: nothing under the apparmor paths, so the
        // state folds to Unknown/NeedsInstall and defers.
        let probes = scratch_probes(dir.path());
        std::fs::create_dir_all(probes.exe_dir.parent().unwrap()).unwrap();
        let mut exec = |argv: &[String]| -> Result<String, String> {
            if answers_nix_probe(argv) {
                return Ok("nix-store (Nix) 2.34.8".to_string());
            }
            if argv.iter().any(|a| a == "--realise") {
                return Ok(String::new());
            }
            Err(format!("unexpected argv: {}", argv.join(" ")))
        };
        let args = HostSetupArgs {
            config: config_dir.join("kata.toml"),
            install_apparmor: false,
            environment_file: Some(environment_file(dir.path())),
            provider_source: Some(provider_source(dir.path())),
            provider_ip: Some(store_ip(dir.path())),
        };
        let report = run_setup_with(
            &args,
            &probes,
            &mut exec,
            &verify_ok,
            &delegation_ok,
            &no_ambient,
            &|config| {
                crate::cli::doctor::doctor_report_with_logins_dir(
                    config,
                    &[],
                    crate::cli::testing::no_kata_logins(config),
                )
            },
        )
        .unwrap();
        assert!(
            !report.complete,
            "a deferred host action must hold the composed verdict at incomplete: {report:?}"
        );
        assert_eq!(
            report.actions,
            vec![APPARMOR_INSTALL_COMMAND.to_string()],
            "the deferred action is named exactly"
        );
        assert!(report.doctor.is_some(), "the real doctor still ran");
    }

    #[test]
    fn install_apparmor_execs_sudo_and_the_pin_stays_the_guard() {
        let dir = tempfile::tempdir().unwrap();
        let config_dir = dir.path().join(".kata");
        std::fs::create_dir_all(&config_dir).unwrap();
        let mut probes = green_probes(dir.path());
        std::fs::write(&probes.apparmor_loaded, "unconfined (unconfined)\n").unwrap();
        std::fs::remove_file(probes.apparmor_dir.join(pin().profile_name())).unwrap();
        // The install verb "fixes" the state only if the exec actually
        // installed — here the sudo re-exec writes the profile+list so the
        // post-install re-fold sees Ready, the honest shape of the hand-off.
        let profile_path = probes.apparmor_dir.join(pin().profile_name());
        let loaded_path = probes.apparmor_loaded.clone();
        let mut exec = |argv: &[String]| -> Result<String, String> {
            if argv[0] == "sudo" {
                std::fs::write(&profile_path, render_apparmor_profile(pin())).unwrap();
                std::fs::write(&loaded_path, "youki (enforce)\n").unwrap();
                return Ok(String::new());
            }
            if answers_nix_probe(argv) {
                return Ok("nix".to_string());
            }
            if argv.iter().any(|a| a == "--realise") {
                return Ok(String::new());
            }
            Err("unexpected".to_string())
        };
        probes.exe = dir.path().join("kata");
        let args = HostSetupArgs {
            config: config_dir.join("kata.toml"),
            install_apparmor: true,
            environment_file: Some(environment_file(dir.path())),
            provider_source: Some(provider_source(dir.path())),
            provider_ip: Some(store_ip(dir.path())),
        };
        let report = run_setup_with(
            &args,
            &probes,
            &mut exec,
            &verify_ok,
            &delegation_ok,
            &no_ambient,
            &passing_doctor,
        )
        .unwrap();
        let apparmor = report.steps.iter().find(|s| s.name == "apparmor").unwrap();
        assert_eq!(apparmor.status, StepStatus::Changed, "{apparmor:?}");
    }

    /// The privileged install re-exec writes the render, but this process
    /// re-reads the kernel's loaded list as the unprivileged caller — on a
    /// hardened host that read fails. The file comparison is the half the
    /// re-check CAN prove, and the certification's functional arm (a rootless
    /// container that starts) is the other, so the step is `changed` — never a
    /// refusal claiming the profile is "still not in force". Its twin, where the
    /// container does not start, is
    /// `an_install_whose_container_still_does_not_start_is_not_complete`.
    #[test]
    fn install_apparmor_reports_changed_when_the_loaded_list_is_unreadable() {
        let dir = tempfile::tempdir().unwrap();
        let config_dir = dir.path().join(".kata");
        std::fs::create_dir_all(&config_dir).unwrap();
        let mut probes = green_probes(dir.path());
        // Pre-install state: the list is UNREADABLE (absent file), the
        // installed file absent — `Unknown`, the deferred/refusable arm.
        std::fs::remove_file(&probes.apparmor_loaded).unwrap();
        std::fs::remove_file(probes.apparmor_dir.join(pin().profile_name())).unwrap();
        // The privileged verb lands the file — but leaves the loaded list as
        // unreadable as it was, the hardened-host shape.
        let profile_path = probes.apparmor_dir.join(pin().profile_name());
        let mut exec = |argv: &[String]| -> Result<String, String> {
            if argv[0] == "sudo" {
                std::fs::write(&profile_path, render_apparmor_profile(pin())).unwrap();
                return Ok(String::new());
            }
            if answers_nix_probe(argv) {
                return Ok("nix".to_string());
            }
            if argv.iter().any(|a| a == "--realise") {
                return Ok(String::new());
            }
            Err("unexpected".to_string())
        };
        probes.exe = dir.path().join("kata");
        let args = HostSetupArgs {
            config: config_dir.join("kata.toml"),
            install_apparmor: true,
            environment_file: Some(environment_file(dir.path())),
            provider_source: Some(provider_source(dir.path())),
            provider_ip: Some(store_ip(dir.path())),
        };
        let report = run_setup_with(
            &args,
            &probes,
            &mut exec,
            &verify_ok,
            &delegation_ok,
            &no_ambient,
            &passing_doctor,
        )
        .unwrap();
        let apparmor = report.steps.iter().find(|s| s.name == "apparmor").unwrap();
        assert_eq!(
            apparmor.status,
            StepStatus::Changed,
            "an unverifiable load with a proven-installed file is not a refusal: {apparmor:?}"
        );
        assert!(
            apparmor.detail.contains("kata-oci-certify-test")
                && apparmor.detail.contains("load is NOT observed"),
            "the step re-observes through the certification's functional arm, and on this \
             unrestricted fixture kernel claims nothing about the load: {}",
            apparmor.detail
        );
        assert!(
            report.complete,
            "nothing was deferred and doctor passed: {report:?}"
        );
    }

    /// The main runs the `nix` CLI (`nix store info` at boot, `nix path-info` and
    /// `nix store verify` on a declaration), which needs Nix's `nix-command` feature;
    /// `nix-store` does not. A host whose `nix-store` answers and whose `nix` refuses the
    /// feature must stop at the `nix` step, naming the feature — not finish `complete`
    /// for a main that then refuses at boot. The refusal text is nix's own (Nix 2.35.5
    /// with `NIX_CONFIG='experimental-features = '`).
    #[test]
    fn a_nix_without_the_nix_command_feature_stops_setup_at_the_nix_step() {
        let dir = tempfile::tempdir().unwrap();
        let config_dir = dir.path().join(".kata");
        std::fs::create_dir_all(&config_dir).unwrap();
        let probes = green_probes(dir.path());
        let mut exec = |argv: &[String]| -> Result<String, String> {
            match argv
                .iter()
                .map(String::as_str)
                .collect::<Vec<_>>()
                .as_slice()
            {
                ["nix-store", "--version"] => Ok("nix-store (Nix) 2.35.5".to_string()),
                ["nix", "store", "info"] => Err("exited 1: error: experimental Nix feature \
                     'nix-command' is disabled; add '--extra-experimental-features \
                     nix-command' to enable it"
                    .to_string()),
                _ => Ok(String::new()),
            }
        };
        let args = HostSetupArgs {
            config: config_dir.join("kata.toml"),
            install_apparmor: false,
            environment_file: None,
            provider_source: None,
            provider_ip: None,
        };
        let report = run_setup_with(
            &args,
            &probes,
            &mut exec,
            &verify_ok,
            &delegation_ok,
            &no_ambient,
            &passing_doctor,
        )
        .unwrap();
        assert!(!report.complete, "{report:?}");
        let last = report.steps.last().unwrap();
        assert_eq!(last.name, "nix", "{report:?}");
        assert_eq!(last.status, StepStatus::Refused, "{last:?}");
        assert!(
            last.detail.starts_with("nix_command_unavailable")
                && last.detail.contains("experimental-features = nix-command"),
            "the refusal names the feature and where to enable it: {}",
            last.detail
        );
    }

    #[test]
    fn a_named_refusal_stops_the_run_at_that_step() {
        // Nix absent: every step after `nix` must be absent from the report.
        let dir = tempfile::tempdir().unwrap();
        let config_dir = dir.path().join(".kata");
        std::fs::create_dir_all(&config_dir).unwrap();
        let probes = green_probes(dir.path());
        let mut exec =
            |_: &[String]| -> Result<String, String> { Err("command not found".to_string()) };
        let args = HostSetupArgs {
            config: config_dir.join("kata.toml"),
            install_apparmor: false,
            environment_file: None,
            provider_source: None,
            provider_ip: None,
        };
        let report = run_setup_with(
            &args,
            &probes,
            &mut exec,
            &verify_ok,
            &delegation_ok,
            &no_ambient,
            &passing_doctor,
        )
        .unwrap();
        assert!(!report.complete);
        let last = report.steps.last().unwrap();
        assert_eq!(last.name, "nix");
        assert_eq!(last.status, StepStatus::Refused);
        assert!(last.detail.starts_with("nix_absent"), "{}", last.detail);
        assert!(
            !config_dir.join("kata.toml").exists(),
            "no config is written past a refusal"
        );
    }

    #[test]
    fn a_userns_refusal_names_the_knob_it_never_touches() {
        let dir = tempfile::tempdir().unwrap();
        let config_dir = dir.path().join(".kata");
        std::fs::create_dir_all(&config_dir).unwrap();
        let probes = green_probes(dir.path());
        std::fs::write(&probes.userns_clone_knob, "0\n").unwrap();
        let mut exec = |argv: &[String]| -> Result<String, String> {
            if answers_nix_probe(argv) {
                return Ok("nix".to_string());
            }
            Err("unexpected".to_string())
        };
        let args = HostSetupArgs {
            config: config_dir.join("kata.toml"),
            install_apparmor: false,
            environment_file: None,
            provider_source: None,
            provider_ip: None,
        };
        let report = run_setup_with(
            &args,
            &probes,
            &mut exec,
            &verify_ok,
            &delegation_ok,
            &no_ambient,
            &passing_doctor,
        )
        .unwrap();
        let last = report.steps.last().unwrap();
        assert_eq!(last.name, "userns");
        assert_eq!(last.status, StepStatus::Refused);
        assert!(last.detail.starts_with("userns_refused"), "{}", last.detail);
    }

    #[test]
    fn an_unrealisable_youki_refuses_with_the_realised_by_recourse() {
        let dir = tempfile::tempdir().unwrap();
        let config_dir = dir.path().join(".kata");
        std::fs::create_dir_all(&config_dir).unwrap();
        let probes = green_probes(dir.path());
        let mut exec = |argv: &[String]| -> Result<String, String> {
            if answers_nix_probe(argv) {
                return Ok("nix".to_string());
            }
            if argv.iter().any(|a| a == "--realise") {
                return Err("the path is not in any binary cache".to_string());
            }
            Err("unexpected".to_string())
        };
        let absent = |_pin: &YoukiPin| -> Result<String, OciPrerequisiteRefusal> {
            Err(OciPrerequisiteRefusal::BinaryAbsent {
                store_path: "/nix/store/missing".to_string(),
                realised_by: "just youki-build".to_string(),
            })
        };
        let args = HostSetupArgs {
            config: config_dir.join("kata.toml"),
            install_apparmor: false,
            environment_file: None,
            provider_source: None,
            provider_ip: None,
        };
        let report = run_setup_with(
            &args,
            &probes,
            &mut exec,
            &absent,
            &delegation_ok,
            &no_ambient,
            &passing_doctor,
        )
        .unwrap();
        let last = report.steps.last().unwrap();
        assert_eq!(last.name, "youki");
        assert_eq!(last.status, StepStatus::Refused);
        assert!(last.detail.starts_with("binary_absent"), "{}", last.detail);
        assert!(last.detail.contains(pin().realised_by()), "{}", last.detail);
    }

    #[test]
    fn a_missing_provider_source_and_a_missing_member_both_refuse() {
        let dir = tempfile::tempdir().unwrap();
        let config_dir = dir.path().join(".kata");
        std::fs::create_dir_all(&config_dir).unwrap();
        let probes = green_probes(dir.path());
        let mut exec = |argv: &[String]| -> Result<String, String> {
            if answers_nix_probe(argv) {
                return Ok("nix".to_string());
            }
            if argv.iter().any(|a| a == "--realise") {
                return Ok(String::new());
            }
            Err("unexpected".to_string())
        };
        // No --provider-source and no packaged dir under the scratch prefix.
        let args = HostSetupArgs {
            config: config_dir.join("kata.toml"),
            install_apparmor: false,
            environment_file: Some(environment_file(dir.path())),
            provider_source: None,
            provider_ip: None,
        };
        let report = run_setup_with(
            &args,
            &probes,
            &mut exec,
            &verify_ok,
            &delegation_ok,
            &no_ambient,
            &passing_doctor,
        )
        .unwrap();
        let last = report.steps.last().unwrap();
        assert_eq!(last.name, "provider");
        assert!(
            last.detail.starts_with("provider_source_absent"),
            "{}",
            last.detail
        );
        // A source missing `kata-oci-hook` is refused by name.
        let incomplete = dir.path().join("incomplete-source");
        std::fs::create_dir_all(&incomplete).unwrap();
        std::fs::write(incomplete.join("kata-provider-youki"), "x").unwrap();
        let args = HostSetupArgs {
            config: config_dir.join("kata.toml"),
            install_apparmor: false,
            environment_file: Some(environment_file(dir.path())),
            provider_source: Some(incomplete),
            provider_ip: Some(store_ip(dir.path())),
        };
        let report = run_setup_with(
            &args,
            &probes,
            &mut exec,
            &verify_ok,
            &delegation_ok,
            &no_ambient,
            &passing_doctor,
        )
        .unwrap();
        let last = report.steps.last().unwrap();
        assert!(
            last.detail.starts_with("provider_source_incomplete"),
            "{}",
            last.detail
        );
        assert!(last.detail.contains("`kata-oci-hook`"), "{}", last.detail);
    }

    /// The by-hash entries a run published under `.kata/providers`, read off
    /// the filesystem.
    fn published_entries(dir: &Path) -> Vec<String> {
        std::fs::read_dir(dir.join(".kata/providers"))
            .map(|entries| {
                entries
                    .filter_map(Result::ok)
                    .map(|entry| entry.file_name().to_string_lossy().into_owned())
                    .filter(|name| !name.starts_with('.'))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// No `ip` declared — no `--provider-ip`, no packaged declaration — is a
    /// refusal naming both probes, and a declaration file that does not parse
    /// is a refusal naming the file. Nothing is provisioned either way.
    #[test]
    fn an_undeclared_or_unreadable_provider_ip_is_refused_by_name() {
        let mut rig = SetupRig::new();
        rig.args.provider_ip = None;
        let report = rig.run();
        let last = report.steps.last().unwrap();
        assert_eq!(
            (last.name, last.status),
            ("provider", StepStatus::Refused),
            "{last:?}"
        );
        assert!(
            last.detail.starts_with("provider_ip_absent"),
            "{}",
            last.detail
        );
        assert!(last.detail.contains("--provider-ip"), "{}", last.detail);
        assert!(
            last.detail.contains(PACKAGED_PROVIDER_MEMBERS),
            "{}",
            last.detail
        );
        assert!(published_entries(rig.dir.path()).is_empty());

        let packaged = rig
            .probes
            .exe_dir
            .parent()
            .unwrap()
            .join(PACKAGED_PROVIDER_MEMBERS);
        std::fs::create_dir_all(packaged.parent().unwrap()).unwrap();
        std::fs::write(&packaged, "ip = 7\n").unwrap();
        let report = rig.run();
        let last = report.steps.last().unwrap();
        assert!(
            last.detail.starts_with("provider_ip_declaration"),
            "{}",
            last.detail
        );
        assert!(
            last.detail.contains(&packaged.display().to_string()),
            "{}",
            last.detail
        );
        assert!(published_entries(rig.dir.path()).is_empty());
    }

    /// A declared `ip` that does not resolve, resolves to something that is
    /// not a regular executable file, or resolves outside the Nix store is
    /// refused by name — the declared path and the reason in the row — and no
    /// provider entry is published. A link inside the store is FOLLOWED to
    /// the file it names, and that file is what must be under the store.
    #[test]
    fn a_declared_ip_that_is_absent_irregular_or_outside_the_store_is_refused() {
        use std::os::unix::fs::PermissionsExt;
        let mut rig = SetupRig::new();
        let store = rig.probes.nix_store.clone();
        let object = store.join("vwxyz0123456789abcdfghijklmnpqrs-iproute2-7.1.0");
        std::fs::create_dir_all(object.join("bin/ip-dir")).unwrap();
        std::fs::write(object.join("bin/ip-plain"), IP_BYTES).unwrap();
        std::fs::set_permissions(
            object.join("bin/ip-plain"),
            std::fs::Permissions::from_mode(0o444),
        )
        .unwrap();
        let outside = rig.dir.path().join("elsewhere/bin/ip");
        std::fs::create_dir_all(outside.parent().unwrap()).unwrap();
        std::fs::write(&outside, IP_BYTES).unwrap();
        std::fs::set_permissions(&outside, std::fs::Permissions::from_mode(0o555)).unwrap();
        std::os::unix::fs::symlink(&outside, object.join("bin/ip-link-out")).unwrap();

        for (declared, reason) in [
            (object.join("bin/ip-missing"), "does not resolve"),
            (object.join("bin/ip-dir"), "not a regular file"),
            (object.join("bin/ip-plain"), "not executable"),
            (outside.clone(), "outside"),
            (object.join("bin/ip-link-out"), "outside"),
            (store.clone(), "not a regular file"),
        ] {
            rig.args.provider_ip = Some(declared.clone());
            let report = rig.run();
            let last = report.steps.last().unwrap();
            assert_eq!(
                (last.name, last.status),
                ("provider", StepStatus::Refused),
                "{declared:?}: {last:?}"
            );
            assert!(
                last.detail.starts_with("provider_ip_unusable"),
                "{declared:?}: {}",
                last.detail
            );
            assert!(
                last.detail.contains(&declared.display().to_string())
                    && last.detail.contains(reason),
                "{declared:?} must be named with `{reason}`: {}",
                last.detail
            );
            assert!(
                published_entries(rig.dir.path()).is_empty(),
                "{declared:?} published an entry"
            );
        }
    }

    /// The provider entry `kata host setup` provisions from the split layout —
    /// a source of kata-built members plus a declared store `ip` — is the
    /// entry the complete layout (all three in one directory) provisions: one
    /// address, the same three files with the same bytes. Proven through the
    /// packaged declaration, through `--provider-ip` naming a link that
    /// resolves into the store (the link is followed; the file is copied), and
    /// with `--provider-ip` outranking a packaged declaration that names
    /// nothing usable. An old-layout source that still holds `ip` is refused
    /// `provider_source_holds_ip`, with or without a declared one, rather than
    /// resolved by a pick.
    #[test]
    fn a_declared_store_ip_provisions_the_entry_the_complete_layout_does() {
        use std::os::unix::fs::PermissionsExt;
        let mut rig = SetupRig::new();
        let ip = store_ip(rig.dir.path());

        // The complete layout, provisioned directly: the comparison baseline.
        let complete = rig.dir.path().join("complete-source");
        std::fs::create_dir_all(&complete).unwrap();
        for member in PROVIDER_SOURCE_MEMBERS {
            std::fs::create_dir_all(complete.join(member).parent().unwrap()).unwrap();
            std::fs::copy(
                rig.args.provider_source.as_ref().unwrap().join(member),
                complete.join(member),
            )
            .unwrap();
        }
        std::fs::copy(&ip, complete.join("ip")).unwrap();
        let baseline = kata_worker::ProviderStore::new(rig.dir.path().join("baseline-store"))
            .provision(kata_worker::oci_driver::OCI_PROVIDER_NAME, &complete)
            .unwrap();

        let packaged = rig
            .probes
            .exe_dir
            .parent()
            .unwrap()
            .join(PACKAGED_PROVIDER_MEMBERS);
        std::fs::create_dir_all(packaged.parent().unwrap()).unwrap();
        std::fs::write(&packaged, format!("ip = \"{}\"\n", ip.display())).unwrap();
        let profile_link = rig.dir.path().join("profile/bin/ip");
        std::fs::create_dir_all(profile_link.parent().unwrap()).unwrap();
        std::os::unix::fs::symlink(&ip, &profile_link).unwrap();

        for (label, provider_ip, declaration) in [
            ("packaged", None, format!("ip = \"{}\"\n", ip.display())),
            (
                "--provider-ip link",
                Some(profile_link.clone()),
                String::new(),
            ),
            (
                "--provider-ip over packaged",
                Some(ip.clone()),
                "ip = \"/nix/store/absent\"\n".to_string(),
            ),
        ] {
            std::fs::write(&packaged, &declaration).unwrap();
            rig.args.provider_ip = provider_ip;
            let report = rig.run();
            let provider = report
                .steps
                .iter()
                .find(|step| step.name == "provider")
                .unwrap_or_else(|| panic!("{label}: no provider row: {report:?}"));
            assert_ne!(
                provider.status,
                StepStatus::Refused,
                "{label}: {provider:?}"
            );
            assert!(
                provider.detail.contains(&ip.display().to_string()),
                "{label}: the row names the store file copied: {}",
                provider.detail
            );
            // Read back off the filesystem: the `.env` the run wrote and the
            // entry it published.
            let env = std::fs::read_to_string(rig.dir.path().join(".env")).unwrap();
            assert!(
                env.contains(&format!(
                    "KATA_EXTERNAL_EXECUTION_PROVIDER_ADDRESS={}",
                    baseline.address
                )),
                "{label}: the split layout must mint the complete layout's address {}: {env}",
                baseline.address
            );
            assert_eq!(
                published_entries(rig.dir.path()),
                vec![baseline.address.hex().to_string()],
                "{label}"
            );
            let entry = rig
                .dir
                .path()
                .join(".kata/providers")
                .join(baseline.address.hex());
            let mut names: Vec<String> = std::fs::read_dir(&entry)
                .unwrap()
                .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
                .collect();
            names.sort();
            assert_eq!(
                names,
                ["ip", "kata-oci-hook", "kata-provider-youki", "toolhost"],
                "{label}"
            );
            for name in std::iter::once(PROVIDER_IP_MEMBER).chain(PROVIDER_SOURCE_MEMBERS) {
                assert_eq!(
                    std::fs::read(entry.join(name)).unwrap(),
                    std::fs::read(baseline.entry.join(name)).unwrap(),
                    "{label}: `{name}` bytes"
                );
            }
            let ip_meta = std::fs::symlink_metadata(entry.join("ip")).unwrap();
            assert!(
                ip_meta.file_type().is_file() && ip_meta.permissions().mode() & 0o111 != 0,
                "{label}: the entry's `ip` is a regular executable file"
            );
        }

        // An old-layout source still holding `ip` — beside a declared one,
        // and with none declared — is one refusal naming the source's `ip`,
        // so neither order of fixes meets a second refusal.
        std::fs::remove_file(&packaged).unwrap();
        let before = published_entries(rig.dir.path());
        rig.args.provider_source = Some(complete.clone());
        for (label, provider_ip) in [("declared", Some(ip)), ("undeclared", None)] {
            rig.args.provider_ip = provider_ip;
            let report = rig.run();
            let last = report.steps.last().unwrap();
            assert_eq!(
                (last.name, last.status),
                ("provider", StepStatus::Refused),
                "{label}: {last:?}"
            );
            assert!(
                last.detail.starts_with("provider_source_holds_ip")
                    && last
                        .detail
                        .contains(&complete.join("ip").display().to_string()),
                "{label}: {}",
                last.detail
            );
            assert_eq!(published_entries(rig.dir.path()), before, "{label}");
        }
    }

    /// A kata checkout under the rig's scratch dir with `kata` built into its
    /// `target/release/` beside the two provider members (and the rest of a
    /// Cargo target directory), NO packaged `share/kata` tree, and no flag
    /// naming a source, an `ip` or an environment. Returns the bin dir.
    fn checkout_build(rig: &mut SetupRig) -> PathBuf {
        let checkout = rig.dir.path().join("checkout");
        std::fs::create_dir_all(checkout.join("nix")).unwrap();
        std::fs::write(checkout.join("Cargo.toml"), "[workspace]\n").unwrap();
        std::fs::write(checkout.join("nix/share.nix"), "{ }: null\n").unwrap();
        std::fs::write(checkout.join("nix/youki.nix"), "{ }: null\n").unwrap();
        let bin_dir = checkout.join("target/release");
        std::fs::create_dir_all(bin_dir.join("deps")).unwrap();
        for member in ["kata-provider-youki", "kata-oci-hook"] {
            std::fs::write(bin_dir.join(member), format!("#!/{member}\n")).unwrap();
        }
        for noise in ["kata", "kata-worker", "kata.d", "deps/libkata.rlib"] {
            std::fs::write(bin_dir.join(noise), "not a provider member\n").unwrap();
        }
        // The musl build of the same profile, and the noise beside it.
        let musl = checkout.join("target/x86_64-unknown-linux-musl/release");
        std::fs::create_dir_all(musl.join("deps")).unwrap();
        std::fs::write(musl.join("kata-toolhost"), "#!/kata-toolhost musl\n").unwrap();
        for noise in ["kata-toolhost.d", "deps/kata_toolhost-0123"] {
            std::fs::write(musl.join(noise), "not a provider member\n").unwrap();
        }
        rig.probes.exe_dir = bin_dir.clone();
        rig.probes.exe = bin_dir.join("kata");
        rig.args.provider_source = None;
        rig.args.provider_ip = None;
        rig.args.environment_file = None;
        bin_dir
    }

    /// Run the rig with an `exec` that also answers `nix-build`: for the
    /// checkout's `nix/share.nix` it plants a scratch store object laid out
    /// `share/kata/{provider-members.toml,node-environment.toml}` (declaring the
    /// scratch store `ip` and [`NODE_ENVIRONMENT_TOML`]) and prints its path;
    /// for `nix/youki.nix` it prints a path. `fail_builds` makes every
    /// `nix-build` exit non-zero instead.
    fn run_checkout(
        rig: &SetupRig,
        verify_pin: &dyn Fn(&YoukiPin) -> Result<String, OciPrerequisiteRefusal>,
        fail_builds: bool,
    ) -> HostSetupReport {
        let ip = store_ip(rig.dir.path());
        let share_out = rig
            .dir
            .path()
            .join("nix/store/abcdfghijklmnpqrsvwxyz0123456789-kata-share");
        let mut exec = |argv: &[String]| -> Result<String, String> {
            rig.execs.borrow_mut().push(argv.join(" "));
            if answers_nix_probe(argv) {
                return Ok("nix-store (Nix) 2.34.8".to_string());
            }
            if argv.iter().any(|a| a == "--realise") {
                return Ok(argv[2].clone());
            }
            if argv[0] == "nix-build" {
                if fail_builds {
                    // What `run_command` returns for a failed `nix-build`: its
                    // log streamed to the terminal, so only the exit is here.
                    return Err("exited 1".to_string());
                }
                if argv[3].ends_with("nix/share.nix") {
                    let share = share_out.join("share/kata");
                    std::fs::create_dir_all(&share).unwrap();
                    std::fs::write(
                        share.join("provider-members.toml"),
                        format!("ip = \"{}\"\n", ip.display()),
                    )
                    .unwrap();
                    std::fs::write(share.join("node-environment.toml"), NODE_ENVIRONMENT_TOML)
                        .unwrap();
                    return Ok(share_out.display().to_string());
                }
                return Ok("/nix/store/0123456789abcdfghijklmnpqrsvwxyz-youki".to_string());
            }
            Err(format!("unexpected argv: {}", argv.join(" ")))
        };
        run_setup_with(
            &rig.args,
            &rig.probes,
            &mut exec,
            verify_pin,
            &delegation_ok,
            &no_ambient,
            &passing_doctor,
        )
        .unwrap()
    }

    /// `target/release/kata host setup` in a checkout, with no packaged tree
    /// and no flag: the provider entry holds exactly the two members copied
    /// from beside the binary, the musl release toolhost as
    /// `toolhost/kata-toolhost` (the directory's one entry, as
    /// `ResolvedProvider::toolhost_dir` requires), plus the declared store `ip` — the entry the complete layout mints, none
    /// of the target directory's other files —
    /// and the `ip` and default environment come from ONE `nix-build` of the
    /// checkout's `nix/share.nix`, rooted under `.kata/nix-roots`. Read back
    /// off the filesystem: `.env`, the published entry, the merged config.
    #[test]
    fn a_checkout_build_provisions_its_siblings_and_builds_its_declarations() {
        let mut rig = SetupRig::new();
        let bin_dir = checkout_build(&mut rig);
        let ip = store_ip(rig.dir.path());
        let complete = rig.dir.path().join("complete-source");
        std::fs::create_dir_all(complete.join("toolhost")).unwrap();
        for member in ["kata-provider-youki", "kata-oci-hook"] {
            std::fs::copy(bin_dir.join(member), complete.join(member)).unwrap();
        }
        std::fs::copy(
            rig.dir
                .path()
                .join("checkout/target/x86_64-unknown-linux-musl/release/kata-toolhost"),
            complete.join("toolhost/kata-toolhost"),
        )
        .unwrap();
        std::fs::copy(&ip, complete.join("ip")).unwrap();
        let baseline = kata_worker::ProviderStore::new(rig.dir.path().join("baseline-store"))
            .provision(kata_worker::oci_driver::OCI_PROVIDER_NAME, &complete)
            .unwrap();

        let report = run_checkout(&rig, &verify_ok, false);
        assert!(
            report.complete,
            "a checkout build must complete: {report:?}"
        );
        let env = std::fs::read_to_string(rig.dir.path().join(".env")).unwrap();
        assert!(
            env.contains(&format!(
                "KATA_EXTERNAL_EXECUTION_PROVIDER_ADDRESS={}",
                baseline.address
            )),
            "the checkout build must mint the complete layout's address {}: {env}",
            baseline.address
        );
        assert_eq!(
            published_entries(rig.dir.path()),
            vec![baseline.address.hex().to_string()]
        );
        let mut names: Vec<String> = std::fs::read_dir(
            rig.dir
                .path()
                .join(".kata/providers")
                .join(baseline.address.hex()),
        )
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
        names.sort();
        assert_eq!(
            names,
            ["ip", "kata-oci-hook", "kata-provider-youki", "toolhost"]
        );
        let entry = rig
            .dir
            .path()
            .join(".kata/providers")
            .join(baseline.address.hex());
        assert_eq!(
            std::fs::read(entry.join("toolhost/kata-toolhost")).unwrap(),
            b"#!/kata-toolhost musl\n",
            "the entry's toolhost is the musl build, not anything beside `kata`"
        );
        let toolhost: Vec<String> = std::fs::read_dir(entry.join("toolhost"))
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(toolhost, ["kata-toolhost"]);
        // The staging directory the members were copied through is gone.
        let leftovers: Vec<String> = std::fs::read_dir(rig.dir.path().join(".kata"))
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .filter(|name| name.starts_with(".provider-source"))
            .collect();
        assert!(leftovers.is_empty(), "{leftovers:?}");

        let config = std::fs::read_to_string(&rig.args.config).unwrap();
        assert!(
            config.contains("store_paths = [\"/nix/store/0123456789abcdfghijklmnpqrsvwxyz-env-a\""),
            "the built declaration is the merged environment: {config}"
        );
        let builds: Vec<String> = rig
            .execs()
            .into_iter()
            .filter(|argv| argv.starts_with("nix-build"))
            .collect();
        let checkout = rig.dir.path().join("checkout");
        assert_eq!(
            builds,
            vec![format!(
                "nix-build --out-link {} {}",
                rig.dir.path().join(".kata/nix-roots/kata-share").display(),
                checkout.join("nix/share.nix").display()
            )],
            "one build answers both the `ip` and the environment"
        );
        let provider = report
            .steps
            .iter()
            .find(|step| step.name == "provider")
            .unwrap();
        assert!(
            provider.detail.contains(&bin_dir.display().to_string())
                && provider.detail.contains(&ip.display().to_string()),
            "{}",
            provider.detail
        );
    }

    /// A rebuild changes the provider members' bytes, so re-running setup
    /// provisions a new address. The exports setup wrote to `.env` are its
    /// own: the re-run replaces them and completes, rather than refusing the
    /// file it wrote itself. Read back off the filesystem: `.env` names the
    /// new entry, once, and both entries stay published.
    #[test]
    fn a_rebuilt_checkout_re_runs_setup_over_its_own_env_exports() {
        let mut rig = SetupRig::new();
        let bin_dir = checkout_build(&mut rig);
        let first = run_checkout(&rig, &verify_ok, false);
        assert!(first.complete, "the first run completes: {first:?}");
        let address_line = |env: &str| -> Vec<String> {
            env.lines()
                .filter(|line| line.starts_with("KATA_EXTERNAL_EXECUTION_PROVIDER_ADDRESS="))
                .map(str::to_string)
                .collect()
        };
        let env_path = rig.dir.path().join(".env");
        let before = address_line(&std::fs::read_to_string(&env_path).unwrap());

        std::fs::write(bin_dir.join("kata-oci-hook"), "#!/kata-oci-hook rebuilt\n").unwrap();
        let second = run_checkout(&rig, &verify_ok, false);
        assert!(
            second.complete,
            "a re-run after a rebuild must complete: {:?}",
            second.steps.last()
        );
        let env = std::fs::read_to_string(&env_path).unwrap();
        let after = address_line(&env);
        assert_eq!(after.len(), 1, "one address export: {env}");
        assert_ne!(
            after, before,
            "the export names the rebuilt provider: {env}"
        );
        let entries = published_entries(rig.dir.path());
        assert_eq!(entries.len(), 2, "{entries:?}");
        let hex = after[0].rsplit(':').next().unwrap();
        assert!(
            entries.iter().any(|entry| entry == hex),
            "{hex} in {entries:?}"
        );
        assert_eq!(
            env.matches("# kata host setup").count(),
            1,
            "one setup block: {env}"
        );
        let env_step = second.steps.iter().find(|s| s.name == "env_file").unwrap();
        assert_eq!(env_step.status, StepStatus::Changed, "{env_step:?}");
    }

    /// A checkout build whose pinned youki is absent builds it with the pin's
    /// own expression, `nix/youki.nix` in the checkout, rooted under
    /// `.kata/nix-roots` by the pinned store object's name — not a bare
    /// `nix-store --realise`, which only a binary cache could answer.
    #[test]
    fn a_checkout_build_builds_an_absent_youki_from_the_checkout() {
        let mut rig = SetupRig::new();
        checkout_build(&mut rig);
        let calls = std::cell::Cell::new(0_u32);
        let absent_then_built = |_pin: &YoukiPin| -> Result<String, OciPrerequisiteRefusal> {
            calls.set(calls.get() + 1);
            if calls.get() == 1 {
                Err(OciPrerequisiteRefusal::BinaryAbsent {
                    store_path: pin().store_path().to_string(),
                    realised_by: pin().realised_by().to_string(),
                })
            } else {
                Ok("deadbeef".to_string())
            }
        };
        let report = run_checkout(&rig, &absent_then_built, false);
        let youki = report.steps.iter().find(|s| s.name == "youki").unwrap();
        assert_eq!(youki.status, StepStatus::Changed, "{youki:?}");
        let execs = rig.execs();
        let expected = format!(
            "nix-build --out-link {} {}",
            rig.dir
                .path()
                .join(".kata/nix-roots")
                .join(pin().store_object().base_name())
                .display(),
            rig.dir.path().join("checkout/nix/youki.nix").display()
        );
        assert!(execs.contains(&expected), "{execs:?}");
        assert!(
            !execs
                .iter()
                .any(|argv| argv.contains("--realise")
                    && argv.contains(pin().store_object().as_str())),
            "{execs:?}"
        );
        assert!(youki.detail.contains("nix/youki.nix"), "{}", youki.detail);
    }

    /// A checkout build missing a member beside the binary is
    /// `provider_source_incomplete` naming that directory and the member; a
    /// failing build of the checkout's declarations is `checkout_build_failed`
    /// carrying the argv. Nothing is provisioned either way.
    #[test]
    fn a_checkout_build_missing_a_member_or_failing_its_build_refuses_by_name() {
        let mut rig = SetupRig::new();
        let bin_dir = checkout_build(&mut rig);
        std::fs::remove_file(bin_dir.join("kata-oci-hook")).unwrap();
        let report = run_checkout(&rig, &verify_ok, false);
        let last = report.steps.last().unwrap();
        assert_eq!((last.name, last.status), ("provider", StepStatus::Refused));
        assert!(
            last.detail.starts_with("provider_source_incomplete")
                && last.detail.contains(&bin_dir.display().to_string())
                && last.detail.contains("`kata-oci-hook`"),
            "{}",
            last.detail
        );
        assert!(published_entries(rig.dir.path()).is_empty());

        std::fs::write(bin_dir.join("kata-oci-hook"), "#!/kata-oci-hook\n").unwrap();
        let report = run_checkout(&rig, &verify_ok, true);
        let last = report.steps.last().unwrap();
        assert_eq!((last.name, last.status), ("provider", StepStatus::Refused));
        assert!(
            last.detail.starts_with("checkout_build_failed")
                && last.detail.contains("nix/share.nix")
                && last.detail.contains("failed: exited 1."),
            "{}",
            last.detail
        );
        assert!(published_entries(rig.dir.path()).is_empty());
    }

    /// **The toolhost is probed in `kata`'s own Cargo target directory.**
    /// `target/release/kata` finds it under `target/<musl>/release/`; a `kata`
    /// built into a `CARGO_TARGET_DIR` nested under the checkout's `target/`
    /// (`target/x/release/kata`) finds it under `target/x/<musl>/release/`,
    /// where `CARGO_TARGET_DIR=target/x cargo build --target <musl>` puts it,
    /// not under the checkout's own `target/<musl>/`. The siblings stay
    /// beside `kata`.
    ///
    /// **Would red if:** the toolhost were probed under the checkout root's
    /// `target/` whatever `kata`'s target directory.
    #[test]
    fn the_toolhost_is_probed_in_katas_own_target_directory() {
        let toolhost = "x86_64-unknown-linux-musl/release/kata-toolhost";
        assert_eq!(
            checkout_member(Path::new("/c/target/release"), PROVIDER_TOOLHOST_MEMBER),
            Path::new("/c/target").join(toolhost)
        );
        assert_eq!(
            checkout_member(Path::new("/c/target/x/release"), PROVIDER_TOOLHOST_MEMBER),
            Path::new("/c/target/x").join(toolhost)
        );
        assert_eq!(
            checkout_member(Path::new("/c/target/x/debug"), PROVIDER_TOOLHOST_MEMBER),
            Path::new("/c/target/x/x86_64-unknown-linux-musl/debug/kata-toolhost")
        );
        assert_eq!(
            checkout_member(Path::new("/c/target/x/release"), "kata-oci-hook"),
            Path::new("/c/target/x/release/kata-oci-hook")
        );
    }

    /// A provider source without `toolhost/kata-toolhost` is
    /// `provider_source_incomplete` naming it, both as `--provider-source` (and
    /// so as the packaged `share/kata/provider-source`, the same check) and as a
    /// checkout build, where it is the musl build under the checkout's
    /// `target/x86_64-unknown-linux-musl/<profile>/`, not a sibling of `kata`:
    /// the refusal names that path and the build that makes it. Nothing is
    /// published either way, read off the filesystem.
    ///
    /// **Would red if:** the members list did not hold the toolhost (both
    /// sources provision, with no nanocode capsule init in the entry), or the
    /// checkout looked for it beside `kata`.
    #[test]
    fn a_provider_source_without_the_toolhost_is_refused_by_name() {
        let mut rig = SetupRig::new();
        let source = rig.dir.path().join("no-toolhost-source");
        std::fs::create_dir_all(&source).unwrap();
        for member in ["kata-provider-youki", "kata-oci-hook"] {
            std::fs::write(source.join(member), format!("#!/{member}\n")).unwrap();
        }
        rig.args.provider_source = Some(source.clone());
        let report = rig.run();
        let last = report.steps.last().unwrap();
        assert_eq!((last.name, last.status), ("provider", StepStatus::Refused));
        assert!(
            last.detail.starts_with("provider_source_incomplete")
                && last.detail.contains(&source.display().to_string())
                && last.detail.contains("`toolhost/kata-toolhost`"),
            "{}",
            last.detail
        );
        assert!(published_entries(rig.dir.path()).is_empty());

        let bin_dir = checkout_build(&mut rig);
        let musl = rig
            .dir
            .path()
            .join("checkout/target/x86_64-unknown-linux-musl/release/kata-toolhost");
        std::fs::remove_file(&musl).unwrap_or_default();
        std::fs::write(
            bin_dir.join("kata-toolhost"),
            "#!/a host build beside kata\n",
        )
        .unwrap();
        let report = run_checkout(&rig, &verify_ok, false);
        let last = report.steps.last().unwrap();
        assert_eq!((last.name, last.status), ("provider", StepStatus::Refused));
        assert!(
            last.detail.starts_with("provider_source_incomplete")
                && last.detail.contains("`toolhost/kata-toolhost`")
                && last.detail.contains(&musl.display().to_string())
                && last.detail.contains(
                    "cargo build --release --locked --target x86_64-unknown-linux-musl -p \
                     kata-toolhost"
                ),
            "{}",
            last.detail
        );
        assert!(published_entries(rig.dir.path()).is_empty());
    }

    /// A `nix-build` can run for minutes, so `run_command` streams its log to
    /// the terminal while it runs and its failure carries only the exit — the
    /// `checkout_build_failed` refusal says the log is above it. Any other
    /// command's stderr is captured into its failure. Proven on a real child:
    /// the cell re-runs itself with stderr piped, and reads what the child's
    /// terminal received.
    #[test]
    fn run_command_streams_a_nix_build_log_and_captures_any_other() {
        const CHILD: &str = "KATA_RUN_COMMAND_TEST_DIR";
        if let Some(dir) = std::env::var_os(CHILD) {
            let dir = PathBuf::from(dir);
            let run = |name: &str| run_command(&[dir.join(name).display().to_string()]);
            assert_eq!(run("nix-build"), Err("exited 3".to_string()));
            assert_eq!(
                run("nix-store"),
                Err("exited 3: log line of nix-store".to_string())
            );
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        for name in ["nix-build", "nix-store"] {
            let script = dir.path().join(name);
            std::fs::write(
                &script,
                format!("#!/bin/sh\necho 'log line of {name}' >&2\nexit 3\n"),
            )
            .unwrap();
            std::fs::set_permissions(&script, std::os::unix::fs::PermissionsExt::from_mode(0o755))
                .unwrap();
        }
        let output = Command::new(std::env::current_exe().unwrap())
            .arg("--exact")
            .arg("host_setup::tests::run_command_streams_a_nix_build_log_and_captures_any_other")
            .arg("--nocapture")
            .env(CHILD, dir.path())
            .output()
            .expect("run the run_command child");
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            output.status.success() && stdout.contains("1 passed"),
            "child failed: stdout={stdout} stderr={stderr}"
        );
        assert!(
            stderr.contains("log line of nix-build"),
            "the build log reached the terminal: {stderr}"
        );
        assert!(
            !stderr.contains("log line of nix-store"),
            "a captured command's stderr is in its failure, not the terminal: {stderr}"
        );
    }

    /// The checkout layout is read only for a binary inside the checkout's
    /// `target/`, and only when no packaged tree is beside it: a binary
    /// copied elsewhere in the checkout is refused as before, naming the
    /// packaged paths it probed, and builds nothing; a packaged
    /// `share/kata` beside a build in `target/` is the answer, and the
    /// checkout's expressions are never built.
    #[test]
    fn only_a_build_in_the_checkout_target_without_a_package_reads_the_checkout() {
        let mut rig = SetupRig::new();
        checkout_build(&mut rig);
        let copied = rig.dir.path().join("checkout/dist/bin");
        std::fs::create_dir_all(&copied).unwrap();
        for member in ["kata-provider-youki", "kata-oci-hook"] {
            std::fs::write(copied.join(member), format!("#!/{member}\n")).unwrap();
        }
        rig.probes.exe_dir = copied.clone();
        rig.probes.exe = copied.join("kata");
        let report = run_checkout(&rig, &verify_ok, false);
        let last = report.steps.last().unwrap();
        assert!(
            last.detail.starts_with("provider_source_absent")
                && last.detail.contains("share/kata/provider-source"),
            "{}",
            last.detail
        );
        assert!(
            !rig.execs().iter().any(|argv| argv.starts_with("nix-build")),
            "{:?}",
            rig.execs()
        );

        let bin_dir = rig.dir.path().join("checkout/target/release");
        rig.probes.exe_dir = bin_dir.clone();
        rig.probes.exe = bin_dir.join("kata");
        let packaged = rig.dir.path().join("checkout/target/share/kata");
        provider_source(&packaged);
        std::fs::write(
            packaged.join("provider-members.toml"),
            format!("ip = \"{}\"\n", store_ip(rig.dir.path()).display()),
        )
        .unwrap();
        std::fs::write(
            packaged.join("node-environment.toml"),
            NODE_ENVIRONMENT_TOML,
        )
        .unwrap();
        let report = run_checkout(&rig, &verify_ok, false);
        assert!(report.complete, "{report:?}");
        assert!(
            !rig.execs().iter().any(|argv| argv.starts_with("nix-build")),
            "{:?}",
            rig.execs()
        );
    }

    #[test]
    fn a_conflicting_env_file_refuses_instead_of_overwriting() {
        let dir = tempfile::tempdir().unwrap();
        let config_dir = dir.path().join(".kata");
        std::fs::create_dir_all(&config_dir).unwrap();
        let probes = green_probes(dir.path());
        // The project-root .env already names a DIFFERENT provider.
        std::fs::write(
            dir.path().join(".env"),
            "KATA_EXTERNAL_EXECUTION_PROVIDER=podman\n",
        )
        .unwrap();
        let mut exec = |argv: &[String]| -> Result<String, String> {
            if answers_nix_probe(argv) {
                return Ok("nix".to_string());
            }
            if argv.iter().any(|a| a == "--realise") {
                return Ok(String::new());
            }
            Err("unexpected".to_string())
        };
        let args = HostSetupArgs {
            config: config_dir.join("kata.toml"),
            install_apparmor: false,
            environment_file: Some(environment_file(dir.path())),
            provider_source: Some(provider_source(dir.path())),
            provider_ip: Some(store_ip(dir.path())),
        };
        let report = run_setup_with(
            &args,
            &probes,
            &mut exec,
            &verify_ok,
            &delegation_ok,
            &no_ambient,
            &passing_doctor,
        )
        .unwrap();
        let last = report.steps.last().unwrap();
        assert_eq!(last.name, "env_file");
        assert_eq!(last.status, StepStatus::Refused);
        assert!(
            last.detail.starts_with("env_file_conflict"),
            "{}",
            last.detail
        );
        // And the operator's line is untouched.
        let env = std::fs::read_to_string(dir.path().join(".env")).unwrap();
        assert_eq!(env, "KATA_EXTERNAL_EXECUTION_PROVIDER=podman\n");
    }

    #[test]
    fn a_conflicting_config_refuses_instead_of_rewriting() {
        let dir = tempfile::tempdir().unwrap();
        let config_dir = dir.path().join(".kata");
        std::fs::create_dir_all(&config_dir).unwrap();
        let probes = green_probes(dir.path());
        std::fs::write(
            config_dir.join("kata.toml"),
            "[node]\nexecution_profile = \"legacy\"\n",
        )
        .unwrap();
        let mut exec = |argv: &[String]| -> Result<String, String> {
            if answers_nix_probe(argv) {
                return Ok("nix".to_string());
            }
            if argv.iter().any(|a| a == "--realise") {
                return Ok(String::new());
            }
            Err("unexpected".to_string())
        };
        let args = HostSetupArgs {
            config: config_dir.join("kata.toml"),
            install_apparmor: false,
            environment_file: Some(environment_file(dir.path())),
            provider_source: Some(provider_source(dir.path())),
            provider_ip: Some(store_ip(dir.path())),
        };
        let report = run_setup_with(
            &args,
            &probes,
            &mut exec,
            &verify_ok,
            &delegation_ok,
            &no_ambient,
            &passing_doctor,
        )
        .unwrap();
        let last = report.steps.last().unwrap();
        assert_eq!(last.name, "config");
        assert_eq!(last.status, StepStatus::Refused);
        assert!(
            last.detail.starts_with("config_conflict"),
            "{}",
            last.detail
        );
        // The undeclared key is the operator's line here — the file is untouched.
        let text = std::fs::read_to_string(config_dir.join("kata.toml")).unwrap();
        assert!(text.contains("execution_profile = \"legacy\""), "{text}");
    }

    #[test]
    fn an_absent_environment_source_refuses_with_the_probed_paths() {
        let dir = tempfile::tempdir().unwrap();
        let config_dir = dir.path().join(".kata");
        std::fs::create_dir_all(&config_dir).unwrap();
        let probes = green_probes(dir.path());
        std::fs::write(config_dir.join("kata.toml"), "[node]\n").unwrap();
        let mut exec = |argv: &[String]| -> Result<String, String> {
            if answers_nix_probe(argv) {
                return Ok("nix".to_string());
            }
            Err("unexpected".to_string())
        };
        let args = HostSetupArgs {
            config: config_dir.join("kata.toml"),
            install_apparmor: false,
            environment_file: None,
            provider_source: Some(provider_source(dir.path())),
            provider_ip: Some(store_ip(dir.path())),
        };
        let report = run_setup_with(
            &args,
            &probes,
            &mut exec,
            &verify_ok,
            &delegation_ok,
            &no_ambient,
            &passing_doctor,
        )
        .unwrap();
        let last = report.steps.last().unwrap();
        assert_eq!(last.name, "config");
        assert!(
            last.detail.starts_with("node_environment_source_absent"),
            "{}",
            last.detail
        );
    }

    /// The unified-hierarchy question and the delegation question are the SAME
    /// measurement — `cgroup_delegation`'s own `unified_hierarchy` read folds a
    /// missing v2 hierarchy into the same `delegation_incomplete` refusal as a
    /// missing controller, so this step delegates the naming to it verbatim.
    #[test]
    fn a_host_without_delegation_refuses_by_name() {
        let dir = tempfile::tempdir().unwrap();
        let config_dir = dir.path().join(".kata");
        std::fs::create_dir_all(&config_dir).unwrap();
        let probes = scratch_probes(dir.path());
        std::fs::write(&probes.userns_restriction_knob, "0\n").unwrap();
        let mut exec = |argv: &[String]| -> Result<String, String> {
            if answers_nix_probe(argv) {
                return Ok("nix".to_string());
            }
            Err("unexpected".to_string())
        };
        let args = HostSetupArgs {
            config: config_dir.join("kata.toml"),
            install_apparmor: false,
            environment_file: None,
            provider_source: None,
            provider_ip: None,
        };
        // No unified hierarchy — the fold's own evidence text.
        let no_v2 = || -> Result<(), OciPrerequisiteRefusal> {
            Err(OciPrerequisiteRefusal::DelegationIncomplete {
                missing: vec!["memory", "pids"],
                evidence: "no cgroup v2 unified hierarchy is mounted at /sys/fs/cgroup".to_string(),
            })
        };
        let report = run_setup_with(
            &args,
            &probes,
            &mut exec,
            &verify_ok,
            &no_v2,
            &no_ambient,
            &passing_doctor,
        )
        .unwrap();
        let last = report.steps.last().unwrap();
        assert_eq!(last.name, "cgroup_v2");
        assert_eq!(last.status, StepStatus::Refused);
        assert!(
            last.detail.starts_with("delegation_incomplete"),
            "{}",
            last.detail
        );
        assert!(
            last.detail.contains("no cgroup v2 unified hierarchy"),
            "the fold's evidence must reach the operator verbatim: {}",
            last.detail
        );

        // Hierarchy present but the delegation probe cannot prove the two
        // controllers usable → refused with the folded measurement's own text.
        let refused = || -> Result<(), OciPrerequisiteRefusal> {
            Err(OciPrerequisiteRefusal::DelegationIncomplete {
                missing: vec!["pids"],
                evidence: "cgroup.subtree_control lacks pids".to_string(),
            })
        };
        let report = run_setup_with(
            &args,
            &probes,
            &mut exec,
            &verify_ok,
            &refused,
            &no_ambient,
            &passing_doctor,
        )
        .unwrap();
        let last = report.steps.last().unwrap();
        assert_eq!(last.name, "cgroup_v2");
        assert_eq!(last.status, StepStatus::Refused);
        assert!(
            last.detail.starts_with("delegation_incomplete"),
            "{}",
            last.detail
        );
    }

    #[test]
    fn an_ambient_provider_declaration_that_differs_is_a_named_conflict() {
        let dir = tempfile::tempdir().unwrap();
        let config_dir = dir.path().join(".kata");
        std::fs::create_dir_all(&config_dir).unwrap();
        let probes = green_probes(dir.path());
        // The ambient declares a DIFFERENT provider — `.env` could never
        // override it, so writing one would be a lie.
        let ambient = |key: &'static str| -> Option<String> {
            (key == "KATA_EXTERNAL_EXECUTION_PROVIDER").then(|| "podman".to_string())
        };
        let mut exec = |argv: &[String]| -> Result<String, String> {
            if answers_nix_probe(argv) {
                return Ok("nix".to_string());
            }
            if argv.iter().any(|a| a == "--realise") {
                return Ok(String::new());
            }
            Err("unexpected".to_string())
        };
        let args = HostSetupArgs {
            config: config_dir.join("kata.toml"),
            install_apparmor: false,
            environment_file: Some(environment_file(dir.path())),
            provider_source: Some(provider_source(dir.path())),
            provider_ip: Some(store_ip(dir.path())),
        };
        let report = run_setup_with(
            &args,
            &probes,
            &mut exec,
            &verify_ok,
            &delegation_ok,
            &ambient,
            &passing_doctor,
        )
        .unwrap();
        let last = report.steps.last().unwrap();
        assert_eq!(last.name, "provider");
        assert_eq!(last.status, StepStatus::Refused);
        assert!(
            last.detail.starts_with("provider_env_conflict"),
            "{}",
            last.detail
        );
        assert!(!dir.path().join(".env").exists(), "no .env is written");
    }

    #[test]
    fn a_declared_environment_and_a_different_file_refuse() {
        let dir = tempfile::tempdir().unwrap();
        let config_dir = dir.path().join(".kata");
        std::fs::create_dir_all(&config_dir).unwrap();
        let probes = green_probes(dir.path());
        // The config declares ONE closure; --environment-file names another.
        // Two answers is a refusal, never a silent pick.
        std::fs::write(
            config_dir.join("kata.toml"),
            "[node]\n\
             environment = { store_paths = [\"/nix/store/different\"] }\n",
        )
        .unwrap();
        let mut exec = |argv: &[String]| -> Result<String, String> {
            if answers_nix_probe(argv) {
                return Ok("nix".to_string());
            }
            if argv.iter().any(|a| a == "--realise") {
                return Ok(String::new());
            }
            Err("unexpected".to_string())
        };
        let args = HostSetupArgs {
            config: config_dir.join("kata.toml"),
            install_apparmor: false,
            environment_file: Some(environment_file(dir.path())),
            provider_source: Some(provider_source(dir.path())),
            provider_ip: Some(store_ip(dir.path())),
        };
        let report = run_setup_with(
            &args,
            &probes,
            &mut exec,
            &verify_ok,
            &delegation_ok,
            &no_ambient,
            &passing_doctor,
        )
        .unwrap();
        let last = report.steps.last().unwrap();
        assert_eq!(last.name, "config");
        assert_eq!(last.status, StepStatus::Refused);
        assert!(
            last.detail.starts_with("config_conflict"),
            "{}",
            last.detail
        );
        assert!(
            last.detail.contains("/nix/store/different"),
            "{}",
            last.detail
        );
        // And the operator's declared closure is untouched.
        let text = std::fs::read_to_string(config_dir.join("kata.toml")).unwrap();
        assert!(text.contains("/nix/store/different"), "{text}");
    }

    /// The packaged default is a default for a node that declares NOTHING —
    /// it is not a truth an existing declaration is compared against. A
    /// config carrying its own closure (one the operator built, a
    /// previous pin's) must stand even when the packaged file declares a
    /// different one: otherwise every upgrade that moved the store paths
    /// would deadlock `host setup` behind a conflict the run cannot fix.
    #[test]
    fn a_declared_environment_stands_against_a_different_packaged_default() {
        let dir = tempfile::tempdir().unwrap();
        let config_dir = dir.path().join(".kata");
        std::fs::create_dir_all(&config_dir).unwrap();
        let probes = green_probes(dir.path());
        // The packaged file EXISTS under the probe prefix and declares a
        // DIFFERENT closure than the config does.
        let packaged_dir = probes.exe_dir.parent().unwrap().join("share/kata");
        std::fs::create_dir_all(&packaged_dir).unwrap();
        std::fs::write(
            packaged_dir.join("node-environment.toml"),
            NODE_ENVIRONMENT_TOML,
        )
        .unwrap();
        // The config's own closure — a legitimate declaration, not the
        // packaged default's.
        let declared_closure = "/nix/store/aaaa0123456789bcdfghijklmnpqrsvw-operator-env";
        std::fs::write(
            config_dir.join("kata.toml"),
            format!(
                "[node]\n\
                 environment = {{ label = \"mine\", system = \"x86_64-linux\", \
                 nixpkgs_attribute = \"ops\", store_paths = [\"{declared_closure}\"] }}\n"
            ),
        )
        .unwrap();
        let execs = std::cell::RefCell::new(Vec::new());
        let mut exec = |argv: &[String]| -> Result<String, String> {
            execs.borrow_mut().push(argv.join(" "));
            if answers_nix_probe(argv) {
                return Ok("nix".to_string());
            }
            if argv.iter().any(|a| a == "--realise") {
                return Ok(String::new());
            }
            Err("unexpected".to_string())
        };
        let args = HostSetupArgs {
            config: config_dir.join("kata.toml"),
            install_apparmor: false,
            environment_file: None,
            provider_source: Some(provider_source(dir.path())),
            provider_ip: Some(store_ip(dir.path())),
        };
        let report = run_setup_with(
            &args,
            &probes,
            &mut exec,
            &verify_ok,
            &delegation_ok,
            &no_ambient,
            &passing_doctor,
        )
        .unwrap();
        assert!(
            report.complete,
            "the config's declared environment stands; no conflict: {report:?}"
        );
        let config_step = report.steps.iter().find(|s| s.name == "config").unwrap();
        assert!(
            config_step
                .detail
                .contains("environment declaration stands"),
            "the step reports the stand: {}",
            config_step.detail
        );
        // The DECLARED closure's paths were realised — the packaged file's
        // were never consulted.
        let execs = execs.borrow();
        assert!(
            execs.iter().any(|a| a.contains(declared_closure)),
            "the declared closure is realised: {execs:?}"
        );
        assert!(
            !execs
                .iter()
                .any(|a| a.contains("0123456789abcdfghijklmnpqrsvwxyz-env-a")),
            "the packaged default was never consulted: {execs:?}"
        );
    }

    /// The same stand holds even when the packaged file is malformed: it is
    /// not read at all once the config declares an environment, so a corrupt
    /// `share/kata/node-environment.toml` cannot fail a node that does not
    /// need it.
    #[test]
    fn a_malformed_packaged_environment_is_irrelevant_to_a_declared_node() {
        let dir = tempfile::tempdir().unwrap();
        let config_dir = dir.path().join(".kata");
        std::fs::create_dir_all(&config_dir).unwrap();
        let probes = green_probes(dir.path());
        let packaged_dir = probes.exe_dir.parent().unwrap().join("share/kata");
        std::fs::create_dir_all(&packaged_dir).unwrap();
        std::fs::write(
            packaged_dir.join("node-environment.toml"),
            "this is [[ not toml at all",
        )
        .unwrap();
        std::fs::write(
            config_dir.join("kata.toml"),
            "[node]\n\
             environment = { store_paths = [\"/nix/store/aaaa0123456789bcdfghijklmnpqrsvw-mine\"] }\n",
        )
        .unwrap();
        let mut exec = |argv: &[String]| -> Result<String, String> {
            if answers_nix_probe(argv) {
                return Ok("nix".to_string());
            }
            if argv.iter().any(|a| a == "--realise") {
                return Ok(String::new());
            }
            Err("unexpected".to_string())
        };
        let args = HostSetupArgs {
            config: config_dir.join("kata.toml"),
            install_apparmor: false,
            environment_file: None,
            provider_source: Some(provider_source(dir.path())),
            provider_ip: Some(store_ip(dir.path())),
        };
        let report = run_setup_with(
            &args,
            &probes,
            &mut exec,
            &verify_ok,
            &delegation_ok,
            &no_ambient,
            &passing_doctor,
        )
        .unwrap();
        assert!(
            report.complete,
            "a malformed packaged file cannot fail a declared node: {report:?}"
        );
    }

    /// A store path reaching `nix-store --realise` from the operator's config
    /// never went through `parse_environment_file` — so the exec boundary
    /// validates it. `../../etc/passwd` must refuse `node_environment_realise`
    /// naming the value, and nix-store must never have run for it.
    #[test]
    fn a_non_store_path_in_a_declared_environment_refuses_before_exec() {
        let dir = tempfile::tempdir().unwrap();
        let config_dir = dir.path().join(".kata");
        std::fs::create_dir_all(&config_dir).unwrap();
        let probes = green_probes(dir.path());
        std::fs::write(
            config_dir.join("kata.toml"),
            "[node]\n\
             environment = { store_paths = [\"../../etc/passwd\"] }\n",
        )
        .unwrap();
        let execs = std::cell::RefCell::new(Vec::new());
        let mut exec = |argv: &[String]| -> Result<String, String> {
            execs.borrow_mut().push(argv.join(" "));
            if answers_nix_probe(argv) {
                return Ok("nix".to_string());
            }
            if argv.iter().any(|a| a == "--realise") {
                return Ok(String::new());
            }
            Err("unexpected".to_string())
        };
        let args = HostSetupArgs {
            config: config_dir.join("kata.toml"),
            install_apparmor: false,
            environment_file: None,
            provider_source: Some(provider_source(dir.path())),
            provider_ip: Some(store_ip(dir.path())),
        };
        let report = run_setup_with(
            &args,
            &probes,
            &mut exec,
            &verify_ok,
            &delegation_ok,
            &no_ambient,
            &passing_doctor,
        )
        .unwrap();
        let config_step = report.steps.iter().find(|s| s.name == "config").unwrap();
        assert_eq!(config_step.status, StepStatus::Refused, "{config_step:?}");
        assert!(
            config_step.detail.starts_with("node_environment_realise"),
            "{}",
            config_step.detail
        );
        assert!(
            config_step.detail.contains("../../etc/passwd"),
            "{}",
            config_step.detail
        );
        let execs = execs.borrow();
        assert!(
            !execs.iter().any(|a| a.contains("--realise")),
            "the bad value never reached nix-store: {execs:?}"
        );
    }

    /// `.env` exists only where dotenvy would find it — the project root of
    /// the `.kata/kata.toml` layout. Any other `--config` shape has no home
    /// for the file, so the exports become the operator's deferred action and
    /// the run is incomplete until they are declared.
    #[test]
    fn a_non_kata_config_layout_defers_the_exports_as_actions() {
        let dir = tempfile::tempdir().unwrap();
        let probes = green_probes(dir.path());
        let mut exec = |argv: &[String]| -> Result<String, String> {
            if answers_nix_probe(argv) {
                return Ok("nix".to_string());
            }
            if argv.iter().any(|a| a == "--realise") {
                return Ok(String::new());
            }
            Err("unexpected".to_string())
        };
        // `--config` NOT under a `.kata` directory.
        let args = HostSetupArgs {
            config: dir.path().join("kata.toml"),
            install_apparmor: false,
            environment_file: Some(environment_file(dir.path())),
            provider_source: Some(provider_source(dir.path())),
            provider_ip: Some(store_ip(dir.path())),
        };
        let report = run_setup_with(
            &args,
            &probes,
            &mut exec,
            &verify_ok,
            &delegation_ok,
            &no_ambient,
            &passing_doctor,
        )
        .unwrap();
        let env_step = report.steps.iter().find(|s| s.name == "env_file").unwrap();
        assert_eq!(env_step.status, StepStatus::Deferred, "{env_step:?}");
        assert!(
            report
                .actions
                .iter()
                .any(|a| a.starts_with("export KATA_EXTERNAL_PROVIDER_STORE=")),
            "the exports are named as actions: {:?}",
            report.actions
        );
        assert!(
            !dir.path().join(".env").exists(),
            "no .env is written where nothing would load it"
        );
        assert!(
            !report.complete,
            "deferred exports hold the run at incomplete: {report:?}"
        );
    }

    #[test]
    fn a_failing_doctor_is_the_runs_verdict() {
        let dir = tempfile::tempdir().unwrap();
        let config_dir = dir.path().join(".kata");
        std::fs::create_dir_all(&config_dir).unwrap();
        let probes = green_probes(dir.path());
        let mut exec = |argv: &[String]| -> Result<String, String> {
            if answers_nix_probe(argv) {
                return Ok("nix".to_string());
            }
            if argv.iter().any(|a| a == "--realise") {
                return Ok(String::new());
            }
            Err("unexpected".to_string())
        };
        let args = HostSetupArgs {
            config: config_dir.join("kata.toml"),
            install_apparmor: false,
            environment_file: Some(environment_file(dir.path())),
            provider_source: Some(provider_source(dir.path())),
            provider_ip: Some(store_ip(dir.path())),
        };
        let report = run_setup_with(
            &args,
            &probes,
            &mut exec,
            &verify_ok,
            &delegation_ok,
            &no_ambient,
            &failing_doctor,
        )
        .unwrap();
        assert!(!report.complete, "doctor's red is the run's verdict");
        let doctor = report.doctor.unwrap();
        assert!(!doctor.passed);
        assert_eq!(doctor.failed_checks, vec!["oci_containment".to_string()]);
    }

    /// The packaged paths this command probes beside the binary —
    /// `PACKAGED_NODE_ENVIRONMENT`, `PACKAGED_PROVIDER_SOURCE` and its member
    /// names, and `PACKAGED_PROVIDER_MEMBERS` with its `ip` key — are
    /// installed by `flake.nix`'s `installKata`, and the two declarations at
    /// those paths are rendered by `nix/share.nix`, the checkout expression a
    /// checkout build realises. A packaging change that drops or renames one
    /// must red a test here rather than an operator's `kata host setup` in
    /// the field.
    #[test]
    fn the_packaged_paths_the_probes_name_are_installed_by_the_flake() {
        let root = concat!(env!("CARGO_MANIFEST_DIR"), "/../..");
        let flake = std::fs::read_to_string(format!("{root}/flake.nix"))
            .expect("flake.nix at the workspace root");
        let share = std::fs::read_to_string(format!("{root}/{CHECKOUT_SHARE_EXPRESSION}"))
            .expect("the checkout's share expression");
        assert!(
            std::path::Path::new(&format!("{root}/{CHECKOUT_YOUKI_EXPRESSION}")).is_file(),
            "the checkout's youki expression"
        );
        for packaged in [
            PACKAGED_NODE_ENVIRONMENT,
            PACKAGED_PROVIDER_SOURCE,
            PACKAGED_PROVIDER_MEMBERS,
            &format!("import ./{CHECKOUT_SHARE_EXPRESSION}"),
        ] {
            assert!(
                flake.contains(packaged),
                "flake.nix installs no `{packaged}`"
            );
        }
        // The declaration's key is a literal `ip = "<store path>"` line, the
        // shape `ProviderMembersDeclaration` reads, at the paths the probes
        // name under the share prefix.
        for rendered in [
            &format!("{PROVIDER_IP_MEMBER} = \"${{pkgs.iproute2}}/bin/ip\"\n"),
            &format!("$out/{PACKAGED_PROVIDER_MEMBERS}"),
            &format!("$out/{PACKAGED_NODE_ENVIRONMENT}"),
        ] {
            assert!(
                share.contains(rendered.as_str()),
                "{CHECKOUT_SHARE_EXPRESSION} renders no `{rendered}`"
            );
        }
        for member in PROVIDER_SOURCE_MEMBERS {
            assert!(
                flake.contains(member),
                "flake.nix installs no provider member `{member}`"
            );
        }
    }
}
