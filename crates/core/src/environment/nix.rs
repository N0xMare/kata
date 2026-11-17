//! The ONE door to the Nix CLI.
//!
//! Every Nix interaction in kata goes through this module, and every function
//! here takes an explicit [`NixStore`]. That parameter is the whole point:
//! ADR-0001 trust boundary 5 keeps "Nix/store/cache trust" distinct from kata's
//! acceptance trust, and ADR-0001's consequences say the Nix daemon is never
//! exposed to a workload. A single wrapper with an explicit store selector is
//! what makes both checkable — a test drives a DISPOSABLE
//! [`NixStore::Local`] directory it owns and can corrupt, production drives the
//! host daemon, and nothing else the main or a worker runs spawns `nix`. The one other
//! caller of the Nix CLI is `kata host setup` (`bin/kata/src/host_setup.rs`), an operator
//! command that runs before any main: it probes (`nix-store --version`, `nix store info`)
//! and builds (`nix-build`) through its own injected exec, names no store selector, and
//! reaches no workload.
//!
//! # No shell, ever
//!
//! Every call is [`std::process::Command`] with an explicit argv. There is no
//! `sh -c`, no string interpolation into a command line, and no environment
//! inherited beyond what the process already has, so a store path or a source
//! directory carrying shell metacharacters is an argument and not a command.
//!
//! # What "typed error" means here
//!
//! [`NixError`] carries the program, the argv, the exit status and the tail of
//! stderr as DATA. The tail is SANITIZED: `$HOME`'s value is replaced by the
//! literal `$HOME` before the string is retained, because these messages reach
//! logs and operator surfaces and a home directory is a host fact kata does not
//! publish.
//!
//! # Nix 2.34 quirks this module absorbs
//!
//! * `--json` alone is deprecated; `path-info` is always called with
//!   `--json-format 2`. Under format 2 the top level is
//!   `{"info": {<BASE NAME>: {...}|null}, "storeDir": ..., "version": 2}` — the
//!   keys and every `references`/`deriver` entry are BASE NAMES, not absolute
//!   paths, so this module re-joins them onto `storeDir`. A refusal here on a
//!   `storeDir` other than [`NIX_STORE_DIRECTORY`] is what keeps
//!   [`StorePath`]'s invariant total.
//! * A path that is not in the store is reported as a `null` info entry with
//!   exit status 0, NOT as an error. [`path_exists`] reads exactly that, and
//!   [`path_info_recursive`] turns it into a typed missing-path refusal.
//! * `path-info` is called with `--option substituters ''`. Without it, a
//!   missing path that some configured binary cache could supply makes nix
//!   attempt a substitution and change both the exit status and the message, so
//!   the "is this path here" question would depend on the network.
//! * `store verify`'s `--no-trust` DISABLES the signature check, so a
//!   `--sigs-needed N` after it enforces nothing. [`verify`] therefore picks one
//!   or the other by policy; see that function for the measured exit codes.
//! * [`NixStore::Daemon`] passes NO `--store` argument. An untrusted client that
//!   passes `--store daemon` gets `warning: ignoring the client-specified
//!   setting 'store'` and the host's configuration anyway, so naming it would be
//!   a claim the CLI does not honour.

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use kata_types::error::KataError;
use kata_types::nix_environment::{
    IntegrityPolicy, NIX_STORE_DIRECTORY, NarVerification, StorePath,
};
use smol_str::SmolStr;

/// Which store a call operates on.
///
/// There is no default and no fallback: a caller that cannot name a store cannot
/// call this module.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NixStore {
    /// The host's configured store — in production, the Nix daemon. Passes no
    /// `--store` argument; see the module docs.
    Daemon,
    /// A store rooted at this directory, physically at `<dir>/nix/store`. Used by
    /// tests, which own the directory and may therefore corrupt it.
    Local(PathBuf),
}

impl NixStore {
    /// The `--store` arguments this selector contributes, if any.
    fn arguments(&self) -> Vec<OsString> {
        match self {
            Self::Daemon => Vec::new(),
            Self::Local(directory) => vec![OsString::from("--store"), directory.into()],
        }
    }

    /// Physical location of `store_path`'s bytes on this host.
    ///
    /// For [`Self::Daemon`] that is the logical path itself. For
    /// [`Self::Local`] it is the store directory plus the logical path, which is
    /// what lets a test read (or corrupt) the bytes without asking Nix.
    #[must_use]
    #[cfg(any(test, feature = "test-support"))]
    pub fn physical_path(&self, store_path: &StorePath) -> PathBuf {
        match self {
            Self::Daemon => PathBuf::from(store_path.as_str()),
            Self::Local(directory) => {
                // `as_str()` always begins with a `/`, which `Path::join` would
                // read as "replace the whole path".
                directory.join(store_path.as_str().trim_start_matches('/'))
            }
        }
    }
}

/// A Nix CLI failure, with the evidence needed to act on it.
#[derive(Debug, thiserror::Error)]
pub enum NixError {
    /// The executable could not be started at all.
    #[error("{program} could not be started: {source}; is nix installed and on PATH?")]
    Spawn {
        program: &'static str,
        #[source]
        source: std::io::Error,
    },
    /// The executable ran and refused.
    #[error("{program} {argv} failed ({status}); nix said: {stderr_tail}")]
    Refused {
        program: &'static str,
        argv: String,
        status: String,
        stderr_tail: String,
    },
    /// The executable succeeded and its output was not what this module parses.
    #[error("{program} {argv} succeeded but its output is unusable: {reason}")]
    Unusable {
        program: &'static str,
        argv: String,
        reason: String,
    },
    /// The executable did not finish within [`exec_deadline`]; it was killed. A hung
    /// daemon is the case this exists for: without it a node's boot waited forever.
    #[error(
        "{program} {argv} did not finish within {seconds}s and was killed (nix_exec_deadline_exceeded)"
    )]
    TimedOut {
        program: &'static str,
        argv: String,
        seconds: u64,
    },
    /// The store does not contain a path a caller named.
    #[error("nix store does not contain {path}")]
    MissingPath { path: String },
    /// A local filesystem operation around a store call failed.
    #[error("{operation} failed: {source}")]
    Io {
        operation: String,
        #[source]
        source: std::io::Error,
    },
}

impl From<NixError> for KataError {
    /// A Nix refusal is a VALIDATION refusal on kata's side of trust boundary 5:
    /// the store declined to supply or vouch for bytes, which is a statement
    /// about the declaration, not about kata's storage.
    fn from(error: NixError) -> Self {
        Self::Validation(error.to_string())
    }
}

/// Result alias for this module's own functions.
pub type NixResult<T> = Result<T, NixError>;

/// Number of trailing stderr bytes retained in a [`NixError`]. Enough for nix's
/// own `error:` line plus context, short enough that a refusal is readable.
const STDERR_TAIL_BYTES: usize = 2_048;

/// One store object's metadata AS NIX REPORTS IT.
///
/// Nothing here is a verification result — see trust boundary 5 and
/// [`kata_types::nix_environment::ClosureEntry`], whose fields these become.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PathInfo {
    pub path: StorePath,
    /// SRI `sha256-<base64>`, as `narHash`.
    pub nar_hash: SmolStr,
    pub nar_size: u64,
    /// Absolute store paths, rejoined from format 2's base names.
    pub references: Vec<StorePath>,
    pub deriver: Option<StorePath>,
    pub signatures: Vec<SmolStr>,
    /// Format 2 reports `ca` as `{"hash": ..., "method": ...}`; this module
    /// renders it as `<method>:<hash>` so the manifest carries one string.
    pub ca: Option<SmolStr>,
}

/// Import `source` into `store` as a content-addressed store object.
///
/// `nix store add-path`, whose stdout is the one resulting store path.
pub fn add_path(store: &NixStore, source: &Path) -> NixResult<StorePath> {
    let mut arguments = store.arguments();
    arguments.push("store".into());
    arguments.push("add-path".into());
    arguments.push(source.into());
    let output = run(store, NIX, &arguments)?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    let line = stdout.trim();
    StorePath::new(line).map_err(|error| NixError::Unusable {
        program: NIX,
        argv: render_argv(store, &arguments),
        reason: format!("stdout {line:?} is not a store path: {error}"),
    })
}

/// Every store object in the closure of `roots`, with its metadata.
///
/// # Failure
///
/// Refuses, exactly: an empty `roots` (a closure over nothing is not a
/// question this module answers); a `storeDir` or `version` other than
/// `/nix/store` and `2` (a different store layout would make every rejoined
/// base name a lie); a `null` info entry, as [`NixError::MissingPath`]; a
/// `narHash`, reference or deriver that is not a value the typed layer accepts;
/// and any root that does not appear in the result.
pub fn path_info_recursive(store: &NixStore, roots: &[StorePath]) -> NixResult<Vec<PathInfo>> {
    if roots.is_empty() {
        return Err(NixError::Unusable {
            program: NIX,
            argv: String::new(),
            reason: "a closure query needs at least one root".to_owned(),
        });
    }
    let mut arguments = store.arguments();
    arguments.push("path-info".into());
    arguments.push("--json".into());
    arguments.push("--json-format".into());
    arguments.push("2".into());
    arguments.push("--recursive".into());
    // See the module docs: without this, "is this path here" depends on whether a
    // binary cache could supply it.
    arguments.push("--option".into());
    arguments.push("substituters".into());
    arguments.push(OsString::new());
    for root in roots {
        arguments.push(root.as_str().into());
    }
    let output = run(store, NIX, &arguments)?;
    let argv = render_argv(store, &arguments);
    let document = parse_document(&output.stdout, &argv)?;
    let mut infos = Vec::with_capacity(document.info.len());
    for (base_name, entry) in document.info {
        let path = join_base_name(&argv, &base_name)?;
        let Some(entry) = entry else {
            return Err(NixError::MissingPath {
                path: path.as_str().to_owned(),
            });
        };
        infos.push(PathInfo {
            path,
            nar_hash: entry.nar_hash,
            nar_size: entry.nar_size,
            references: entry
                .references
                .iter()
                .map(|name| join_base_name(&argv, name))
                .collect::<NixResult<Vec<_>>>()?,
            deriver: entry
                .deriver
                .as_deref()
                .map(|name| join_base_name(&argv, name))
                .transpose()?,
            signatures: entry.signatures,
            ca: entry
                .ca
                .map(|ca| SmolStr::new(format!("{}:{}", ca.method, ca.hash))),
        });
    }
    infos.sort_by(|left, right| left.path.cmp(&right.path));
    for root in roots {
        if !infos.iter().any(|info| info.path == *root) {
            return Err(NixError::MissingPath {
                path: root.as_str().to_owned(),
            });
        }
    }
    Ok(infos)
}

/// Ask Nix to verify `paths` under `policy`.
///
/// # The flag interaction that decides whether this enforces anything
///
/// `--no-trust` and `--sigs-needed` are MUTUALLY EXCLUSIVE in effect, not
/// additive. `--no-trust` tells `nix store verify` to skip the trust/signature
/// check entirely, so `--sigs-needed N` placed after it is DEAD. Measured on
/// 2.34.8 against an unsigned, non-content-addressed object in a disposable
/// store:
///
/// ```text
/// nix store verify --no-trust --sigs-needed 1 <p>   -> exit 0   (nothing enforced)
/// nix store verify            --sigs-needed 1 <p>   -> exit 2   "path '<p>' is untrusted"
/// ```
///
/// So the argv is chosen BY POLICY rather than fixed:
///
/// * [`NarVerification::NarHashOnly`] passes `--no-trust`. Signatures are not
///   being required, and without `--no-trust` nix would refuse an unsigned path
///   the policy deliberately admits.
/// * [`NarVerification::NarHashAndSignatures`] passes `--sigs-needed N` and NOT
///   `--no-trust`, because `--no-trust` is precisely the flag that would make the
///   count unenforced.
///
/// `--no-contents` is orthogonal and is added when
/// `verify_contents_at_declare` is unset.
///
/// # What this proves, and what it does not
///
/// With `verify_contents_at_declare` set, a successful call means nix re-hashed
/// every object's contents and they matched their registered `narHash`. Without
/// it, the call checks only signatures — so a caller that skipped contents has
/// NOT verified bytes, which is trust boundary 5 exactly. `IntegrityPolicy` is
/// what records which of the two was asked for.
///
/// Two policy fields nix CANNOT express are therefore NOT claimed here and are
/// enforced by [`super::declare`] over [`PathInfo::signatures`] and
/// [`PathInfo::ca`] instead: `required_signers` (nix's `--sigs-needed` is a
/// COUNT over whatever keys the store trusts, never a named-key set) and
/// `allow_unsigned_content_addressed == false` (nix always accepts a
/// content-addressed object without a signature, because its address is its
/// evidence — measured: a CA path passes `--sigs-needed 1` at exit 0).
pub fn verify(store: &NixStore, paths: &[StorePath], policy: &IntegrityPolicy) -> NixResult<()> {
    if paths.is_empty() {
        return Ok(());
    }
    let mut arguments = store.arguments();
    arguments.push("store".into());
    arguments.push("verify".into());
    match policy.verify {
        NarVerification::NarHashOnly => arguments.push("--no-trust".into()),
        NarVerification::NarHashAndSignatures => {
            arguments.push("--sigs-needed".into());
            arguments.push(policy.sigs_needed.to_string().into());
        }
    }
    if !policy.verify_contents_at_declare {
        arguments.push("--no-contents".into());
    }
    for path in paths {
        arguments.push(path.as_str().into());
    }
    run(store, NIX, &arguments).map(|_| ())
}

/// Create an INDIRECT gc root at `link` naming `path`.
///
/// `nix-store --add-root <link> --indirect -r <path>`. Indirect is what makes the
/// root survive across kata restarts without kata having to re-register it: the
/// store keeps an auto-root pointing at `link`, and `link` points at `path`.
///
/// # The rename hazard
///
/// That auto-root names `link` BY PATH. Moving or renaming `link` (or any
/// directory above it) does not move the auto-root, so the next collection finds
/// the auto-root stale, removes it, and the store object becomes collectable —
/// observed on 2.34.8. Every promotion in [`super::roots`] therefore ADDS the
/// root at its new path before removing the old link, and never renames one.
pub fn add_indirect_root(store: &NixStore, link: &Path, path: &StorePath) -> NixResult<()> {
    if let Some(parent) = link.parent() {
        std::fs::create_dir_all(parent).map_err(|source| NixError::Io {
            operation: format!("create the gc-root directory {}", parent.display()),
            source,
        })?;
    }
    // `--add-root` refuses to overwrite nothing, but a leftover link from an
    // interrupted run would make the call fail; removing it first is what makes
    // this operation idempotent, which every recovery path depends on.
    match std::fs::remove_file(link) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(source) => {
            return Err(NixError::Io {
                operation: format!("replace the gc root {}", link.display()),
                source,
            });
        }
    }
    let mut arguments = store.arguments();
    arguments.push("--add-root".into());
    arguments.push(link.into());
    arguments.push("--indirect".into());
    arguments.push("-r".into());
    arguments.push(path.as_str().into());
    run(store, NIX_STORE, &arguments).map(|_| ())
}

/// Whether `path` is a valid object in `store`.
///
/// Reads format 2's `null` info entry rather than an exit status, because a
/// missing path exits 0; see the module docs.
pub fn path_exists(store: &NixStore, path: &StorePath) -> NixResult<bool> {
    let mut arguments = store.arguments();
    arguments.push("path-info".into());
    arguments.push("--json".into());
    arguments.push("--json-format".into());
    arguments.push("2".into());
    arguments.push("--option".into());
    arguments.push("substituters".into());
    arguments.push(OsString::new());
    arguments.push(path.as_str().into());
    let output = run(store, NIX, &arguments)?;
    let document = parse_document(&output.stdout, &render_argv(store, &arguments))?;
    Ok(document
        .info
        .get(path.base_name())
        .is_some_and(Option::is_some))
}

/// Collect every unrooted object in `store`.
///
/// TEST-ONLY. Production collection is the operator's or the daemon's, never
/// kata's: kata's obligation is to hold a root for what it authorized, and a
/// component that can also collect could discharge that obligation by deleting
/// the evidence.
#[cfg(any(test, feature = "test-support"))]
pub fn gc(store: &NixStore) -> NixResult<()> {
    let mut arguments = store.arguments();
    arguments.push("store".into());
    arguments.push("gc".into());
    run(store, NIX, &arguments).map(|_| ())
}

const NIX: &str = "nix";
const NIX_STORE: &str = "nix-store";

/// The wall-clock bound on EVERY nix exec this module makes.
///
/// Ten minutes: the longest legitimate call is a whole-closure `nix store verify` with
/// `verify_contents_at_declare`, which re-hashes every byte of the closure — measured in
/// seconds for the busybox closure and bounded by disk throughput for a large toolchain.
/// A bound this loose still turns a HUNG daemon into a named refusal instead of a boot
/// that never returns, which is the whole point.
const DEFAULT_EXEC_DEADLINE_MS: u64 = 600_000;

static EXEC_DEADLINE_MS: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(DEFAULT_EXEC_DEADLINE_MS);

/// The bound [`run`] holds every nix exec to.
#[must_use]
pub fn exec_deadline() -> std::time::Duration {
    std::time::Duration::from_millis(EXEC_DEADLINE_MS.load(std::sync::atomic::Ordering::Relaxed))
}

/// Shorten the exec deadline for a cell that drives a hung daemon.
#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub fn set_exec_deadline_for_test(deadline: std::time::Duration) {
    EXEC_DEADLINE_MS.store(
        u64::try_from(deadline.as_millis()).unwrap_or(u64::MAX),
        std::sync::atomic::Ordering::Relaxed,
    );
}

/// Spawn `program` with exactly `arguments`, bounded by [`exec_deadline`], and refuse a
/// non-zero status.
fn run(store: &NixStore, program: &'static str, arguments: &[OsString]) -> NixResult<Output> {
    use std::io::Read as _;

    let mut child = Command::new(program)
        .args(arguments)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .map_err(|source| NixError::Spawn { program, source })?;
    // Drained on their own threads so a chatty child cannot fill a pipe and look hung.
    let mut stdout_pipe = child.stdout.take();
    let mut stderr_pipe = child.stderr.take();
    let stdout_reader = std::thread::spawn(move || {
        let mut bytes = Vec::new();
        if let Some(pipe) = stdout_pipe.as_mut() {
            let _ = pipe.read_to_end(&mut bytes);
        }
        bytes
    });
    let stderr_reader = std::thread::spawn(move || {
        let mut bytes = Vec::new();
        if let Some(pipe) = stderr_pipe.as_mut() {
            let _ = pipe.read_to_end(&mut bytes);
        }
        bytes
    });
    let deadline = exec_deadline();
    let started = std::time::Instant::now();
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if started.elapsed() < deadline => {
                std::thread::sleep(std::time::Duration::from_millis(20));
            }
            Ok(None) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(NixError::TimedOut {
                    program,
                    argv: render_argv(store, arguments),
                    seconds: deadline.as_secs(),
                });
            }
            Err(source) => {
                return Err(NixError::Io {
                    operation: format!("wait for {program}"),
                    source,
                });
            }
        }
    };
    let output = Output {
        status,
        stdout: stdout_reader.join().unwrap_or_default(),
        stderr: stderr_reader.join().unwrap_or_default(),
    };
    if output.status.success() {
        return Ok(output);
    }
    Err(NixError::Refused {
        program,
        argv: render_argv(store, arguments),
        status: output.status.to_string(),
        stderr_tail: sanitized_stderr_tail(store, &output.stderr),
    })
}

/// Ask the store to answer at all: `nix store info`, bounded like every exec.
///
/// # Errors
///
/// Whatever [`run`] refuses — a missing executable, a store that refuses the connection,
/// a daemon that does not answer within [`exec_deadline`].
pub fn store_reachable(store: &NixStore) -> NixResult<()> {
    let mut arguments = store.arguments();
    arguments.push("store".into());
    arguments.push("info".into());
    run(store, NIX, &arguments).map(|_| ())
}

/// Parse and validate one `path-info --json-format 2` document.
///
/// ONE parser for both readers, so `path_exists` and `path_info_recursive` cannot
/// come to disagree about what a format-2 document is — the version and
/// `storeDir` refusals apply to both or to neither.
fn parse_document(stdout: &[u8], argv: &str) -> NixResult<PathInfoDocument> {
    let document: PathInfoDocument =
        serde_json::from_slice(stdout).map_err(|error| NixError::Unusable {
            program: NIX,
            argv: argv.to_owned(),
            reason: format!("path-info --json-format 2 did not parse: {error}"),
        })?;
    if document.version != 2 || document.store_dir != NIX_STORE_DIRECTORY {
        return Err(NixError::Unusable {
            program: NIX,
            argv: argv.to_owned(),
            reason: format!(
                "expected a format-2 document over {NIX_STORE_DIRECTORY}, got version {} over {:?}",
                document.version, document.store_dir
            ),
        });
    }
    Ok(document)
}

/// Rejoin one format-2 base name onto [`NIX_STORE_DIRECTORY`].
fn join_base_name(argv: &str, base_name: &str) -> NixResult<StorePath> {
    StorePath::new(format!("{NIX_STORE_DIRECTORY}/{base_name}")).map_err(|error| {
        NixError::Unusable {
            program: NIX,
            argv: argv.to_owned(),
            reason: format!("path-info named {base_name:?}, which is not a store path: {error}"),
        }
    })
}

/// Quote an argv for a message, host paths redacted. Presentation only — nothing
/// re-executes this.
fn render_argv(store: &NixStore, arguments: &[OsString]) -> String {
    redact_host_paths(
        store,
        &arguments
            .iter()
            .map(|argument| format!("{}", argument.as_os_str().display()))
            .collect::<Vec<_>>()
            .join(" "),
    )
}

/// The tail of stderr, host paths redacted.
fn sanitized_stderr_tail(store: &NixStore, stderr: &[u8]) -> String {
    let text = String::from_utf8_lossy(stderr);
    let start = text.len().saturating_sub(STDERR_TAIL_BYTES);
    let tail = text
        .char_indices()
        .find(|(index, _)| *index >= start)
        .map_or("", |(index, _)| &text[index..]);
    redact_host_paths(store, tail.trim())
}

/// Replace the host paths this module can actually name with symbolic ones.
///
/// Not cosmetic: every string this module puts in a [`NixError`] reaches logs,
/// refusal messages and operator surfaces, and ADR-0001 keeps main-host paths off
/// those surfaces.
///
/// # Redacted set, stated exactly
///
/// The store directory of a [`NixStore::Local`] (`$NIX_STORE_ROOT`) and, if
/// different, `$HOME`. The store directory goes FIRST: a disposable store under
/// `$HOME` would otherwise be half-rewritten into a path naming neither.
///
/// It is a REDACTION and NOT a claim that no host path can appear. A nix message
/// naming some third directory passes through; kata's OWN messages about its
/// gc-root tree are rendered relative to the data directory at their source (see
/// [`super::roots::shown`]) rather than scrubbed here, because this function
/// cannot see a data directory; and `/nix/store/...` paths are deliberately KEPT,
/// because they are portable by construction and are the only thing an operator
/// can act on.
fn redact_host_paths(store: &NixStore, text: &str) -> String {
    let mut text = text.to_owned();
    let mut redact = |value: &str, name: &str| {
        if value.len() > 1 {
            text = text.replace(value, name);
        }
    };
    if let NixStore::Local(directory) = store {
        redact(&directory.to_string_lossy(), "$NIX_STORE_ROOT");
    }
    if let Some(home) = std::env::var_os("HOME") {
        redact(&home.to_string_lossy(), "$HOME");
    }
    text
}

/// Raw mirror of `nix path-info --json-format 2`'s document.
///
/// `deny_unknown_fields` is deliberately OFF and every field this module needs is
/// REQUIRED: a nix release that adds a field must not break kata, and one that
/// drops a field kata reads must not be silently tolerated.
#[derive(serde::Deserialize)]
struct PathInfoDocument {
    info: std::collections::BTreeMap<String, Option<RawPathInfo>>,
    #[serde(rename = "storeDir")]
    store_dir: String,
    version: u32,
}

#[derive(serde::Deserialize)]
struct RawPathInfo {
    #[serde(rename = "narHash")]
    nar_hash: SmolStr,
    #[serde(rename = "narSize")]
    nar_size: u64,
    references: Vec<String>,
    deriver: Option<String>,
    signatures: Vec<SmolStr>,
    ca: Option<RawContentAddress>,
}

#[derive(serde::Deserialize)]
struct RawContentAddress {
    hash: String,
    method: String,
}

/// Refuse a `nix` that is not on PATH, naming it.
///
/// Callers use this to fail rather than skip: an unavailable capability is not a
/// pass, so a plane that needs Nix must name the missing
/// executable instead of reporting success.
#[cfg(any(test, feature = "test-support"))]
pub fn require_available() -> kata_types::error::KataResult<()> {
    for program in [NIX, NIX_STORE] {
        let found = Command::new(program)
            .arg("--version")
            .output()
            .is_ok_and(|output| output.status.success());
        if !found {
            return Err(KataError::Validation(format!(
                "the Nix environment plane requires {program} on PATH and it is absent or \
                 unusable; kata inherits the host's answer and refuses when there is none"
            )));
        }
    }
    Ok(())
}
