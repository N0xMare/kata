//! Artifact-bound proof of Git object availability at one configured remote.
//!
//! This does not enumerate runtime references or make an artifact recoverable.
//! Call on bounded blocking capacity. Storage monitoring requests cancellation
//! after observing a threshold; it is not a hard disk/network peak limit.

use std::collections::{BTreeMap, BTreeSet};
use std::io;
use std::path::Path;
use std::time::{Duration, Instant};

use ulid::Ulid;

use crate::process::VcsCommand;

/// URL is deliberately neither Debug nor serializable: it is runtime binding,
/// never proof metadata. Credential material belongs in the host's Git helpers.
pub struct RecoveryRemoteRequest {
    pub artifact_id: Ulid,
    pub remote_id: String,
    pub url: String,
    pub required_commits: Vec<String>,
    pub reference_set_digest: String,
}

#[derive(Clone, Copy, Debug)]
pub struct RecoveryRemoteLimits {
    pub timeout: Duration,
    pub max_storage_bytes: u64,
    pub max_objects: usize,
    pub max_uncompressed_bytes: u64,
    pub max_output_bytes: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedRemoteClosure {
    pub artifact_id: Ulid,
    pub remote_id: String,
    pub required_commits: Vec<String>,
    pub reference_set_digest: String,
    pub closure_digest: String,
}

/// Owns the exact isolated repository whose object closure was verified.
/// Keeping this guard alive retains restore bytes; proof metadata alone does not.
#[derive(Debug)]
pub struct VerifiedRecoveryRepository {
    proof: VerifiedRemoteClosure,
    staging: tempfile::TempDir,
}

impl VerifiedRecoveryRepository {
    pub fn proof(&self) -> &VerifiedRemoteClosure {
        &self.proof
    }
    pub fn repository_path(&self) -> &Path {
        self.staging.path()
    }

    /// Install into a new, operator-selected target. Every verified root gets a
    /// retention ref, including commits unreachable from the selected trunk.
    /// Names are supplied by the artifact binding verifier, never guessed from
    /// source name hashes. Failure leaves an unactivated target for inspection.
    pub fn install_git_repository(
        &self,
        target: &Path,
        bookmarks: &BTreeMap<String, String>,
        trunk: &str,
        ignored_roots: &[&str],
        limits: RecoveryRemoteLimits,
    ) -> Result<()> {
        if !bookmarks.contains_key(trunk)
            || bookmarks.len() > 100_000
            || bookmarks
                .values()
                .any(|id| self.proof.required_commits.binary_search(id).is_err())
            || bookmarks.keys().any(|name| {
                name.is_empty() || name.len() > 1024 || name.contains(['\n', '\r', '\0'])
            })
        {
            return Err(RecoveryRemoteError::InvalidRequest(
                "target bookmarks must name verified roots and an explicit trunk",
            ));
        }
        validate_ignored_roots(ignored_roots)?;
        // Validate names before creating the operator's target. Git's own ref
        // parser is authoritative; shell quoting is never involved.
        let source = Session {
            root: self.staging.path(),
            started: Instant::now(),
            limits,
            auth: Vec::new(),
        };
        for name in bookmarks.keys() {
            source.checked(
                "validate target bookmark",
                &["check-ref-format", &format!("refs/heads/{name}")],
                &[],
            )?;
        }
        std::fs::create_dir(target)
            .map_err(|error| io_error("create new target repository", error))?;
        let target = target
            .canonicalize()
            .map_err(|error| io_error("resolve target repository", error))?;
        let session = Session {
            root: &target,
            started: source.started,
            limits,
            auth: Vec::new(),
        };
        session.checked(
            "initialize target repository",
            &["init", "--initial-branch", trunk, "."],
            &[],
        )?;
        install_local_excludes(&target, ignored_roots)?;
        let source_path =
            self.staging
                .path()
                .to_str()
                .ok_or(RecoveryRemoteError::InvalidRequest(
                    "non UTF-8 retained repository path",
                ))?;
        // Fetch full SHA refspecs, not a clone of the staging refs: the isolated
        // verifier deliberately fetches objects without creating source refs.
        for chunk in self.proof.required_commits.chunks(128) {
            let specs: Vec<_> = chunk
                .iter()
                .map(|id| format!("{id}:refs/kata/recovery/{}/{id}", self.proof.artifact_id))
                .collect();
            let mut args = vec![
                "fetch",
                "--no-tags",
                "--no-write-fetch-head",
                "--",
                source_path,
            ];
            args.extend(specs.iter().map(String::as_str));
            session.checked("retain verified target objects", &args, &[])?;
        }
        for (name, commit) in bookmarks {
            session.checked(
                "install target bookmark",
                &["update-ref", &format!("refs/heads/{name}"), commit],
                &[],
            )?;
        }
        session.checked(
            "verify target closure",
            &["fsck", "--full", "--strict", "--no-reflogs"],
            &[],
        )?;
        // Git has no working-tree checkout here: jj adopts the explicit HEAD
        // and materializes candidate workspaces through its normal provider.
        sync_repository_tree(&target, session.started, limits.timeout)?;
        if let Some(parent) = target.parent() {
            std::fs::File::open(parent)
                .and_then(|file| file.sync_all())
                .map_err(|error| io_error("sync target parent", error))?;
        }
        Ok(())
    }
}

fn validate_ignored_roots(roots: &[&str]) -> Result<()> {
    if roots.len() > 64
        || roots.iter().any(|root| {
            root.len() > 1024
                || root
                    .split('/')
                    .any(|part| part.is_empty() || matches!(part, "." | ".."))
                || root.contains(['\\', '\n', '\r', '\0', '*', '?', '[', ']', '!', '#'])
        })
    {
        return Err(RecoveryRemoteError::InvalidRequest(
            "target ignored roots must be bounded literal repository-relative directories",
        ));
    }
    Ok(())
}

/// Runtime supplies the provider-owned inventory. Local Git metadata keeps the
/// restored commit trees unchanged and never adds a broad ancestor exclusion.
fn install_local_excludes(target: &Path, roots: &[&str]) -> Result<()> {
    use std::io::Write as _;
    if !std::fs::symlink_metadata(target.join(".git"))
        .map_err(|error| io_error("inspect target Git metadata", error))?
        .file_type()
        .is_dir()
    {
        return Err(RecoveryRemoteError::InvalidRequest(
            "target Git metadata is not a directory",
        ));
    }
    let directory = target.join(".git/info");
    match std::fs::symlink_metadata(&directory) {
        Ok(metadata) if metadata.file_type().is_dir() => {}
        Ok(_) => {
            return Err(RecoveryRemoteError::InvalidRequest(
                "target Git info is not a directory",
            ));
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => std::fs::create_dir(&directory)
            .map_err(|error| io_error("create target Git info directory", error))?,
        Err(error) => return Err(io_error("inspect target Git info directory", error)),
    }
    let path = directory.join("exclude");
    let mut options = std::fs::OpenOptions::new();
    options.append(true).create(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC);
    }
    let mut file = options
        .open(&path)
        .map_err(|error| io_error("open target local exclusions", error))?;
    if !file
        .metadata()
        .map_err(|error| io_error("inspect target local exclusions", error))?
        .is_file()
    {
        return Err(RecoveryRemoteError::InvalidRequest(
            "target local exclusions are not a regular file",
        ));
    }
    file.write_all(b"\n# Kata-owned workspace metadata (local recovery target policy).\n")
        .map_err(|error| io_error("write target local exclusions", error))?;
    for root in roots {
        writeln!(file, "/{root}/")
            .map_err(|error| io_error("write target local exclusions", error))?;
    }
    file.sync_all()
        .map_err(|error| io_error("sync target local exclusions", error))
}

fn sync_repository_tree(root: &Path, started: Instant, timeout: Duration) -> Result<()> {
    let mut directories = vec![root.to_path_buf()];
    let mut index = 0;
    while index < directories.len() {
        if started.elapsed() >= timeout {
            return Err(RecoveryRemoteError::LimitExceeded("deadline"));
        }
        for entry in std::fs::read_dir(&directories[index])
            .map_err(|error| io_error("read target for sync", error))?
        {
            if started.elapsed() >= timeout {
                return Err(RecoveryRemoteError::LimitExceeded("deadline"));
            }
            let entry = entry.map_err(|error| io_error("read target entry for sync", error))?;
            let kind = entry
                .file_type()
                .map_err(|error| io_error("inspect target for sync", error))?;
            if kind.is_dir() {
                directories.push(entry.path());
            } else if kind.is_file() {
                std::fs::File::open(entry.path())
                    .and_then(|file| file.sync_all())
                    .map_err(|error| io_error("sync target file", error))?;
            } else {
                return Err(RecoveryRemoteError::InvalidClosure);
            }
        }
        index += 1;
    }
    for directory in directories.iter().rev() {
        std::fs::File::open(directory)
            .and_then(|file| file.sync_all())
            .map_err(|error| io_error("sync target directory", error))?;
    }
    Ok(())
}

#[derive(Debug, thiserror::Error)]
pub enum RecoveryRemoteError {
    #[error("invalid recovery remote request: {0}")]
    InvalidRequest(&'static str),
    #[error("recovery remote verification exceeded its {0} bound")]
    LimitExceeded(&'static str),
    #[error("recovery remote operation {phase} failed ({kind:?})")]
    Io {
        phase: &'static str,
        kind: io::ErrorKind,
    },
    #[error(
        "recovery remote Git operation {phase} failed (exit {status:?}); credential diagnostics withheld"
    )]
    Git {
        phase: &'static str,
        status: Option<i32>,
    },
    #[error("recovery remote could not supply required commits: {0:?}")]
    MissingCommits(Vec<String>),
    #[error("recovery remote returned malformed or incomplete object closure")]
    InvalidClosure,
}

type Result<T> = std::result::Result<T, RecoveryRemoteError>;

fn hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn validate(request: &RecoveryRemoteRequest, limits: RecoveryRemoteLimits) -> Result<()> {
    kata_types::config::validate_recovery_remote_binding(&request.remote_id, &request.url)
        .map_err(|_| RecoveryRemoteError::InvalidRequest("invalid remote binding"))?;
    if !hex(&request.reference_set_digest, 64) {
        return Err(RecoveryRemoteError::InvalidRequest(
            "invalid non-secret proof binding",
        ));
    }
    if request.required_commits.len() > 100_000
        || !request
            .required_commits
            .windows(2)
            .all(|pair| pair[0] < pair[1])
        || request.required_commits.iter().any(|id| !hex(id, 40))
    {
        return Err(RecoveryRemoteError::InvalidRequest(
            "expected sorted unique full SHA-1 Git commit IDs",
        ));
    }
    if limits.timeout.is_zero()
        || limits.max_objects == 0
        || limits.max_storage_bytes == 0
        || limits.max_uncompressed_bytes == 0
        || limits.max_output_bytes == 0
    {
        return Err(RecoveryRemoteError::InvalidRequest("zero resource budget"));
    }
    Ok(())
}

fn io_error(phase: &'static str, error: io::Error) -> RecoveryRemoteError {
    if error.kind() == io::ErrorKind::TimedOut {
        RecoveryRemoteError::LimitExceeded("deadline")
    } else if error.kind() == io::ErrorKind::FileTooLarge {
        RecoveryRemoteError::LimitExceeded("storage/output")
    } else {
        RecoveryRemoteError::Io {
            phase,
            kind: error.kind(),
        }
    }
}

/// A bounded census of the fresh staging tree. No symlink or alternate object
/// store may lend the verifier bytes from another repository.
fn check_storage(root: &Path, limits: RecoveryRemoteLimits, settled: bool) -> io::Result<()> {
    let mut pending = vec![root.to_path_buf()];
    let mut bytes = 0u64;
    let mut entries = 0usize;
    while let Some(dir) = pending.pop() {
        for entry in std::fs::read_dir(dir)? {
            let entry = entry?;
            entries = entries.saturating_add(1);
            if entries > limits.max_objects.saturating_add(256) {
                return Err(io::Error::from(io::ErrorKind::FileTooLarge));
            }
            let metadata = match entry.path().symlink_metadata() {
                Ok(metadata) => metadata,
                // Git atomically renames temporary packs while the monitor
                // samples. The post-command census checks the settled tree.
                Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
                Err(error) => return Err(error),
            };
            if metadata.file_type().is_symlink() {
                // `git init` probes symlink support with a short-lived link.
                // Never follow it, and require a link-free settled generation.
                if settled {
                    return Err(io::Error::other("unexpected staging symlink"));
                }
                continue;
            }
            if metadata.is_dir() {
                pending.push(entry.path());
            } else if metadata.is_file() {
                bytes = bytes.saturating_add(metadata.len());
                if bytes > limits.max_storage_bytes {
                    return Err(io::Error::from(io::ErrorKind::FileTooLarge));
                }
                if matches!(
                    entry.file_name().to_str(),
                    Some("alternates" | "http-alternates" | "shallow" | "grafts")
                ) || entry
                    .path()
                    .extension()
                    .is_some_and(|ext| ext == "promisor")
                {
                    return Err(io::Error::other("unexpected external object source"));
                }
            } else {
                return Err(io::Error::other("unexpected staging object kind"));
            }
        }
    }
    Ok(())
}

struct Session<'a> {
    root: &'a Path,
    started: Instant,
    limits: RecoveryRemoteLimits,
    auth: Vec<(String, String)>,
}

impl Session<'_> {
    fn command(&self, inherit_config: bool) -> Result<VcsCommand> {
        let remaining = self
            .limits
            .timeout
            .checked_sub(self.started.elapsed())
            .filter(|duration| !duration.is_zero())
            .ok_or(RecoveryRemoteError::LimitExceeded("deadline"))?;
        let mut command = VcsCommand::new("git", &[], remaining);
        command.current_dir(self.root);
        // Repository/config selectors can defeat isolation even with `-C`.
        for (key, _) in std::env::vars_os() {
            if key.to_string_lossy().starts_with("GIT_") {
                command.env_remove(key);
            }
        }
        command
            .env("GIT_TERMINAL_PROMPT", "0")
            .env("GIT_NO_LAZY_FETCH", "1")
            .env("GIT_NO_REPLACE_OBJECTS", "1")
            .env("GIT_ALLOW_PROTOCOL", "file:https:http:ssh:git")
            .env(
                "GIT_CEILING_DIRECTORIES",
                self.root.parent().unwrap_or(self.root),
            );
        if !inherit_config {
            command
                .env("GIT_CONFIG_GLOBAL", "/dev/null")
                .env("GIT_CONFIG_NOSYSTEM", "1");
            for (key, value) in &self.auth {
                command.arg("-c").arg(format!("{key}={value}"));
            }
            let ssh = self
                .auth
                .iter()
                .rev()
                .find(|(key, _)| key == "core.sshCommand")
                .map_or("ssh", |(_, value)| value.as_str());
            command.env("GIT_SSH_COMMAND", format!("{ssh} -oBatchMode=yes"));
        }
        command.args([
            "-c",
            "init.templateDir=",
            "-c",
            "core.hooksPath=/dev/null",
            "-c",
            "protocol.ext.allow=never",
            "-c",
            "fetch.recurseSubmodules=false",
            "-c",
            "fetch.writeCommitGraph=false",
            "-c",
            "gc.auto=0",
            "-c",
            "maintenance.auto=false",
            "-c",
            "credential.interactive=false",
        ]);
        Ok(command)
    }

    fn run(
        &self,
        phase: &'static str,
        args: &[&str],
        input: &[u8],
        inherit_config: bool,
    ) -> Result<std::process::Output> {
        let mut command = self.command(inherit_config)?;
        command.args(args);
        let output = command
            .output_with_guard(input, self.limits.max_output_bytes, &mut || {
                check_storage(self.root, self.limits, false)
            })
            .map_err(|error| io_error(phase, error))?;
        check_storage(self.root, self.limits, true).map_err(|error| io_error(phase, error))?;
        Ok(output)
    }

    fn checked(&self, phase: &'static str, args: &[&str], input: &[u8]) -> Result<Vec<u8>> {
        let output = self.run(phase, args, input, false)?;
        if !output.status.success() {
            return Err(RecoveryRemoteError::Git {
                phase,
                status: output.status.code(),
            });
        }
        Ok(output.stdout)
    }
}

/// Independently reacquire and validate the entire ancestry/tree/blob closure.
/// Full SHA-1 IDs are the supported Git-backed jj format; other
/// object formats refuse rather than being interpreted as another backend.
pub fn verify_recovery_remote(
    request: &RecoveryRemoteRequest,
    limits: RecoveryRemoteLimits,
) -> Result<VerifiedRemoteClosure> {
    Ok(reacquire_recovery_repository(request, limits)?.proof)
}

/// Reacquire with the same checks as capture, retaining the verified bytes for
/// target installation. No unverified local repository is used as a substitute.
pub fn reacquire_recovery_repository(
    request: &RecoveryRemoteRequest,
    limits: RecoveryRemoteLimits,
) -> Result<VerifiedRecoveryRepository> {
    validate(request, limits)?;
    let staging = tempfile::tempdir().map_err(|error| io_error("create staging", error))?;
    let mut session = Session {
        root: staging.path(),
        started: Instant::now(),
        limits,
        auth: Vec::new(),
    };
    // Capture only authentication configuration. No insteadOf, alternates,
    // templates, fetch filters or ambient repository settings reach Git fetch.
    let credentials = session.run(
        "read credential helper configuration",
        &[
            "config",
            "--null",
            "--get-regexp",
            "^credential\\..*(helper|username|usehttppath)$",
        ],
        &[],
        true,
    )?;
    if credentials.status.success() {
        let values = std::str::from_utf8(&credentials.stdout)
            .map_err(|_| RecoveryRemoteError::InvalidClosure)?;
        for record in values.split_terminator('\0') {
            let (key, value) = record
                .split_once('\n')
                .ok_or(RecoveryRemoteError::InvalidClosure)?;
            session.auth.push((key.into(), value.into()));
        }
    } else if credentials.status.code() != Some(1) {
        return Err(RecoveryRemoteError::Git {
            phase: "read credential helper configuration",
            status: credentials.status.code(),
        });
    }
    {
        let key = "core.sshCommand";
        let output = session.run(
            "read authentication configuration",
            &["config", "--get-all", key],
            &[],
            true,
        )?;
        if output.status.success() {
            let values = std::str::from_utf8(&output.stdout)
                .map_err(|_| RecoveryRemoteError::InvalidClosure)?;
            for value in values.lines() {
                session.auth.push((key.to_string(), value.to_string()));
            }
        } else if output.status.code() != Some(1) {
            return Err(RecoveryRemoteError::Git {
                phase: "read authentication configuration",
                status: output.status.code(),
            });
        }
    }
    if let Some(ssh) = std::env::var_os("GIT_SSH_COMMAND") {
        let ssh = ssh
            .into_string()
            .map_err(|_| RecoveryRemoteError::InvalidRequest("non-UTF-8 SSH command"))?;
        session.auth.push(("core.sshCommand".into(), ssh));
    }
    session.checked(
        "initialize isolated repository",
        &["init", "--bare", "--object-format=sha1", "."],
        &[],
    )?;
    let mut missing = Vec::new();
    for commit in &request.required_commits {
        let output = session.run(
            "fetch required commit",
            &[
                "fetch",
                "--no-tags",
                "--no-recurse-submodules",
                "--no-write-fetch-head",
                "--no-auto-maintenance",
                "--",
                &request.url,
                commit,
            ],
            &[],
            false,
        )?;
        if !output.status.success() {
            missing.push(commit.clone());
        }
    }
    if !missing.is_empty() {
        return Err(RecoveryRemoteError::MissingCommits(missing));
    }
    let roots = request.required_commits.join("\n") + "\n";
    if !request.required_commits.is_empty() {
        let root_types = session.checked(
            "verify commit types",
            &["cat-file", "--batch-check=%(objectname) %(objecttype)"],
            roots.as_bytes(),
        )?;
        let expected = request.required_commits.join(" commit\n") + " commit\n";
        if root_types != expected.as_bytes() {
            return Err(RecoveryRemoteError::InvalidClosure);
        }
    }
    let traversal = if request.required_commits.is_empty() {
        Vec::new()
    } else {
        session.checked(
            "traverse closure",
            &[
                "rev-list",
                "--objects",
                "--no-object-names",
                "--missing=print",
                "--stdin",
            ],
            roots.as_bytes(),
        )?
    };
    let text = std::str::from_utf8(&traversal).map_err(|_| RecoveryRemoteError::InvalidClosure)?;
    let objects: BTreeSet<_> = text.lines().collect();
    if objects.len() > limits.max_objects {
        return Err(RecoveryRemoteError::LimitExceeded("object count"));
    }
    if objects.iter().any(|id| !hex(id, 40)) {
        return Err(RecoveryRemoteError::InvalidClosure);
    }
    session.checked(
        "verify object integrity",
        &["fsck", "--full", "--strict", "--no-reflogs"],
        &[],
    )?;
    let inventory = session.checked(
        "measure received objects",
        &[
            "cat-file",
            "--batch-all-objects",
            "--batch-check=%(objectname) %(objecttype) %(objectsize)",
        ],
        &[],
    )?;
    let inventory_text =
        std::str::from_utf8(&inventory).map_err(|_| RecoveryRemoteError::InvalidClosure)?;
    if inventory_text.lines().count() > limits.max_objects {
        return Err(RecoveryRemoteError::LimitExceeded("object count"));
    }
    let mut bytes = 0u64;
    let mut closure_inventory = BTreeMap::new();
    for line in inventory_text.lines() {
        let fields: Vec<_> = line.split(' ').collect();
        if fields.len() != 3
            || !hex(fields[0], 40)
            || !matches!(fields[1], "commit" | "tree" | "blob" | "tag")
        {
            return Err(RecoveryRemoteError::InvalidClosure);
        }
        let size = fields[2]
            .parse::<u64>()
            .map_err(|_| RecoveryRemoteError::InvalidClosure)?;
        bytes = bytes
            .checked_add(size)
            .ok_or(RecoveryRemoteError::LimitExceeded("uncompressed bytes"))?;
        if bytes > limits.max_uncompressed_bytes {
            return Err(RecoveryRemoteError::LimitExceeded("uncompressed bytes"));
        }
        if objects.contains(fields[0]) {
            closure_inventory.insert(fields[0], line);
        }
    }
    if closure_inventory.len() != objects.len() {
        return Err(RecoveryRemoteError::InvalidClosure);
    }
    let mut digest = blake3::Hasher::new();
    digest.update(b"kata-git-recovery-closure-v1\0");
    for line in closure_inventory.values() {
        digest.update(line.as_bytes());
        digest.update(b"\n");
    }
    let proof = VerifiedRemoteClosure {
        artifact_id: request.artifact_id,
        remote_id: request.remote_id.clone(),
        required_commits: request.required_commits.clone(),
        reference_set_digest: request.reference_set_digest.clone(),
        closure_digest: digest.finalize().to_hex().to_string(),
    };
    Ok(VerifiedRecoveryRepository { proof, staging })
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    #[test]
    fn recovery_monitor_tolerates_init_probe_but_refuses_a_settled_symlink() {
        let root = tempfile::tempdir().unwrap();
        let link = root.path().join("init-probe");
        std::os::unix::fs::symlink("testing", &link).unwrap();
        let limits = RecoveryRemoteLimits {
            timeout: Duration::from_secs(1),
            max_storage_bytes: 1024,
            max_objects: 100,
            max_uncompressed_bytes: 1024,
            max_output_bytes: 1024,
        };
        check_storage(root.path(), limits, false).unwrap();
        assert!(check_storage(root.path(), limits, true).is_err());
        std::fs::remove_file(link).unwrap();
        check_storage(root.path(), limits, true).unwrap();
    }
}
