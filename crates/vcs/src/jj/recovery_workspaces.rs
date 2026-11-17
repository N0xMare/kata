//! Execution workspace metadata for offline checkpoint export and reconstruction.
//! File bytes are captured separately; this module never snapshots source files.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Instant;

use jj_lib::backend::CommitId;
use jj_lib::object_id::ObjectId as _;
use jj_lib::ref_name::WorkspaceNameBuf;
use jj_lib::repo::{Repo as _, StoreFactories};
use jj_lib::settings::UserSettings;
use jj_lib::workspace::{Workspace, default_working_copy_factories, default_working_copy_factory};
use kata_types::{AgentId, KataError, KataResult};
use ulid::Ulid;

use super::JjBackend;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecoveryExecutionWorkspace {
    pub execution_id: Ulid,
    pub commit_id: String,
    /// Source-local only; artifact schemas must use logical identity, not this path.
    pub path: PathBuf,
    pub(super) stored_tree_id: String,
}

/// The execution workspaces a checkpoint captures, from the target repository's
/// jj registrations and its `<agents>` directory.
///
/// Refused set, stated: a `fork-*` registration (no build creates one); an
/// `agent-*` registration that is not a ULID, names the root commit, or whose
/// `<agents>/<ulid>` workspace is missing or mismatched; an `<agents>` root that
/// is not a plain directory; a census past its bound or deadline; and a
/// ULID-named `<agents>` entry with no `agent-*` registration.
///
/// Any other registration is skipped, and so is any other `<agents>` entry: it
/// is not an execution workspace. That includes an operator's directory and a
/// `kata-fork` tree a build with the deleted invocation-fork plane left in this
/// repository. The target repository outlives the data directory, so such a tree
/// is reachable input, but its bytes belong to an execution of a data directory
/// this build refuses at boot, never to one a checkpoint here reconstructs.
pub(super) fn census_execution_workspaces(
    root: &Path,
    repo_path: &Path,
    settings: &UserSettings,
    registrations: &BTreeMap<WorkspaceNameBuf, CommitId>,
    deadline: Instant,
) -> Result<Vec<RecoveryExecutionWorkspace>, &'static str> {
    let root = root
        .canonicalize()
        .map_err(|_| "workspace root unavailable")?;
    let expected_repo = repo_path
        .canonicalize()
        .map_err(|_| "workspace repository unavailable")?;
    let agents = root.join(super::AGENTS_DIR_NAME);
    let mut entries = Vec::new();
    let mut ids = BTreeSet::new();
    for (name, commit) in registrations {
        if Instant::now() >= deadline {
            return Err("workspace census deadline elapsed");
        }
        if name.as_str().starts_with("fork-") {
            return Err(
                "leftover fork workspace registration `fork-*` blocks checkpoint: no build \
                 creates one; `jj workspace forget` it and retry — checkpoint does not \
                 capture the `<agents>/kata-fork` files it used",
            );
        }
        let Some(id) = name.as_str().strip_prefix("agent-") else {
            continue;
        };
        let execution_id: Ulid = id
            .parse()
            .map_err(|_| "unknown execution workspace registration")?;
        if commit.as_bytes().iter().all(|byte| *byte == 0) {
            return Err("root commit cannot be an execution workspace");
        }
        let path = agents.join(execution_id.to_string());
        validate_workspace_path(&path)?;
        let workspace = Workspace::load(
            settings,
            &path,
            &StoreFactories::default(),
            &default_working_copy_factories(),
        )
        .map_err(|_| "execution workspace metadata unavailable")?;
        if workspace.workspace_name().as_str() != name.as_str()
            || workspace
                .repo_path()
                .canonicalize()
                .map_err(|_| "execution workspace repository unavailable")?
                != expected_repo
        {
            return Err("execution workspace registration mismatch");
        }
        ids.insert(execution_id);
        let tree = workspace
            .working_copy()
            .tree()
            .map_err(|_| "execution workspace tree metadata unavailable")?;
        entries.push(RecoveryExecutionWorkspace {
            execution_id,
            commit_id: commit.hex(),
            path,
            stored_tree_id: JjBackend::merged_tree_id_hex(tree.tree_ids()),
        });
    }
    match fs::symlink_metadata(&agents) {
        Ok(metadata) => {
            if !metadata.is_dir() || metadata.file_type().is_symlink() {
                return Err("execution workspace root is not a directory");
            }
            for (count, entry) in fs::read_dir(&agents)
                .map_err(|_| "execution workspace root unreadable")?
                .enumerate()
            {
                if count >= 100_000 || Instant::now() >= deadline {
                    return Err("workspace census bound exceeded");
                }
                let entry = entry.map_err(|_| "execution workspace entry unreadable")?;
                let name = entry.file_name();
                if let Some(id) = name.to_str().and_then(|name| name.parse::<Ulid>().ok())
                    && !ids.contains(&id)
                {
                    return Err("execution workspace has no registration");
                }
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound && entries.is_empty() => {}
        Err(_) => return Err("execution workspace root unavailable"),
    }
    entries.sort_by_key(|entry| entry.execution_id);
    Ok(entries)
}

fn validate_workspace_path(path: &Path) -> Result<(), &'static str> {
    for path in [
        path.to_path_buf(),
        path.join(".jj"),
        path.join(".jj/working_copy"),
    ] {
        let metadata =
            fs::symlink_metadata(path).map_err(|_| "execution workspace path missing")?;
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            return Err("execution workspace path is not a directory");
        }
    }
    Ok(())
}

fn refused(message: impl Into<String>) -> KataError {
    KataError::Validation(message.into())
}

impl JjBackend {
    /// Flush new target jj authority after all checkpoint registrations, before identity publication.
    /// The caller owns the target exclusively; deadlines are cooperative between syscalls.
    #[cfg(unix)]
    pub fn sync_recovery_metadata(&self, deadline: Instant) -> KataResult<()> {
        use std::os::fd::AsRawFd as _;
        let settings = self.user_settings()?;
        let workspace = self.load_root_workspace(&settings)?;
        let repo = Self::block_on(workspace.repo_loader().load_at_head())
            .map_err(|_| refused("target metadata unavailable"))?;
        let mut executions = Vec::new();
        for name in repo.view().wc_commit_ids().keys() {
            if Instant::now() >= deadline {
                return Err(refused("metadata sync deadline expired"));
            }
            if let Some(id) = name.as_str().strip_prefix("agent-") {
                let id = id
                    .parse::<Ulid>()
                    .map_err(|_| refused("unknown target execution registration"))?;
                executions.push(id);
            }
        }
        let mut count = 0;
        let root = nix::dir::Dir::open(
            &self.repo_path,
            metadata_directory_flags(),
            nix::sys::stat::Mode::empty(),
        )
        .map_err(|error| refused(format!("open target root: {error}")))?;
        let child = |fd, name: &str| {
            nix::dir::Dir::openat(
                Some(fd),
                name,
                metadata_directory_flags(),
                nix::sys::stat::Mode::empty(),
            )
            .map_err(|error| refused(format!("open target metadata directory: {error}")))
        };
        let mut metadata = child(root.as_raw_fd(), ".jj")?;
        sync_metadata_directory(&mut metadata, deadline, &mut count, 0)?;
        if !executions.is_empty() {
            let agents = child(root.as_raw_fd(), super::AGENTS_DIR_NAME)?;
            for execution in executions {
                let workspace = child(agents.as_raw_fd(), &execution.to_string())?;
                let mut metadata = child(workspace.as_raw_fd(), ".jj")?;
                sync_metadata_directory(&mut metadata, deadline, &mut count, 0)?;
                nix::unistd::fsync(workspace.as_raw_fd())
                    .map_err(|error| refused(error.to_string()))?;
            }
            nix::unistd::fsync(agents.as_raw_fd()).map_err(|error| refused(error.to_string()))?;
        }
        nix::unistd::fsync(root.as_raw_fd()).map_err(|error| refused(error.to_string()))
    }

    /// Creates an absent execution workspace in an exclusively owned target.
    /// The caller installs and verifies objects first, overlays checkpoint bytes
    /// afterward, and retains target ownership until activation. No source opens.
    pub fn restore_execution_workspace(
        &self,
        execution_id: Ulid,
        commit_id: &str,
    ) -> KataResult<PathBuf> {
        if commit_id.len() != 40
            || !commit_id
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(refused("invalid checkpoint commit"));
        }
        let agent = AgentId(execution_id);
        let path = self.workspace_path(&agent);
        let settings = self.user_settings()?;
        let root = self.load_root_workspace(&settings)?;
        let repo = Self::block_on(root.repo_loader().load_at_head())
            .map_err(|_| refused("target repository unavailable"))?;
        let name = Self::workspace_name(&agent);
        if fs::symlink_metadata(&path).is_ok() || repo.view().get_wc_commit_id(&name).is_some() {
            return Err(refused("checkpoint workspace target already exists"));
        }
        let commit_id_value = super::recovery_references::parse_commit(commit_id)
            .map_err(|_| refused("invalid checkpoint commit"))?;
        let commit = repo
            .store()
            .get_commit(&commit_id_value)
            .map_err(|_| refused("checkpoint commit unavailable in target"))?;
        if commit.id() == repo.store().root_commit_id() {
            return Err(refused("root commit cannot be an execution workspace"));
        }
        let agents = self.agents_root();
        match fs::symlink_metadata(&agents) {
            Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => {}
            Ok(_) => {
                return Err(refused(
                    "target execution workspace root is not a directory",
                ));
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => fs::create_dir(&agents)?,
            Err(error) => return Err(error.into()),
        }
        fs::create_dir(&path)?;
        let (mut workspace, repo) = Self::block_on(Workspace::init_workspace_with_existing_repo(
            &path,
            root.repo_path(),
            &repo,
            &*default_working_copy_factory(),
            name.clone(),
        ))
        .map_err(|_| refused("initialize checkpoint workspace failed"))?;
        let old_tree = Self::workspace_commit(repo.as_ref(), &name)?.tree();
        let mut tx = repo.start_transaction();
        // A recovery retention ref is not a jj bookmark. Loading the Git object
        // alone does not index its ancestry for ordinary later commit/rebase.
        tx.repo_mut()
            .add_head(&commit)
            .map_err(|_| refused("index checkpoint ancestry failed"))?;
        tx.repo_mut()
            .set_wc_commit(name, commit.id().clone())
            .map_err(|_| refused("register checkpoint commit failed"))?;
        let repo = Self::block_on(tx.commit("kata restore execution checkpoint"))
            .map_err(|_| refused("publish checkpoint workspace failed"))?;
        Self::block_on(workspace.check_out(repo.op_id().clone(), Some(&old_tree), &commit))
            .map_err(|_| refused("materialize checkpoint commit failed"))?;
        // jj writes these working-copy metadata files but does not fsync them.
        // The caller still owns this unpublished target throughout this boundary.
        for relative in [
            ".jj/repo",
            ".jj/working_copy/type",
            ".jj/working_copy/checkout",
            ".jj/working_copy/tree_state",
        ] {
            sync_created(&path.join(relative), false)?;
        }
        for directory in [
            path.join(".jj/working_copy"),
            path.join(".jj"),
            path.clone(),
            agents,
            self.repo_path.clone(),
        ] {
            sync_created(&directory, true)?;
        }
        self.verify_recovery_execution_workspace(execution_id, commit_id)
    }

    /// Checks actual registration and provider path without snapshotting files.
    pub fn verify_recovery_execution_workspace(
        &self,
        execution_id: Ulid,
        commit_id: &str,
    ) -> KataResult<PathBuf> {
        let agent = AgentId(execution_id);
        let path = self.workspace_path(&agent);
        validate_workspace_path(&path).map_err(refused)?;
        let settings = self.user_settings()?;
        let workspace = self.load_agent_workspace(&settings, &agent)?;
        let name = Self::workspace_name(&agent);
        let root = self.load_root_workspace(&settings)?;
        if workspace.workspace_name().as_str() != name.as_str()
            || workspace.repo_path().canonicalize()? != root.repo_path().canonicalize()?
        {
            return Err(refused("restored workspace registration mismatch"));
        }
        let repo = Self::block_on(root.repo_loader().load_at_head())
            .map_err(|_| refused("restored view unavailable"))?;
        if repo
            .view()
            .get_wc_commit_id(&name)
            .map(jj_lib::object_id::ObjectId::hex)
            .as_deref()
            != Some(commit_id)
        {
            return Err(refused("restored workspace commit mismatch"));
        }
        let commit = Self::workspace_commit(repo.as_ref(), &name)?;
        let tree = workspace
            .working_copy()
            .tree()
            .map_err(|_| refused("restored checkout metadata unavailable"))?;
        if tree.tree_ids() != commit.tree_ids() {
            return Err(refused("restored checkout metadata mismatch"));
        }
        Ok(path)
    }
}

fn sync_created(path: &Path, directory: bool) -> KataResult<()> {
    let mut options = fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.custom_flags(
            nix::libc::O_NOFOLLOW | if directory { nix::libc::O_DIRECTORY } else { 0 },
        );
    }
    let file = options.open(path)?;
    let metadata = file.metadata()?;
    if (directory && !metadata.is_dir()) || (!directory && !metadata.is_file()) {
        return Err(refused("created checkpoint metadata changed type"));
    }
    file.sync_all()?;
    Ok(())
}

#[cfg(unix)]
fn metadata_directory_flags() -> nix::fcntl::OFlag {
    nix::fcntl::OFlag::O_RDONLY
        | nix::fcntl::OFlag::O_DIRECTORY
        | nix::fcntl::OFlag::O_NOFOLLOW
        | nix::fcntl::OFlag::O_CLOEXEC
}

#[cfg(unix)]
fn sync_metadata_directory(
    directory: &mut nix::dir::Dir,
    deadline: Instant,
    count: &mut usize,
    depth: usize,
) -> KataResult<()> {
    use nix::sys::stat::{Mode, SFlag};
    use std::os::fd::AsRawFd as _;
    if depth > 64 || Instant::now() >= deadline {
        return Err(refused("metadata sync depth or deadline exceeded"));
    }
    let fd = directory.as_raw_fd();
    for entry in directory.iter() {
        if Instant::now() >= deadline {
            return Err(refused("metadata sync deadline expired"));
        }
        let entry = entry.map_err(|error| refused(format!("read target metadata: {error}")))?;
        let name = entry.file_name();
        if matches!(name.to_bytes(), b"." | b"..") {
            continue;
        }
        *count += 1;
        if *count > 100_000 {
            return Err(refused("metadata sync entry bound exceeded"));
        }
        let stat =
            nix::sys::stat::fstatat(Some(fd), name, nix::fcntl::AtFlags::AT_SYMLINK_NOFOLLOW)
                .map_err(|error| refused(format!("inspect target metadata: {error}")))?;
        match SFlag::from_bits_truncate(stat.st_mode) {
            SFlag::S_IFDIR => {
                let mut child = nix::dir::Dir::openat(
                    Some(fd),
                    name,
                    metadata_directory_flags(),
                    Mode::empty(),
                )
                .map_err(|error| refused(format!("open target metadata directory: {error}")))?;
                sync_metadata_directory(&mut child, deadline, count, depth + 1)?;
            }
            SFlag::S_IFREG => {
                let opened = nix::fcntl::openat(
                    Some(fd),
                    name,
                    nix::fcntl::OFlag::O_RDONLY
                        | nix::fcntl::OFlag::O_NOFOLLOW
                        | nix::fcntl::OFlag::O_NONBLOCK
                        | nix::fcntl::OFlag::O_CLOEXEC,
                    Mode::empty(),
                )
                .map_err(|error| refused(format!("open target metadata file: {error}")))?;
                // nix 0.28 returns RawFd; close on every result without unsafe conversion.
                let result = (|| {
                    let stat = nix::sys::stat::fstat(opened)
                        .map_err(|error| refused(error.to_string()))?;
                    if SFlag::from_bits_truncate(stat.st_mode) != SFlag::S_IFREG {
                        return Err(refused("target metadata changed type"));
                    }
                    nix::unistd::fsync(opened)
                        .map_err(|error| refused(format!("sync target metadata: {error}")))
                })();
                let closed = nix::unistd::close(opened).map_err(|error| refused(error.to_string()));
                result?;
                closed?;
            }
            _ => return Err(refused("target metadata contains a link or special file")),
        }
    }
    nix::unistd::fsync(fd).map_err(|error| refused(format!("sync metadata directory: {error}")))
}
