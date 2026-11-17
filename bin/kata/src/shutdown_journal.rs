//! Bounded installed-main shutdown diagnostics.
//!
//! Graceful shutdown spans admission, workflow, provider, listener, durable
//! store, discovery, and data-directory-lock boundaries. A process exit alone
//! cannot prove their order. This module durably replaces one small
//! `installed-main.shutdown.json` record on each phase so service diagnostics
//! and host acceptance can observe the exact process generation and sequence.
//! The complete record is fsynced before lock release. Intermediate updates are
//! visible but deliberately not individually forced to stable storage: the
//! record is never recovery authority, so an absent, incomplete, or corrupt
//! record changes diagnostics only while durable lifecycle and kernel locks
//! remain authoritative.

use std::fs::{File, OpenOptions};
use std::io::Write as _;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use kata_types::time::now_ms;
use serde::{Deserialize, Serialize};

use crate::authority_file::normalize_new_owner_only_file;

const SCHEMA_VERSION: u32 = 1;
const JOURNAL_FILE: &str = "installed-main.shutdown.json";
const TEMPORARY_FILE: &str = ".installed-main.shutdown.tmp";
const MAX_PROCESS_GENERATION_BYTES: usize = 256;
const MAX_PHASE_DETAIL_BYTES: usize = 4 * 1024;
const MAX_JOURNAL_BYTES: usize = 512 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ShutdownPhase {
    AdmissionClosed,
    ProducersStopped,
    AdmissionQuiescent,
    WorkflowTasksDrained,
    ProviderAcceptorsStopped,
    WorkersAndDescendantsStopped,
    LocalCapacityStopped,
    ApiDrained,
    AuthoritativeLedgerCheckpointed,
    AttachmentRemoved,
    LockReleaseImminent,
}

impl ShutdownPhase {
    const ALL: [Self; 11] = [
        Self::AdmissionClosed,
        Self::ProducersStopped,
        Self::AdmissionQuiescent,
        Self::WorkflowTasksDrained,
        Self::ProviderAcceptorsStopped,
        Self::WorkersAndDescendantsStopped,
        Self::LocalCapacityStopped,
        Self::ApiDrained,
        Self::AuthoritativeLedgerCheckpointed,
        Self::AttachmentRemoved,
        Self::LockReleaseImminent,
    ];

    pub(crate) const fn name(self) -> &'static str {
        match self {
            Self::AdmissionClosed => "admission_closed",
            Self::ProducersStopped => "producers_stopped",
            Self::AdmissionQuiescent => "admission_quiescent",
            Self::WorkflowTasksDrained => "workflow_tasks_drained",
            Self::ProviderAcceptorsStopped => "provider_acceptors_stopped",
            Self::WorkersAndDescendantsStopped => "workers_and_descendants_stopped",
            Self::LocalCapacityStopped => "local_capacity_stopped",
            Self::ApiDrained => "api_drained",
            Self::AuthoritativeLedgerCheckpointed => "authoritative_ledger_checkpointed",
            Self::AttachmentRemoved => "attachment_removed",
            Self::LockReleaseImminent => "lock_release_imminent",
        }
    }

    const fn sequence(self) -> u32 {
        match self {
            Self::AdmissionClosed => 1,
            Self::ProducersStopped => 2,
            Self::AdmissionQuiescent => 3,
            Self::WorkflowTasksDrained => 4,
            Self::ProviderAcceptorsStopped => 5,
            Self::WorkersAndDescendantsStopped => 6,
            Self::LocalCapacityStopped => 7,
            Self::ApiDrained => 8,
            Self::AuthoritativeLedgerCheckpointed => 9,
            Self::AttachmentRemoved => 10,
            Self::LockReleaseImminent => 11,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct PhaseObservation {
    sequence: u32,
    phase: String,
    clean: bool,
    observed_at_unix_ms: u64,
    detail: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct ShutdownRecord {
    schema_version: u32,
    process_generation: String,
    started_at_unix_ms: u64,
    complete: bool,
    phases: Vec<PhaseObservation>,
}

pub(crate) struct InstalledShutdownJournal {
    path: PathBuf,
    temporary: PathBuf,
    record: ShutdownRecord,
}

impl InstalledShutdownJournal {
    pub(crate) fn create(data_dir: &Path, process_generation: &str) -> Result<Self> {
        if process_generation.is_empty() {
            bail!("installed-main shutdown generation is empty");
        }
        if process_generation.len() > MAX_PROCESS_GENERATION_BYTES {
            bail!(
                "installed-main shutdown generation exceeds the {MAX_PROCESS_GENERATION_BYTES}-byte diagnostic bound"
            );
        }
        let journal = Self {
            path: data_dir.join(JOURNAL_FILE),
            temporary: data_dir.join(TEMPORARY_FILE),
            record: ShutdownRecord {
                schema_version: SCHEMA_VERSION,
                process_generation: process_generation.to_string(),
                started_at_unix_ms: now_ms(),
                complete: false,
                phases: Vec::with_capacity(ShutdownPhase::ALL.len()),
            },
        };
        journal.persist()?;
        Ok(journal)
    }

    pub(crate) fn record(
        &mut self,
        phase: ShutdownPhase,
        clean: bool,
        detail: impl Into<String>,
    ) -> Result<()> {
        let expected = u32::try_from(self.record.phases.len() + 1)
            .context("installed-main shutdown phase count exceeds u32")?;
        if phase.sequence() != expected {
            bail!(
                "installed-main shutdown phase order violated: expected sequence {expected}, got {} ({})",
                phase.sequence(),
                phase.name()
            );
        }
        let detail = detail.into();
        if detail.len() > MAX_PHASE_DETAIL_BYTES {
            bail!(
                "installed-main shutdown phase detail exceeds the {MAX_PHASE_DETAIL_BYTES}-byte diagnostic bound"
            );
        }
        self.record.phases.push(PhaseObservation {
            sequence: expected,
            phase: phase.name().to_string(),
            clean,
            observed_at_unix_ms: now_ms(),
            detail: detail.clone(),
        });
        self.record.complete = phase == ShutdownPhase::LockReleaseImminent;
        self.persist()?;
        tracing::info!(
            target: "kata.shutdown",
            process_generation = %self.record.process_generation,
            sequence = expected,
            phase = phase.name(),
            clean,
            detail = %detail,
            "installed-main shutdown phase"
        );
        Ok(())
    }

    fn persist(&self) -> Result<()> {
        let mut payload = serde_json::to_vec_pretty(&self.record)
            .context("serializing installed-main shutdown journal")?;
        payload.push(b'\n');
        if payload.len() > MAX_JOURNAL_BYTES {
            bail!(
                "installed-main shutdown journal exceeds the {MAX_JOURNAL_BYTES}-byte diagnostic bound"
            );
        }

        // Never open the fixed diagnostic pathname for writing. It is not
        // recovery authority, and a stale same-owner path may be a FIFO,
        // symlink, hardlink, or otherwise unsuitable inode. Publishing a new
        // regular inode by rename is both atomic for readers and incapable of
        // truncating or following the inode formerly named by `self.path`.
        match std::fs::remove_file(&self.temporary) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(error).with_context(|| {
                    format!(
                        "removing stale shutdown journal temporary {}",
                        self.temporary.display()
                    )
                });
            }
        }
        let mut options = OpenOptions::new();
        options.create_new(true).write(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options
                .mode(0o600)
                .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
        }
        let mut file = options.open(&self.temporary).with_context(|| {
            format!(
                "creating shutdown journal temporary {}",
                self.temporary.display()
            )
        })?;
        normalize_new_owner_only_file(&file, &self.temporary, "shutdown journal temporary")?;
        file.write_all(&payload).with_context(|| {
            format!(
                "writing shutdown journal temporary {}",
                self.temporary.display()
            )
        })?;
        if self.record.complete {
            file.sync_all().with_context(|| {
                format!(
                    "syncing final shutdown journal temporary {}",
                    self.temporary.display()
                )
            })?;
        } else {
            file.flush().with_context(|| {
                format!(
                    "flushing shutdown journal temporary {}",
                    self.temporary.display()
                )
            })?;
        }
        std::fs::rename(&self.temporary, &self.path).with_context(|| {
            format!(
                "publishing shutdown journal {} -> {}",
                self.temporary.display(),
                self.path.display()
            )
        })?;
        if self.record.complete {
            sync_directory(
                self.path
                    .parent()
                    .ok_or_else(|| anyhow::anyhow!("shutdown journal has no parent"))?,
            )?;
        }
        Ok(())
    }
}

fn sync_directory(path: &Path) -> Result<()> {
    let directory = File::open(path)
        .with_context(|| format!("opening shutdown journal directory {}", path.display()))?;
    directory
        .sync_all()
        .with_context(|| format!("syncing shutdown journal directory {}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    const INODE_TEST_ROOT: &str = "KATA_SHUTDOWN_JOURNAL_INODE_TEST_ROOT";

    #[cfg(unix)]
    fn inode_test_child_root() -> Option<PathBuf> {
        std::env::var_os(INODE_TEST_ROOT).map(PathBuf::from)
    }

    #[cfg(unix)]
    fn run_inode_test_child(test_name: &str, root: &Path) {
        use std::io::Read as _;
        use std::process::Stdio;
        use std::thread;
        use std::time::{Duration, Instant};

        let mut child = std::process::Command::new(std::env::current_exe().expect("test binary"))
            .arg("--exact")
            .arg(test_name)
            .arg("--nocapture")
            .env(INODE_TEST_ROOT, root)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn shutdown-journal inode child");
        // Generous on purpose: a hang detector around a re-exec of the whole kata
        // test binary, which a loaded host starts slowly; no time property is
        // under test.
        let deadline = Instant::now() + Duration::from_secs(60);
        let status = loop {
            if let Some(status) = child.try_wait().expect("poll inode child") {
                break status;
            }
            if Instant::now() >= deadline {
                let _ = child.kill();
                let _ = child.wait();
                panic!("shutdown-journal inode child exceeded its sixty-second safety bound");
            }
            thread::sleep(Duration::from_millis(10));
        };
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        child
            .stdout
            .take()
            .expect("child stdout")
            .read_to_end(&mut stdout)
            .expect("read child stdout");
        child
            .stderr
            .take()
            .expect("child stderr")
            .read_to_end(&mut stderr)
            .expect("read child stderr");
        assert!(
            status.success(),
            "shutdown-journal inode child failed: stdout={} stderr={}",
            String::from_utf8_lossy(&stdout),
            String::from_utf8_lossy(&stderr)
        );
    }

    #[cfg(unix)]
    fn assert_owner_only_journal(path: &Path) {
        use std::os::unix::fs::MetadataExt as _;

        let metadata = std::fs::symlink_metadata(path).expect("journal metadata");
        assert!(metadata.is_file(), "journal must be a regular file");
        assert_eq!(metadata.mode() & 0o7777, 0o600);
        assert_eq!(metadata.nlink(), 1);
        assert_eq!(load(path).process_generation, "generation-inode-test");
    }

    #[cfg(unix)]
    fn publish_inode_test_child(root: &Path) {
        InstalledShutdownJournal::create(root, "generation-inode-test")
            .expect("publish shutdown journal");
    }

    fn load(path: &Path) -> ShutdownRecord {
        serde_json::from_slice(&std::fs::read(path).expect("read journal")).expect("parse journal")
    }

    #[test]
    fn journal_is_bounded_ordered_and_complete_only_at_lock_release() {
        let root = tempfile::tempdir().expect("tempdir");
        let mut journal =
            InstalledShutdownJournal::create(root.path(), "generation-a").expect("create journal");
        let initial = load(&root.path().join(JOURNAL_FILE));
        assert!(!initial.complete);
        assert!(initial.phases.is_empty());

        for (index, phase) in ShutdownPhase::ALL.iter().copied().enumerate() {
            journal
                .record(phase, true, format!("phase-{index}"))
                .expect("record phase");
            let current = load(&root.path().join(JOURNAL_FILE));
            assert_eq!(current.phases.len(), index + 1);
            assert_eq!(
                current.phases[index].sequence,
                u32::try_from(index + 1).expect("phase index fits u32")
            );
            assert_eq!(current.phases[index].phase, phase.name());
            assert_eq!(current.complete, index + 1 == ShutdownPhase::ALL.len());
        }
        assert!(!root.path().join(TEMPORARY_FILE).exists());
    }

    #[test]
    fn journal_refuses_a_skipped_or_reordered_phase_without_mutating_disk() {
        let root = tempfile::tempdir().expect("tempdir");
        let mut journal =
            InstalledShutdownJournal::create(root.path(), "generation-b").expect("create journal");
        let before = std::fs::read(root.path().join(JOURNAL_FILE)).expect("before");
        let error = journal
            .record(ShutdownPhase::ProducersStopped, true, "out of order")
            .expect_err("phase two before phase one must fail");
        assert!(error.to_string().contains("expected sequence 1"));
        assert_eq!(
            std::fs::read(root.path().join(JOURNAL_FILE)).expect("after"),
            before
        );
    }

    #[test]
    fn journal_refuses_oversized_detail_without_mutating_disk() {
        let root = tempfile::tempdir().expect("tempdir");
        let mut journal =
            InstalledShutdownJournal::create(root.path(), "generation-bounded").expect("create");
        let path = root.path().join(JOURNAL_FILE);
        let before = std::fs::read(&path).expect("before");
        let error = journal
            .record(
                ShutdownPhase::AdmissionClosed,
                true,
                "x".repeat(MAX_PHASE_DETAIL_BYTES + 1),
            )
            .expect_err("oversized diagnostic detail must fail closed");
        assert!(error.to_string().contains("diagnostic bound"));
        assert_eq!(std::fs::read(&path).expect("after"), before);
    }

    #[test]
    #[cfg(unix)]
    fn journal_atomically_replaces_stale_fifo_without_blocking() {
        use nix::sys::stat::Mode;

        if let Some(root) = inode_test_child_root() {
            publish_inode_test_child(&root);
            return;
        }
        let root = tempfile::tempdir().expect("tempdir");
        let path = root.path().join(JOURNAL_FILE);
        nix::unistd::mkfifo(&path, Mode::S_IRUSR | Mode::S_IWUSR).expect("create stale FIFO");

        run_inode_test_child(
            "shutdown_journal::tests::journal_atomically_replaces_stale_fifo_without_blocking",
            root.path(),
        );
        assert_owner_only_journal(&path);
    }

    #[test]
    #[cfg(unix)]
    fn journal_atomically_replaces_symlink_without_mutating_target() {
        use std::os::unix::fs::symlink;

        if let Some(root) = inode_test_child_root() {
            publish_inode_test_child(&root);
            return;
        }
        let root = tempfile::tempdir().expect("tempdir");
        let path = root.path().join(JOURNAL_FILE);
        let target = root.path().join("symlink-target");
        let sentinel = b"symlink target must remain byte-identical";
        std::fs::write(&target, sentinel).expect("write symlink target");
        symlink(&target, &path).expect("create stale symlink");

        run_inode_test_child(
            "shutdown_journal::tests::journal_atomically_replaces_symlink_without_mutating_target",
            root.path(),
        );
        assert_eq!(std::fs::read(&target).expect("read target"), sentinel);
        assert_owner_only_journal(&path);
    }

    #[test]
    #[cfg(unix)]
    fn journal_atomically_replaces_same_owner_hardlink_without_mutating_peer() {
        use std::os::unix::fs::MetadataExt as _;

        if let Some(root) = inode_test_child_root() {
            publish_inode_test_child(&root);
            return;
        }
        let root = tempfile::tempdir().expect("tempdir");
        let path = root.path().join(JOURNAL_FILE);
        let peer = root.path().join("hardlink-peer");
        let sentinel = b"same-owner hardlink peer must remain byte-identical";
        std::fs::write(&peer, sentinel).expect("write hardlink peer");
        std::fs::hard_link(&peer, &path).expect("create stale hardlink");
        let peer_inode = peer.metadata().expect("peer metadata").ino();

        run_inode_test_child(
            "shutdown_journal::tests::journal_atomically_replaces_same_owner_hardlink_without_mutating_peer",
            root.path(),
        );
        let peer_metadata = peer.metadata().expect("peer metadata after publication");
        assert_eq!(peer_metadata.ino(), peer_inode);
        assert_eq!(peer_metadata.nlink(), 1);
        assert_eq!(std::fs::read(&peer).expect("read peer"), sentinel);
        assert_ne!(
            std::fs::symlink_metadata(&path)
                .expect("journal metadata")
                .ino(),
            peer_inode
        );
        assert_owner_only_journal(&path);
    }

    #[test]
    #[cfg(unix)]
    fn journal_replaces_permissive_destination_without_mutating_old_inode() {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

        if let Some(root) = inode_test_child_root() {
            publish_inode_test_child(&root);
            return;
        }
        let root = tempfile::tempdir().expect("tempdir");
        let path = root.path().join(JOURNAL_FILE);
        let peer = root.path().join("permissive-peer");
        let sentinel = b"permissive old inode must remain byte-identical";
        std::fs::write(&peer, sentinel).expect("write permissive peer");
        std::fs::set_permissions(&peer, std::fs::Permissions::from_mode(0o666))
            .expect("make old inode permissive");
        std::fs::hard_link(&peer, &path).expect("publish permissive destination");
        let peer_inode = peer.metadata().expect("peer metadata").ino();

        run_inode_test_child(
            "shutdown_journal::tests::journal_replaces_permissive_destination_without_mutating_old_inode",
            root.path(),
        );
        let peer_metadata = peer.metadata().expect("peer metadata after publication");
        assert_eq!(peer_metadata.ino(), peer_inode);
        assert_eq!(peer_metadata.mode() & 0o7777, 0o666);
        assert_eq!(std::fs::read(&peer).expect("read peer"), sentinel);
        assert_ne!(
            std::fs::symlink_metadata(&path)
                .expect("journal metadata")
                .ino(),
            peer_inode
        );
        assert_owner_only_journal(&path);
    }

    #[test]
    #[cfg(unix)]
    fn journal_creation_and_second_phase_ignore_restrictive_umask() {
        use std::os::unix::fs::MetadataExt as _;

        const CHILD_ROOT: &str = "KATA_SHUTDOWN_JOURNAL_UMASK_TEST_ROOT";
        if let Some(raw) = std::env::var_os(CHILD_ROOT) {
            let root = PathBuf::from(raw);
            let mut journal =
                InstalledShutdownJournal::create(&root, "generation-umask").expect("create");
            journal
                .record(ShutdownPhase::AdmissionClosed, true, "phase-one")
                .expect("second publication");
            let path = root.join(JOURNAL_FILE);
            assert_eq!(path.metadata().expect("metadata").mode() & 0o7777, 0o600);
            let record = load(&path);
            assert_eq!(record.phases.len(), 1);
            return;
        }

        let root = tempfile::tempdir().expect("tempdir");
        let output = std::process::Command::new("/bin/sh")
            .arg("-c")
            .arg("umask 0777; exec \"$1\" --exact shutdown_journal::tests::journal_creation_and_second_phase_ignore_restrictive_umask --nocapture")
            .arg("kata-shutdown-journal-umask")
            .arg(std::env::current_exe().expect("test executable"))
            .env(CHILD_ROOT, root.path())
            .output()
            .expect("run restrictive-umask child");
        assert!(
            output.status.success(),
            "restrictive-umask child failed: stdout={} stderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
}
