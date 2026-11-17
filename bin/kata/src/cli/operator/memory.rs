//! `kata memory ...` snapshot / propose / import-inbox commands.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow, bail};
use kata_client::{
    KataClient, MemoryObjectKind, MemoryObjectStatus, MemoryProposal, MemoryProposalResponse,
    MemorySnapshot,
};
use serde::Serialize;

use crate::cli::MemoryCmd;

use super::{block_on, client, emit};

/// Dispatch `kata memory ...`.
pub(crate) fn run_memory_cmd(api_url: &str, cmd: MemoryCmd) -> Result<()> {
    block_on(async move {
        let client = client(api_url)?;
        match cmd {
            MemoryCmd::Snapshot {
                kind,
                kinds,
                status,
                statuses,
                query,
                limit,
                out_dir,
            } => {
                let kinds = parse_memory_kinds(kind.as_deref(), kinds.as_deref())?;
                let statuses = parse_memory_statuses(status.as_deref(), statuses.as_deref())?;
                let snapshot = client
                    .memory_snapshot_query(&kinds, &statuses, query.as_deref(), limit)
                    .await?;
                if let Some(out_dir) = out_dir {
                    let summary = write_memory_projection(&out_dir, &snapshot)?;
                    emit(&summary)
                } else {
                    emit(&snapshot)
                }
            }
            MemoryCmd::Get { id } => emit(&client.get_memory_object(id).await?),
            MemoryCmd::Propose { file } => {
                let proposal = read_memory_proposal(&file)?;
                emit(&client.propose_memory(&proposal).await?)
            }
            MemoryCmd::ImportInbox {
                dir,
                archive_dir,
                delete_processed,
            } => {
                let MemoryInboxEntries {
                    total_entries,
                    mut files,
                    mut skipped,
                } = memory_inbox_entries(&dir)?;
                files.sort();
                skipped.sort_by(|left, right| left.path.cmp(&right.path));
                let mut responses = Vec::new();
                for skipped in skipped {
                    responses.push(MemoryInboxImportResult {
                        file: skipped.path.display().to_string(),
                        status: "skipped".to_string(),
                        response: None,
                        error: Some(skipped.reason),
                        archived_to: None,
                        deleted: false,
                    });
                }
                for file in files {
                    let result = import_memory_inbox_file(
                        &client,
                        &file,
                        archive_dir.as_deref(),
                        delete_processed,
                    )
                    .await;
                    responses.push(result);
                }
                let summary = MemoryInboxImportSummary::from_results(
                    dir.display().to_string(),
                    archive_dir.as_ref().map(|dir| dir.display().to_string()),
                    delete_processed,
                    total_entries,
                    responses,
                );
                emit(&summary)?;
                if summary.failed > 0 {
                    bail!(
                        "memory inbox import failed for {} file(s); see JSON summary on stdout",
                        summary.failed
                    );
                }
                Ok(())
            }
        }
    })
}
fn parse_memory_kinds(kind: Option<&str>, kinds: Option<&str>) -> Result<Vec<MemoryObjectKind>> {
    if kind.is_some() && kinds.is_some() {
        bail!("use either --kind or --kinds, not both");
    }
    parse_memory_filter_list("memory kind", kind.or(kinds), MemoryObjectKind::parse)
}
fn parse_memory_statuses(
    status: Option<&str>,
    statuses: Option<&str>,
) -> Result<Vec<MemoryObjectStatus>> {
    if status.is_some() && statuses.is_some() {
        bail!("use either --status or --statuses, not both");
    }
    parse_memory_filter_list(
        "memory status",
        status.or(statuses),
        MemoryObjectStatus::parse,
    )
}
fn parse_memory_filter_list<T>(
    label: &str,
    value: Option<&str>,
    parse: impl Fn(&str) -> Option<T>,
) -> Result<Vec<T>>
where
    T: Copy + Eq,
{
    let Some(raw) = value else {
        return Ok(Vec::new());
    };
    let mut parsed = Vec::new();
    for token in raw.split(',') {
        let token = token.trim();
        if token.is_empty() {
            bail!("{label} filter cannot contain an empty value");
        }
        let value = parse(token).ok_or_else(|| anyhow!("unknown {label} `{token}`"))?;
        if !parsed.contains(&value) {
            parsed.push(value);
        }
    }
    Ok(parsed)
}
fn read_memory_proposal(path: &Path) -> Result<MemoryProposal> {
    let bytes = std::fs::read(path)
        .with_context(|| format!("reading memory proposal from {}", path.display()))?;
    serde_json::from_slice(&bytes)
        .with_context(|| format!("parsing memory proposal JSON from {}", path.display()))
}
async fn import_memory_inbox_file(
    client: &KataClient,
    file: &Path,
    archive_dir: Option<&Path>,
    delete_processed: bool,
) -> MemoryInboxImportResult {
    let proposal = match read_memory_proposal(file) {
        Ok(proposal) => proposal,
        Err(err) => {
            return MemoryInboxImportResult::failed(file, err);
        }
    };
    let response = match client.propose_memory(&proposal).await {
        Ok(response) => response,
        Err(err) => {
            return MemoryInboxImportResult::failed(file, err);
        }
    };
    let response_status = memory_response_import_status(&response);
    let processed = matches!(response_status, "applied" | "conflicted");
    let queue_cleanup = cleanup_imported_memory_inbox_file(
        file,
        archive_dir,
        delete_processed && processed,
        processed,
    );
    let (archived_to, deleted, cleanup_error) = match queue_cleanup {
        Ok(cleanup) => (cleanup.archived_to, cleanup.deleted, None),
        Err(err) => (None, false, Some(err.to_string())),
    };
    MemoryInboxImportResult {
        file: file.display().to_string(),
        status: cleanup_error
            .as_ref()
            .map_or_else(|| response_status.to_string(), |_| "failed".to_string()),
        response: Some(response),
        error: cleanup_error,
        archived_to,
        deleted,
    }
}
fn memory_response_import_status(response: &MemoryProposalResponse) -> &'static str {
    if response.conflict.is_some() {
        "conflicted"
    } else if response.status == "applied" {
        "applied"
    } else {
        "failed"
    }
}
pub(super) struct MemoryInboxEntries {
    pub(super) total_entries: usize,
    pub(super) files: Vec<PathBuf>,
    pub(super) skipped: Vec<MemoryInboxSkipped>,
}
pub(super) struct MemoryInboxSkipped {
    pub(super) path: PathBuf,
    pub(super) reason: String,
}
pub(super) fn memory_inbox_entries(dir: &Path) -> Result<MemoryInboxEntries> {
    let entries = std::fs::read_dir(dir)
        .with_context(|| format!("reading memory inbox {}", dir.display()))?;
    let mut files = Vec::new();
    let mut skipped = Vec::new();
    let mut total_entries = 0usize;
    for entry in entries {
        let entry = entry.with_context(|| format!("reading entry in {}", dir.display()))?;
        let path = entry.path();
        total_entries += 1;
        if !path.is_file() {
            skipped.push(MemoryInboxSkipped {
                path,
                reason: "not a regular file".to_string(),
            });
        } else if path
            .extension()
            .and_then(|extension| extension.to_str())
            .is_some_and(|extension| extension.eq_ignore_ascii_case("json"))
        {
            files.push(path);
        } else {
            skipped.push(MemoryInboxSkipped {
                path,
                reason: "not a JSON proposal file".to_string(),
            });
        }
    }
    Ok(MemoryInboxEntries {
        total_entries,
        files,
        skipped,
    })
}
struct MemoryInboxCleanup {
    pub(super) archived_to: Option<String>,
    pub(super) deleted: bool,
}
fn cleanup_imported_memory_inbox_file(
    file: &Path,
    archive_dir: Option<&Path>,
    delete_file: bool,
    processed: bool,
) -> Result<MemoryInboxCleanup> {
    if let Some(archive_dir) = archive_dir
        && processed
    {
        let archived_to = archive_memory_inbox_file(file, archive_dir)?;
        return Ok(MemoryInboxCleanup {
            archived_to: Some(archived_to.display().to_string()),
            deleted: false,
        });
    }
    if delete_file {
        std::fs::remove_file(file)
            .with_context(|| format!("deleting imported memory proposal {}", file.display()))?;
        return Ok(MemoryInboxCleanup {
            archived_to: None,
            deleted: true,
        });
    }
    Ok(MemoryInboxCleanup {
        archived_to: None,
        deleted: false,
    })
}
pub(super) fn archive_memory_inbox_file(file: &Path, archive_dir: &Path) -> Result<PathBuf> {
    std::fs::create_dir_all(archive_dir)
        .with_context(|| format!("creating memory archive dir {}", archive_dir.display()))?;
    let file_name = file
        .file_name()
        .ok_or_else(|| anyhow!("memory inbox path has no filename: {}", file.display()))?;
    let destination = unique_archive_destination(archive_dir, file_name);
    std::fs::rename(file, &destination).with_context(|| {
        format!(
            "archiving memory proposal {} to {}",
            file.display(),
            destination.display()
        )
    })?;
    Ok(destination)
}
fn unique_archive_destination(archive_dir: &Path, file_name: &std::ffi::OsStr) -> PathBuf {
    let candidate = archive_dir.join(file_name);
    if !candidate.exists() {
        return candidate;
    }
    let file_name = file_name.to_string_lossy();
    for suffix in 1.. {
        let candidate = archive_dir.join(format!("{file_name}.{suffix}"));
        if !candidate.exists() {
            return candidate;
        }
    }
    unreachable!("unbounded suffix search must return before overflow")
}
fn write_memory_projection(
    out_dir: &Path,
    snapshot: &MemorySnapshot,
) -> Result<MemoryProjectionSummary> {
    std::fs::create_dir_all(out_dir)
        .with_context(|| format!("creating memory projection dir {}", out_dir.display()))?;
    let snapshot_path = out_dir.join("snapshot.json");
    write_json_file(&snapshot_path, snapshot)?;

    let mut object_files = Vec::new();
    for object in &snapshot.objects {
        let object_dir = out_dir.join(object.kind.label());
        std::fs::create_dir_all(&object_dir).with_context(|| {
            format!(
                "creating memory projection object dir {}",
                object_dir.display()
            )
        })?;
        let path = object_dir.join(format!("{}.json", object.id));
        write_json_file(&path, object)?;
        object_files.push(path.display().to_string());
    }

    Ok(MemoryProjectionSummary {
        out_dir: out_dir.display().to_string(),
        snapshot_path: snapshot_path.display().to_string(),
        object_count: snapshot.object_count,
        object_files,
    })
}
fn write_json_file<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    let bytes = serde_json::to_vec_pretty(value)
        .with_context(|| format!("serializing JSON projection {}", path.display()))?;
    std::fs::write(path, bytes).with_context(|| format!("writing {}", path.display()))
}
#[derive(Debug, Serialize)]
struct MemoryProjectionSummary {
    out_dir: String,
    snapshot_path: String,
    object_count: usize,
    object_files: Vec<String>,
}
#[derive(Debug, Serialize)]
pub(super) struct MemoryInboxImportSummary {
    dir: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    archive_dir: Option<String>,
    delete_processed: bool,
    pub(super) total_entries: usize,
    pub(super) total_files: usize,
    pub(super) imported: usize,
    pub(super) applied: usize,
    pub(super) conflicted: usize,
    pub(super) failed: usize,
    pub(super) skipped: usize,
    responses: Vec<MemoryInboxImportResult>,
}
impl MemoryInboxImportSummary {
    pub(super) fn from_results(
        dir: String,
        archive_dir: Option<String>,
        delete_processed: bool,
        total_entries: usize,
        responses: Vec<MemoryInboxImportResult>,
    ) -> Self {
        let applied = responses
            .iter()
            .filter(|result| result.status == "applied")
            .count();
        let conflicted = responses
            .iter()
            .filter(|result| result.status == "conflicted")
            .count();
        let failed = responses
            .iter()
            .filter(|result| result.status == "failed")
            .count();
        let skipped = responses
            .iter()
            .filter(|result| result.status == "skipped")
            .count();
        Self {
            dir,
            archive_dir,
            delete_processed,
            total_entries,
            total_files: applied + conflicted + failed,
            imported: applied + conflicted,
            applied,
            conflicted,
            failed,
            skipped,
            responses,
        }
    }
}
#[derive(Debug, Serialize)]
pub(super) struct MemoryInboxImportResult {
    pub(super) file: String,
    pub(super) status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) response: Option<MemoryProposalResponse>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) archived_to: Option<String>,
    pub(super) deleted: bool,
}
impl MemoryInboxImportResult {
    fn failed(file: &Path, err: impl std::fmt::Display) -> Self {
        Self {
            file: file.display().to_string(),
            status: "failed".to_string(),
            response: None,
            error: Some(err.to_string()),
            archived_to: None,
            deleted: false,
        }
    }
}
