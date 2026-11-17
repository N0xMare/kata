use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result, bail};
use serde::Serialize;
use serde_json::Value;

use super::EvidenceCmd;

#[derive(Debug, Clone, Serialize)]
struct EvidenceList {
    summary_kind: &'static str,
    root: PathBuf,
    total_count: usize,
    passed_count: usize,
    failed_count: usize,
    unknown_count: usize,
    invalid_count: usize,
    packets: Vec<EvidenceSummary>,
}

#[derive(Debug, Clone, Serialize)]
struct EvidenceSummary {
    summary_kind: &'static str,
    path: PathBuf,
    packet_path: PathBuf,
    status: EvidenceStatus,
    raw_status: Option<String>,
    packet_kind: Option<String>,
    workflow: Option<String>,
    commit: Option<String>,
    snapshot_sha: Option<String>,
    execution_ids: Vec<String>,
    decision_ids: Vec<String>,
    recommended_actions: Vec<EvidenceAction>,
    artifact_count: usize,
    declared_artifact_count: usize,
    missing_artifacts: Vec<String>,
    validation_errors: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum EvidenceStatus {
    Passed,
    Failed,
    Unknown,
}

#[derive(Debug, Clone, Serialize)]
struct EvidenceAction {
    action: Option<String>,
    command: Option<String>,
    reason: Option<String>,
}

pub fn run_evidence_cmd(cmd: EvidenceCmd) -> Result<()> {
    match cmd {
        EvidenceCmd::Summary { path, json, strict } => {
            let summary = summarize_path(&path)?;
            if json {
                println!("{}", serde_json::to_string_pretty(&summary)?);
            } else {
                print_summary(&summary);
            }
            ensure_strict(strict, &summary)
        }
        EvidenceCmd::List { path, json, strict } => {
            let list = list_evidence(&path)?;
            if json {
                println!("{}", serde_json::to_string_pretty(&list)?);
            } else {
                print_list(&list);
            }
            if strict && list.total_count == 0 {
                bail!("evidence list has no packets");
            }
            if strict && (list.failed_count > 0 || list.unknown_count > 0 || list.invalid_count > 0)
            {
                bail!(
                    "evidence list has {} failed, {} unknown, and {} invalid packet(s)",
                    list.failed_count,
                    list.unknown_count,
                    list.invalid_count
                );
            }
            Ok(())
        }
    }
}

fn summarize_path(path: &Path) -> Result<EvidenceSummary> {
    let packet_path = resolve_packet_path(path)?;
    let value = read_json(&packet_path)?;
    summarize_value(path, packet_path, &value)
}

fn list_evidence(root: &Path) -> Result<EvidenceList> {
    let root = root
        .canonicalize()
        .with_context(|| format!("failed to resolve evidence root {}", root.display()))?;
    if !root.is_dir() {
        bail!("evidence list path must be a directory: {}", root.display());
    }

    let mut packet_paths = Vec::new();
    collect_packet_paths(&root, &mut packet_paths)?;
    packet_paths.sort();
    packet_paths.dedup();

    let mut packets = Vec::with_capacity(packet_paths.len());
    for packet_path in packet_paths {
        let display_path = packet_path
            .parent()
            .filter(|_| {
                packet_path
                    .file_name()
                    .is_some_and(|name| name == "evidence-summary.json")
            })
            .unwrap_or(packet_path.as_path())
            .to_path_buf();
        let value = read_json(&packet_path)?;
        packets.push(summarize_value(&display_path, packet_path, &value)?);
    }

    let passed_count = packets
        .iter()
        .filter(|packet| packet.status == EvidenceStatus::Passed)
        .count();
    let failed_count = packets
        .iter()
        .filter(|packet| packet.status == EvidenceStatus::Failed)
        .count();
    let unknown_count = packets
        .iter()
        .filter(|packet| packet.status == EvidenceStatus::Unknown)
        .count();
    let invalid_count = packets
        .iter()
        .filter(|packet| !packet.validation_errors.is_empty())
        .count();

    Ok(EvidenceList {
        summary_kind: "operator_evidence_list",
        root,
        total_count: packets.len(),
        passed_count,
        failed_count,
        unknown_count,
        invalid_count,
        packets,
    })
}

fn resolve_packet_path(path: &Path) -> Result<PathBuf> {
    let path = path
        .canonicalize()
        .with_context(|| format!("failed to resolve evidence path {}", path.display()))?;
    if path.is_file() {
        if !is_evidence_packet_file(&path) {
            bail!(
                "evidence JSON file must be named evidence-summary.json or *-evidence.json: {}",
                path.display()
            );
        }
        return Ok(path);
    }
    if !path.is_dir() {
        bail!(
            "evidence path is neither file nor directory: {}",
            path.display()
        );
    }

    let summary = path.join("evidence-summary.json");
    if summary.is_file() {
        return Ok(summary);
    }

    let mut packet_paths = Vec::new();
    collect_packet_paths(&path, &mut packet_paths)?;
    packet_paths.sort();
    packet_paths.dedup();
    match packet_paths.as_slice() {
        [only] => Ok(only.clone()),
        [] => bail!(
            "no evidence packet found under {}; expected evidence-summary.json or *-evidence.json",
            path.display()
        ),
        many => bail!(
            "multiple evidence packets found under {}; pass one packet directory or JSON file (found {})",
            path.display(),
            many.len()
        ),
    }
}

fn read_json(path: &Path) -> Result<Value> {
    let text = fs::read_to_string(path)
        .with_context(|| format!("failed to read evidence JSON {}", path.display()))?;
    serde_json::from_str(&text)
        .with_context(|| format!("failed to parse evidence JSON {}", path.display()))
}

fn summarize_value(
    display_path: &Path,
    packet_path: PathBuf,
    value: &Value,
) -> Result<EvidenceSummary> {
    let raw_status = string_at(value, &["status"]);
    let status = normalize_status(raw_status.as_deref());
    let packet_kind = string_at(value, &["summary_kind"]);
    let workflow = string_at(value, &["workflow"])
        .or_else(|| string_at(value, &["workflow", "ref"]))
        .or_else(|| string_at(value, &["workflow_name"]));
    let commit = string_at(value, &["repo_sha"])
        .or_else(|| string_at(value, &["git", "head"]))
        .or_else(|| string_at(value, &["commit"]));
    let snapshot_sha = string_at(value, &["snapshot_sha"]);
    let artifact_count = artifact_count(display_path, &packet_path)?;
    let artifact_validation = validate_declared_artifacts(value, display_path, &packet_path);
    let mut validation_errors = validate_packet_shape(value, &packet_path);
    validation_errors.extend(artifact_validation.errors);

    Ok(EvidenceSummary {
        summary_kind: "operator_evidence_summary",
        path: display_path.to_path_buf(),
        packet_path,
        status,
        raw_status,
        packet_kind,
        workflow,
        commit,
        snapshot_sha,
        execution_ids: collect_key_suffix_strings(value, "execution_id"),
        decision_ids: collect_key_suffix_strings(value, "decision_id"),
        recommended_actions: collect_recommended_actions(value),
        artifact_count,
        declared_artifact_count: artifact_validation.declared_count,
        missing_artifacts: artifact_validation.missing,
        validation_errors,
    })
}

fn collect_packet_paths(dir: &Path, out: &mut Vec<PathBuf>) -> Result<()> {
    for entry in fs::read_dir(dir).with_context(|| format!("failed to read {}", dir.display()))? {
        let entry =
            entry.with_context(|| format!("failed to read entry under {}", dir.display()))?;
        let path = entry.path();
        let ty = entry
            .file_type()
            .with_context(|| format!("failed to read file type for {}", path.display()))?;
        if ty.is_dir() {
            collect_packet_paths(&path, out)?;
        } else if ty.is_file() && is_evidence_packet_file(&path) {
            out.push(path);
        }
    }
    Ok(())
}

fn is_evidence_packet_file(path: &Path) -> bool {
    let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
        return false;
    };
    name == "evidence-summary.json" || name.ends_with("-evidence.json")
}

fn normalize_status(status: Option<&str>) -> EvidenceStatus {
    match status.map(str::to_ascii_lowercase) {
        Some(status) if matches!(status.as_str(), "pass" | "passed" | "ok" | "success") => {
            EvidenceStatus::Passed
        }
        Some(status) if matches!(status.as_str(), "fail" | "failed" | "error" | "errored") => {
            EvidenceStatus::Failed
        }
        _ => EvidenceStatus::Unknown,
    }
}

fn string_at(value: &Value, path: &[&str]) -> Option<String> {
    let mut cursor = value;
    for key in path {
        cursor = cursor.get(*key)?;
    }
    cursor.as_str().map(ToOwned::to_owned)
}

fn collect_key_suffix_strings(value: &Value, suffix: &str) -> Vec<String> {
    let mut seen = BTreeSet::new();
    collect_key_suffix_strings_inner(value, suffix, &mut seen);
    seen.into_iter().collect()
}

fn collect_key_suffix_strings_inner(value: &Value, suffix: &str, out: &mut BTreeSet<String>) {
    match value {
        Value::Object(map) => {
            for (key, child) in map {
                if key.ends_with(suffix)
                    && let Some(value) = child.as_str()
                    && !value.is_empty()
                {
                    out.insert(value.to_string());
                }
                collect_key_suffix_strings_inner(child, suffix, out);
            }
        }
        Value::Array(values) => {
            for child in values {
                collect_key_suffix_strings_inner(child, suffix, out);
            }
        }
        _ => {}
    }
}

fn collect_recommended_actions(value: &Value) -> Vec<EvidenceAction> {
    value
        .get("recommended_actions")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|action| {
            if let Some(action_str) = action.as_str() {
                return Some(EvidenceAction {
                    action: Some(action_str.to_string()),
                    command: None,
                    reason: None,
                });
            }
            let action_name = string_at(action, &["action"]);
            let command = string_at(action, &["command"]);
            let reason = string_at(action, &["reason"]);
            (action_name.is_some() || command.is_some() || reason.is_some()).then_some(
                EvidenceAction {
                    action: action_name,
                    command,
                    reason,
                },
            )
        })
        .collect()
}

fn artifact_count(display_path: &Path, packet_path: &Path) -> Result<usize> {
    let artifact_dir = if display_path.is_dir() {
        Some(display_path)
    } else if packet_path
        .file_name()
        .is_some_and(|name| name == "evidence-summary.json")
    {
        packet_path.parent()
    } else {
        None
    };

    let Some(dir) = artifact_dir else {
        return Ok(0);
    };

    let mut count = 0;
    for entry in fs::read_dir(dir).with_context(|| format!("failed to read {}", dir.display()))? {
        let entry =
            entry.with_context(|| format!("failed to read entry under {}", dir.display()))?;
        if entry
            .file_type()
            .with_context(|| format!("failed to read file type for {}", entry.path().display()))?
            .is_file()
        {
            count += 1;
        }
    }
    Ok(count)
}

#[derive(Debug, Default)]
struct ArtifactValidation {
    declared_count: usize,
    missing: Vec<String>,
    errors: Vec<String>,
}

fn validate_packet_shape(value: &Value, packet_path: &Path) -> Vec<String> {
    let mut errors = Vec::new();
    if !value.is_object() {
        errors.push("evidence packet root must be a JSON object".to_string());
        return errors;
    }
    if string_at(value, &["status"]).is_none() {
        errors.push("evidence packet missing string status".to_string());
    }

    let is_summary = packet_path
        .file_name()
        .is_some_and(|name| name == "evidence-summary.json");
    if is_summary {
        if string_at(value, &["summary_kind"]).is_none() {
            errors.push("evidence-summary.json missing string summary_kind".to_string());
        }
    } else if string_at(value, &["summary_kind"]).is_none()
        && !has_standalone_evidence_identity(value)
    {
        errors.push(
            "standalone evidence file missing summary_kind or checked execution identity"
                .to_string(),
        );
    }

    errors
}

fn has_standalone_evidence_identity(value: &Value) -> bool {
    value.get("schema_version").is_some()
        && string_at(value, &["workflow", "ref"]).is_some()
        && string_at(value, &["result", "execution_id"]).is_some()
        && string_at(value, &["result", "execution_program", "program_hash"]).is_some()
}

fn validate_declared_artifacts(
    value: &Value,
    display_path: &Path,
    packet_path: &Path,
) -> ArtifactValidation {
    let mut validation = ArtifactValidation::default();
    let Some(artifacts) = value.get("artifacts") else {
        return validation;
    };
    let Some(artifacts) = artifacts.as_array() else {
        validation
            .errors
            .push("artifacts must be an array of relative file paths".to_string());
        return validation;
    };
    validation.declared_count = artifacts.len();

    let artifact_dir = if display_path.is_dir() {
        Some(display_path)
    } else if packet_path
        .file_name()
        .is_some_and(|name| name == "evidence-summary.json")
    {
        packet_path.parent()
    } else {
        None
    };

    let Some(artifact_dir) = artifact_dir else {
        if !artifacts.is_empty() {
            validation
                .errors
                .push("declared artifacts require a packet directory".to_string());
        }
        return validation;
    };

    for artifact in artifacts {
        let Some(artifact) = artifact.as_str().filter(|artifact| !artifact.is_empty()) else {
            validation
                .errors
                .push("artifacts entries must be non-empty strings".to_string());
            continue;
        };
        if !is_safe_relative_artifact_path(artifact) {
            validation.errors.push(format!(
                "artifact path must be relative and stay within the packet directory: {artifact}"
            ));
            continue;
        }
        if !artifact_dir.join(artifact).is_file() {
            validation.missing.push(artifact.to_string());
            validation
                .errors
                .push(format!("declared artifact missing: {artifact}"));
        }
    }

    validation
}

fn is_safe_relative_artifact_path(path: &str) -> bool {
    let path = Path::new(path);
    !path.is_absolute()
        && path
            .components()
            .all(|component| matches!(component, std::path::Component::Normal(_)))
}

fn ensure_strict(strict: bool, summary: &EvidenceSummary) -> Result<()> {
    if !strict {
        return Ok(());
    }
    if summary.status != EvidenceStatus::Passed {
        bail!("evidence packet is not passing: {:?}", summary.status);
    }
    if !summary.validation_errors.is_empty() {
        bail!(
            "evidence packet failed strict validation: {}",
            summary.validation_errors.join("; ")
        );
    }
    Ok(())
}

fn print_summary(summary: &EvidenceSummary) {
    println!("Evidence: {}", status_label(summary.status));
    print_optional("Kind", summary.packet_kind.as_deref());
    print_optional("Workflow", summary.workflow.as_deref());
    print_optional("Commit", summary.commit.as_deref().map(short_sha));
    print_optional("Snapshot", summary.snapshot_sha.as_deref().map(short_sha));
    if !summary.execution_ids.is_empty() {
        println!("Executions: {}", summary.execution_ids.join(", "));
    }
    if !summary.decision_ids.is_empty() {
        println!("Decisions: {}", summary.decision_ids.join(", "));
    }
    if !summary.recommended_actions.is_empty() {
        println!("Recommended actions:");
        for action in &summary.recommended_actions {
            let name = action.action.as_deref().unwrap_or("unknown");
            match (&action.command, &action.reason) {
                (Some(command), Some(reason)) => println!("  - {name}: {command} ({reason})"),
                (Some(command), None) => println!("  - {name}: {command}"),
                (None, Some(reason)) => println!("  - {name}: {reason}"),
                (None, None) => println!("  - {name}"),
            }
        }
    }
    println!("Artifacts: {}", summary.artifact_count);
    if summary.declared_artifact_count > 0 {
        println!("Declared artifacts: {}", summary.declared_artifact_count);
    }
    if !summary.missing_artifacts.is_empty() {
        println!(
            "Missing artifacts: {}",
            summary.missing_artifacts.join(", ")
        );
    }
    if !summary.validation_errors.is_empty() {
        println!("Validation errors:");
        for error in &summary.validation_errors {
            println!("  - {error}");
        }
    }
    println!("Path: {}", summary.path.display());
    println!("Packet: {}", summary.packet_path.display());
}

fn print_list(list: &EvidenceList) {
    println!(
        "Evidence packets: {} passed, {} failed, {} unknown, {} invalid, {} total",
        list.passed_count,
        list.failed_count,
        list.unknown_count,
        list.invalid_count,
        list.total_count
    );
    for packet in &list.packets {
        let kind = packet.packet_kind.as_deref().unwrap_or("unknown");
        let workflow = packet.workflow.as_deref().unwrap_or("-");
        let validity = if packet.validation_errors.is_empty() {
            "valid"
        } else {
            "invalid"
        };
        println!(
            "- {} {} {} {} {}",
            status_label(packet.status),
            validity,
            kind,
            workflow,
            packet.path.display()
        );
    }
}

fn print_optional(label: &str, value: Option<&str>) {
    if let Some(value) = value.filter(|value| !value.is_empty()) {
        println!("{label}: {value}");
    }
}

fn status_label(status: EvidenceStatus) -> &'static str {
    match status {
        EvidenceStatus::Passed => "passed",
        EvidenceStatus::Failed => "failed",
        EvidenceStatus::Unknown => "unknown",
    }
}

fn short_sha(value: &str) -> &str {
    value.get(..12).unwrap_or(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn summary_reads_evidence_directory() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(
            dir.path().join("evidence-summary.json"),
            r#"{
              "summary_kind": "factory_self_improve_evidence",
              "status": "passed",
              "workflow": "std.software_factory.kata_self_improve",
              "repo_sha": "0123456789abcdef0123456789abcdef01234567",
              "initial_execution_id": "01KINIT",
              "next_execution_id": "01KNEXT",
              "artifacts": ["solo.log"],
              "recommended_actions": [
                {"action": "promote", "command": "kata factory apply 01KNEXT", "reason": "validated"}
              ]
            }"#,
        )
        .unwrap();
        fs::write(dir.path().join("solo.log"), "ok").unwrap();

        let summary = summarize_path(dir.path()).unwrap();
        assert_eq!(summary.status, EvidenceStatus::Passed);
        assert_eq!(
            summary.packet_kind.as_deref(),
            Some("factory_self_improve_evidence")
        );
        assert_eq!(
            summary.workflow.as_deref(),
            Some("std.software_factory.kata_self_improve")
        );
        assert_eq!(summary.execution_ids, vec!["01KINIT", "01KNEXT"]);
        assert_eq!(summary.recommended_actions.len(), 1);
        assert_eq!(summary.artifact_count, 2);
        assert_eq!(summary.declared_artifact_count, 1);
        assert!(summary.missing_artifacts.is_empty());
        assert!(summary.validation_errors.is_empty());
        ensure_strict(true, &summary).unwrap();
    }

    #[test]
    fn list_discovers_summary_and_standalone_evidence_files() {
        let dir = tempfile::tempdir().unwrap();
        let packet_dir = dir.path().join("packet");
        fs::create_dir(&packet_dir).unwrap();
        fs::write(
            packet_dir.join("evidence-summary.json"),
            r#"{"summary_kind":"factory_self_improve_evidence","status":"passed","artifacts":["run.json"]}"#,
        )
        .unwrap();
        fs::write(packet_dir.join("run.json"), "{}").unwrap();
        fs::write(
            dir.path().join("kata-local-worker-smoke-evidence.json"),
            r#"{
              "schema_version": 1,
              "status": "pass",
              "workflow": {"ref": "local-worker-ping"},
              "result": {
                "execution_id": "01KTAIL",
                "execution_program": {"program_hash": "abc123"}
              }
            }"#,
        )
        .unwrap();

        let list = list_evidence(dir.path()).unwrap();
        assert_eq!(list.total_count, 2);
        assert_eq!(list.passed_count, 2);
        assert_eq!(list.failed_count, 0);
        assert_eq!(list.unknown_count, 0);
        assert_eq!(list.invalid_count, 0);
        assert!(
            list.packets
                .iter()
                .any(|packet| packet.workflow.as_deref() == Some("local-worker-ping"))
        );
    }

    #[test]
    fn strict_rejects_unknown_status() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(
            dir.path().join("evidence-summary.json"),
            r#"{"summary_kind":"factory_self_improve_evidence","status":"unknown"}"#,
        )
        .unwrap();

        let summary = summarize_path(dir.path()).unwrap();
        let err = ensure_strict(true, &summary).unwrap_err();
        assert!(err.to_string().contains("not passing"));
    }

    #[test]
    fn summary_rejects_arbitrary_json_file_name() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("foo.json");
        fs::write(&path, r#"{"status":"passed"}"#).unwrap();

        let err = summarize_path(&path).unwrap_err();
        assert!(
            err.to_string()
                .contains("must be named evidence-summary.json or *-evidence.json"),
            "unexpected error: {err:#}"
        );
    }

    #[test]
    fn strict_rejects_missing_summary_kind() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(
            dir.path().join("evidence-summary.json"),
            r#"{"status":"passed"}"#,
        )
        .unwrap();

        let summary = summarize_path(dir.path()).unwrap();
        let err = ensure_strict(true, &summary).unwrap_err();
        assert!(
            err.to_string().contains("missing string summary_kind"),
            "unexpected error: {err:#}"
        );
    }

    #[test]
    fn strict_rejects_missing_declared_artifact() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(
            dir.path().join("evidence-summary.json"),
            r#"{
              "summary_kind": "factory_self_improve_evidence",
              "status": "passed",
              "artifacts": ["missing.json"]
            }"#,
        )
        .unwrap();

        let summary = summarize_path(dir.path()).unwrap();
        assert_eq!(summary.missing_artifacts, vec!["missing.json"]);
        let err = ensure_strict(true, &summary).unwrap_err();
        assert!(
            err.to_string()
                .contains("declared artifact missing: missing.json"),
            "unexpected error: {err:#}"
        );
    }
}
