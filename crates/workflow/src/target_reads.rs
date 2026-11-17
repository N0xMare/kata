//! The `{{ target.* }}` namespace's live object: [`TargetReads`] answers every
//! key [`kata_program::target_namespace`] names (and documents) off the execution's
//! frozen target, reading `changed_files` and `diff` through the execution
//! workspace provider when a render first asks for them.

use std::sync::{Arc, OnceLock};

use kata_effects_contract::{ExecutionWorkspaceProvider, RecordedChangeKind, RecordedPathChange};
use kata_types::target::ExecutionTarget;
use minijinja::value::{Enumerator, Object};
use minijinja::{Error, ErrorKind, Value};

use kata_program::target_namespace::{
    MAX_TARGET_CHANGED_FILES, MAX_TARGET_DIFF_BYTES, TARGET_KEYS,
};

/// The `target` namespace object one render reads.
#[derive(Clone)]
pub struct TargetReads {
    target: Arc<ExecutionTarget>,
    provider: Option<Arc<dyn ExecutionWorkspaceProvider>>,
    changes: Arc<OnceLock<Result<Vec<RecordedPathChange>, String>>>,
    diff: Arc<OnceLock<Result<kata_effects_contract::RecordedTextDiff, String>>>,
}

impl std::fmt::Debug for TargetReads {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TargetReads")
            .field("target", &self.target)
            .field("provider", &self.provider.is_some())
            .finish_non_exhaustive()
    }
}

impl TargetReads {
    /// The namespace over `target`, reading `changed_files` / `diff` through
    /// `provider` when a render first asks for them. `None` makes those reads
    /// fail the render — an isolated execution always has a provider.
    #[must_use]
    pub fn new(
        target: Arc<ExecutionTarget>,
        provider: Option<Arc<dyn ExecutionWorkspaceProvider>>,
    ) -> Self {
        Self {
            target,
            provider,
            changes: Arc::new(OnceLock::new()),
            diff: Arc::new(OnceLock::new()),
        }
    }

    /// The merge base and head the range reads span, or `None` when the target
    /// has no baseline.
    fn range(&self) -> Option<(&str, &str)> {
        let compare = self.target.compare.as_ref()?;
        let head = self.target.head.commit()?;
        Some((compare.merge_base.as_str(), head))
    }

    fn provider(&self, key: &str) -> Result<&dyn ExecutionWorkspaceProvider, String> {
        self.provider.as_deref().ok_or_else(|| {
            format!(
                "target.{key}: no execution-workspace provider is attached to this render, so \
                 the frozen range cannot be read"
            )
        })
    }

    /// Every change in the frozen range, uncapped — `None` without a baseline.
    fn changes(&self) -> Option<&Result<Vec<RecordedPathChange>, String>> {
        let (base, head) = self.range()?;
        Some(self.changes.get_or_init(|| {
            self.provider("changed_files")?
                .recorded_commit_diff(base, head)
                .map_err(|err| format!("target.changed_files: {err}"))
        }))
    }

    /// The bounded text diff of the frozen range — `None` without a baseline.
    fn diff(&self) -> Option<&Result<kata_effects_contract::RecordedTextDiff, String>> {
        let (base, head) = self.range()?;
        Some(self.diff.get_or_init(|| {
            self.provider("diff")?
                .recorded_commit_text_diff(base, head, MAX_TARGET_DIFF_BYTES)
                .map_err(|err| format!("target.diff: {err}"))
        }))
    }

    fn changed_files_value(&self) -> Value {
        match self.changes() {
            None => Value::from(()),
            Some(Err(err)) => invalid(err),
            Some(Ok(changes)) => Value::from_serialize(
                changes
                    .iter()
                    .take(MAX_TARGET_CHANGED_FILES)
                    .map(|change| {
                        serde_json::json!({
                            "path": change.path.as_str(),
                            "kind": change_kind(change.kind),
                        })
                    })
                    .collect::<Vec<_>>(),
            ),
        }
    }

    fn changed_files_truncated_value(&self) -> Value {
        match self.changes() {
            None => Value::from(false),
            Some(Err(err)) => invalid(err),
            Some(Ok(changes)) => Value::from(changes.len() > MAX_TARGET_CHANGED_FILES),
        }
    }

    fn diff_value(&self, truncated: bool) -> Value {
        match self.diff() {
            None if truncated => Value::from(false),
            None => Value::from(()),
            Some(Err(err)) => invalid(err),
            Some(Ok(diff)) if truncated => Value::from(diff.truncated),
            Some(Ok(diff)) => Value::from(diff.text.clone()),
        }
    }
}

/// An invalid value carrying `message`: a render that reads it fails, naming
/// the read.
fn invalid(message: &str) -> Value {
    Value::from(Error::new(ErrorKind::InvalidOperation, message.to_owned()))
}

/// The lowercase kind name, as `workspace.diff` spells it.
const fn change_kind(kind: RecordedChangeKind) -> &'static str {
    match kind {
        RecordedChangeKind::Added => "added",
        RecordedChangeKind::Modified => "modified",
        RecordedChangeKind::Deleted => "deleted",
    }
}

impl Object for TargetReads {
    fn get_value(self: &Arc<Self>, key: &Value) -> Option<Value> {
        let target = &self.target;
        Some(match key.as_str()? {
            "spec" => Value::from(target.spec.to_string()),
            "kind" => Value::from(target.spec.kind()),
            "head" => target
                .head
                .commit()
                .map_or_else(|| Value::from(()), Value::from),
            "branch" => target
                .branch
                .as_deref()
                .map_or_else(|| Value::from(()), Value::from),
            "compare" => target.compare.as_ref().map_or_else(
                || Value::from(()),
                |compare| {
                    Value::from_serialize(serde_json::json!({
                        "name": compare.name,
                        "commit": compare.commit,
                        "merge_base": compare.merge_base,
                    }))
                },
            ),
            "pr" => target.pull_request.as_ref().map_or_else(
                || Value::from(()),
                |pr| {
                    Value::from_serialize(serde_json::json!({
                        "number": pr.number,
                        "url": pr.url,
                        "title": pr.title,
                        "title_truncated": pr.title_truncated,
                        "body": pr.body,
                        "body_truncated": pr.body_truncated,
                        "base_ref": pr.base_ref,
                        "head_ref": pr.head_ref,
                    }))
                },
            ),
            "changed_files" => self.changed_files_value(),
            "changed_files_truncated" => self.changed_files_truncated_value(),
            "diff" => self.diff_value(false),
            "diff_truncated" => self.diff_value(true),
            _ => return None,
        })
    }

    fn enumerate(self: &Arc<Self>) -> Enumerator {
        Enumerator::Str(TARGET_KEYS)
    }
}
