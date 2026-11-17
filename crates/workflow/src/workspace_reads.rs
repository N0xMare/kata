//! The typed READ-plane VCS facts exposed to stage prompts as the
//! `{{ workspace.* }}` namespace.
//!
//! Agents are forbidden from shelling `git`/`jj` inside the sandbox (the
//! worktree's VCS store lives outside the sandbox mount). The gap this closes is
//! the missing *builtins*: a controller/reviewer stage that must reason about
//! the workspace can cite AUTHORITATIVE VCS facts computed IN-PROCESS on the
//! host, instead of trusting model prose. The surface is deliberately narrow and
//! typed:
//!
//! * `{{ workspace.head }}` / `{{ workspace.head_sha }}` — the recorded head
//!   commit id: the commit that holds the execution's content.
//! * `{{ workspace.tree_id }}` — that head's jj `MergedTree` content address
//!   (the workspace effect's key).
//! * `{{ workspace.changed_files }}` — the files this execution changed relative
//!   to its base: the paths the recorded head's tree differs from the
//!   execution's BASE commit's in (the commit admission forked the workspace
//!   from, recorded on the execution's head row).
//! * `{{ workspace.diff }}` — the same diff with each path's kind,
//!   `[{path, kind}]`, `kind` one of `added` / `modified` / `deleted`.
//! * `{{ workspace.query("<revset>") }}` — a bounded jj revset query, accepting
//!   the FULL revset language. Evaluated lazily at render time
//!   against the workspace's recorded `.jj` view.
//!
//! Every fact is RECORDED state, read through the provider
//! (`WorkflowRunner::workspace_template_context`): the head and tree from the
//! shared repo view, the diff from two recorded commits. Nothing here scans the
//! worktree's files, so the same two commits render the same namespace.
//!
//! `kata check` refuses a `workspace.<name>` outside these names
//! ([`WORKSPACE_READ_KEYS`], [`WORKSPACE_METHODS`](kata_program::template::WORKSPACE_METHODS)). A plain subscript or alias
//! read the check cannot see fails the strict dispatch-time render as an
//! undefined read; a form that tolerates an undefined value
//! (`workspace['x'] | default(..)`, `workspace['x'] is defined`) renders its
//! fallback, as it would for any field the namespace lacks.

use std::path::PathBuf;
use std::sync::Arc;

use kata_effects_contract::{RecordedChangeKind, RecordedPathChange};
use kata_vcs::revset::DEFAULT_REVSET_LIMIT;
use minijinja::value::{Enumerator, Object, from_args};
use minijinja::{Error, ErrorKind, State, Value};
use smol_str::SmolStr;

use kata_program::template::WORKSPACE_READ_KEYS;

/// The typed READ-plane VCS facts for one execution worktree. Cloned into the
/// prompt render environment as a live minijinja object so `query()` can be
/// evaluated lazily against the arbitrary revset an author writes.
#[derive(Clone, Debug)]
pub struct WorkspaceReads {
    /// The worktree root on disk, used to evaluate `query()` at render time.
    worktree: PathBuf,
    /// The recorded head commit id (jj commit hex).
    head: String,
    /// jj `MergedTree` root hash.
    tree_id: String,
    /// The changed paths alone, in diff order (`changed_files`).
    changed_files: Vec<SmolStr>,
    /// The typed diff from the base commit to the recorded head (`diff`).
    changes: Vec<RecordedPathChange>,
}

impl WorkspaceReads {
    /// Build the read plane from the recorded head and its diff from the
    /// execution's base. `changed_files` is derived so the two never drift.
    pub fn new(
        worktree: PathBuf,
        head: String,
        tree_id: String,
        changes: Vec<RecordedPathChange>,
    ) -> Self {
        let changed_files = changes.iter().map(|change| change.path.clone()).collect();
        Self {
            worktree,
            head,
            tree_id,
            changed_files,
            changes,
        }
    }

    /// Uniform lowercase name for a change kind, as cited by `{{ workspace.diff }}`.
    fn kind_str(kind: RecordedChangeKind) -> &'static str {
        match kind {
            RecordedChangeKind::Added => "added",
            RecordedChangeKind::Modified => "modified",
            RecordedChangeKind::Deleted => "deleted",
        }
    }

    /// The `{{ workspace.diff }}` value: the per-file `[{path, kind}]` changeset.
    fn diff_json(&self) -> serde_json::Value {
        serde_json::Value::Array(
            self.changes
                .iter()
                .map(|change| {
                    serde_json::json!({
                        "path": change.path.as_str(),
                        "kind": Self::kind_str(change.kind),
                    })
                })
                .collect(),
        )
    }

    /// Evaluate `{{ workspace.query("<revset>") }}` against the workspace's
    /// recorded `.jj` view, riding the full-language revset parser.
    fn run_query(&self, revset: &str, limit: usize) -> Result<Value, Error> {
        let result = kata_vcs::JjBackend::query_revset_at_path(&self.worktree, revset, limit)
            .map_err(|err| {
                Error::new(
                    ErrorKind::InvalidOperation,
                    format!("workspace.query failed: {err}"),
                )
            })?;
        Ok(Value::from_serialize(&result))
    }
}

impl Object for WorkspaceReads {
    fn get_value(self: &Arc<Self>, key: &Value) -> Option<Value> {
        match key.as_str()? {
            "changed_files" => Some(Value::from_serialize(&self.changed_files)),
            "head" | "head_sha" => Some(Value::from(self.head.clone())),
            "tree_id" => Some(Value::from(self.tree_id.clone())),
            "diff" => Some(Value::from_serialize(self.diff_json())),
            _ => None,
        }
    }

    fn enumerate(self: &Arc<Self>) -> Enumerator {
        Enumerator::Str(WORKSPACE_READ_KEYS)
    }

    fn call_method(
        self: &Arc<Self>,
        _state: &State<'_, '_>,
        method: &str,
        args: &[Value],
    ) -> Result<Value, Error> {
        match method {
            "query" => {
                let (revset, limit): (String, Option<usize>) = from_args(args)?;
                let limit = limit.unwrap_or(DEFAULT_REVSET_LIMIT).max(1);
                self.run_query(&revset, limit)
            }
            other => Err(Error::new(
                ErrorKind::UnknownMethod,
                format!("workspace has no method `{other}`"),
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::WorkspaceReads;

    fn render(template: &str) -> kata_types::KataResult<String> {
        let reads = WorkspaceReads::new(
            std::path::PathBuf::from("/nonexistent"),
            "c0ffee".to_owned(),
            "7ree".to_owned(),
            Vec::new(),
        );
        kata_program::template::render_prompt_with_runtime_context(
            "s",
            template,
            &BTreeMap::new(),
            None,
            None,
            None,
            None,
            None,
            Some(minijinja::Value::from_object(reads.clone())),
            None,
        )
    }

    /// A name the namespace does not answer — here `dirty` and `status` — read
    /// in a shape the check-time refusal cannot see (a subscript, an alias)
    /// fails at the strict dispatch-time render. The undefined-tolerant forms
    /// render their fallback, exactly as for any field the namespace lacks: the
    /// module header states that edge. The enumeration is the declared key set.
    #[test]
    fn unknown_reads_are_undefined_at_render() {
        for template in [
            "{{ workspace.dirty }}",
            "{{ workspace['status'] }}",
            "{% if workspace['dirty'] %}x{% endif %}",
            "{% with w = workspace %}{{ w.dirty }}{% endwith %}",
        ] {
            assert!(
                render(template).is_err(),
                "{template:?} must not render: {:?}",
                render(template)
            );
        }
        assert_eq!(
            render("{{ workspace['dirty'] | default('fallback') }}").unwrap(),
            "fallback"
        );
        assert_eq!(
            render("{{ workspace['status'] is defined }}").unwrap(),
            "false"
        );
        assert_eq!(
            render("{% for key in workspace %}{{ key }},{% endfor %}").unwrap(),
            "head,diff,tree_id,changed_files,head_sha,"
        );
        // Every declared key is answered: the check admits no key the
        // namespace cannot render. (The converse — every answered key is
        // declared — is held by hand-matching `get_value`/`call_method`.)
        for key in kata_program::template::WORKSPACE_READ_KEYS {
            assert!(
                render(&format!("{{{{ workspace.{key} }}}}")).is_ok(),
                "declared key {key} must render"
            );
        }
    }
}
