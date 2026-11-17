//! Binding a subworkflow stage's child program at the parent's CHECK.
//!
//! A `subworkflow(pack = "x")` stage names its child by pack NAME, and a name is a
//! machine fact: what it resolves to depends on the library roots of whoever reads
//! it, and when. AGENTS.md (Design principles) requires a pack to compile to a
//! content-hashed IR frozen at admission that names no such fact, so the compiler
//! resolves every child ONCE, through the library roots the compile was handed,
//! compiles it (recursively, through the same compiler), and embeds the result as
//! a [`BoundChildProgram`] whose hash the parent's `program_hash` folds.
//!
//! # The refused set, stated exactly
//!
//! A compile refuses, by name:
//!
//! * `subworkflow_unresolvable_without_library` — the program has a subworkflow stage
//!   and the compile door holds no library (the programmatic doors:
//!   `compile_execution_program_from_parts*`, `compile_agent_run_execution_program`,
//!   and the in-crate `compile_execution_program` fixtures). A program with no
//!   subworkflow stage is never refused here, whatever the door;
//! * `subworkflow_pack_unresolved` — the pack name resolves in none of the roots, or
//!   the file it resolves to cannot be read;
//! * `subworkflow_cycle` — the resolved child's canonical file, or its source bytes'
//!   hash, already appears on the chain from the root to this stage (the message names
//!   the chain). Equal source bytes are a cycle even under two names: the same source
//!   resolves the same children through the same roots, so the expansion never ends;
//! * `subworkflow_depth_exceeded` — the child would sit more than
//!   [`MAX_SUBWORKFLOW_DEPTH`] invocations below the root;
//!
//! and any compile error of the child itself, prefixed with the stage and pack that
//! invoked it (so a nested failure reads as the chain down to it).
//!
//! # Each distinct child is bound once per compile
//!
//! A child with the same canonical file and source bytes as one this compile already
//! bound is REUSED — its body shared, not recompiled — when its deepest descendant stays
//! within [`MAX_SUBWORKFLOW_DEPTH`] where it is now invoked. Otherwise it is compiled
//! afresh, so the depth refusal names the chain it is refused on. The stored program
//! then carries each distinct child once (`super::bound_children`).
//!
//! Reuse needs no cycle question beyond the one `subworkflow_cycle` asks of the child
//! itself: a child is in the table only because its subtree bound WITHOUT a cycle, and a
//! compile's expansion of a pack depends only on its bytes and the roots, so no program
//! of that subtree can invoke a program on the current chain — if one did, the same
//! expansion would have met the child again inside its own first binding and refused it.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use kata_types::primitives::ContentHash;
use kata_types::workflow::{StageId, WorkflowDefinition, workflow_source_hash};
use kata_types::{KataError, KataResult};

use super::{BoundChildProgram, ExecutionProgramCompileOptions};
use crate::library::WorkflowLibrary;

/// The deepest chain of nested subworkflow invocations below a root program that a
/// compile admits: the root is depth 0, its children depth 1. A judgement — no
/// shipped pack nests at all — revisited when a pack needs more.
pub const MAX_SUBWORKFLOW_DEPTH: usize = 8;

/// One program on the chain from the root to the child being bound.
struct ChainLink {
    /// The pack name (or, for the root, the workflow name) — for messages only.
    label: String,
    /// The canonical file the program was read from, when it came from one.
    path: Option<PathBuf>,
    /// The frontend source hash of the program's own source bytes.
    source_hash: Option<ContentHash>,
}

/// One bound child's identity, as reuse compares it: its canonical file and its source
/// bytes' hash (rendered).
type Member = (PathBuf, String);

/// A child already bound by this compile, reused for every later invocation of the same
/// bytes: identity is content, so one compile binds each distinct child ONCE.
struct Bound {
    /// The bound child, its body shared.
    child: BoundChildProgram,
    /// How many invocations its deepest descendant sits below it (0: no subworkflow).
    height: usize,
}

/// What the children bound while one program compiles add up to, for its own [`Bound`]:
/// the greatest height among them, `None` while it has bound none.
#[derive(Default)]
struct Frame {
    deepest_child: Option<usize>,
}

/// Resolves and compiles the children of the programs one compile produces.
pub(crate) struct SubworkflowBinder<'a> {
    /// The library roots child packs resolve through; `None` for a door that holds
    /// no library.
    roots: Option<&'a [PathBuf]>,
    /// The root program's file, when the compile started from one.
    root_path: Option<PathBuf>,
    /// Root first. Empty until the root program's definition is seen.
    chain: Vec<ChainLink>,
    /// Every child this compile bound, by `(canonical file, source hash)`.
    bound: BTreeMap<Member, Bound>,
    /// One frame per program being compiled below the root, innermost last.
    frames: Vec<Frame>,
}

impl<'a> SubworkflowBinder<'a> {
    /// A compile that resolves children through `roots` — the same roots the pack's
    /// `load()`s resolve against. `root_path` is the root pack's file, when there is
    /// one, so a child resolving back to it is a cycle by path as well as by bytes.
    pub(crate) fn with_library(roots: &'a [PathBuf], root_path: Option<&Path>) -> Self {
        Self {
            roots: Some(roots),
            root_path: root_path.map(canonical),
            chain: Vec::new(),
            bound: BTreeMap::new(),
            frames: Vec::new(),
        }
    }

    /// A compile door that holds no library: any subworkflow stage is refused.
    pub(crate) const fn without_library() -> Self {
        Self {
            roots: None,
            root_path: None,
            chain: Vec::new(),
            bound: BTreeMap::new(),
            frames: Vec::new(),
        }
    }

    /// Whether the program being compiled is a CHILD being bound (not the root).
    pub(crate) fn is_binding_child(&self) -> bool {
        self.chain.len() > 1
    }

    /// Bind every subworkflow stage of `definition`, which is the program at the top
    /// of the chain (the root on the first call).
    pub(crate) fn bind_children(
        &mut self,
        definition: &WorkflowDefinition,
    ) -> KataResult<BTreeMap<StageId, BoundChildProgram>> {
        if self.chain.is_empty() {
            self.chain.push(ChainLink {
                label: definition.name.to_string(),
                path: self.root_path.clone(),
                source_hash: definition.provenance.frontend.source_hash,
            });
        }
        let mut bound = BTreeMap::new();
        for (stage_id, stage) in &definition.stages {
            let Some(spec) = stage.subworkflow.as_ref() else {
                continue;
            };
            let child = self.bind_child(stage_id, spec.pack.as_str())?;
            bound.insert(stage_id.clone(), child);
        }
        Ok(bound)
    }

    fn bind_child(&mut self, stage_id: &StageId, pack: &str) -> KataResult<BoundChildProgram> {
        let Some(roots) = self.roots else {
            return Err(KataError::Validation(format!(
                "subworkflow_unresolvable_without_library: stage \"{stage}\" invokes subworkflow \
                 pack \"{pack}\", and this compile holds no workflow library to resolve it \
                 through. A child program is bound at the parent's check, so a subworkflow can \
                 only be compiled from a library-bearing door (a pack file, or inline Starlark \
                 with library roots)",
                stage = stage_id.0,
            )));
        };
        let path = WorkflowLibrary::new(roots.to_vec())
            .resolve(pack)
            .map_err(|error| self.unresolved(stage_id, pack, &error.to_string()))?;
        let source = std::fs::read_to_string(&path).map_err(|error| {
            self.unresolved(stage_id, pack, &format!("read {}: {error}", path.display()))
        })?;
        let source_hash = workflow_source_hash(source.as_bytes());
        let canonical_path = canonical(&path);
        if self.chain.iter().any(|link| {
            link.path.as_ref() == Some(&canonical_path) || link.source_hash == Some(source_hash)
        }) {
            return Err(KataError::Validation(format!(
                "subworkflow_cycle: stage \"{stage}\" invokes subworkflow pack \"{pack}\", which \
                 is already on the invocation chain {chain} -> {pack}. A cyclic subworkflow chain \
                 never finishes binding, so it is refused at check",
                stage = stage_id.0,
                chain = self.chain_label(),
            )));
        }
        if self.chain.len() > MAX_SUBWORKFLOW_DEPTH {
            return Err(KataError::Validation(format!(
                "subworkflow_depth_exceeded: stage \"{stage}\" invokes subworkflow pack \
                 \"{pack}\" at depth {depth} of the invocation chain {chain} -> {pack}; at most \
                 {MAX_SUBWORKFLOW_DEPTH} nested subworkflow invocations below the root are \
                 admitted",
                stage = stage_id.0,
                depth = self.chain.len(),
                chain = self.chain_label(),
            )));
        }

        let member: Member = (canonical_path.clone(), source_hash.to_string());
        if let Some(bound) = self.reusable(&member) {
            let (child, height) = (bound.child.clone(), bound.height);
            self.record_in_parent(height);
            return Ok(child);
        }

        self.chain.push(ChainLink {
            label: pack.to_owned(),
            path: Some(canonical_path),
            source_hash: Some(source_hash),
        });
        self.frames.push(Frame::default());
        let compiled = crate::starlark_eval::evaluate_starlark_with_loader_checked(
            &source,
            &path.display().to_string(),
            roots,
        )
        .and_then(|checked| {
            super::compile::compile_execution_program_with_options(
                &checked,
                ExecutionProgramCompileOptions::empty(),
                self,
                // A bound child never runs the profile door here (`is_binding_child`
                // skips it); the parent's admission recursion collects its deferred
                // facts. The scratch set is therefore always empty on return.
                &mut std::collections::BTreeSet::new(),
            )
        });
        self.chain.pop();
        let frame = self.frames.pop().unwrap_or_default();
        let program = compiled.map_err(|error| {
            KataError::Validation(format!(
                "stage \"{stage}\" invokes subworkflow pack \"{pack}\", which does not compile: \
                 {error}",
                stage = stage_id.0,
            ))
        })?;
        let child = BoundChildProgram::bind(program)?;
        let height = frame.deepest_child.map_or(0, |deepest| deepest + 1);
        self.record_in_parent(height);
        self.bound.insert(
            member,
            Bound {
                child: child.clone(),
                height,
            },
        );
        Ok(child)
    }

    /// The child this compile already bound for `member`, when binding it HERE would pass
    /// the depth check a fresh compile of it would: its deepest descendant still sits
    /// within [`MAX_SUBWORKFLOW_DEPTH`] below the root. Otherwise `None`, and the child is
    /// compiled afresh, so the refusal names the chain it is refused on. (No cycle check:
    /// see the module docs, "Each distinct child is bound once per compile".)
    fn reusable(&self, member: &Member) -> Option<&Bound> {
        let bound = self.bound.get(member)?;
        (self.chain.len() + bound.height <= MAX_SUBWORKFLOW_DEPTH).then_some(bound)
    }

    /// Fold a bound child's height into the frame of the program invoking it.
    fn record_in_parent(&mut self, height: usize) {
        if let Some(parent) = self.frames.last_mut() {
            parent.deepest_child = Some(parent.deepest_child.map_or(height, |d| d.max(height)));
        }
    }

    fn unresolved(&self, stage_id: &StageId, pack: &str, reason: &str) -> KataError {
        KataError::Validation(format!(
            "subworkflow_pack_unresolved: stage \"{stage}\" invokes subworkflow pack \"{pack}\" \
             (invocation chain {chain} -> {pack}), which does not resolve to a readable pack: \
             {reason}",
            stage = stage_id.0,
            chain = self.chain_label(),
        ))
    }

    fn chain_label(&self) -> String {
        self.chain
            .iter()
            .map(|link| link.label.as_str())
            .collect::<Vec<_>>()
            .join(" -> ")
    }
}

/// The canonical form of `path`, or `path` itself when it cannot be canonicalized
/// (the comparison then falls back to the source hash, which is always present for a
/// child).
fn canonical(path: &Path) -> PathBuf {
    std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf())
}

#[cfg(test)]
mod tests {
    /// A ROOT-LESS compile door refuses a subworkflow stage by name, and admits a
    /// program with none — the refusal is about the construct, not the door.
    #[test]
    fn a_root_less_door_refuses_a_subworkflow_and_nothing_else() {
        let checked = crate::starlark_eval::evaluate_starlark_checked(
            "run_child = subworkflow(id = \"run_child\", pack = \"child\")\n\
             workflow(\"parent\", root = run_child)\n",
            "parent.star",
        )
        .expect("the parent evaluates");
        let error = crate::execution_program::compile_execution_program(&checked)
            .expect_err("a root-less door cannot bind a child")
            .to_string();
        assert!(
            error.contains("subworkflow_unresolvable_without_library")
                && error.contains("\"run_child\"")
                && error.contains("\"child\""),
            "{error}"
        );

        let plain = crate::starlark_eval::evaluate_starlark_checked(
            "only = stage(id = \"only\", agent = \"shell\", run = \":\")\n\
             workflow(\"plain\", root = only)\n",
            "plain.star",
        )
        .expect("the plain pack evaluates");
        crate::execution_program::compile_execution_program(&plain)
            .expect("a program with no subworkflow compiles through a root-less door");
    }
}
