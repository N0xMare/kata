//! The `parallel()` fan-in merge: when a barrier stage's
//! join resolves, the `/work` the branches produced is folded back into the
//! head the barrier's own coordinate names, IN the join's one claim-and-resolve
//! transaction.
//!
//! # The merge
//!
//! Every branch of the barrier forked at ONE point — the first sibling row's
//! `fork_base_artifact_id`, frozen the moment the branch's first capsule was
//! dispatched — so each input's contribution is the content difference
//! `TreeDelta::between(fork_base, branch_head)`, independent of how far the
//! parent head has moved since. Those deltas merge by [`TreeDelta::merge`]:
//! disjoint paths union, identical changes collapse, and two branches touching
//! one path differently is a `work_fanin_conflict` — recorded as the join
//! attempt's `failed` resolution, never a partial land.
//!
//! The parent head's OWN movement since the fork is the ambient input: a path
//! a branch changed that the parent ALSO changed differently is contested just
//! as branch-vs-branch — the join's stage wrote nothing, but a sibling branch
//! of an OUTER barrier could have advanced the same head between fork and
//! join. Ambient changes to paths no branch touched are simply already in the
//! parent manifest the union folds onto.
//!
//! # What the merge produces
//!
//! The surviving artifact is the APPLY delta — `between(parent_head, merged)`:
//! the union expressed as changes over the head's CURRENT artifact, so the
//! `#apply/<join>` sweep's stale-base check compares it against exactly the
//! row it will advance. The join's accepted output carries its artifact id,
//! which puts the apply on the same two-phase attempt, the same
//! candidate-fence/jj-vs-CAS legs, and the same successor gate every other
//! `/work` apply takes. A merge producing the parent's own tree declares no
//! delta and drives no apply — the head is already the union.

use kata_types::error::{KataError, KataResult};
use kata_types::execution_contract::ArtifactRef;
use kata_types::primitives::ObjectId;
use kata_types::tree_artifact::{TreeEntry, TreeManifest, TreeNode, TreePath};
use kata_types::tree_delta::{BranchLabel, TreeChangeKind, TreeDelta, TreeDeltaMergeConflict};
use kata_types::work_tree_head::WorkTreeHeadCoordinate;
use rusqlite::Transaction;
use smol_str::SmolStr;
use ulid::Ulid;

use super::OperationalDb;
use super::artifacts::declare_artifact_in_tx;
use super::records::CasRootOwner;
use super::work_tree_head::{ensure_head_in_tx, read_head_in_tx_pub};

/// The typed refusal a `parallel()` join resolves `failed` with when its
/// branches' `/work` deltas cannot merge — the recorded reason names every
/// contested path and the branches that touched it.
pub const WORK_FANIN_CONFLICT: &str = "work_fanin_conflict";

/// The merge label the parent head's own movement carries in a conflict
/// report — not a stage id, so it cannot be mistaken for one.
const AMBIENT_LABEL: &str = "<the parent head>";

/// One input to a barrier's fan-in: the occurrence whose acceptance the join
/// precondition requires, the head coordinate its branch's stages advanced,
/// and the label (its exit stage's id) a conflict report names it by.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct JoinFanInInput {
    /// The input's occurrence id — the join waits on its acceptance.
    pub occurrence: [u8; 32],
    /// The input stage's own coordinate — `parent.pushed(join, exit)`: the
    /// head row the branch's applies advanced. An input that resolves to the
    /// parent's own coordinate contributes through the ambient comparison
    /// instead.
    pub branch: WorkTreeHeadCoordinate,
    /// The exit stage's id — the `BranchLabel` a conflict report shows.
    pub label: String,
}

/// What a barrier stage's [`OperationalDb::resolve_join`] must merge: which
/// head the union lands on, and which heads the inputs read.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct JoinFanIn {
    /// The barrier stage's own coordinate — the head the merged delta applies
    /// to, and the fork parent every input's row was taken from.
    pub parent: WorkTreeHeadCoordinate,
    /// One entry per join input, in the join's declared order.
    pub inputs: Vec<JoinFanInInput>,
}

impl JoinFanIn {
    /// The occurrences the join's precondition requires accepted, in order.
    pub fn occurrences(&self) -> Vec<[u8; 32]> {
        self.inputs.iter().map(|input| input.occurrence).collect()
    }
}

/// What the fan-in merge computed, inside the join's transaction.
pub(super) enum FanInMerge {
    /// The union is the parent's own tree — the join resolves `completed`
    /// with no `work_delta_artifact_id`, and no `#apply/<join>` ever runs.
    Unchanged,
    /// The merged delta — base the parent head's CURRENT artifact — was
    /// published to CAS and declared `kind='tree_delta'` inside the join's
    /// transaction; the join's output carries it and the apply sweep lands it.
    Delta {
        /// The declared `tree_delta` artifact's id.
        artifact_id: [u8; 32],
    },
    /// The merge is contested: the join's claim resolves `failed` with this
    /// reason (`work_fanin_conflict: …`) in the same transaction — the parent
    /// head and any jj workspace are untouched.
    Conflicted {
        /// The recorded failure reason.
        reason: String,
    },
}

/// RUN the merge for barrier `join_stage` of `execution_id` on the caller's
/// writer transaction: ensure the branch rows, compute the per-branch deltas
/// off the frozen fork base, merge them, hold the union against the parent
/// head's ambient movement, and publish the apply delta.
///
/// # Errors
///
/// `Storage` for a missing CAS binding, a dropped artifact row, or bytes that
/// do not decode — all plane faults, never a merge verdict; `Validation` for a
/// fork-base disagreement between siblings or a `merge`/`between` refusal,
/// which are corruption rather than conflict (a conflict is DATA, and returns
/// [`FanInMerge::Conflicted`] for the caller to record, not an `Err`).
pub(super) fn merge_fan_in_in_tx(
    db: &OperationalDb,
    tx: &Transaction<'_>,
    execution_id: Ulid,
    join_stage: &str,
    fanin: &JoinFanIn,
) -> KataResult<FanInMerge> {
    // An execution with NO root head has no /work state at all: no capsule
    // could have mapped `/work` (its submit refuses an unrecorded head), so no
    // branch head exists either — the fork chain cannot reach a row the root
    // is missing — and the merge is vacuous. The head the union would land on
    // is simply absent, and `Unchanged` is exactly that answer.
    let Some(_) = read_head_in_tx_pub(tx, execution_id, "")? else {
        return Ok(FanInMerge::Unchanged);
    };
    let cas = db.output_cas().ok_or_else(|| {
        KataError::Storage(format!(
            "join {join_stage}'s fan-in needs the node's content store and this operational db \
             has none bound — a /work head cannot exist without one"
        ))
    })?;
    let parent_head = ensure_head_in_tx(tx, execution_id, &fanin.parent)?;
    let parent_spelling = fanin.parent.spelling();

    // Read every input's branch head — `ensure` rather than `read`, so a
    // branch whose stages published no /work change still answers (a row forked
    // at the current fork base contributes an empty delta, never a refusal).
    struct BranchHead {
        label: SmolStr,
        fork_base: [u8; 32],
        artifact: [u8; 32],
    }
    let mut branches: Vec<BranchHead> = Vec::with_capacity(fanin.inputs.len());
    for input in &fanin.inputs {
        let spelling = input.branch.spelling();
        if spelling == parent_spelling {
            // A stage at the barrier's own coordinate wrote to the parent head
            // directly; its delta is already inside the ambient comparison.
            continue;
        }
        // The plan's shape, checked rather than assumed: an input's head is a
        // CHILD of the parent coordinate forked by THIS barrier — anything else
        // names a head this join does not own the merge of, and no row is forked
        // for it.
        let child = input.branch.innermost();
        if input.branch.parent().as_ref() != Some(&fanin.parent)
            || child.is_none_or(|fork| fork.join != join_stage)
        {
            return Err(KataError::Validation(format!(
                "join {join_stage}'s input {:?} carries branch coordinate {spelling:?}, which \
                 is neither the barrier's own coordinate {parent_spelling:?} (the ambient arm) \
                 nor a child forked by this barrier — a fan-in merges only the heads its own \
                 barrier's branches advanced",
                input.label,
            )));
        }
        let head = ensure_head_in_tx(tx, execution_id, &input.branch)?;
        let fork_base = head.fork_base_artifact_id.ok_or_else(|| {
            KataError::Storage(format!(
                "join {join_stage}'s input {:?} reads a head row at {spelling:?} with no \
                 fork_base_artifact_id — only the root head has none, and this coordinate is a \
                 branch",
                input.label,
            ))
        })?;
        branches.push(BranchHead {
            label: SmolStr::new(input.label.as_str()),
            fork_base,
            artifact: head.work_tree_artifact_id,
        });
    }

    // ONE fork point per barrier: the first row's pinned base is every
    // sibling's; a second value under one (parent, join) pair is a stored
    // divergence no merge can average — refuse by name rather than pick.
    let fork_base = branches
        .first()
        .map_or(parent_head.work_tree_artifact_id, |branch| branch.fork_base);
    if let Some(other) = branches.iter().find(|branch| branch.fork_base != fork_base) {
        return Err(KataError::Storage(format!(
            "join {join_stage}'s branches record two fork bases — {:?} and {} — under one \
             barrier; the fork is one point by construction, so a second value is a plane \
             divergence",
            other.label,
            hex::encode(other.fork_base),
        )));
    }

    let (fork_ref, fork_manifest) = manifest_in_tx(tx, cas, fork_base)?;
    let (parent_ref, parent_manifest) = manifest_in_tx(tx, cas, parent_head.work_tree_artifact_id)?;

    let mut deltas: Vec<(BranchLabel, TreeDelta)> = Vec::with_capacity(branches.len());
    for branch in &branches {
        let (_, manifest) = manifest_in_tx(tx, cas, branch.artifact)?;
        deltas.push((
            branch.label.clone(),
            TreeDelta::between(fork_ref.clone(), &fork_manifest, &manifest)?,
        ));
    }
    let delta_refs: Vec<(BranchLabel, &TreeDelta)> = deltas
        .iter()
        .map(|(label, delta)| (label.clone(), delta))
        .collect();
    let merged = match TreeDelta::merge(&fork_ref, &fork_manifest, &delta_refs)? {
        Ok(merged) => merged,
        Err(conflict) => {
            return Ok(FanInMerge::Conflicted {
                reason: conflict_reason(join_stage, &conflict),
            });
        }
    };

    // AMBIENT: the parent head moved since the fork only where a stage at its
    // own coordinate applied. A path a branch changed that the parent also
    // changed DIFFERENTLY is contested by the same rule as branch-vs-branch;
    // paths only the parent touched are already what the union folds onto.
    let mut contested: Vec<(TreePath, Vec<BranchLabel>)> = Vec::new();
    if parent_head.work_tree_artifact_id != fork_base {
        let ambient = TreeDelta::between(fork_ref.clone(), &fork_manifest, &parent_manifest)?;
        for change in merged.changes() {
            let Some(ambient_change) = ambient
                .changes()
                .iter()
                .find(|ambient| ambient.path == change.path)
            else {
                continue;
            };
            if ambient_change.change == change.change {
                continue;
            }
            let mut labels: Vec<BranchLabel> = deltas
                .iter()
                .filter(|(_, delta)| delta.changes().iter().any(|c| c.path == change.path))
                .map(|(label, _)| label.clone())
                .collect();
            labels.push(SmolStr::new(AMBIENT_LABEL));
            labels.sort();
            labels.dedup();
            contested.push((change.path.clone(), labels));
        }
        if !contested.is_empty() {
            return Ok(FanInMerge::Conflicted {
                reason: conflict_reason(
                    join_stage,
                    &TreeDeltaMergeConflict {
                        paths: contested,
                        structural: None,
                    },
                ),
            });
        }
    }

    // Fold the union onto the parent's CURRENT manifest — lenient per path
    // (the strictness a delta needs against a stale base, `apply`'s refusals,
    // was already decided: ambient overlap is contested above, and the union
    // was validated against the fork base by `merge`).
    let mut nodes: std::collections::BTreeMap<TreePath, TreeNode> = parent_manifest
        .entries()
        .iter()
        .map(|entry| (entry.path.clone(), entry.node.clone()))
        .collect();
    for change in merged.changes() {
        match &change.change {
            TreeChangeKind::Write { node } => {
                nodes.insert(change.path.clone(), node.clone());
            }
            TreeChangeKind::Delete => {
                nodes.remove(&change.path);
            }
        }
    }
    let union = match TreeManifest::new(
        nodes
            .into_iter()
            .map(|(path, node)| TreeEntry { path, node })
            .collect(),
    ) {
        Ok(union) => union,
        Err(error) => {
            // AMBIENT structural conflict: the per-path checks compare equal
            // paths only, so a parent-side FILE at `x` folding against a
            // branch's `x/y` reaches here — `TreeManifest::new` refuses the
            // impossible union. A merge conflict is a recorded verdict, never
            // an `Err`: name both sides (the ambient path carries
            // `AMBIENT_LABEL`, the branch path its writers) through the same
            // door the sibling conflicts take.
            return Ok(FanInMerge::Conflicted {
                reason: conflict_reason(
                    join_stage,
                    &TreeDeltaMergeConflict {
                        paths: ambient_structural_pairs(&parent_manifest, &merged, &deltas),
                        structural: Some(error.to_string()),
                    },
                ),
            });
        }
    };
    let apply_delta = TreeDelta::between(parent_ref, &parent_manifest, &union)?;
    if apply_delta.changes().is_empty() {
        return Ok(FanInMerge::Unchanged);
    }
    let bytes = apply_delta.delta_bytes()?;
    let durable = cas.put_durable(&bytes)?;
    let declaration = super::artifacts::ArtifactDeclaration::for_durable_delta(
        &apply_delta,
        kata_types::execution_contract::ArtifactPrivacy::Private,
        CasRootOwner::Execution(execution_id),
        &durable,
    )?;
    declare_artifact_in_tx(tx, &declaration, super::now_ms())?;
    Ok(FanInMerge::Delta {
        artifact_id: declaration.artifact_id(),
    })
}

/// The ambient-structural pairs a union-fold refusal names: for each merged
/// write, every prefix of its path the PARENT manifest carries as an entry
/// (a file at `x` vs the branch's `x/y`) and every parent entry beneath the
/// written path (`x/…` vs the branch's file `x`). The ambient side carries
/// [`AMBIENT_LABEL`]; the branch side carries its writers.
fn ambient_structural_pairs(
    parent_manifest: &TreeManifest,
    merged: &TreeDelta,
    deltas: &[(BranchLabel, TreeDelta)],
) -> Vec<(TreePath, Vec<BranchLabel>)> {
    let mut pairs: Vec<(TreePath, Vec<BranchLabel>)> = Vec::new();
    let mut push = |path: &TreePath, labels: Vec<BranchLabel>| {
        if !pairs.iter().any(|(p, _)| p == path) {
            pairs.push((path.clone(), labels));
        }
    };
    for change in merged.changes() {
        if !matches!(change.change, TreeChangeKind::Write { .. }) {
            continue;
        }
        let path = change.path.as_str();
        let writers: Vec<BranchLabel> = deltas
            .iter()
            .filter(|(_, delta)| delta.changes().iter().any(|c| c.path == change.path))
            .map(|(label, _)| label.clone())
            .collect();
        // An ancestor the parent holds — `x` is an entry while `x/y` is
        // written: file-vs-descendant, the union cannot hold both.
        for (offset, _) in path.char_indices().filter(|(_, byte)| *byte == '/') {
            let prefix = &path[..offset];
            if parent_manifest
                .entries()
                .iter()
                .any(|entry| entry.path.as_str() == prefix)
            {
                if let Ok(tp) = TreePath::new(prefix) {
                    push(&tp, vec![SmolStr::new(AMBIENT_LABEL)]);
                }
                push(&change.path, writers.clone());
            }
        }
        // A descendant the parent holds — `x/…` is an entry while `x` is
        // written: the symmetric direction.
        for entry in parent_manifest.entries() {
            if entry.path.as_str().starts_with(&format!("{path}/")) {
                push(&change.path, writers.clone());
                push(&entry.path, vec![SmolStr::new(AMBIENT_LABEL)]);
            }
        }
    }
    pairs.sort_by(|a, b| a.0.as_str().cmp(b.0.as_str()));
    pairs
}

/// The `work_fanin_conflict` reason — the token first, then every contested
/// path and the branches that touched it, then the structural verdict when the
/// per-path merge was clean but the union is impossible.
fn conflict_reason(join_stage: &str, conflict: &TreeDeltaMergeConflict) -> String {
    let paths = conflict
        .paths
        .iter()
        .map(|(path, labels)| {
            format!(
                "{path:?} touched by [{}]",
                labels
                    .iter()
                    .map(BranchLabel::as_str)
                    .collect::<Vec<_>>()
                    .join(", ")
            )
        })
        .collect::<Vec<_>>()
        .join("; ");
    match &conflict.structural {
        Some(structural) => format!(
            "{WORK_FANIN_CONFLICT}: join {join_stage}'s branches cannot merge — contested: \
             {paths}; structural: {structural}"
        ),
        None => format!(
            "{WORK_FANIN_CONFLICT}: join {join_stage}'s branches cannot merge — contested: \
             {paths}"
        ),
    }
}

/// Read one `kind='tree'` artifact's manifest inside the caller's transaction —
/// the row's own `object_id`/`size_bytes` bound the verified CAS read, so the
/// merge's base, branch and parent manifests are the content the head rows
/// name, not a re-walk.
fn manifest_in_tx(
    tx: &Transaction<'_>,
    cas: &crate::store::cas::CasStore,
    artifact_id: [u8; 32],
) -> KataResult<(ArtifactRef, TreeManifest)> {
    let row = super::artifacts::read_artifact(tx, artifact_id)?.ok_or_else(|| {
        KataError::Storage(format!(
            "a /work head names artifact {} and the artifacts row is gone — the head's \
             ON DELETE NO ACTION foreign key is exactly the refusal to be here",
            hex::encode(artifact_id),
        ))
    })?;
    let bytes = cas.get_verified(
        &ObjectId::new(row.object_id),
        row.size_bytes,
        TreeManifest::MAXIMUM_ENCODED_BYTES,
    )?;
    let manifest: TreeManifest = serde_json::from_slice(&bytes).map_err(|error| {
        KataError::Storage(format!(
            "the /work head's recorded manifest {} does not decode: {error}",
            hex::encode(artifact_id),
        ))
    })?;
    let reference = ArtifactRef::new(ObjectId::new(row.object_id), row.size_bytes, row.privacy);
    if reference.id().0.0 != artifact_id {
        return Err(KataError::Storage(format!(
            "the stored artifacts row for {} re-derives artifact id {} — the row is \
             corrupt, not divergent",
            hex::encode(artifact_id),
            hex::encode(reference.id().0.0),
        )));
    }
    Ok((reference, manifest))
}
