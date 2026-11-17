//! WHICH `/work` head a stage reads and advances: the
//! stack of `parallel()` branches enclosing it, outermost first, spelled as a
//! [`kata_types::work_tree_head::WorkTreeHeadCoordinate`].
//!
//! # The rule
//!
//! Every capsule stage's `/work` maps the `execution_work_tree_heads` row at
//! exactly this coordinate — the row is forked lazily at the branch's first
//! submit and advanced by that branch's applies — and a barrier stage's join
//! fans the rows at `coordinate.pushed(join, exit)` back into the row at the
//! barrier's own coordinate.
//!
//! Stage `S` sits inside barrier `J`'s branch `E` — `E` one of `J`'s
//! `depends_on` exits — when BOTH hold:
//!
//! * **Private ancestor**: `S` is `E` or an ancestor of `E`, and of NO sibling
//!   exit of `J`. A stage feeding two exits of one barrier is the shared
//!   trunk the branches fork from — not a member of either.
//! * **No escape**: every stage that depends on `S` stays inside the branch or
//!   past its barrier — each descendant of `S` is an ancestor-or-self of `E`
//!   or a descendant-or-self of `J`. The one shape this rules out is a stage
//!   REUSED as a later barrier's input (an earlier `parallel()`'s exit named
//!   in a second `parallel()` call): its descendants include the later
//!   barrier's branch stages, which neither side of the union covers. Such a
//!   stage ran under its true (enclosing) coordinate, and the later barrier's
//!   fan-in takes its contribution through the ambient comparison, not a
//!   branch row.
//!
//! The two rules make membership exact: a stage is enclosed by a fork or it is
//! not, with no silent trunk fallback for a shape that would have read a
//! second head.
//!
//! # Ordering and the refused set
//!
//! Nested `parallel()` composes: an inner barrier's own coordinate is the
//! outer branch it sits in, so `S`'s forks form a CHAIN — each inner barrier
//! an ancestor of the enclosing branch's exit. [`WORK_HEAD_COORDINATE_AMBIGUOUS`]
//! refuses the one shape that is not a chain: two forks whose barriers sit in
//! incomparable regions (a stage private to a branch of EACH of two unrelated
//! barriers). `register_parallel` does not mint that shape; the refusal is the
//! door nothing else closes.
use std::collections::{BTreeMap, BTreeSet};

use kata_types::error::{KataError, KataResult};
use kata_types::work_tree_head::WorkTreeHeadCoordinate;
use kata_types::workflow::{StageId, SynthesizedStage};

use super::types::ExecutionProgram;

/// The refusal [`work_head_coordinate`] answers when two `parallel()` forks
/// enclose one stage and neither barrier's region contains the other — the
/// stage would have to run inside two unrelated branches, which are two
/// different heads.
pub const WORK_HEAD_COORDINATE_AMBIGUOUS: &str = "work_head_coordinate_ambiguous";

/// The stage's `/work` head coordinate — the stack of enclosing `parallel()`
/// forks, outermost first. `WorkTreeHeadCoordinate::root()` for a stage no
/// barrier encloses.
///
/// # Errors
///
/// [`WORK_HEAD_COORDINATE_AMBIGUOUS`] for the incomparable-forks shape above;
/// `Validation` for a `stage` the program does not carry.
pub fn work_head_coordinate(
    program: &ExecutionProgram,
    stage: &StageId,
) -> KataResult<WorkTreeHeadCoordinate> {
    if !program.stages.contains_key(stage) {
        return Err(KataError::Validation(format!(
            "{WORK_HEAD_COORDINATE_AMBIGUOUS}: stage {} is no stage of program {} — \
             a /work coordinate exists only for a stage the checked program carries",
            stage.0, program.workflow_name,
        )));
    }
    let reach = Reach::of(program);
    // Every fork (barrier, exit) whose branch region contains `stage`.
    let mut forks: Vec<(StageId, StageId)> = Vec::new();
    for (join, join_stage) in &program.stages {
        if join_stage.synthesized != Some(SynthesizedStage::ParallelJoin) {
            continue;
        }
        for exit in &join_stage.depends_on {
            if reach.encloses(join, exit, &join_stage.depends_on, stage) {
                forks.push((join.clone(), exit.clone()));
            }
        }
    }
    // Order outermost-first: the outer fork's region contains every inner
    // barrier, so peel off the fork whose exit's ancestors hold ALL remaining
    // joins. No such fork means two regions claim the stage incomparably.
    let mut coordinate = WorkTreeHeadCoordinate::root();
    while !forks.is_empty() {
        let Some(pos) = forks.iter().position(|(join, exit)| {
            forks
                .iter()
                .all(|(other, _)| other == join || reach.ancestors(exit).contains(other))
        }) else {
            let spellings = forks
                .iter()
                .map(|(join, exit)| format!("({},{})", join.0, exit.0))
                .collect::<Vec<_>>()
                .join(", ");
            return Err(KataError::Validation(format!(
                "{WORK_HEAD_COORDINATE_AMBIGUOUS}: stage {} is enclosed by forks {spellings} \
                 and no one of them contains the others — a stage runs inside exactly one branch \
                 chain, and this program's `parallel()` barriers leave it in incomparable regions",
                stage.0
            )));
        };
        let (join, exit) = forks.remove(pos);
        coordinate = coordinate.pushed(join.0.as_str(), exit.0.as_str());
    }
    Ok(coordinate)
}

/// The `/work` head a stage EXPANSION's settle lands on, and the branch every
/// member of it maps — or `None` when `path` names no stage
/// expansion of `program`.
///
/// A static `topology(..)` stage's expansion sits at the stage's own coordinate
/// `[i]`; its members are `/work` BRANCHES of the stage's head exactly as
/// `parallel()` branches are of a barrier's: member `m` (durable spelling
/// `member_stage`) maps `work_head_coordinate(stage).pushed(<the expansion's
/// #op/<path>>, member_stage)`, every member of one expansion forks at one
/// point, and the expansion's resolving transaction merges the branches back
/// onto the stage's head (`OperationalDb::resolve_expansion_attempt_merging`).
///
/// # Errors
///
/// [`work_head_coordinate`]'s, for the expansion's stage.
pub fn expansion_work_head_coordinate(
    program: &ExecutionProgram,
    path: &kata_types::execution_contract::OperationPath,
) -> KataResult<Option<WorkTreeHeadCoordinate>> {
    Ok(expansion_settle_head(program, path)?.map(|(_, head)| head))
}

/// [`expansion_work_head_coordinate`] together with the AUTHORED stage whose head
/// it is — the topology stage itself, or the loop member stage a nested topology
/// runs as — which the settle's `#apply/<stage>` spelling names.
///
/// # Errors
///
/// [`work_head_coordinate`]'s, for that stage.
pub fn expansion_settle_head(
    program: &ExecutionProgram,
    path: &kata_types::execution_contract::OperationPath,
) -> KataResult<Option<(StageId, WorkTreeHeadCoordinate)>> {
    let stage = match super::program_operation_at(program, path) {
        Some(super::ProgramOperationAt::Expansion(
            super::ExpansionKind::Topology(index) | super::ExpansionKind::DynamicFanout(index),
        )) => program.stages.keys().nth(index),
        // A topology nested in a loop settles onto the LOOP MEMBER's head
        // — the coordinate the member stage's iterations advance one after
        // another.
        Some(super::ProgramOperationAt::Expansion(super::ExpansionKind::LoopMemberTopology {
            loop_index,
            member,
            ..
        })) => super::operation_lowering::loop_member_stage(program, loop_index, member)
            .map(|stage| &stage.stage_id),
        _ => None,
    };
    let Some(stage) = stage else {
        return Ok(None);
    };
    Ok(Some((stage.clone(), work_head_coordinate(program, stage)?)))
}

/// The `/work` BRANCH a stage-expansion member at `member_path` maps, under its
/// durable stage spelling `member_stage` — see [`expansion_work_head_coordinate`]
/// — or `None` when `member_path`'s parent is no stage expansion (a plain stage,
/// a review-loop member, a program operation). A RETRY seat
/// `seat.child(k)` — whose parent is a capsule seat, never an expansion — maps
/// its seat's branch, so a topology root's retry writes the branch its attempt
/// 0 did.
///
/// # Errors
///
/// [`work_head_coordinate`]'s, for the expansion's stage.
pub fn expansion_member_work_coordinate(
    program: &ExecutionProgram,
    member_path: &kata_types::execution_contract::OperationPath,
    member_stage: &str,
) -> KataResult<Option<WorkTreeHeadCoordinate>> {
    let Some((_, parent)) = member_path.0.split_last() else {
        return Ok(None);
    };
    let expansion = kata_types::execution_contract::OperationPath(parent.to_vec());
    if let Some(head) = expansion_work_head_coordinate(program, &expansion)? {
        return Ok(Some(
            head.pushed(expansion.program_operation_stage_id(), member_stage),
        ));
    }
    let Some((_, grandparent)) = parent.split_last() else {
        return Ok(None);
    };
    let seat_expansion = kata_types::execution_contract::OperationPath(grandparent.to_vec());
    Ok(expansion_work_head_coordinate(program, &seat_expansion)?
        .map(|head| head.pushed(seat_expansion.program_operation_stage_id(), member_stage)))
}

/// Inclusive ancestor and descendant sets over `depends_on`, one computation
/// shared by every fork question a coordinate answers.
struct Reach<'a> {
    /// `ancestors[x]` = `x` plus every stage `x` transitively depends on.
    ancestors: BTreeMap<&'a StageId, BTreeSet<&'a StageId>>,
    /// `descendants[x]` = `x` plus every stage that transitively depends on `x`.
    descendants: BTreeMap<&'a StageId, BTreeSet<&'a StageId>>,
}

impl<'a> Reach<'a> {
    fn of(program: &'a ExecutionProgram) -> Self {
        // Edges once: stage -> the stages it depends on, and the reverse.
        let mut down_edges: BTreeMap<&StageId, Vec<&StageId>> = BTreeMap::new();
        for (id, stage) in &program.stages {
            for dependency in &stage.depends_on {
                down_edges.entry(dependency).or_default().push(id);
            }
        }
        let mut ancestors: BTreeMap<&StageId, BTreeSet<&StageId>> = BTreeMap::new();
        let mut descendants: BTreeMap<&StageId, BTreeSet<&StageId>> = BTreeMap::new();
        for id in program.stages.keys() {
            let mut up = BTreeSet::from([id]);
            let mut frontier: Vec<&StageId> = program.stages[id].depends_on.iter().collect();
            while let Some(next) = frontier.pop() {
                if up.insert(next) {
                    frontier.extend(
                        program
                            .stages
                            .get(next)
                            .map(|stage| stage.depends_on.iter().collect::<Vec<_>>())
                            .unwrap_or_default(),
                    );
                }
            }
            let mut down = BTreeSet::from([id]);
            let mut frontier: Vec<&StageId> = down_edges.get(id).cloned().unwrap_or_default();
            while let Some(next) = frontier.pop() {
                if down.insert(next) {
                    frontier.extend(down_edges.get(next).cloned().unwrap_or_default());
                }
            }
            ancestors.insert(id, up);
            descendants.insert(id, down);
        }
        Self {
            ancestors,
            descendants,
        }
    }

    fn ancestors(&self, stage: &StageId) -> &BTreeSet<&'a StageId> {
        self.ancestors
            .get(stage)
            .expect("every stage of the program has a reach row")
    }

    /// Whether barrier `join`'s branch `exit` encloses `stage`: private
    /// ancestor, and no descendant escaping the branch except through `exit`
    /// or past `join` — the module doc's two rules.
    fn encloses(
        &self,
        join: &StageId,
        exit: &StageId,
        siblings: &[StageId],
        stage: &StageId,
    ) -> bool {
        if !self.ancestors(exit).contains(&stage) {
            return false;
        }
        if siblings
            .iter()
            .any(|sibling| sibling != exit && self.ancestors(sibling).contains(&stage))
        {
            return false;
        }
        let branch = self.ancestors(exit);
        let past_barrier = self
            .descendants
            .get(join)
            .expect("every stage of the program has a reach row");
        self.descendants
            .get(stage)
            .expect("every stage of the program has a reach row")
            .iter()
            .all(|descendant| branch.contains(descendant) || past_barrier.contains(descendant))
    }
}
