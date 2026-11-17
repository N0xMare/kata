//! Non-executing invocation-plan previews derived from stage topology.
//!
//! This module is the bridge between declarative topology metadata and future
//! runtime child invocations. It deliberately does not dispatch anything: it
//! lowers a checked workflow envelope into an inspectable, serializable preview
//! that can be validated before the runner grows dynamic expansion.

use std::collections::{BTreeMap, BTreeSet};

use kata_types::workflow::{
    AgentRolePolicy, AgentSelector, MutationPolicy, StageDefinition, StageId, StageTopology,
    WorkflowDefinition,
};
use kata_types::{KataError, KataResult};
use serde::{Deserialize, Serialize};
use smol_str::SmolStr;

use crate::parser::CheckedWorkflowDefinition;

/// A whole-workflow preview of the invocation tree each stage would own.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkflowInvocationPlanPreview {
    pub stages: BTreeMap<StageId, StageInvocationPlanPreview>,
}

/// The non-executing invocation shape for one stage.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StageInvocationPlanPreview {
    pub stage_id: StageId,
    pub stage_agent: SmolStr,
    pub topology_kind: SmolStr,
    pub root: InvocationRolePreview,
    pub children: Vec<InvocationRolePreview>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_concurrency: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fanout_limit: Option<u32>,
    pub dynamic_fanout: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mutation_policy: Option<MutationPolicy>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub review_quorum: Option<ReviewQuorumPreview>,
    /// Always true: the plan is a preview. Future runtime execution should add a
    /// separate observed invocation graph rather than mutating this contract.
    pub preview_only: bool,
}

/// Role kind inside a stage-level invocation plan.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InvocationRoleKind {
    Root,
    Worker,
    Reviewer,
    Stage,
}

/// One planned invocation role.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct InvocationRolePreview {
    pub kind: InvocationRoleKind,
    pub role: SmolStr,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent: Option<SmolStr>,
    pub required: bool,
}

/// Review quorum lowered into an inspectable form with reviewer counts.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReviewQuorumPreview {
    pub required: u32,
    pub block_on_any_finding: bool,
    pub count_optional_reviewers: bool,
    pub block_on_optional_findings: bool,
    pub available_reviewers: u32,
    pub required_reviewers: u32,
    pub advisory_reviewers: u32,
}

/// Build a non-executing invocation-plan preview for every checked stage.
pub(crate) fn build_invocation_plan_preview(
    checked: &CheckedWorkflowDefinition,
) -> KataResult<WorkflowInvocationPlanPreview> {
    build_invocation_plan_preview_for_definition(checked.definition())
}

fn build_invocation_plan_preview_for_definition(
    definition: &WorkflowDefinition,
) -> KataResult<WorkflowInvocationPlanPreview> {
    let mut stages = BTreeMap::new();
    for (stage_id, stage) in &definition.stages {
        stages.insert(stage_id.clone(), preview_stage(stage_id, stage)?);
    }
    Ok(WorkflowInvocationPlanPreview { stages })
}

fn preview_stage(
    stage_id: &StageId,
    stage: &StageDefinition,
) -> KataResult<StageInvocationPlanPreview> {
    let stage_agent = format_agent_selector(&stage.agent);
    let Some(topology) = stage.topology.as_ref() else {
        return Ok(StageInvocationPlanPreview {
            stage_id: stage_id.clone(),
            stage_agent: stage_agent.clone(),
            topology_kind: SmolStr::new("direct_stage"),
            root: InvocationRolePreview {
                kind: InvocationRoleKind::Stage,
                role: SmolStr::new("stage"),
                agent: Some(stage_agent),
                required: true,
            },
            children: vec![],
            max_concurrency: Some(1),
            fanout_limit: None,
            dynamic_fanout: false,
            mutation_policy: None,
            review_quorum: None,
            preview_only: true,
        });
    };

    validate_topology(stage_id, topology)?;

    let root = topology.root.as_ref().map_or_else(
        || InvocationRolePreview {
            kind: InvocationRoleKind::Root,
            role: SmolStr::new("root"),
            agent: Some(stage_agent.clone()),
            required: true,
        },
        |role| role_preview(InvocationRoleKind::Root, role),
    );

    let mut children = Vec::with_capacity(topology.workers.len() + topology.reviewers.len());
    children.extend(
        topology
            .workers
            .iter()
            .map(|role| role_preview(InvocationRoleKind::Worker, role)),
    );
    children.extend(
        topology
            .reviewers
            .iter()
            .map(|role| role_preview(InvocationRoleKind::Reviewer, role)),
    );

    let review_quorum = if let Some(quorum) = topology.review_quorum.as_ref() {
        let required_reviewers = count_to_u32(
            stage_id,
            "required reviewer",
            topology
                .reviewers
                .iter()
                .filter(|role| role.required)
                .count(),
        )?;
        let available_reviewers =
            count_to_u32(stage_id, "available reviewer", topology.reviewers.len())?;
        Some(ReviewQuorumPreview {
            required: quorum.required,
            block_on_any_finding: quorum.block_on_any_finding,
            count_optional_reviewers: quorum.count_optional_reviewers,
            block_on_optional_findings: quorum.block_on_optional_findings,
            available_reviewers,
            required_reviewers,
            advisory_reviewers: available_reviewers.saturating_sub(required_reviewers),
        })
    } else {
        None
    };

    Ok(StageInvocationPlanPreview {
        stage_id: stage_id.clone(),
        stage_agent,
        topology_kind: topology.kind.clone(),
        root,
        children,
        max_concurrency: topology.max_concurrency,
        fanout_limit: topology.fanout_limit,
        dynamic_fanout: topology.dynamic_fanout,
        mutation_policy: Some(topology.mutation_policy),
        review_quorum,
        preview_only: true,
    })
}

fn validate_topology(stage_id: &StageId, topology: &StageTopology) -> KataResult<()> {
    if topology.kind.is_empty() {
        return Err(KataError::Validation(format!(
            "stage {} topology.kind must be non-empty",
            stage_id.0
        )));
    }
    if matches!(topology.max_concurrency, Some(0)) {
        return Err(KataError::Validation(format!(
            "stage {} topology.max_concurrency must be >= 1",
            stage_id.0
        )));
    }
    if matches!(topology.fanout_limit, Some(0)) {
        return Err(KataError::Validation(format!(
            "stage {} topology.fanout_limit must be >= 1",
            stage_id.0
        )));
    }
    if let Some(limit) = topology.fanout_limit
        && count_to_u32(stage_id, "worker role", topology.workers.len())? > limit
    {
        return Err(KataError::Validation(format!(
            "stage {} topology.fanout_limit={} is less than worker role count={}",
            stage_id.0,
            limit,
            topology.workers.len()
        )));
    }
    if let Some(limit) = topology.max_concurrency {
        let child_count = topology.workers.len() + topology.reviewers.len();
        if count_to_u32(stage_id, "child role", child_count)? > limit {
            return Err(KataError::Validation(format!(
                "stage {} topology.max_concurrency={} is less than child role count={child_count}",
                stage_id.0, limit
            )));
        }
    }
    if topology.dynamic_fanout && topology.workers.is_empty() && topology.reviewers.is_empty() {
        return Err(KataError::Validation(format!(
            "stage {} topology.dynamic_fanout requires at least one child role",
            stage_id.0
        )));
    }

    let mut seen = BTreeSet::new();
    if let Some(root) = topology.root.as_ref() {
        remember_role(stage_id, &mut seen, "root", root)?;
    }
    for worker in &topology.workers {
        remember_role(stage_id, &mut seen, "worker", worker)?;
    }
    for reviewer in &topology.reviewers {
        remember_role(stage_id, &mut seen, "reviewer", reviewer)?;
    }
    if topology.dynamic_fanout {
        validate_dynamic_fanout_role_prefixes(stage_id, topology)?;
    }

    if let Some(quorum) = topology.review_quorum.as_ref() {
        if quorum.required == 0 {
            return Err(KataError::Validation(format!(
                "stage {} review_quorum.required must be >= 1",
                stage_id.0
            )));
        }
        if topology.reviewers.is_empty() {
            return Err(KataError::Validation(format!(
                "stage {} review_quorum requires at least one reviewer role",
                stage_id.0
            )));
        }
        let eligible_reviewers = if quorum.count_optional_reviewers {
            count_to_u32(stage_id, "eligible reviewer", topology.reviewers.len())?
        } else {
            count_to_u32(
                stage_id,
                "eligible required reviewer",
                topology
                    .reviewers
                    .iter()
                    .filter(|role| role.required)
                    .count(),
            )?
        };
        if quorum.required > eligible_reviewers {
            let reviewer_kind = if quorum.count_optional_reviewers {
                "reviewer"
            } else {
                "required reviewer"
            };
            return Err(KataError::Validation(format!(
                "stage {} review_quorum.required={} exceeds {reviewer_kind} count={eligible_reviewers}",
                stage_id.0, quorum.required
            )));
        }
    }

    Ok(())
}

fn validate_dynamic_fanout_role_prefixes(
    stage_id: &StageId,
    topology: &StageTopology,
) -> KataResult<()> {
    let roles = topology
        .workers
        .iter()
        .chain(topology.reviewers.iter())
        .map(|role| role.role.as_str())
        .collect::<Vec<_>>();
    for (idx, left) in roles.iter().enumerate() {
        for right in roles.iter().skip(idx + 1) {
            if dynamic_child_role_prefix_collision(left, right) {
                return Err(KataError::Validation(format!(
                    "stage {} topology.dynamic_fanout child roles {:?} and {:?} are ambiguous because runtime child names use '<role>-<id>' suffixes",
                    stage_id.0, left, right
                )));
            }
        }
    }
    Ok(())
}

fn dynamic_child_role_prefix_collision(left: &str, right: &str) -> bool {
    left.strip_prefix(right)
        .is_some_and(|suffix| suffix.starts_with('-'))
        || right
            .strip_prefix(left)
            .is_some_and(|suffix| suffix.starts_with('-'))
}

fn remember_role(
    stage_id: &StageId,
    seen: &mut BTreeSet<SmolStr>,
    group: &str,
    role: &AgentRolePolicy,
) -> KataResult<()> {
    if role.role.is_empty() {
        return Err(KataError::Validation(format!(
            "stage {} topology {group} role must be non-empty",
            stage_id.0
        )));
    }
    if !seen.insert(role.role.clone()) {
        return Err(KataError::Validation(format!(
            "stage {} topology role {} is declared more than once",
            stage_id.0, role.role
        )));
    }
    Ok(())
}

fn count_to_u32(stage_id: &StageId, label: &str, count: usize) -> KataResult<u32> {
    u32::try_from(count).map_err(|_| {
        KataError::Validation(format!(
            "stage {} {label} count={count} exceeds u32::MAX",
            stage_id.0
        ))
    })
}

fn role_preview(kind: InvocationRoleKind, role: &AgentRolePolicy) -> InvocationRolePreview {
    InvocationRolePreview {
        kind,
        role: role.role.clone(),
        agent: role.agent.clone(),
        required: role.required,
    }
}

fn format_agent_selector(agent: &AgentSelector) -> SmolStr {
    match agent {
        AgentSelector::Backend(backend) => SmolStr::new(backend.label()),
        AgentSelector::Labelled(label) => label.clone(),
        AgentSelector::Any => SmolStr::new("any"),
        // The preview identity is the panel's PRIMARY (first) member,
        // matching `op.agent`; the full panel rides on `op.agent_panel`.
        AgentSelector::Panel(members) => members
            .first()
            .cloned()
            .unwrap_or_else(|| SmolStr::new("any")),
    }
}
