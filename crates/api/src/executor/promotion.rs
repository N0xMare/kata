//! Workspace promotion / parking summaries.

use kata_effects_contract::PromotedWorkspace;
use kata_types::execution::{ExecutionRecord, ExecutionStatus};
use kata_types::workspace_awareness::{
    ExecutionWorkspaceParking, ExecutionWorkspacePromotion, ExecutionWorkspaceWorktree,
};

use super::ValidationCriteriaGate;

pub(super) fn execution_workspace_promotion_summary(
    record: &ExecutionRecord,
    provider_attached: bool,
    promotion_snapshots_dirty: bool,
    worktree: Option<&ExecutionWorkspaceWorktree>,
    validation_gate: &ValidationCriteriaGate,
) -> ExecutionWorkspacePromotion {
    let mut blockers = Vec::new();
    if record.evidence.parked_candidate.is_some() {
        blockers.push("already_parked".to_string());
    }
    if !provider_attached {
        blockers.push("no_workspace_provider".to_string());
    }
    if let Some(worktree) = worktree {
        if !worktree.exists {
            blockers.push("worktree_missing".to_string());
        }
    } else if provider_attached {
        blockers.push("worktree_not_registered".to_string());
    }
    if record.status != ExecutionStatus::Completed {
        blockers.push("execution_not_completed".to_string());
    }
    if validation_gate.active && !validation_gate.passed {
        blockers.push("validation_criteria_not_satisfied".to_string());
        blockers.extend(validation_gate.blockers.iter().cloned());
    } else if !validation_gate.active {
        blockers.push("validation_criteria_missing".to_string());
    }
    let dirty = worktree.and_then(|worktree| worktree.dirty);
    let available = provider_attached
        && worktree.is_some_and(|worktree| worktree.exists)
        && record.status == ExecutionStatus::Completed
        && record.evidence.parked_candidate.is_none();
    let policy_satisfied = validation_gate.active && validation_gate.passed;
    let dirty_promotable =
        dirty == Some(false) || (dirty == Some(true) && promotion_snapshots_dirty);
    let safe_to_promote = available && dirty_promotable && policy_satisfied;
    let (status, reason) = if safe_to_promote && dirty == Some(true) {
        (
            "ready_dirty_snapshot",
            Some("worktree has uncommitted changed paths; promotion will snapshot them before merging".to_string()),
        )
    } else if safe_to_promote {
        ("ready", None)
    } else if available && !validation_gate.active {
        (
            "validation_criteria_missing",
            Some(
                "promotion requires at least one required validation criterion declared by the checked ExecutionProgram"
                    .to_string(),
            ),
        )
    } else if available && !policy_satisfied {
        (
            "validation_criteria_blocked",
            validation_gate.reason.clone().or_else(|| {
                Some("required validation criteria have not passed or been waived".to_string())
            }),
        )
    } else if available && dirty == Some(true) {
        (
            "dirty_worktree",
            Some(
                "worktree has uncommitted changed paths; this provider does not snapshot dirty state before promotion"
                    .to_string(),
            ),
        )
    } else if available {
        (
            "status_unavailable",
            Some("worktree changed-path status could not be computed".to_string()),
        )
    } else {
        (
            "blocked",
            Some(format!("promotion blocked by {}", blockers.join(", "))),
        )
    };

    ExecutionWorkspacePromotion {
        available,
        safe_to_promote,
        status: status.to_string(),
        blockers,
        reason,
        promoted_ref: None,
        promoted_commit_sha: None,
        identity: worktree.and_then(|worktree| worktree.identity.clone()),
    }
}

pub(super) fn promotion_with_promoted_workspace(
    mut promotion: ExecutionWorkspacePromotion,
    promoted: &PromotedWorkspace,
) -> ExecutionWorkspacePromotion {
    promotion.available = false;
    promotion.safe_to_promote = false;
    promotion.status = "promoted".to_string();
    promotion.blockers.clear();
    promotion.reason = Some(format!(
        "workspace promoted to {} at {}",
        promoted.ref_name, promoted.commit_sha
    ));
    promotion.promoted_ref = Some(promoted.ref_name.clone());
    promotion.promoted_commit_sha = Some(promoted.commit_sha.clone());
    promotion.identity.clone_from(&promoted.identity);
    promotion
}

pub(super) fn execution_workspace_parking_summary(
    record: &ExecutionRecord,
    provider_attached: bool,
    worktree: Option<&ExecutionWorkspaceWorktree>,
) -> ExecutionWorkspaceParking {
    let parked = record.evidence.parked_candidate.is_some();
    let mut blockers = Vec::new();
    if parked {
        blockers.push("already_parked".to_string());
    }
    if !provider_attached {
        blockers.push("no_workspace_provider".to_string());
    }
    if let Some(worktree) = worktree {
        if !worktree.exists {
            blockers.push("worktree_missing".to_string());
        }
    } else if provider_attached {
        blockers.push("worktree_not_registered".to_string());
    }
    let available =
        !parked && provider_attached && worktree.is_some_and(|worktree| worktree.exists);
    let (status, reason) = if parked {
        ("parked", None)
    } else if available {
        ("available", None)
    } else {
        (
            "blocked",
            Some(format!("parking blocked by {}", blockers.join(", "))),
        )
    };

    ExecutionWorkspaceParking {
        available,
        parked,
        auto_parked: record.evidence.auto_parked,
        status: status.to_string(),
        blockers,
        reason,
        candidate: record.evidence.parked_candidate.clone(),
    }
}
