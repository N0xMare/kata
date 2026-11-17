//! [`prepare_action`] — the [`PreparedAction`] identity for one lowered operation.

use kata_types::error::KataResult;
use kata_types::execution_contract::{EnvironmentId, PlatformId, PreparedAction};
use kata_types::sandbox::SandboxDirective;

use crate::capsule_assembly::sandbox_permissions_hash;
use kata_program::execution_program::{ExecutionProgramStage, LoweredOperation};

/// PREPARE one action: the identity of "this operation, with these permissions, in
/// this environment, for this platform".
///
/// # THE ONE CONSTRUCTOR OF A `PreparedAction` IN THIS CRATE
///
/// `crate::capsule_assembly::assemble_capsule` calls it rather than spelling
/// `PreparedAction::new` a second time. That matters because the identity folds a
/// hash (`sandbox_permissions_hash`) and a manifest built from two stage fields, and
/// two spellings of those three arguments is how a capsule and an authorization come
/// to disagree about which action they name while both look right.
///
/// # The COMMAND identity is the checked stage contract hash
///
/// `ActionManifest`'s `command` is [`ExecutionProgramStage::contract_hash`]: it
/// already folds the stage's normalized contract (policies, outputs, execution
/// class) and rotates when any of them moves. No production path resolves an
/// input set to per-path digests; the manifest folds the empty one.
///
/// # Failure — the refused set, stated exactly
///
/// Delegated rather than restated: [`sandbox_permissions_hash`]'s refused set (a
/// directive still presuming the main's filesystem after the workspace key is
/// projected out, and one that does not serialize).
///
/// Nothing else. In particular this door does NOT refuse a permissive posture
/// (`FsPolicy::Host`, `NetPolicy::Host`) and does not refuse `fs = custom`:
/// `assemble_capsule` refuses the host paths, because a capsule is what has to
/// encode them, and answering that question in two places would be two refused sets
/// to keep in agreement.
pub fn prepare_action(
    stage: &ExecutionProgramStage,
    lowered: &LoweredOperation,
    environment: EnvironmentId,
    platform: PlatformId,
    directive: &SandboxDirective,
) -> KataResult<PreparedAction> {
    Ok(PreparedAction::new(
        lowered.contract.id(),
        stage.action_manifest(stage.contract_hash),
        environment,
        sandbox_permissions_hash(directive)?,
        platform,
    ))
}
