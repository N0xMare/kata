//! The `forge_export` driver: the export's two wire effects — the push of
//! `kata/<exec>` and the pull request from it — each issued under an intent
//! row (`OperationalDb::record_forge_intent`), and every outcome a crash or a
//! failed command leaves unknown judged by that effect's OBSERVER, its verdict
//! recorded on the intent (ADR 0003 "Effects"; M0's `ForgeIntent.tla`).
//!
//! # One driver for every leg
//!
//! The live claim, an approved gate and the recovery sweep all run
//! [`Dispatcher::drive_forge_export`], which reads the attempt's intents and
//! takes the step they leave owed ([`owed_step`]):
//!
//! | The attempt's last intent | Step |
//! | --- | --- |
//! | none, or a push `not_performed` | the push |
//! | a push with no verdict | the push's observer, when it is due |
//! | a push `performed` | the pull request |
//! | a pull request with no verdict | the pull request's observer, when it is due |
//! | a pull request `not_performed` | the pull request: a fresh lookup, then a fresh intent |
//!
//! No intent means nothing of the export was issued, so the push runs from
//! the start; nothing is issued again under an intent that has no verdict.
//!
//! # The push
//!
//! Before its intent, in order: the uncommitted-candidate refusal, a
//! configured forge, the forge repository the recorded push remote names
//! (`forge_export_repository`; none is `forge_export_repository_unresolved`,
//! refused with nothing written or pushed), the forge's confirmation that it
//! addresses that repository (`Forge::confirm_repository`, a read-only `gh repo
//! view`; any other answer, or none, is `forge_export_repository_unaddressed`,
//! refused with nothing written or pushed — so a repository every later `gh`
//! call would fail on, an SSH host alias's literal host among them, is refused
//! before the push, not after it), the local `kata/<exec>` write
//! behind its own refusals
//! (`write_workspace_effect_forge_ref`), then the read of the remote's head
//! (`forge_remote_head`). A read that fails fails the export with no intent,
//! PROVEN NOT PERFORMED (`forge_export_remote_unread`). A head that is neither
//! absent, this export's commit, nor the commit this execution last pushed
//! there (`last_performed_forge_push`) is a foreign write, refused
//! `forge_export_diverged` with no intent. Any other head is the push's LEASE:
//! the intent records it and the push lands only over it
//! (`--force-with-lease=refs/heads/<branch>:<lease>`). The push writes the
//! intent's commit to `<branch>` and nothing else
//! (`<commit>^{commit}:refs/heads/<branch>`, the closed set in `kata_vcs::jj`
//! `forge_export`'s narrowing): never through a local ref — not `kata/<exec>`,
//! which is not the effect's subject, nor a ref spelled as the commit's id
//! under any of git's name rules — with replace objects off, no graft file
//! read, and the configuration's `push.followTags` and
//! `push.recurseSubmodules` overridden. A write from outside kata to the local
//! refs, replace refs included, to a graft file, or to those two keys after
//! kata wrote the branch changes neither what is pushed — the commit and the
//! objects it reaches — nor what the receipt names (`pushed`, the intent's
//! commit).
//!
//! The push's observer is the remote ref ([`push_observation`]): PERFORMED
//! when it holds the intent's commit; NOT PERFORMED only while it still holds
//! the lease (absent, when the lease is absence); any other head, a state that
//! contradicts both, UNCLASSIFIED at once — the export fails
//! `workspace_effect_unclassified` and nothing is pushed again. A remote that
//! does not answer is no verdict (see below).
//!
//! A PERFORMED push verdict, the push's receipt or its observer's, commits on
//! its own (`OperationalDb::settle_forge_intent`) before anything else is
//! asked: a main that dies in the pull request's lookup that follows has lost
//! nothing the remote answered, and the push's observer is never asked again
//! (M0's `PushReceipt` before `LookupPR`).
//!
//! Residuals, stated. **ABA:** a branch back on the very head kata leased on,
//! by any path after kata's push landed and before its PERFORMED verdict
//! commits — a crash between the push and its receipt, then a move before the
//! observer's first answered read: moved back, or deleted when kata found it
//! absent — reads NOT PERFORMED, and the push is issued again under a fresh
//! intent (M0 finding F9); unanswered reads keep that window open. **A moved
//! lease:** a push the remote refused because the branch moved between the read and the
//! push records the command's error on its intent and asks the observer, which
//! reads UNCLASSIFIED while the branch holds that other head: it cannot tell the
//! refusal from a landed push someone then overwrote. Only a branch back on the
//! lease by the observer's answered read reads NOT PERFORMED, and a push whose
//! command failed is then not issued again: the export fails, nothing pushed
//! (ForgeIntent's `Push` and `ObservePush`).
//!
//! # The pull request
//!
//! Every `Forge` call — the confirmation, the lookup, the create and the
//! observer — is bound to the forge repository the recorded push remote's
//! configured URL names (`ExportDrive::repository`, read again at each call as
//! git reads the remote at each push), never the forge client's default. The
//! remote's NAME is what the claim records; its URL, and so the repository, is
//! re-read, and only the push confirms the forge addresses it. A drive that
//! finds the remote no longer names one fails before the pull request's
//! intent, PROVEN NOT PERFORMED; the observer counts it as a read not
//! answered.
//!
//! Before its intent, the lookup of an OPEN pull request from the head into
//! the export's base (`Forge::find_open_pr`; M0's `LookupPR`), like the push's
//! remote read: one found whose head is in the forge's repository — never a
//! fork's branch of the same name — is adopted
//! and the export completes with no pull-request intent, since adopting sends
//! nothing; a lookup that fails, or whose listing reaches its bound without
//! one, records no intent and fails the export PROVEN NOT PERFORMED
//! (`forge_export_forge_unread`). Otherwise the intent commits, and the body
//! `Forge::create_pull_request` sends ends with a
//! marker naming the intent's coordinates ([`pull_request_marker`]: a whole
//! HTML comment, terminator included, which the forge keeps and does not
//! render); the create's receipt commits with the export's result. The
//! observer is the pull request carrying the marker in ANY state, its head in
//! the forge's repository (`Forge::find_marked_pull_request`): found — open, closed or merged — it is
//! adopted, PERFORMED; none, NOT PERFORMED; an answer too large to rule one
//! out (`MarkedPullRequest::BeyondBound`), UNCLASSIFIED at once. A forge that
//! does not answer is no verdict (see below). Residual, stated: a marker deleted from the body of a pull
//! request that is no longer open, before the observer reads it, yields a
//! second pull request (an open one is adopted by the lookup before the
//! fresh intent).
//!
//! # A command that fails
//!
//! A push or create that returns an error records that error on its intent
//! (`OperationalDb::record_forge_command_error`), then asks its observer.
//! PERFORMED goes on; UNCLASSIFIED fails the export unclassified; NOT
//! PERFORMED — from this ask or any later one — fails it with the command's
//! error, proven not performed. Only an intent whose command never answered (a
//! crash left it) is issued again after a NOT PERFORMED verdict.
//!
//! # An observer the remote does not answer
//!
//! An observer read that fails — the remote or the forge did not answer —
//! settles nothing (owner decision #15; M0's `NoUnclassifiedBeforeTheBound`):
//! the read is counted on the intent
//! (`OperationalDb::record_unanswered_forge_read`), the intent stays open and
//! the attempt pending, and the sweep, which runs on every pass, asks again
//! once [`FORGE_OBSERVER_ASK_SPACING`] has passed since the last unanswered
//! read (wall clock, the row's `last_unanswered_at_ms`). The read that brings
//! the count to [`FORGE_OBSERVER_UNANSWERED_BOUND`] settles the intent
//! UNCLASSIFIED and fails the export `workspace_effect_unclassified`; a drive
//! that finds the count already there (a crash between the count and the
//! settlement) settles it without asking again, so no intent is asked past the
//! bound (`NoAskPastTheBound`). [`Dispatcher::reconcile_forge_exports`] — `kata
//! run forge-reconcile` — asks at once, outside the spacing; its read counts
//! like any other.
//!
//! # What the observers assume
//!
//! A crashed main's `git push` or `gh` child died with it. The shipped service
//! unit makes it so: `KillMode=control-group` kills the main's control group
//! before `Restart=on-failure` starts it again (measured: a `setsid` child of a
//! SIGKILLed main is gone once the unit has restarted). `VcsCommand` gives
//! each child its own process group and no death signal, so a main killed
//! outside the unit can leave one running that lands after the restarted
//! main's observer read NOT PERFORMED, and the effect is issued again. A push
//! or create killed at `FORGE_COMMAND_TIMEOUT` is observed at once: a remote
//! still applying it reads NOT PERFORMED, and the export is recorded failed,
//! proven not performed, though the effect may then land — a wrong record,
//! never a second effect, since that verdict after a failed command issues
//! nothing again.
//!
//! # A cancel between the push and the pull request
//!
//! The push's receipt commits whether or not the attempt is still drivable,
//! so a cancel or a terminal drain that settles the attempt after the push
//! returned leaves the push recorded PERFORMED, and
//! `OperationalDb::record_forge_intent` then records no pull-request intent.
//! Any push intent still open when the attempt is settled stays open — one a
//! crash left between the push's intent and its receipt, or one whose command
//! failed and whose observer has not yet answered: the sweep drives no settled
//! attempt, and the record says the push may have been issued.

use std::sync::Arc;
use std::time::Duration;

use kata_core::operational::{
    ForgeIntentEffect, ForgeIntentId, ForgeIntentOutcome, ForgeIntentRecord, ForgeIntentVerdict,
    ForgeVerdictSource, MainResolution, NewForgeIntent, WorkspaceEffectSpec,
};
use kata_effects_contract::{
    ExecutionWorkspaceKey, ExecutionWorkspaceProvider, Forge, MarkedPullRequest,
    PullRequestReceipt, PullRequestSpec,
};
use kata_types::error::{KataError, KataResult};
use kata_types::workflow::WorkspaceEffectOp;
use ulid::Ulid;

use super::{ForgeExportPlan, WORKSPACE_EFFECT_UNCLASSIFIED, effect_envelope, effect_output};
use crate::dispatcher::Dispatcher;

/// The bound on every read of the remote's head: the pre-intent read and the
/// push's observer.
const FORGE_REMOTE_READ_TIMEOUT: Duration = Duration::from_secs(60);

/// The observer reads a remote may leave unanswered while an intent stays open:
/// the read that reaches it settles the intent UNCLASSIFIED (M0's `MaxAsks`).
pub const FORGE_OBSERVER_UNANSWERED_BOUND: u32 = 10;

/// The least time the sweep lets pass after an unanswered observer read
/// before it asks again. `kata run forge-reconcile` does not wait for it.
pub const FORGE_OBSERVER_ASK_SPACING: Duration = Duration::from_secs(60);

/// No pending `forge_export` of the execution for `kata run forge-reconcile` to
/// drive.
const FORGE_RECONCILE_NOTHING_PENDING: &str = "forge_reconcile_nothing_pending";

/// Who drives an export, which decides whether an open intent's observer is
/// asked before [`FORGE_OBSERVER_ASK_SPACING`] has passed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum ObserverAsk {
    /// The live claim, an approved gate or the sweep: an intent whose last read
    /// went unanswered is asked again only once the spacing has passed.
    Scheduled,
    /// `kata run forge-reconcile`: asked at once.
    Operator,
}

/// The export failed before its push intent because the remote did not answer
/// the read whose answer would have been the lease: nothing was pushed.
const FORGE_EXPORT_REMOTE_UNREAD: &str = "forge_export_remote_unread";

/// The remote's `kata/<exec>` holds a commit kata did not push there: nothing
/// is pushed over it.
const FORGE_EXPORT_DIVERGED: &str = "forge_export_diverged";

/// The export failed before its pull request's intent because the forge did
/// not answer the lookup of an open pull request on the head, or answered a
/// listing at its bound that rules none out: none was opened.
const FORGE_EXPORT_FORGE_UNREAD: &str = "forge_export_forge_unread";

/// The export failed before its push intent because the forge did not confirm
/// the repository the push remote names (`Forge::confirm_repository`): nothing
/// was pushed.
const FORGE_EXPORT_REPOSITORY_UNADDRESSED: &str = "forge_export_repository_unaddressed";

/// The marker a pull request's body carries for the intent that opened it —
/// the whole HTML comment naming its coordinates, `<attempt>/<effect index>`,
/// terminator included, so no intent's marker is a prefix of another's (intent
/// 1's of intent 10's) — what [`Forge::find_marked_pull_request`] looks for.
fn pull_request_marker(id: ForgeIntentId) -> String {
    format!("<!-- kata-forge-intent: {id} -->")
}

/// The body `gh pr create` sends: the authored body, then the marker.
fn marked_body(body: &str, id: ForgeIntentId) -> String {
    format!("{body}\n\n{}", pull_request_marker(id))
}

/// The step an attempt's intents leave owed.
enum ExportStep {
    /// Nothing of the export is issued, or its last push was not performed.
    Push,
    /// A push whose outcome is unknown.
    ObservePush(ForgeIntentRecord),
    /// The push performed, its verdict written: the pull request.
    PullRequest,
    /// A pull request whose outcome is unknown.
    ObservePullRequest(ForgeIntentRecord),
}

/// The step owed after `intents`, the attempt's intents in effect order.
fn owed_step(intents: &[ForgeIntentRecord]) -> KataResult<ExportStep> {
    let Some(last) = intents.last() else {
        return Ok(ExportStep::Push);
    };
    match (&last.effect, last.verdict()) {
        (ForgeIntentEffect::Push { .. }, None) => Ok(ExportStep::ObservePush(last.clone())),
        (ForgeIntentEffect::Push { .. }, Some(ForgeIntentVerdict::NotPerformed)) => {
            Ok(ExportStep::Push)
        }
        (ForgeIntentEffect::Push { .. }, Some(ForgeIntentVerdict::Performed))
        | (ForgeIntentEffect::PullRequest { .. }, Some(ForgeIntentVerdict::NotPerformed)) => {
            Ok(ExportStep::PullRequest)
        }
        (ForgeIntentEffect::PullRequest { .. }, None) => {
            Ok(ExportStep::ObservePullRequest(last.clone()))
        }
        // A performed pull request and every unclassified intent commit with
        // the export's result, so a pending attempt never ends on one.
        (_, Some(verdict)) => Err(KataError::Internal(format!(
            "forge_export attempt {} is pending after its intent {} recorded {verdict:?}, which \
             commits with the export's result",
            last.id.attempt_id, last.id
        ))),
    }
}

/// What an observer read that the remote answered, and the verdict it gives.
struct Observation {
    outcome: ForgeIntentOutcome,
    /// What the observer read, for the export's recorded reason.
    account: String,
    /// The pull request a PERFORMED pull-request observer found.
    receipt: Option<PullRequestReceipt>,
}

impl Observation {
    fn new(verdict: ForgeIntentVerdict, detail: serde_json::Value, account: String) -> Self {
        Self {
            outcome: ForgeIntentOutcome {
                verdict,
                source: ForgeVerdictSource::Observer,
                detail,
            },
            account,
            receipt: None,
        }
    }
}

/// One ask of an observer: an answer, or a read the remote did not answer.
enum ObserverRead {
    /// The remote answered; the observation carries the verdict.
    Answered(Observation),
    /// The read failed, so it says nothing about the effect.
    Unanswered(KataError),
}

/// Where an ask left the drive.
enum Asked {
    /// The observer's answer, for the caller to act on.
    Answered(Observation),
    /// Nothing more this drive: the ask was not due, went unanswered (the
    /// intent stays open), or settled the export at the bound.
    Done,
}

/// The push's observer: the remote ref, judged against the intent's own
/// commit and lease.
fn push_observation(
    provider: &Arc<dyn ExecutionWorkspaceProvider>,
    intent: &ForgeIntentRecord,
) -> ObserverRead {
    let lease = match &intent.effect {
        ForgeIntentEffect::Push { lease } => lease.clone(),
        ForgeIntentEffect::PullRequest { .. } => {
            return ObserverRead::Answered(Observation::new(
                ForgeIntentVerdict::Unclassified,
                serde_json::json!({"error": "a pull-request intent has no push observer"}),
                format!("intent {} is no push", intent.id),
            ));
        }
    };
    let head =
        match provider.forge_remote_head(&intent.remote, &intent.branch, FORGE_REMOTE_READ_TIMEOUT)
        {
            Ok(head) => head,
            Err(error) => return ObserverRead::Unanswered(error),
        };
    let detail = serde_json::json!({"observed_head": head, "lease": lease});
    let shown = |sha: Option<&str>| sha.map_or_else(|| "no branch".to_owned(), str::to_owned);
    ObserverRead::Answered(if head.as_deref() == Some(intent.commit.as_str()) {
        Observation::new(
            ForgeIntentVerdict::Performed,
            detail,
            format!(
                "the remote {} holds the pushed {}",
                intent.remote, intent.commit
            ),
        )
    } else if head == lease {
        Observation::new(
            ForgeIntentVerdict::NotPerformed,
            detail,
            format!(
                "the remote {} still holds the lease ({}) at `{}`",
                intent.remote,
                shown(lease.as_deref()),
                intent.branch
            ),
        )
    } else {
        Observation::new(
            ForgeIntentVerdict::Unclassified,
            detail,
            format!(
                "the remote {} holds {} at `{}`, neither the pushed {} nor the lease ({})",
                intent.remote,
                shown(head.as_deref()),
                intent.branch,
                intent.commit,
                shown(lease.as_deref())
            ),
        )
    })
}

/// The pull request's observer: a pull request of `repository` on the
/// intent's branch whose body carries the intent's marker, in any state.
fn pull_request_observation(
    forge: &Arc<dyn Forge>,
    repository: &str,
    intent: &ForgeIntentRecord,
) -> ObserverRead {
    let marker = pull_request_marker(intent.id);
    ObserverRead::Answered(
        match forge.find_marked_pull_request(repository, &intent.branch, &marker) {
            Ok(MarkedPullRequest::Found(receipt)) => Observation {
                receipt: Some(receipt.clone()),
                ..Observation::new(
                    ForgeIntentVerdict::Performed,
                    serde_json::json!({"pr_url": receipt.url, "pr_number": receipt.number}),
                    format!("the forge lists {} carrying `{marker}`", receipt.url),
                )
            },
            Ok(MarkedPullRequest::Absent) => Observation::new(
                ForgeIntentVerdict::NotPerformed,
                serde_json::json!({"marked": null}),
                format!(
                    "the forge lists no pull request of {repository} on `{}` carrying `{marker}`",
                    intent.branch
                ),
            ),
            Ok(MarkedPullRequest::BeyondBound(account)) => Observation::new(
                ForgeIntentVerdict::Unclassified,
                serde_json::json!({"beyond_bound": account}),
                account,
            ),
            Err(error) => return ObserverRead::Unanswered(error),
        },
    )
}

/// `true` once [`FORGE_OBSERVER_ASK_SPACING`] has passed since `last_at_ms`
/// (wall clock, as the row records it).
fn ask_due(last_at_ms: i64) -> bool {
    let now_ms = i64::try_from(kata_types::time::now_ms()).unwrap_or(i64::MAX);
    let spacing_ms = i64::try_from(FORGE_OBSERVER_ASK_SPACING.as_millis()).unwrap_or(i64::MAX);
    now_ms.saturating_sub(last_at_ms) >= spacing_ms
}

/// The recorded reason of an export whose intent cannot be classified.
fn unclassified_reason(intent: &ForgeIntentRecord, account: &str) -> String {
    let effect = match intent.effect {
        ForgeIntentEffect::Push { .. } => "push",
        ForgeIntentEffect::PullRequest { .. } => "pull request",
    };
    format!(
        "{WORKSPACE_EFFECT_UNCLASSIFIED}: the forge_export's {effect} under intent {} cannot be \
         classified — {account}. Whether it reached the remote is unknown: it is recorded \
         failed and never issued again",
        intent.id
    )
}

/// One drive of one export attempt: its facts, and the doors it acts through.
struct ExportDrive<'a> {
    dispatcher: &'a Dispatcher,
    db: Arc<kata_core::OperationalDb>,
    execution_id: Ulid,
    attempt_id: Ulid,
    stage_name: &'a str,
    spec: &'a WorkspaceEffectSpec,
    plan: ForgeExportPlan,
    provider: &'a Arc<dyn ExecutionWorkspaceProvider>,
    forge: Option<&'a Arc<dyn Forge>>,
    ask: ObserverAsk,
}

impl ExportDrive<'_> {
    /// The configured forge, or the refusal that names its absence — asked
    /// before any intent, so a missing forge issues nothing.
    fn forge(&self) -> KataResult<&Arc<dyn Forge>> {
        self.forge.ok_or_else(|| {
            KataError::Config(
                "forge_export stage dispatched but no Forge is configured on this node; wire a \
                 forge (the `gh` CLI) at boot so `forge_export` can open a PR; nothing was pushed"
                    .to_owned(),
            )
        })
    }

    /// The forge repository the export's push remote names
    /// (`forge_export_repository`), which every `Forge` call is bound to —
    /// read again at each, as git reads the remote's URL at each push and
    /// observer read.
    fn repository(&self) -> KataResult<String> {
        self.provider.forge_export_repository(&self.plan.remote)
    }

    /// Resolve the attempt failed with `reason`, writing `settle` with it.
    fn fail(
        &self,
        settle: Option<(ForgeIntentId, &ForgeIntentOutcome)>,
        reason: &str,
    ) -> KataResult<Option<ExportStep>> {
        self.db.resolve_forge_export_attempt(
            self.attempt_id,
            settle,
            &MainResolution::Fail {
                reason,
                terminal_charge: None,
            },
        )?;
        Ok(None)
    }

    /// Resolve the attempt completed with the pull request `receipt` names,
    /// writing `settle` with it.
    fn complete(
        &self,
        settle: Option<(ForgeIntentId, &ForgeIntentOutcome)>,
        receipt: &PullRequestReceipt,
    ) -> KataResult<Option<ExportStep>> {
        let output = effect_output(
            self.stage_name,
            effect_envelope(
                WorkspaceEffectOp::ForgeExport,
                serde_json::json!({
                    "branch": self.plan.branch,
                    "commit_sha": self.spec.delivered_commit,
                    "remote": self.plan.remote,
                    "pr_url": receipt.url,
                    "pr_number": receipt.number,
                })
                .as_object()
                .cloned()
                .unwrap_or_default(),
            ),
        );
        self.db.resolve_forge_export_attempt(
            self.attempt_id,
            settle,
            &MainResolution::Complete { output: &output },
        )?;
        Ok(None)
    }

    /// The push: everything that can fail without issuing it, its intent,
    /// then the push itself.
    fn push(&self) -> KataResult<Option<ExportStep>> {
        match self
            .dispatcher
            .refuse_uncommitted_export(self.execution_id, self.spec)
        {
            Ok(()) => {}
            Err(KataError::Validation(reason)) => return self.fail(None, &reason),
            Err(error) => return Err(error),
        }
        let forge = self.forge()?;
        let repository = match self.repository() {
            Ok(repository) => repository,
            Err(KataError::Validation(reason)) => {
                return self.fail(
                    None,
                    &format!("{reason}. No intent was recorded and nothing was pushed"),
                );
            }
            Err(error) => return Err(error),
        };
        if let Err(error) = forge.confirm_repository(&repository) {
            return self.fail(
                None,
                &format!(
                    "{FORGE_EXPORT_REPOSITORY_UNADDRESSED}: the forge does not address \
                     {repository}, the repository the push remote `{}` names, so no pull \
                     request could open where the branch would be pushed — {error}. Set the \
                     remote's URL to one the forge addresses (an SSH host alias is read as \
                     its literal host). No intent was recorded and nothing was pushed",
                    self.plan.remote
                ),
            );
        }
        let key = ExecutionWorkspaceKey::execution(self.execution_id);
        // A crash between a jj publish and its checkout leaves the working
        // copy stale, and the write's refusals snapshot the disk.
        if let Some(handle) = self.provider.lookup_workspace(&key)? {
            self.provider.repair_stale_checkout(&handle)?;
        }
        match self.provider.write_workspace_effect_forge_ref(
            &key,
            &self.plan.branch,
            &self.spec.candidate_commit,
            &self.spec.delivered_commit,
            &self.attempt_id.to_string(),
        ) {
            Ok(()) => {}
            Err(KataError::Validation(reason)) => return self.fail(None, &reason),
            Err(error) => return Err(error),
        }
        let (remote, branch, delivered) = (
            self.plan.remote.as_str(),
            self.plan.branch.as_str(),
            self.spec.delivered_commit.as_str(),
        );
        let lease = match self
            .provider
            .forge_remote_head(remote, branch, FORGE_REMOTE_READ_TIMEOUT)
        {
            Ok(head) => head,
            Err(error) => {
                return self.fail(
                    None,
                    &format!(
                        "{FORGE_EXPORT_REMOTE_UNREAD}: the remote {remote} did not answer the \
                         read of `{branch}` that would lease the push — {error}. No intent was \
                         recorded, so nothing was pushed: PROVEN NOT PERFORMED"
                    ),
                );
            }
        };
        if let Some(found) = lease.as_deref()
            && found != delivered
            && self
                .db
                .last_performed_forge_push(self.execution_id, remote, branch)?
                .as_deref()
                != Some(found)
        {
            return self.fail(
                None,
                &format!(
                    "{FORGE_EXPORT_DIVERGED}: the remote {remote} holds {found} at `{branch}`, \
                     neither this export's {delivered} nor a commit this execution pushed there — \
                     a foreign write owns the branch; no intent was recorded and nothing is pushed"
                ),
            );
        }
        kata_core::fault_inject::operational_crash_point("after_forge_read_before_push_intent");
        let Some(intent) = self.db.record_forge_intent(&NewForgeIntent {
            attempt_id: self.attempt_id,
            remote,
            branch,
            commit: delivered,
            effect: ForgeIntentEffect::Push {
                lease: lease.clone(),
            },
        })?
        else {
            // The attempt was settled under us (a cancel): nothing is issued.
            return Ok(None);
        };
        kata_core::fault_inject::operational_crash_point("after_forge_push_intent_before_push");
        // The push sends the intent's own commit, resolved by object id and
        // never through a local ref a write from outside kata can move, so a
        // push git reports done sent that commit and the receipt names it.
        match self.provider.push_workspace_effect_ref_expecting(
            remote,
            branch,
            &intent.commit,
            lease.as_deref(),
        ) {
            Ok(()) => {
                kata_core::fault_inject::operational_crash_point("after_forge_push_before_pr");
                self.db.settle_forge_intent(
                    intent.id,
                    &ForgeIntentOutcome {
                        verdict: ForgeIntentVerdict::Performed,
                        source: ForgeVerdictSource::Receipt,
                        detail: serde_json::json!({"pushed": intent.commit, "lease": lease}),
                    },
                )?;
                Ok(Some(ExportStep::PullRequest))
            }
            Err(error) => {
                let intent = self
                    .db
                    .record_forge_command_error(intent.id, &error.to_string())?;
                self.observed_push(&intent)
            }
        }
    }

    /// Ask `intent`'s observer through `read` — unless the intent's unanswered
    /// reads already reached the bound, which settles it without asking, or
    /// the scheduled ask is not yet due. A read the remote does not answer is
    /// counted on the intent, and the one that reaches the bound settles it.
    fn ask(
        &self,
        intent: &ForgeIntentRecord,
        read: impl FnOnce() -> ObserverRead,
    ) -> KataResult<Asked> {
        if let Some(unanswered) = &intent.unanswered {
            if unanswered.count >= FORGE_OBSERVER_UNANSWERED_BOUND {
                self.settle_unanswered(intent, unanswered.count, &unanswered.last_error)?;
                return Ok(Asked::Done);
            }
            if self.ask == ObserverAsk::Scheduled && !ask_due(unanswered.last_at_ms) {
                return Ok(Asked::Done);
            }
        }
        match read() {
            ObserverRead::Answered(observation) => Ok(Asked::Answered(observation)),
            ObserverRead::Unanswered(error) => {
                let error = error.to_string();
                let unanswered = self.db.record_unanswered_forge_read(intent.id, &error)?;
                if unanswered.count >= FORGE_OBSERVER_UNANSWERED_BOUND {
                    self.settle_unanswered(intent, unanswered.count, &error)?;
                }
                Ok(Asked::Done)
            }
        }
    }

    /// Fail the export UNCLASSIFIED: `intent`'s observer saw `count`
    /// unanswered reads, the last failing with `last_error`.
    fn settle_unanswered(
        &self,
        intent: &ForgeIntentRecord,
        count: u32,
        last_error: &str,
    ) -> KataResult<Option<ExportStep>> {
        let outcome = ForgeIntentOutcome {
            verdict: ForgeIntentVerdict::Unclassified,
            source: ForgeVerdictSource::Observer,
            detail: serde_json::json!({
                "unanswered_reads": count,
                "last_read_error": last_error,
            }),
        };
        self.fail(
            Some((intent.id, &outcome)),
            &unclassified_reason(
                intent,
                &format!(
                    "the remote {} did not answer {count} reads of its observer, the last: \
                     {last_error}",
                    intent.remote
                ),
            ),
        )
    }

    /// The push's observer over `intent`. An intent carrying its command's
    /// error is judged with it: NOT PERFORMED then fails the export.
    fn observed_push(&self, intent: &ForgeIntentRecord) -> KataResult<Option<ExportStep>> {
        let observation = match self.ask(intent, || push_observation(self.provider, intent))? {
            Asked::Answered(observation) => observation,
            Asked::Done => return Ok(None),
        };
        match observation.outcome.verdict {
            ForgeIntentVerdict::Performed => {
                self.db
                    .settle_forge_intent(intent.id, &observation.outcome)?;
                Ok(Some(ExportStep::PullRequest))
            }
            ForgeIntentVerdict::NotPerformed => {
                if let Some(error) = &intent.command_error {
                    return self.fail(
                        Some((intent.id, &observation.outcome)),
                        &format!(
                            "forge_export: the push of `{}` to {} failed — {error}; {}, so it \
                             was not performed and nothing is pushed again",
                            intent.branch, intent.remote, observation.account
                        ),
                    );
                }
                self.db
                    .settle_forge_intent(intent.id, &observation.outcome)?;
                Ok(Some(ExportStep::Push))
            }
            ForgeIntentVerdict::Unclassified => self.fail(
                Some((intent.id, &observation.outcome)),
                &unclassified_reason(intent, &observation.account),
            ),
        }
    }

    /// The pull request: the lookup of an open one on the head, then its
    /// intent, then `gh pr create` with the marked body.
    fn pull_request(&self) -> KataResult<Option<ExportStep>> {
        let forge = self.forge()?;
        let (branch, base) = (self.plan.branch.as_str(), self.plan.base.as_str());
        let repository = match self.repository() {
            Ok(repository) => repository,
            Err(KataError::Validation(reason)) => {
                return self.fail(
                    None,
                    &format!(
                        "{reason}. No pull-request intent was recorded, so none was opened: \
                         PROVEN NOT PERFORMED; the pushed branch stands"
                    ),
                );
            }
            Err(error) => return Err(error),
        };
        match forge.find_open_pr(&repository, branch, base) {
            Ok(None) => {}
            Ok(Some(existing)) => return self.complete(None, &existing),
            Err(error) => {
                return self.fail(
                    None,
                    &format!(
                        "{FORGE_EXPORT_FORGE_UNREAD}: the lookup of an open pull request on \
                         `{branch}` got no answer it can act on — {error}. No pull-request \
                         intent was recorded, so none was opened: PROVEN NOT PERFORMED; the \
                         pushed branch stands"
                    ),
                );
            }
        }
        let Some(intent) = self.db.record_forge_intent(&NewForgeIntent {
            attempt_id: self.attempt_id,
            remote: &self.plan.remote,
            branch: &self.plan.branch,
            commit: &self.spec.delivered_commit,
            effect: ForgeIntentEffect::PullRequest {
                base: self.plan.base.clone(),
            },
        })?
        else {
            return Ok(None);
        };
        kata_core::fault_inject::operational_crash_point("after_forge_pr_intent_before_create");
        match forge.create_pull_request(&PullRequestSpec {
            repository,
            title: self.plan.title.clone(),
            body: marked_body(&self.plan.body, intent.id),
            base: self.plan.base.clone(),
            head: self.plan.branch.clone(),
        }) {
            Ok(receipt) => {
                kata_core::fault_inject::operational_crash_point(
                    "after_forge_pr_create_before_receipt",
                );
                self.complete(
                    Some((
                        intent.id,
                        &ForgeIntentOutcome {
                            verdict: ForgeIntentVerdict::Performed,
                            source: ForgeVerdictSource::Receipt,
                            detail: serde_json::json!({
                                "pr_url": receipt.url,
                                "pr_number": receipt.number,
                            }),
                        },
                    )),
                    &receipt,
                )
            }
            Err(error) => {
                let intent = self
                    .db
                    .record_forge_command_error(intent.id, &error.to_string())?;
                self.observed_pull_request(&intent)
            }
        }
    }

    /// The pull request's observer over `intent`. An intent carrying the
    /// create's error is judged with it: NOT PERFORMED then fails the export.
    fn observed_pull_request(&self, intent: &ForgeIntentRecord) -> KataResult<Option<ExportStep>> {
        let forge = self.forge()?;
        let observation = match self.ask(intent, || match self.repository() {
            Ok(repository) => pull_request_observation(forge, &repository, intent),
            Err(error) => ObserverRead::Unanswered(error),
        })? {
            Asked::Answered(observation) => observation,
            Asked::Done => return Ok(None),
        };
        match (observation.outcome.verdict, &observation.receipt) {
            (ForgeIntentVerdict::Performed, Some(receipt)) => {
                self.complete(Some((intent.id, &observation.outcome)), receipt)
            }
            (ForgeIntentVerdict::NotPerformed, _) => {
                if let Some(error) = &intent.command_error {
                    return self.fail(
                        Some((intent.id, &observation.outcome)),
                        &format!(
                            "forge_export: `gh pr create` from `{}` failed — {error}; {}, so no \
                             pull request was opened; the pushed branch stands",
                            intent.branch, observation.account
                        ),
                    );
                }
                self.db
                    .settle_forge_intent(intent.id, &observation.outcome)?;
                Ok(Some(ExportStep::PullRequest))
            }
            _ => self.fail(
                Some((intent.id, &observation.outcome)),
                &unclassified_reason(intent, &observation.account),
            ),
        }
    }
}

impl Dispatcher {
    /// DRIVE a claimed `forge_export` attempt to its next settled point — the
    /// live claim, an approved gate and the recovery sweep alike (the module
    /// doc states the steps). Serialized with every other effect perform and
    /// re-checked drivable inside the lock, like
    /// [`Self::perform_workspace_effect`]. The lock is held across the drive's
    /// network calls, up to about 28 minutes
    /// (`OperationalDb::effect_perform_lock` states the bound).
    ///
    /// `ask` says whether an open intent whose last observer read went
    /// unanswered is asked before [`FORGE_OBSERVER_ASK_SPACING`] has passed.
    ///
    /// # Errors
    ///
    /// The store's failures; the provider's failures before an intent (the
    /// workspace lookup, the stale-checkout repair, the local write's
    /// non-refusal errors); an absent forge (`Config`), before anything is
    /// issued. A refused or failed export is recorded on the attempt and
    /// returned `Ok`; so is one left pending on an open intent.
    #[allow(clippy::too_many_arguments)]
    pub(super) fn drive_forge_export(
        &self,
        execution_id: Ulid,
        attempt_id: Ulid,
        stage_name: &str,
        spec: &WorkspaceEffectSpec,
        provider: &Arc<dyn ExecutionWorkspaceProvider>,
        forge: Option<&Arc<dyn Forge>>,
        ask: ObserverAsk,
    ) -> KataResult<()> {
        let lifecycle = self.execution_lifecycle();
        let db = lifecycle.db();
        let _permit = db.effect_perform_lock();
        if !db.workspace_effect_attempt_drivable(attempt_id)? {
            return Ok(());
        }
        let plan = match self.forge_export_plan(execution_id, spec) {
            Ok(plan) => plan,
            Err(KataError::Validation(reason)) => {
                db.resolve_forge_export_attempt(
                    attempt_id,
                    None,
                    &MainResolution::Fail {
                        reason: &reason,
                        terminal_charge: None,
                    },
                )?;
                return Ok(());
            }
            Err(error) => return Err(error),
        };
        let drive = ExportDrive {
            dispatcher: self,
            db: Arc::clone(db),
            execution_id,
            attempt_id,
            stage_name,
            spec,
            plan,
            provider,
            forge,
            ask,
        };
        let mut step = Some(owed_step(&db.forge_intents(attempt_id)?)?);
        while let Some(owed) = step {
            step = match owed {
                ExportStep::Push => drive.push()?,
                ExportStep::ObservePush(intent) => drive.observed_push(&intent)?,
                ExportStep::PullRequest => drive.pull_request()?,
                ExportStep::ObservePullRequest(intent) => drive.observed_pull_request(&intent)?,
            };
        }
        Ok(())
    }

    /// RECONCILE `execution_id`'s pending `forge_export`s now — `kata run
    /// forge-reconcile`: each is driven as the sweep drives it, except that an
    /// open intent's observer is asked at once, whenever its last read went
    /// unanswered ([`ObserverAsk::Operator`]). The ask counts toward
    /// [`FORGE_OBSERVER_UNANSWERED_BOUND`] like any other, and nothing is
    /// issued that the sweep's next pass would not issue. Answers each export
    /// as it stands afterwards, read back from the store.
    ///
    /// # Errors
    ///
    /// `Validation` ([`FORGE_RECONCILE_NOTHING_PENDING`]) when the execution
    /// has no pending `forge_export`; `Internal` when it has one but no
    /// workspace provider is attached; the drive's own errors.
    pub fn reconcile_forge_exports(
        &self,
        execution_id: Ulid,
        provider: Option<&Arc<dyn ExecutionWorkspaceProvider>>,
        forge: Option<&Arc<dyn Forge>>,
    ) -> KataResult<Vec<ForgeReconcile>> {
        let lifecycle = self.execution_lifecycle();
        let db = lifecycle.db();
        let pending: Vec<_> = db
            .pending_workspace_effects(execution_id)?
            .into_iter()
            .filter(|attempt| attempt.spec.op == WorkspaceEffectOp::ForgeExport)
            .collect();
        if pending.is_empty() {
            return Err(KataError::Validation(format!(
                "{FORGE_RECONCILE_NOTHING_PENDING}: execution {execution_id} has no pending \
                 forge_export, so there is no intent to ask about; `kata run show \
                 {execution_id}` reports how each export ended"
            )));
        }
        let provider = provider.ok_or_else(|| {
            KataError::Internal(format!(
                "execution {execution_id} holds a pending forge_export but no workspace provider \
                 is attached, so nothing can read its remote"
            ))
        })?;
        let mut reconciled = Vec::with_capacity(pending.len());
        for attempt in pending {
            self.drive_forge_export(
                execution_id,
                attempt.attempt_id,
                &attempt.stage_id,
                &attempt.spec,
                provider,
                forge,
                ObserverAsk::Operator,
            )?;
            reconciled.push(ForgeReconcile {
                attempt_id: attempt.attempt_id,
                state: db.attempt_state(attempt.attempt_id)?.ok_or_else(|| {
                    KataError::Internal(format!(
                        "forge_export attempt {} reads back no state after its drive",
                        attempt.attempt_id
                    ))
                })?,
                intent: db.forge_intents(attempt.attempt_id)?.pop(),
                stage_id: attempt.stage_id,
            });
        }
        Ok(reconciled)
    }
}

/// One pending `forge_export` as `kata run forge-reconcile` left it.
#[derive(Clone, Debug)]
pub struct ForgeReconcile {
    /// The export's attempt.
    pub attempt_id: Ulid,
    /// Its stage coordinate.
    pub stage_id: String,
    /// The attempt's state after the drive: `pending` while an intent stays
    /// open, else how it resolved.
    pub state: String,
    /// The attempt's last intent, as recorded: the one the observer was asked
    /// about, or the next effect the drive went on to.
    pub intent: Option<ForgeIntentRecord>,
}
