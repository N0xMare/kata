//! The `CapsuleProcess::Agent` arm of a capsule attempt.
//!
//! A shell capsule's lifecycle is *spawn container, wait, publish*; an agent
//! capsule's is *launch, open the protocol session, prompt, classify the turn
//! outcome, close, teardown, publish*. The differences are the protocol's: the
//! container's init is the turn's kind's own (`kata-toolhost`, fixed by the
//! kind), its stdin/stdout are the FIFOs the adapter's
//! codec speaks, and its exit is the session's terminal frame rather than a
//! stage outcome. Everything else — the materialized attempt root, the `/out`
//! publication, the `/work` delta, the fence, the provenance — is the same
//! capsule path's, which is why this module composes with
//! `capsule_execution`'s pieces rather than beside them.
//!
//! The order is the contract's:
//!
//! 1. the prompt blob is read BEFORE the capsule launches (a missing input is
//!    a pre-container refusal, never an in-flight one);
//! 2. the capsule launches through the driver's `launch_interactive` (the
//!    interactive `OciStdio` arm);
//! 3. the adapter opens the session over the interactive process; `open`
//!    performs no model call, so a refusal there is pre-container;
//! 4. `session.prompt` answers a [`TurnOutcome`], classified exactly as
//!    ADR-0001's classes are: `Completed` reports; `Refused` is PROVEN NOT
//!    PERFORMED — the refusal happened before the watermark, so NO model
//!    call was issued and the refusal publishes nothing (no response, no
//!    `/work` delta, no capture);
//!    `Cancelled` is a confirmed stop, settled through the same `Failed`
//!    frame a fenced stop reports, and the burn the harness reported rides
//!    that frame metered — a cancelled turn that spent is not a free turn,
//!    and one that reported nothing is `Unavailable`, never a zero;
//!    `ProviderFailed` (a turn the model provider failed, classed `refused`
//!    or `transient` from the harness's typed error) is PROVEN NOT PERFORMED
//!    with that class and the provider's reason — nothing the turn did left an
//!    offline capsule, and nothing is published — charged as the adapter
//!    states (`FailedTurnCharge`): the authoritative `0` (no attempt billed),
//!    the metered usage (only completed attempts billed), or `Unavailable`
//!    (an attempt may have billed what no response stated); after a tool call in a capsule that can reach the
//!    network, or a teardown that could not confirm, it is PROVEN AMBIGUOUS;
//!    `Ambiguous` is PROVEN AMBIGUOUS with the unmetered usage
//!    shape — never a zero, because an ambiguous turn may have billed what
//!    it cannot report;
//! 5. `session.close()` runs the adapter's own teardown ladder, then the
//!    placement's `teardown()` runs the cgroup sweep — in that order, never
//!    instead of each other;
//! 6. a `Completed` turn's response is published as a Private blob the frame
//!    names in `agent`, and `/out`, the `/work` delta and the captures are
//!    published through the shell arm's own verbs.

use std::sync::Arc;

use kata_agent::adapter::scope::{SessionObservation, SessionProgressSink};
use kata_agent::adapter::session::{CancelToken, TurnOutcome};
use kata_agent::adapter::{AgentSession, AttemptScope, SessionSeed};
use kata_agent::adapter::{FailedTurnCharge, MayHaveIssued};
use kata_transport::types::{AttemptFence, CapsuleAssignment, WorkerMessage};
use kata_types::agent::{AgentTurnReport, Prompt};
use kata_types::cache::TokenUsage;
use kata_types::error::{KataError, KataResult};
use kata_types::execution_contract::{
    ArtifactPrivacy, ArtifactRef, Capsule, CapsuleNetwork, CapsuleProcess,
};
use kata_types::metering::{CredentialMode, MeteredCost, StageUsage};

use crate::capsule_execution::{
    CapsuleAttemptRefusal, CapsuleExecution, ExecutionProvenanceVerdict, publish_captures,
};
use crate::interactive_capsule::InteractiveTeardown;
use crate::oci_driver::CapsuleDriver;

/// The grace a deadline-expired turn gives the fenced stop before the outcome
/// is classified. The harness that CAN still answer — between frames, or
/// blocked on kata's own read — gets a bounded window to report `Cancelled`
/// honestly; a wedged one pays the window once rather than never. The
/// supervisor's own teardown grace is the codebase's five-second answer to
/// "how long to wait for a counterparty to confirm a stop", and the turn's
/// cancel is the same question. It is the floor: a session that states a
/// longer `AgentSession::stop_grace` (one that ends its turn inside `prompt`)
/// is given that instead.
const TURN_CANCEL_GRACE: std::time::Duration = crate::provider_supervisor::DEFAULT_TEARDOWN_GRACE;

/// Run one agent capsule's turn end to end.
///
/// # Errors
///
/// [`CapsuleAttemptRefusal`]'s arms: PROVEN NOT PERFORMED for anything that
/// precedes a billable issuance (prompt resolution, launch, open, an adapter
/// `Refused`), PROVEN AMBIGUOUS for the `Ambiguous` outcome and for any
/// post-container step — the turn may have run before the step failed.
#[allow(clippy::too_many_arguments)]
/// The credential load, run off the async runtime. The resolver is
/// synchronous and reads files (and, for kata's own ChatGPT login, may refresh
/// it over the network). On the worker's own threads that would starve the
/// drains, the egress proxies and the adapters sharing the runtime, so the load
/// moves to the blocking pool on owned clones. A join failure is a refusal of the same
/// provenance the resolver's own errors carry: nothing was lifted, and the
/// container does not exist yet.
pub(crate) async fn resolve_agent_credential_off_runtime(
    turn: &kata_types::execution_contract::AgentTurnSpec,
    source: &crate::agent_credential::AgentCredentialSource,
) -> Result<crate::agent_credential::ResolvedAgentCredential, KataError> {
    let turn = turn.clone();
    let source = source.clone();
    tokio::task::spawn_blocking(move || {
        crate::agent_credential::resolve_agent_credential(&turn, &source)
    })
    .await
    .map_err(|error| {
        KataError::Validation(format!(
            "credential_resolution_lost: the lift's blocking task ended without an answer — the worker lost the resolution itself, and no credential was handed out: {error}"
        ))
    })?
}

pub(super) async fn execute_agent_turn(
    execution: &CapsuleExecution<'_>,
    frame: &CapsuleAssignment,
    capsule: &Capsule,
    request: &crate::oci_driver::OciStageRequest<'_>,
    driver: &dyn CapsuleDriver,
    attempt_tag: &str,
    cancel: tokio::sync::oneshot::Receiver<String>,
    progress: Option<&crate::capsule_progress::CapsuleProgress>,
) -> Result<WorkerMessage, CapsuleAttemptRefusal> {
    let CapsuleProcess::Agent(turn) = capsule.process() else {
        return Err(CapsuleAttemptRefusal::before_the_container(
            KataError::Internal(
                "agent_turn: a Command capsule reached the agent arm — a wiring defect, \
                 not a refusal"
                    .into(),
            ),
        ));
    };
    let adapter = execution.adapters.adapter(turn.adapter).ok_or_else(|| {
        CapsuleAttemptRefusal::before_the_container(KataError::Validation(format!(
            "adapter_unavailable: the capsule's turn declares adapter `{}` and this worker \
             carries no adapter for it. The CHECK admits only kinds a registry answers, so \
             reaching here means a capsule the admission door never judged",
            turn.adapter.as_label(),
        )))
    })?;

    // THE PROMPT — before the capsule launches, so a missing input refuses
    // before a container exists rather than mid-turn.
    let prompt_reference = request.trees.tree_reference(turn.prompt).map_err(|error| {
        CapsuleAttemptRefusal::before_the_container(KataError::Validation(format!(
            "the agent turn's prompt artifact {id} does not resolve on this worker: {error}",
            id = turn.prompt.0,
        )))
    })?;
    let prompt_bytes = request
        .source
        .read_verified(
            prompt_reference.object_id(),
            prompt_reference.size_bytes(),
            prompt_reference.size_bytes(),
        )
        .map_err(|error| {
            CapsuleAttemptRefusal::before_the_container(KataError::Validation(format!(
                "the agent turn's prompt blob {} is not readable from this worker's content \
                 store: {error}",
                prompt_reference.object_id(),
            )))
        })?;
    let prompt_text = String::from_utf8(prompt_bytes).map_err(|error| {
        CapsuleAttemptRefusal::before_the_container(KataError::Validation(format!(
            "the agent turn's prompt blob {} does not decode as UTF-8: {error} — the submit \
             door publishes the rendered prompt, which is always text",
            prompt_reference.object_id(),
        )))
    })?;

    // THE CREDENTIAL — the worker's lift, resolved BEFORE the launch so an
    // unavailable or expired login refuses before a container exists. It
    // rides the `Prompt` to the harness in-process and never reaches the
    // capsule. Budget = the stage's own wall clock: a token that expires
    // inside it refuses `credential_expired` here, never mid-turn.
    let credential = resolve_agent_credential_off_runtime(turn, execution.credentials)
        .await
        .map_err(|error| {
            CapsuleAttemptRefusal::before_the_container(KataError::Validation(format!("{error}")))
        })?;
    // THE SCRUB LIST — every loaded VALUE the attempt carries. A provider
    // can echo a key into an error, and the refusal reason quoting that error
    // is the durable `worker_reason` row verbatim — so every
    // adapter-influenced string below is scrubbed through this list before it
    // becomes a refusal.
    let lifted = kata_types::redaction::LiftedSecrets::new(credential.lifted_values());

    // THE TURN'S WALL CLOCK arms at the launch: credential resolution and the
    // request build are admission and do not bill against it; everything from
    // the provider's spawn onward does — the prompt leg first of all, which
    // `run_session_and_settle` races against this instant. `checked_add`
    // because `u64::MAX` ms of wall budget is a legal declaration that must
    // not panic the worker on an `Instant` overflow.
    let turn_deadline = tokio::time::Instant::now()
        .checked_add(std::time::Duration::from_millis(
            capsule.budgets().wall_time_ms,
        ))
        // `Instant` arithmetic panics past platform bounds, so an
        // astronomical-but-legal declaration clamps to a year out rather than
        // wedging the worker on its own overflow.
        .unwrap_or_else(|| tokio::time::Instant::now() + std::time::Duration::from_hours(8760));
    // THE LAUNCH — the toolhost's own refusal vocabulary is the refusal's.
    let placement = driver
        .launch_interactive(attempt_tag, request)
        .await
        .map_err(|refusal| refusal_for_failed_launch(refusal, &lifted))?;
    let attempt_root = placement.attempt_root().to_path_buf();
    let (mut process, teardown) = placement.into_halves();

    // THE TOOLHOST'S STDERR — the one stream no adapter's codec takes
    // (protocols live on stdin/stdout), so the composition drains it to the
    // capture spool as the only capsule output kata records verbatim. `None`
    // leaves the stream unconsumed — a placement that never piped stderr has
    // nothing to drain, which the spool's empty file states honestly.
    let stderr_reader = process.take_stderr();

    // THE SCOPE — the attempt's own facts, the capsule's own mapping and
    // budget vocabulary. The session seed is derived from the
    // capsule id + the attempt id: deterministic for one attempt, distinct
    // across attempts of one occurrence.
    let mut seed_hasher = blake3::Hasher::new();
    seed_hasher.update(b"agent-session-seed/v1");
    seed_hasher.update(capsule.id().0.0.as_slice());
    seed_hasher.update(frame.attempt_id.to_bytes().as_slice());
    let scope = AttemptScope::new(
        frame.attempt_id,
        SessionSeed::new(kata_types::primitives::ContentHash::new(
            *seed_hasher.finalize().as_bytes(),
        )),
        capsule.inputs().to_vec(),
        capsule.budgets(),
        capsule.id(),
        lifted.clone(),
    );
    // The stage's authored visibility rides the scope, so the session's
    // own event funnels report through it. `off` gave this call `None`, and a
    // scope without a sink emits nothing — which is the authored semantic,
    // reached here with no flag left to disagree with itself.
    let sink = progress.map(crate::capsule_progress::CapsuleProgress::session_sink);
    let sink = if kata_core::fault_inject::operational_point_armed(FIRST_PROVIDER_EVENT) {
        Some(Arc::new(FirstProviderEvent { inner: sink }) as Arc<dyn SessionProgressSink>)
    } else {
        sink
    };
    let scope = match sink {
        Some(sink) => scope.with_progress(sink),
        None => scope,
    };

    let session = match adapter.open(scope, process) {
        Ok(session) => session,
        Err(refusal) => {
            // The harness never spoke — but it LAUNCHED and its container was
            // ACCEPTED, so the teardown ladder still runs before the refusal is
            // reported, and the refusal carries what the ladder PROVED:
            // confirmed teardown is `ProvenNotPerformed` (no prompt was ever
            // written and the container is provably gone), an unconfirmed one
            // is `ProvenAmbiguous` — never a blanket `before_the_container`,
            // which would claim a clean start even when the container's absence
            // was not observed.
            return Err(teardown_into_refusal(
                teardown,
                &attempt_root,
                attempt_tag,
                "session_refused",
                lifted.scrub(&format!(
                    "adapter `{}` refused to open a session: {refusal}",
                    turn.adapter.as_label(),
                )),
            )
            .await);
        }
    };

    let mut turn_end = TurnEndFindings::default();
    run_session_and_settle(
        session,
        teardown,
        stderr_reader,
        prompt_text,
        credential.turn_credential,
        &lifted,
        turn,
        frame,
        capsule,
        execution,
        request,
        attempt_tag,
        attempt_root,
        cancel,
        turn_deadline,
        &mut turn_end,
    )
    .await
    .map_err(|refusal| turn_end.noted_in(refusal))
}

/// What the embedded harness's turn end left that a refused turn's reason
/// names, read off its turn-end records: the ones in the evidence the worker
/// drained, and the ones the session's `close` made after that drain, when it
/// ran a turn end whose future the deadline race dropped
/// (`CleanupReport::turn_end`). The worker publishes the evidence only with a
/// completed turn's result; a refusal's reason is the durable record every
/// other outcome has.
#[derive(Debug, Default)]
struct TurnEndFindings {
    /// The `KillAll` fallback a `TurnEnd{kill_all}` record names
    /// (`unconfirmed`, `wire_broken`); a confirmed kill records nothing.
    kill_all: Option<smol_str::SmolStr>,
    /// The nonzero count of Code Mode workers a `CodeModeWorkersLive` record
    /// found live once the harness's shutdown returned or its grace expired.
    code_mode_workers_live: Option<u64>,
}

impl TurnEndFindings {
    /// Fold one source's records in. A turn end runs each step once, so each
    /// finding comes from at most one record.
    fn read(&mut self, records: &[kata_types::agent::SessionEvidenceEvent]) {
        use kata_types::agent::SessionEvidenceEvent;
        for record in records {
            match record {
                SessionEvidenceEvent::TurnEnd { step, outcome } if step == "kill_all" => {
                    self.kill_all = Some(outcome.clone());
                }
                SessionEvidenceEvent::CodeModeWorkersLive { live } if *live > 0 => {
                    self.code_mode_workers_live = Some(*live);
                }
                _ => {}
            }
        }
    }

    /// `refusal`, its reason carrying what was found: a failed turn is the one
    /// whose Code Mode cells nanocode detaches rather than ends, and any turn
    /// end may find its `KillAll` unanswered.
    fn noted_in(&self, mut refusal: CapsuleAttemptRefusal) -> CapsuleAttemptRefusal {
        use std::fmt::Write as _;
        if let Some(outcome) = &self.kill_all {
            let _ = write!(
                refusal.reason,
                "; kill_all: {outcome}: the embedded harness's turn end did not see its \
                 KillAll confirmed, so it closed the tool host's stdin, on which the tool host \
                 kills every process it started (the outcome did not wait for that)"
            );
        }
        if let Some(live) = self.code_mode_workers_live {
            let _ = write!(
                refusal.reason,
                "; code_mode_workers_live: {live} Code Mode worker(s) were live in this worker's \
                 process once the embedded harness's shutdown returned or its grace expired \
                 (process-wide; a worker counts until its interpreter process is reaped)"
            );
        }
        refusal
    }
}

/// The session-evidence publication bound, stated once so its `>` edge is
/// itself testable: `SESSION_EVIDENCE_BYTES` and under publishes; over refuses.
/// With per-field [`kata_types::redaction::LiftedSecrets::bound_field`] the
/// bound is reachable only through JSON-escape expansion (`\u00XX` is six
/// bytes per control byte — the evidence cells reach it that way).
fn session_evidence_over_bound(byte_len: u64) -> bool {
    byte_len > kata_types::agent::SESSION_EVIDENCE_BYTES
}

/// The attempt root's disposition after a teardown — removed when the
/// container's absence was confirmed, retained with the `teardown_ambiguous`
/// marker when it was not, so `kata doctor` names the tree kata cannot
/// account for rather than the sweep silently racing a live container.
fn settle_attempt_root(
    guard: Option<crate::attempt_root::OwnedAttemptRoot>,
    attempt_root: &std::path::Path,
    attempt_tag: &str,
    teardown_confirmed: bool,
    why: &'static str,
    outcome: &str,
) {
    match guard {
        Some(root) if teardown_confirmed => root.remove(attempt_tag, why),
        // The tree is retained for inspection: the container's fate is
        // unproven.
        Some(root) => root.retain_ambiguous(attempt_tag, outcome),
        None => {
            // A rig's fake placement carries no guard; the real one always
            // does. Removing the tree without the flock is exactly what the
            // guard exists to prevent, so this arm only logs.
            tracing::debug!(
                attempt = %attempt_tag,
                root = %attempt_root.display(),
                "interactive teardown carried no attempt-root guard (a rig's fake placement); \
                 the tree stays for the sweep"
            );
        }
    }
}

/// A launch refusal → the attempt's refusal, with the provenance the refusing
/// arm PROVED rather than the position its label guesses at.
///
/// `PostAssignment` is the arm that ran after the provider's `accepted`: a
/// container was started and the launch already swept it with
/// `kill_and_contain`, so the sweep's verdict IS the provenance —
/// confirmed-empty reads `ProvenNotPerformed` (kata owns the only prompt
/// channel and wrote no byte over it; the container is provably gone),
/// anything less is `ProvenAmbiguous`, because a container kata gave up
/// observing may still be live. Its own words carry the report verbatim, and
/// the lifted secret values are scrubbed first because the report quotes a
/// provider's strings.
///
/// Every other arm is pre-acceptance by construction — the launch's own
/// `?`-free structure keeps it that way — and reports `before_the_container`.
fn refusal_for_failed_launch(
    refusal: crate::interactive_capsule::InteractiveLaunchRefusal,
    lifted: &kata_types::redaction::LiftedSecrets,
) -> CapsuleAttemptRefusal {
    match refusal {
        crate::interactive_capsule::InteractiveLaunchRefusal::PostAssignment { reason, report } => {
            CapsuleAttemptRefusal::with_verdict(
                lifted.scrub(&format!(
                    "the provider had ACCEPTED the agent container when the launch refused \
                     — {reason}; the sweep's verdict: {report}",
                )),
                if report.residue().is_contained() {
                    ExecutionProvenanceVerdict::ProvenNotPerformed
                } else {
                    ExecutionProvenanceVerdict::ProvenAmbiguous
                },
            )
        }
        // The refusal's own words, not only its label: the label says WHICH check
        // refused, the text says what it found (the path, the error, the member) —
        // and this string is the one the record, `kata run show`, `--watch` and the
        // API execution view carry. Scrubbed for the reason the arm above is.
        other => CapsuleAttemptRefusal::before_the_container(KataError::Validation(lifted.scrub(
            &format!("the interactive launch refused before the container was assigned: {other}"),
        ))),
    }
}

/// A refusal ARMED AFTER the placement existed: the teardown ladder runs
/// first, the root settles on its verdict, and the refusal carries what the
/// ladder proved — confirmed teardown is `ProvenNotPerformed` (kata owns the
/// only prompt channel and wrote nothing; the container is provably gone), an
/// unconfirmed one is `ProvenAmbiguous`. No post-launch refusal may pick
/// `before_the_container` by label alone.
async fn teardown_into_refusal(
    mut teardown: Box<dyn InteractiveTeardown>,
    attempt_root: &std::path::Path,
    attempt_tag: &str,
    why: &'static str,
    reason: String,
) -> CapsuleAttemptRefusal {
    let guard = teardown.take_attempt_root();
    let outcome = teardown.teardown().await;
    let confirmed = outcome.is_confirmed();
    settle_attempt_root(
        guard,
        attempt_root,
        attempt_tag,
        confirmed,
        why,
        &format!("{outcome:?}"),
    );
    CapsuleAttemptRefusal::with_verdict(
        reason,
        if confirmed {
            ExecutionProvenanceVerdict::ProvenNotPerformed
        } else {
            ExecutionProvenanceVerdict::ProvenAmbiguous
        },
    )
}

/// The session half, after `open` — the prompt, the outcome classification
/// and the publication, so `execute_agent_turn` reads as the two halves it is.
#[allow(clippy::too_many_arguments)]
async fn run_session_and_settle(
    mut session: Box<dyn AgentSession>,
    teardown: Box<dyn InteractiveTeardown>,
    stderr_reader: Option<Box<dyn tokio::io::AsyncRead + Send + Unpin>>,
    prompt_text: String,
    turn_credential: Option<kata_types::agent::HarnessCredential>,
    lifted: &kata_types::redaction::LiftedSecrets,
    turn: &kata_types::execution_contract::AgentTurnSpec,
    frame: &CapsuleAssignment,
    capsule: &Capsule,
    execution: &CapsuleExecution<'_>,
    request: &crate::oci_driver::OciStageRequest<'_>,
    attempt_tag: &str,
    attempt_root: std::path::PathBuf,
    cancel: tokio::sync::oneshot::Receiver<String>,
    turn_deadline: tokio::time::Instant,
    turn_end: &mut TurnEndFindings,
) -> Result<WorkerMessage, CapsuleAttemptRefusal> {
    // The `/work` base snapshot and the attempt-root guard — taken BEFORE
    // `teardown()` consumes its handle, because the delta publishes after the
    // container's exit and the tree's disposition is decided from the same
    // verdict.
    let mut teardown = teardown;
    let work_snapshot = teardown.work_snapshot().cloned();
    let root_guard = teardown.take_attempt_root();
    // The egress proxy, taken beside the other teardown-owned state — `Some`
    // only on an `Egress` capsule; drained after the container's sweep, in the
    // shell arm's own order (stage completes, then the proxy's close).
    // THE CANCEL PLUMBING — the attempt's fenced stop becomes the session's
    // `CancelToken`, which the adapter's prompt loop polls; a closed sender is
    // "no stop requested" and settles nothing.
    let token = CancelToken::new();
    let watcher = {
        let token = token.clone();
        let attempt_tag = attempt_tag.to_owned();
        tokio::spawn(async move {
            if let Ok(reason) = cancel.await {
                tracing::info!(attempt = %attempt_tag, %reason, "agent turn: fenced stop reached the session");
                token.cancel();
            }
        })
    };

    // THE STDERR DRAIN — bounded at the capsule's `output_bytes` and written
    // to the same `capture/` spool the provider leaves for a shell stage, so
    // `publish_captures` is ONE verb across both arms. `stdout` is written
    // empty: on an interactive arm the toolhost's stdout IS the protocol, which
    // the codec consumed — there is no stage output on it to record.
    let spool = attempt_root.join(crate::oci_driver::ATTEMPT_SPOOL_DIRECTORY);
    std::fs::create_dir_all(&spool).map_err(|error| {
        CapsuleAttemptRefusal::before_the_container(KataError::Storage(format!(
            "the attempt's capture spool {} could not be created: {error}",
            spool.display(),
        )))
    })?;
    let stdout_spool = spool.join(kata_provider_protocol::capture::SPOOL_STDOUT);
    std::fs::write(&stdout_spool, b"").map_err(|error| {
        CapsuleAttemptRefusal::before_the_container(KataError::Storage(format!(
            "the stdout spool {} could not be written empty: {error}",
            stdout_spool.display(),
        )))
    })?;
    let bound = capsule.budgets().output_bytes;
    let stderr_drain = {
        let stderr_spool = spool.join(kata_provider_protocol::capture::SPOOL_STDERR);
        tokio::spawn(async move { drain_bounded(stderr_reader, &stderr_spool, bound).await })
    };

    let prompt = Prompt {
        text: prompt_text,
        model_hint: turn.model.clone(),
        effort_hint: turn.reasoning_effort.clone(),
        output_schema: turn.output_schema.clone(),
        credential: turn_credential,
    };
    // THE WALL CLOCK — armed at the launch and raced against the prompt leg
    // here. A harness that wedges in `next_frame` never polls the cancel token
    // (adapters read it at each loop head), so the token alone cannot unstick
    // a silent harness: the deadline is the only bound. On expiry the fenced
    // stop goes out and the grace lets a harness that CAN still answer confirm
    // honestly — its own outcome rides through, but the refusal names the
    // deadline, because a stop the wall clock demanded is not a stop kata
    // asked for. Past the grace the classification comes from the session's
    // OWN watermark (`session.issuance()` — read once `drop(prompting)`
    // releases the `&mut` borrow): still clean is the pre-issuance stop,
    // crossed is `Ambiguous` at exactly the class crossed. Naming
    // `ToolCall` for every wedged harness would claim a tool call may be out
    // for a process that never finished its handshake.
    // `Box::pin` and not `pin!`: the macro's hidden temporary would hold the
    // `&mut session` borrow to end of scope and fight `close`'s `self` move;
    // the Box is dropped below at the point the borrow must end.
    enum Race {
        /// The prompt leg answered before the deadline.
        Answered(TurnOutcome),
        /// The deadline fired and the session answered inside the grace —
        /// the outcome is the session's; the refusal still names the wall.
        AnsweredAfterDeadline(TurnOutcome),
        /// The deadline fired and the grace expired unanswered.
        Unconfirmed,
    }
    // The session's own stop grace when it states a longer one: an adapter
    // whose `prompt` ends its turn after a stop (the embedded harness kills
    // the capsule's processes and shuts its agent down first) would otherwise
    // lose a stop it confirmed to this race.
    let stop_grace = session
        .stop_grace()
        .map_or(TURN_CANCEL_GRACE, |grace| grace.max(TURN_CANCEL_GRACE));
    let mut prompting = Box::pin(session.prompt(&prompt, &token));
    let raced = tokio::select! {
        outcome = &mut prompting => Race::Answered(outcome),
        () = tokio::time::sleep_until(turn_deadline) => {
            token.cancel();
            match tokio::time::timeout(stop_grace, &mut prompting).await {
                Ok(outcome) => Race::AnsweredAfterDeadline(outcome),
                Err(_elapsed) => Race::Unconfirmed,
            }
        }
    };
    // The pinned future's `&mut session` must end HERE: `issuance` borrows it
    // and `close` below takes it by value, and an un-dropped `Pin` would hold
    // the borrow to end of scope.
    drop(prompting);
    watcher.abort();
    let timed_out_reason = |what_happened: String| {
        format!(
            "agent_turn_timed_out: the capsule's {} ms wall budget elapsed with the turn still \
             in flight; {what_happened}",
            capsule.budgets().wall_time_ms,
        )
    };
    // The deadline stop's outcome vocabulary: an answer inside the grace rides
    // its own arm with `deadline_fired` naming the wall; NO answer is
    // classified off the session's watermark — clean is a refusal all its
    // own (provably nothing issued, like an adapter `Refused`, but the stop
    // was the deadline's), crossed is `Ambiguous` at the crossed class.
    enum Settled {
        Outcome {
            outcome: TurnOutcome,
            deadline_fired: bool,
        },
        /// The deadline fired, the grace passed unanswered, and the
        /// session's watermark was never crossed — provably nothing issued.
        TimedOutBeforeIssuance,
    }
    let settled = match raced {
        Race::Answered(outcome) => Settled::Outcome {
            outcome,
            deadline_fired: false,
        },
        Race::AnsweredAfterDeadline(outcome) => Settled::Outcome {
            outcome,
            deadline_fired: true,
        },
        Race::Unconfirmed => match session.issuance() {
            Some(issued) => Settled::Outcome {
                outcome: TurnOutcome::Ambiguous {
                    issued,
                    evidence: format!(
                        "the fenced stop went out and {} ms of grace passed without the harness \
                         confirming it; the session's own watermark was already crossed at \
                         {issued:?}",
                        stop_grace.as_millis(),
                    ),
                },
                deadline_fired: true,
            },
            None => Settled::TimedOutBeforeIssuance,
        },
    };

    // THE EVIDENCE, drained BEFORE `close` consumes the session — the record
    // of what the session observed (auto-served permissions, refused
    // callbacks, foreign updates) lives nowhere else, so a caller that does
    // not drain it here loses it exactly when the toolhost goes away. `mut`:
    // the scratch commits below are the WORKER's own contribution, folded in
    // after teardown, which the drained record cannot already carry.
    let mut session_evidence = session.take_evidence();
    turn_end.read(&session_evidence.events);

    // THE CLOSE — always run, whatever the outcome: the session's own ladder
    // (terminate, wait, escalate) is the process-level teardown, and the
    // placement's teardown after it is the cgroup-level one. A dropped
    // session drops the process half, which cgroup-kills the subtree
    // unscored — so the ladder is run even on the ambiguous arm, because
    // "we cannot confirm the turn" is not a reason to leave the container.
    let close_report = session.close().await;
    // What `close`'s own run of a dropped turn's end found, made after the
    // drain above: only the refusal's reason can carry it.
    turn_end.read(close_report.turn_end());
    let egress_proxy = teardown.take_egress();
    let teardown_outcome = teardown.teardown().await;
    let egress_outcome = match egress_proxy {
        Some(proxy) => {
            let refusals = proxy.refusals().await;
            let refusals_dropped = proxy.refusals_dropped();
            let opened_tunnels = proxy.opened_tunnels();
            let relayed_bytes = proxy.relayed_bytes();
            let close = proxy.close().await;
            Some(crate::oci_driver::OciEgressOutcome {
                refusals,
                refusals_dropped,
                opened_tunnels,
                relayed_bytes,
                close,
            })
        }
        None => None,
    };
    let teardown_confirmed = match (&teardown_outcome, &egress_outcome) {
        // The shell arm's paired verdict: a confirmed sweep whose proxy never
        // drained reports the PROXY's ambiguity.
        (outcome, Some(egress)) if outcome.is_confirmed() && !egress.close.is_confirmed() => false,
        (outcome, _) => outcome.is_confirmed(),
    };
    let teardown_debug = format!("{teardown_outcome:?}");
    let settle = |why: &'static str| {
        settle_attempt_root(
            root_guard,
            &attempt_root,
            attempt_tag,
            teardown_confirmed,
            why,
            &teardown_debug,
        );
    };
    let (_stderr_spooled_len, stderr_exceeded) = stderr_drain
        .await
        .map_err(|error| {
            CapsuleAttemptRefusal::at_or_after_the_container(&format!(
                "the toolhost's stderr drain task did not join: {error}"
            ))
        })?
        .map_err(|error| {
            CapsuleAttemptRefusal::at_or_after_the_container(&format!(
                "the toolhost's stderr spool could not be written: {error}"
            ))
        })?;

    match settled {
        Settled::TimedOutBeforeIssuance => {
            settle("session_settled");
            Err(CapsuleAttemptRefusal::with_verdict(
                lifted.scrub(&timed_out_reason(format!(
                    "the fenced stop went out and {} ms of grace passed unanswered, and \
                     the session's own watermark was never crossed — the harness never \
                     reached an issuance-capable frame",
                    stop_grace.as_millis(),
                ))),
                if teardown_confirmed {
                    ExecutionProvenanceVerdict::ProvenNotPerformed
                } else {
                    ExecutionProvenanceVerdict::ProvenAmbiguous
                },
            ))
        }
        Settled::Outcome {
            outcome,
            deadline_fired,
        } => match outcome {
            TurnOutcome::Completed {
                response,
                usage,
                model,
                response_exceeded,
                stop_reason,
            } => {
                if !teardown_confirmed {
                    settle("teardown_ambiguous");
                    return Err(CapsuleAttemptRefusal::at_or_after_the_container(&format!(
                        "the agent container's cgroup teardown could not confirm the container's subtree \
                     empty: {teardown_debug} (session close: {close_report:?})"
                    )));
                }
                let published = (|| -> Result<_, CapsuleAttemptRefusal> {
                    // The response, scrubbed of every lifted value BEFORE it
                    // reaches a durable blob — and fragment-dropped when the
                    // adapter's RAW bound cut mid-value, because the scrub
                    // cannot match the head a straddle leaves at the tail.
                    // The scrubbed text is then cut at `output_bytes` again:
                    // a short lifted value replaced by the longer
                    // `[redacted]` can grow the answer past the bound, and an
                    // adoption-facing response must fit the claim.
                    let scrubbed_response = lifted.scrub(&response);
                    let scrubbed_response = if response_exceeded {
                        lifted.drop_trailing_fragment(&scrubbed_response).to_owned()
                    } else {
                        scrubbed_response
                    };
                    let (response, response_cut) = lifted.cut(
                        &scrubbed_response,
                        usize::try_from(capsule.budgets().output_bytes).unwrap_or(usize::MAX),
                    );
                    let response_exceeded = response_exceeded || response_cut;
                    let response_receipt =
                        execution
                            .sink
                            .publish(response.as_bytes())
                            .map_err(|error| {
                                CapsuleAttemptRefusal::at_or_after_the_container(&format!(
                                    "the turn's response did not publish to this worker's content \
                             store: {error}"
                                ))
                            })?;
                    let response_ref = ArtifactRef::new(
                        response_receipt.object_id(),
                        response_receipt.size(),
                        ArtifactPrivacy::Private,
                    );
                    let stage_usage = usage.as_ref().map(|usage| {
                        StageUsage::metered(
                            usage,
                            meter_agent_turn(turn, usage),
                            cache_savings_micro_usd(turn, usage),
                        )
                    });
                    // THE SCRATCH COMMITS — read while the attempt root still
                    // exists and AFTER teardown confirmed nothing in the
                    // container can still write, folded INTO the session's
                    // record before it serializes. The blob the report names is
                    // the one durable surface the turn's evidence gets, so the
                    // scratch repository's own account rides it rather than a
                    // wire field of its own: the scratch branch's tip is the
                    // turn's own left-behind, walked back to the declared base
                    // with its ancestry hidden so the evidence names what the
                    // agent made, not what it was handed — every text field
                    // scrubbed against the lifted values first, because a
                    // commit message can carry anything the agent held.
                    session_evidence.scratch_commits = match capsule.git_view() {
                        Some(view) => crate::git_view::scratch_commits(
                            &attempt_root,
                            frame.execution_id,
                            frame.attempt_id,
                            view,
                            lifted,
                        )
                        .map_err(|error| {
                            CapsuleAttemptRefusal::at_or_after_the_container(&format!(
                                "the turn completed but its scratch repository would not report \
                                 what it holds: {error}"
                            ))
                        })?,
                        None => Vec::new(),
                    };
                    // The session's observed-event record — refused requests,
                    // model calls, tool results, the scratch commits beside them — published Private like
                    // the response. A completed turn carries it unconditionally:
                    // an empty record is the honest "the harness asked for
                    // nothing", and a report without the ref is an adoption
                    // refusal upstream.
                    let evidence_bytes =
                        serde_json::to_vec(&session_evidence).map_err(|error| {
                            CapsuleAttemptRefusal::at_or_after_the_container(&format!(
                                "the session evidence could not serialize for publication: {error}"
                            ))
                        })?;
                    if session_evidence_over_bound(evidence_bytes.len() as u64) {
                        return Err(CapsuleAttemptRefusal::at_or_after_the_container(&format!(
                            "the session evidence serializes to {} bytes, over the {}-byte bound — \
                         a session record that will not fit the durable claim is refused rather \
                         than truncated silently",
                            evidence_bytes.len(),
                            kata_types::agent::SESSION_EVIDENCE_BYTES,
                        )));
                    }
                    let evidence_receipt =
                        execution.sink.publish(&evidence_bytes).map_err(|error| {
                            CapsuleAttemptRefusal::at_or_after_the_container(&format!(
                                "the session evidence did not publish to this worker's content \
                             store: {error}"
                            ))
                        })?;
                    let evidence_ref = ArtifactRef::new(
                        evidence_receipt.object_id(),
                        evidence_receipt.size(),
                        ArtifactPrivacy::Private,
                    );
                    let report = AgentTurnReport {
                        response: response_ref,
                        usage: stage_usage,
                        adapter: turn.adapter,
                        model_reported: model,
                        session_evidence: Some(evidence_ref),
                        stop_reason,
                    };
                    let out = attempt_root.join(crate::oci_bundle::ATTEMPT_OUT_DIRECTORY);
                    let (result, _manifest) = crate::result_publication::publish_result_tree(
                        &out,
                        capsule.budgets(),
                        execution.sink,
                    )
                    .map_err(|error| CapsuleAttemptRefusal::at_or_after_the_container(&error))?;
                    let work_delta = capsule
                        .inputs()
                        .iter()
                        .find(|mapping| {
                            mapping.guest_path.as_str() == crate::work_delta::WORK_GUEST_ROOT
                        })
                        .map(|mapping| {
                            crate::work_delta::publish_work_delta(
                                &attempt_root.join(crate::oci_bundle::ATTEMPT_WORK_DIRECTORY),
                                mapping.artifact,
                                request.trees,
                                capsule.budgets(),
                                execution.sink,
                                work_snapshot.as_ref(),
                                capsule.work_view(),
                            )
                        })
                        .transpose()
                        .map_err(|error| {
                            CapsuleAttemptRefusal::at_or_after_the_container(&error)
                        })?;
                    // The ONE combined capture bound: the response took
                    // `response.len()` of `output_bytes`; the drained stderr
                    // keeps what is left, scrubbed before any cut so no lifted
                    // value — whole or straddling the raw drain's own cut —
                    // lands in the published capture.
                    let stderr_spool = attempt_root
                        .join(crate::oci_driver::ATTEMPT_SPOOL_DIRECTORY)
                        .join(kata_provider_protocol::capture::SPOOL_STDERR);
                    let raw_stderr = std::fs::read(&stderr_spool).map_err(|error| {
                        CapsuleAttemptRefusal::at_or_after_the_container(&format!(
                            "the toolhost's stderr spool {} could not be read for scrubbing: \
                             {error}",
                            stderr_spool.display(),
                        ))
                    })?;
                    let stderr_room = capsule
                        .budgets()
                        .output_bytes
                        .saturating_sub(response.len() as u64);
                    let scrubbed_stderr = lifted.scrub(&String::from_utf8_lossy(&raw_stderr));
                    // The drain's RAW spool cut can leave a lifted value's
                    // head at the tail — a fragment the whole-value scrub
                    // cannot see — so an exceeded drain drops it by shape
                    // before the room the response left is applied.
                    let scrubbed_stderr = if stderr_exceeded {
                        lifted.drop_trailing_fragment(&scrubbed_stderr).to_owned()
                    } else {
                        scrubbed_stderr
                    };
                    let (bounded_stderr, cut_dropped) = lifted.cut(
                        &scrubbed_stderr,
                        usize::try_from(stderr_room).unwrap_or(usize::MAX),
                    );
                    let stderr_dropped = stderr_exceeded || cut_dropped;
                    // The rewrite keys on the BYTES, not the length: a lifted
                    // value exactly `[redacted]`'s ten bytes scrubs to the
                    // same length, and a length compare would publish the
                    // raw spool.
                    if bounded_stderr.as_bytes() != raw_stderr.as_slice() {
                        std::fs::write(&stderr_spool, bounded_stderr.as_bytes()).map_err(
                            |error| {
                                CapsuleAttemptRefusal::at_or_after_the_container(&format!(
                                    "the stderr spool {} could not be rewritten scrubbed and \
                                     bounded: {error}",
                                    stderr_spool.display(),
                                ))
                            },
                        )?;
                    }
                    let stderr_len = bounded_stderr.len() as u64;
                    let (stdout_ref, stderr_ref) =
                        publish_captures(&attempt_root, 0, stderr_len, execution.sink).map_err(
                            |error| CapsuleAttemptRefusal::at_or_after_the_container(&error),
                        )?;
                    Ok((
                        report,
                        result,
                        work_delta,
                        stdout_ref,
                        stderr_ref,
                        response_exceeded || stderr_dropped,
                    ))
                })();
                let (report, result, work_delta, stdout_ref, stderr_ref, capture_exceeded) =
                    match published {
                        Ok(parts) => {
                            settle("result_published");
                            parts
                        }
                        Err(refusal) => {
                            settle("result_publication_refused");
                            return Err(refusal);
                        }
                    };
                Ok(WorkerMessage::CompletedCapsule {
                    attempt_id: frame.attempt_id,
                    fence: AttemptFence::echoing_capsule(frame),
                    result,
                    work_delta,
                    exit_code: Some(0),
                    stdout: stdout_ref,
                    stderr: stderr_ref,
                    capture_exceeded,
                    agent: Some(report),
                    // The proxy's own record, sequenced like the shell arm's —
                    // `[]` exactly when no proxy ran (an `Offline` turn).
                    egress_refusals: egress_outcome
                        .as_ref()
                        .map(|outcome| {
                            outcome
                                .refusals
                                .iter()
                                .enumerate()
                                .map(|(seq, refusal)| refusal.report(frame.attempt_id, seq as u64))
                                .collect()
                        })
                        .unwrap_or_default(),
                    provenance:
                        kata_types::execution_provenance::ExecutionProvenance::local_oci_runtime(
                            "this worker resolved the capsule from its own content store, planned the \
                         interactive container the turn's kind fixes, spoke the declared \
                         adapter's protocol over its FIFOs, and confirmed the container's cgroup \
                         subtree empty before publishing its /out",
                        ),
                })
            }
            TurnOutcome::Refused { reason } => {
                settle("session_settled");
                Err(CapsuleAttemptRefusal::before_the_container(
                    KataError::Validation(lifted.scrub(&if deadline_fired {
                        timed_out_reason(format!(
                            "the harness answered inside the grace having refused the turn \
                             before issuing it — adapter `{}`: {reason}",
                            turn.adapter.as_label(),
                        ))
                    } else {
                        format!(
                            "adapter `{}` refused the turn before issuing it: {reason}",
                            turn.adapter.as_label(),
                        )
                    })),
                ))
            }
            TurnOutcome::Cancelled { usage } => {
                settle("session_settled");
                // What kata observed of the stop, never wider: the arm is
                // either a stop the harness confirmed or one before the
                // watermark nobody confirmed, and only the session's close
                // report records which.
                let stopped = match (
                    close_report.harness_acknowledged_cancel(),
                    token.is_cancelled(),
                ) {
                    (true, _) => "the harness confirmed the cancel",
                    (false, true) => {
                        "the turn stopped before it issued anything, and the harness did not \
                         confirm the stop"
                    }
                    (false, false) => {
                        "the turn stopped before it issued anything, on a stop kata never \
                         asked for (not a confirmed cancel)"
                    }
                };
                Err(
                    CapsuleAttemptRefusal::at_or_after_the_container(&lifted.scrub(
                        &if deadline_fired {
                            timed_out_reason(format!(
                                "the fenced stop went out and, inside the {} ms grace, {stopped} \
                                 (usage: {usage:?})",
                                stop_grace.as_millis(),
                            ))
                        } else if token.is_cancelled() {
                            format!(
                                "the fenced stop cancelled the turn — {stopped}, and the cancel \
                                 path's own settlement names it, never the turn's (usage: \
                                 {usage:?})"
                            )
                        } else {
                            format!("{stopped} (usage: {usage:?})")
                        },
                    ))
                    .with_usage(Some(match usage {
                        // The burn the harness reported, metered exactly like a
                        // completion's would be — a cancelled turn that spent is not
                        // a free turn.
                        Some(usage) => StageUsage::metered(
                            &usage,
                            meter_agent_turn(turn, &usage),
                            cache_savings_micro_usd(turn, &usage),
                        ),
                        // The burn the harness could not report is `Unavailable`,
                        // naming the adapter and the turn's declared model — never
                        // an authoritative 0 on a call that was provably in flight.
                        None => StageUsage::unmetered(
                            turn.adapter.as_label(),
                            turn.model.as_ref().map_or("", smol_str::SmolStr::as_str),
                        ),
                    })),
                )
            }
            TurnOutcome::ProviderFailed {
                class,
                reason,
                charge,
                tool_called,
            } => {
                settle("session_settled");
                let failed = format!(
                    "the model provider failed the turn ({}): {reason}",
                    class.as_str()
                );
                let failed = if deadline_fired {
                    timed_out_reason(failed)
                } else {
                    failed
                };
                // THE REFUSED SET of a provider failure: what the turn did reaches
                // beyond its capsule only through a tool call in a capsule that can
                // reach the network, so a tool call there keeps the attempt
                // ambiguous; so does a teardown that could not confirm the
                // container's subtree empty, as for a completed turn. Every other
                // provider failure is known: the requests the provider answered,
                // and capsule-local effects nothing publishes.
                let reached_beyond =
                    tool_called && !matches!(capsule.network(), CapsuleNetwork::Offline);
                if reached_beyond || !teardown_confirmed {
                    let why = if reached_beyond {
                        "a tool call ran in a capsule that can reach the network".to_owned()
                    } else {
                        format!(
                            "the agent container's cgroup teardown could not confirm the container's \
                             subtree empty: {teardown_debug}"
                        )
                    };
                    let issued = if tool_called {
                        MayHaveIssued::ToolCall
                    } else {
                        MayHaveIssued::ModelTokens
                    };
                    return Err(CapsuleAttemptRefusal::at_or_after_the_container(
                        &lifted.scrub(&format!(
                            "the turn's answer is unknown (issued={issued:?}): {failed}; {why}"
                        )),
                    ));
                }
                let usage = match charge {
                    // `None` on a not-performed refusal is the authoritative `0`.
                    FailedTurnCharge::Nothing => None,
                    FailedTurnCharge::Metered(usage) => Some(StageUsage::metered(
                        &usage,
                        meter_agent_turn(turn, &usage),
                        cache_savings_micro_usd(turn, &usage),
                    )),
                    FailedTurnCharge::Unknown => Some(StageUsage::unmetered(
                        turn.adapter.as_label(),
                        turn.model.as_ref().map_or("", smol_str::SmolStr::as_str),
                    )),
                };
                Err(CapsuleAttemptRefusal::with_verdict(
                    lifted.scrub(&format!(
                        "adapter `{}`: {failed}; nothing the turn did left its capsule but \
                         the model requests the provider answered, and nothing was published",
                        turn.adapter.as_label(),
                    )),
                    ExecutionProvenanceVerdict::ProvenNotPerformed,
                )
                .with_usage(usage)
                .with_provider_failure(class))
            }
            TurnOutcome::Ambiguous { issued, evidence } => {
                settle("session_settled");
                let body = format!("the turn's answer is unknown (issued={issued:?}): {evidence}");
                Err(CapsuleAttemptRefusal::at_or_after_the_container(
                    &lifted.scrub(&if deadline_fired {
                        timed_out_reason(body)
                    } else {
                        body
                    }),
                ))
            }
        },
    }
}

/// The stderr drain, bounded: the first `bound` bytes land in the spool;
/// whether more arrived is reported so `capture_exceeded` carries it.
async fn drain_bounded(
    reader: Option<Box<dyn tokio::io::AsyncRead + Send + Unpin>>,
    spool: &std::path::Path,
    bound: u64,
) -> KataResult<(u64, bool)> {
    use tokio::io::AsyncReadExt as _;
    let mut written = 0_u64;
    let mut exceeded = false;
    let mut buffer = vec![0_u8; 8192];
    let mut writer = std::io::BufWriter::new(std::fs::File::create(spool).map_err(|error| {
        KataError::Storage(format!("stderr spool {}: {error}", spool.display()))
    })?);
    if let Some(mut reader) = reader {
        loop {
            let read = reader
                .read(&mut buffer)
                .await
                .map_err(|error| KataError::Storage(format!("toolhost stderr read: {error}")))?;
            if read == 0 {
                break;
            }
            let keep = usize::try_from(bound.saturating_sub(written))
                .unwrap_or(usize::MAX)
                .min(read);
            if keep < read {
                exceeded = true;
            }
            if keep > 0 {
                std::io::Write::write_all(&mut writer, &buffer[..keep]).map_err(|error| {
                    KataError::Storage(format!("stderr spool {}: {error}", spool.display()))
                })?;
                written += keep as u64;
            }
            // Keep draining to EOF so the toolhost's writes do not block on a
            // full pipe; the breach is already recorded.
        }
    }
    std::io::Write::flush(&mut writer).map_err(|error| {
        KataError::Storage(format!("stderr spool {}: {error}", spool.display()))
    })?;
    Ok((written, exceeded))
}

/// The turn's metered cost — the worker's own `meter_call` under the
/// credential mode the turn declares (`Subscription` reports `Unavailable`
/// and is never estimated). `Unstated` always: adapters report no provider-stated
/// charge unless the protocol surfaces one.
fn meter_agent_turn(
    turn: &kata_types::execution_contract::AgentTurnSpec,
    usage: &TokenUsage,
) -> MeteredCost {
    let model = turn.model.as_ref().map_or("", smol_str::SmolStr::as_str);
    let Some(backend) = turn.adapter.billing_backend() else {
        return MeteredCost::Unavailable {
            backend: smol_str::SmolStr::new(turn.adapter.as_label()),
            model: smol_str::SmolStr::new(model),
        };
    };
    // The mode the node's `credential = { mode }` declared — `subscription`
    // has no per-token price an estimate can bound, so it lands as
    // `Unavailable` with the tokens kept, never `Estimated`. A turn with no
    // declared credential defaults `api_key`: the provider answered anyway,
    // and the mode that prices it is the only one the declaration could
    // have meant.
    let mode = turn
        .credential
        .as_ref()
        .map_or(CredentialMode::ApiKey, |reference| reference.mode);
    crate::pricing::meter_call(
        backend,
        model,
        *usage,
        kata_types::metering::ProviderCost::Unstated,
        mode,
    )
}

/// The cache-read savings the metered record carries, on the same backend —
/// `0` when the adapter has no billing row, for the same honesty rule as
/// `meter_agent_turn`'s `None` arm.
fn cache_savings_micro_usd(
    turn: &kata_types::execution_contract::AgentTurnSpec,
    usage: &TokenUsage,
) -> u64 {
    let Some(backend) = turn.adapter.billing_backend() else {
        return 0;
    };
    let model = turn.model.as_ref().map_or("", smol_str::SmolStr::as_str);
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    {
        (crate::pricing::cache_read_savings_usd(backend, model, *usage) * 1_000_000.0) as u64
    }
}

/// The `Harness` family's crash point: the node hosting the embedded harness
/// ends once the harness reports its first completed model call — the provider
/// answered, so the attempt cannot be PROVEN NOT PERFORMED, and the attempt's
/// terminal is not built.
const FIRST_PROVIDER_EVENT: &str = "after_first_provider_event";

/// The observation sink a turn gets only while [`FIRST_PROVIDER_EVENT`] is armed:
/// it fires the point at the first `model_call_completed` and forwards every
/// observation to the stage's own sink, if it authored one. An unarmed process
/// never builds it, so a production turn's sink is exactly the authored one.
#[derive(Debug)]
struct FirstProviderEvent {
    inner: Option<Arc<dyn SessionProgressSink>>,
}

impl SessionProgressSink for FirstProviderEvent {
    fn observe(&self, observation: SessionObservation) {
        if observation.kind == "model_call_completed" {
            kata_core::fault_inject::operational_crash_point(FIRST_PROVIDER_EVENT);
        }
        if let Some(inner) = &self.inner {
            inner.observe(observation);
        }
    }
}

#[cfg(test)]
mod tests {
    //! The post-acceptance refusal vocabulary and its provenance, and what a
    //! refused or retained attempt leaves on the disk.
    //!
    //! The live cells (`tests/nanocode_capsule_live.rs`,
    //! `tests/interactive_capsule_live.rs`) prove the whole composition against a
    //! certified provider. What a unit
    //! cell can isolate — and must, because a live provider cannot be made to
    //! fault after `accepted` on cue — is the mapping: which verdict a refusal
    //! arm CARRIES, and which bytes the settle deletes.

    use super::*;
    use crate::provider_supervisor::{CrashPrecondition, ProviderCrashReport};
    use kata_agent::adapter::scope::ObservationClass;
    use kata_agent::resource_bounds::{AmbiguousTeardown, TeardownOutcome, TeardownProbe};

    /// The stage's own sink, recording each kind it is handed.
    #[derive(Debug, Default)]
    struct Recorded(std::sync::Mutex<Vec<&'static str>>);

    impl SessionProgressSink for Recorded {
        fn observe(&self, observation: SessionObservation) {
            self.0.lock().unwrap().push(observation.kind);
        }
    }

    fn observation(kind: &'static str) -> SessionObservation {
        SessionObservation {
            kind,
            text: None,
            class: ObservationClass::Milestone,
        }
    }

    /// **`operational.after_first_provider_event` ends the process at the
    /// harness's first completed model call, and nowhere before it.** An armed
    /// child hands the sink a `model_call_started`, then a `model_call_completed`:
    /// the stage's own sink received the first (forwarded), the child printed
    /// past it, and it died by SIGABRT at the second, naming the point on stderr
    /// and printing nothing after it — read off its wait status and its pipes.
    ///
    /// **Would red if:** the point fired on any observation (the child would die
    /// before its first line), or the sink swallowed the stage's own observations
    /// (the forwarded count would be 0).
    #[test]
    fn the_first_provider_event_point_ends_the_process_at_the_first_completed_call() {
        const CHILD: &str = "KATA_WORKER_FIRST_PROVIDER_EVENT_CHILD";
        const TEST: &str = "agent_turn::tests::the_first_provider_event_point_ends_the_process_at_the_first_completed_call";
        if std::env::var_os(CHILD).is_some() {
            assert!(
                kata_core::fault_inject::operational_point_armed(FIRST_PROVIDER_EVENT),
                "the child is armed"
            );
            let stage = Arc::new(Recorded::default());
            let sink = FirstProviderEvent {
                inner: Some(Arc::clone(&stage) as Arc<dyn SessionProgressSink>),
            };
            sink.observe(observation("model_call_started"));
            println!("forwarded={}", stage.0.lock().unwrap().len());
            sink.observe(observation("model_call_completed"));
            println!("survived the completed call");
            return;
        }
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([TEST, "--exact", "--nocapture", "--test-threads=1"])
            .env(CHILD, "1")
            .env(
                "KATA_FAULT_INJECT",
                "operational.after_first_provider_event",
            )
            .output()
            .expect("spawn the armed child");
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        use std::os::unix::process::ExitStatusExt as _;
        assert_eq!(
            output.status.signal(),
            Some(libc::SIGABRT),
            "the armed child dies by SIGABRT: {:?}\nstdout:\n{stdout}\nstderr:\n{stderr}",
            output.status
        );
        assert!(
            stdout.contains("forwarded=1"),
            "the started call passed and reached the stage's sink:\n{stdout}"
        );
        assert!(
            !stdout.contains("survived the completed call"),
            "nothing ran past the point:\n{stdout}"
        );
        assert!(
            stderr.contains("crash point reached: operational.after_first_provider_event"),
            "the child died IN the point:\n{stderr}"
        );
        assert!(
            !kata_core::fault_inject::operational_point_armed(FIRST_PROVIDER_EVENT),
            "an unarmed process builds no harness crash sink"
        );
    }

    /// **A `nanocode_openai` turn is `Unavailable` under every credential mode;
    /// a `nanocode_anthropic` turn is priced on `api_key` and `Unavailable` on a
    /// subscription.** `nanocode_openai` calls OpenAI's models, but the built-in
    /// table is not re-verified (D1 §2.7), so no turn of it is estimated — not on
    /// a model the table prices (`gpt-5.4-mini`), not on one it does not
    /// (`gpt-6-luna`), and not under a `subscription` login. `nanocode_anthropic`
    /// bills against the `anthropic` rows: its `api_key` turn on
    /// `claude-sonnet-5-5` is `Estimated` from the table ($2 in / $10 out per
    /// MTok: 1M in + 100k out = $3), and its subscription turn is `Unavailable`
    /// naming its billing backend (`anthropic`).
    ///
    /// **Would red if:** `nanocode_openai` were given a rate table (its `api_key`
    /// turns would be `Estimated`), `nanocode_anthropic` were left unpriced or
    /// priced on a subscription, or an unpriced turn were floored or zero.
    #[test]
    fn only_a_nanocode_anthropic_api_key_turn_is_priced() {
        use kata_types::agent::AdapterKind;
        use kata_types::execution_contract::{AgentTurnSpec, CredentialSource, TurnCredentialRef};
        use kata_types::metering::MeteredCost;
        let turn =
            |adapter: AdapterKind, model: &str, mode: CredentialMode, source| AgentTurnSpec {
                adapter,
                model: Some(smol_str::SmolStr::new(model)),
                reasoning_effort: None,
                output_schema: None,
                prompt: kata_types::execution_contract::ArtifactId(
                    kata_types::primitives::ContentHash::new([7; 32]),
                ),
                credential: Some(TurnCredentialRef { mode, source }),
                env: std::collections::BTreeMap::new(),
            };
        let env = || CredentialSource::EnvVar {
            var: smol_str::SmolStr::new("OPENAI_API_KEY"),
        };
        let usage = TokenUsage {
            input: 1_000_000,
            output: 100_000,
            cache_read: 0,
            cache_write: 0,
        };
        for (adapter, model, mode, source) in [
            (
                AdapterKind::NanocodeOpenai,
                "gpt-5.4-mini",
                CredentialMode::ApiKey,
                env(),
            ),
            (
                AdapterKind::NanocodeOpenai,
                "gpt-6-luna",
                CredentialMode::ApiKey,
                env(),
            ),
            (
                AdapterKind::NanocodeOpenai,
                "gpt-5.4-mini",
                CredentialMode::Subscription,
                CredentialSource::KataLogin,
            ),
            (
                AdapterKind::NanocodeAnthropic,
                "claude-sonnet-5-5",
                CredentialMode::Subscription,
                CredentialSource::KataLogin,
            ),
        ] {
            // An unpriced kind names itself; a priced kind's subscription turn
            // names its billing backend.
            let backend = adapter
                .billing_backend()
                .map_or(adapter.as_label(), |backend| backend.label());
            assert_eq!(
                meter_agent_turn(&turn(adapter, model, mode, source), &usage),
                MeteredCost::Unavailable {
                    backend: backend.into(),
                    model: model.into(),
                },
                "{adapter:?} {model} {mode:?}"
            );
        }
        assert_eq!(
            meter_agent_turn(
                &turn(
                    AdapterKind::NanocodeAnthropic,
                    "claude-sonnet-5-5",
                    CredentialMode::ApiKey,
                    env(),
                ),
                &usage
            ),
            MeteredCost::Estimated {
                micro_usd: 3_000_000,
                basis: kata_types::metering::EstimateBasis::PriceTable {
                    rates_as_of: crate::pricing::PRICE_TABLE_AS_OF.into(),
                },
            },
        );
    }
    /// A report as `refuse_after_accept!` produces one: the provider had
    /// accepted and framed, and the teardown verdict is the parameter under
    /// test.
    fn post_acceptance_report(teardown: TeardownOutcome) -> Box<ProviderCrashReport> {
        Box::new(ProviderCrashReport::fabricated(
            CrashPrecondition::AcceptedAndFramed {
                assignment_id: "attempt-x".to_owned(),
                frames_read: 3,
            },
            teardown,
        ))
    }

    /// A post-acceptance refusal whose sweep confirmed the subtree's absence is
    /// PROVEN NOT PERFORMED — the prompt was never written over kata's FIFOs
    /// and the container is provably gone — and the report's own words reach
    /// the reason, with a lifted credential scrubbed before either is durable.
    ///
    /// COUNTERFACTUAL: drop the `PostAssignment` arm from
    /// `refusal_for_failed_launch` and this arm reports
    /// `ProvenNotPerformed` anyway but loses the sweep's words; drop the
    /// `is_contained()` read and an ambiguous sweep claims the same verdict —
    /// the next test falsifies that.
    #[test]
    fn a_post_assignment_refusal_with_a_confirmed_sweep_is_proven_not_performed() {
        let refusal = refusal_for_failed_launch(
            crate::interactive_capsule::InteractiveLaunchRefusal::PostAssignment {
                reason: "the egress handoff never arrived: planted-token-a1".to_owned(),
                report: post_acceptance_report(TeardownOutcome::Confirmed {
                    probe: TeardownProbe::CgroupPopulation,
                    elapsed_ms: 1,
                }),
            },
            &kata_types::redaction::LiftedSecrets::new(vec!["planted-token-a1".to_owned()]),
        );
        assert_eq!(
            refusal.performed,
            ExecutionProvenanceVerdict::ProvenNotPerformed
        );
        assert!(
            refusal.reason.contains("ACCEPTED"),
            "the refusal must SAY the provider accepted, not claim a clean start: {}",
            refusal.reason
        );
        assert!(
            !refusal.reason.contains("planted-token-a1"),
            "a lifted credential may not reach the durable reason: {}",
            refusal.reason
        );
    }

    /// The same refusal under a sweep that could NOT confirm absence is
    /// AMBIGUOUS — never a `before_the_container` claim, which a live
    /// container would make a lie.
    #[test]
    fn a_post_assignment_refusal_with_an_unconfirmed_sweep_is_ambiguous() {
        let refusal = refusal_for_failed_launch(
            crate::interactive_capsule::InteractiveLaunchRefusal::PostAssignment {
                reason: "the egress proxy refused its listener".to_owned(),
                report: post_acceptance_report(TeardownOutcome::Ambiguous {
                    reason: AmbiguousTeardown::Unobservable(
                        "the outer cgroup was never delegated".to_owned(),
                    ),
                    elapsed_ms: 1,
                }),
            },
            &kata_types::redaction::LiftedSecrets::none(),
        );
        assert_eq!(
            refusal.performed,
            ExecutionProvenanceVerdict::ProvenAmbiguous
        );
    }

    /// A pre-acceptance PLAN refusal carries its own words — the label AND
    /// what the refusing check found — with a lifted credential scrubbed.
    ///
    /// Watched red: with the arm formatting `other.label()` alone, the reason
    /// is `...assigned: plan_refused` and the planted path is absent.
    #[test]
    fn a_plan_refusal_carries_its_reason_not_only_its_label() {
        let refusal = refusal_for_failed_launch(
            crate::interactive_capsule::InteractiveLaunchRefusal::Placement(
                crate::oci_driver::OciDriveRefusal::PlanRefused(KataError::Validation(
                    "the egress handoff endpoint /planted/handoff.sock could not be bound: \
                     planted-token-b2"
                        .to_owned(),
                )),
            ),
            &kata_types::redaction::LiftedSecrets::new(vec!["planted-token-b2".to_owned()]),
        );
        assert_eq!(
            refusal.performed,
            ExecutionProvenanceVerdict::ProvenNotPerformed
        );
        for needle in [
            "before the container was assigned",
            "plan_refused",
            "the egress handoff endpoint /planted/handoff.sock could not be bound",
        ] {
            assert!(
                refusal.reason.contains(needle),
                "the reason carries `{needle}`: {}",
                refusal.reason
            );
        }
        assert!(
            !refusal.reason.contains("planted-token-b2"),
            "a lifted credential may not reach the durable reason: {}",
            refusal.reason
        );
    }

    /// A pre-acceptance launch refusal still reports the
    /// before-the-container vocabulary — the `PostAssignment` arm may not
    /// widen to cover what `accepted` never described.
    #[test]
    fn a_pre_acceptance_refusal_stays_proven_not_performed() {
        let refusal = refusal_for_failed_launch(
            crate::interactive_capsule::InteractiveLaunchRefusal::StdioUnavailable {
                path: std::path::PathBuf::from("/nonexistent/fifo"),
                error: "a fabricated open failure".to_owned(),
            },
            &kata_types::redaction::LiftedSecrets::none(),
        );
        assert_eq!(
            refusal.performed,
            ExecutionProvenanceVerdict::ProvenNotPerformed
        );
        assert!(
            refusal.reason.contains("before the container was assigned"),
            "{}",
            refusal.reason
        );
    }

    /// The retention arm: a root kata retains for inspection keeps its tree
    /// and gains the `TEARDOWN_AMBIGUOUS` marker.
    ///
    /// COUNTERFACTUAL: route `settle_attempt_root`'s unconfirmed arm to
    /// `remove` and the first assertion fails.
    #[test]
    fn an_ambiguously_retained_root_keeps_the_tree_under_its_marker() {
        let dir = tempfile::tempdir().expect("a tempdir");
        let root_path = dir.path().join("attempt-9");
        std::fs::create_dir_all(root_path.join("work")).unwrap();
        let guard = crate::attempt_root::OwnedAttemptRoot::acquire(&root_path)
            .expect("the root's lock acquires");

        settle_attempt_root(
            Some(guard),
            &root_path,
            "attempt-9",
            false,
            "teardown_ambiguous",
            "a fabricated ambiguous outcome",
        );

        assert!(
            root_path.exists(),
            "an unconfirmed teardown retains the tree for inspection"
        );
        assert!(
            root_path
                .join(crate::attempt_root::TEARDOWN_AMBIGUOUS_MARKER)
                .exists(),
            "the retained tree carries its marker"
        );
    }

    #[test]
    fn the_session_evidence_bound_refuses_over_and_never_at() {
        // The durable bound's refused set is `>`, stated once so the edge
        // cannot rot: ON it publishes, one byte over refuses.
        assert!(!session_evidence_over_bound(
            kata_types::agent::SESSION_EVIDENCE_BYTES
        ));
        assert!(session_evidence_over_bound(
            kata_types::agent::SESSION_EVIDENCE_BYTES + 1
        ));
        assert!(!session_evidence_over_bound(0));
    }
}
