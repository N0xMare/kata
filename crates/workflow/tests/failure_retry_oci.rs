//! FAILURE retries on the `oci` capsule route: a plain stage's
//! failed attempt re-run on its seat chain (`[i].child(k)`), never for a PROVEN
//! AMBIGUOUS attempt: a transient model provider failure on the same agent,
//! twice, each after its backoff, on any plain stage and on a `loop(..)`
//! member (through the loop's own walk); any other retryable failure at once on
//! its agent fallback panel's (`agent = [a, b]`) next member whose agent the
//! provider has not refused. A panel of `N` members is the stage's fallback
//! budget: `N - 1` advances.
//!
//! # Invariant
//!
//! Every verdict is read outside the code under test: which agent each attempt
//! ran is the delivered capsule's own `argv` (the worker end of a real
//! `InProcessTransport`), the chain is the raw `occurrences`/`attempts` rows of a
//! second rusqlite handle.

use std::collections::BTreeMap;
use std::path::Path;
use std::time::Duration;

use kata_program::execution_program::{
    ExecutionProgram, compile_starlark_execution_program, lower_stage_operation,
};
use kata_transport::types::DispatchFrame;
use kata_types::effect::{DeliveryFailureProvenance, ProviderFailureClass};
use kata_types::execution_contract::{
    ActionExecutor, ArtifactPrivacy, ArtifactRef, CapsuleProcess, ExecuteOperation, OccurrenceRef,
    OperationContractId, OperationPath, RuntimeOperation,
};
use kata_types::primitives::ContentHash;
use kata_types::tree_artifact::{TreeEntry, TreeEntryMode, TreeManifest, TreeNode, TreePath};
use kata_types::workflow::{ExecutionId, StageId};
use kata_workflow::runner::testing::{
    capsule_failure_retry_for_test, inject_parsed_if_declared_for_test,
    pending_failure_retries_for_test, pending_validate_retries_for_test,
};
use kata_workflow::test_harness::{
    OCI_RIG_WORKER, OciNodeRig, seed_claimed_capsule_attempt, seed_claimed_capsule_attempt_at,
};
use smol_str::SmolStr;
use ulid::Ulid;

/// One agent stage over a two-member fallback panel.
const PANEL_PACK: &str = "p = stage(\n\
     \x20   id = \"p\",\n\
     \x20   agent = [\"codex\", \"codex2\"],\n\
     \x20   prompt = \"answer\",\n\
     \x20   sandbox = \"work\",\n\
     )\n\
     workflow(\"failure-retry-oci\", root = [p], sandbox_profiles = \
     {\"work\": sandbox_profile(workspace = \"ro\", net = \"host\")})\n";

/// One agent stage over a THREE-member fallback panel: a two-advance budget.
const THREE_MEMBER_PANEL_PACK: &str = "p = stage(\n\
     \x20   id = \"p\",\n\
     \x20   agent = [\"codex\", \"codex2\", \"codex3\"],\n\
     \x20   prompt = \"answer\",\n\
     \x20   sandbox = \"work\",\n\
     )\n\
     workflow(\"failure-retry-oci\", root = [p], sandbox_profiles = \
     {\"work\": sandbox_profile(workspace = \"ro\", net = \"host\")})\n";

/// One agent stage whose fallback panel names ONE agent twice: a re-run of the
/// same agent on a failed attempt.
const SAME_AGENT_PANEL_PACK: &str = "p = stage(\n\
     \x20   id = \"p\",\n\
     \x20   agent = [\"codex\", \"codex\"],\n\
     \x20   prompt = \"answer\",\n\
     \x20   sandbox = \"work\",\n\
     )\n\
     workflow(\"failure-retry-oci\", root = [p], sandbox_profiles = \
     {\"work\": sandbox_profile(workspace = \"ro\", net = \"host\")})\n";

/// `[agents.<label>]` for every panel member — each its own launch argv, so
/// the delivered capsule says which member ran.
fn install_agents() {
    install_agents_except(None);
}

/// [`install_agents`] without `missing`'s block.
fn install_agents_except(missing: Option<&str>) {
    let mut agents = std::collections::BTreeMap::new();
    for label in ["codex", "codex2", "codex3"]
        .into_iter()
        .filter(|label| Some(*label) != missing)
    {
        // The member's label rides its turn as `reasoning_effort`, the
        // witness `frame_agent` reads of which member ran.
        let mut block = kata_program::test_harness::rig_agent_backend_config();
        if let kata_types::config::AgentBackendConfig::Harness {
            reasoning_effort, ..
        } = &mut block
        {
            *reasoning_effort = Some(label.to_owned());
        }
        agents.insert(label.to_owned(), block);
    }
    kata_types::node_profile::install_node_agents(agents);
    kata_types::node_profile::install_node_egress_allow(std::collections::BTreeSet::from([
        kata_types::execution_contract::EgressAuthority::from_authority_str("api.example.com:443")
            .expect("an authority parses"),
    ]));
}

fn program_of(pack: &str) -> ExecutionProgram {
    kata_types::node_profile::mark_node_installed();
    install_agents();
    compile_starlark_execution_program(pack, "failure-retry-oci.star", &[])
        .expect("the panel pack compiles under oci")
}

fn rig(path: &Path) -> OciNodeRig {
    OciNodeRig::open_with_programs(path, &["sh", "codex", "codex2"])
}

fn raw(path: &Path) -> rusqlite::Connection {
    rusqlite::Connection::open_with_flags(
        path,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .expect("a second raw handle")
}

fn reactor(rig: &OciNodeRig) -> kata_workflow::reactor::ResultReactor {
    kata_workflow::reactor::ResultReactor::new(
        SmolStr::new(OCI_RIG_WORKER),
        std::sync::Arc::clone(&rig.worker_side)
            as std::sync::Arc<dyn kata_transport::WorkerResultTransport>,
        std::sync::Arc::clone(&rig.dispatcher),
        std::sync::Arc::new(kata_transport::heartbeat::HeartbeatMonitor::new(
            Duration::from_secs(30),
            Duration::from_secs(30),
        )),
    )
}

fn publish_blob(rig: &OciNodeRig, bytes: &[u8]) -> ArtifactRef {
    let receipt = rig.cas.put_durable(bytes).unwrap();
    ArtifactRef::new(
        receipt.object_id(),
        receipt.size(),
        ArtifactPrivacy::Private,
    )
}

/// The `/out` result tree the stub reports: one member, `result.txt`.
fn publish_result(rig: &OciNodeRig) -> ArtifactRef {
    let member = rig.cas.put_durable(b"done\n").unwrap();
    let manifest = TreeManifest::new(vec![TreeEntry {
        path: TreePath::new("result.txt").unwrap(),
        node: TreeNode::File {
            mode: TreeEntryMode::Regular,
            object: member.object_id(),
            size_bytes: member.size(),
        },
    }])
    .unwrap();
    publish_blob(rig, &manifest.manifest_bytes().unwrap())
}

async fn next_frame(rig: &OciNodeRig) -> kata_transport::types::CapsuleAssignment {
    match tokio::time::timeout(Duration::from_secs(30), rig.worker_side.recv_frame())
        .await
        .expect("a capsule frame reaches the worker")
        .expect("the transport delivers it")
    {
        DispatchFrame::Capsule(capsule) => *capsule,
    }
}

/// The delivered turn's `reasoning_effort` — the member label
/// [`install_agents_except`] declares there, so which panel member ran.
fn frame_agent(rig: &OciNodeRig, frame: &kata_transport::types::CapsuleAssignment) -> String {
    let bytes = rig
        .cas
        .get(&frame.capsule.object)
        .expect("the CAS reads")
        .expect("the capsule object is published");
    let capsule: kata_types::execution_contract::Capsule =
        serde_json::from_slice(&bytes).expect("the capsule decodes");
    match capsule.process() {
        CapsuleProcess::Agent(turn) => turn
            .reasoning_effort
            .as_deref()
            .expect("the rig declares each member's label")
            .to_owned(),
        CapsuleProcess::Command { .. } => panic!("the panel stage is an agent capsule"),
    }
}

fn frame_path(rig: &OciNodeRig, frame: &kata_transport::types::CapsuleAssignment) -> Vec<u32> {
    let bytes: Vec<u8> = raw(&rig.op_path)
        .query_row(
            "SELECT operation_path FROM occurrences WHERE occurrence_id = ?1",
            [frame.occurrence_id.0.0.as_slice()],
            |row| row.get(0),
        )
        .expect("the frame's occurrence row");
    OperationPath::from_canonical_bytes(&bytes)
        .expect("the path decodes")
        .0
}

/// The rendered prompt the delivered agent capsule carries: the CAS blob the
/// turn's `prompt` artifact names — the bytes the vendor reads, never the
/// runner's in-memory copy.
fn frame_prompt(rig: &OciNodeRig, frame: &kata_transport::types::CapsuleAssignment) -> String {
    frame_agent_prompt(rig, frame).expect("the stage is an agent capsule")
}

/// [`frame_prompt`] as an `Option` — `None` for a Command capsule, which
/// renders no prompt.
fn frame_agent_prompt(
    rig: &OciNodeRig,
    frame: &kata_transport::types::CapsuleAssignment,
) -> Option<String> {
    let bytes = rig
        .cas
        .get(&frame.capsule.object)
        .expect("the CAS reads")
        .expect("the capsule object is published");
    let capsule: kata_types::execution_contract::Capsule =
        serde_json::from_slice(&bytes).expect("the capsule decodes");
    let CapsuleProcess::Agent(turn) = capsule.process() else {
        return None;
    };
    let object: Vec<u8> = raw(&rig.op_path)
        .query_row(
            "SELECT object_id FROM artifacts WHERE artifact_id = ?1",
            [turn.prompt.0.0.as_slice()],
            |row| row.get(0),
        )
        .expect("the prompt's artifact row exists");
    let object: [u8; 32] = object
        .try_into()
        .expect("an artifacts.object_id row is 32 bytes");
    let bytes = rig
        .cas
        .get(&kata_types::primitives::FixedBytes(object))
        .expect("the CAS reads")
        .expect("the prompt object is published");
    Some(String::from_utf8(bytes).expect("the prompt is utf8"))
}

/// The frame's authored stage spelling, off its attempt row — a `loop(..)`
/// member keeps its stage's own `stage_id`, a topology child its durable
/// `<base>#child-<role>` one.
fn frame_stage_id(rig: &OciNodeRig, frame: &kata_transport::types::CapsuleAssignment) -> String {
    raw(&rig.op_path)
        .query_row(
            "SELECT stage_id FROM attempts WHERE attempt_id = ?1",
            [frame.attempt_id.to_bytes().as_slice()],
            |row| row.get(0),
        )
        .expect("the frame's attempt row")
}

/// What one scripted frame does.
#[derive(Clone, Copy)]
enum Answer {
    /// A completion whose `agent.response` bytes are this body — what an
    /// agent capsule's `content` (hence its output contract) is judged
    /// against.
    Complete(&'static [u8]),
    /// An agent capsule's completion whose process exited with this non-zero
    /// code — the main's completion judgement refuses it, PERFORMED BUT FAILED.
    CompleteExited(i32),
    /// The same completion for a COMMAND capsule — no agent report, the
    /// staged stdout carries the bytes `content` is judged against.
    CompleteStdout(&'static [u8]),
    Fail(DeliveryFailureProvenance),
    /// An agent turn its model provider failed, settled PROVEN NOT PERFORMED
    /// with the provider's failure class, as the worker reports it
    /// (`kata_worker::agent_turn`).
    ProviderFail(ProviderFailureClass),
    /// A failure frame pairing `verdict` with a provider failure class — a
    /// pairing the main records as the worker sent it, whatever the verdict.
    FailClassed(DeliveryFailureProvenance, ProviderFailureClass),
    /// An operator stop recorded on the attempt (fenced, as the cancel's worker
    /// arm records it), then [`Self::ProviderFail`]: the attempt settles
    /// `cancelled`.
    StoppedThenProviderFail(ProviderFailureClass),
}

fn answer(
    rig: &OciNodeRig,
    reactor: &kata_workflow::reactor::ResultReactor,
    frame: &kata_transport::types::CapsuleAssignment,
    answer: Answer,
) {
    let message = match answer {
        Answer::Fail(verdict) => kata_transport::types::WorkerMessage::Failed {
            assignment_id: frame.attempt_id,
            reason: "the vendor turn failed".to_owned(),
            verdict,
            provider_failure: None,
            usage: None,
            fence: kata_transport::types::AttemptFence::echoing_capsule(frame),
        },
        Answer::ProviderFail(class) => kata_transport::types::WorkerMessage::Failed {
            assignment_id: frame.attempt_id,
            reason: format!("the model provider failed the turn ({})", class.as_str()),
            verdict: DeliveryFailureProvenance::ProvenNotPerformed,
            provider_failure: Some(class),
            usage: None,
            fence: kata_transport::types::AttemptFence::echoing_capsule(frame),
        },
        Answer::FailClassed(verdict, class) => kata_transport::types::WorkerMessage::Failed {
            assignment_id: frame.attempt_id,
            reason: format!("the model provider failed the turn ({})", class.as_str()),
            verdict,
            provider_failure: Some(class),
            usage: None,
            fence: kata_transport::types::AttemptFence::echoing_capsule(frame),
        },
        Answer::StoppedThenProviderFail(class) => {
            let (_, fence) = rig
                .dispatcher
                .attempt_command_target(frame.attempt_id)
                .expect("the command target reads")
                .expect("the attempt is placed");
            rig.dispatcher
                .record_attempt_stop_request(frame.attempt_id, &fence, "the operator's stop")
                .expect("the stop request is recorded");
            kata_transport::types::WorkerMessage::Failed {
                assignment_id: frame.attempt_id,
                reason: format!("the model provider failed the turn ({})", class.as_str()),
                verdict: DeliveryFailureProvenance::ProvenNotPerformed,
                provider_failure: Some(class),
                usage: None,
                fence: kata_transport::types::AttemptFence::echoing_capsule(frame),
            }
        }
        Answer::Complete(_) | Answer::CompleteExited(_) => {
            let (response, exit_code): (&[u8], i32) = match answer {
                Answer::CompleteExited(code) => (b"done\n", code),
                Answer::Complete(response) => (response, 0),
                _ => unreachable!("the arm's own variants"),
            };
            kata_transport::types::WorkerMessage::CompletedCapsule {
                attempt_id: frame.attempt_id,
                fence: kata_transport::types::AttemptFence::echoing_capsule(frame),
                result: publish_result(rig),
                work_delta: kata_workflow::test_harness::stub_work_delta(
                    &rig.db,
                    &rig.cas,
                    frame.occurrence_id,
                ),
                exit_code: Some(exit_code),
                stdout: publish_blob(rig, b""),
                stderr: publish_blob(rig, b""),
                capture_exceeded: false,
                agent: Some(kata_types::agent::AgentTurnReport {
                    response: publish_blob(rig, response),
                    usage: None,
                    adapter: kata_types::agent::AdapterKind::NanocodeOpenai,
                    model_reported: None,
                    session_evidence: Some(publish_blob(
                        rig,
                        b"{\"events\":[],\"events_dropped\":0,\"scratch_commits\":[]}",
                    )),
                    stop_reason: None,
                }),
                provenance:
                    kata_types::execution_provenance::ExecutionProvenance::local_oci_runtime(
                        "failure retry cell",
                    ),
                egress_refusals: vec![],
            }
        }
        Answer::CompleteStdout(stdout) => kata_transport::types::WorkerMessage::CompletedCapsule {
            attempt_id: frame.attempt_id,
            fence: kata_transport::types::AttemptFence::echoing_capsule(frame),
            result: publish_result(rig),
            work_delta: kata_workflow::test_harness::stub_work_delta(
                &rig.db,
                &rig.cas,
                frame.occurrence_id,
            ),
            exit_code: Some(0),
            stdout: publish_blob(rig, stdout),
            stderr: publish_blob(rig, b""),
            capture_exceeded: false,
            agent: None,
            provenance: kata_types::execution_provenance::ExecutionProvenance::local_oci_runtime(
                "failure retry cell",
            ),
            egress_refusals: vec![],
        },
    };
    reactor
        .handle_message_for_test(message)
        .expect("the frame's answer is adjudicated");
}

/// Drive `program` answering its n-th frame with `script[n]`; returns the
/// outcome and every frame's `(agent, path, prompt)` in delivery order. A
/// transient provider re-run is due at once here (a zero backoff): these cells
/// pin the chain's walk, and the backoff cells below its timing.
async fn drive(
    rig: &OciNodeRig,
    program: &ExecutionProgram,
    execution: Ulid,
    script: &[Answer],
) -> (
    kata_types::error::KataResult<std::collections::BTreeMap<SmolStr, serde_json::Value>>,
    Vec<(String, Vec<u32>, String)>,
) {
    drive_runner(
        rig,
        rig.runner(program, execution)
            .with_transient_rerun_backoff_for_test([0, 0]),
        script,
    )
    .await
}

/// [`drive`] over a runner the cell built.
async fn drive_runner(
    rig: &OciNodeRig,
    runner: kata_workflow::runner::WorkflowRunner,
    script: &[Answer],
) -> (
    kata_types::error::KataResult<std::collections::BTreeMap<SmolStr, serde_json::Value>>,
    Vec<(String, Vec<u32>, String)>,
) {
    let reactor = reactor(rig);
    let mut frames = Vec::new();
    let run = runner.run();
    tokio::pin!(run);
    let outcome = tokio::time::timeout(Duration::from_secs(60), async {
        loop {
            tokio::select! {
                outcome = &mut run => break outcome,
                frame = next_frame(rig) => {
                    let n = frames.len();
                    frames.push((
                        frame_agent(rig, &frame),
                        frame_path(rig, &frame),
                        frame_prompt(rig, &frame),
                    ));
                    answer(rig, &reactor, &frame, script.get(n).copied().unwrap_or(Answer::Complete(b"done\n")));
                }
            }
        }
    })
    .await
    .expect("the drive reaches a terminal within the budget");
    (outcome, frames)
}

/// A fallback panel's stage whose first attempt FAILED (PERFORMED
/// BUT FAILED) retries on the panel's NEXT member, at the stage seat's
/// `child(1)`, and the stage completes on it. Raw: two occurrences, the first
/// attempt `failed`, the second accepted.
///
/// **Would red if:** failure retries were not driven: the first failure would
/// fail the run and no second frame would be delivered — the panel's tail never
/// runs.
#[tokio::test(flavor = "current_thread")]
async fn a_failed_panel_stage_retries_on_its_next_panel_member() {
    let rig = rig(&tempfile::tempdir().unwrap().keep());
    rig.declare_bound_environment();
    let program = program_of(PANEL_PACK);
    let execution = Ulid::new();
    let (outcome, frames) = drive(
        &rig,
        &program,
        execution,
        &[Answer::Fail(DeliveryFailureProvenance::PerformedButFailed)],
    )
    .await;
    outcome.expect("the panel's next member completes the stage");
    assert_eq!(
        frames.len(),
        2,
        "attempt 0 plus one failure retry: {frames:?}"
    );
    assert_eq!(frames[0].0, "codex", "attempt 0 runs the panel's primary");
    assert_eq!(
        frames[1].0, "codex2",
        "the retry runs the panel's next member"
    );
    let mut retry_seat = frames[0].1.clone();
    retry_seat.push(1);
    assert_eq!(
        frames[1].1, retry_seat,
        "the retry sits at the stage seat's child(1)"
    );
    let states: Vec<String> = raw(&rig.op_path)
        .prepare(
            "SELECT p.state FROM attempts a JOIN attempt_projection p
               ON p.execution_id = a.execution_id AND p.stage_id = a.stage_id
              AND p.attempt_ordinal = a.attempt_ordinal
             WHERE a.execution_id = ?1 AND a.stage_id = 'p' ORDER BY a.attempt_ordinal",
        )
        .unwrap()
        .query_map([execution.to_bytes().as_slice()], |row| row.get(0))
        .unwrap()
        .collect::<rusqlite::Result<_>>()
        .unwrap();
    assert_eq!(
        states,
        ["failed", "completed"],
        "raw: the chain's two attempts"
    );
}

/// Protected property `uncertainty-not-reissued` on the retry
/// chain: a PROVEN AMBIGUOUS failure is never re-run, even with a panel member
/// left — the run fails and no second frame is delivered.
#[tokio::test(flavor = "current_thread")]
async fn a_proven_ambiguous_failure_is_never_retried() {
    let rig = rig(&tempfile::tempdir().unwrap().keep());
    rig.declare_bound_environment();
    let program = program_of(PANEL_PACK);
    let execution = Ulid::new();
    let (outcome, frames) = drive(
        &rig,
        &program,
        execution,
        &[Answer::Fail(DeliveryFailureProvenance::ProvenAmbiguous)],
    )
    .await;
    outcome.expect_err("an ambiguous failure fails the run");
    assert_eq!(
        frames.len(),
        1,
        "no retry of an ambiguous attempt: {frames:?}"
    );
}

/// A spent panel fails the stage in the panel-exhaustion phrasing.
#[tokio::test(flavor = "current_thread")]
async fn a_spent_panel_fails_in_legacys_exhaustion_phrasing() {
    let rig = rig(&tempfile::tempdir().unwrap().keep());
    rig.declare_bound_environment();
    let program = program_of(PANEL_PACK);
    let execution = Ulid::new();
    let (outcome, frames) = drive(
        &rig,
        &program,
        execution,
        &[
            Answer::Fail(DeliveryFailureProvenance::PerformedButFailed),
            Answer::Fail(DeliveryFailureProvenance::PerformedButFailed),
        ],
    )
    .await;
    let error = outcome
        .expect_err("a spent panel fails the run")
        .to_string();
    assert!(
        error.contains(
            "stage failed after exhausting agent fallback panel [codex, codex2] across 1 attempt(s)"
        ),
        "the panel-exhaustion phrasing: {error}"
    );
    assert_eq!(frames.len(), 2);
}

/// Every fallback panel member is judged at CHECK, not only the
/// primary: a panel whose second member this node does not declare is refused
/// `adapter_undeclared` naming that member — never discovered mid-run when the
/// first attempt fails.
///
/// **Watched red**: with the panel loop removed from the CHECK door the pack
/// compiles.
#[test]
fn an_undeclared_panel_member_is_refused_at_check() {
    kata_types::node_profile::mark_node_installed();
    install_agents_except(Some("codex2"));
    let refusal = compile_starlark_execution_program(PANEL_PACK, "failure-retry-oci.star", &[])
        .expect_err("a panel member the node cannot launch is refused")
        .to_string();
    assert!(
        refusal.contains("adapter_undeclared") && refusal.contains("`codex2`"),
        "refused by name, naming the member: {refusal}"
    );
}

/// A failure-retry policy on an EXPANSION member is refused by
/// name under `oci` rather than silently dropped: a fallback panel on a
/// `loop(..)` member, and one on a `topology` stage
/// (`expansion_failure_retries_unsupported_under_oci`); the same stages with a
/// single agent compile.
///
/// **Watched red**: with the CHECK arm removed both packs compile.
#[test]
fn a_failure_retry_policy_on_an_expansion_member_is_refused_by_name() {
    kata_types::node_profile::mark_node_installed();
    install_agents();
    let looped = |agent: &str| {
        format!(
            "w = stage(id = \"w\", agent = {agent}, prompt = \"work\", sandbox = \"work\")\n\
             g = stage(id = \"g\", agent = \"shell\", run = \"printf ok\", depends_on = [\"w\"], \
             outputs = {{\"verdict\": \"string\"}})\n\
             loop(body = w, gate = g, max_iterations = 2)\n\
             workflow(\"looped\", root = [w, g], sandbox_profiles = \
             {{\"work\": sandbox_profile(workspace = \"ro\", net = \"host\")}})\n"
        )
    };
    let topology = |agent: &str| {
        format!(
            "t = stage(id = \"t\", agent = {agent}, prompt = \"plan\", sandbox = \"work\", \
             topology = topology(\"root_with_parallel_workers\", workers = \
             [role(\"w\", agent = \"shell\")]))\n\
             workflow(\"fanned\", root = [t], sandbox_profiles = \
             {{\"work\": sandbox_profile(workspace = \"ro\", net = \"host\")}})\n"
        )
    };
    for (name, pack) in [
        ("loop", &looped as &dyn Fn(&str) -> String),
        ("topology", &topology),
    ] {
        let refusal =
            compile_starlark_execution_program(&pack("[\"codex\", \"codex2\"]"), "p.star", &[])
                .expect_err("a panel on an expansion member is refused")
                .to_string();
        assert!(
            refusal.contains("expansion_failure_retries_unsupported_under_oci"),
            "{name}: refused by name: {refusal}"
        );
        compile_starlark_execution_program(&pack("\"codex\""), "p.star", &[])
            .unwrap_or_else(|error| panic!("{name}: a single agent compiles: {error}"));
    }
}

/// A two-member panel over a stage with a structured-output contract — the
/// shape a MIXED validation+failure chain needs: an attempt may fail outright
/// (its failure retry advances the panel) or complete with a `content` that
/// fails the contract (its validation retry keeps the panel's tail member).
fn mixed_pack(validate_retries: u32) -> String {
    format!(
        "p = stage(\n\
         \x20   id = \"p\",\n\
         \x20   agent = [\"codex\", \"codex2\"],\n\
         \x20   prompt = \"answer\",\n\
         \x20   outputs = {{\"verdict\": \"string\"}},\n\
         \x20   validate_retries = {validate_retries},\n\
         \x20   sandbox = \"work\",\n\
         )\n\
         workflow(\"failure-retry-oci\", root = [p], sandbox_profiles = \
         {{\"work\": sandbox_profile(workspace = \"ro\", net = \"host\")}})\n"
    )
}

/// A MIXED validation+failure chain is authorized by its
/// validation ORDINAL, never its seat index: attempt 0 FAILED (the failure
/// retry mints seat 1 on the panel's next member), attempt 1's accepted
/// `content` fails the contract (the validation retry mints seat 2 — its
/// `child(2)` coordinate counts the failed seat, so a budget check that read
/// the SEAT as the ordinal would refuse a `validate_retries = 1` retry the
/// checked program authorizes). The chain completes on it; the validation
/// retry keeps the driver the chain advanced to; its prompt carries the
/// validation feedback.
///
/// **Watched red**: with `dispatch_capsule_validation_retry` feeding
/// `retry.attempt` (the seat) into `DerivedDispatchKind::ValidationRetry`,
/// the seat-2 retry is refused `validation retry budget 1 does not authorize
/// attempt 2` and the run fails.
#[tokio::test(flavor = "current_thread")]
async fn a_validation_retry_after_a_failed_seat_is_authorized_by_its_ordinal() {
    let rig = rig(&tempfile::tempdir().unwrap().keep());
    rig.declare_bound_environment();
    let program = program_of(&mixed_pack(1));
    let execution = Ulid::new();
    let (outcome, frames) = drive(
        &rig,
        &program,
        execution,
        &[
            Answer::Fail(DeliveryFailureProvenance::PerformedButFailed),
            Answer::Complete(b"not json at all"),
            Answer::Complete(b"{\"verdict\": \"ok\"}"),
        ],
    )
    .await;
    let outputs =
        outcome.expect("the validation retry the checked budget authorizes completes the stage");
    assert_eq!(
        outputs["p"]["parsed"]["verdict"],
        serde_json::json!("ok"),
        "the retried attempt's parsed output lands"
    );
    assert_eq!(
        frames.len(),
        3,
        "attempt 0, its failure retry, its validation retry: {frames:?}"
    );
    assert_eq!(frames[0].0, "codex", "attempt 0 runs the panel's primary");
    assert_eq!(
        frames[1].0, "codex2",
        "the failure retry advances the panel"
    );
    assert_eq!(
        frames[2].0, "codex2",
        "a validation retry keeps the driver the chain advanced to"
    );
    assert_eq!(
        frames[1].1,
        frames[0].1.iter().copied().chain([1]).collect::<Vec<_>>(),
        "the failure retry sits at child(1)"
    );
    assert_eq!(
        frames[2].1,
        frames[0].1.iter().copied().chain([2]).collect::<Vec<_>>(),
        "the validation retry sits at child(2)"
    );
    assert!(
        frames[2].2.starts_with("answer")
            && frames[2]
                .2
                .contains("Your previous response did not parse correctly"),
        "the validation retry's prompt carries the validation feedback: {}",
        frames[2].2
    );
    assert!(
        !frames[1]
            .2
            .contains("Your previous response did not parse correctly"),
        "a failure retry re-renders the prompt with no validation feedback"
    );
    let states: Vec<String> = raw(&rig.op_path)
        .prepare(
            "SELECT p.state FROM attempts a JOIN attempt_projection p
               ON p.execution_id = a.execution_id AND p.stage_id = a.stage_id
              AND p.attempt_ordinal = a.attempt_ordinal
             WHERE a.execution_id = ?1 AND a.stage_id = 'p' ORDER BY a.attempt_ordinal",
        )
        .unwrap()
        .query_map([execution.to_bytes().as_slice()], |row| row.get(0))
        .unwrap()
        .collect::<rusqlite::Result<_>>()
        .unwrap();
    assert_eq!(
        states,
        ["failed", "completed", "completed"],
        "raw: the mixed chain's three attempts"
    );
}

/// The converse seat: an accepted-but-invalid attempt 0
/// mints validation retry 1 (seat 1, the stage's own driver), ITS failure
/// mints failure retry (seat 2, advanced to the panel's tail), and THAT
/// attempt's invalid `content` mints validation retry TWO at seat 3 — its
/// ordinal is 2 (two accepted causes), not its seat 3, so a `validate_retries
/// = 2` budget authorizes it. The run completes; every cause's seat and
/// driver is the one the durable chain implies.
///
/// **Watched red**: with the seat index passed as the retry's ordinal, seat
/// 3's preflight reads `budget 2 does not authorize attempt 3`.
#[tokio::test(flavor = "current_thread")]
async fn an_interleaved_chain_counts_validation_ordinals_not_seats() {
    let rig = rig(&tempfile::tempdir().unwrap().keep());
    rig.declare_bound_environment();
    let program = program_of(&mixed_pack(2));
    let execution = Ulid::new();
    let (outcome, frames) = drive(
        &rig,
        &program,
        execution,
        &[
            Answer::Complete(b"also not json"),
            Answer::Fail(DeliveryFailureProvenance::PerformedButFailed),
            Answer::Complete(b"still not json"),
            Answer::Complete(b"{\"verdict\": \"ok\"}"),
        ],
    )
    .await;
    let outputs = outcome.expect("the second validation retry the budget authorizes completes");
    assert_eq!(outputs["p"]["parsed"]["verdict"], serde_json::json!("ok"));
    assert_eq!(frames.len(), 4, "four seats, mixed causes: {frames:?}");
    assert_eq!(frames[0].0, "codex");
    assert_eq!(
        frames[1].0, "codex",
        "a validation retry keeps the stage's own driver"
    );
    assert_eq!(
        frames[2].0, "codex2",
        "the failure retry advances the panel"
    );
    assert_eq!(
        frames[3].0, "codex2",
        "the second validation retry keeps the tail member"
    );
    assert_eq!(
        frames[1].1,
        frames[0].1.iter().copied().chain([1]).collect::<Vec<_>>()
    );
    assert_eq!(
        frames[2].1,
        frames[0].1.iter().copied().chain([2]).collect::<Vec<_>>()
    );
    assert_eq!(
        frames[3].1,
        frames[0].1.iter().copied().chain([3]).collect::<Vec<_>>()
    );
    assert!(
        frames[1]
            .2
            .contains("Your previous response did not parse correctly")
            && frames[3]
                .2
                .contains("Your previous response did not parse correctly"),
        "each validation retry carries the feedback"
    );
    let states: Vec<String> = raw(&rig.op_path)
        .prepare(
            "SELECT p.state FROM attempts a JOIN attempt_projection p
               ON p.execution_id = a.execution_id AND p.stage_id = a.stage_id
              AND p.attempt_ordinal = a.attempt_ordinal
             WHERE a.execution_id = ?1 AND a.stage_id = 'p' ORDER BY a.attempt_ordinal",
        )
        .unwrap()
        .query_map([execution.to_bytes().as_slice()], |row| row.get(0))
        .unwrap()
        .collect::<rusqlite::Result<_>>()
        .unwrap();
    assert_eq!(
        states,
        ["completed", "failed", "completed", "completed"],
        "raw: accepted-invalid, failed, accepted-invalid, accepted"
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// The retry surface's remaining host-free cells: agent
// validation feedback in the capsule prompt on a PLAIN stage, a `loop(..)`
// member, and a `topology` root; the failure retry's deadline anchored on the
// failed attempt's durable `finished_at_ms`; the panel's tail clamp;
// UNCLASSIFIED never retried; PROVEN NOT PERFORMED retried; a topology root's
// spent validation budget; and a crash between the failed attempt and its
// retry.
// ═══════════════════════════════════════════════════════════════════════════

/// A plain AGENT stage — `p` carries a structured contract and one
/// `validate_retries`, no panel to advance.
const AGENT_FEEDBACK_PACK: &str = "p = stage(\n\
     \x20   id = \"p\",\n\
     \x20   agent = \"codex\",\n\
     \x20   prompt = \"answer\",\n\
     \x20   outputs = {\"verdict\": \"string\"},\n\
     \x20   validate_retries = 1,\n\
     \x20   sandbox = \"work\",\n\
     )\n\
     workflow(\"agent-feedback\", root = [p], sandbox_profiles = \
     {\"work\": sandbox_profile(workspace = \"ro\", net = \"host\")})\n";

/// An agent `loop(..)` member — `worker` declares a structured contract and
/// one `validate_retries`; `controller` is the shell gate whose `decision`
/// resolves the loop.
const LOOP_FEEDBACK_PACK: &str = r#"worker = stage(
    id = "worker",
    agent = "codex",
    prompt = "work",
    outputs = {
        "stage": "string",
        "marker": "number",
    },
    validate_retries = 1,
    sandbox = "work",
)

controller = stage(
    id = "controller",
    agent = "shell",
    run = "printf '{\"decision\":\"promote\",\"feedback\":\"ship\"}\n'",
    depends_on = ["worker"],
    outputs = {
        "decision": "string",
        "feedback": "string",
    },
)

loop(
    body = worker,
    gate = controller,
    max_iterations = 2,
    on_exhaustion = "fail",
    gate_verdict = {
        "field": "decision",
        "approve": ["promote"],
        "refine": ["continue"],
        "block": ["stop"],
    },
)

workflow(
    "feedback-loop",
    root = [worker, controller],
    sandbox_profiles = {
        "work": sandbox_profile(workspace = "ro", net = "host"),
    },
)
"#;

/// A static `topology(..)` whose ROOT is an agent stage carrying a structured
/// contract and one `validate_retries`.
const TOPOLOGY_FEEDBACK_PACK: &str = r#"parent = stage(
    id = "parent",
    agent = "codex",
    prompt = "plan",
    outputs = {
        "note": "string",
    },
    validate_retries = 1,
    sandbox = "work",
    topology = topology(
        "root_with_parallel_workers",
        workers = [
            role("w", agent = "shell"),
        ],
    ),
)

workflow(
    "topology-feedback",
    root = [parent],
    sandbox_profiles = {
        "work": sandbox_profile(workspace = "ro", net = "offline"),
    },
)
"#;

/// When [`drive_by_stage`] answers one frame.
#[derive(Clone, Copy)]
enum Reply {
    /// The moment the frame is delivered.
    Now(Answer),
    /// Only once a frame of the named stage has been delivered: the attempt stays
    /// live across every runner pass in between, as a real container outlives one.
    AfterFrameOf(&'static str, Answer),
}

impl From<Answer> for Reply {
    fn from(answer: Answer) -> Self {
        Self::Now(answer)
    }
}

/// Drive `program` answering each frame by its durable `stage_id` through
/// `script(stage_id, n)` — `n` that stage's own frame count. Returns the
/// outcome and every frame's `(stage_id, path, agent prompt)` in delivery
/// order — `None` for a command capsule, which renders no prompt.
async fn drive_by_stage<R: Into<Reply>>(
    rig: &OciNodeRig,
    program: &ExecutionProgram,
    execution: Ulid,
    script: impl Fn(&str, usize) -> R,
) -> (
    kata_types::error::KataResult<BTreeMap<SmolStr, serde_json::Value>>,
    Vec<(String, Vec<u32>, Option<String>)>,
) {
    drive_runner_by_stage(rig, rig.runner(program, execution), script).await
}

/// [`drive_by_stage`] over a runner the cell built.
async fn drive_runner_by_stage<R: Into<Reply>>(
    rig: &OciNodeRig,
    runner: kata_workflow::runner::WorkflowRunner,
    script: impl Fn(&str, usize) -> R,
) -> (
    kata_types::error::KataResult<BTreeMap<SmolStr, serde_json::Value>>,
    Vec<(String, Vec<u32>, Option<String>)>,
) {
    let reactor = reactor(rig);
    let mut frames: Vec<(String, Vec<u32>, Option<String>)> = Vec::new();
    let mut per_stage: BTreeMap<String, usize> = BTreeMap::new();
    let mut held = Vec::new();
    let run = runner.run();
    tokio::pin!(run);
    let outcome = tokio::time::timeout(Duration::from_secs(60), async {
        loop {
            tokio::select! {
                outcome = &mut run => break outcome,
                frame = next_frame(rig) => {
                    let stage = frame_stage_id(rig, &frame);
                    let n = per_stage.get(&stage).copied().unwrap_or(0);
                    *per_stage.entry(stage.clone()).or_default() += 1;
                    frames.push((stage.clone(), frame_path(rig, &frame), frame_agent_prompt(rig, &frame)));
                    match script(&stage, n).into() {
                        Reply::Now(reply) => answer(rig, &reactor, &frame, reply),
                        Reply::AfterFrameOf(awaited, reply) => held.push((frame, awaited, reply)),
                    }
                    let (due, waiting): (Vec<_>, Vec<_>) = std::mem::take(&mut held)
                        .into_iter()
                        .partition(|(_, awaited, _)| frames.iter().any(|f| f.0 == *awaited));
                    held = waiting;
                    for (frame, _, reply) in due {
                        answer(rig, &reactor, &frame, reply);
                    }
                }
            }
        }
    })
    .await
    .expect("the drive reaches a terminal within the budget");
    assert!(
        held.is_empty(),
        "the run reached its terminal with frames still held — the frame they awaited never \
         came: {frames:?}"
    );
    (outcome, frames)
}

/// An AGENT stage's validation retry carries the validation
/// feedback in its capsule prompt: attempt 0's accepted-but-invalid `content`
/// mints seat 1 re-rendered through `build_retry_prompt` (the `is_agent` arm
/// of `dispatch_capsule_validation_retry` — a command stage would re-run its
/// command verbatim instead).
///
/// **Watched red**: with `is_agent` forced false the retry's prompt is the
/// bare re-render and the feedback assert fails.
#[tokio::test(flavor = "current_thread")]
async fn an_agent_stages_validation_retry_carries_the_feedback_in_its_prompt() {
    let rig = rig(&tempfile::tempdir().unwrap().keep());
    rig.declare_bound_environment();
    let program = program_of(AGENT_FEEDBACK_PACK);
    let execution = Ulid::new();
    let (outcome, frames) = drive(
        &rig,
        &program,
        execution,
        &[
            Answer::Complete(b"not json at all"),
            Answer::Complete(b"{\"verdict\": \"ok\"}"),
        ],
    )
    .await;
    outcome.expect("the feedback-bearing retry completes the stage");
    assert_eq!(
        frames.len(),
        2,
        "attempt 0 plus its validation retry: {frames:?}"
    );
    let mut retry_seat = frames[0].1.clone();
    retry_seat.push(1);
    assert_eq!(frames[1].1, retry_seat);
    assert!(
        frames[0].2.starts_with("answer") && !frames[0].2.contains("did not parse"),
        "attempt 0 renders the bare prompt: {}",
        frames[0].2
    );
    assert!(
        frames[1].2.starts_with("answer")
            && frames[1]
                .2
                .contains("Your previous response did not parse correctly"),
        "the retry's prompt is the stage's own plus the validation feedback: {}",
        frames[1].2
    );
}

/// A `loop(..)` MEMBER's agent retry carries the same
/// feedback: the member's accepted-but-invalid envelope hands the derive to
/// the member seat's `child(1)` (`dispatch_expansion_member`'s `retry` arm
/// re-renders an AGENT member through `build_retry_prompt`).
///
/// **Watched red**: with that arm's `matches!(..Agent..)` forced false the
/// retry's prompt is the bare re-render.
#[tokio::test(flavor = "current_thread")]
async fn a_loop_members_agent_retry_carries_the_validation_feedback() {
    let rig = rig(&tempfile::tempdir().unwrap().keep());
    rig.declare_bound_environment();
    let program = program_of(LOOP_FEEDBACK_PACK);
    let execution = Ulid::new();
    let (outcome, frames) =
        drive_by_stage(&rig, &program, execution, |stage, n| match (stage, n) {
            ("worker", 0) => Answer::Complete(b"not json at all"),
            ("worker", _) => Answer::Complete(b"{\"stage\":\"w\",\"marker\":1}"),
            _ => Answer::CompleteStdout(b"{\"decision\":\"promote\",\"feedback\":\"ship\"}"),
        })
        .await;
    outcome.expect("the retried member's loop approves");
    let workers: Vec<_> = frames.iter().filter(|f| f.0 == "worker").collect();
    assert_eq!(workers.len(), 2, "attempt 0 plus one retry: {frames:?}");
    let mut retry_seat = workers[0].1.clone();
    retry_seat.push(1);
    assert_eq!(
        workers[1].1, retry_seat,
        "the retry sits at the member seat's child(1)"
    );
    let retry_prompt = workers[1]
        .2
        .as_deref()
        .expect("the member is an agent capsule");
    assert!(
        retry_prompt.contains("work")
            && retry_prompt.contains("Your previous response did not parse correctly"),
        "the member retry's prompt is the stage's own plus the validation feedback: {retry_prompt}"
    );
    assert!(
        !workers[0]
            .2
            .as_deref()
            .expect("the member is an agent capsule")
            .contains("did not parse"),
        "attempt 0's prompt is the bare render"
    );
}

/// A `topology` ROOT's agent retry carries the feedback:
/// the root's accepted-but-invalid envelope mints `root_retry`, dispatched at
/// the root seat's `child(1)` (`dispatch_topology_members`' root-retry arm),
/// then the declared worker fans out over the accepted root.
///
/// **Watched red**: with that arm's `matches!(..Agent..)` forced false the
/// retry's prompt is the bare parent render.
#[tokio::test(flavor = "current_thread")]
async fn a_topology_roots_agent_retry_carries_the_validation_feedback() {
    let rig = rig(&tempfile::tempdir().unwrap().keep());
    rig.declare_bound_environment();
    let program = program_of(TOPOLOGY_FEEDBACK_PACK);
    let execution = Ulid::new();
    let (outcome, frames) =
        drive_by_stage(&rig, &program, execution, |stage, n| match (stage, n) {
            ("parent", 0) => Answer::Complete(b"not json at all"),
            ("parent", _) => Answer::Complete(b"{\"note\":\"ok\"}"),
            _ => Answer::CompleteStdout(b"worker done"),
        })
        .await;
    outcome.expect("the retried root's fanout settles");
    let roots: Vec<_> = frames.iter().filter(|f| f.0 == "parent").collect();
    assert_eq!(roots.len(), 2, "root attempt 0 plus its retry: {frames:?}");
    let mut retry_seat = roots[0].1.clone();
    retry_seat.push(1);
    assert_eq!(
        roots[1].1, retry_seat,
        "the retry sits at the root seat's child(1)"
    );
    let retry_prompt = roots[1].2.as_deref().expect("the root is an agent capsule");
    assert!(
        retry_prompt.contains("plan")
            && retry_prompt.contains("Your previous response did not parse correctly"),
        "the root retry's prompt is the parent's own plus the validation feedback: {retry_prompt}"
    );
    assert_eq!(
        frames.len(),
        3,
        "root, its retry, the one declared worker: {frames:?}"
    );
}

/// A topology root whose every attempt fails its contract
/// spends `validate_retries`: the retry seat is minted, its invalid envelope
/// reads as a dead root, and the run fails with the validator's own message.
/// The declared worker mints in the fanout of the first pass that reads the
/// root live — exactly once, never re-minted as the root retries and dies.
///
/// Attempt 0's answer is HELD until the worker's frame is delivered. The rig
/// answers in zero time and the delivery door yields while the frame's write
/// task runs, so an answer given at once can fold before the fanout's pass;
/// `derive_topology` then dispatches the owed root retry alone and fails the
/// expansion on the dead root, and a chain spent before that pass mints no
/// worker at all.
///
/// **Watched red**: with the chain's `should_retry` arm forced false the root
/// dies after attempt 0 and the second root frame never exists.
#[tokio::test(flavor = "current_thread")]
async fn a_topology_root_spending_its_validation_budget_fails_the_run() {
    let rig = rig(&tempfile::tempdir().unwrap().keep());
    rig.declare_bound_environment();
    let program = program_of(TOPOLOGY_FEEDBACK_PACK);
    let execution = Ulid::new();
    let (outcome, frames) =
        drive_by_stage(&rig, &program, execution, |stage, n| match (stage, n) {
            ("parent", 0) => {
                Reply::AfterFrameOf("parent#child-w", Answer::Complete(b"still not json"))
            }
            ("parent", _) => Reply::Now(Answer::Complete(b"still not json")),
            _ => Reply::Now(Answer::CompleteStdout(b"worker done")),
        })
        .await;
    assert_eq!(
        frames.iter().map(|f| f.0.as_str()).collect::<Vec<_>>(),
        ["parent", "parent#child-w", "parent"],
        "the root alone, its fanout while it is live, then its one retry: {frames:?}"
    );
    let text = outcome
        .expect_err("a spent root budget fails the run")
        .to_string();
    assert!(
        text.contains("structured-output stage \"parent\""),
        "the validator's own message names the root stage: {text}"
    );
    let roots = frames.iter().filter(|f| f.0 == "parent").count();
    assert_eq!(
        roots, 2,
        "attempt 0 plus validate_retries = 1 retries — a third root would run \
         past the budget: {frames:?}"
    );
    let children = frames.iter().filter(|f| f.0 != "parent").count();
    assert_eq!(
        children, 1,
        "the declared worker mints once in the root's fanout, never retried: {frames:?}"
    );
}

/// An UNCLASSIFIED failure is never re-run: nothing durable
/// says the effect did not happen, so the chain stops at one frame — the
/// panel's remaining member is not spent on a maybe-performed attempt.
///
/// **Watched red**: with `"unclassified"` added to the retryable verdicts a
/// second frame arrives.
#[tokio::test(flavor = "current_thread")]
async fn an_unclassified_failure_is_never_retried() {
    let rig = rig(&tempfile::tempdir().unwrap().keep());
    rig.declare_bound_environment();
    let program = program_of(PANEL_PACK);
    let execution = Ulid::new();
    let (outcome, frames) = drive(
        &rig,
        &program,
        execution,
        &[Answer::Fail(DeliveryFailureProvenance::Unclassified)],
    )
    .await;
    outcome.expect_err("an unclassified failure fails the run");
    assert_eq!(
        frames.len(),
        1,
        "no retry of an unclassified attempt: {frames:?}"
    );
}

/// A PROVEN NOT PERFORMED failure IS retried: the worker's
/// definite negative answer authorizes the re-delivery — a NEW attempt on the
/// panel's next member at `child(1)`, never a re-send of the unsent one.
///
/// **Watched red**: with `"proven_not_performed"` dropped from the retryable
/// verdicts the run fails where the cell expects the retry.
#[tokio::test(flavor = "current_thread")]
async fn a_proven_not_performed_failure_is_retried() {
    let rig = rig(&tempfile::tempdir().unwrap().keep());
    rig.declare_bound_environment();
    let program = program_of(PANEL_PACK);
    let execution = Ulid::new();
    let (outcome, frames) = drive(
        &rig,
        &program,
        execution,
        &[Answer::Fail(DeliveryFailureProvenance::ProvenNotPerformed)],
    )
    .await;
    outcome.expect("a proven-not-performed attempt retries and completes");
    assert_eq!(
        frames.len(),
        2,
        "attempt 0 plus its failure retry: {frames:?}"
    );
    assert_eq!(frames[0].0, "codex", "attempt 0 runs the panel's primary");
    assert_eq!(
        frames[1].0, "codex2",
        "the retry runs the panel's next member"
    );
    let mut retry_seat = frames[0].1.clone();
    retry_seat.push(1);
    assert_eq!(frames[1].1, retry_seat);
    let states: Vec<String> = raw(&rig.op_path)
        .prepare(
            "SELECT p.state FROM attempts a JOIN attempt_projection p
               ON p.execution_id = a.execution_id AND p.stage_id = a.stage_id
              AND p.attempt_ordinal = a.attempt_ordinal
             WHERE a.execution_id = ?1 AND a.stage_id = 'p' ORDER BY a.attempt_ordinal",
        )
        .unwrap()
        .query_map([execution.to_bytes().as_slice()], |row| row.get(0))
        .unwrap()
        .collect::<rusqlite::Result<_>>()
        .unwrap();
    assert_eq!(
        states,
        ["failed", "completed"],
        "raw: the chain's two attempts"
    );
}

/// The raw `provider_failure` the accepting transition of stage `p`'s first
/// attempt recorded, through a second handle.
fn first_attempts_provider_failure(rig: &OciNodeRig, execution: Ulid) -> Option<String> {
    raw(&rig.op_path)
        .query_row(
            "SELECT json_extract(t.payload_json, '$.provider_failure') FROM transitions t
               JOIN attempts a ON a.attempt_id = t.attempt_id
              WHERE a.execution_id = ?1 AND a.stage_id = 'p' AND a.attempt_ordinal = 0
                AND t.kind = 'event_accepted'",
            [execution.to_bytes().as_slice()],
            |row| row.get(0),
        )
        .expect("the first attempt's accepting transition reads")
}

/// The raw projection states of stage `p`'s chain, in attempt order.
fn chain_states(rig: &OciNodeRig, execution: Ulid) -> Vec<String> {
    raw(&rig.op_path)
        .prepare(
            "SELECT p.state FROM attempts a JOIN attempt_projection p
               ON p.execution_id = a.execution_id AND p.stage_id = a.stage_id
              AND p.attempt_ordinal = a.attempt_ordinal
             WHERE a.execution_id = ?1 AND a.stage_id = 'p' ORDER BY a.attempt_ordinal",
        )
        .unwrap()
        .query_map([execution.to_bytes().as_slice()], |row| row.get(0))
        .unwrap()
        .collect::<rusqlite::Result<_>>()
        .unwrap()
}

/// **A provider-REFUSED attempt is never re-run on the agent the provider
/// refused.** The panel names `codex` twice; its first attempt is an agent
/// turn the model provider refused, settled PROVEN NOT PERFORMED with the
/// class `refused`. The same request from the same agent is refused again, so
/// the stage fails at once naming the refusal: one frame reaches the worker,
/// the raw chain holds one `failed` attempt, and its accepting transition
/// records `provider_failure = "refused"`.
///
/// **Would red if:** the chain's walk did not record the refused agent
/// (watched, with `PanelWalk::after_failure`'s refused-label push removed: a
/// second frame on `codex`, and the run completes).
#[tokio::test(flavor = "current_thread")]
async fn a_provider_refused_attempt_is_not_rerun_on_the_agent_it_refused() {
    let rig = rig(&tempfile::tempdir().unwrap().keep());
    rig.declare_bound_environment();
    let program = program_of(SAME_AGENT_PANEL_PACK);
    let execution = Ulid::new();
    let (outcome, frames) = drive(
        &rig,
        &program,
        execution,
        &[Answer::ProviderFail(ProviderFailureClass::Refused)],
    )
    .await;
    let error = outcome
        .expect_err("a refused request is not re-sent by the same agent")
        .to_string();
    assert!(
        error.contains("the model provider refused agent \"codex\"'s request"),
        "the stage fails naming the refusal: {error}"
    );
    assert_eq!(
        frames.len(),
        1,
        "no re-run of the refused agent: {frames:?}"
    );
    assert_eq!(chain_states(&rig, execution), ["failed"]);
    assert_eq!(
        first_attempts_provider_failure(&rig, execution).as_deref(),
        Some("refused")
    );
}

/// **A provider-REFUSED attempt falls back to a panel member that is another
/// agent.** On the `[codex, codex2]` panel the primary's turn is refused by
/// its provider; the next member is a different agent, so the panel advances
/// as for any not-performed failure and `codex2` completes the stage.
///
/// **Would red if:** a refusal spent the chain whatever the panel held
/// (watched, with `PanelWalk::after_failure` answering `Spent` for every
/// refusal: the run fails after one frame).
#[tokio::test(flavor = "current_thread")]
async fn a_provider_refused_attempt_falls_back_to_another_panel_agent() {
    let rig = rig(&tempfile::tempdir().unwrap().keep());
    rig.declare_bound_environment();
    let program = program_of(PANEL_PACK);
    let execution = Ulid::new();
    let (outcome, frames) = drive(
        &rig,
        &program,
        execution,
        &[Answer::ProviderFail(ProviderFailureClass::Refused)],
    )
    .await;
    outcome.expect("the panel's other agent completes the stage");
    let agents: Vec<&str> = frames.iter().map(|frame| frame.0.as_str()).collect();
    assert_eq!(agents, ["codex", "codex2"]);
    assert_eq!(chain_states(&rig, execution), ["failed", "completed"]);
}

/// **A TRANSIENT provider failure is re-run by the stage's retry chain, on the
/// same agent, and the stage completes.** The panel names `codex` twice; its
/// first attempt is an agent turn whose provider failed transiently past the
/// harness's own retries, settled PROVEN NOT PERFORMED with the class
/// `transient`. The chain re-runs it on `codex` at `child(1)` — a fresh capsule
/// from the same base — and the second attempt completes. Raw: `failed`,
/// `completed`, the first recording `provider_failure = "transient"`.
///
/// **Would red if:** a transient failure spent the chain (watched, with
/// `PanelWalk::after_failure`'s transient arm answering `Spent`: the run fails
/// after one frame). The worker's own twin,
/// `agent_turn_capsule::a_transient_nanocode_failure_is_not_performed_and_a_fresh_attempt_completes`,
/// is red where the worker settled the turn as a lost protocol (PROVEN
/// AMBIGUOUS, never re-run).
#[tokio::test(flavor = "current_thread")]
async fn a_transient_provider_failure_is_rerun_on_the_same_agent_and_completes() {
    let rig = rig(&tempfile::tempdir().unwrap().keep());
    rig.declare_bound_environment();
    let program = program_of(SAME_AGENT_PANEL_PACK);
    let execution = Ulid::new();
    let (outcome, frames) = drive(
        &rig,
        &program,
        execution,
        &[Answer::ProviderFail(ProviderFailureClass::Transient)],
    )
    .await;
    outcome.expect("the re-run completes the stage");
    let agents: Vec<&str> = frames.iter().map(|frame| frame.0.as_str()).collect();
    assert_eq!(agents, ["codex", "codex"], "the same agent runs again");
    let mut retry_seat = frames[0].1.clone();
    retry_seat.push(1);
    assert_eq!(frames[1].1, retry_seat, "the re-run sits at child(1)");
    assert_eq!(chain_states(&rig, execution), ["failed", "completed"]);
    assert_eq!(
        first_attempts_provider_failure(&rig, execution).as_deref(),
        Some("transient")
    );
}

/// One agent stage on ONE agent, no fallback panel: the default stage.
const SINGLE_AGENT_PACK: &str = "p = stage(\n\
     \x20   id = \"p\",\n\
     \x20   agent = \"codex\",\n\
     \x20   prompt = \"answer\",\n\
     \x20   sandbox = \"work\",\n\
     )\n\
     workflow(\"failure-retry-oci\", root = [p], sandbox_profiles = \
     {\"work\": sandbox_profile(workspace = \"ro\", net = \"host\")})\n";

/// A three-member panel whose LAST member is its first agent again.
const RETURNING_AGENT_PANEL_PACK: &str = "p = stage(\n\
     \x20   id = \"p\",\n\
     \x20   agent = [\"codex\", \"codex2\", \"codex\"],\n\
     \x20   prompt = \"answer\",\n\
     \x20   sandbox = \"work\",\n\
     )\n\
     workflow(\"failure-retry-oci\", root = [p], sandbox_profiles = \
     {\"work\": sandbox_profile(workspace = \"ro\", net = \"host\")})\n";

/// A three-member panel naming its first agent twice before another.
const REPEATED_AGENT_PANEL_PACK: &str = "p = stage(\n\
     \x20   id = \"p\",\n\
     \x20   agent = [\"codex\", \"codex\", \"codex2\"],\n\
     \x20   prompt = \"answer\",\n\
     \x20   sandbox = \"work\",\n\
     )\n\
     workflow(\"failure-retry-oci\", root = [p], sandbox_profiles = \
     {\"work\": sandbox_profile(workspace = \"ro\", net = \"host\")})\n";

/// **A single-agent stage re-runs a TRANSIENT provider failure on its agent,
/// with no fallback panel, and completes.** The default stage names one agent;
/// its first attempt's provider failed transiently past the harness's own
/// retries. The stage's failure retry re-runs it on the same agent at
/// `child(1)`, a fresh capsule from the same base, and the stage completes.
/// Raw: `failed`, `completed`, the first recording `provider_failure =
/// "transient"`.
///
/// **Would red if:** only a fallback panel re-ran a failed attempt (watched,
/// before the chain's walk re-ran transient failures: the run failed after one
/// frame, "failed after 0 retries").
#[tokio::test(flavor = "current_thread")]
async fn a_single_agent_stage_reruns_a_transient_provider_failure_and_completes() {
    let rig = rig(&tempfile::tempdir().unwrap().keep());
    rig.declare_bound_environment();
    let program = program_of(SINGLE_AGENT_PACK);
    let execution = Ulid::new();
    let (outcome, frames) = drive(
        &rig,
        &program,
        execution,
        &[Answer::ProviderFail(ProviderFailureClass::Transient)],
    )
    .await;
    outcome.expect("the re-run completes the stage");
    let agents: Vec<&str> = frames.iter().map(|frame| frame.0.as_str()).collect();
    assert_eq!(agents, ["codex", "codex"], "the same agent runs again");
    let mut retry_seat = frames[0].1.clone();
    retry_seat.push(1);
    assert_eq!(frames[1].1, retry_seat, "the re-run sits at child(1)");
    assert_eq!(chain_states(&rig, execution), ["failed", "completed"]);
    assert_eq!(
        first_attempts_provider_failure(&rig, execution).as_deref(),
        Some("transient")
    );
}

/// **A stage's transient provider failures are re-run on their agent at most
/// `TRANSIENT_PROVIDER_RERUNS` (2) times, and a refusal or any other failure
/// of a single-agent stage is not re-run.** Three transient failures in a row
/// on the one-agent stage: two re-runs, then the stage fails naming the spent
/// re-runs, three frames in all, every one on `codex`. A refused turn, and a
/// PERFORMED BUT FAILED one, on the same stage fail it after one frame.
///
/// **Would red if:** transient re-runs were unbounded (watched, with
/// `PanelWalk::after_failure`'s `TRANSIENT_PROVIDER_RERUNS` test removed: a
/// fourth frame, and the run completes), or every provider failure were re-run
/// as transient (a second frame for the refusal), or the re-run admitted any
/// retryable failure (a second frame for the performed-but-failed attempt).
#[tokio::test(flavor = "current_thread")]
async fn a_single_agent_stage_reruns_transient_failures_twice_and_nothing_else() {
    let transient = Answer::ProviderFail(ProviderFailureClass::Transient);
    let program = program_of(SINGLE_AGENT_PACK);
    let spent = rig(&tempfile::tempdir().unwrap().keep());
    spent.declare_bound_environment();
    let execution = Ulid::new();
    let (outcome, frames) = drive(&spent, &program, execution, &[transient; 4]).await;
    let error = outcome
        .expect_err("a third transient failure fails the stage")
        .to_string();
    assert!(
        error.contains("after 2 re-run(s) of a transient model provider failure"),
        "the stage names the spent re-runs: {error}"
    );
    let agents: Vec<&str> = frames.iter().map(|frame| frame.0.as_str()).collect();
    assert_eq!(agents, ["codex"; 3], "attempt 0 and its two re-runs");
    assert_eq!(chain_states(&spent, execution), ["failed"; 3]);

    for (answer, label) in [
        (
            Answer::ProviderFail(ProviderFailureClass::Refused),
            "refused",
        ),
        (
            Answer::Fail(DeliveryFailureProvenance::PerformedButFailed),
            "performed but failed",
        ),
    ] {
        let once = rig(&tempfile::tempdir().unwrap().keep());
        once.declare_bound_environment();
        let execution = Ulid::new();
        let (outcome, frames) = drive(&once, &program, execution, &[answer]).await;
        outcome.expect_err(label);
        assert_eq!(frames.len(), 1, "{label}: no re-run: {frames:?}");
        assert_eq!(chain_states(&once, execution), ["failed"], "{label}");
    }
}

/// Each attempt of `execution`'s stage `p`, in ordinal order: the instant the
/// chain recorded its first transition (its claim) and, when it reached one, its
/// `failed` terminal — read raw.
fn seat_instants(rig: &OciNodeRig, execution: Ulid) -> Vec<(i64, Option<i64>)> {
    stage_seat_instants(rig, execution, "p")
}

/// [`seat_instants`] for `execution`'s stage `stage`.
fn stage_seat_instants(rig: &OciNodeRig, execution: Ulid, stage: &str) -> Vec<(i64, Option<i64>)> {
    raw(&rig.op_path)
        .prepare(
            "SELECT (SELECT MIN(t.recorded_at_ms) FROM transitions t
                      WHERE t.attempt_id = a.attempt_id),
                    (SELECT MAX(t.recorded_at_ms) FROM transitions t
                      WHERE t.attempt_id = a.attempt_id AND t.resulting_state = 'failed')
               FROM attempts a WHERE a.execution_id = ?1 AND a.stage_id = ?2
              ORDER BY a.attempt_ordinal",
        )
        .unwrap()
        .query_map(
            rusqlite::params![execution.to_bytes().as_slice(), stage],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap()
        .collect::<rusqlite::Result<_>>()
        .unwrap()
}

/// **A transient provider re-run waits its BACKOFF, measured from the failed
/// seat's terminal frame.** Under a 700 ms then 1400 ms backoff, the one-agent
/// stage's first two attempts fail transiently and its third completes. Read
/// raw: re-run 1's claim is recorded at least 700 ms after attempt 0's `failed`
/// frame, and re-run 2's at least 1400 ms after attempt 1's. (A loaded host only
/// widens the gaps.)
///
/// **Would red if:** a re-run were dispatched at once (watched, with
/// `execute_failure_retries` draining every queued seat whatever its due
/// instant: gaps of a few milliseconds).
#[tokio::test(flavor = "current_thread")]
async fn a_transient_rerun_waits_its_backoff_from_the_failed_frame() {
    let rig = rig(&tempfile::tempdir().unwrap().keep());
    rig.declare_bound_environment();
    let program = program_of(SINGLE_AGENT_PACK);
    let execution = Ulid::new();
    let transient = Answer::ProviderFail(ProviderFailureClass::Transient);
    let (outcome, frames) = drive_runner(
        &rig,
        rig.runner(&program, execution)
            .with_transient_rerun_backoff_for_test([700, 1400]),
        &[transient, transient],
    )
    .await;
    outcome.expect("the second re-run completes the stage");
    assert_eq!(frames.len(), 3, "attempt 0 and two re-runs: {frames:?}");
    let seats = seat_instants(&rig, execution);
    let gaps: Vec<i64> = seats
        .windows(2)
        .map(|pair| pair[1].0 - pair[0].1.expect("a re-run follows a failed seat"))
        .collect();
    assert!(
        gaps.len() == 2 && gaps[0] >= 700 && gaps[1] >= 1400,
        "each re-run's claim waits its backoff after the failed frame: gaps {gaps:?} ms, \
         seats {seats:?}"
    );
}

/// **A transient re-run's due instant survives a main restart.** Under a 5 s
/// backoff the one-agent stage's first attempt fails transiently and the run
/// dies with the re-run queued, undispatched (it is no durable row). 5.2 s
/// later — past the due instant — a fresh runner replays the chain: it
/// re-derives the re-run AND its due instant from the failed frame, so the
/// re-run is claimed at once, not 5 s after the resume. Read raw: the re-run's
/// claim is recorded at least 5 s after attempt 0's `failed` frame, and less
/// than 5 s after the resumed runner started; it completes the stage.
///
/// **Would red if:** the due instant were measured from the clock the fold runs
/// under (watched, with `capsule_failure_retry` anchoring the backoff at
/// `now_ms()`: the resumed runner waited a fresh 5 s).
#[tokio::test(flavor = "current_thread")]
async fn a_transient_reruns_due_instant_survives_a_main_restart() {
    let rig = rig(&tempfile::tempdir().unwrap().keep());
    rig.declare_bound_environment();
    let program = program_of(SINGLE_AGENT_PACK);
    let execution = Ulid::new();
    {
        let runner = rig
            .runner(&program, execution)
            .with_transient_rerun_backoff_for_test([5_000, 5_000]);
        let reactor = reactor(&rig);
        let run = runner.run();
        tokio::pin!(run);
        let first = tokio::time::timeout(Duration::from_secs(30), async {
            tokio::select! {
                outcome = &mut run => panic!("the run resolved before its first frame: {outcome:?}"),
                frame = next_frame(&rig) => frame,
            }
        })
        .await
        .expect("attempt 0's frame arrives");
        answer(
            &rig,
            &reactor,
            &first,
            Answer::ProviderFail(ProviderFailureClass::Transient),
        );
    } // `run` drops with the block — the main died.
    tokio::time::sleep(Duration::from_millis(5_200)).await;
    let resumed_at = i64::try_from(kata_types::time::now_ms()).unwrap();
    let (outcome, frames) = drive_runner(
        &rig,
        rig.runner(&program, execution)
            .with_transient_rerun_backoff_for_test([5_000, 5_000]),
        &[Answer::Complete(b"done\n")],
    )
    .await;
    outcome.expect("the resumed runner's re-run completes the stage");
    assert_eq!(
        frames.len(),
        1,
        "the resumed runner dispatches the re-run once"
    );
    let seats = seat_instants(&rig, execution);
    let failed_at = seats[0].1.expect("attempt 0 failed");
    let rerun_at = seats.get(1).expect("the re-run was claimed").0;
    assert!(
        rerun_at - failed_at >= 5_000 && rerun_at - resumed_at < 5_000,
        "the re-run is due 5 s after the failed frame, not 5 s after the resume: failed \
         {failed_at}, resumed {resumed_at}, re-run claimed {rerun_at}"
    );
}

/// **A run whose only open work is a transient re-run inside its backoff
/// detaches on a graceful shutdown.** Under a ten-minute backoff the one-agent
/// stage's first attempt fails transiently; once that failure is durable the
/// main begins its ordered shutdown, and the run hands itself back
/// (`AdmissionClosed`) within the cell's 20 s budget instead of holding the drain
/// for the backoff. Nothing is lost: read raw, the chain holds the one failed
/// attempt and no re-run, which a replay re-derives with its due instant.
///
/// **Would red if:** `detach_loses_nothing` did not count a queued re-run not
/// yet due as a park (watched: the run kept waiting and the 20 s budget
/// expired).
#[tokio::test(flavor = "current_thread")]
async fn a_run_waiting_out_a_transient_backoff_detaches_on_shutdown() {
    let rig = rig(&tempfile::tempdir().unwrap().keep());
    rig.declare_bound_environment();
    let program = program_of(SINGLE_AGENT_PACK);
    let execution = Ulid::new();
    let runner = rig
        .runner(&program, execution)
        .with_transient_rerun_backoff_for_test([600_000, 600_000]);
    let reactor = reactor(&rig);
    let run = runner.run();
    tokio::pin!(run);
    let mut answered = false;
    let mut stopping = false;
    let outcome = tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            tokio::select! {
                outcome = &mut run => break outcome,
                frame = next_frame(&rig), if !answered => {
                    answer(&rig, &reactor, &frame, Answer::ProviderFail(ProviderFailureClass::Transient));
                    answered = true;
                }
                () = tokio::time::sleep(Duration::from_millis(50)), if answered && !stopping => {
                    if chain_states(&rig, execution) == ["failed"] {
                        rig.dispatcher.begin_graceful_shutdown();
                        stopping = true;
                    }
                }
            }
        }
    })
    .await
    .expect("the stopping run detaches instead of holding the drain");
    assert!(
        matches!(
            outcome,
            Err(kata_types::error::KataError::AdmissionClosed(_))
        ),
        "{outcome:?}"
    );
    assert_eq!(
        chain_states(&rig, execution),
        ["failed"],
        "detaching dispatched and terminalized nothing"
    );
}

/// **A cancel latched while a transient re-run waits out its backoff ends the
/// run at once.** Under a ten-minute backoff the one-agent stage's first attempt
/// fails transiently; once that failure is durable the execution's cancel is
/// latched (`OperationalDb::latch_execution_cancel`, the operator cancel's first
/// write). The runner ends within the cell's 5 s budget, its re-run's claim
/// refused by the latch (`claim_after_terminal_intent`), as a run latched
/// between two stages ends. Raw: the chain holds the one failed attempt.
///
/// **Would red if:** the drain waited the backoff out under the latch (watched,
/// with the drain's latch read removed: the 5 s budget expired).
#[tokio::test(flavor = "current_thread")]
async fn a_cancel_latched_inside_a_transient_backoff_ends_the_run_at_once() {
    let rig = rig(&tempfile::tempdir().unwrap().keep());
    rig.declare_bound_environment();
    let program = program_of(SINGLE_AGENT_PACK);
    let execution = Ulid::new();
    let runner = rig
        .runner(&program, execution)
        .with_transient_rerun_backoff_for_test([600_000, 600_000]);
    let reactor = reactor(&rig);
    let run = runner.run();
    tokio::pin!(run);
    let mut answered = false;
    let mut latched = false;
    let outcome = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            tokio::select! {
                outcome = &mut run => break outcome,
                frame = next_frame(&rig), if !answered => {
                    answer(&rig, &reactor, &frame, Answer::ProviderFail(ProviderFailureClass::Transient));
                    answered = true;
                }
                () = tokio::time::sleep(Duration::from_millis(50)), if answered && !latched => {
                    if chain_states(&rig, execution) == ["failed"] {
                        assert!(
                            rig.dispatcher
                                .execution_lifecycle()
                                .db()
                                .latch_execution_cancel(execution, "the operator's cancel")
                                .expect("the cancel latches"),
                            "the cancel wrote the latch"
                        );
                        latched = true;
                    }
                }
            }
        }
    })
    .await
    .expect("the latched run ends inside its backoff");
    let error = outcome.expect_err("the re-run is not claimed").to_string();
    assert!(error.contains("claim_after_terminal_intent"), "{error}");
    assert_eq!(
        chain_states(&rig, execution),
        ["failed"],
        "no re-run was claimed"
    );
}

/// The walk-away rows of `execution`, read raw: `persist_walkaway_halt` records
/// each as a `failed` STAGE-scope transition on a synthetic `#bound-halt-<kind>`,
/// `#budget-halt` or `#metering-halt` stage, and writes no `attempts` row.
fn walk_away_transitions(rig: &OciNodeRig, execution: Ulid) -> i64 {
    raw(&rig.op_path)
        .query_row(
            "SELECT count(*) FROM transitions
              WHERE execution_id = ?1 AND scope = 'stage' AND resulting_state = 'failed'
                AND (stage_id LIKE '%#bound-halt-%' OR stage_id LIKE '%#budget-halt'
                     OR stage_id LIKE '%#metering-halt')",
            [execution.to_bytes().as_slice()],
            |row| row.get(0),
        )
        .unwrap()
}

/// **A transient re-run due past the run's `time_bound` is not dispatched.**
/// Under a `time_bound(1500)` and a 4 s backoff the one-agent stage's first
/// attempt fails transiently at once: its re-run would be due about 4 s into the
/// run, past the bound, where its own terminal could only trip it. The stage
/// fails at once, naming the bound; raw, the chain holds the one failed attempt
/// and no walk-away row.
///
/// **Would red if:** the re-run were queued whatever its due instant (watched,
/// with `capsule_failure_retry`'s time-bound read removed: a second attempt
/// claimed 4 s after the first, and the run walked away at its terminal).
#[tokio::test(flavor = "current_thread")]
async fn a_transient_rerun_due_past_the_time_bound_is_not_dispatched() {
    let rig = rig(&tempfile::tempdir().unwrap().keep());
    rig.declare_bound_environment();
    let source = SINGLE_AGENT_PACK.replace(
        "sandbox_profiles = ",
        "bounds = [time_bound(1500)], sandbox_profiles = ",
    );
    assert!(source.contains("time_bound(1500)"), "{source}");
    let program = program_of(&source);
    let execution = Ulid::new();
    let started = std::time::Instant::now();
    let (outcome, frames) = drive_runner(
        &rig,
        rig.runner(&program, execution)
            .with_transient_rerun_backoff_for_test([4_000, 4_000]),
        &[
            Answer::ProviderFail(ProviderFailureClass::Transient),
            Answer::Complete(b"done\n"),
        ],
    )
    .await;
    let error = outcome.expect_err("the stage fails").to_string();
    assert!(
        error.contains("past the run's 1500 ms `time_bound`, so it is not dispatched"),
        "{error}"
    );
    assert_eq!(frames.len(), 1, "one attempt, no re-run: {frames:?}");
    assert_eq!(chain_states(&rig, execution), ["failed"]);
    assert_eq!(
        walk_away_transitions(&rig, execution),
        0,
        "no walk-away row: the bound never tripped"
    );
    assert!(
        started.elapsed() < Duration::from_secs(4),
        "the stage failed without waiting the backoff out: {:?}",
        started.elapsed()
    );
}

/// **A `loop(..)` member's transient provider failure is re-run on its agent,
/// after its backoff, and the loop goes on.** Under a 600 ms backoff the loop's
/// agent member `worker` fails transiently on its first attempt; the loop's own
/// seat walk re-runs it at the member seat's `child(1)` with the same prompt (no
/// feedback), the re-run completes, and the shell gate approves. Raw: the
/// re-run's claim is recorded at least 600 ms after the failed attempt's
/// `failed` frame.
///
/// **Would red if:** a loop member's transient failure ended the loop (watched,
/// with the derive's transient arm disabled: one `worker` frame, and the run
/// failed "review loop aborted"), or the re-run were due at once (watched, with
/// the derive's due test disabled: a gap of a few milliseconds).
#[tokio::test(flavor = "current_thread")]
async fn a_loop_members_transient_provider_failure_is_rerun_after_its_backoff() {
    let rig = rig(&tempfile::tempdir().unwrap().keep());
    rig.declare_bound_environment();
    let program = program_of(LOOP_FEEDBACK_PACK);
    let execution = Ulid::new();
    let (outcome, frames) = drive_runner_by_stage(
        &rig,
        rig.runner(&program, execution)
            .with_transient_rerun_backoff_for_test([600, 600]),
        |stage, n| match (stage, n) {
            ("worker", 0) => Answer::ProviderFail(ProviderFailureClass::Transient),
            ("worker", _) => Answer::Complete(b"{\"stage\":\"w\",\"marker\":1}"),
            _ => Answer::CompleteStdout(b"{\"decision\":\"promote\",\"feedback\":\"ship\"}"),
        },
    )
    .await;
    outcome.expect("the re-run member's loop approves");
    let workers: Vec<_> = frames.iter().filter(|f| f.0 == "worker").collect();
    assert_eq!(workers.len(), 2, "attempt 0 plus one re-run: {frames:?}");
    let mut rerun_seat = workers[0].1.clone();
    rerun_seat.push(1);
    assert_eq!(
        workers[1].1, rerun_seat,
        "the re-run sits at the member seat's child(1)"
    );
    assert_eq!(
        workers[1].2, workers[0].2,
        "the re-run's prompt is attempt 0's, with no feedback"
    );
    let seats = stage_seat_instants(&rig, execution, "worker");
    let gap = seats[1].0 - seats[0].1.expect("attempt 0 failed");
    assert!(
        gap >= 600,
        "the re-run's claim waits its backoff after the failed frame: {gap} ms, {seats:?}"
    );
}

/// **A `loop(..)` member's transient re-runs are bounded as a plain stage's
/// are.** Three transient failures of `worker` in a row: two re-runs, then the
/// loop fails on the third, three `worker` frames in all and no gate frame.
///
/// **Would red if:** a loop member's transient re-runs were unbounded (watched,
/// with the derive's `TRANSIENT_PROVIDER_RERUNS` test removed: a fourth frame,
/// and the loop approved).
#[tokio::test(flavor = "current_thread")]
async fn a_loop_members_transient_reruns_are_bounded() {
    let rig = rig(&tempfile::tempdir().unwrap().keep());
    rig.declare_bound_environment();
    let program = program_of(LOOP_FEEDBACK_PACK);
    let execution = Ulid::new();
    let (outcome, frames) = drive_runner_by_stage(
        &rig,
        rig.runner(&program, execution)
            .with_transient_rerun_backoff_for_test([0, 0]),
        |stage, n| match (stage, n) {
            ("worker", 0..=2) => Answer::ProviderFail(ProviderFailureClass::Transient),
            ("worker", _) => Answer::Complete(b"{\"stage\":\"w\",\"marker\":1}"),
            _ => Answer::CompleteStdout(b"{\"decision\":\"promote\",\"feedback\":\"ship\"}"),
        },
    )
    .await;
    let error = outcome
        .expect_err("a third transient failure fails the loop")
        .to_string();
    assert!(
        error.contains("worker"),
        "the loop names its member: {error}"
    );
    let stages: Vec<&str> = frames.iter().map(|f| f.0.as_str()).collect();
    assert_eq!(
        stages, ["worker"; 3],
        "attempt 0 and two re-runs, no gate: {frames:?}"
    );
}

/// **A run whose only open work is a `loop(..)` member's transient re-run inside
/// its backoff detaches on a graceful shutdown.** Under a ten-minute backoff the
/// loop's agent member fails transiently; once that failure is durable the main
/// begins its ordered shutdown, and the run hands itself back (`AdmissionClosed`)
/// within the cell's 20 s budget instead of holding the drain for the backoff.
/// Nothing is lost: raw, one `worker` attempt, failed, and the loop's own main
/// attempt still `pending`, which a replay re-derives with its member's due
/// instant.
///
/// **Would red if:** `detach_loses_nothing` counted the loop's pending main
/// attempt as open work whatever its derive (watched, with the backoff probe
/// answering `false`: the 20 s budget expired).
#[tokio::test(flavor = "current_thread")]
async fn a_loop_waiting_out_its_members_backoff_detaches_on_shutdown() {
    let rig = rig(&tempfile::tempdir().unwrap().keep());
    rig.declare_bound_environment();
    let program = program_of(LOOP_FEEDBACK_PACK);
    let execution = Ulid::new();
    let runner = rig
        .runner(&program, execution)
        .with_transient_rerun_backoff_for_test([600_000, 600_000]);
    let reactor = reactor(&rig);
    let run = runner.run();
    tokio::pin!(run);
    let mut answered = false;
    let mut stopping = false;
    let outcome = tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            tokio::select! {
                outcome = &mut run => break outcome,
                frame = next_frame(&rig), if !answered => {
                    answer(&rig, &reactor, &frame, Answer::ProviderFail(ProviderFailureClass::Transient));
                    answered = true;
                }
                () = tokio::time::sleep(Duration::from_millis(50)), if answered && !stopping => {
                    let seats = stage_seat_instants(&rig, execution, "worker");
                    if seats.len() == 1 && seats[0].1.is_some() {
                        rig.dispatcher.begin_graceful_shutdown();
                        stopping = true;
                    }
                }
            }
        }
    })
    .await
    .expect("the stopping loop run detaches instead of holding the drain");
    assert!(
        matches!(
            outcome,
            Err(kata_types::error::KataError::AdmissionClosed(_))
        ),
        "{outcome:?}"
    );
    assert_eq!(
        stage_seat_instants(&rig, execution, "worker").len(),
        1,
        "detaching dispatched nothing"
    );
    let open_main: Vec<String> = raw(&rig.op_path)
        .prepare(
            "SELECT p.state FROM attempts a JOIN attempt_projection p
               ON p.execution_id = a.execution_id AND p.stage_id = a.stage_id
              AND p.attempt_ordinal = a.attempt_ordinal
             WHERE a.execution_id = ?1 AND a.executor = 'main'",
        )
        .unwrap()
        .query_map([execution.to_bytes().as_slice()], |row| row.get(0))
        .unwrap()
        .collect::<rusqlite::Result<_>>()
        .unwrap();
    assert_eq!(
        open_main,
        ["pending"],
        "the loop's own attempt stays pending for the replay"
    );
}

/// **A cancel latched while a `loop(..)` member's transient re-run waits out its
/// backoff ends the run at once.** Under a ten-minute backoff the loop's agent
/// member fails transiently; once that failure is durable the execution's cancel
/// is latched. The loop's walk, still driven under the latch, does not wait the
/// backoff out: the re-run's claim is refused (`claim_after_terminal_intent`)
/// and the runner ends inside the cell's 5 s budget. Raw: one `worker` attempt.
///
/// **Would red if:** the member walk waited a not-yet-due re-run out under the
/// latch (watched, with the derive's latch read removed: the 5 s budget
/// expired).
#[tokio::test(flavor = "current_thread")]
async fn a_cancel_latched_inside_a_loop_members_backoff_ends_the_run_at_once() {
    let rig = rig(&tempfile::tempdir().unwrap().keep());
    rig.declare_bound_environment();
    let program = program_of(LOOP_FEEDBACK_PACK);
    let execution = Ulid::new();
    let runner = rig
        .runner(&program, execution)
        .with_transient_rerun_backoff_for_test([600_000, 600_000]);
    let reactor = reactor(&rig);
    let run = runner.run();
    tokio::pin!(run);
    let mut answered = false;
    let mut latched = false;
    let outcome = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            tokio::select! {
                outcome = &mut run => break outcome,
                frame = next_frame(&rig), if !answered => {
                    answer(&rig, &reactor, &frame, Answer::ProviderFail(ProviderFailureClass::Transient));
                    answered = true;
                }
                () = tokio::time::sleep(Duration::from_millis(50)), if answered && !latched => {
                    let seats = stage_seat_instants(&rig, execution, "worker");
                    if seats.len() == 1 && seats[0].1.is_some() {
                        assert!(
                            rig.dispatcher
                                .execution_lifecycle()
                                .db()
                                .latch_execution_cancel(execution, "the operator's cancel")
                                .expect("the cancel latches"),
                            "the cancel wrote the latch"
                        );
                        latched = true;
                    }
                }
            }
        }
    })
    .await
    .expect("the latched loop run ends inside its member's backoff");
    let error = outcome.expect_err("the re-run is not claimed").to_string();
    assert!(error.contains("claim_after_terminal_intent"), "{error}");
    assert_eq!(
        stage_seat_instants(&rig, execution, "worker").len(),
        1,
        "no re-run was claimed"
    );
}

/// **A `loop(..)` member's transient re-run due past the run's `time_bound` is
/// not dispatched.** Under a workflow `time_bound(1500)` and a 4 s backoff the
/// loop's agent member fails transiently at once; its re-run would be due past
/// the bound, so the loop fails at once, its member's failure naming the bound.
/// Raw: one `worker` attempt and no walk-away row.
///
/// **Would red if:** the member walk queued the re-run whatever its due instant
/// (watched, with the derive's time-bound read removed: a second `worker`
/// attempt claimed after the backoff, and the run walked away at its terminal).
#[tokio::test(flavor = "current_thread")]
async fn a_loop_members_transient_rerun_due_past_the_time_bound_is_not_dispatched() {
    let rig = rig(&tempfile::tempdir().unwrap().keep());
    rig.declare_bound_environment();
    let source = LOOP_FEEDBACK_PACK.replace(
        "    sandbox_profiles = {",
        "    bounds = [time_bound(1500)],\n    sandbox_profiles = {",
    );
    assert!(source.contains("time_bound(1500)"), "{source}");
    let program = program_of(&source);
    let execution = Ulid::new();
    let started = std::time::Instant::now();
    let (outcome, frames) = drive_runner_by_stage(
        &rig,
        rig.runner(&program, execution)
            .with_transient_rerun_backoff_for_test([4_000, 4_000]),
        |stage, n| match (stage, n) {
            ("worker", 0) => Answer::ProviderFail(ProviderFailureClass::Transient),
            ("worker", _) => Answer::Complete(b"{\"stage\":\"w\",\"marker\":1}"),
            _ => Answer::CompleteStdout(b"{\"decision\":\"promote\",\"feedback\":\"ship\"}"),
        },
    )
    .await;
    let error = outcome.expect_err("the loop fails").to_string();
    assert!(
        error.contains("review loop aborted")
            && error.contains("past the run's 1500 ms `time_bound`, so it is not dispatched"),
        "{error}"
    );
    assert_eq!(frames.len(), 1, "one attempt, no re-run: {frames:?}");
    assert_eq!(
        walk_away_transitions(&rig, execution),
        0,
        "no walk-away row: the bound never tripped"
    );
    assert!(
        started.elapsed() < Duration::from_secs(4),
        "the loop failed without waiting the backoff out: {:?}",
        started.elapsed()
    );
}

/// Drive [`LOOP_FEEDBACK_PACK`] under a zero backoff with the loop member
/// `worker`'s first attempt answered `first`; returns the run's error and the
/// `worker` attempts' terminal states, read raw.
async fn loop_member_answered(first: Answer) -> (String, Vec<(i64, String)>) {
    let rig = rig(&tempfile::tempdir().unwrap().keep());
    rig.declare_bound_environment();
    let program = program_of(LOOP_FEEDBACK_PACK);
    let execution = Ulid::new();
    let (outcome, _) = drive_runner_by_stage(
        &rig,
        rig.runner(&program, execution)
            .with_transient_rerun_backoff_for_test([0, 0]),
        |stage, n| match (stage, n) {
            ("worker", 0) => first,
            ("worker", _) => Answer::Complete(b"{\"stage\":\"w\",\"marker\":1}"),
            _ => Answer::CompleteStdout(b"{\"decision\":\"promote\",\"feedback\":\"ship\"}"),
        },
    )
    .await;
    let error = outcome
        .expect_err("the member's one attempt ends the loop")
        .to_string();
    let terminals = raw(&rig.op_path)
        .prepare(
            "SELECT a.attempt_ordinal, t.resulting_state FROM transitions t
               JOIN attempts a ON a.attempt_id = t.attempt_id
              WHERE a.execution_id = ?1 AND a.stage_id = 'worker' AND t.scope = 'attempt'
                AND t.resulting_state IN ('completed', 'failed', 'orphaned', 'cancelled')
              ORDER BY t.seq",
        )
        .unwrap()
        .query_map([execution.to_bytes().as_slice()], |row| {
            Ok((row.get(0)?, row.get(1)?))
        })
        .unwrap()
        .collect::<rusqlite::Result<_>>()
        .unwrap();
    (error, terminals)
}

/// **A loop member settled PROVEN AMBIGUOUS is never re-run, whatever provider
/// class its terminal records.** The plain stage's rule: a failure kata cannot
/// rule out having had effects is never retried. The member's one attempt
/// answers PROVEN AMBIGUOUS beside a `transient` class; raw, the chain holds
/// that one `worker` attempt, and the loop fails on it.
///
/// **Would red if:** the loop's walk re-ran a transient class without the plain
/// stage's verdict gate (watched: a second `worker` attempt completed and the
/// loop approved).
#[tokio::test(flavor = "current_thread")]
async fn a_loop_member_settled_ambiguous_is_never_rerun_for_its_transient_class() {
    let (error, terminals) = loop_member_answered(Answer::FailClassed(
        DeliveryFailureProvenance::ProvenAmbiguous,
        ProviderFailureClass::Transient,
    ))
    .await;
    assert_eq!(terminals.len(), 1, "one worker attempt: {terminals:?}");
    assert!(error.contains("review loop aborted"), "{error}");
}

/// **A loop member the operator stopped is never re-run, whatever provider
/// class its terminal records.** The plain stage's rule: a cancelled fold never
/// enters the failure retry path. An operator stop is recorded on the member's
/// attempt, which then answers PROVEN NOT PERFORMED beside a `transient` class;
/// raw, the chain holds that one `worker` attempt, settled `cancelled`, and the
/// loop fails on it.
///
/// **Would red if:** the loop's walk re-ran a cancelled seat (watched: a second
/// `worker` attempt completed and the loop approved).
#[tokio::test(flavor = "current_thread")]
async fn a_loop_member_the_operator_stopped_is_never_rerun_for_its_transient_class() {
    let (error, terminals) = loop_member_answered(Answer::StoppedThenProviderFail(
        ProviderFailureClass::Transient,
    ))
    .await;
    assert_eq!(
        terminals,
        [(0, "cancelled".to_owned())],
        "one worker attempt, settled cancelled"
    );
    assert!(error.contains("review loop aborted"), "{error}");
}

/// **A refused agent is never re-run at a LATER seat of its panel.** On
/// `[codex, codex2, codex]` the provider refuses `codex`'s turn; the panel
/// falls back to `codex2`, which fails PERFORMED BUT FAILED. The panel's last
/// member is `codex` again, the agent the provider refused, so the stage fails
/// naming the refusal instead: two frames, `codex` then `codex2`.
///
/// **Would red if:** the retry decision compared the refused agent with the
/// panel's NEXT member only (watched, before the chain's walk: a third frame on
/// `codex`, and the run completed), or the walk did not record the refused agent (watched,
/// with `PanelWalk::after_failure`'s refused-label push removed: the same).
#[tokio::test(flavor = "current_thread")]
async fn a_refused_agent_is_never_rerun_at_a_later_panel_seat() {
    let rig = rig(&tempfile::tempdir().unwrap().keep());
    rig.declare_bound_environment();
    let program = program_of(RETURNING_AGENT_PANEL_PACK);
    let execution = Ulid::new();
    let (outcome, frames) = drive(
        &rig,
        &program,
        execution,
        &[
            Answer::ProviderFail(ProviderFailureClass::Refused),
            Answer::Fail(DeliveryFailureProvenance::PerformedButFailed),
        ],
    )
    .await;
    let error = outcome
        .expect_err("the panel holds no agent the provider did not refuse")
        .to_string();
    assert!(
        error.contains("the model provider refused agent \"codex\"'s request"),
        "the stage fails naming the refusal: {error}"
    );
    let agents: Vec<&str> = frames.iter().map(|frame| frame.0.as_str()).collect();
    assert_eq!(agents, ["codex", "codex2"], "codex never runs again");
    assert_eq!(chain_states(&rig, execution), ["failed", "failed"]);
}

/// **A refused agent's later panel seats are skipped to the panel's next OTHER
/// agent.** On `[codex, codex, codex2]` the provider refuses `codex`'s turn;
/// the panel's next member is `codex` again, so the chain skips it and runs
/// `codex2`, which completes the stage at `child(1)`.
///
/// **Would red if:** a refusal failed the stage whenever the panel's next
/// member was the refused agent (watched, before the chain's walk: one frame,
/// and the run failed), or the walk did not record the refused agent (watched, with
/// `PanelWalk::after_failure`'s refused-label push removed: a second frame on
/// `codex`).
#[tokio::test(flavor = "current_thread")]
async fn a_refused_agents_later_seats_are_skipped_to_another_agent() {
    let rig = rig(&tempfile::tempdir().unwrap().keep());
    rig.declare_bound_environment();
    let program = program_of(REPEATED_AGENT_PANEL_PACK);
    let execution = Ulid::new();
    let (outcome, frames) = drive(
        &rig,
        &program,
        execution,
        &[Answer::ProviderFail(ProviderFailureClass::Refused)],
    )
    .await;
    outcome.expect("the panel's other agent completes the stage");
    let agents: Vec<&str> = frames.iter().map(|frame| frame.0.as_str()).collect();
    assert_eq!(agents, ["codex", "codex2"]);
    let mut retry_seat = frames[0].1.clone();
    retry_seat.push(1);
    assert_eq!(frames[1].1, retry_seat, "the fallback sits at child(1)");
    assert_eq!(chain_states(&rig, execution), ["failed", "completed"]);
}

/// **A panel stage whose WORKER DIES mid-attempt is settled PROVEN AMBIGUOUS
/// and never re-run**, whatever its panel holds: the main cannot know what the
/// turn did, so a process death is no provider failure. The panel names
/// `codex` twice; the worker dies with the first attempt dispatched; the
/// worker-death leg settles it, and the run fails after one frame, the raw
/// chain holding one `failed` attempt whose reason names the death and the
/// verdict — the reason in prose, and the typed `verdict` the retry decision
/// reads, both off a second read-only handle.
///
/// **Would red if:** the retry decision re-ran a dead worker's attempt (a
/// second frame reaches the worker), or the settlement recorded no typed
/// `verdict` (watched: `NULL` on the base, whose settlements named their
/// verdict in the reason alone).
#[tokio::test(flavor = "current_thread")]
async fn a_panel_stage_whose_worker_dies_is_settled_ambiguous_and_never_rerun() {
    let rig = rig(&tempfile::tempdir().unwrap().keep());
    rig.declare_bound_environment();
    let program = program_of(SAME_AGENT_PANEL_PACK);
    let execution = Ulid::new();
    let runner = rig.runner(&program, execution);
    let mut frames = 0_usize;
    let run = runner.run();
    tokio::pin!(run);
    let outcome = tokio::time::timeout(Duration::from_secs(60), async {
        loop {
            tokio::select! {
                outcome = &mut run => break outcome,
                frame = next_frame(&rig) => {
                    frames += 1;
                    let settled = rig
                        .dispatcher
                        .handle_worker_death(
                            OCI_RIG_WORKER,
                            &kata_workflow::dispatcher::WorkerLoss::ConnectionClosed(
                                "the rig closed it".into(),
                            ),
                        )
                        .await
                        .expect("the worker-death leg runs");
                    assert!(settled.contains(&frame.attempt_id), "{settled:?}");
                }
            }
        }
    })
    .await
    .expect("the run reaches a terminal within the budget");
    outcome.expect_err("a dead worker's attempt fails the run");
    assert_eq!(frames, 1, "no re-run of an ambiguous attempt");
    assert_eq!(chain_states(&rig, execution), ["failed"]);
    let reason: String = raw(&rig.op_path)
        .query_row(
            "SELECT json_extract(t.payload_json, '$.reason') FROM transitions t
               JOIN attempts a ON a.attempt_id = t.attempt_id
              WHERE a.execution_id = ?1 AND a.stage_id = 'p'
              ORDER BY t.seq DESC LIMIT 1",
            [execution.to_bytes().as_slice()],
            |row| row.get(0),
        )
        .expect("the settlement's reason reads");
    assert!(
        reason.contains("PROVEN AMBIGUOUS") && reason.contains("died"),
        "{reason}"
    );
    let verdict: Option<String> = raw(&rig.op_path)
        .query_row(
            "SELECT json_extract(t.payload_json, '$.verdict') FROM transitions t
               JOIN attempts a ON a.attempt_id = t.attempt_id
              WHERE a.execution_id = ?1 AND a.stage_id = 'p'
              ORDER BY t.seq DESC LIMIT 1",
            [execution.to_bytes().as_slice()],
            |row| row.get(0),
        )
        .expect("the settlement's verdict reads");
    assert_eq!(
        verdict.as_deref(),
        Some("proven_ambiguous"),
        "the settlement records its verdict typed, not only in its reason"
    );
}

/// The typed `verdict` the LATEST terminal transition of `attempt` recorded,
/// off the raw second handle.
fn raw_terminal_verdict(path: &Path, attempt: Ulid) -> Option<String> {
    raw(path)
        .query_row(
            "SELECT json_extract(payload_json, '$.verdict') FROM transitions \
              WHERE attempt_id = ?1 AND folds_projection = 1 ORDER BY seq DESC LIMIT 1",
            [attempt.to_bytes().as_slice()],
            |row| row.get(0),
        )
        .expect("the attempt's terminal reads")
}

/// **A capsule the main's completion judgement refuses is settled PERFORMED BUT
/// FAILED, typed, and re-run on the panel's next member.** The first attempt's
/// process exits non-zero; `judge_capsule_completion` settles it through
/// `settle_capsule_attempt`, the production writer of the typed `verdict`, and
/// the runner's fold reads that verdict alone. Raw: attempt 0 `failed` with
/// `performed_but_failed`, the seat-1 retry on `codex2` `completed`.
///
/// **Watched red:** with `SettlementVerdict::provenance` mapping
/// `PerformedButFailed` to `ProvenAmbiguous`, attempt 0 records
/// `proven_ambiguous` and no retry frame is delivered.
#[tokio::test(flavor = "current_thread")]
async fn a_completion_judged_failed_is_settled_performed_but_failed_and_rerun() {
    let rig = rig(&tempfile::tempdir().unwrap().keep());
    rig.declare_bound_environment();
    let program = program_of(PANEL_PACK);
    let execution = Ulid::new();
    let (outcome, frames) = drive(&rig, &program, execution, &[Answer::CompleteExited(1)]).await;
    let agents: Vec<&str> = frames.iter().map(|frame| frame.0.as_str()).collect();
    let rows: Vec<(String, Option<String>)> = raw(&rig.op_path)
        .prepare(
            "SELECT p.state, (SELECT json_extract(t.payload_json, '$.verdict') FROM transitions t
                               WHERE t.attempt_id = a.attempt_id AND t.folds_projection = 1
                               ORDER BY t.seq DESC LIMIT 1)
               FROM attempts a JOIN attempt_projection p
                 ON p.execution_id = a.execution_id AND p.stage_id = a.stage_id
                AND p.attempt_ordinal = a.attempt_ordinal
              WHERE a.execution_id = ?1 AND a.stage_id = 'p' ORDER BY a.attempt_ordinal",
        )
        .unwrap()
        .query_map([execution.to_bytes().as_slice()], |row| {
            Ok((row.get(0)?, row.get(1)?))
        })
        .unwrap()
        .collect::<rusqlite::Result<_>>()
        .unwrap();
    assert_eq!(
        rows,
        [
            ("failed".to_owned(), Some("performed_but_failed".to_owned())),
            ("completed".to_owned(), None),
        ],
        "raw: the judged attempt's typed verdict, then the retry; frames {agents:?}"
    );
    assert_eq!(
        agents,
        ["codex", "codex2"],
        "the retry runs the next member"
    );
    outcome.expect("the panel's next member completes the stage");
}

/// **A capsule frame the delivery door cannot deliver is settled PROVEN NOT
/// PERFORMED, typed, and its seat's retry is queued.** Attempt 0 of a two-member
/// panel is claimed and placed at its chain seat; a malformed command row at its
/// epoch makes `frame_for_dispatch` fail, and `deliver_capsule_frame` settles it
/// through `settle_undelivered_capsule_attempt` — the production writer, not a
/// seeded terminal. The runner's fold of that terminal queues seat 1.
///
/// **Watched red:** with `SettlementVerdict::provenance` mapping
/// `ProvenNotPerformed` to `ProvenAmbiguous`, attempt 0 records
/// `proven_ambiguous` and the fold queues nothing.
#[tokio::test(flavor = "current_thread")]
async fn an_undelivered_capsule_is_settled_proven_not_performed_and_its_retry_queued() {
    let rig = rig(&tempfile::tempdir().unwrap().keep());
    rig.declare_bound_environment();
    let program = program_of(PANEL_PACK);
    let execution = Ulid::new();
    let runner = rig.runner(&program, execution);
    let (attempt, assignment_json) = seed_claimed_capsule_attempt_at(
        &rig.db,
        &rig.cas,
        "p",
        &chain_occurrence(&program, execution, "p", &[0], 0),
    );
    rig.db
        .dispatch_claimed_attempt(
            attempt,
            OCI_RIG_WORKER,
            Ulid::new(),
            &kata_core::operational::CommandSpec {
                command_json: assignment_json,
            },
        )
        .expect("the placement");
    // A command row at the attempt's epoch whose id is not a ULID, newer than the
    // real one, so the delivery door's stamp read decodes it and fails.
    rusqlite::Connection::open(&rig.op_path)
        .unwrap()
        .execute(
            "INSERT INTO attempt_commands (command_id, attempt_id, lease_epoch, command_json, \
             created_at_ms) SELECT X'0102', attempt_id, lease_epoch, X'7B7D', 9223372036854775807 \
             FROM attempts WHERE attempt_id = ?1",
            [attempt.to_bytes().as_slice()],
        )
        .unwrap();
    rig.dispatcher
        .deliver_capsule_frame(attempt)
        .await
        .expect_err("the frame cannot be built");
    assert_eq!(
        raw_terminal_verdict(&rig.op_path, attempt).as_deref(),
        Some("proven_not_performed"),
        "raw: the undelivered settlement records its verdict typed"
    );
    let reason = rig
        .db
        .attempt_terminal_reason(attempt)
        .expect("the reason reads")
        .expect("the settlement recorded a reason");
    assert!(
        capsule_failure_retry_for_test(&runner, "p", attempt, &reason)
            .expect("the fold adjudicates"),
        "a PROVEN NOT PERFORMED settlement queues its retry: {reason}"
    );
    assert_eq!(
        pending_failure_retries_for_test(&runner),
        vec![("p".to_owned(), 1)],
        "one seat-1 failure retry queued"
    );
}

/// **A failed terminal that records no typed `verdict` is never re-run, whatever
/// its reason says.** The retry decision reads the classification off the
/// terminal transition's `verdict` alone (`failure_is_retryable`): a reason is
/// operator-facing text, and one that merely SPELLS a retryable verdict clause
/// classifies nothing.
///
/// **Would red if:** the decision parsed the reason again (watched: on the base,
/// whose substring arm matched `PROVEN NOT PERFORMED:`, the fold queued the
/// seat-1 retry).
#[test]
fn a_failed_terminal_with_no_typed_verdict_is_never_rerun_whatever_its_reason_says() {
    let rig = rig(&tempfile::tempdir().unwrap().keep());
    rig.declare_bound_environment();
    let program = program_of(PANEL_PACK);
    let execution = Ulid::new();
    let runner = rig.runner(&program, execution);
    let reason = "the worker's capsule died on start. PROVEN NOT PERFORMED: no dispatch frame \
                  for this capsule attempt reached a worker";
    let attempt = seed_claimed_capsule_attempt_at(
        &rig.db,
        &rig.cas,
        "p",
        &chain_occurrence(&program, execution, "p", &[0], 0),
    )
    .0;
    fail_claimed_attempt(&rig, attempt, reason, None);
    let verdict: Option<String> = raw(&rig.op_path)
        .query_row(
            "SELECT json_extract(payload_json, '$.verdict') FROM transitions
              WHERE attempt_id = ?1 AND resulting_state = 'failed'",
            [attempt.to_bytes().as_slice()],
            |row| row.get(0),
        )
        .expect("the failed terminal reads");
    assert_eq!(
        verdict, None,
        "the seeded terminal carries no typed verdict"
    );
    assert!(
        !capsule_failure_retry_for_test(&runner, "p", attempt, reason)
            .expect("the failed fold adjudicates"),
        "a terminal with no typed verdict is not retried"
    );
    assert!(
        pending_failure_retries_for_test(&runner).is_empty(),
        "no retry seat is queued"
    );
}

/// A crash between a failed attempt and its retry: the
/// failure is durably settled, the retry never dispatched, and a fresh runner
/// re-derives the identical next seat from the durable chain — the queued
/// retry is never a durable row, so resume recomputes it. The resumed fold's
/// `mark_retry_pending_in_flight` is what keeps `advance` from re-submitting
/// the base seat beside the queued retry.
///
/// **Watched red**: with the `Retrying` arm's in-flight mark dropped, the
/// resumed run mints a second `dispatched` attempt at the base seat — the raw
/// chain ends `failed, completed, dispatched` instead of `failed, completed`.
#[tokio::test(flavor = "current_thread")]
async fn a_crashed_run_rederives_a_failed_attempts_retry() {
    let rig = rig(&tempfile::tempdir().unwrap().keep());
    rig.declare_bound_environment();
    let program = program_of(PANEL_PACK);
    let execution = Ulid::new();

    // Attempt 0 fails and settles durably; the run dies before it can fold.
    {
        let runner = rig.runner(&program, execution);
        let reactor = reactor(&rig);
        let run = runner.run();
        tokio::pin!(run);
        let first = tokio::time::timeout(Duration::from_secs(30), async {
            tokio::select! {
                outcome = &mut run => panic!("the run resolved without a retry to drive: {outcome:?}"),
                frame = next_frame(&rig) => frame,
            }
        })
        .await
        .expect("attempt 0's frame arrives");
        answer(
            &rig,
            &reactor,
            &first,
            Answer::Fail(DeliveryFailureProvenance::PerformedButFailed),
        );
    } // `run` drops with the block — the crash.

    // Raw: the failure is durable, the retry occurrence never minted.
    let seats: i64 = raw(&rig.op_path)
        .query_row(
            "SELECT COUNT(*) FROM attempts WHERE execution_id = ?1 AND stage_id = 'p'",
            [execution.to_bytes().as_slice()],
            |row| row.get(0),
        )
        .expect("the attempt count reads");
    assert_eq!(
        seats, 1,
        "one durable attempt — the retry was never dispatched"
    );

    // The resumed runner re-derives the retry and completes the stage.
    let runner = rig.runner(&program, execution);
    let reactor = reactor(&rig);
    let mut frames = Vec::new();
    let run = runner.run();
    tokio::pin!(run);
    let outcome = tokio::time::timeout(Duration::from_secs(60), async {
        loop {
            tokio::select! {
                outcome = &mut run => break outcome,
                frame = next_frame(&rig) => {
                    frames.push((frame_agent(&rig, &frame), frame_path(&rig, &frame)));
                    answer(&rig, &reactor, &frame, Answer::Complete(b"done\n"));
                }
            }
        }
    })
    .await
    .expect("the resumed drive reaches a terminal within the budget");
    outcome.expect("the resumed runner's derived retry completes the stage");
    assert_eq!(
        frames.len(),
        1,
        "the resumed runner dispatches exactly the pending retry: {frames:?}"
    );
    assert_eq!(
        frames[0].0, "codex2",
        "the derived retry runs the panel's next member"
    );
    assert_eq!(
        frames[0].1,
        vec![0, 1],
        "the derived retry sits at the stage seat's child(1)"
    );
    let states: Vec<String> = raw(&rig.op_path)
        .prepare(
            "SELECT p.state FROM attempts a JOIN attempt_projection p
               ON p.execution_id = a.execution_id AND p.stage_id = a.stage_id
              AND p.attempt_ordinal = a.attempt_ordinal
             WHERE a.execution_id = ?1 AND a.stage_id = 'p' ORDER BY a.attempt_ordinal",
        )
        .unwrap()
        .query_map([execution.to_bytes().as_slice()], |row| row.get(0))
        .unwrap()
        .collect::<rusqlite::Result<_>>()
        .unwrap();
    assert_eq!(
        states,
        ["failed", "completed"],
        "raw: the crashed chain's two attempts"
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// Mutation-survivor cells — the retry surface's dedup, seat and outcome gates. A
// fold observed twice (the broadcast leg AND the resync leg both re-fold a
// settled attempt, and a crash re-derives the fold wholesale) must mint each
// chain seat ONCE; a capsule attempt bound off its stage's chain seat is no
// retry seat at all; and an attempt settled CANCELLED never enters the
// failure-retry path, however retryable its recorded reason reads.
// ═══════════════════════════════════════════════════════════════════════════

/// The occurrence a capsule retry chain mints at `path` — the stage's own
/// contract, narrowed to the panel tail from `member`, the panel member the
/// seat runs on, exactly as `capsule_chain_seat` derives it. A seeded claim
/// bound to this occurrence IS the minted row the durable dedup reads.
fn chain_occurrence(
    program: &ExecutionProgram,
    execution: Ulid,
    stage: &str,
    path: &[u32],
    member: usize,
) -> OccurrenceRef {
    let stage_id = StageId(SmolStr::new(stage));
    let mut lowered = lower_stage_operation(program, &stage_id).expect("the stage lowers");
    lowered.path = OperationPath(path.to_vec());
    let panel = &program.stages[&stage_id].op.agent_panel;
    let index = member.min(panel.len().saturating_sub(1));
    if index > 0
        && let RuntimeOperation::Execute(ExecuteOperation {
            executor: ActionExecutor::Agent { drivers },
            ..
        }) = &mut lowered.contract.operation
    {
        *drivers = panel[index..].to_vec();
    }
    OccurrenceRef::new(
        ExecutionId(execution),
        program.program_hash,
        lowered.contract.id(),
        lowered.path,
    )
}

/// Settle a claimed attempt `failed` main-side, recording `verdict` as its
/// terminal transition's typed classification (`None`: it records none) — the
/// durable shape a main-side settlement writes.
fn fail_claimed_attempt(
    rig: &OciNodeRig,
    attempt_id: Ulid,
    reason: &str,
    verdict: Option<DeliveryFailureProvenance>,
) {
    rig.db
        .record_main_side_transition(
            attempt_id,
            &kata_core::operational::MainSideTransition {
                reason: Some(reason),
                verdict,
                ..kata_core::operational::MainSideTransition::bare("failed")
            },
        )
        .expect("the failed terminal lands");
}

/// A capsule validation fold that runs TWICE on the same settled attempt —
/// the broadcast leg and the resync leg both observe it — mints the retry's
/// chain seat once: the in-memory queue entry IS the dedup. And a re-fold of
/// the NEXT seat's own invalid completion queues the seat after it — the
/// `(base, attempt)` pair is the key, not the stage name alone.
///
/// **Mutant die**: `queued.base != *base` or `queued.attempt != next_attempt`
/// double-queue the re-folded seat; `==` for `||` dedups a retry that was
/// never queued (the seat-1 fold queues seat 2 while seat 1 sits pending);
/// `!minted || !queued` pushes through the queue's own answer.
#[tokio::test(flavor = "current_thread")]
async fn a_capsule_validation_retry_queues_once_per_chain_seat() {
    let rig = rig(&tempfile::tempdir().unwrap().keep());
    rig.declare_bound_environment();
    let program = program_of(AGENT_FEEDBACK_PACK);
    let execution = Ulid::new();
    let runner = rig.runner(&program, execution);
    let invalid = serde_json::json!({"content": "not json at all"});
    let (attempt0, _) = seed_claimed_capsule_attempt_at(
        &rig.db,
        &rig.cas,
        "p",
        &chain_occurrence(&program, execution, "p", &[0], 0),
    );
    assert!(
        inject_parsed_if_declared_for_test(&runner, "p", attempt0, invalid.clone())
            .expect("the first invalid fold adjudicates"),
        "the first invalid fold queues the retry"
    );
    assert_eq!(
        pending_validate_retries_for_test(&runner),
        vec![("p".to_owned(), 1)],
        "one seat-1 retry queued"
    );
    // The resync leg's re-fold of the same settled attempt queues nothing.
    assert!(
        inject_parsed_if_declared_for_test(&runner, "p", attempt0, invalid.clone())
            .expect("the re-fold adjudicates"),
        "the re-fold still reports QueuedRetry"
    );
    assert_eq!(
        pending_validate_retries_for_test(&runner),
        vec![("p".to_owned(), 1)],
        "a re-fold queues no second seat-1 retry"
    );
    // The seat-1 attempt's own invalid fold queues seat 2 — the attempt
    // coordinate is the dedup's, not the stage's alone.
    let (attempt1, _) = seed_claimed_capsule_attempt_at(
        &rig.db,
        &rig.cas,
        "p",
        &chain_occurrence(&program, execution, "p", &[0, 1], 0),
    );
    assert!(
        inject_parsed_if_declared_for_test(&runner, "p", attempt1, invalid)
            .expect("the seat-1 invalid fold adjudicates"),
        "the seat-1 fold queues the seat-2 retry"
    );
    assert_eq!(
        pending_validate_retries_for_test(&runner),
        vec![("p".to_owned(), 1), ("p".to_owned(), 2)],
        "the chain's pending seats, in order"
    );
}

/// A capsule attempt bound to NO coordinate of its stage's retry chain is no
/// retry seat: `capsule_retry_seat` answers `None` for a foreign `[_]` path,
/// a `[seat, attempt]` at the wrong seat or at `attempt` 0 — and the fold
/// refuses rather than queueing a retry off another stage's occurrence.
///
/// **Mutant die**: the `path == stage_path` or `*seat == stage_path.0[0] &&
/// *attempt >= 1` guard forced true, or its `&&` weakened to `||`, accepts a
/// bound-off attempt as a chain seat and queues a retry.
#[tokio::test(flavor = "current_thread")]
async fn a_capsule_attempt_bound_off_its_stages_seat_is_no_retry_seat() {
    let rig = rig(&tempfile::tempdir().unwrap().keep());
    rig.declare_bound_environment();
    let program = program_of(AGENT_FEEDBACK_PACK);
    let execution = Ulid::new();
    let runner = rig.runner(&program, execution);
    // Stage p sits at index 0 — its chain lives at [0] and [0].child(k).
    for foreign in [[7].as_slice(), &[0, 0], &[7, 2]] {
        let (attempt, _) = seed_claimed_capsule_attempt_at(
            &rig.db,
            &rig.cas,
            "p",
            &OccurrenceRef::new(
                ExecutionId(execution),
                program.program_hash,
                OperationContractId(ContentHash::new([0x6D; 32])),
                OperationPath(foreign.to_vec()),
            ),
        );
        let refusal = inject_parsed_if_declared_for_test(
            &runner,
            "p",
            attempt,
            serde_json::json!({"content": "not json at all"}),
        )
        .expect_err("an attempt bound off the chain's seat chains no retry");
        assert!(
            refusal
                .to_string()
                .contains("bound to no occurrence at the stage's retry seat"),
            "the refusal names the missing seat binding at {foreign:?}: {refusal}"
        );
    }
    assert!(
        pending_validate_retries_for_test(&runner).is_empty(),
        "no retry queued off a foreign occurrence"
    );
}

/// A `loop(..)` member that declares NO structured-output contract is never
/// revalidated: `member_output_validity` passes the accepted envelope through
/// for `outputs.is_empty() && output_schema.is_none()` — a contractless
/// member's free-form `content` is not asked to be JSON.
///
/// **Mutant die**: `||` for `&&` sends the contractless member through
/// `validate_and_inject_parsed`, its non-JSON `content` fails, and the loop
/// dies where it should promote.
#[tokio::test(flavor = "current_thread")]
async fn a_contractless_loop_member_is_not_revalidated() {
    const PACK: &str = r#"worker = stage(
    id = "worker",
    agent = "codex",
    prompt = "work",
    sandbox = "work",
)

controller = stage(
    id = "controller",
    agent = "shell",
    run = "printf '{\"decision\":\"promote\",\"feedback\":\"ship\"}\n'",
    depends_on = ["worker"],
    outputs = {
        "decision": "string",
        "feedback": "string",
    },
)

loop(
    body = worker,
    gate = controller,
    max_iterations = 2,
    on_exhaustion = "fail",
    gate_verdict = {
        "field": "decision",
        "approve": ["promote"],
        "refine": ["continue"],
        "block": ["stop"],
    },
)

workflow(
    "contractless-loop",
    root = [worker, controller],
    sandbox_profiles = {
        "work": sandbox_profile(workspace = "ro", net = "host"),
    },
)
"#;
    let rig = rig(&tempfile::tempdir().unwrap().keep());
    rig.declare_bound_environment();
    let program = program_of(PACK);
    let execution = Ulid::new();
    let (outcome, frames) = drive_by_stage(&rig, &program, execution, |stage, _| match stage {
        "worker" => Answer::Complete(b"plain prose, not JSON"),
        _ => Answer::CompleteStdout(b"{\"decision\":\"promote\",\"feedback\":\"ship\"}\n"),
    })
    .await;
    outcome.expect("a contractless member's free-form content promotes its loop");
    assert_eq!(
        frames.iter().filter(|f| f.0 == "worker").count(),
        1,
        "the member ran once — no phantom validation retry: {frames:?}"
    );
}

/// An attempt settled CANCELLED never enters the capsule failure-retry path:
/// the fold's `Failed | Cancelled` arm gates the retry on `Failed` alone —
/// a stop the operator recorded against the attempt is the stage's terminal,
/// not a seed for its chain. The settlement still records the worker's
/// retryable verdict, which is exactly why the gate must be the OUTCOME.
///
/// **Mutant die**: `Failed && is_capsule` weakened to `||` folds the
/// cancelled attempt through `capsule_failure_retry`, queues seat 1, and a
/// second frame reaches the worker — the operator's stop re-dispatched.
#[tokio::test(flavor = "current_thread")]
async fn a_cancelled_fold_never_enters_the_failure_retry_path() {
    let rig = rig(&tempfile::tempdir().unwrap().keep());
    rig.declare_bound_environment();
    let program = program_of(PANEL_PACK);
    let execution = Ulid::new();
    let runner = rig.runner(&program, execution);
    let reactor = reactor(&rig);
    let mut frames = Vec::new();
    let run = runner.run();
    tokio::pin!(run);
    let outcome = tokio::time::timeout(Duration::from_secs(60), async {
        loop {
            tokio::select! {
                outcome = &mut run => break outcome,
                frame = next_frame(&rig) => {
                    frames.push(frame.attempt_id);
                    if frames.len() == 1 {
                        rig.db
                            .record_stop_request(
                                frame.attempt_id,
                                frame.lease_epoch,
                                frame.placed_on.as_str(),
                                "operator cancelled the execution",
                            )
                            .expect("the stop records against the dispatched attempt");
                    }
                    answer(
                        &rig,
                        &reactor,
                        &frame,
                        Answer::Fail(DeliveryFailureProvenance::PerformedButFailed),
                    );
                }
            }
        }
    })
    .await
    .expect("the drive reaches a terminal within the budget");
    outcome.expect_err("an operator-stopped attempt fails the stage");
    assert_eq!(
        frames.len(),
        1,
        "a cancelled attempt is terminal — no failure retry is dispatched: {frames:?}"
    );
    let state: String = raw(&rig.op_path)
        .query_row(
            "SELECT resulting_state FROM transitions WHERE attempt_id = ?1 \
             ORDER BY seq DESC LIMIT 1",
            [frames[0].to_bytes().as_slice()],
            |row| row.get(0),
        )
        .expect("the attempt's last transition reads");
    assert_eq!(state, "cancelled", "the stop's outcome is the recorded one");
}

/// A THREE-member fallback panel exhausted says so in the panel phrasing,
/// naming every member and the two-advance budget the panel IS.
///
/// **Mutant die**: a budget of `panel.len()` instead of `panel.len() - 1`
/// dispatches a fourth frame and names three attempts — the property is the
/// spend the panel authorizes and the phrasing the operator reads.
#[tokio::test(flavor = "current_thread")]
async fn a_spent_three_member_panel_fails_in_legacys_exhaustion_phrasing() {
    let rig = OciNodeRig::open_with_programs(
        &tempfile::tempdir().unwrap().keep(),
        &["sh", "codex", "codex2", "codex3"],
    );
    rig.declare_bound_environment();
    let program = program_of(THREE_MEMBER_PANEL_PACK);
    let execution = Ulid::new();
    let (outcome, frames) = drive(
        &rig,
        &program,
        execution,
        &[Answer::Fail(DeliveryFailureProvenance::PerformedButFailed); 3],
    )
    .await;
    let text = outcome
        .expect_err("a spent three-member panel fails the stage")
        .to_string();
    assert!(
        text.contains(
            "stage failed after exhausting agent fallback panel [codex, codex2, codex3] across 2 \
             attempt(s)"
        ),
        "the exhaustion phrasing names the whole panel: {text}"
    );
    assert_eq!(
        frames.len(),
        3,
        "attempt 0 plus the two retries the budget authorizes: {frames:?}"
    );
}

/// Rewrite `attempt`'s durable completion frame to bill `micro_usd` authoritative micro-USD
/// — a stub completion bills nothing — before the runner folds it.
fn bill_completion(rig: &OciNodeRig, attempt: Ulid, micro_usd: u64) {
    let conn = rusqlite::Connection::open(&rig.op_path).unwrap();
    let (seq, payload): (i64, Vec<u8>) = conn
        .query_row(
            "SELECT seq, payload_json FROM transitions
              WHERE attempt_id = ?1 AND resulting_state = 'completed'",
            [attempt.to_bytes().as_slice()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .expect("the attempt's completed frame");
    let mut payload: serde_json::Value = serde_json::from_slice(&payload).unwrap();
    payload["output"]["token_usage"] = serde_json::json!({
        "cost": {"quality": "authoritative", "micro_usd": micro_usd},
        "cost_micro_usd": micro_usd,
    });
    let affected = conn
        .execute(
            "UPDATE transitions SET payload_json = ?1 WHERE seq = ?2",
            rusqlite::params![serde_json::to_vec(&payload).unwrap(), seq],
        )
        .expect("the bill lands");
    assert_eq!(
        affected, 1,
        "the bill rewrites exactly the frame at seq={seq}"
    );
}

/// **A panel stage's failure-retry seat dispatches nothing after a walk-away.** `x`, a
/// shell stage beside the panel stage `p`, bills 600 micro-USD against its own
/// `cost_budget("halt", 0.0005)` (the raw `x#budget-halt` row; `p`, under no hard cost
/// policy, trips nothing on its own charge); `p`'s first attempt fails PERFORMED BUT
/// FAILED — once the row is durable, or in `x`'s turn before `x`, so the fold queues the
/// panel's next member before the trip. Either way that member is never dispatched: `p` holds
/// exactly one row in the raw `attempts` table and no second frame reaches the worker,
/// the walk-away rows are exactly `x`'s, and the run fails naming the row and `p`'s
/// failure, which says the run walked away.
///
/// **Would red if:** the failure-retry drain dispatched a queued panel member without
/// consulting the durable walk-away (`codex2` runs `p` again), or only the fold consulted
/// it (the member queued before the trip dispatches).
#[tokio::test(flavor = "current_thread")]
async fn a_panel_stages_failure_retry_dispatches_nothing_after_a_walk_away() {
    let source = PANEL_PACK.replace(
        "workflow(\"failure-retry-oci\", root = [p],",
        "x = stage(id = \"x\", agent = \"shell\", run = \"true\", \
             cost_budget = cost_budget(\"halt\", 0.0005))\n\
             workflow(\"failure-retry-oci\", root = [x, p],",
    );
    assert!(
        source.contains(
            "cost_budget(\"halt\", 0.0005))\nworkflow(\"failure-retry-oci\", root = [x, p],"
        ),
        "`x` is spliced in: {source}"
    );
    let program = program_of(&source);
    let mut wrong = Vec::new();
    for together in [false, true] {
        let leg = if together {
            "failed in `x`'s turn, before it"
        } else {
            "failed after the row"
        };
        let rig = rig(&tempfile::tempdir().unwrap().keep());
        rig.declare_bound_environment();
        let execution = Ulid::new();
        let runner = rig.runner(&program, execution);
        let reactor = reactor(&rig);
        let walk_away_rows = || -> Vec<String> {
            raw(&rig.op_path)
                .prepare(
                    "SELECT stage_id FROM transitions
                      WHERE execution_id = ?1 AND scope = 'stage' AND resulting_state = 'failed'
                        AND (stage_id LIKE '%#bound-halt-%' OR stage_id LIKE '%#budget-halt'
                             OR stage_id LIKE '%#metering-halt')
                      ORDER BY seq",
                )
                .unwrap()
                .query_map([execution.to_bytes().as_slice()], |row| row.get(0))
                .unwrap()
                .collect::<rusqlite::Result<_>>()
                .unwrap()
        };
        let mut frames = Vec::new();
        let mut held_x = None;
        let mut held_p = None;
        let run = runner.run();
        tokio::pin!(run);
        let outcome = tokio::time::timeout(Duration::from_secs(60), async {
            loop {
                tokio::select! {
                    outcome = &mut run => break outcome,
                    frame = next_frame(&rig) => {
                        let stage_id = frame_stage_id(&rig, &frame);
                        match stage_id.as_str() {
                            "x" => held_x = Some(frame),
                            "p" if held_p.is_none() && !frames.iter().any(|seen| seen == "p") => {
                                held_p = Some(frame);
                            }
                            _ => answer(&rig, &reactor, &frame, Answer::Complete(b"done\n")),
                        }
                        frames.push(stage_id);
                    }
                    () = tokio::time::sleep(Duration::from_millis(20)) => {}
                }
                if held_p.is_some()
                    && let Some(x) = held_x.take()
                {
                    if together {
                        let p = held_p.take().expect("p is held");
                        answer(
                            &rig,
                            &reactor,
                            &p,
                            Answer::Fail(DeliveryFailureProvenance::PerformedButFailed),
                        );
                    }
                    answer(&rig, &reactor, &x, Answer::CompleteStdout(b"x ran"));
                    bill_completion(&rig, x.attempt_id, 600);
                } else if held_x.is_none()
                    && !walk_away_rows().is_empty()
                    && let Some(p) = held_p.take()
                {
                    answer(
                        &rig,
                        &reactor,
                        &p,
                        Answer::Fail(DeliveryFailureProvenance::PerformedButFailed),
                    );
                }
            }
        })
        .await
        .expect("the drive settles within the budget");
        let rows = walk_away_rows();
        let p_attempts: i64 = raw(&rig.op_path)
            .query_row(
                "SELECT COUNT(*) FROM attempts WHERE execution_id = ?1 AND stage_id = 'p'",
                [execution.to_bytes().as_slice()],
                |row| row.get(0),
            )
            .unwrap();
        let p_frames = frames.iter().filter(|stage| *stage == "p").count();
        let failed = outcome.as_ref().err().is_some_and(|error| {
            let error = error.to_string();
            error.contains("x#budget-halt")
                && error.contains("\"p\" failed")
                && error.contains("walked away")
        });
        if !(p_attempts == 1 && p_frames == 1 && rows == ["x#budget-halt"] && failed) {
            wrong.push(format!(
                "{leg}: frames {frames:?}, `p` ran {p_attempts} attempt(s), walk-away rows \
                 {rows:?}, the run {}",
                match &outcome {
                    Ok(_) => "completed".to_owned(),
                    Err(error) => format!("failed: {error}"),
                }
            ));
        }
    }
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
}

/// The capsule failure-retry fold is idempotent over BOTH halves of its
/// dedup — the in-memory queue entry and the minted durable occurrence — and
/// it queues for a settlement whose typed `verdict` is retryable (a terminal
/// recording none is a `Fail` —
/// `a_failed_terminal_with_no_typed_verdict_is_never_rerun_whatever_its_reason_says`).
///
/// **Mutant die**: `queued.base !=` or `queued.attempt !=` or `!minted ||
/// !queued` re-queue an already-queued seat; `failures * 1` asks the minted
/// check of the UNTRUNCATED contract — the retried seat's capsule narrows the
/// panel to its tail, so a fresh runner's re-fold after the retry's dispatch
/// misses and queues it again.
#[test]
fn a_capsule_failure_retry_queues_once_per_seat_and_only_when_retryable() {
    let rig = OciNodeRig::open_with_programs(
        &tempfile::tempdir().unwrap().keep(),
        &["sh", "codex", "codex2", "codex3"],
    );
    rig.declare_bound_environment();
    let program = program_of(THREE_MEMBER_PANEL_PACK);
    let execution = Ulid::new();
    let runner = rig.runner(&program, execution);
    // A main-side settlement records its typed verdict beside the reason's
    // clause; `failure_is_retryable` reads the verdict.
    let retryable = "the worker's capsule died on start: PROVEN NOT PERFORMED: no dispatch frame \
                     for this capsule attempt can have reached the worker";
    let attempt0 = seed_claimed_capsule_attempt_at(
        &rig.db,
        &rig.cas,
        "p",
        &chain_occurrence(&program, execution, "p", &[0], 0),
    )
    .0;
    fail_claimed_attempt(
        &rig,
        attempt0,
        retryable,
        Some(DeliveryFailureProvenance::ProvenNotPerformed),
    );
    assert!(
        capsule_failure_retry_for_test(&runner, "p", attempt0, retryable)
            .expect("the first failed fold adjudicates"),
        "a retryable failed attempt queues its retry"
    );
    assert_eq!(
        pending_failure_retries_for_test(&runner),
        vec![("p".to_owned(), 1)],
        "one seat-1 failure retry queued"
    );
    // The resync leg's re-fold of the same settled attempt queues nothing.
    assert!(
        capsule_failure_retry_for_test(&runner, "p", attempt0, retryable)
            .expect("the re-fold adjudicates"),
        "the re-fold still reports Retrying"
    );
    assert_eq!(
        pending_failure_retries_for_test(&runner),
        vec![("p".to_owned(), 1)],
        "a re-fold queues no second seat-1 retry"
    );
    // The seat-1 attempt fails too — its occurrence minted under the
    // TRUNCATED contract the chain's seat-1 capsule carries (the panel's
    // tail from codex2) — and its fold queues seat 2.
    let attempt1 = seed_claimed_capsule_attempt_at(
        &rig.db,
        &rig.cas,
        "p",
        &chain_occurrence(&program, execution, "p", &[0, 1], 1),
    )
    .0;
    fail_claimed_attempt(
        &rig,
        attempt1,
        retryable,
        Some(DeliveryFailureProvenance::ProvenNotPerformed),
    );
    assert!(
        capsule_failure_retry_for_test(&runner, "p", attempt1, retryable)
            .expect("the seat-1 failed fold adjudicates"),
        "the seat-1 fold queues the seat-2 retry"
    );
    assert_eq!(
        pending_failure_retries_for_test(&runner),
        vec![("p".to_owned(), 1), ("p".to_owned(), 2)],
        "the chain's pending seats, in order"
    );
    // A fresh runner — a crash's resume — re-folds attempt 0 with the
    // in-memory queue empty: the MINTED occurrence at seat 1 is the dedup,
    // under the same truncated contract the retry was dispatched with.
    let resumed = rig.runner(&program, execution);
    assert!(
        capsule_failure_retry_for_test(&resumed, "p", attempt0, retryable)
            .expect("the resumed fold adjudicates"),
        "the resumed fold still reports Retrying"
    );
    assert!(
        pending_failure_retries_for_test(&resumed).is_empty(),
        "the minted seat-1 occurrence dedups the re-fold — the queue stays empty"
    );
}

/// A `topology` stage's SYNTHETIC child spelling is checked against the
/// invocation envelope's DECLARED roles at settlement: `parent#child-w-x`
/// names a member the envelope does not declare — `child.role == role`
/// fails, and the dynamic-fanout suffix arm (`<role>-<label>`) is closed on
/// a STATIC topology — so the completion is refused by name and the
/// occurrence never accepts.
///
/// **Mutant die**: `dynamic_fanout && <label>` weakened to `||` declares any
/// `<declared>-<anything>` role on a static topology — the undeclared member
/// settles instead of refusing.
#[tokio::test(flavor = "current_thread")]
async fn an_undeclared_topology_child_label_is_refused_at_settlement() {
    let rig = rig(&tempfile::tempdir().unwrap().keep());
    rig.declare_bound_environment();
    let program = program_of(TOPOLOGY_FEEDBACK_PACK);
    let execution = Ulid::new();
    let _runner = rig.runner(&program, execution);
    let (attempt_id, assignment_json) = seed_claimed_capsule_attempt(
        &rig.db,
        &rig.cas,
        execution,
        program.program_hash,
        "parent#child-w-x",
    );
    rig.db
        .dispatch_claimed_attempt(
            attempt_id,
            OCI_RIG_WORKER,
            Ulid::new(),
            &kata_core::operational::CommandSpec {
                command_json: assignment_json.clone(),
            },
        )
        .expect("the seeded attempt dispatches");
    let DispatchFrame::Capsule(mut frame) =
        serde_json::from_slice(&assignment_json).expect("the seed's frame is the capsule arm");
    let row = rig
        .db
        .attempt(attempt_id)
        .unwrap()
        .expect("the attempt row");
    frame.lease_epoch = row.lease_epoch;
    frame.placed_on = SmolStr::new(OCI_RIG_WORKER);
    let refusal = reactor(&rig)
        .handle_message_for_test(kata_transport::types::WorkerMessage::CompletedCapsule {
            attempt_id: frame.attempt_id,
            fence: kata_transport::types::AttemptFence::echoing_capsule(&frame),
            result: publish_result(&rig),
            work_delta: kata_workflow::test_harness::stub_work_delta(
                &rig.db,
                &rig.cas,
                frame.occurrence_id,
            ),
            exit_code: Some(0),
            stdout: publish_blob(&rig, b""),
            stderr: publish_blob(&rig, b""),
            capture_exceeded: false,
            agent: None,
            provenance: kata_types::execution_provenance::ExecutionProvenance::local_oci_runtime(
                "undeclared child cell",
            ),
            egress_refusals: vec![],
        })
        .expect_err("a member the envelope does not declare is refused");
    assert!(
        refusal.to_string().contains("does not declare"),
        "the refusal names the undeclared role: {refusal}"
    );
    let accepted: i64 = raw(&rig.op_path)
        .query_row(
            "SELECT COUNT(*) FROM occurrences WHERE accepted_attempt_id IS NOT NULL AND \
             execution_id = ?1",
            [execution.to_bytes().as_slice()],
            |row| row.get(0),
        )
        .expect("the occurrence row reads");
    assert_eq!(accepted, 0, "the refused member's occurrence never accepts");
}

/// A resume in the crash window the guard at `submit_stage_as_capsule`'s
/// head exists for: attempt 0's accepted-but-invalid completion is durable,
/// its validation retry never dispatched, and the resumed runner's advance
/// would re-submit the stage at its OWN coordinate — where the occurrence is
/// already accepted and the chain's seat-1 capsule owns the next attempt.
/// The guard makes that re-submit a no-op; the retry chain alone mints.
///
/// **Mutant die**: `lowered.path.0.len() == 1` flipped to `!=` skips the
/// accepted-occurrence check on the only coordinate shape it guards, so the
/// re-submit mints a SECOND attempt bound to the accepted occurrence — the
/// raw chain grows a third row, at seat [0] rather than the retry's [0,1].
#[tokio::test(flavor = "current_thread")]
async fn a_resumed_run_never_resubmits_an_accepted_occurrence() {
    let rig = rig(&tempfile::tempdir().unwrap().keep());
    rig.declare_bound_environment();
    let program = program_of(AGENT_FEEDBACK_PACK);
    let execution = Ulid::new();

    // Attempt 0 completes with invalid content: its acceptance commits, the
    // run dies before its fold can queue the retry — the crash.
    {
        let runner = rig.runner(&program, execution);
        let reactor = reactor(&rig);
        let run = runner.run();
        tokio::pin!(run);
        let first = tokio::time::timeout(Duration::from_secs(30), async {
            tokio::select! {
                outcome = &mut run => panic!("the run resolved with nothing to drive: {outcome:?}"),
                frame = next_frame(&rig) => frame,
            }
        })
        .await
        .expect("attempt 0's frame arrives");
        answer(&rig, &reactor, &first, Answer::Complete(b"not json at all"));
    }

    let runner = rig.runner(&program, execution);
    let reactor = reactor(&rig);
    let mut frames = Vec::new();
    let run = runner.run();
    tokio::pin!(run);
    let outcome = tokio::time::timeout(Duration::from_secs(60), async {
        loop {
            tokio::select! {
                outcome = &mut run => break outcome,
                frame = next_frame(&rig) => {
                    frames.push(frame_path(&rig, &frame));
                    answer(&rig, &reactor, &frame, Answer::Complete(b"{\"verdict\": \"ok\"}"));
                }
            }
        }
    })
    .await
    .expect("the resumed drive reaches a terminal within the budget");
    outcome.expect("the resumed runner's validation retry completes");
    assert_eq!(
        frames,
        vec![vec![0, 1]],
        "the resume dispatches exactly the seat-1 retry — never a second attempt 0: {frames:?}"
    );
    let seats: i64 = raw(&rig.op_path)
        .query_row(
            "SELECT COUNT(*) FROM attempts WHERE execution_id = ?1 AND stage_id = 'p'",
            [execution.to_bytes().as_slice()],
            |row| row.get(0),
        )
        .expect("the attempt count reads");
    assert_eq!(
        seats, 2,
        "raw: the accepted occurrence's chain holds attempt 0 and its retry, no resubmit"
    );
}

/// The crash window's second door: `mark_retry_pending_in_flight` keeps a pure-fold
/// resume's `advance` from re-presenting a retry-pending stage — but the submit door
/// itself refuses too. A `submit_stage_as_capsule` at a stage coordinate whose `[i]`
/// occurrence is durably accepted is owned by that occurrence's retry chain: a no-op,
/// never a second attempt 0.
#[tokio::test]
async fn an_accepted_stage_occurrence_no_ops_the_capsule_submit() {
    let rig = rig(&tempfile::tempdir().unwrap().keep());
    rig.declare_bound_environment();
    let program = program_of(AGENT_FEEDBACK_PACK);
    let execution = Ulid::new();

    // Attempt 0's completion accepts the stage's `[0]` occurrence.
    {
        let runner = rig.runner(&program, execution);
        let reactor = reactor(&rig);
        let run = runner.run();
        tokio::pin!(run);
        let first = tokio::time::timeout(Duration::from_secs(30), async {
            tokio::select! {
                outcome = &mut run => panic!("the run resolved with nothing to drive: {outcome:?}"),
                frame = next_frame(&rig) => frame,
            }
        })
        .await
        .expect("attempt 0's frame arrives");
        answer(
            &rig,
            &reactor,
            &first,
            Answer::Complete(b"{\"verdict\": \"ok\"}"),
        );
    }

    // The stage's OWN resolved directive, so the submit carries everything a
    // production re-presentment would — the no-op is the occurrence check, not
    // some earlier door refusing first.
    let checked = program
        .stages
        .get(&StageId(SmolStr::new("p")))
        .expect("stage p");
    let directive = rig
        .dispatcher
        .resolve_sandbox(
            checked.policies.sandbox.as_ref(),
            &program.sandbox_profiles,
            Ulid::new(),
            execution,
            checked.should_confine_to_declared_inputs(),
            checked.is_content_cacheable(),
        )
        .await
        .expect("the stage's sandbox resolves");
    let runner = rig.runner(&program, execution);
    runner
        .submit_stage_as_capsule_for_test(
            &SmolStr::new("p"),
            directive,
            &kata_workflow::capsule_assembly::RenderedCommand::rendered("answer"),
        )
        .await
        .expect("an accepted stage-coordinate occurrence no-ops the submit");
    let seats: i64 = raw(&rig.op_path)
        .query_row(
            "SELECT COUNT(*) FROM attempts WHERE execution_id = ?1 AND stage_id = 'p'",
            [execution.to_bytes().as_slice()],
            |row| row.get(0),
        )
        .expect("the attempt count reads");
    assert_eq!(
        seats, 1,
        "raw: the accepted [0] owns its retry chain — the submit minted no second attempt"
    );
}
